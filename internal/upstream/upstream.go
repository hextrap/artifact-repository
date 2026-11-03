// Package upstream is shared by the proxy repositories of every format: a
// short-lived cache for upstream indexes, one download for concurrent cache
// misses, the firewall gate, and HTTP fetching with consistent errors.
package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"hextrap.io/artifacts/internal/registry"
)

// IndexTTL is how long an upstream index or metadata document is reused.
const IndexTTL = 5 * time.Minute

// Request describes a file about to be fetched from upstream.
type Request struct {
	Repo      registry.Repo
	Package   string
	Version   string
	Filename  string
	Published time.Time
}

// Gate decides whether a file may be fetched and cached. It runs before
// anything is downloaded; returning an error refuses the request. The
// firewall rules plug in here.
type Gate func(ctx context.Context, req Request) error

type entry struct {
	value   any
	fetched time.Time
}

type flight struct {
	done chan struct{}
	err  error
}

type Proxy struct {
	client    *http.Client
	firewalls map[string]firewall // by origin; set at startup
	now       func() time.Time
	gate      Gate
	mu        sync.Mutex
	cache     map[string]entry
	inflight  map[string]*flight
}

func New() *Proxy {
	return &Proxy{
		client:   &http.Client{Timeout: 10 * time.Minute},
		now:      time.Now,
		cache:    map[string]entry{},
		inflight: map[string]*flight{},
	}
}

func (p *Proxy) SetClock(now func() time.Time) { p.now = now }
func (p *Proxy) SetGate(g Gate)                { p.gate = g }
func (p *Proxy) SetClient(c *http.Client)      { p.client = c }

// Cached returns the value stored under key if it was fetched within
// IndexTTL (and force is false); otherwise it calls fetch and stores the
// result. Errors aren't cached.
func (p *Proxy) Cached(key string, force bool, fetch func() (any, error)) (any, error) {
	p.mu.Lock()
	e, ok := p.cache[key]
	p.mu.Unlock()
	if ok && !force && p.now().Sub(e.fetched) < IndexTTL {
		return e.value, nil
	}
	v, err := fetch()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cache) > 10000 {
		for k, old := range p.cache {
			if p.now().Sub(old.fetched) >= IndexTTL {
				delete(p.cache, k)
			}
		}
	}
	p.cache[key] = entry{value: v, fetched: p.now()}
	return v, nil
}

// Once runs fn for the first caller with key; concurrent callers with the
// same key wait and get its result.
func (p *Proxy) Once(key string, fn func() error) error {
	p.mu.Lock()
	if f, ok := p.inflight[key]; ok {
		p.mu.Unlock()
		<-f.done
		return f.err
	}
	f := &flight{done: make(chan struct{})}
	p.inflight[key] = f
	p.mu.Unlock()

	f.err = fn()

	p.mu.Lock()
	delete(p.inflight, key)
	p.mu.Unlock()
	close(f.done)
	return f.err
}

// Check runs the gate, if any.
func (p *Proxy) Check(ctx context.Context, req Request) error {
	if p.gate == nil {
		return nil
	}
	if err := p.gate(ctx, req); err != nil {
		return fmt.Errorf("%w: %v", registry.ErrBlocked, err)
	}
	return nil
}

// Get fetches an upstream URL. A 404 is registry.ErrNotFound; network
// failures and other non-2xx statuses are registry.ErrUpstreamUnavailable.
// The caller closes the body.
func (p *Proxy) Get(ctx context.Context, rawURL string, header http.Header) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("%w: refusing to fetch %q", registry.ErrUpstreamUnavailable, rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	p.authorize(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	if resp.StatusCode > 299 {
		if err := p.firewallError(resp); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		resp.Body.Close()
		return nil, registry.ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s returned %s", registry.ErrUpstreamUnavailable, u.Host, resp.Status)
	}
	return resp, nil
}

// Do sends a request upstream and returns the response whatever its status,
// for protocols that handle challenges or redirects themselves. Network
// failures are registry.ErrUpstreamUnavailable.
func (p *Proxy) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, fmt.Errorf("%w: refusing to fetch %q", registry.ErrUpstreamUnavailable, req.URL)
	}
	p.authorize(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	return resp, nil
}

// Head returns an upstream URL's response headers without fetching the body,
// with the same errors as Get.
func (p *Proxy) Head(ctx context.Context, rawURL string) (http.Header, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("%w: refusing to fetch %q", registry.ErrUpstreamUnavailable, rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return nil, err
	}
	p.authorize(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, registry.ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 399:
		return nil, fmt.Errorf("%w: %s returned %s", registry.ErrUpstreamUnavailable, u.Host, resp.Status)
	}
	return resp.Header, nil
}

// Host is the upstream's host, recorded as a cached version's origin.
func Host(repo registry.Repo) string {
	if u, err := url.Parse(repo.Upstream); err == nil && u.Host != "" {
		return u.Host
	}
	return repo.Upstream
}
