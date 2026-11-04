package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"hextrap.io/artifacts/internal/registry"
)

// A hextrap firewall can be a proxy repo's upstream. It speaks the
// registry's own protocol, applies the customer's policy to every file
// download, and answers a blocked one with "400 blocking rule" (or 403).
// The repository has no policy of its own: it sends the firewall its
// credentials, treats a block as final, and asks again before serving a
// cached file.

// RecheckTimeout bounds a cache hit's wait for the firewall.
const RecheckTimeout = 10 * time.Second

type firewall struct {
	username, password string
}

// AddFirewall marks baseURL's host as a hextrap firewall and sets the
// credentials sent to it (and to no other host). Call it at startup.
func (p *Proxy) AddFirewall(baseURL, username, password string) {
	if p.firewalls == nil {
		p.firewalls = map[string]firewall{}
	}
	if o := origin(baseURL); o != "" {
		p.firewalls[o] = firewall{username: username, password: password}
	}
}

func origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (p *Proxy) firewallFor(u *url.URL) (firewall, bool) {
	fw, ok := p.firewalls[u.Scheme+"://"+u.Host]
	return fw, ok
}

// IsFirewall reports whether repo's upstream is a hextrap firewall.
func (p *Proxy) IsFirewall(repo registry.Repo) bool {
	_, ok := p.firewalls[origin(repo.Upstream)]
	return ok
}

// ViaFirewall points a download link from an upstream index at repo's
// firewall, keeping its path, so a link to the public registry can't route
// a download around the policy. Links for other repos are unchanged.
func (p *Proxy) ViaFirewall(repo registry.Repo, src string) string {
	if !p.IsFirewall(repo) {
		return src
	}
	u, err := url.Parse(src)
	if err != nil {
		return src
	}
	if origin(src) == origin(repo.Upstream) {
		u.User = nil // we send the credentials; keep them out of URLs and logs
		return u.String()
	}
	out := repo.Upstream + u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// authorize adds the firewall's credentials to a request bound for it.
func (p *Proxy) authorize(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	if fw, ok := p.firewallFor(req.URL); ok && req.Header.Get("Authorization") == "" {
		req.SetBasicAuth(fw.username, fw.password)
	}
}

// firewallError interprets a firewall's non-2xx response. It returns nil
// for responses that aren't from a firewall or mean something else.
func (p *Proxy) firewallError(resp *http.Response) error {
	if _, ok := p.firewallFor(resp.Request.URL); !ok {
		return nil
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusProxyAuthRequired:
		return fmt.Errorf("%w: the hextrap firewall rejected the configured credentials", registry.ErrUpstreamUnavailable)
	case http.StatusForbidden:
		return fmt.Errorf("%w: blocked by the hextrap firewall", registry.ErrBlocked)
	case http.StatusBadRequest:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if bytes.Contains(body, []byte("blocking rule")) {
			return fmt.Errorf("%w: blocked by the hextrap firewall", registry.ErrBlocked)
		}
	}
	return nil
}

// Recheck asks repo's firewall whether a cached file may still be served,
// so a package denied after it was cached stops installing (and the
// install shows in the hextrap dashboard). An allow is reused for
// IndexTTL. If the firewall can't be reached, the file is served: it was
// allowed when it was cached. Repos without a firewall always pass.
func (p *Proxy) Recheck(ctx context.Context, repo registry.Repo, rawURL string) error {
	if !p.IsFirewall(repo) {
		return nil
	}
	_, err := p.Cached("recheck "+rawURL, false, func() (any, error) {
		ctx, cancel := context.WithTimeout(ctx, RecheckTimeout)
		defer cancel()
		resp, err := p.Get(ctx, rawURL, nil)
		if err != nil {
			return nil, err
		}
		resp.Body.Close() // only the decision matters
		return true, nil
	})
	if errors.Is(err, registry.ErrBlocked) {
		return err
	}
	if err != nil {
		slog.Warn("hextrap firewall check failed; serving the cached file", "url", rawURL, "error", err)
	}
	return nil
}
