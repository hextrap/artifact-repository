package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/registry"
)

// fakeFirewall answers like codeproxy: Basic auth, then "400 blocking rule"
// for blocked files.
type fakeFirewall struct {
	srv     *httptest.Server
	blocked map[string]bool // path -> blocked
	hits    atomic.Int32
	status  int // forces a status when set
}

func newFakeFirewall(t *testing.T) *fakeFirewall {
	f := &fakeFirewall{blocked: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if u, p, ok := r.BasicAuth(); !ok || u != "fw-user" || p != "fw-pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		if f.blocked[r.URL.Path] {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("blocking rule"))
			return
		}
		w.Write([]byte("content of " + r.URL.Path))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func firewallProxy(f *fakeFirewall) (*Proxy, registry.Repo) {
	p := New()
	p.AddFirewall(f.srv.URL, "fw-user", "fw-pass")
	return p, registry.Repo{Tenant: "t", Name: "pypi", Upstream: f.srv.URL}
}

func TestFirewallGetsCredentials(t *testing.T) {
	f := newFakeFirewall(t)
	p, _ := firewallProxy(f)
	resp, err := p.Get(context.Background(), f.srv.URL+"/packages/a.whl", nil)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestFirewallCredentialsStayOnTheFirewall(t *testing.T) {
	var auth atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
	}))
	defer other.Close()
	p, _ := firewallProxy(newFakeFirewall(t))
	resp, err := p.Get(context.Background(), other.URL+"/x", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, "", auth.Load(), "never sent to another host")
}

func TestFirewallBlockIsBlocked(t *testing.T) {
	f := newFakeFirewall(t)
	f.blocked["/packages/evil.whl"] = true
	p, _ := firewallProxy(f)
	_, err := p.Get(context.Background(), f.srv.URL+"/packages/evil.whl", nil)
	require.ErrorIs(t, err, registry.ErrBlocked)
	require.ErrorContains(t, err, "hextrap firewall")

	f.status = http.StatusForbidden
	_, err = p.Get(context.Background(), f.srv.URL+"/packages/x.whl", nil)
	require.ErrorIs(t, err, registry.ErrBlocked, "403 is a block too")

	// A 400 that isn't a block is an upstream problem.
	f.status = http.StatusBadRequest
	_, err = p.Get(context.Background(), f.srv.URL+"/packages/x.whl", nil)
	require.ErrorIs(t, err, registry.ErrUpstreamUnavailable)
}

func TestFirewallRejectedCredentials(t *testing.T) {
	f := newFakeFirewall(t)
	p := New()
	p.AddFirewall(f.srv.URL, "fw-user", "wrong")
	_, err := p.Get(context.Background(), f.srv.URL+"/packages/a.whl", nil)
	require.ErrorIs(t, err, registry.ErrUpstreamUnavailable)
	require.ErrorContains(t, err, "credentials")
}

func TestPublicRegistryBlockStatusesAreNotBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := New().Get(context.Background(), srv.URL+"/x", nil)
	require.ErrorIs(t, err, registry.ErrUpstreamUnavailable, "only the firewall can block")
}

func TestIsFirewall(t *testing.T) {
	f := newFakeFirewall(t)
	p, repo := firewallProxy(f)
	require.True(t, p.IsFirewall(repo))
	require.False(t, p.IsFirewall(registry.Repo{Upstream: "https://pypi.org"}))
}

func TestViaFirewall(t *testing.T) {
	f := newFakeFirewall(t)
	p, repo := firewallProxy(f)
	// Download links that point at the public registry go through the
	// firewall instead, keeping the path.
	require.Equal(t, f.srv.URL+"/left-pad/-/left-pad-1.3.0.tgz",
		p.ViaFirewall(repo, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"))
	require.Equal(t, f.srv.URL+"/packages/a/b.whl", p.ViaFirewall(repo, f.srv.URL+"/packages/a/b.whl"))
	public := registry.Repo{Upstream: "https://registry.npmjs.org"}
	require.Equal(t, "https://registry.npmjs.org/x/-/x-1.tgz", p.ViaFirewall(public, "https://registry.npmjs.org/x/-/x-1.tgz"))
}

func TestRecheck(t *testing.T) {
	f := newFakeFirewall(t)
	p, repo := firewallProxy(f)
	now := time.Now()
	p.SetClock(func() time.Time { return now })
	ctx := context.Background()
	url := f.srv.URL + "/packages/a.whl"

	require.NoError(t, p.Recheck(ctx, repo, url))
	require.NoError(t, p.Recheck(ctx, repo, url))
	require.Equal(t, int32(1), f.hits.Load(), "an allow is reused for a while")

	f.blocked["/packages/a.whl"] = true
	now = now.Add(IndexTTL)
	require.ErrorIs(t, p.Recheck(ctx, repo, url), registry.ErrBlocked, "a later deny applies to cached files")
	require.ErrorIs(t, p.Recheck(ctx, repo, url), registry.ErrBlocked, "blocks aren't cached as allows")

	// If the firewall can't be reached, cached files keep serving.
	f.srv.Close()
	require.NoError(t, p.Recheck(ctx, repo, f.srv.URL+"/packages/b.whl"))
}

func TestRecheckSkipsPublicUpstreams(t *testing.T) {
	require.NoError(t, New().Recheck(context.Background(), registry.Repo{Upstream: "https://pypi.org"}, "https://pypi.org/x"))
}
