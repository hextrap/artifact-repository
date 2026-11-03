package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/registry"
)

func TestCachedReusesWithinTTL(t *testing.T) {
	r := require.New(t)
	p := New()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	p.SetClock(func() time.Time { return now })
	calls := 0
	fetch := func() (any, error) { calls++; return calls, nil }

	v, err := p.Cached("k", false, fetch)
	r.NoError(err)
	r.Equal(1, v)
	v, _ = p.Cached("k", false, fetch)
	r.Equal(1, v, "reused")
	v, _ = p.Cached("k", true, fetch)
	r.Equal(2, v, "forced refresh")
	now = now.Add(IndexTTL)
	v, _ = p.Cached("k", false, fetch)
	r.Equal(3, v, "expired")
	v, _ = p.Cached("other", false, fetch)
	r.Equal(4, v, "keys are separate")
}

func TestCachedDoesNotCacheErrors(t *testing.T) {
	p := New()
	fail := true
	fetch := func() (any, error) {
		if fail {
			return nil, ErrUnavailableForTest
		}
		return "ok", nil
	}
	_, err := p.Cached("k", false, fetch)
	require.Error(t, err)
	fail = false
	v, err := p.Cached("k", false, fetch)
	require.NoError(t, err)
	require.Equal(t, "ok", v)
}

var ErrUnavailableForTest = errors.New("boom")

func TestOnceSharesConcurrentWork(t *testing.T) {
	p := New()
	var runs atomic.Int32
	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = p.Once("k", func() error {
				runs.Add(1)
				time.Sleep(30 * time.Millisecond)
				return ErrUnavailableForTest
			})
		}(i)
	}
	wg.Wait()
	require.Equal(t, int32(1), runs.Load())
	for _, err := range errs {
		require.ErrorIs(t, err, ErrUnavailableForTest, "everyone sees the shared result")
	}
	// A later call runs again.
	require.NoError(t, p.Once("k", func() error { return nil }))
}

func TestGetMapsStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("hello"))
		case "/missing":
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	p := New()
	ctx := context.Background()

	resp, err := p.Get(ctx, srv.URL+"/ok", nil)
	require.NoError(t, err)
	resp.Body.Close()
	_, err = p.Get(ctx, srv.URL+"/missing", nil)
	require.ErrorIs(t, err, registry.ErrNotFound)
	_, err = p.Get(ctx, srv.URL+"/broken", nil)
	require.ErrorIs(t, err, registry.ErrUpstreamUnavailable)
	srv.Close()
	_, err = p.Get(ctx, srv.URL+"/ok", nil)
	require.ErrorIs(t, err, registry.ErrUpstreamUnavailable)
	_, err = p.Get(ctx, "file:///etc/passwd", nil)
	require.Error(t, err, "only http(s)")
}

func TestCheckRunsGate(t *testing.T) {
	p := New()
	require.NoError(t, p.Check(context.Background(), Request{Package: "x"}), "no gate: allowed")
	var seen Request
	p.SetGate(func(_ context.Context, req Request) error {
		seen = req
		return errors.New("too new")
	})
	err := p.Check(context.Background(), Request{Package: "x", Version: "1"})
	require.ErrorIs(t, err, registry.ErrBlocked)
	require.ErrorContains(t, err, "too new")
	require.Equal(t, "1", seen.Version)
}

func TestHost(t *testing.T) {
	require.Equal(t, "pypi.org", Host(registry.Repo{Upstream: "https://pypi.org"}))
	require.Equal(t, "repo.maven.apache.org", Host(registry.Repo{Upstream: "https://repo.maven.apache.org/maven2"}))
}

func TestStatusMapping(t *testing.T) {
	require.Equal(t, http.StatusBadGateway, registry.HTTPStatus(registry.ErrUpstreamUnavailable))
	require.Equal(t, http.StatusForbidden, registry.HTTPStatus(registry.ErrBlocked))
}

func TestHead(t *testing.T) {
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Mon, 15 Jan 2024 10:00:00 GMT")
		w.Write([]byte("body"))
	}))
	defer srv.Close()
	p := New()
	hdr, err := p.Head(context.Background(), srv.URL+"/crate")
	require.NoError(t, err)
	require.Equal(t, "Mon, 15 Jan 2024 10:00:00 GMT", hdr.Get("Last-Modified"))
	require.Equal(t, int32(0), gets.Load(), "no body fetched")
	_, err = p.Head(context.Background(), srv.URL+"/missing")
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestDoReturnsAnyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := New()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := p.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "callers handle challenges themselves")
	req, _ = http.NewRequest(http.MethodGet, "file:///etc/passwd", nil)
	_, err = p.Do(req)
	require.ErrorIs(t, err, registry.ErrUpstreamUnavailable)
}
