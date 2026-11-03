package npm

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
	"hextrap.io/artifacts/internal/upstream/upstreamtest"
)

// fakeNPM is a minimal npm registry.
type fakeNPM struct {
	srv      *httptest.Server
	tarballs map[string][]byte // path -> content
	tamper   map[string][]byte
	hits     sync.Map
	// tarballBase is where packuments link tarballs; the registry itself
	// when empty. A firewall passes npmjs packuments through unchanged.
	tarballBase string
	firewall    *upstreamtest.Firewall // in front of the registry when set
	registry    http.Handler
}

func integrity(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

func shasum(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])
}

func newFakeNPM(t *testing.T) *fakeNPM {
	f := &fakeNPM{
		tarballs: map[string][]byte{
			"/left-pad/-/left-pad-1.3.0.tgz": []byte("LEFTPAD-1.3.0"),
			"/left-pad/-/left-pad-0.0.9.tgz": []byte("LEFTPAD-0.0.9"),
			"/@acme/utils/-/utils-2.0.0.tgz": []byte("UTILS-2.0.0"),
		},
		tamper: map[string][]byte{},
	}
	version := func(name, v, path string, withIntegrity bool) map[string]any {
		body := f.tarballs[path]
		base := f.tarballBase
		if base == "" {
			base = f.srv.URL
		}
		dist := map[string]any{"tarball": base + path, "shasum": shasum(body)}
		if withIntegrity {
			dist["integrity"] = integrity(body)
		}
		return map[string]any{"name": name, "version": v, "main": "index.js", "dependencies": map[string]string{}, "dist": dist}
	}
	var registryHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		if strings.Contains(path, "/-/") {
			c, _ := f.hits.LoadOrStore(r.URL.Path, &atomic.Int32{})
			c.(*atomic.Int32).Add(1)
			body, ok := f.tamper[r.URL.Path]
			if !ok {
				body, ok = f.tarballs[r.URL.Path]
			}
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(body)
			return
		}
		var doc map[string]any
		switch path {
		case "/left-pad":
			doc = map[string]any{
				"_id": "left-pad", "name": "left-pad", "description": "pad strings",
				"dist-tags": map[string]string{"latest": "1.3.0", "old": "0.0.9"},
				"versions": map[string]any{
					"1.3.0": version("left-pad", "1.3.0", "/left-pad/-/left-pad-1.3.0.tgz", true),
					"0.0.9": version("left-pad", "0.0.9", "/left-pad/-/left-pad-0.0.9.tgz", false), // pre-integrity era
				},
				"time": map[string]string{"created": "2014-03-14T00:00:00.000Z", "modified": "2018-04-01T00:00:00.000Z",
					"1.3.0": "2018-04-01T00:00:00.000Z", "0.0.9": "2014-03-14T00:00:00.000Z"},
			}
		case "/@acme%2futils", "/@acme%2Futils":
			doc = map[string]any{
				"_id": "@acme/utils", "name": "@acme/utils", "dist-tags": map[string]string{"latest": "2.0.0"},
				"versions": map[string]any{"2.0.0": version("@acme/utils", "2.0.0", "/@acme/utils/-/utils-2.0.0.tgz", true)},
				"time":     map[string]string{"2.0.0": "2026-01-01T00:00:00.000Z"},
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.firewall != nil {
			f.firewall.ServeHTTP(w, r)
			return
		}
		registryHandler(w, r)
	}))
	f.registry = registryHandler
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNPM) tarballHits(path string) int32 {
	c, ok := f.hits.Load(path)
	if !ok {
		return 0
	}
	return c.(*atomic.Int32).Load()
}

type proxyEnv struct {
	*env
	up      *fakeNPM
	handler *Handler
	mu      sync.Mutex
	clock   time.Time
}

func (e *proxyEnv) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func newProxyEnv(t *testing.T) *proxyEnv { return newProxyEnvWith(t, false) }

// newProxyEnvWith builds a proxy repo; with firewall, its upstream is a
// hextrap firewall in front of the fake registry.
func newProxyEnvWith(t *testing.T, firewall bool) *proxyEnv {
	up := newFakeNPM(t)
	e := &proxyEnv{up: up, clock: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	svc := registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.now, nil)
	if firewall {
		up.firewall = upstreamtest.NewFirewall(up.registry)
		svc.AllowFirewall(registry.FormatNPM, up.srv.URL)
	} else {
		svc.AllowUpstreams(registry.FormatNPM, up.srv.URL)
	}
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "proxy", Format: registry.FormatNPM, Type: registry.TypeProxy}))
	for name, role := range map[string]rbac.Role{"maintainer": rbac.RoleMaintainer, "developer": rbac.RoleDeveloper, "reader": rbac.RoleReader} {
		require.NoError(t, svc.SetGrant(ctx, admin, "proxy", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: principals[name].Email, Role: role}))
	}
	e.env = &env{t: t, svc: svc}
	e.env.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			p = principals[tok]
		}
		e.handler.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	e.handler = New(svc, func(*http.Request) string { return e.env.srv.URL })
	e.handler.SetClock(e.now)
	if firewall {
		e.handler.AddFirewall(up.srv.URL, upstreamtest.Username, upstreamtest.Password)
	}
	t.Cleanup(e.env.srv.Close)
	return e
}

func tarballOf(t *testing.T, p packument, version string) string {
	v, ok := p.Versions[version]
	require.True(t, ok, "version %s missing", version)
	return v["dist"].(map[string]any)["tarball"].(string)
}

func TestNPMProxyPackument(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, p := e.packument("/npm/proxy/left-pad", "reader")
	r.Equal(200, code)
	r.Equal("left-pad", p.Name)
	r.Equal(map[string]string{"latest": "1.3.0", "old": "0.0.9"}, p.DistTags)
	r.Equal(e.srv.URL+"/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", tarballOf(t, p, "1.3.0"), "downloads go through hextrap")
	r.Equal(integrity(e.up.tarballs["/left-pad/-/left-pad-1.3.0.tgz"]), p.Versions["1.3.0"]["dist"].(map[string]any)["integrity"])
	r.Equal("index.js", p.Versions["1.3.0"]["main"])
	r.Equal("2018-04-01T00:00:00.000Z", p.Time["1.3.0"])
}

func TestNPMProxyCachesTarball(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	path := "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz"
	for i, want := range []string{"miss", "hit"} {
		code, body, hdr := e.do("GET", path, "reader", nil)
		r.Equal(200, code, string(body))
		r.Equal("LEFTPAD-1.3.0", string(body))
		r.Equal(want, hdr.Get("X-Hextrap-Cache"), "request %d", i)
	}
	r.Equal(int32(1), e.up.tarballHits("/left-pad/-/left-pad-1.3.0.tgz"))

	versions, err := e.svc.Versions(context.Background(), principals["admin"], "proxy", "left-pad")
	r.NoError(err)
	r.Len(versions, 1)
	r.Equal(registry.SourceUpstream, versions[0].Source)
	u, _ := url.Parse(e.up.srv.URL)
	r.Equal(u.Host, versions[0].Origin)
}

func TestNPMProxySha1OnlyPackage(t *testing.T) {
	e := newProxyEnv(t)
	code, body, _ := e.do("GET", "/npm/proxy/left-pad/-/left-pad-0.0.9.tgz", "reader", nil)
	require.Equal(t, 200, code, string(body))
	require.Equal(t, "LEFTPAD-0.0.9", string(body))
}

func TestNPMProxyRejectsTamperedTarball(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.up.tamper["/left-pad/-/left-pad-1.3.0.tgz"] = []byte("EVIL")
	code, body, _ := e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "reader", nil)
	r.Equal(http.StatusBadGateway, code, string(body))
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "proxy", "left-pad")
	r.Empty(versions)
}

func TestNPMProxyScopedPackage(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, p := e.packument("/npm/proxy/@acme%2futils", "reader")
	r.Equal(200, code)
	r.Equal(e.srv.URL+"/npm/proxy/@acme/utils/-/utils-2.0.0.tgz", tarballOf(t, p, "2.0.0"))
	code, body, _ := e.do("GET", "/npm/proxy/@acme/utils/-/utils-2.0.0.tgz", "reader", nil)
	r.Equal(200, code)
	r.Equal("UTILS-2.0.0", string(body))
}

func TestNPMProxyServesCacheWhenUpstreamIsDown(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, _, _ := e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "reader", nil)
	r.Equal(200, code)
	e.up.srv.Close()
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()

	code, p := e.packument("/npm/proxy/left-pad", "reader")
	r.Equal(200, code)
	r.Len(p.Versions, 1, "only what's cached")
	r.Equal(e.srv.URL+"/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", tarballOf(t, p, "1.3.0"))
	r.Equal("index.js", p.Versions["1.3.0"]["main"], "the cached manifest is kept")
	code, body, hdr := e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "reader", nil)
	r.Equal(200, code)
	r.Equal("LEFTPAD-1.3.0", string(body))
	r.Equal("hit", hdr.Get("X-Hextrap-Cache"))

	code, _, _ = e.do("GET", "/npm/proxy/left-pad/-/left-pad-0.0.9.tgz", "reader", nil)
	r.Equal(http.StatusBadGateway, code)
}

func TestNPMProxyIsReadOnly(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, _, _ := e.do("PUT", "/npm/proxy/left-pad", "admin", publishBody("left-pad", "9.9.9", "x", nil))
	r.Equal(http.StatusMethodNotAllowed, code)
	code, _, _ = e.do("PUT", "/npm/proxy/-/package/left-pad/dist-tags/beta", "admin", []byte(`"1.3.0"`))
	r.Equal(http.StatusMethodNotAllowed, code)
	code, _, _ = e.do("DELETE", "/npm/proxy/left-pad/-rev/1-x", "admin", nil)
	r.Equal(http.StatusMethodNotAllowed, code)
}

func TestNPMProxyGate(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	var seen upstream.Request
	e.handler.SetGate(func(_ context.Context, req upstream.Request) error {
		seen = req
		return errors.New("on the deny list")
	})
	code, body, _ := e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "reader", nil)
	r.Equal(http.StatusForbidden, code)
	r.Contains(string(body), "deny list")
	r.Equal(int32(0), e.up.tarballHits("/left-pad/-/left-pad-1.3.0.tgz"))
	r.Equal("left-pad", seen.Package)
	r.Equal("1.3.0", seen.Version)
	r.Equal("left-pad-1.3.0.tgz", seen.Filename)
	r.Equal(time.Date(2018, 4, 1, 0, 0, 0, 0, time.UTC), seen.Published)
}

func TestNPMProxyRemovedVersionStaysRemoved(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "reader", nil)
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "proxy", "left-pad", "1.3.0"))

	_, p := e.packument("/npm/proxy/left-pad", "reader")
	r.NotContains(p.Versions, "1.3.0")
	r.NotContains(p.DistTags, "latest", "tags never point at removed versions")
	r.Equal("0.0.9", p.DistTags["old"])

	code, _, _ := e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "reader", nil)
	r.Equal(http.StatusNotFound, code)
	r.Equal(int32(1), e.up.tarballHits("/left-pad/-/left-pad-1.3.0.tgz"), "not fetched again")
}

func TestNPMProxyUnknownPackage(t *testing.T) {
	e := newProxyEnv(t)
	code, _ := e.packument("/npm/proxy/no-such-package", "reader")
	require.Equal(t, http.StatusNotFound, code)
}

func TestNPMProxyAccess(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, _, _ := e.do("GET", "/npm/proxy/left-pad", "", nil)
	r.Equal(http.StatusUnauthorized, code)
	code, _, _ = e.do("GET", "/npm/proxy/left-pad/-/left-pad-1.3.0.tgz", "stranger", nil)
	r.Equal(http.StatusNotFound, code)
	r.Equal(int32(0), e.up.tarballHits("/left-pad/-/left-pad-1.3.0.tgz"))
}
