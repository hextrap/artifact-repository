package gomod

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

// Known answer from the Go checksum database (sum.golang.org/lookup) for
// rsc.io/quote v1.5.2/go.mod.
func TestHashGoModKnownAnswer(t *testing.T) {
	mod := "module \"rsc.io/quote\"\n\nrequire \"rsc.io/sampler\" v1.3.0\n"
	require.Equal(t, "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=", hashGoMod([]byte(mod)))
}

func TestEscaping(t *testing.T) {
	r := require.New(t)
	for escaped, path := range map[string]string{
		"github.com/!burnt!sushi/toml": "github.com/BurntSushi/toml",
		"golang.org/x/text":            "golang.org/x/text",
	} {
		got, err := unescapePath(escaped)
		r.NoError(err)
		r.Equal(path, got)
		r.Equal(escaped, escapePath(path))
	}
	_, err := unescapePath("github.com/Upper/case")
	r.Error(err, "escaped paths are lowercase")
}

func user(email string) identity.Principal {
	return identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub|" + email, Email: email}
}

var principals = map[string]identity.Principal{
	"admin":    user("admin@acme.com"),
	"reader":   user("reader@acme.com"),
	"stranger": user("stranger@acme.com"),
}

const module = "github.com/BurntSushi/toml"

func moduleZip(t *testing.T, version, content string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"go.mod": "module " + module + "\n", "toml.go": content} {
		w, err := zw.Create(module + "@" + version + "/" + name)
		require.NoError(t, err)
		io.WriteString(w, body)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// fakeGoProxy serves the GOPROXY protocol and a checksum database.
type fakeGoProxy struct {
	srv      *httptest.Server
	files    map[string][]byte // "<version>.zip|.mod|.info" -> content
	evil     map[string][]byte
	hits     sync.Map
	noSumDB  bool
	firewall *upstreamtest.Firewall // in front of the proxy when set
	registry http.Handler
}

func newFakeGoProxy(t *testing.T) *fakeGoProxy {
	f := &fakeGoProxy{files: map[string][]byte{}, evil: map[string][]byte{}}
	for _, v := range []string{"v1.3.2", "v1.4.0"} {
		f.files[v+".zip"] = moduleZip(t, v, "package toml // "+v)
		f.files[v+".mod"] = []byte("module " + module + "\n")
		f.files[v+".info"] = []byte(fmt.Sprintf(`{"Version":%q,"Time":"2024-06-01T10:00:00Z"}`, v))
	}
	esc := "/github.com/!burnt!sushi/toml"
	var registryHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		c, _ := f.hits.LoadOrStore(r.URL.Path, &atomic.Int32{})
		c.(*atomic.Int32).Add(1)
		switch {
		case r.URL.Path == esc+"/@v/list":
			io.WriteString(w, "v1.3.2\nv1.4.0\n")
		case r.URL.Path == esc+"/@latest":
			w.Write(f.files["v1.4.0.info"])
		case strings.HasPrefix(r.URL.Path, esc+"/@v/"):
			name := strings.TrimPrefix(r.URL.Path, esc+"/@v/")
			body, ok := f.evil[name]
			if !ok {
				body, ok = f.files[name]
			}
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(body)
		case strings.HasPrefix(r.URL.Path, "/sumdb/lookup/"):
			if f.noSumDB {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			v := strings.TrimPrefix(r.URL.Path, "/sumdb/lookup/github.com/!burnt!sushi/toml@")
			zh, err := hashZip(f.files[v+".zip"])
			require.NoError(t, err)
			fmt.Fprintf(w, "123\n%s %s %s\n%s %s/go.mod %s\n\ngo.sum database tree\n1\nhash\n", module, v, zh, module, v, hashGoMod(f.files[v+".mod"]))
		default:
			http.NotFound(w, r)
		}
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

func (f *fakeGoProxy) count(path string) int32 {
	c, ok := f.hits.Load(path)
	if !ok {
		return 0
	}
	return c.(*atomic.Int32).Load()
}

type env struct {
	t       *testing.T
	srv     *httptest.Server
	svc     *registry.Service
	handler *Handler
	up      *fakeGoProxy
	mu      sync.Mutex
	clock   time.Time
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func newEnv(t *testing.T) *env { return newEnvWith(t, false) }

// newEnvWith builds a proxy repo; with firewall, its upstream is a hextrap
// firewall in front of the fake proxy.
func newEnvWith(t *testing.T, firewall bool) *env {
	up := newFakeGoProxy(t)
	e := &env{t: t, up: up, clock: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	e.svc = registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.now, nil)
	if firewall {
		up.firewall = upstreamtest.NewFirewall(up.registry)
		e.svc.AllowFirewall(registry.FormatGo, up.srv.URL)
	} else {
		e.svc.AllowUpstreams(registry.FormatGo, up.srv.URL)
	}
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "goproxy", Format: registry.FormatGo, Type: registry.TypeProxy}))
	require.NoError(t, e.svc.SetGrant(ctx, admin, "goproxy", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "reader@acme.com", Role: rbac.RoleReader}))
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if _, pass, ok := r.BasicAuth(); ok {
			p = principals[pass]
		}
		e.handler.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	e.handler = New(e.svc)
	e.handler.SetClock(e.now)
	e.handler.SetSumDB(up.srv.URL + "/sumdb")
	if firewall {
		e.handler.AddFirewall(up.srv.URL, upstreamtest.Username, upstreamtest.Password)
	}
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) get(path, as string) (int, string, http.Header) {
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	if as != "" {
		req.SetBasicAuth("token", as)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

const base = "/go/goproxy/github.com/!burnt!sushi/toml"

func TestList(t *testing.T) {
	code, body, _ := newEnv(t).get(base+"/@v/list", "reader")
	require.Equal(t, 200, code)
	require.Equal(t, "v1.3.2\nv1.4.0\n", body)
}

func TestCachesAndVerifiesModuleFiles(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	for _, ext := range []string{".info", ".mod", ".zip"} {
		for _, want := range []string{"miss", "hit"} {
			code, body, hdr := e.get(base+"/@v/v1.4.0"+ext, "reader")
			r.Equal(200, code, "%s: %s", ext, body)
			r.Equal(string(e.up.files["v1.4.0"+ext]), body, ext)
			r.Equal(want, hdr.Get("X-Hextrap-Cache"), ext)
		}
		r.Equal(int32(1), e.up.count("/github.com/!burnt!sushi/toml/@v/v1.4.0"+ext), ext)
	}
	versions, err := e.svc.Versions(context.Background(), principals["admin"], "goproxy", module)
	r.NoError(err)
	r.Len(versions, 1)
	r.Equal(module, versions[0].Package, "stored under the real (unescaped) module path")
	r.Equal(registry.SourceUpstream, versions[0].Source)
	r.Len(versions[0].Files, 3)
}

func TestRejectsZipThatDoesntMatchSumDB(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.up.evil["v1.4.0.zip"] = moduleZip(t, "v1.4.0", "package toml // backdoored")
	code, body, _ := e.get(base+"/@v/v1.4.0.zip", "reader")
	r.Equal(http.StatusBadGateway, code)
	r.Contains(body, "sum.golang.org")
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "goproxy", module)
	r.Empty(versions)
}

func TestRejectsGoModThatDoesntMatchSumDB(t *testing.T) {
	e := newEnv(t)
	e.up.evil["v1.4.0.mod"] = []byte("module " + module + "\n\nrequire evil.example/x v1.0.0\n")
	code, _, _ := e.get(base+"/@v/v1.4.0.mod", "reader")
	require.Equal(t, http.StatusBadGateway, code)
}

func TestFailsClosedWhenSumDBIsUnreachable(t *testing.T) {
	e := newEnv(t)
	e.up.noSumDB = true
	code, _, _ := e.get(base+"/@v/v1.4.0.zip", "reader")
	require.Equal(t, http.StatusBadGateway, code, "unverifiable modules aren't cached")
}

func TestSumDBCanBeDisabledForPrivateUpstreams(t *testing.T) {
	e := newEnv(t)
	e.up.noSumDB = true
	e.handler.SetSumDB("")
	code, _, _ := e.get(base+"/@v/v1.4.0.zip", "reader")
	require.Equal(t, 200, code)
}

func TestRejectsMalformedZip(t *testing.T) {
	e := newEnv(t)
	e.handler.SetSumDB("")
	e.up.evil["v1.4.0.zip"] = []byte("not a zip")
	code, _, _ := e.get(base+"/@v/v1.4.0.zip", "reader")
	require.Equal(t, http.StatusBadGateway, code)
}

func TestLatest(t *testing.T) {
	code, body, _ := newEnv(t).get(base+"/@latest", "reader")
	require.Equal(t, 200, code)
	var info struct{ Version string }
	require.NoError(t, json.Unmarshal([]byte(body), &info))
	require.Equal(t, "v1.4.0", info.Version)
}

func TestGate(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	var seen upstream.Request
	e.handler.SetGate(func(_ context.Context, req upstream.Request) error {
		seen = req
		return errors.New("too new")
	})
	code, body, _ := e.get(base+"/@v/v1.4.0.zip", "reader")
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "too new")
	r.Equal(int32(0), e.up.count("/github.com/!burnt!sushi/toml/@v/v1.4.0.zip"), "never downloaded")
	r.Equal(module, seen.Package)
	r.Equal("v1.4.0", seen.Version)
	r.Equal(time.Date(2024, 6, 1, 10, 0, 0, 0, time.UTC), seen.Published, "from the .info file")
}

func TestServesCacheWhenUpstreamIsDown(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	for _, ext := range []string{".info", ".mod", ".zip"} {
		code, _, _ := e.get(base+"/@v/v1.4.0"+ext, "reader")
		r.Equal(200, code)
	}
	e.up.srv.Close()
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()
	code, body, _ := e.get(base+"/@v/list", "reader")
	r.Equal(200, code)
	r.Equal("v1.4.0\n", body, "only what's cached")
	code, _, _ = e.get(base+"/@v/v1.4.0.zip", "reader")
	r.Equal(200, code)
	code, body, _ = e.get(base+"/@latest", "reader")
	r.Equal(200, code)
	r.Contains(body, "v1.4.0")
}

func TestRemovedVersion(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.get(base+"/@v/v1.4.0.zip", "reader")
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "goproxy", module, "v1.4.0"))
	_, body, _ := e.get(base+"/@v/list", "reader")
	r.Equal("v1.3.2\n", body)
	code, _, _ := e.get(base+"/@v/v1.4.0.zip", "reader")
	r.Equal(http.StatusNotFound, code)
}

func TestSumDBProxyNotOffered(t *testing.T) {
	// The go command then checks sum.golang.org directly.
	code, _, _ := newEnv(t).get("/go/goproxy/sumdb/sum.golang.org/supported", "reader")
	require.Equal(t, http.StatusNotFound, code)
}

func TestAccessAndWrites(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	code, _, hdr := e.get(base+"/@v/list", "")
	r.Equal(http.StatusUnauthorized, code)
	r.Contains(hdr.Get("WWW-Authenticate"), "Basic", "the go command sends .netrc credentials after a Basic challenge")
	code, _, _ = e.get(base+"/@v/list", "stranger")
	r.Equal(http.StatusNotFound, code)
	req, _ := http.NewRequest("PUT", e.srv.URL+base+"/@v/v9.9.9.zip", strings.NewReader("x"))
	req.SetBasicAuth("token", "admin")
	resp, err := http.DefaultClient.Do(req)
	r.NoError(err)
	resp.Body.Close()
	r.Equal(http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHostedGoReposAreRefused(t *testing.T) {
	svc := registry.New(registry.NewMemoryStore(), blob.NewMemory(), time.Now, nil)
	err := svc.CreateRepo(context.Background(), principals["admin"], registry.RepoInput{Name: "go", Format: registry.FormatGo})
	require.ErrorIs(t, err, registry.ErrInvalid, "Go has no publish command")
}
