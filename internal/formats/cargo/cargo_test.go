package cargo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func user(email string) identity.Principal {
	return identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub|" + email, Email: email}
}

var principals = map[string]identity.Principal{
	"admin":      user("admin@acme.com"),
	"maintainer": user("maint@acme.com"),
	"developer":  user("dev@acme.com"),
	"reader":     user("reader@acme.com"),
	"stranger":   user("stranger@acme.com"),
}

type env struct {
	t       *testing.T
	srv     *httptest.Server
	svc     *registry.Service
	handler *Handler
	mu      sync.Mutex
	clock   time.Time
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func newEnv(t *testing.T, upstreamURL string) *env { return newEnvWith(t, upstreamURL, false) }

// newEnvWith builds the repos; with firewall, the proxy's upstream is a
// hextrap firewall.
func newEnvWith(t *testing.T, upstreamURL string, firewall bool) *env {
	e := &env{t: t, clock: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	e.svc = registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.now, nil)
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "crates", Format: registry.FormatCargo}))
	repos := []string{"crates"}
	if upstreamURL != "" {
		if firewall {
			e.svc.AllowFirewall(registry.FormatCargo, upstreamURL)
		} else {
			e.svc.AllowUpstreams(registry.FormatCargo, upstreamURL)
		}
		require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "crates-io", Format: registry.FormatCargo, Type: registry.TypeProxy}))
		repos = append(repos, "crates-io")
	}
	for _, repo := range repos {
		for name, role := range map[string]rbac.Role{"maintainer": rbac.RoleMaintainer, "developer": rbac.RoleDeveloper, "reader": rbac.RoleReader} {
			require.NoError(t, e.svc.SetGrant(ctx, admin, repo, rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: principals[name].Email, Role: role}))
		}
	}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if tok := r.Header.Get("Authorization"); tok != "" {
			p = principals[tok] // cargo sends the bare token
		}
		e.handler.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	e.handler = New(e.svc, func(*http.Request) string { return e.srv.URL })
	e.handler.SetClock(e.now)
	if firewall {
		e.handler.AddFirewall(upstreamURL, upstreamtest.Username, upstreamtest.Password)
	}
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(method, path, as string, body []byte) (int, string, http.Header) {
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	require.NoError(e.t, err)
	if as != "" {
		req.Header.Set("Authorization", as)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// publishBody is what `cargo publish` sends: a little-endian u32 length and
// JSON metadata, then a u32 length and the .crate file.
func publishBody(name, vers string, crate []byte) []byte {
	meta, _ := json.Marshal(map[string]any{
		"name": name, "vers": vers,
		"deps": []map[string]any{
			{"name": "serde", "version_req": "^1.0", "features": []string{"derive"}, "optional": false,
				"default_features": true, "target": nil, "kind": "normal", "registry": "https://github.com/rust-lang/crates.io-index"},
			{"name": "rand_core", "version_req": "^0.6", "features": []string{}, "optional": true,
				"default_features": true, "target": nil, "kind": "normal", "explicit_name_in_toml": "rand-core"},
		},
		"features": map[string][]string{"default": {}, "fast": {"dep:rand_core"}},
		"authors":  []string{"Acme"}, "description": "utilities", "license": "MIT", "links": nil, "rust_version": "1.70",
	})
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(len(meta)))
	buf.Write(meta)
	binary.Write(&buf, binary.LittleEndian, uint32(len(crate)))
	buf.Write(crate)
	return buf.Bytes()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type indexLine struct {
	Name     string              `json:"name"`
	Vers     string              `json:"vers"`
	Cksum    string              `json:"cksum"`
	Yanked   bool                `json:"yanked"`
	Features map[string][]string `json:"features"`
	V        int                 `json:"v"`
	Rust     string              `json:"rust_version"`
	Deps     []struct {
		Name     string   `json:"name"`
		Req      string   `json:"req"`
		Features []string `json:"features"`
		Optional bool     `json:"optional"`
		Kind     string   `json:"kind"`
		Registry string   `json:"registry"`
		Package  string   `json:"package"`
	} `json:"deps"`
}

func (e *env) index(path, as string) []indexLine {
	code, body, _ := e.do("GET", path, as, nil)
	require.Equal(e.t, 200, code, body)
	var out []indexLine
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		var l indexLine
		require.NoError(e.t, json.Unmarshal(sc.Bytes(), &l), sc.Text())
		out = append(out, l)
	}
	return out
}

// ---------- Hosted ----------

func TestConfigJSON(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	code, body, _ := e.do("GET", "/cargo/crates/index/config.json", "reader", nil)
	r.Equal(200, code)
	var cfg map[string]any
	r.NoError(json.Unmarshal([]byte(body), &cfg))
	r.Equal(e.srv.URL+"/cargo/crates/api/v1/crates", cfg["dl"])
	r.Equal(e.srv.URL+"/cargo/crates", cfg["api"])
	r.Equal(true, cfg["auth-required"])
}

func TestPublishAndInstall(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	crate := []byte("CRATE-1.2.0")
	code, body, _ := e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("acme-utils", "1.2.0", crate))
	r.Equal(200, code, body)
	r.Contains(body, `"warnings"`)

	lines := e.index("/cargo/crates/index/ac/me/acme-utils", "reader")
	r.Len(lines, 1)
	l := lines[0]
	r.Equal("acme-utils", l.Name)
	r.Equal("1.2.0", l.Vers)
	r.Equal(sha(crate), l.Cksum)
	r.False(l.Yanked)
	r.Equal(2, l.V)
	r.Equal("1.70", l.Rust)
	r.Equal([]string{"dep:rand_core"}, l.Features["fast"])
	r.Len(l.Deps, 2)
	r.Equal("serde", l.Deps[0].Name)
	r.Equal("^1.0", l.Deps[0].Req, "publish's version_req becomes the index's req")
	r.Equal("https://github.com/rust-lang/crates.io-index", l.Deps[0].Registry)
	r.Equal("rand-core", l.Deps[1].Name, "a renamed dependency uses its name in Cargo.toml")
	r.Equal("rand_core", l.Deps[1].Package, "with the real crate name in package")

	code, body, _ = e.do("GET", "/cargo/crates/api/v1/crates/acme-utils/1.2.0/download", "reader", nil)
	r.Equal(200, code)
	r.Equal("CRATE-1.2.0", body)

	e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("acme-utils", "1.3.0", []byte("NEWER")))
	r.Len(e.index("/cargo/crates/index/ac/me/acme-utils", "reader"), 2)
}

func TestIndexPaths(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	for name, path := range map[string]string{"a": "1/a", "ab": "2/ab", "abc": "3/a/abc", "Serde": "se/rd/serde"} {
		code, _, _ := e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody(name, "1.0.0", []byte(name)))
		r.Equal(200, code, name)
		r.Len(e.index("/cargo/crates/index/"+path, "reader"), 1, name)
	}
	code, _, _ := e.do("GET", "/cargo/crates/index/xx/yy/serde", "reader", nil)
	r.Equal(http.StatusNotFound, code, "wrong prefix for the name")
}

func TestRepublishRejected(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("acme-utils", "1.0.0", []byte("one")))
	code, body, _ := e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("acme-utils", "1.0.0", []byte("two")))
	r.Equal(http.StatusConflict, code)
	var errs struct {
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	r.NoError(json.Unmarshal([]byte(body), &errs))
	r.NotEmpty(errs.Errors, "cargo shows errors[].detail")
	code, _, _ = e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("Acme_Utils", "1.0.0", []byte("three")))
	r.Equal(http.StatusConflict, code, "crate names are unique ignoring case and -/_")
}

func TestYank(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("acme-utils", "1.0.0", []byte("x")))
	code, _, _ := e.do("DELETE", "/cargo/crates/api/v1/crates/acme-utils/1.0.0/yank", "developer", nil)
	r.Equal(http.StatusForbidden, code)
	code, body, _ := e.do("DELETE", "/cargo/crates/api/v1/crates/acme-utils/1.0.0/yank", "maintainer", nil)
	r.Equal(200, code)
	r.JSONEq(`{"ok":true}`, body)
	r.True(e.index("/cargo/crates/index/ac/me/acme-utils", "reader")[0].Yanked)
	code, _, _ = e.do("GET", "/cargo/crates/api/v1/crates/acme-utils/1.0.0/download", "reader", nil)
	r.Equal(200, code, "yanked crates still download for existing lockfiles")
	code, _, _ = e.do("PUT", "/cargo/crates/api/v1/crates/acme-utils/1.0.0/unyank", "maintainer", nil)
	r.Equal(200, code)
	r.False(e.index("/cargo/crates/index/ac/me/acme-utils", "reader")[0].Yanked)
}

func TestPublishValidation(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	for name, body := range map[string][]byte{
		"truncated":   publishBody("ok", "1.0.0", []byte("x"))[:10],
		"bad name":    publishBody("9lives", "1.0.0", []byte("x")),
		"bad version": publishBody("ok", "1.0", []byte("x")),
		"not a body":  []byte("{}"),
	} {
		code, _, _ := e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", body)
		r.Equal(http.StatusBadRequest, code, name)
	}
}

func TestAccess(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	code, _, _ := e.do("GET", "/cargo/crates/index/config.json", "", nil)
	r.Equal(http.StatusUnauthorized, code, "cargo retries with the token after a 401")
	code, _, _ = e.do("PUT", "/cargo/crates/api/v1/crates/new", "reader", publishBody("x1", "1.0.0", []byte("x")))
	r.Equal(http.StatusForbidden, code)
	code, _, _ = e.do("GET", "/cargo/crates/index/config.json", "stranger", nil)
	r.Equal(http.StatusNotFound, code)
}

func TestSearch(t *testing.T) {
	e := newEnv(t, "")
	e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("acme-utils", "1.0.0", []byte("x")))
	e.do("PUT", "/cargo/crates/api/v1/crates/new", "developer", publishBody("other", "1.0.0", []byte("y")))
	code, body, _ := e.do("GET", "/cargo/crates/api/v1/crates?q=acme", "reader", nil)
	require.Equal(t, 200, code)
	require.JSONEq(t, `{"crates":[{"name":"acme-utils","max_version":"1.0.0","description":""}],"meta":{"total":1}}`, body)
}

// ---------- Proxy ----------

type fakeCratesIO struct {
	srv    *httptest.Server
	crates map[string][]byte // "name/version" -> .crate
	evil   map[string][]byte
	hits   sync.Map
	// firewall, when set, guards the registry, and config.json embeds the
	// credentials in dl the way codeproxy does.
	firewall *upstreamtest.Firewall
	registry http.Handler
}

func newFakeCratesIO(t *testing.T) *fakeCratesIO {
	f := &fakeCratesIO{crates: map[string][]byte{
		"serde/1.0.200": []byte("SERDE-200"),
		"serde/1.0.201": []byte("SERDE-201"),
	}, evil: map[string][]byte{}}
	var registryHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		c, _ := f.hits.LoadOrStore(r.Method+" "+r.URL.Path, &atomic.Int32{})
		c.(*atomic.Int32).Add(1)
		switch {
		case r.URL.Path == "/config.json":
			dl := f.srv.URL + "/dl"
			if f.firewall != nil {
				dl = strings.Replace(dl, "://", "://"+upstreamtest.Username+":"+upstreamtest.Password+"@", 1)
			}
			json.NewEncoder(w).Encode(map[string]string{"dl": dl, "api": "https://crates.io"})
		case r.URL.Path == "/se/rd/serde":
			for _, v := range []string{"1.0.200", "1.0.201"} {
				line, _ := json.Marshal(map[string]any{"name": "serde", "vers": v, "deps": []any{}, "cksum": sha(f.crates["serde/"+v]),
					"features": map[string]any{}, "yanked": false, "v": 2})
				w.Write(append(line, '\n'))
			}
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			key := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/dl/"), "/download")
			body, ok := f.evil[key]
			if !ok {
				body, ok = f.crates[key]
			}
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Last-Modified", "Mon, 15 Jan 2024 10:00:00 GMT")
			if r.Method == http.MethodGet {
				w.Write(body)
			}
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

func (f *fakeCratesIO) count(key string) int32 {
	c, ok := f.hits.Load(key)
	if !ok {
		return 0
	}
	return c.(*atomic.Int32).Load()
}

func TestProxyIndexAndConfig(t *testing.T) {
	r := require.New(t)
	f := newFakeCratesIO(t)
	e := newEnv(t, f.srv.URL)
	lines := e.index("/cargo/crates-io/index/se/rd/serde", "reader")
	r.Len(lines, 2)
	_, body, _ := e.do("GET", "/cargo/crates-io/index/config.json", "reader", nil)
	r.Contains(body, e.srv.URL+"/cargo/crates-io/api/v1/crates", "downloads come through hextrap")
}

func TestProxyCachesCrate(t *testing.T) {
	r := require.New(t)
	f := newFakeCratesIO(t)
	e := newEnv(t, f.srv.URL)
	for _, want := range []string{"miss", "hit"} {
		code, body, hdr := e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
		r.Equal(200, code, body)
		r.Equal("SERDE-201", body)
		r.Equal(want, hdr.Get("X-Hextrap-Cache"))
	}
	r.Equal(int32(1), f.count("GET /dl/serde/1.0.201/download"))
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "crates-io", "serde")
	r.Len(versions, 1)
	r.Equal(registry.SourceUpstream, versions[0].Source)
}

func TestProxyRejectsTamperedCrate(t *testing.T) {
	r := require.New(t)
	f := newFakeCratesIO(t)
	f.evil["serde/1.0.201"] = []byte("EVIL")
	e := newEnv(t, f.srv.URL)
	code, _, _ := e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
	r.Equal(http.StatusBadGateway, code)
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "crates-io", "serde")
	r.Empty(versions)
}

func TestProxyServesCacheWhenUpstreamIsDown(t *testing.T) {
	r := require.New(t)
	f := newFakeCratesIO(t)
	e := newEnv(t, f.srv.URL)
	code, _, _ := e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
	r.Equal(200, code)
	f.srv.Close()
	e.advance(upstream.IndexTTL + time.Second)

	lines := e.index("/cargo/crates-io/index/se/rd/serde", "reader")
	r.Len(lines, 1, "only what's cached")
	r.Equal("1.0.201", lines[0].Vers)
	code, body, _ := e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
	r.Equal(200, code)
	r.Equal("SERDE-201", body)
}

func TestProxyRemovedVersion(t *testing.T) {
	r := require.New(t)
	f := newFakeCratesIO(t)
	e := newEnv(t, f.srv.URL)
	e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "crates-io", "serde", "1.0.201"))
	lines := e.index("/cargo/crates-io/index/se/rd/serde", "reader")
	r.Len(lines, 1)
	r.Equal("1.0.200", lines[0].Vers)
	code, _, _ := e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
	r.Equal(http.StatusNotFound, code)
}

func TestProxyGate(t *testing.T) {
	r := require.New(t)
	f := newFakeCratesIO(t)
	e := newEnv(t, f.srv.URL)
	var seen upstream.Request
	e.handler.SetGate(func(_ context.Context, req upstream.Request) error {
		seen = req
		return errors.New("too new")
	})
	code, body, _ := e.do("GET", "/cargo/crates-io/api/v1/crates/serde/1.0.201/download", "reader", nil)
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "too new")
	r.Equal(int32(0), f.count("GET /dl/serde/1.0.201/download"), "never downloaded")
	r.Equal("serde", seen.Package)
	r.Equal("1.0.201", seen.Version)
	r.Equal(time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC), seen.Published)
}

func TestProxyIsReadOnly(t *testing.T) {
	f := newFakeCratesIO(t)
	e := newEnv(t, f.srv.URL)
	code, _, _ := e.do("PUT", "/cargo/crates-io/api/v1/crates/new", "admin", publishBody("x1", "1.0.0", []byte("x")))
	require.Equal(t, http.StatusMethodNotAllowed, code)
}
