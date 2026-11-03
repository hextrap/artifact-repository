package server

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/edition"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/ratelimit/limitertest"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/tokens"
)

// fakeSessions maps a "session" cookie value to a principal.
type fakeSessions map[string]identity.Principal

func (f fakeSessions) Authenticate(r *http.Request) (identity.Principal, bool) {
	c, err := r.Cookie("session")
	if err != nil {
		return identity.Principal{}, false
	}
	p, ok := f[c.Value]
	return p, ok
}

type env struct {
	t        *testing.T
	srv      *httptest.Server
	reg      *registry.Service
	tok      *tokens.Manager
	sessions fakeSessions
	clock    *limitertest.FakeClock
}

func user(tenant, email string, groups ...string) identity.Principal {
	return identity.Principal{Tenant: tenant, Kind: identity.KindUser, Subject: "sub|" + email, Email: email, Groups: groups}
}

func newEnv(t *testing.T, rl ratelimit.Config) *env {
	e := &env{t: t, clock: limitertest.NewFakeClock(), sessions: fakeSessions{
		"alice": user("acme", "alice@acme.com"),
		"bob":   user("acme", "bob@acme.com"),
		"root":  user("acme", "root@acme.com", "hextrap-admins"),
		"eve":   user("evil", "eve@evil.com"),
	}}
	e.reg = registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.clock.Now, nil)
	e.tok = tokens.NewManager(tokens.NewMemoryStore(), e.clock.Now)
	e.srv = httptest.NewUnstartedServer(nil)
	e.srv.Config.Handler = New(Options{
		Registry: e.reg,
		Tokens:   e.tok,
		Sessions: e.sessions,
		Admins:   identity.InstanceAdmins{Groups: []string{"hextrap-admins"}},
		Guard:    ratelimit.NewGuard(ratelimit.StaticConfig(rl), ratelimit.NewMemory(e.clock.Now)),
		Tenant:   SubdomainTenant("repo.test"),
		BaseURL:  func(r *http.Request) string { return "http://" + r.Host },
	})
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	return e
}

type call struct {
	method, path string
	host         string // tenant subdomain; default "acme"
	session      string
	token        string
	basic        string // token sent as basic-auth password
	body         any
	contentType  string
}

func (e *env) do(c call) (int, string, http.Header) {
	var rd io.Reader
	ct := c.contentType
	switch b := c.body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case *bytes.Buffer:
		rd = b
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
		if ct == "" {
			ct = "application/json"
		}
	}
	req, err := http.NewRequest(c.method, e.srv.URL+c.path, rd)
	require.NoError(e.t, err)
	host := c.host
	if host == "" {
		host = "acme"
	}
	req.Host = host + ".repo.test"
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if c.session != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: c.session})
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.basic != "" {
		req.SetBasicAuth("__token__", c.basic)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (e *env) mustJSON(c call, wantStatus int, out any) {
	code, body, _ := e.do(c)
	require.Equal(e.t, wantStatus, code, "%s %s: %s", c.method, c.path, body)
	if out != nil {
		require.NoError(e.t, json.Unmarshal([]byte(body), out), body)
	}
}

func (e *env) createRepo(session, name, format string) {
	e.mustJSON(call{method: "POST", path: "/api/v1/repos", session: session, host: e.sessions[session].Tenant,
		body: map[string]any{"name": name, "format": format}}, 201, nil)
}

func (e *env) mintPAT(session string) string {
	var out struct {
		Token string      `json:"token"`
		Info  tokens.Info `json:"info"`
	}
	e.mustJSON(call{method: "POST", path: "/api/v1/tokens", session: session, host: e.sessions[session].Tenant,
		body: map[string]any{"name": "laptop"}}, 201, &out)
	require.True(e.t, strings.HasPrefix(out.Token, "hxr_"))
	return out.Token
}

func npmPublishBody(name, version, tarball string) map[string]any {
	s1 := sha1.Sum([]byte(tarball))
	s512 := sha512.Sum512([]byte(tarball))
	base := name[strings.LastIndex(name, "/")+1:]
	return map[string]any{
		"_id": name, "name": name, "dist-tags": map[string]string{"latest": version},
		"versions": map[string]any{version: map[string]any{"name": name, "version": version,
			"dist": map[string]any{"shasum": hex.EncodeToString(s1[:]), "integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:])}}},
		"_attachments": map[string]any{base + "-" + version + ".tgz": map[string]any{
			"data": base64.StdEncoding.EncodeToString([]byte(tarball)), "length": len(tarball)}},
	}
}

func pypiUpload(name, version string, content []byte) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{":action": "file_upload", "name": name, "version": version, "filetype": "sdist"} {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("content", name+"-"+version+".tar.gz")
	fw.Write(content)
	mw.Close()
	return &buf, mw.FormDataContentType()
}

// --- End to end ---

func TestEndToEndNPM(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "npm-internal", "npm")
	pat := e.mintPAT("alice")

	code, body, _ := e.do(call{method: "PUT", path: "/npm/npm-internal/@acme%2fui", token: pat,
		body: npmPublishBody("@acme/ui", "1.0.0", "UI-TARBALL")})
	r.Equal(201, code, body)

	code, body, _ = e.do(call{method: "GET", path: "/npm/npm-internal/@acme%2fui", token: pat})
	r.Equal(200, code)
	r.Contains(body, `"tarball":"http://acme.repo.test/npm/npm-internal/@acme/ui/-/ui-1.0.0.tgz"`)

	code, body, _ = e.do(call{method: "GET", path: "/npm/npm-internal/@acme/ui/-/ui-1.0.0.tgz", token: pat})
	r.Equal(200, code)
	r.Equal("UI-TARBALL", body)
}

func TestEndToEndPyPI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "py-internal", "pypi")
	pat := e.mintPAT("alice")

	buf, ct := pypiUpload("acme-lib", "1.0", []byte("SDIST"))
	code, body, _ := e.do(call{method: "POST", path: "/pypi/py-internal/", basic: pat, body: buf, contentType: ct})
	r.Equal(200, code, body)

	code, body, _ = e.do(call{method: "GET", path: "/pypi/py-internal/simple/acme-lib/", basic: pat})
	r.Equal(200, code)
	r.Contains(body, "acme-lib-1.0.tar.gz")
	code, body, _ = e.do(call{method: "GET", path: "/pypi/py-internal/files/acme-lib/acme-lib-1.0.tar.gz", basic: pat})
	r.Equal(200, code)
	r.Equal("SDIST", body)
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	code, _, _ := e.do(call{method: "GET", path: "/healthz"})
	require.Equal(t, 200, code)
}

// --- Authentication ---

func TestInvalidTokenIs401NotAnonymous(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "npm", "npm")
	anon := true
	e.mustJSON(call{method: "PATCH", path: "/api/v1/repos/npm", session: "alice", body: map[string]any{"anonymous_read": anon}}, 200, nil)

	code, _, hdr := e.do(call{method: "GET", path: "/npm/npm/x", token: "hxr_revoked-or-wrong"})
	require.Equal(t, 401, code)
	require.NotEmpty(t, hdr.Get("WWW-Authenticate"))
}

func TestTokenUsedOnAnotherTenantsHost(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	pat := e.mintPAT("eve")
	code, _, _ := e.do(call{method: "GET", path: "/api/v1/me", token: pat, host: "acme"})
	require.Equal(t, 401, code)
	code, _, _ = e.do(call{method: "GET", path: "/api/v1/me", session: "eve", host: "acme"})
	require.Equal(t, 401, code)
}

func TestMe(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	var me map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/me", session: "root"}, 200, &me)
	r.Equal("root@acme.com", me["email"])
	r.Equal(true, me["instance_admin"], "instance admin from config file")

	pat := e.mintPAT("root")
	e.mustJSON(call{method: "GET", path: "/api/v1/me", token: pat}, 200, &me)
	r.Equal(true, me["instance_admin"])

	e.mustJSON(call{method: "GET", path: "/api/v1/me", session: "alice"}, 200, &me)
	r.Equal(false, me["instance_admin"])
	code, _, _ := e.do(call{method: "GET", path: "/api/v1/me"})
	r.Equal(401, code)
}

func TestTokensCannotMintTokens(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	pat := e.mintPAT("alice")
	code, _, _ := e.do(call{method: "POST", path: "/api/v1/tokens", token: pat, body: map[string]any{"name": "chained"}})
	require.Equal(t, 403, code, "new tokens require a fresh SSO login")
}

func TestSessionCookieDoesNotAuthorizePackageClients(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "py", "pypi")
	buf, ct := pypiUpload("lib", "1.0", []byte("x"))
	code, _, _ := e.do(call{method: "POST", path: "/pypi/py/", session: "alice", body: buf, contentType: ct})
	require.Equal(t, 401, code, "a cross-site form post must not ride on the browser session")
}

func TestSessionMutationsRequireJSON(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	code, _, _ := e.do(call{method: "POST", path: "/api/v1/repos", session: "alice",
		body: []byte(`{"name":"x","format":"npm"}`), contentType: "text/plain"})
	require.Equal(t, 415, code)
	code, _, _ = e.do(call{method: "POST", path: "/api/v1/repos", session: "alice",
		body: []byte(`name=x&format=npm`), contentType: "application/x-www-form-urlencoded"})
	require.Equal(t, 415, code)
}

func TestPersonalTokenManagement(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	pat := e.mintPAT("alice")
	var list []tokens.Info
	e.mustJSON(call{method: "GET", path: "/api/v1/tokens", session: "alice"}, 200, &list)
	r.Len(list, 1)
	r.NotContains(fmt.Sprint(list), pat)

	code, _, _ := e.do(call{method: "DELETE", path: "/api/v1/tokens/" + list[0].ID, session: "bob"})
	r.Equal(404, code)
	code, _, _ = e.do(call{method: "DELETE", path: "/api/v1/tokens/" + list[0].ID, session: "alice"})
	r.Equal(204, code)
	code, _, _ = e.do(call{method: "GET", path: "/api/v1/me", token: pat})
	r.Equal(401, code)
}

// --- Management API ---

func TestRepoAndAccessAPI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "npm", "npm")

	code, _, _ := e.do(call{method: "GET", path: "/api/v1/repos/npm", session: "bob"})
	r.Equal(404, code)
	e.mustJSON(call{method: "PUT", path: "/api/v1/repos/npm/grants", session: "alice",
		body: map[string]any{"subject_kind": "user", "subject": "bob@acme.com", "role": "admin"}}, 200, nil)

	var repo map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm", session: "bob"}, 200, &repo)
	r.Equal("admin", repo["role"])

	var grants []map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/grants", session: "bob"}, 200, &grants)
	r.Len(grants, 2)

	code, body, _ := e.do(call{method: "PUT", path: "/api/v1/repos/npm/grants", session: "alice",
		body: map[string]any{"subject_kind": "user", "subject": "x@acme.com", "role": "owner"}})
	r.Equal(400, code, body)

	e.mustJSON(call{method: "DELETE", path: "/api/v1/repos/npm/grants?subject_kind=user&subject=sub%7Calice%40acme.com", session: "bob"}, 204, nil)
	code, body, _ = e.do(call{method: "DELETE", path: "/api/v1/repos/npm/grants?subject_kind=user&subject=bob%40acme.com", session: "bob"})
	r.Equal(409, code, "last admin: "+body)

	var repos []map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/repos", session: "alice"}, 200, &repos)
	r.Empty(repos, "alice removed")
}

func TestVersionLifecycleAPI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "npm", "npm")
	pat := e.mintPAT("alice")
	e.do(call{method: "PUT", path: "/npm/npm/p", token: pat, body: npmPublishBody("p", "1.0.0", "x")})

	var pkgs []registry.PackageSummary
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/packages", session: "alice"}, 200, &pkgs)
	r.Len(pkgs, 1)
	r.Equal("p", pkgs[0].Name)
	r.Equal(registry.SourcePublished, pkgs[0].Source)
	r.Equal(1, pkgs[0].Versions)

	act := func(action string, extra map[string]any) (int, string) {
		b := map[string]any{"package": "p", "version": "1.0.0"}
		for k, v := range extra {
			b[k] = v
		}
		code, body, _ := e.do(call{method: "POST", path: "/api/v1/repos/npm/versions/" + action, session: "alice", body: b})
		return code, body
	}
	code, _ := act("yank", map[string]any{"reason": "bad"})
	r.Equal(204, code)
	var versions []registry.Version
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/versions?package=p", session: "alice"}, 200, &versions)
	r.True(versions[0].Yanked)

	code, _ = act("delete", nil)
	r.Equal(204, code)
	var trash []registry.Version
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/trash", session: "alice"}, 200, &trash)
	r.Len(trash, 1)
	code, _ = act("restore", nil)
	r.Equal(204, code)
	code, _ = act("purge", map[string]any{"confirm": "p@9"})
	r.Equal(400, code)
	code, _ = act("purge", map[string]any{"confirm": "p@1.0.0"})
	r.Equal(204, code)
	code, _ = act("explode", nil)
	r.Equal(404, code)

	var audit []registry.AuditEntry
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/audit?limit=3", session: "alice"}, 200, &audit)
	r.Len(audit, 3)
	r.Equal("version.purge", audit[0].Action)
	r.NotEmpty(audit[0].SourceIP)

	var usage map[string]int64
	e.mustJSON(call{method: "GET", path: "/api/v1/usage", session: "alice"}, 200, &usage)
	r.Equal(int64(0), usage["storage_bytes"])
}

func TestServiceTokensAPI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.createRepo("alice", "npm", "npm")

	code, _, _ := e.do(call{method: "POST", path: "/api/v1/repos/npm/service-tokens", session: "bob",
		body: map[string]any{"name": "ci", "role": "developer"}})
	r.Equal(404, code)
	code, _, _ = e.do(call{method: "POST", path: "/api/v1/repos/npm/service-tokens", session: "alice",
		body: map[string]any{"name": "ci", "role": "admin"}})
	r.Equal(400, code)

	var out struct {
		Token string      `json:"token"`
		Info  tokens.Info `json:"info"`
	}
	e.mustJSON(call{method: "POST", path: "/api/v1/repos/npm/service-tokens", session: "alice",
		body: map[string]any{"name": "github-actions", "role": "developer"}}, 201, &out)

	code, body, _ := e.do(call{method: "PUT", path: "/npm/npm/p", token: out.Token, body: npmPublishBody("p", "1.0.0", "x")})
	r.Equal(201, code, body)
	code, _, _ = e.do(call{method: "POST", path: "/api/v1/repos/npm/versions/delete", token: out.Token,
		body: map[string]any{"package": "p", "version": "1.0.0"}})
	r.Equal(403, code, "a leaked CI token can't delete")

	var list []tokens.Info
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/service-tokens", session: "alice"}, 200, &list)
	r.Len(list, 1)

	e.mustJSON(call{method: "DELETE", path: "/api/v1/repos/npm/service-tokens/" + out.Info.ID, session: "alice"}, 204, nil)
	code, _, _ = e.do(call{method: "GET", path: "/npm/npm/p", token: out.Token})
	r.Equal(401, code)
	var grants []map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/repos/npm/grants", session: "alice"}, 200, &grants)
	r.Len(grants, 1, "the token's grant is removed with it")
}

// --- Rate limiting ---

func TestRateLimitResponses(t *testing.T) {
	r := require.New(t)
	cfg := ratelimit.DefaultConfig()
	cfg.Enabled = true
	cfg.Tenant = ratelimit.Limit{Rate: 1, Burst: 40} // alice's share: burst 20 at 0.5/s
	e := newEnv(t, cfg)
	ctx := context.Background()
	alice := e.sessions["alice"]
	r.NoError(e.reg.CreateRepo(ctx, alice, registry.RepoInput{Name: "npm", Format: registry.FormatNPM}))
	r.NoError(e.reg.CreateRepo(ctx, alice, registry.RepoInput{Name: "py", Format: registry.FormatPyPI}))
	pat, _, err := e.tok.IssuePersonal(alice, "laptop", 0)
	r.NoError(err)

	for i := 0; i < 20; i++ {
		code, _, _ := e.do(call{method: "GET", path: "/npm/npm/p", token: pat})
		r.Equal(404, code, "request %d", i)
	}
	code, body, hdr := e.do(call{method: "GET", path: "/npm/npm/p", token: pat})
	r.Equal(429, code)
	r.Equal("2", hdr.Get("Retry-After"))
	r.NotEmpty(hdr.Get("RateLimit"))
	r.JSONEq(`{"error":"rate limit exceeded for principal; retry after 2s"}`, body)

	code, body, _ = e.do(call{method: "GET", path: "/pypi/py/simple/", basic: pat})
	r.Equal(429, code)
	r.True(strings.HasPrefix(body, "rate limit exceeded"), body)

	// Bob in the same tenant still has his own share.
	code, _, _ = e.do(call{method: "GET", path: "/api/v1/me", session: "bob"})
	r.Equal(200, code)
	// Health checks are never limited.
	code, _, _ = e.do(call{method: "GET", path: "/healthz"})
	r.Equal(200, code)

	e.clock.Advance(15 * time.Second)
	code, _, _ = e.do(call{method: "GET", path: "/api/v1/me", token: pat})
	r.Equal(200, code)
}

func TestSubdomainTenant(t *testing.T) {
	f := SubdomainTenant("repo.hextrap.com")
	for host, want := range map[string]string{
		"acme.repo.hextrap.com":      "acme",
		"acme.repo.hextrap.com:8443": "acme",
		"repo.hextrap.com":           "",
		"a.b.repo.hextrap.com":       "",
		"acme.repo.hextrap.com.evil": "",
		"evil.com":                   "",
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		require.Equal(t, want, f(req), host)
	}
	require.Equal(t, "default", SingleTenant("default")(httptest.NewRequest("GET", "/", nil)))
}

func TestUnknownTenantHost(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/me", nil)
	req.Host = "repo.test"
	resp, err := http.DefaultTransport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 404, resp.StatusCode)
}

// --- Tenant isolation, generated from the route table ---

func TestTenantIsolationAcrossAllRoutes(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	ctx := context.Background()

	// Tenant acme: a private repo, a package, a service token.
	e.createRepo("alice", "shared", "npm")
	pat := e.mintPAT("alice")
	code, _, _ := e.do(call{method: "PUT", path: "/npm/shared/secret-pkg", token: pat, body: npmPublishBody("secret-pkg", "1.0.0", "TENANT-A-SECRET")})
	r.Equal(201, code)
	var svcTok struct {
		Info tokens.Info `json:"info"`
	}
	e.mustJSON(call{method: "POST", path: "/api/v1/repos/shared/service-tokens", session: "alice",
		body: map[string]any{"name": "ci", "role": "developer"}}, 201, &svcTok)
	alice := e.sessions["alice"]
	before, err := e.reg.Audit(ctx, alice, "shared", 1000)
	r.NoError(err)

	// Tenant evil: an instance admin with their own token.
	evilRoot := user("evil", "root@evil.com", "hextrap-admins")
	e.sessions["evilroot"] = evilRoot
	evilPAT := e.mintPAT("evilroot")

	values := map[string]string{
		"{repo}": "shared", "{pkg}": "secret-pkg", "{version}": "1.0.0", "{file}": "secret-pkg-1.0.0.tgz",
		"{id}": svcTok.Info.ID, "{action}": "delete", "{tag}": "latest",
	}
	secrets := []string{"secret-pkg", "TENANT-A-SECRET", svcTok.Info.ID, "alice@acme.com"}

	routes := Routes()
	r.Greater(len(routes), 25, "route table should cover the API and both formats")
	for _, rt := range routes {
		path := rt.Example
		for k, v := range values {
			path = strings.ReplaceAll(path, k, v)
		}
		body := map[string]any{"package": "secret-pkg", "version": "1.0.0", "confirm": "secret-pkg@1.0.0",
			"subject_kind": "user", "subject": "root@evil.com", "role": "admin", "name": "x", "format": "npm"}
		for _, attempt := range []call{
			{method: rt.Method, path: path, host: "evil", token: evilPAT, body: body},      // own host
			{method: rt.Method, path: path, host: "acme", token: evilPAT, body: body},      // victim's host
			{method: rt.Method, path: path, host: "acme", session: "evilroot", body: body}, // victim's host, session
		} {
			code, resp, _ := e.do(attempt)
			for _, s := range secrets {
				r.NotContains(resp, s, "%s %s (host %s) leaked tenant data", rt.Method, path, attempt.host)
			}
			if rt.RepoScoped {
				r.False(code >= 200 && code < 300, "%s %s (host %s) returned %d", rt.Method, path, attempt.host, code)
			}
		}
	}

	after, err := e.reg.Audit(ctx, alice, "shared", 1000)
	r.NoError(err)
	r.Equal(len(before), len(after), "no change was made to the victim's repo")
	versions, _ := e.reg.Versions(ctx, alice, "shared", "secret-pkg")
	r.Len(versions, 1)
}

func TestForwardedForIP(t *testing.T) {
	for _, tc := range []struct{ xff, remote, want string }{
		{"", "10.0.0.1:5000", "10.0.0.1"},
		{"203.0.113.9", "10.0.0.1:5000", "203.0.113.9"},
		// The client controls everything left of what the LB appended.
		{"1.1.1.1, 203.0.113.9", "10.0.0.1:5000", "203.0.113.9"},
		{"1.1.1.1,  203.0.113.9 ", "10.0.0.1:5000", "203.0.113.9"},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.xff != "" {
			req.Header.Set("X-Forwarded-For", tc.xff)
		}
		require.Equal(t, tc.want, ForwardedForIP(req), tc.xff)
	}
}

func TestHomeRedirectsAnonymousToSignIn(t *testing.T) {
	e := newEnv(t, ratelimit.DefaultConfig())
	code, _, hdr := e.do(call{method: "GET", path: "/"})
	require.Equal(t, http.StatusFound, code)
	require.Equal(t, "/auth/login", hdr.Get("Location"))
}

func TestAppShell(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.sessions["xss"] = user("acme", "<script>@acme.com")
	code, body, hdr := e.do(call{method: "GET", path: "/", session: "xss"})
	r.Equal(200, code)
	r.Contains(hdr.Get("Content-Type"), "text/html")

	// Layout: logo, left navigation, full-width main area.
	r.Contains(body, `points="20,2 35,12 35,28 20,38 5,28 5,12"`, "the hextrap logo")
	for _, nav := range []string{"Repositories", "Access tokens", "Account"} {
		r.Contains(body, nav)
	}
	r.Contains(body, `class="sidebar"`)
	r.Contains(body, `data-base="http://acme.repo.test"`, "the app builds client snippets from the server's base URL")

	// Data from the identity provider is escaped.
	r.Contains(body, "&lt;script&gt;@acme.com")
	r.NotContains(body, "<script>@acme.com")

	// Scripts and styles come only from files the server ships.
	r.Contains(body, `<script src="/ui/app.js"`)
	r.Contains(body, `<link rel="stylesheet" href="/ui/app.css">`)
	r.NotRegexp(`<script>`, body, "no inline scripts")
	r.NotContains(body, `style="`, "no inline styles")

	csp := hdr.Get("Content-Security-Policy")
	r.Contains(csp, "default-src 'self'")
	r.Contains(csp, "frame-ancestors 'none'")
	r.NotContains(csp, "unsafe-inline")
	r.Equal("DENY", hdr.Get("X-Frame-Options"))
	r.Equal("nosniff", hdr.Get("X-Content-Type-Options"))
}

func TestUIAssets(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	for path, ctype := range map[string]string{
		"/ui/app.js":      "text/javascript",
		"/ui/app.css":     "text/css",
		"/ui/favicon.svg": "image/svg+xml",
	} {
		code, body, hdr := e.do(call{method: "GET", path: path})
		r.Equal(200, code, path)
		r.Contains(hdr.Get("Content-Type"), ctype, path)
		r.NotEmpty(body, path)
	}
	_, js, _ := e.do(call{method: "GET", path: "/ui/app.js"})
	for _, endpoint := range []string{"/api/v1/repos", "/api/v1/tokens", "/api/v1/me"} {
		r.Contains(js, endpoint)
	}
	r.NotContains(js, "innerHTML", "the UI builds DOM nodes, so API data can't inject markup")

	code, _, _ := e.do(call{method: "GET", path: "/ui/../server.go"})
	r.NotEqual(200, code)
	code, _, _ = e.do(call{method: "GET", path: "/nope"})
	r.Equal(404, code)
}

// Self-hosted installs promise no outbound calls, and that includes the
// browser: no CDNs, web fonts or analytics.
func TestUIMakesNoExternalRequests(t *testing.T) {
	entries, err := uiFiles.ReadDir("ui")
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	allowed := regexp.MustCompile(`http://www\.w3\.org/2000/svg`)
	external := regexp.MustCompile(`(https?:)?//[a-zA-Z0-9.-]+\.[a-z]{2,}`)
	for _, entry := range entries {
		b, err := uiFiles.ReadFile("ui/" + entry.Name())
		require.NoError(t, err)
		for _, m := range external.FindAllString(allowed.ReplaceAllString(string(b), ""), -1) {
			t.Errorf("%s references an external URL: %s", entry.Name(), m)
		}
	}
}

func TestProxyRepoAPI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.reg.AllowUpstreams(registry.FormatPyPI, "https://pypi.org")

	var upstreams map[string][]map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/upstreams", session: "alice"}, 200, &upstreams)
	r.Equal(map[string][]map[string]any{"pypi": {{"url": "https://pypi.org", "firewall": false}}}, upstreams)
	code, _, _ := e.do(call{method: "GET", path: "/api/v1/upstreams"})
	r.Equal(401, code)

	var repo map[string]any
	e.mustJSON(call{method: "POST", path: "/api/v1/repos", session: "alice",
		body: map[string]any{"name": "pypi-proxy", "format": "pypi", "type": "proxy"}}, 201, &repo)
	r.Equal("proxy", repo["type"])
	r.Equal("https://pypi.org", repo["upstream"])

	code, body, _ := e.do(call{method: "POST", path: "/api/v1/repos", session: "alice",
		body: map[string]any{"name": "evil", "format": "pypi", "type": "proxy", "upstream": "http://169.254.169.254"}})
	r.Equal(400, code, body)
}

func TestConnectProxyToFirewallAPI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.reg.AllowUpstreams(registry.FormatPyPI, "https://pypi.org")
	e.mustJSON(call{method: "POST", path: "/api/v1/repos", session: "alice",
		body: map[string]any{"name": "pypi-proxy", "format": "pypi", "type": "proxy"}}, 201, nil)
	e.reg.AllowFirewall(registry.FormatPyPI, "https://pypi.hextrap.com")

	var upstreams map[string][]map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/upstreams", session: "alice"}, 200, &upstreams)
	r.Equal(map[string]any{"url": "https://pypi.hextrap.com", "firewall": true}, upstreams["pypi"][0])

	var repo map[string]any
	e.mustJSON(call{method: "PATCH", path: "/api/v1/repos/pypi-proxy", session: "alice",
		body: map[string]any{"upstream": "https://pypi.hextrap.com"}}, 200, &repo)
	r.Equal("https://pypi.hextrap.com", repo["upstream"])
	r.Equal(true, repo["firewall"])

	var me map[string]any
	e.mustJSON(call{method: "GET", path: "/api/v1/me", session: "alice"}, 200, &me)
	r.Equal(edition.Name, me["edition"], "the UI shows the connect prompts only when self-hosted")
}

func TestEndToEndMaven(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.mustJSON(call{method: "POST", path: "/api/v1/repos", session: "alice", body: map[string]any{"name": "releases", "format": "maven"}}, 201, nil)
	pat := e.mintPAT("alice")

	path := "/maven/releases/com/acme/widgets/1.0.0/widgets-1.0.0.jar"
	code, body, _ := e.do(call{method: "PUT", path: path, basic: pat, body: []byte("JAR"), contentType: "application/java-archive"})
	r.Equal(201, code, body)
	code, body, _ = e.do(call{method: "GET", path: path, basic: pat})
	r.Equal(200, code)
	r.Equal("JAR", body)
	code, body, _ = e.do(call{method: "GET", path: "/maven/releases/com/acme/widgets/maven-metadata.xml", basic: pat})
	r.Equal(200, code)
	r.Contains(body, "<version>1.0.0</version>")

	code, _, hdr := e.do(call{method: "GET", path: path, basic: "hxr_wrong"})
	r.Equal(401, code)
	r.Contains(hdr.Get("WWW-Authenticate"), "Basic", "Maven needs a Basic challenge to send credentials")
}

func TestEndToEndOCI(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, ratelimit.DefaultConfig())
	e.mustJSON(call{method: "POST", path: "/api/v1/repos", session: "alice", body: map[string]any{"name": "images", "format": "oci"}}, 201, nil)
	pat := e.mintPAT("alice")

	code, _, hdr := e.do(call{method: "GET", path: "/v2/"})
	r.Equal(401, code)
	r.Contains(hdr.Get("WWW-Authenticate"), "Basic", "docker login needs a Basic challenge")
	code, _, _ = e.do(call{method: "GET", path: "/v2/", basic: pat})
	r.Equal(200, code)

	layer := []byte("LAYER")
	sum := sha256.Sum256(layer)
	d := "sha256:" + hex.EncodeToString(sum[:])
	code, body, _ := e.do(call{method: "POST", path: "/v2/images/app/blobs/uploads/?digest=" + d, basic: pat, body: layer, contentType: "application/octet-stream"})
	r.Equal(201, code, body)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"` + d + `","size":5},"layers":[]}`)
	code, body, _ = e.do(call{method: "PUT", path: "/v2/images/app/manifests/1.0", basic: pat, body: manifest, contentType: "application/vnd.oci.image.manifest.v1+json"})
	r.Equal(201, code, body)
	code, body, _ = e.do(call{method: "GET", path: "/v2/images/app/manifests/1.0", basic: pat})
	r.Equal(200, code)
	r.Equal(string(manifest), body)

	code, body, _ = e.do(call{method: "GET", path: "/v2/images/app/manifests/1.0", basic: "hxr_wrong"})
	r.Equal(401, code)
	r.Contains(body, `"code":"UNAUTHORIZED"`, "docker shows errors[].code")
}
