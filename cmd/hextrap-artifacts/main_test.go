package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/config"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/localauth"
	"hextrap.io/artifacts/internal/postgres/pgtest"
	"hextrap.io/artifacts/internal/registry"
)

func fakeIssuer(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testConfig signs in with OIDC.
func testConfig(t *testing.T, dataDir string) config.Config {
	cfg := config.Config{
		PublicURL: "https://repo.example.com", DataDir: dataDir, Tenant: "default",
		OIDC:    &config.OIDCConfig{AdminGroups: []string{"admins"}},
		Storage: config.StorageConfig{Filesystem: filepath.Join(dataDir, "blobs")},
	}
	cfg.OIDC.Issuer = fakeIssuer(t).URL
	cfg.OIDC.ClientID = "hextrap"
	cfg.OIDC.RedirectURL = cfg.PublicURL + "/auth/callback"
	cfg.OIDC.CookieSecret = strings.Repeat("x", 32)
	return cfg
}

var adminHash = func() string {
	h, err := localauth.HashPassword("correct horse")
	if err != nil {
		panic(err)
	}
	return h
}()

// localConfig is the minimal setup: one local admin, files on disk, no
// public_url.
func localConfig(dataDir string) config.Config {
	return config.Config{
		DataDir: dataDir, Tenant: "default",
		Users:   []localauth.User{{Username: "admin", PasswordHash: adminHash}},
		Admins:  []string{"admin"},
		Storage: config.StorageConfig{Filesystem: filepath.Join(dataDir, "blobs")},
	}
}

func TestBuild(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	ctx := context.Background()

	app, err := build(ctx, testConfig(t, dir), http.DefaultClient, time.Now)
	r.NoError(err)

	rec := httptest.NewRecorder()
	app.handler.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	r.Equal(200, rec.Code)

	rec = httptest.NewRecorder()
	app.handler.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login", nil))
	r.Equal(302, rec.Code)
	r.Contains(rec.Header().Get("Location"), "/authorize?")

	alice := identity.Principal{Tenant: "default", Kind: identity.KindUser, Subject: "alice"}
	r.NoError(app.registry.CreateRepo(ctx, alice, registry.RepoInput{Name: "npm", Format: registry.FormatNPM}))
	r.NoError(app.registry.Publish(ctx, alice, "npm", registry.VersionInput{Package: "p", DisplayName: "p", Version: "1.0.0",
		Files: []registry.FileInput{{Filename: "p-1.0.0.tgz", Content: strings.NewReader("data")}}}))
	raw, _, err := app.tokens.IssuePersonal(alice, "laptop", 0)
	r.NoError(err)

	// Everything survives a restart from the same data directory.
	app2, err := build(ctx, testConfig(t, dir), http.DefaultClient, time.Now)
	r.NoError(err)
	rc, _, err := app2.registry.OpenFile(ctx, alice, "npm", "p", "p-1.0.0.tgz")
	r.NoError(err)
	rc.Close()
	_, err = app2.tokens.Authenticate(raw)
	r.NoError(err)
}

func TestBuildFailsWhenIssuerUnreachable(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	cfg.OIDC.Issuer = "http://127.0.0.1:1"
	_, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	require.ErrorContains(t, err, "oidc")
}

func TestBuildFailsWhenDatabaseUnreachable(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	cfg.DatabaseURL = "postgres://hextrap:s3cret@127.0.0.1:1/hextrap?sslmode=disable&connect_timeout=2"
	_, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	require.ErrorContains(t, err, "database")
	require.NotContains(t, err.Error(), "s3cret")
}

func TestBuildWithPostgres(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	cfg := testConfig(t, t.TempDir())
	cfg.DatabaseURL = pgtest.URL(t) // skips without Postgres

	app, err := build(ctx, cfg, http.DefaultClient, time.Now)
	r.NoError(err)
	alice := identity.Principal{Tenant: "default", Kind: identity.KindUser, Subject: "alice"}
	r.NoError(app.registry.CreateRepo(ctx, alice, registry.RepoInput{Name: "npm", Format: registry.FormatNPM}))
	raw, _, err := app.tokens.IssuePersonal(alice, "laptop", 0)
	r.NoError(err)
	app.close()

	// A second replica, or a restart, sees the same state.
	cfg.DataDir = t.TempDir() // nothing comes from local files
	app2, err := build(ctx, cfg, http.DefaultClient, time.Now)
	r.NoError(err)
	defer app2.close()
	_, err = app2.registry.Repo(ctx, alice, "npm")
	r.NoError(err)
	_, err = app2.tokens.Authenticate(raw)
	r.NoError(err)
}

// fakeBucket is a minimal path-style S3 endpoint for wiring tests; request
// signing itself is verified in pkg/artifact/blob.
type fakeBucket struct {
	srv     *httptest.Server
	objects map[string][]byte
	deny    bool
}

func newFakeBucket(t *testing.T) *fakeBucket {
	b := &fakeBucket{objects: map[string][]byte{}}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.deny || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			b.objects[key] = body
		case http.MethodGet, http.MethodHead:
			obj, ok := b.objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodGet {
				w.Write(obj)
			}
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func s3Config(t *testing.T, b *fakeBucket) config.Config {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	cfg := testConfig(t, t.TempDir())
	cfg.Storage = config.StorageConfig{S3: &blob.S3Config{
		Bucket: "artifacts", Region: "us-east-1", Prefix: "prod/",
		Endpoint: b.srv.URL, ForcePathStyle: true,
	}}
	return cfg
}

func TestBuildWithS3(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	b := newFakeBucket(t)
	cfg := s3Config(t, b)
	app, err := build(ctx, cfg, http.DefaultClient, time.Now)
	r.NoError(err)

	alice := identity.Principal{Tenant: "default", Kind: identity.KindUser, Subject: "alice"}
	r.NoError(app.registry.CreateRepo(ctx, alice, registry.RepoInput{Name: "npm", Format: registry.FormatNPM}))
	r.NoError(app.registry.Publish(ctx, alice, "npm", registry.VersionInput{Package: "p", DisplayName: "p", Version: "1.0.0",
		Files: []registry.FileInput{{Filename: "p-1.0.0.tgz", Content: strings.NewReader("tarball")}}}))

	r.Len(b.objects, 1)
	for k, v := range b.objects {
		r.True(strings.HasPrefix(k, "artifacts/prod/sha256/"), k)
		r.Equal("tarball", string(v))
	}
	entries, _ := os.ReadDir(cfg.DataDir)
	for _, e := range entries {
		r.NotEqual("blobs", e.Name(), "nothing is written to local blob storage")
	}
}

func TestBuildFailsWhenS3Denied(t *testing.T) {
	b := newFakeBucket(t)
	b.deny = true
	_, err := build(context.Background(), s3Config(t, b), http.DefaultClient, time.Now)
	require.ErrorContains(t, err, "blob store")
}

func TestFilesystemStoreWarnsTestingOnly(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	_, err := build(context.Background(), testConfig(t, t.TempDir()), http.DefaultClient, time.Now)
	require.NoError(t, err)
	require.Contains(t, logs.String(), "testing only")
}

func TestBuildWithLocalUsers(t *testing.T) {
	r := require.New(t)
	app, err := build(context.Background(), localConfig(t.TempDir()), http.DefaultClient, time.Now)
	r.NoError(err)
	srv := httptest.NewServer(app.handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/auth/login")
	r.NoError(err)
	resp.Body.Close()
	r.Equal(200, resp.StatusCode, "a sign-in form, not an IdP redirect")

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noRedirect.PostForm(srv.URL+"/auth/login", url.Values{"username": {"admin"}, "password": {"correct horse"}})
	r.NoError(err)
	resp.Body.Close()
	r.Equal(http.StatusFound, resp.StatusCode)
	cookies := resp.Cookies()
	r.NotEmpty(cookies)

	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/me", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err = http.DefaultClient.Do(req)
	r.NoError(err)
	defer resp.Body.Close()
	var me map[string]any
	r.NoError(json.NewDecoder(resp.Body).Decode(&me))
	r.Equal("admin", me["subject"])
	r.Equal(true, me["instance_admin"], "admins lists local usernames")
}

func TestLinksUseRequestHostWithoutPublicURL(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	for _, tc := range []struct {
		trustProxy bool
		proto      string
		want       string
	}{
		{false, "", "http://pkgs.internal:8080/npm/npm/p/-/p-1.0.0.tgz"},
		{false, "https", "http://pkgs.internal:8080/npm/npm/p/-/p-1.0.0.tgz"}, // header ignored unless trusted
		{true, "https", "https://pkgs.internal:8080/npm/npm/p/-/p-1.0.0.tgz"},
	} {
		cfg := localConfig(t.TempDir())
		cfg.TrustProxyHeaders = tc.trustProxy
		app, err := build(ctx, cfg, http.DefaultClient, time.Now)
		r.NoError(err)
		admin := identity.Principal{Tenant: "default", Kind: identity.KindUser, Subject: "admin"}
		r.NoError(app.registry.CreateRepo(ctx, admin, registry.RepoInput{Name: "npm", Format: registry.FormatNPM}))
		r.NoError(app.registry.Publish(ctx, admin, "npm", registry.VersionInput{Package: "p", DisplayName: "p", Version: "1.0.0",
			Files: []registry.FileInput{{Filename: "p-1.0.0.tgz", Content: strings.NewReader("x")}}}))
		tok, _, err := app.tokens.IssuePersonal(admin, "t", 0)
		r.NoError(err)

		req := httptest.NewRequest("GET", "/npm/npm/p", nil)
		req.Host = "pkgs.internal:8080"
		req.Header.Set("Authorization", "Bearer "+tok)
		if tc.proto != "" {
			req.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		rec := httptest.NewRecorder()
		app.handler.ServeHTTP(rec, req)
		r.Equal(200, rec.Code, rec.Body.String())
		r.Contains(rec.Body.String(), `"tarball":"`+tc.want+`"`, "trust_proxy_headers=%v proto=%q", tc.trustProxy, tc.proto)
	}
}

func TestHashPasswordCommand(t *testing.T) {
	r := require.New(t)
	var out, errOut bytes.Buffer
	r.NoError(hashPassword(strings.NewReader("correct horse battery\n"), &out, &errOut))
	h := strings.TrimSpace(out.String())
	r.NoError(localauth.ValidateHash(h))
	r.NotContains(h, "correct horse")

	r.Error(hashPassword(strings.NewReader("\n"), &out, &errOut), "empty password")
	r.Error(hashPassword(strings.NewReader("short\n"), &out, &errOut), "too short")
}

func TestBuildConfiguresUpstreams(t *testing.T) {
	cfg := localConfig(t.TempDir())
	cfg.Upstreams.PyPI = []string{"https://pypi.org"}
	app, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	require.NoError(t, err)
	require.Equal(t, map[registry.Format][]string{registry.FormatPyPI: {"https://pypi.org"}}, app.registry.Upstreams())
}
