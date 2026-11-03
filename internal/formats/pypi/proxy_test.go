package pypi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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

func hexsha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeUpstream is a PEP 691 index serving the "requests" project.
type fakeUpstream struct {
	srv       *httptest.Server
	files     map[string][]byte // filename -> content
	served    map[string][]byte // overrides what's actually sent (tampering)
	extra     []map[string]any  // extra index entries
	indexHits atomic.Int32
	fileHits  sync.Map // filename -> *atomic.Int32
	delay     time.Duration
	mux       *http.ServeMux
	fileBase  string                 // absolute file links (e.g. a public file host) when set
	firewall  *upstreamtest.Firewall // in front of mux when set
}

const metadataBody = "Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\n"

func newFakeUpstream(t *testing.T) *fakeUpstream {
	u := &fakeUpstream{
		files: map[string][]byte{
			"requests-2.32.3-py3-none-any.whl": []byte("WHEEL-BYTES"),
			"requests-2.32.3.tar.gz":           []byte("SDIST-BYTES"),
			"requests-2.31.0.tar.gz":           []byte("OLD-SDIST"),
			"requests-0.1.egg":                 []byte("EGG"),
		},
		served: map[string][]byte{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/simple/requests/", func(w http.ResponseWriter, r *http.Request) {
		u.indexHits.Add(1)
		if r.Header.Get("Accept") != jsonType {
			http.Error(w, "want PEP 691", http.StatusNotAcceptable)
			return
		}
		var files []map[string]any
		for name, body := range u.files {
			f := map[string]any{
				"filename": name, "url": u.fileBase + "/packages/" + name, "hashes": map[string]string{"sha256": hexsha(body)},
				"requires-python": ">=3.8", "yanked": false, "size": len(body), "upload-time": "2024-05-29T15:37:47.444Z",
			}
			if name == "requests-2.31.0.tar.gz" {
				f["yanked"] = "security issue"
			}
			if strings.HasSuffix(name, ".whl") {
				f["core-metadata"] = map[string]string{"sha256": hexsha([]byte(metadataBody))}
			}
			files = append(files, f)
		}
		files = append(files, u.extra...)
		w.Header().Set("Content-Type", jsonType)
		json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"api-version": "1.1"}, "name": "requests", "files": files})
	})
	mux.HandleFunc("/packages/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/packages/")
		c, _ := u.fileHits.LoadOrStore(name, &atomic.Int32{})
		c.(*atomic.Int32).Add(1)
		time.Sleep(u.delay)
		if name == "requests-2.32.3-py3-none-any.whl.metadata" {
			io.WriteString(w, metadataBody)
			return
		}
		body, ok := u.served[name]
		if !ok {
			body, ok = u.files[name]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})
	mux.HandleFunc("/simple/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u.firewall != nil {
			u.firewall.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	u.mux = mux
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) hits(name string) int32 {
	c, ok := u.fileHits.Load(name)
	if !ok {
		return 0
	}
	return c.(*atomic.Int32).Load()
}

type proxyEnv struct {
	*env
	up      *fakeUpstream
	handler *Handler
	clock   time.Time
	mu      sync.Mutex
}

func (e *proxyEnv) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *proxyEnv) advance(d time.Duration) {
	e.mu.Lock()
	e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func newProxyEnv(t *testing.T) *proxyEnv { return newProxyEnvWith(t, false) }

// newProxyEnvWith builds a proxy repo; with firewall, its upstream is a
// hextrap firewall in front of the fake registry.
func newProxyEnvWith(t *testing.T, firewall bool) *proxyEnv {
	up := newFakeUpstream(t)
	e := &proxyEnv{up: up, clock: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	svc := registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.now, nil)
	if firewall {
		up.firewall = upstreamtest.NewFirewall(up.mux)
		svc.AllowFirewall(registry.FormatPyPI, up.srv.URL)
	} else {
		svc.AllowUpstreams(registry.FormatPyPI, up.srv.URL)
	}
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "proxy", Format: registry.FormatPyPI, Type: registry.TypeProxy}))
	require.NoError(t, svc.SetGrant(ctx, admin, "proxy", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "reader@acme.com", Role: rbac.RoleReader}))

	e.env = &env{t: t, svc: svc, repo: "proxy"}
	e.env.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if _, pass, ok := r.BasicAuth(); ok {
			p = principals[pass]
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

func (e *proxyEnv) index(t *testing.T) simpleJSON {
	code, body, _ := e.get("/pypi/proxy/simple/requests/", "reader", jsonType)
	require.Equal(t, 200, code, body)
	var idx simpleJSON
	require.NoError(t, json.Unmarshal([]byte(body), &idx))
	return idx
}

func filenames(idx simpleJSON) []string {
	var out []string
	for _, f := range idx.Files {
		out = append(out, f.Filename)
	}
	return out
}

func TestProxyIndexRewritesUpstream(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	idx := e.index(t)

	r.ElementsMatch([]string{"requests-2.32.3-py3-none-any.whl", "requests-2.32.3.tar.gz", "requests-2.31.0.tar.gz"}, filenames(idx),
		"unsupported legacy formats (.egg) are left out")
	r.ElementsMatch([]string{"2.31.0", "2.32.3"}, idx.Versions)
	for _, f := range idx.Files {
		r.Equal(e.srv.URL+"/pypi/proxy/files/requests/"+f.Filename, f.URL, "downloads go through hextrap")
		r.Equal(hexsha(e.up.files[f.Filename]), f.Hashes["sha256"], "upstream hashes kept")
		r.Equal(">=3.8", f.RequiresPython)
		switch f.Filename {
		case "requests-2.31.0.tar.gz":
			r.Equal("security issue", f.Yanked)
		case "requests-2.32.3-py3-none-any.whl":
			r.Equal(map[string]any{"sha256": hexsha([]byte(metadataBody))}, f.CoreMetadata)
		}
	}

	code, html, _ := e.get("/pypi/proxy/simple/requests/", "reader", "")
	r.Equal(200, code)
	r.Contains(html, `href="`+e.srv.URL+`/pypi/proxy/files/requests/requests-2.32.3.tar.gz#sha256=`)
	r.Contains(html, `data-yanked="security issue"`)
}

func TestProxyCachesOnFirstDownload(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	path := "/pypi/proxy/files/requests/requests-2.32.3-py3-none-any.whl"

	code, body, hdr := e.get(path, "reader", "")
	r.Equal(200, code, body)
	r.Equal("WHEEL-BYTES", body)
	r.Equal("miss", hdr.Get("X-Hextrap-Cache"))
	r.Equal(int32(1), e.up.hits("requests-2.32.3-py3-none-any.whl"))

	code, body, hdr = e.get(path, "reader", "")
	r.Equal(200, code)
	r.Equal("WHEEL-BYTES", body)
	r.Equal("hit", hdr.Get("X-Hextrap-Cache"))
	r.Equal(int32(1), e.up.hits("requests-2.32.3-py3-none-any.whl"), "served from the cache")

	versions, err := e.svc.Versions(context.Background(), principals["admin"], "proxy", "requests")
	r.NoError(err)
	r.Len(versions, 1)
	r.Equal(registry.SourceUpstream, versions[0].Source)
	u, _ := url.Parse(e.up.srv.URL)
	r.Equal(u.Host, versions[0].Origin)
}

func TestProxyMetadataFile(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	path := "/pypi/proxy/files/requests/requests-2.32.3-py3-none-any.whl.metadata"
	code, body, _ := e.get(path, "reader", "")
	r.Equal(200, code, body)
	r.Equal(metadataBody, body)
	code, _, hdr := e.get(path, "reader", "")
	r.Equal(200, code)
	r.Equal("hit", hdr.Get("X-Hextrap-Cache"))
}

func TestProxyRejectsTamperedFile(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.up.served["requests-2.32.3.tar.gz"] = []byte("EVIL-BYTES")
	code, body, _ := e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "reader", "")
	r.Equal(http.StatusBadGateway, code, body)
	r.Contains(body, "hash")
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "proxy", "requests")
	r.Empty(versions, "nothing cached")
}

func TestProxyKeepsServingWhenUpstreamIsDown(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, _, _ := e.get("/pypi/proxy/files/requests/requests-2.32.3-py3-none-any.whl", "reader", "")
	r.Equal(200, code)

	e.up.srv.Close()
	e.advance(upstream.IndexTTL + time.Second)

	idx := e.index(t)
	r.Equal([]string{"requests-2.32.3-py3-none-any.whl"}, filenames(idx), "falls back to what's cached")
	code, body, _ := e.get("/pypi/proxy/files/requests/requests-2.32.3-py3-none-any.whl", "reader", "")
	r.Equal(200, code)
	r.Equal("WHEEL-BYTES", body)
	code, _, _ = e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "reader", "")
	r.Equal(http.StatusBadGateway, code, "not cached and upstream unreachable")
}

func TestProxyIndexIsCachedBriefly(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.index(t)
	e.index(t)
	r.Equal(int32(1), e.up.indexHits.Load())
	e.advance(upstream.IndexTTL + time.Second)
	e.index(t)
	r.Equal(int32(2), e.up.indexHits.Load())
}

func TestProxyRefreshesIndexForNewFiles(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.index(t)
	e.up.files["requests-2.33.0.tar.gz"] = []byte("NEW")
	code, body, _ := e.get("/pypi/proxy/files/requests/requests-2.33.0.tar.gz", "reader", "")
	r.Equal(200, code, "a file missing from the cached index triggers one refresh")
	r.Equal("NEW", body)
}

func TestProxyFetchesOnceUnderConcurrency(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.up.delay = 50 * time.Millisecond
	var wg sync.WaitGroup
	codes := make([]int, 10)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _, _ = e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "reader", "")
		}(i)
	}
	wg.Wait()
	for _, c := range codes {
		r.Equal(200, c)
	}
	r.Equal(int32(1), e.up.hits("requests-2.32.3.tar.gz"))
}

func TestProxyGate(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	var seen upstream.Request
	e.handler.SetGate(func(_ context.Context, req upstream.Request) error {
		seen = req
		return errors.New("version is younger than the 7-day soak time")
	})
	code, body, _ := e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "reader", "")
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "soak time")
	r.Equal(int32(0), e.up.hits("requests-2.32.3.tar.gz"), "a blocked file is never downloaded")
	r.Equal("requests", seen.Package)
	r.Equal("2.32.3", seen.Version)
	r.Equal("requests-2.32.3.tar.gz", seen.Filename)
	r.Equal(time.Date(2024, 5, 29, 15, 37, 47, 444e6, time.UTC), seen.Published)
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "proxy", "requests")
	r.Empty(versions)
}

func TestProxyRemovedVersionStaysRemoved(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, _, _ := e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "reader", "")
	r.Equal(200, code)
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "proxy", "requests", "2.32.3"))

	r.NotContains(filenames(e.index(t)), "requests-2.32.3-py3-none-any.whl", "an admin removed this version")
	code, _, _ = e.get("/pypi/proxy/files/requests/requests-2.32.3-py3-none-any.whl", "reader", "")
	r.Equal(http.StatusNotFound, code)
	r.Equal(int32(0), e.up.hits("requests-2.32.3-py3-none-any.whl"))
}

func TestProxyIsReadOnly(t *testing.T) {
	e := newProxyEnv(t)
	code, _ := e.upload("admin", map[string]string{"name": "requests", "version": "9.9"}, "requests-9.9.tar.gz", []byte("x"))
	require.Equal(t, http.StatusMethodNotAllowed, code)
}

func TestProxyUnknownProject(t *testing.T) {
	e := newProxyEnv(t)
	code, _, _ := e.get("/pypi/proxy/simple/no-such-project/", "reader", jsonType)
	require.Equal(t, http.StatusNotFound, code)
}

func TestProxyAccess(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, _, _ := e.get("/pypi/proxy/simple/requests/", "", "")
	r.Equal(http.StatusUnauthorized, code)
	code, _, _ = e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "stranger", "")
	r.Equal(http.StatusNotFound, code)
	r.Equal(int32(0), e.up.indexHits.Load(), "no upstream traffic for unauthorized requests")
}

func TestProxyIgnoresNonHTTPFileURLs(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	e.up.extra = []map[string]any{{
		"filename": "requests-6.6.6.tar.gz", "url": "file:///etc/passwd",
		"hashes": map[string]string{"sha256": hexsha([]byte("x"))}, "yanked": false,
	}}
	r.NotContains(filenames(e.index(t)), "requests-6.6.6.tar.gz")
	code, _, _ := e.get("/pypi/proxy/files/requests/requests-6.6.6.tar.gz", "reader", "")
	r.Equal(http.StatusNotFound, code)
}

func TestProxyProjectListShowsCachedProjects(t *testing.T) {
	r := require.New(t)
	e := newProxyEnv(t)
	code, body, _ := e.get("/pypi/proxy/simple/", "reader", jsonType)
	r.Equal(200, code)
	r.JSONEq(`{"meta":{"api-version":"1.1"},"projects":[]}`, body)
	e.get("/pypi/proxy/files/requests/requests-2.32.3.tar.gz", "reader", "")
	_, body, _ = e.get("/pypi/proxy/simple/", "reader", jsonType)
	r.JSONEq(`{"meta":{"api-version":"1.1"},"projects":[{"name":"requests"}]}`, body)
}
