package oci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
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

func newEnv(t *testing.T, upstreamURL string) *env {
	e := &env{t: t, clock: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	e.svc = registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.now, nil)
	ctx := context.Background()
	admin := principals["admin"]
	repos := []string{"images", "other"}
	for _, name := range repos {
		require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: name, Format: registry.FormatOCI}))
	}
	if upstreamURL != "" {
		e.svc.AllowUpstreams(registry.FormatOCI, upstreamURL)
		require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "hub", Format: registry.FormatOCI, Type: registry.TypeProxy}))
		repos = append(repos, "hub")
	}
	for _, repo := range repos {
		for name, role := range map[string]rbac.Role{"maintainer": rbac.RoleMaintainer, "developer": rbac.RoleDeveloper, "reader": rbac.RoleReader} {
			require.NoError(t, e.svc.SetGrant(ctx, admin, repo, rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: principals[name].Email, Role: role}))
		}
	}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if _, pass, ok := r.BasicAuth(); ok {
			p = principals[pass]
		}
		e.handler.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	e.handler = New(e.svc)
	e.handler.SetClock(e.now)
	t.Cleanup(e.srv.Close)
	return e
}

type resp struct {
	code int
	body string
	hdr  http.Header
}

func (r resp) errorCode() string {
	var body struct {
		Errors []struct{ Code string } `json:"errors"`
	}
	_ = json.Unmarshal([]byte(r.body), &body)
	if len(body.Errors) == 0 {
		return ""
	}
	return body.Errors[0].Code
}

func (e *env) do(method, path, as string, body []byte, hdr ...string) resp {
	if !strings.HasPrefix(path, "http") {
		path = e.srv.URL + path
	}
	req, err := http.NewRequest(method, path, bytes.NewReader(body))
	require.NoError(e.t, err)
	if as != "" {
		req.SetBasicAuth("token", as)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, string(b), res.Header}
}

const (
	manifestType = "application/vnd.oci.image.manifest.v1+json"
	indexType    = "application/vnd.oci.image.index.v1+json"
)

func imageManifest(config, layer []byte) []byte {
	b, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": manifestType,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)},
		"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(layer), "size": len(layer)}},
	})
	return b
}

// pushBlob uploads like docker: POST, PATCH the content, PUT with the digest.
func (e *env) pushBlob(repoImage, as string, content []byte) {
	r := e.do("POST", "/v2/"+repoImage+"/blobs/uploads/", as, nil)
	require.Equal(e.t, http.StatusAccepted, r.code, r.body)
	loc := r.hdr.Get("Location")
	require.NotEmpty(e.t, r.hdr.Get("Docker-Upload-UUID"))
	r = e.do("PATCH", loc, as, content, "Content-Type", "application/octet-stream")
	require.Equal(e.t, http.StatusAccepted, r.code, r.body)
	require.Equal(e.t, fmt.Sprintf("0-%d", len(content)-1), r.hdr.Get("Range"))
	loc = r.hdr.Get("Location")
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	r = e.do("PUT", loc+sep+"digest="+digest(content), as, nil)
	require.Equal(e.t, http.StatusCreated, r.code, r.body)
	require.Equal(e.t, digest(content), r.hdr.Get("Docker-Content-Digest"))
}

func (e *env) pushImage(repoImage, tag, as string) (manifest, layer []byte) {
	config, layer := []byte(`{"architecture":"amd64"}`), []byte("LAYER:"+repoImage+":"+tag)
	e.pushBlob(repoImage, as, config)
	e.pushBlob(repoImage, as, layer)
	manifest = imageManifest(config, layer)
	r := e.do("PUT", "/v2/"+repoImage+"/manifests/"+tag, as, manifest, "Content-Type", manifestType)
	require.Equal(e.t, http.StatusCreated, r.code, r.body)
	require.Equal(e.t, digest(manifest), r.hdr.Get("Docker-Content-Digest"))
	return manifest, layer
}

// ---------- Hosted ----------

func TestPing(t *testing.T) {
	e := newEnv(t, "")
	r := e.do("GET", "/v2/", "", nil)
	require.Equal(t, http.StatusUnauthorized, r.code)
	require.Contains(t, r.hdr.Get("WWW-Authenticate"), "Basic", "docker then sends the credentials from docker login")
	require.Equal(t, "registry/2.0", r.hdr.Get("Docker-Distribution-API-Version"))
	r = e.do("GET", "/v2/", "reader", nil)
	require.Equal(t, http.StatusOK, r.code)
}

func TestPushAndPull(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	manifest, layer := e.pushImage("images/team/app", "1.0", "developer")

	for _, ref := range []string{"1.0", digest(manifest)} {
		r := e.do("GET", "/v2/images/team/app/manifests/"+ref, "reader", nil, "Accept", manifestType)
		rq.Equal(200, r.code, r.body)
		rq.Equal(string(manifest), r.body)
		rq.Equal(manifestType, r.hdr.Get("Content-Type"))
		rq.Equal(digest(manifest), r.hdr.Get("Docker-Content-Digest"))
		r = e.do("HEAD", "/v2/images/team/app/manifests/"+ref, "reader", nil)
		rq.Equal(200, r.code)
		rq.Equal(fmt.Sprint(len(manifest)), r.hdr.Get("Content-Length"))
	}
	r := e.do("GET", "/v2/images/team/app/blobs/"+digest(layer), "reader", nil)
	rq.Equal(200, r.code)
	rq.Equal(string(layer), r.body)
	rq.Equal(digest(layer), r.hdr.Get("Docker-Content-Digest"))
	r = e.do("HEAD", "/v2/images/team/app/blobs/"+digest(layer), "reader", nil)
	rq.Equal(200, r.code)

	e.pushImage("images/team/app", "2.0", "developer")
	r = e.do("GET", "/v2/images/team/app/tags/list", "reader", nil)
	rq.Equal(200, r.code)
	rq.JSONEq(`{"name":"team/app","tags":["1.0","2.0"]}`, r.body)
	r = e.do("GET", "/v2/images/team/app/tags/list?n=1", "reader", nil)
	rq.JSONEq(`{"name":"team/app","tags":["1.0"]}`, r.body)
	rq.Contains(r.hdr.Get("Link"), "last=1.0")
}

func TestMonolithicUpload(t *testing.T) {
	e := newEnv(t, "")
	content := []byte("one request")
	r := e.do("POST", "/v2/images/app/blobs/uploads/?digest="+digest(content), "developer", content)
	require.Equal(t, http.StatusCreated, r.code, r.body)
	require.Equal(t, "/v2/images/app/blobs/"+digest(content), r.hdr.Get("Location"))
	r = e.do("HEAD", "/v2/images/app/blobs/"+digest(content), "developer", nil)
	require.Equal(t, 200, r.code, "the pusher sees the staged blob, so it isn't uploaded twice")
}

func TestPutWithBodyFinishesUpload(t *testing.T) {
	// containerd and podman often send the content with the final PUT.
	e := newEnv(t, "")
	content := []byte("in the put")
	r := e.do("POST", "/v2/images/app/blobs/uploads/", "developer", nil)
	r = e.do("PUT", r.hdr.Get("Location")+"?digest="+digest(content), "developer", content)
	require.Equal(t, http.StatusCreated, r.code, r.body)
}

func TestUploadErrors(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	r := e.do("POST", "/v2/images/app/blobs/uploads/?digest="+digest([]byte("x")), "developer", []byte("y"))
	rq.Equal(http.StatusBadRequest, r.code)
	rq.Equal("DIGEST_INVALID", r.errorCode())

	r = e.do("PATCH", "/v2/images/app/blobs/uploads/0123456789abcdef0123456789abcdef", "developer", []byte("x"))
	rq.Equal(http.StatusNotFound, r.code)
	rq.Equal("BLOB_UPLOAD_UNKNOWN", r.errorCode())

	r = e.do("POST", "/v2/images/app/blobs/uploads/", "developer", nil)
	loc := r.hdr.Get("Location")
	r = e.do("GET", loc, "developer", nil)
	rq.Equal(http.StatusNoContent, r.code)
	r = e.do("DELETE", loc, "developer", nil)
	rq.Equal(http.StatusNoContent, r.code)
	r = e.do("GET", loc, "developer", nil)
	rq.Equal(http.StatusNotFound, r.code)
}

func TestManifestErrors(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	config, layer := []byte("c"), []byte("never uploaded")
	e.pushBlob("images/app", "developer", config)
	m := imageManifest(config, layer)
	r := e.do("PUT", "/v2/images/app/manifests/latest", "developer", m, "Content-Type", manifestType)
	rq.Equal(http.StatusBadRequest, r.code)
	rq.Equal("MANIFEST_BLOB_UNKNOWN", r.errorCode())

	r = e.do("PUT", "/v2/images/app/manifests/"+digest([]byte("other")), "developer", imageManifest(config, config), "Content-Type", manifestType)
	rq.Equal(http.StatusBadRequest, r.code)
	rq.Equal("DIGEST_INVALID", r.errorCode())

	r = e.do("PUT", "/v2/images/app/manifests/latest", "developer", []byte("not json"), "Content-Type", manifestType)
	rq.Equal(http.StatusBadRequest, r.code)
	rq.Equal("MANIFEST_INVALID", r.errorCode())

	r = e.do("GET", "/v2/images/app/manifests/missing", "reader", nil)
	rq.Equal(http.StatusNotFound, r.code)
	rq.Equal("MANIFEST_UNKNOWN", r.errorCode())
	r = e.do("GET", "/v2/images/app/blobs/"+digest([]byte("nope")), "reader", nil)
	rq.Equal(http.StatusNotFound, r.code)
	rq.Equal("BLOB_UNKNOWN", r.errorCode())
	r = e.do("GET", "/v2/images/Bad_Name/manifests/latest", "reader", nil)
	rq.Equal(http.StatusBadRequest, r.code)
	rq.Equal("NAME_INVALID", r.errorCode())
}

func TestImageNamesMayContainOperationWords(t *testing.T) {
	e := newEnv(t, "")
	e.pushImage("images/blobs/manifests", "v1", "developer")
	r := e.do("GET", "/v2/images/blobs/manifests/manifests/v1", "reader", nil)
	require.Equal(t, 200, r.code, r.body)
}

func TestIndex(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	amd64, _ := e.pushImage("images/app", "amd64", "developer")
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": indexType,
		"manifests": []map[string]any{{"mediaType": manifestType, "digest": digest(amd64), "size": len(amd64), "platform": map[string]string{"os": "linux", "architecture": "amd64"}}},
	})
	r := e.do("PUT", "/v2/images/app/manifests/latest", "developer", index, "Content-Type", indexType)
	rq.Equal(http.StatusCreated, r.code, r.body)
	r = e.do("GET", "/v2/images/app/manifests/latest", "reader", nil)
	rq.Equal(indexType, r.hdr.Get("Content-Type"))

	missing, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": indexType,
		"manifests": []map[string]any{{"mediaType": manifestType, "digest": digest([]byte("absent")), "size": 6}},
	})
	r = e.do("PUT", "/v2/images/app/manifests/broken", "developer", missing, "Content-Type", indexType)
	rq.Equal("MANIFEST_BLOB_UNKNOWN", r.errorCode())
}

func TestAccess(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	e.pushImage("images/app", "1", "developer")
	r := e.do("PUT", "/v2/images/app/manifests/2", "reader", []byte("{}"), "Content-Type", manifestType)
	rq.Equal(http.StatusForbidden, r.code)
	rq.Equal("DENIED", r.errorCode())
	r = e.do("POST", "/v2/images/app/blobs/uploads/", "reader", nil)
	rq.Equal(http.StatusForbidden, r.code)
	r = e.do("GET", "/v2/images/app/manifests/1", "stranger", nil)
	rq.Equal(http.StatusNotFound, r.code)
	rq.Equal("NAME_UNKNOWN", r.errorCode())
	r = e.do("GET", "/v2/images/app/manifests/1", "", nil)
	rq.Equal(http.StatusUnauthorized, r.code)
	rq.Contains(r.hdr.Get("WWW-Authenticate"), "Basic")
}

func TestDeleteManifest(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	m, _ := e.pushImage("images/app", "1", "developer")
	r := e.do("DELETE", "/v2/images/app/manifests/1", "maintainer", nil)
	rq.Equal(http.StatusBadRequest, r.code, "delete by digest only")
	r = e.do("DELETE", "/v2/images/app/manifests/"+digest(m), "developer", nil)
	rq.Equal(http.StatusForbidden, r.code)
	r = e.do("DELETE", "/v2/images/app/manifests/"+digest(m), "admin", nil)
	rq.Equal(http.StatusAccepted, r.code, r.body)
	r = e.do("GET", "/v2/images/app/manifests/1", "reader", nil)
	rq.Equal(http.StatusNotFound, r.code)
}

func TestCrossRepoMount(t *testing.T) {
	rq := require.New(t)
	e := newEnv(t, "")
	_, layer := e.pushImage("images/base", "1", "developer")
	// The developer can pull from "images", so mounting into "other" is
	// just a copy they could make anyway.
	r := e.do("POST", "/v2/other/app/blobs/uploads/?mount="+digest(layer)+"&from=images/base", "developer", nil)
	rq.Equal(http.StatusCreated, r.code, r.body)
	rq.Equal(digest(layer), r.hdr.Get("Docker-Content-Digest"))

	// Without pull access to the source, the client is told to upload.
	require.NoError(t, e.svc.RemoveGrant(context.Background(), principals["admin"], "images", rbac.SubjectUser, principals["maintainer"].Email))
	r = e.do("POST", "/v2/other/app2/blobs/uploads/?mount="+digest(layer)+"&from=images/base", "maintainer", nil)
	rq.Equal(http.StatusAccepted, r.code)
	rq.NotEmpty(r.hdr.Get("Location"))
}

// ---------- Proxy ----------

// fakeRegistry is an upstream registry that requires bearer tokens, like
// Docker Hub.
type fakeRegistry struct {
	srv       *httptest.Server
	manifests map[string][]byte // "name:ref" -> manifest
	blobs     map[string][]byte
	evil      map[string][]byte
	lying     bool // send a wrong Docker-Content-Digest
	hits      sync.Map
}

func newFakeRegistry(t *testing.T) (*fakeRegistry, []byte, []byte) {
	f := &fakeRegistry{manifests: map[string][]byte{}, blobs: map[string][]byte{}, evil: map[string][]byte{}}
	config, layer := []byte(`{"os":"linux"}`), []byte("ALPINE-LAYER")
	m := imageManifest(config, layer)
	f.manifests["library/alpine:3.20"] = m
	f.manifests["library/alpine:"+digest(m)] = m
	f.blobs[digest(config)], f.blobs[digest(layer)] = config, layer
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := f.hits.LoadOrStore(r.URL.Path, &atomic.Int32{})
		c.(*atomic.Int32).Add(1)
		if r.URL.Path == "/token" {
			if !strings.HasPrefix(r.URL.Query().Get("scope"), "repository:library/alpine:pull") {
				http.Error(w, "bad scope", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"token": "t0ken", "expires_in": 300})
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0ken" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry.test",scope="repository:library/alpine:pull"`, f.srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v2/library/alpine/")
		switch {
		case strings.HasPrefix(rest, "manifests/"):
			m, ok := f.manifests["library/alpine:"+strings.TrimPrefix(rest, "manifests/")]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Type", manifestType)
			d := digest(m)
			if f.lying {
				d = digest([]byte("lie"))
			}
			w.Header().Set("Docker-Content-Digest", d)
			w.Write(m)
		case strings.HasPrefix(rest, "blobs/"):
			d := strings.TrimPrefix(rest, "blobs/")
			b, ok := f.evil[d]
			if !ok {
				b, ok = f.blobs[d]
			}
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(b)
		case rest == "tags/list":
			w.Write([]byte(`{"name":"library/alpine","tags":["3.19","3.20"]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f, m, layer
}

func (f *fakeRegistry) count(path string) int32 {
	c, ok := f.hits.Load(path)
	if !ok {
		return 0
	}
	return c.(*atomic.Int32).Load()
}

func newProxyEnv(t *testing.T) (*env, *fakeRegistry, []byte, []byte) {
	f, m, layer := newFakeRegistry(t)
	e := newEnv(t, f.srv.URL)
	e.handler.SetLibraryPrefix(func(string) bool { return true }) // as for Docker Hub
	return e, f, m, layer
}

func TestUpstreamName(t *testing.T) {
	require.Equal(t, "library/alpine", upstreamName("https://registry-1.docker.io", "alpine"))
	require.Equal(t, "bitnami/redis", upstreamName("https://registry-1.docker.io", "bitnami/redis"))
	require.Equal(t, "alpine", upstreamName("https://ghcr.io", "alpine"))
}

func TestProxyPull(t *testing.T) {
	rq := require.New(t)
	e, f, m, layer := newProxyEnv(t)
	r := e.do("GET", "/v2/hub/alpine/manifests/3.20", "reader", nil)
	rq.Equal(200, r.code, r.body)
	rq.Equal(string(m), r.body)
	rq.Equal(digest(m), r.hdr.Get("Docker-Content-Digest"))
	rq.Equal(int32(1), f.count("/token"), "anonymous bearer token from the upstream's realm")

	for _, want := range []string{"miss", "hit"} {
		r = e.do("GET", "/v2/hub/alpine/blobs/"+digest(layer), "reader", nil)
		rq.Equal(200, r.code, r.body)
		rq.Equal(string(layer), r.body)
		rq.Equal(want, r.hdr.Get("X-Hextrap-Cache"))
	}
	rq.Equal(int32(1), f.count("/v2/library/alpine/blobs/"+digest(layer)))
	r = e.do("GET", "/v2/hub/alpine/manifests/"+digest(m), "reader", nil)
	rq.Equal(200, r.code)
	rq.Equal("hit", r.hdr.Get("X-Hextrap-Cache"))

	sums, err := e.svc.PackageSummaries(context.Background(), principals["admin"], "hub")
	rq.NoError(err)
	rq.Len(sums, 1)
	rq.Equal("alpine", sums[0].Name)
	rq.Equal(registry.SourceUpstream, sums[0].Source)
}

func TestProxyRejectsTamperedContent(t *testing.T) {
	rq := require.New(t)
	e, f, m, layer := newProxyEnv(t)
	f.lying = true
	r := e.do("GET", "/v2/hub/alpine/manifests/3.20", "reader", nil)
	rq.Equal(http.StatusBadGateway, r.code)
	f.lying = false

	r = e.do("GET", "/v2/hub/alpine/manifests/3.20", "reader", nil)
	rq.Equal(200, r.code)
	f.evil[digest(layer)] = []byte("EVIL-LAYER")
	r = e.do("GET", "/v2/hub/alpine/blobs/"+digest(layer), "reader", nil)
	rq.Equal(http.StatusBadGateway, r.code)
	_, err := e.svc.StatBlob(context.Background(), principals["admin"], "hub", blob.Digest(digest(layer)))
	rq.ErrorIs(err, registry.ErrNotFound, "nothing cached")

	// A manifest fetched by digest must have that digest.
	f.manifests["library/alpine:"+digest([]byte("wanted"))] = m
	r = e.do("GET", "/v2/hub/alpine/manifests/"+digest([]byte("wanted")), "reader", nil)
	rq.Equal(http.StatusBadGateway, r.code)
}

func TestProxyOnlyFetchesBlobsOfCachedManifests(t *testing.T) {
	e, f, _, layer := newProxyEnv(t)
	r := e.do("GET", "/v2/hub/alpine/blobs/"+digest(layer), "reader", nil)
	require.Equal(t, http.StatusNotFound, r.code)
	require.Equal(t, int32(0), f.count("/v2/library/alpine/blobs/"+digest(layer)))
}

func TestProxyServesCacheWhenUpstreamIsDown(t *testing.T) {
	rq := require.New(t)
	e, f, m, layer := newProxyEnv(t)
	e.do("GET", "/v2/hub/alpine/manifests/3.20", "reader", nil)
	e.do("GET", "/v2/hub/alpine/blobs/"+digest(layer), "reader", nil)
	f.srv.Close()
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()
	r := e.do("GET", "/v2/hub/alpine/manifests/3.20", "reader", nil)
	rq.Equal(200, r.code, r.body)
	rq.Equal(string(m), r.body)
	r = e.do("GET", "/v2/hub/alpine/tags/list", "reader", nil)
	rq.Equal(200, r.code)
	rq.JSONEq(`{"name":"alpine","tags":["3.20"]}`, r.body)
}

func TestProxyGate(t *testing.T) {
	rq := require.New(t)
	e, f, _, _ := newProxyEnv(t)
	var seen upstream.Request
	e.handler.SetGate(func(_ context.Context, req upstream.Request) error {
		seen = req
		return errors.New("not allowed")
	})
	r := e.do("GET", "/v2/hub/alpine/manifests/3.20", "reader", nil)
	rq.Equal(http.StatusForbidden, r.code)
	rq.Equal("DENIED", r.errorCode())
	rq.Contains(r.body, "not allowed")
	rq.Equal("alpine", seen.Package)
	rq.Equal("3.20", seen.Version)
	rq.Equal(int32(0), f.count("/v2/library/alpine/manifests/3.20"))
}

func TestProxyIsReadOnly(t *testing.T) {
	e, _, _, _ := newProxyEnv(t)
	r := e.do("POST", "/v2/hub/alpine/blobs/uploads/", "admin", nil)
	require.Equal(t, http.StatusMethodNotAllowed, r.code)
	require.Equal(t, "UNSUPPORTED", r.errorCode())
}
