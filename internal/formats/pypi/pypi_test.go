package pypi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
)

func user(email string) identity.Principal {
	return identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub|" + email, Email: email}
}

var principals = map[string]identity.Principal{
	"admin":     user("admin@acme.com"),
	"developer": user("dev@acme.com"),
	"reader":    user("reader@acme.com"),
	"stranger":  user("stranger@acme.com"),
}

type env struct {
	t   *testing.T
	srv *httptest.Server
	svc *registry.Service
	// repo receives uploads; "internal" when empty.
	repo string
}

func newEnv(t *testing.T) *env {
	svc := registry.New(registry.NewMemoryStore(), blob.NewMemory(), func() time.Time {
		return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	}, nil)
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "internal", Format: registry.FormatPyPI}))
	require.NoError(t, svc.SetGrant(ctx, admin, "internal", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "dev@acme.com", Role: rbac.RoleDeveloper}))
	require.NoError(t, svc.SetGrant(ctx, admin, "internal", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "reader@acme.com", Role: rbac.RoleReader}))

	e := &env{t: t, svc: svc}
	var h *Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if _, pass, ok := r.BasicAuth(); ok {
			p = principals[pass]
		}
		h.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	h = New(svc, func(*http.Request) string { return e.srv.URL })
	t.Cleanup(e.srv.Close)
	return e
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *env) get(path, as, accept string) (int, string, http.Header) {
	req, err := http.NewRequest("GET", e.srv.URL+path, nil)
	require.NoError(e.t, err)
	if as != "" {
		req.SetBasicAuth("__token__", as)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := noRedirect.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// upload sends the multipart form twine and uv send to the legacy API.
func (e *env) upload(as string, fields map[string]string, filename string, content []byte) (int, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	sha := sha256.Sum256(content)
	md := md5.Sum(content)
	defaults := map[string]string{
		":action": "file_upload", "protocol_version": "1", "metadata_version": "2.1",
		"filetype": "bdist_wheel", "pyversion": "py3",
		"sha256_digest": hex.EncodeToString(sha[:]), "md5_digest": hex.EncodeToString(md[:]),
	}
	if strings.HasSuffix(filename, ".tar.gz") {
		defaults["filetype"], defaults["pyversion"] = "sdist", "source"
	}
	for k, v := range fields {
		defaults[k] = v
	}
	for k, v := range defaults {
		require.NoError(e.t, mw.WriteField(k, v))
	}
	fw, err := mw.CreateFormFile("content", filename)
	require.NoError(e.t, err)
	_, _ = fw.Write(content)
	require.NoError(e.t, mw.Close())

	repo := e.repo
	if repo == "" {
		repo = "internal"
	}
	req, err := http.NewRequest("POST", e.srv.URL+"/pypi/"+repo+"/", &buf)
	require.NoError(e.t, err)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if as != "" {
		req.SetBasicAuth("__token__", as)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func wheel(t *testing.T, dist, version, requiresPython string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(dist + "-" + version + ".dist-info/METADATA")
	require.NoError(t, err)
	fmt.Fprintf(w, "Metadata-Version: 2.1\nName: %s\nVersion: %s\nRequires-Python: %s\n", dist, version, requiresPython)
	w, _ = zw.Create(dist + "/__init__.py")
	w.Write([]byte("x = 1\n"))
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

type simpleJSON struct {
	Meta  map[string]string `json:"meta"`
	Name  string            `json:"name"`
	Files []struct {
		Filename       string            `json:"filename"`
		URL            string            `json:"url"`
		Hashes         map[string]string `json:"hashes"`
		RequiresPython string            `json:"requires-python"`
		Yanked         any               `json:"yanked"`
		CoreMetadata   any               `json:"core-metadata"`
		Size           int64             `json:"size"`
	} `json:"files"`
	Versions []string `json:"versions"`
}

func TestUploadAndInstall(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	whl := wheel(t, "acme_utils", "1.2.0", ">=3.9")

	code, body := e.upload("developer", map[string]string{"name": "Acme.Utils", "version": "1.2.0", "requires_python": ">=3.9"},
		"acme_utils-1.2.0-py3-none-any.whl", whl)
	r.Equal(200, code, body)
	code, body = e.upload("developer", map[string]string{"name": "Acme.Utils", "version": "1.2.0", "requires_python": ">=3.9"},
		"acme.utils-1.2.0.tar.gz", []byte("sdist"))
	r.Equal(200, code, body)

	// PEP 691 JSON
	code, body, hdr := e.get("/pypi/internal/simple/acme-utils/", "reader", "application/vnd.pypi.simple.v1+json")
	r.Equal(200, code, body)
	r.Equal("application/vnd.pypi.simple.v1+json", hdr.Get("Content-Type"))
	var idx simpleJSON
	r.NoError(json.Unmarshal([]byte(body), &idx))
	r.Equal("1.1", idx.Meta["api-version"])
	r.Equal("acme-utils", idx.Name)
	r.Equal([]string{"1.2.0"}, idx.Versions)
	r.Len(idx.Files, 2, "the .metadata sibling is not listed as a distribution")
	f := idx.Files[0]
	r.Equal("acme_utils-1.2.0-py3-none-any.whl", f.Filename)
	sha := sha256.Sum256(whl)
	r.Equal(hex.EncodeToString(sha[:]), f.Hashes["sha256"])
	r.Equal(">=3.9", f.RequiresPython)
	r.Equal(false, f.Yanked)
	r.Equal(int64(len(whl)), f.Size)
	r.IsType(map[string]any{}, f.CoreMetadata, "PEP 714 metadata advertised for wheels")
	r.Equal(false, idx.Files[1].CoreMetadata, "no metadata for sdists")

	// Download the wheel and its metadata (PEP 658).
	code, got, _ := e.get(strings.TrimPrefix(f.URL, e.srv.URL), "reader", "")
	r.Equal(200, code)
	r.Equal(string(whl), got)
	code, meta, _ := e.get(strings.TrimPrefix(f.URL, e.srv.URL)+".metadata", "reader", "")
	r.Equal(200, code)
	r.Contains(meta, "Requires-Python: >=3.9")
	metaSHA := sha256.Sum256([]byte(meta))
	r.Equal(hex.EncodeToString(metaSHA[:]), f.CoreMetadata.(map[string]any)["sha256"])

	// PEP 503 HTML (pip's default without Accept header)
	code, html, hdr := e.get("/pypi/internal/simple/acme-utils/", "reader", "")
	r.Equal(200, code)
	r.Contains(hdr.Get("Content-Type"), "text/html")
	r.Contains(html, `#sha256=`+hex.EncodeToString(sha[:]))
	r.Contains(html, `data-requires-python="&gt;=3.9"`)
	r.Contains(html, `data-dist-info-metadata="sha256=`)
	r.Contains(html, `data-core-metadata="sha256=`)
	r.Contains(html, ">acme_utils-1.2.0-py3-none-any.whl</a>")
}

func TestProjectList(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.upload("developer", map[string]string{"name": "zeta", "version": "1.0"}, "zeta-1.0.tar.gz", []byte("z"))
	e.upload("developer", map[string]string{"name": "alpha", "version": "1.0"}, "alpha-1.0.tar.gz", []byte("a"))

	code, body, _ := e.get("/pypi/internal/simple/", "reader", "application/vnd.pypi.simple.v1+json")
	r.Equal(200, code)
	r.JSONEq(`{"meta":{"api-version":"1.1"},"projects":[{"name":"alpha"},{"name":"zeta"}]}`, body)

	code, html, _ := e.get("/pypi/internal/simple/", "reader", "text/html")
	r.Equal(200, code)
	r.Contains(html, `<a href="alpha/">alpha</a>`)
}

func TestNonNormalizedProjectRedirects(t *testing.T) {
	e := newEnv(t)
	e.upload("developer", map[string]string{"name": "Acme_Utils", "version": "1.0"}, "acme_utils-1.0.tar.gz", []byte("a"))
	for _, path := range []string{"/pypi/internal/simple/Acme_Utils/", "/pypi/internal/simple/acme-utils"} {
		code, _, hdr := e.get(path, "reader", "")
		require.Equal(t, 301, code, path)
		require.Equal(t, "/pypi/internal/simple/acme-utils/", hdr.Get("Location"))
	}
}

func TestUploadValidation(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	ok := map[string]string{"name": "pkg", "version": "1.0"}

	code, _ := e.upload("developer", map[string]string{"name": "pkg", "version": "1.0", "sha256_digest": strings.Repeat("0", 64)}, "pkg-1.0.tar.gz", []byte("x"))
	r.Equal(400, code, "digest mismatch")
	code, _ = e.upload("developer", ok, "other-1.0.tar.gz", []byte("x"))
	r.Equal(400, code, "filename doesn't match project")
	code, _ = e.upload("developer", ok, "pkg-2.0.tar.gz", []byte("x"))
	r.Equal(400, code, "filename doesn't match version")
	code, _ = e.upload("developer", ok, "pkg-1.0.exe", []byte("x"))
	r.Equal(400, code, "unsupported file type")
	code, _ = e.upload("developer", map[string]string{"name": "pkg", "version": "1.0", ":action": "submit"}, "pkg-1.0.tar.gz", []byte("x"))
	r.Equal(400, code, "unsupported action")
	code, _ = e.upload("developer", map[string]string{"name": "bad name!", "version": "1.0"}, "bad name!-1.0.tar.gz", []byte("x"))
	r.Equal(400, code)
	code, _ = e.upload("developer", ok, "pkg-1.0-py3-none-any.whl", []byte("not a zip"))
	r.Equal(400, code, "wheels must be valid zip files with METADATA")
}

func TestDuplicateFileRejected(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	fields := map[string]string{"name": "pkg", "version": "1.0"}
	code, _ := e.upload("developer", fields, "pkg-1.0.tar.gz", []byte("one"))
	r.Equal(200, code)
	code, body := e.upload("developer", fields, "pkg-1.0.tar.gz", []byte("two"))
	r.Equal(409, code, "twine --skip-existing recognizes 409")
	r.Contains(body, "already exists")
}

func TestYankedFilesAreFlagged(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.upload("developer", map[string]string{"name": "pkg", "version": "1.0"}, "pkg-1.0.tar.gz", []byte("x"))
	r.NoError(e.svc.Yank(context.Background(), principals["admin"], "internal", "pkg", "1.0", "security <bug>"))

	_, body, _ := e.get("/pypi/internal/simple/pkg/", "reader", "application/vnd.pypi.simple.v1+json")
	var idx simpleJSON
	r.NoError(json.Unmarshal([]byte(body), &idx))
	r.Equal("security <bug>", idx.Files[0].Yanked)

	_, html, _ := e.get("/pypi/internal/simple/pkg/", "reader", "")
	r.Contains(html, `data-yanked="security &lt;bug&gt;"`)
}

func TestDeletedVersionsAreHidden(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.upload("developer", map[string]string{"name": "pkg", "version": "1.0"}, "pkg-1.0.tar.gz", []byte("x"))
	e.upload("developer", map[string]string{"name": "pkg", "version": "2.0"}, "pkg-2.0.tar.gz", []byte("y"))
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "internal", "pkg", "2.0"))

	_, html, _ := e.get("/pypi/internal/simple/pkg/", "reader", "")
	r.NotContains(html, "pkg-2.0.tar.gz")
	code, _, _ := e.get("/pypi/internal/files/pkg/pkg-2.0.tar.gz", "reader", "")
	r.Equal(404, code)
}

func TestVersionNormalization(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	code, _ := e.upload("developer", map[string]string{"name": "pkg", "version": "V1.0.RC1"}, "pkg-V1.0.RC1.tar.gz", []byte("x"))
	r.Equal(200, code)
	versions, err := e.svc.Versions(context.Background(), principals["admin"], "internal", "pkg")
	r.NoError(err)
	r.Equal("1.0rc1", versions[0].Version)
}

func TestAccess(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.upload("developer", map[string]string{"name": "pkg", "version": "1.0"}, "pkg-1.0.tar.gz", []byte("x"))

	code, _, hdr := e.get("/pypi/internal/simple/pkg/", "", "")
	r.Equal(401, code)
	r.Contains(hdr.Get("WWW-Authenticate"), "Basic", "pip only sends keyring/netrc credentials after a Basic challenge")
	code, _ = e.upload("", map[string]string{"name": "pkg", "version": "1.1"}, "pkg-1.1.tar.gz", []byte("x"))
	r.Equal(401, code)
	code, _ = e.upload("reader", map[string]string{"name": "pkg", "version": "1.1"}, "pkg-1.1.tar.gz", []byte("x"))
	r.Equal(403, code)
	code, _, _ = e.get("/pypi/internal/simple/pkg/", "stranger", "")
	r.Equal(404, code)
	code, _, _ = e.get("/pypi/internal/simple/missing/", "reader", "")
	r.Equal(404, code)
}

func TestOpClassification(t *testing.T) {
	h := New(nil, nil)
	for _, tc := range []struct {
		method, path string
		want         ratelimit.Op
	}{
		{"GET", "/pypi/r/simple/p/", ratelimit.OpRead},
		{"GET", "/pypi/r/files/p/p-1.0.tar.gz", ratelimit.OpDownload},
		{"POST", "/pypi/r/", ratelimit.OpPublish},
	} {
		require.Equal(t, tc.want, h.Op(httptest.NewRequest(tc.method, tc.path, nil)), fmt.Sprint(tc))
	}
}
