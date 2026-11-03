// Package pypi serves hosted Python repositories: the legacy upload API
// (twine, uv publish) and the simple repository API in HTML (PEP 503) and
// JSON (PEP 691), with yanking (PEP 592) and wheel metadata (PEP 658/714).
package pypi

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	Prefix        = "/pypi/"
	maxUploadSize = 1 << 30
	maxMetadata   = 10 << 20
	jsonType      = "application/vnd.pypi.simple.v1+json"
	metadataExt   = ".metadata"
)

type Handler struct {
	svc     *registry.Service
	baseURL func(*http.Request) string
	proxy   *upstream.Proxy
}

func New(svc *registry.Service, baseURL func(*http.Request) string) *Handler {
	return &Handler{svc: svc, baseURL: baseURL, proxy: upstream.New()}
}

func (h *Handler) Op(r *http.Request) ratelimit.Op {
	switch {
	case r.Method == http.MethodPost:
		return ratelimit.OpPublish
	case strings.Contains(r.URL.Path, "/files/"):
		return ratelimit.OpDownload
	}
	return ratelimit.OpRead
}

var (
	nameRE      = regexp.MustCompile(`(?i)^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`)
	separatorRE = regexp.MustCompile(`[-_.]+`)
	versionRE   = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
		`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?` +
		`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?` +
		`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
		`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)
)

// NormalizeName implements PEP 503 name normalization.
func NormalizeName(name string) string {
	return strings.ToLower(separatorRE.ReplaceAllString(name, "-"))
}

func trimInt(s string) string {
	if s == "" {
		return "0"
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return s
	}
	return strconv.FormatUint(n, 10)
}

// NormalizeVersion implements PEP 440 normalization.
func NormalizeVersion(v string) (string, error) {
	m := versionRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return "", fmt.Errorf("%w: invalid version %q", registry.ErrInvalid, v)
	}
	var b strings.Builder
	if m[1] != "" && trimInt(m[1]) != "0" {
		b.WriteString(trimInt(m[1]) + "!")
	}
	parts := strings.Split(m[2], ".")
	for i, p := range parts {
		parts[i] = trimInt(p)
	}
	b.WriteString(strings.Join(parts, "."))
	if m[3] != "" {
		pre := map[string]string{"a": "a", "alpha": "a", "b": "b", "beta": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}[m[3]]
		b.WriteString(pre + trimInt(m[4]))
	}
	if m[5] != "" {
		b.WriteString(".post" + trimInt(m[5]))
	} else if m[6] != "" {
		b.WriteString(".post" + trimInt(m[7]))
	}
	if m[8] != "" {
		b.WriteString(".dev" + trimInt(m[9]))
	}
	if m[10] != "" {
		b.WriteString("+" + separatorRE.ReplaceAllString(m[10], "."))
	}
	return b.String(), nil
}

// parseFilename returns the project and version embedded in a
// distribution filename.
func parseFilename(filename string) (name, version string, wheel bool, err error) {
	switch {
	case strings.HasSuffix(filename, ".whl"):
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if len(parts) < 5 {
			return "", "", false, fmt.Errorf("%w: invalid wheel filename", registry.ErrInvalid)
		}
		return parts[0], parts[1], true, nil
	case strings.HasSuffix(filename, ".tar.gz"), strings.HasSuffix(filename, ".zip"):
		base := strings.TrimSuffix(strings.TrimSuffix(filename, ".tar.gz"), ".zip")
		i := strings.LastIndex(base, "-")
		if i <= 0 {
			return "", "", false, fmt.Errorf("%w: invalid sdist filename", registry.ErrInvalid)
		}
		return base[:i], base[i+1:], false, nil
	}
	return "", "", false, fmt.Errorf("%w: unsupported distribution type %q", registry.ErrInvalid, filename)
}

func writeError(w http.ResponseWriter, err error) {
	status := registry.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		slog.Error("pypi request failed", "err", err)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="hextrap"`)
	}
	http.Error(w, registry.PublicMessage(err), status)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, Prefix)
	if !ok {
		writeError(w, registry.ErrNotFound)
		return
	}
	repo, rest, _ := strings.Cut(rest, "/")
	segs := strings.Split(rest, "/")

	switch {
	case r.Method == http.MethodPost && (rest == "" || rest == "legacy/"):
		h.upload(w, r, repo)
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		w.WriteHeader(http.StatusMethodNotAllowed)
	case rest == "simple/":
		h.projectList(w, r, repo)
	case len(segs) >= 2 && segs[0] == "simple" && segs[1] != "" && len(segs) <= 3:
		project := segs[1]
		if NormalizeName(project) != project || len(segs) == 2 || segs[2] != "" {
			http.Redirect(w, r, Prefix+repo+"/simple/"+NormalizeName(project)+"/", http.StatusMovedPermanently)
			return
		}
		if rv, ok := h.lookupRepo(w, r, repo); ok && rv.Type == registry.TypeProxy {
			h.proxyProjectPage(w, r, rv.Repo, project)
		} else if ok {
			h.projectPage(w, r, repo, project)
		}
	case len(segs) == 3 && segs[0] == "files":
		if rv, ok := h.lookupRepo(w, r, repo); ok && rv.Type == registry.TypeProxy {
			h.proxyDownload(w, r, rv.Repo, segs[1], segs[2])
		} else if ok {
			h.download(w, r, repo, segs[1], segs[2])
		}
	default:
		writeError(w, registry.ErrNotFound)
	}
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request, repo string) {
	if err := h.uploadErr(r, repo); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func checkDigest(f multipart.File, newHash func() hash.Hash, want string) error {
	if want == "" {
		return nil
	}
	h := newHash()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
		return fmt.Errorf("%w: digest does not match uploaded file", registry.ErrInvalid)
	}
	return nil
}

var metadataPathRE = regexp.MustCompile(`^[^/]+\.dist-info/METADATA$`)

func wheelMetadata(f multipart.File, size int64) ([]byte, error) {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, fmt.Errorf("%w: wheel is not a valid zip file", registry.ErrInvalid)
	}
	for _, zf := range zr.File {
		if !metadataPathRE.MatchString(zf.Name) {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: unreadable wheel METADATA", registry.ErrInvalid)
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, maxMetadata))
	}
	return nil, fmt.Errorf("%w: wheel has no .dist-info/METADATA", registry.ErrInvalid)
}

func (h *Handler) uploadErr(r *http.Request, repo string) error {
	p := identity.FromContext(r.Context())
	if p.Kind == identity.KindAnonymous {
		// Fail before reading a possibly large body.
		return registry.ErrUnauthenticated
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return fmt.Errorf("%w: malformed upload", registry.ErrInvalid)
	}
	defer r.MultipartForm.RemoveAll()

	if a := r.FormValue(":action"); a != "file_upload" {
		return fmt.Errorf("%w: unsupported action %q", registry.ErrInvalid, a)
	}
	name := r.FormValue("name")
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w: invalid project name %q", registry.ErrInvalid, name)
	}
	version, err := NormalizeVersion(r.FormValue("version"))
	if err != nil {
		return err
	}
	f, hdr, err := r.FormFile("content")
	if err != nil {
		return fmt.Errorf("%w: missing file content", registry.ErrInvalid)
	}
	defer f.Close()

	fileName, fileVersion, isWheel, err := parseFilename(hdr.Filename)
	if err != nil {
		return err
	}
	if NormalizeName(fileName) != NormalizeName(name) {
		return fmt.Errorf("%w: filename does not match project %q", registry.ErrInvalid, name)
	}
	if v, err := NormalizeVersion(fileVersion); err != nil || v != version {
		return fmt.Errorf("%w: filename does not match version %q", registry.ErrInvalid, version)
	}
	if err := checkDigest(f, sha256.New, r.FormValue("sha256_digest")); err != nil {
		return err
	}
	if r.FormValue("sha256_digest") == "" {
		if err := checkDigest(f, md5.New, r.FormValue("md5_digest")); err != nil {
			return err
		}
	}

	attrs := map[string]string{"requires_python": r.FormValue("requires_python")}
	files := []registry.FileInput{{Filename: hdr.Filename, Content: f, Attrs: attrs}}
	if isWheel {
		meta, err := wheelMetadata(f, hdr.Size)
		if err != nil {
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		files = append(files, registry.FileInput{Filename: hdr.Filename + metadataExt, Content: bytes.NewReader(meta)})
	}

	return h.svc.AddFile(r.Context(), p, repo, registry.VersionInput{
		Package: NormalizeName(name), DisplayName: name, Version: version, Files: files,
	})
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), jsonType)
}

func (h *Handler) projectList(w http.ResponseWriter, r *http.Request, repo string) {
	pkgs, err := h.svc.Packages(r.Context(), identity.FromContext(r.Context()), repo)
	if err != nil {
		writeError(w, err)
		return
	}
	if wantsJSON(r) {
		projects := make([]map[string]string, 0, len(pkgs))
		for _, p := range pkgs {
			projects = append(projects, map[string]string{"name": p})
		}
		w.Header().Set("Content-Type", jsonType)
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"api-version": "1.1"}, "projects": projects})
		return
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta name="pypi:repository-version" content="1.1"><title>Simple index</title></head><body>` + "\n")
	for _, p := range pkgs {
		e := html.EscapeString(p)
		fmt.Fprintf(&b, `<a href="%s/">%s</a><br>`+"\n", e, e)
	}
	b.WriteString("</body></html>\n")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

type indexFile struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"`
	RequiresPython string            `json:"requires-python,omitempty"`
	Yanked         any               `json:"yanked"`
	CoreMetadata   any               `json:"core-metadata"`
	DistInfoMeta   any               `json:"dist-info-metadata"`
	Size           int64             `json:"size"`
	UploadTime     string            `json:"upload-time"`
}

func (h *Handler) projectPage(w http.ResponseWriter, r *http.Request, repo, project string) {
	versions, err := h.svc.Versions(r.Context(), identity.FromContext(r.Context()), repo, project)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(versions) == 0 {
		writeError(w, registry.ErrNotFound)
		return
	}
	files, versionList := h.storedIndexFiles(r, repo, project, versions)
	renderIndex(w, r, project, files, versionList)
}

// storedIndexFiles lists the files of versions held in the repository.
func (h *Handler) storedIndexFiles(r *http.Request, repo, project string, versions []registry.Version) ([]indexFile, []string) {
	var files []indexFile
	var versionList []string
	for _, v := range versions {
		versionList = append(versionList, v.Version)
		metadata := map[string]registry.File{}
		for _, f := range v.Files {
			if base, ok := strings.CutSuffix(f.Filename, metadataExt); ok {
				metadata[base] = f
			}
		}
		for _, f := range v.Files {
			if strings.HasSuffix(f.Filename, metadataExt) {
				continue
			}
			var yanked any = false
			if v.Yanked {
				yanked = true
				if v.YankReason != "" {
					yanked = v.YankReason
				}
			}
			var core any = false
			if m, ok := metadata[f.Filename]; ok {
				core = map[string]string{"sha256": m.Digest.Hex()}
			}
			files = append(files, indexFile{
				Filename:       f.Filename,
				URL:            h.fileURL(r, repo, project, f.Filename),
				Hashes:         map[string]string{"sha256": f.Digest.Hex()},
				RequiresPython: f.Attrs["requires_python"],
				Yanked:         yanked,
				CoreMetadata:   core,
				DistInfoMeta:   core,
				Size:           f.Size,
				UploadTime:     v.PublishedAt.UTC().Format(time.RFC3339Nano),
			})
		}
	}
	return files, versionList
}

func (h *Handler) fileURL(r *http.Request, repo, project, filename string) string {
	return h.baseURL(r) + Prefix + repo + "/files/" + project + "/" + filename
}

// renderIndex writes a project page as PEP 691 JSON or PEP 503 HTML.
func renderIndex(w http.ResponseWriter, r *http.Request, project string, files []indexFile, versions []string) {
	if files == nil {
		files = []indexFile{}
	}
	if versions == nil {
		versions = []string{}
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", jsonType)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"meta": map[string]string{"api-version": "1.1"}, "name": project, "files": files, "versions": versions,
		})
		return
	}

	var b strings.Builder
	title := html.EscapeString(project)
	fmt.Fprintf(&b, `<!DOCTYPE html><html><head><meta name="pypi:repository-version" content="1.1"><title>Links for %s</title></head><body><h1>Links for %s</h1>`+"\n", title, title)
	for _, f := range files {
		fmt.Fprintf(&b, `<a href="%s#sha256=%s"`, html.EscapeString(f.URL), html.EscapeString(f.Hashes["sha256"]))
		if f.RequiresPython != "" {
			fmt.Fprintf(&b, ` data-requires-python="%s"`, html.EscapeString(f.RequiresPython))
		}
		if m, ok := f.CoreMetadata.(map[string]string); ok {
			sum := html.EscapeString(m["sha256"])
			fmt.Fprintf(&b, ` data-dist-info-metadata="sha256=%s" data-core-metadata="sha256=%s"`, sum, sum)
		}
		switch y := f.Yanked.(type) {
		case string:
			fmt.Fprintf(&b, ` data-yanked="%s"`, html.EscapeString(y))
		case bool:
			if y {
				b.WriteString(` data-yanked=""`)
			}
		}
		fmt.Fprintf(&b, ">%s</a><br>\n", html.EscapeString(f.Filename))
	}
	b.WriteString("</body></html>\n")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request, repo, project, filename string) {
	rc, f, err := h.svc.OpenFile(r.Context(), identity.FromContext(r.Context()), repo, project, filename)
	if err != nil {
		writeError(w, err)
		return
	}
	serveFile(w, r, rc, f, "")
}

// serveFile streams a stored file. cache, if set, is reported in
// X-Hextrap-Cache ("hit" or "miss") for proxy repos.
func serveFile(w http.ResponseWriter, r *http.Request, rc io.ReadCloser, f registry.File, cache string) {
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, rc); err != nil {
		slog.Error("streaming file", "file", f.Filename, "err", err)
	}
}
