// Package gomod serves Go module proxy repositories (the GOPROXY protocol):
//
//	/go/<repo>/<escaped module>/@v/list
//	/go/<repo>/<escaped module>/@v/<version>.info|.mod|.zip
//	/go/<repo>/<escaped module>/@latest
//
// Go has no publish command, so only proxy repositories exist. Before a
// module zip or go.mod is cached, its h1: hash (the one go.sum records) is
// checked against the Go checksum database, an independent source from the
// proxy it came from.
package gomod

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	Prefix = "/go/"
	// DefaultSumDB is the Go checksum database.
	DefaultSumDB = "https://sum.golang.org"
	maxZipSize   = 500 << 20 // the go command's own limit
	maxModSize   = 16 << 20
)

type Handler struct {
	svc   *registry.Service
	proxy *upstream.Proxy
	sumdb string
}

func New(svc *registry.Service) *Handler {
	return &Handler{svc: svc, proxy: upstream.New(), sumdb: DefaultSumDB}
}

func (h *Handler) SetClock(now func() time.Time)    { h.proxy.SetClock(now) }
func (h *Handler) SetGate(g upstream.Gate)          { h.proxy.SetGate(g) }
func (h *Handler) SetUpstreamClient(c *http.Client) { h.proxy.SetClient(c) }

// AddFirewall marks a hextrap firewall upstream and sets its credentials.
func (h *Handler) AddFirewall(url, username, password string) {
	h.proxy.AddFirewall(url, username, password)
}

// SetSumDB sets the checksum database URL. Empty disables verification,
// for private upstreams whose modules aren't in a public checksum database.
func (h *Handler) SetSumDB(url string) { h.sumdb = strings.TrimSuffix(url, "/") }

// Op classifies a request for rate limiting.
func (h *Handler) Op(r *http.Request) ratelimit.Op {
	switch {
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		return ratelimit.OpPublish
	case strings.HasSuffix(r.URL.Path, ".zip"):
		return ratelimit.OpDownload
	}
	return ratelimit.OpRead
}

func writeError(w http.ResponseWriter, err error) {
	status := registry.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		slog.Error("go proxy request failed", "err", err)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="hextrap"`)
	}
	http.Error(w, registry.PublicMessage(err), status)
}

// ---------- Module path escaping (as in golang.org/x/mod/module) ----------

// escapePath replaces each uppercase letter with "!" and its lowercase,
// so paths are safe on case-insensitive file systems.
func escapePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if 'A' <= r && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unescapePath(escaped string) (string, error) {
	var b strings.Builder
	bang := false
	for _, r := range escaped {
		switch {
		case bang:
			if r < 'a' || r > 'z' {
				return "", fmt.Errorf("%w: invalid escape in %q", registry.ErrInvalid, escaped)
			}
			b.WriteRune(r - ('a' - 'A'))
			bang = false
		case r == '!':
			bang = true
		case 'A' <= r && r <= 'Z':
			return "", fmt.Errorf("%w: escaped path %q has an uppercase letter", registry.ErrInvalid, escaped)
		default:
			b.WriteRune(r)
		}
	}
	if bang {
		return "", fmt.Errorf("%w: trailing escape in %q", registry.ErrInvalid, escaped)
	}
	return b.String(), nil
}

var (
	segmentRE = regexp.MustCompile(`^[A-Za-z0-9_~-][A-Za-z0-9._~-]*$`)
	versionRE = regexp.MustCompile(`^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

func validModule(path string) bool {
	segs := strings.Split(path, "/")
	if len(segs) == 0 || !strings.Contains(segs[0], ".") {
		return false
	}
	for _, s := range segs {
		if !segmentRE.MatchString(s) {
			return false
		}
	}
	return true
}

// ---------- h1: hashes (as in golang.org/x/mod/sumdb/dirhash) ----------

type namedFile struct {
	name string
	open func() (io.ReadCloser, error)
}

func hash1(files []namedFile) (string, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	summary := sha256.New()
	for _, f := range files {
		if strings.Contains(f.name, "\n") {
			return "", errors.New("file names with newlines are not supported")
		}
		rc, err := f.open()
		if err != nil {
			return "", err
		}
		fh := sha256.New()
		_, err = io.Copy(fh, rc)
		rc.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(summary, "%x  %s\n", fh.Sum(nil), f.name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(summary.Sum(nil)), nil
}

func hashGoMod(mod []byte) string {
	h, _ := hash1([]namedFile{{name: "go.mod", open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(mod)), nil
	}}})
	return h
}

func hashZipReader(zr *zip.Reader) (string, error) {
	var files []namedFile
	for _, f := range zr.File {
		f := f
		files = append(files, namedFile{name: f.Name, open: f.Open})
	}
	return hash1(files)
}

func hashZip(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	return hashZipReader(zr)
}

// ---------- Routing ----------

type route struct {
	repo    string
	module  string // unescaped
	escaped string
	kind    string // list, latest, file
	version string
	ext     string // .info, .mod or .zip
}

func parse(urlPath string) (route, error) {
	rest, ok := strings.CutPrefix(urlPath, Prefix)
	if !ok {
		return route{}, registry.ErrNotFound
	}
	repo, rest, _ := strings.Cut(rest, "/")
	rt := route{repo: repo}
	var file string
	switch {
	case strings.Contains(rest, "/@v/"):
		i := strings.Index(rest, "/@v/")
		rt.escaped, file = rest[:i], rest[i+len("/@v/"):]
		if file == "list" {
			rt.kind = "list"
		} else {
			rt.kind = "file"
			for _, ext := range []string{".info", ".mod", ".zip"} {
				if v, ok := strings.CutSuffix(file, ext); ok {
					rt.ext = ext
					var err error
					if rt.version, err = unescapePath(v); err != nil || !versionRE.MatchString(rt.version) {
						return route{}, registry.ErrNotFound
					}
				}
			}
			if rt.ext == "" {
				return route{}, registry.ErrNotFound
			}
		}
	case strings.HasSuffix(rest, "/@latest"):
		rt.kind, rt.escaped = "latest", strings.TrimSuffix(rest, "/@latest")
	default:
		// Includes /sumdb/...: the go command then uses the checksum
		// database directly.
		return route{}, registry.ErrNotFound
	}
	module, err := unescapePath(rt.escaped)
	if err != nil || !validModule(module) {
		return route{}, registry.ErrNotFound
	}
	rt.module = module
	return rt, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, err := parse(r.URL.Path)
	if err != nil {
		writeError(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	rv, err := h.svc.Repo(r.Context(), p, rt.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, registry.ErrReadOnly)
		return
	}
	if rv.Type != registry.TypeProxy {
		writeError(w, registry.ErrNotFound)
		return
	}
	switch rt.kind {
	case "list":
		h.list(w, r, p, rt, rv.Repo)
	case "latest":
		h.latest(w, r, p, rt, rv.Repo)
	default:
		h.file(w, r, p, rt, rv.Repo)
	}
}

func writeBody(w http.ResponseWriter, r *http.Request, body []byte, ctype, cache string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func contentType(ext string) string {
	switch ext {
	case ".info":
		return "application/json"
	case ".zip":
		return "application/zip"
	}
	return "text/plain; charset=utf-8"
}

func upstreamURL(repo registry.Repo, rt route, suffix string) string {
	return repo.Upstream + "/" + rt.escaped + suffix
}

func (h *Handler) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := h.proxy.Get(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	return b, nil
}

// cachedVersions lists stored versions, for when upstream is unreachable.
func (h *Handler) cachedVersions(ctx context.Context, p identity.Principal, repo registry.Repo, rt route, upstreamErr error) ([]registry.Version, error) {
	if !errors.Is(upstreamErr, registry.ErrNotFound) {
		slog.Warn("upstream unavailable; serving cached module versions", "repo", repo.Name, "module", rt.module, "err", upstreamErr)
	}
	versions, err := h.svc.Versions(ctx, p, repo.Name, rt.module)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, upstreamErr
	}
	return versions, nil
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, rt.module)
	if err != nil {
		writeError(w, err)
		return
	}
	v, err := h.proxy.Cached("go/"+repo.Tenant+"/"+repo.Name+"/"+rt.module+"/list", false, func() (any, error) {
		return h.fetch(ctx, upstreamURL(repo, rt, "/@v/list"), 16<<20)
	})
	var out bytes.Buffer
	if err != nil {
		versions, verr := h.cachedVersions(ctx, p, repo, rt, err)
		if verr != nil {
			writeError(w, verr)
			return
		}
		for _, ver := range versions {
			out.WriteString(ver.Version + "\n")
		}
	} else {
		for _, line := range strings.Split(string(v.([]byte)), "\n") {
			if line = strings.TrimSpace(line); line != "" && !removed[line] {
				out.WriteString(line + "\n")
			}
		}
	}
	writeBody(w, r, out.Bytes(), "text/plain; charset=utf-8", "")
}

func (h *Handler) latest(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	v, err := h.proxy.Cached("go/"+repo.Tenant+"/"+repo.Name+"/"+rt.module+"/@latest", false, func() (any, error) {
		b, err := h.fetch(ctx, upstreamURL(repo, rt, "/@latest"), 1<<20)
		if err != nil {
			return nil, err
		}
		var info struct{ Version string }
		if json.Unmarshal(b, &info) != nil || !versionRE.MatchString(info.Version) {
			return nil, fmt.Errorf("%w: malformed @latest", registry.ErrUpstreamUnavailable)
		}
		return b, nil
	})
	if err == nil {
		writeBody(w, r, v.([]byte), "application/json", "")
		return
	}
	versions, verr := h.cachedVersions(ctx, p, repo, rt, err)
	if verr != nil {
		writeError(w, verr)
		return
	}
	// The newest cached version that has its .info.
	for i := len(versions) - 1; i >= 0; i-- {
		rc, _, err := h.svc.OpenFile(ctx, p, repo.Name, rt.module, versions[i].Version+".info")
		if err != nil {
			continue
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err == nil {
			writeBody(w, r, b, "application/json", "")
			return
		}
	}
	writeError(w, err)
}

// ---------- Module files ----------

type moduleInfo struct {
	Version string
	Time    time.Time
}

func (h *Handler) info(ctx context.Context, repo registry.Repo, rt route) (moduleInfo, []byte, error) {
	v, err := h.proxy.Cached("go/"+repo.Tenant+"/"+repo.Name+"/"+rt.module+"/"+rt.version+".info", false, func() (any, error) {
		return h.fetch(ctx, upstreamURL(repo, rt, "/@v/"+escapePath(rt.version)+".info"), 1<<20)
	})
	if err != nil {
		return moduleInfo{}, nil, err
	}
	b := v.([]byte)
	var info moduleInfo
	if json.Unmarshal(b, &info) != nil || info.Version != rt.version {
		return moduleInfo{}, nil, fmt.Errorf("%w: malformed .info for %s@%s", registry.ErrUpstreamUnavailable, rt.module, rt.version)
	}
	return info, b, nil
}

type sumRecord struct {
	zip, mod string
}

var errSumDB = "the Go checksum database (sum.golang.org)"

// lookup reads a module version's hashes from the checksum database. The
// record is fetched over TLS; its transparency-log proof isn't checked
// here (the go command checks it on every client).
func (h *Handler) lookup(ctx context.Context, rt route) (sumRecord, error) {
	v, err := h.proxy.Cached("go/sumdb/"+rt.module+"@"+rt.version, false, func() (any, error) {
		b, err := h.fetch(ctx, h.sumdb+"/lookup/"+rt.escaped+"@"+escapePath(rt.version), 1<<20)
		if err != nil {
			return nil, fmt.Errorf("%w: can't verify %s@%s with %s: %v", registry.ErrUpstreamUnavailable, rt.module, rt.version, errSumDB, err)
		}
		var rec sumRecord
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) != 3 || f[0] != rt.module {
				continue
			}
			switch f[1] {
			case rt.version:
				rec.zip = f[2]
			case rt.version + "/go.mod":
				rec.mod = f[2]
			}
		}
		if rec.zip == "" || rec.mod == "" {
			return nil, fmt.Errorf("%w: %s has no record for %s@%s", registry.ErrUpstreamUnavailable, errSumDB, rt.module, rt.version)
		}
		return rec, nil
	})
	if err != nil {
		return sumRecord{}, err
	}
	return v.(sumRecord), nil
}

func (h *Handler) file(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	name := rt.version + rt.ext
	rc, f, err := h.svc.OpenFile(ctx, p, repo.Name, rt.module, name)
	if err == nil {
		defer rc.Close()
		// The firewall applies policy to zips; ask again before serving one.
		if rt.ext == ".zip" {
			if err := h.proxy.Recheck(ctx, repo, upstreamURL(repo, rt, "/@v/"+escapePath(rt.version)+".zip")); err != nil {
				writeError(w, err)
				return
			}
		}
		b, err := io.ReadAll(rc)
		if err != nil {
			writeError(w, err)
			return
		}
		writeBody(w, r, b, contentType(rt.ext), "hit")
		_ = f
		return
	}
	if !errors.Is(err, registry.ErrNotFound) {
		writeError(w, err)
		return
	}
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, rt.module)
	if err != nil {
		writeError(w, err)
		return
	}
	if removed[rt.version] {
		writeError(w, registry.ErrNotFound)
		return
	}
	info, infoJSON, err := h.info(ctx, repo, rt)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.proxy.Check(ctx, upstream.Request{Repo: repo, Package: rt.module, Version: rt.version, Filename: name, Published: info.Time.UTC()}); err != nil {
		writeError(w, err)
		return
	}

	err = h.proxy.Once("go/"+repo.Tenant+"/"+repo.Name+"/"+rt.module+"/"+name, func() error {
		return h.download(context.WithoutCancel(ctx), p, repo, rt, infoJSON)
	})
	if err != nil {
		if errors.Is(err, registry.ErrVersionExists) {
			err = registry.ErrNotFound // removed by an admin meanwhile
		}
		writeError(w, err)
		return
	}
	rc, _, err = h.svc.OpenFile(ctx, p, repo.Name, rt.module, name)
	if err != nil {
		writeError(w, err)
		return
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		writeError(w, err)
		return
	}
	writeBody(w, r, b, contentType(rt.ext), "miss")
}

// download fetches, verifies and caches one module file.
func (h *Handler) download(ctx context.Context, p identity.Principal, repo registry.Repo, rt route, infoJSON []byte) error {
	var content io.Reader
	var size int64
	switch rt.ext {
	case ".info":
		content, size = bytes.NewReader(infoJSON), int64(len(infoJSON))
	case ".mod":
		mod, err := h.fetch(ctx, upstreamURL(repo, rt, "/@v/"+escapePath(rt.version)+".mod"), maxModSize)
		if err != nil {
			return err
		}
		if h.sumdb != "" {
			rec, err := h.lookup(ctx, rt)
			if err != nil {
				return err
			}
			if got := hashGoMod(mod); got != rec.mod {
				return fmt.Errorf("%w: go.mod for %s@%s doesn't match %s", registry.ErrDigestMismatch, rt.module, rt.version, errSumDB)
			}
		}
		content, size = bytes.NewReader(mod), int64(len(mod))
	case ".zip":
		resp, err := h.proxy.Get(ctx, upstreamURL(repo, rt, "/@v/"+escapePath(rt.version)+".zip"), nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		tmp, err := os.CreateTemp("", "hextrap-gomod-*.zip")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if size, err = io.Copy(tmp, io.LimitReader(resp.Body, maxZipSize+1)); err != nil {
			return fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
		}
		if size > maxZipSize {
			return fmt.Errorf("%w: module zip exceeds %d bytes", registry.ErrUpstreamUnavailable, maxZipSize)
		}
		if err := h.verifyZip(ctx, tmp, size, rt); err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		content = tmp
	}

	// Verification happened above; the checksum guards the copy into storage.
	var buf bytes.Buffer
	sum := sha256.New()
	tee := io.TeeReader(content, sum)
	if _, err := io.Copy(&buf, io.LimitReader(tee, size)); err != nil {
		return err
	}
	return h.svc.CacheFile(ctx, p, repo.Name, upstream.Host(repo), registry.VersionInput{
		Package: rt.module, DisplayName: rt.module, Version: rt.version,
		Files: []registry.FileInput{{
			Filename: rt.version + rt.ext,
			Content:  &buf,
			Expected: registry.Checksums{"sha256": hex.EncodeToString(sum.Sum(nil))},
		}},
	})
}

// verifyZip checks a module zip's structure and, with a checksum database
// configured, its h1: hash.
func (h *Handler) verifyZip(ctx context.Context, f *os.File, size int64, rt route) error {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return fmt.Errorf("%w: %s@%s is not a valid module zip", registry.ErrUpstreamUnavailable, rt.module, rt.version)
	}
	prefix := rt.module + "@" + rt.version + "/"
	for _, zf := range zr.File {
		if !strings.HasPrefix(zf.Name, prefix) {
			return fmt.Errorf("%w: module zip has a file outside %s", registry.ErrUpstreamUnavailable, prefix)
		}
	}
	if h.sumdb == "" {
		return nil
	}
	rec, err := h.lookup(ctx, rt)
	if err != nil {
		return err
	}
	got, err := hashZipReader(zr)
	if err != nil {
		return fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	if got != rec.zip {
		return fmt.Errorf("%w: %s@%s doesn't match %s", registry.ErrDigestMismatch, rt.module, rt.version, errSumDB)
	}
	return nil
}
