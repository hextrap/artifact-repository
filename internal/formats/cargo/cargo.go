// Package cargo serves Rust crate registries using Cargo's sparse index
// protocol (RFC 2789) and registry web API:
//
//	/cargo/<repo>/index/config.json
//	/cargo/<repo>/index/<prefix>/<name>         one JSON line per version
//	/cargo/<repo>/api/v1/crates/new             cargo publish
//	/cargo/<repo>/api/v1/crates/<name>/<version>/download|yank|unyank
//
// Clients point at sparse+<base>/cargo/<repo>/index/. Cargo sends the token
// as the bare Authorization header value.
package cargo

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	Prefix       = "/cargo/"
	maxCrateSize = 256 << 20
	maxMetaSize  = 1 << 20
)

type Handler struct {
	svc     *registry.Service
	baseURL func(*http.Request) string
	proxy   *upstream.Proxy
}

func New(svc *registry.Service, baseURL func(*http.Request) string) *Handler {
	return &Handler{svc: svc, baseURL: baseURL, proxy: upstream.New()}
}

func (h *Handler) SetClock(now func() time.Time)    { h.proxy.SetClock(now) }
func (h *Handler) SetGate(g upstream.Gate)          { h.proxy.SetGate(g) }
func (h *Handler) SetUpstreamClient(c *http.Client) { h.proxy.SetClient(c) }

// AddFirewall marks a hextrap firewall upstream and sets its credentials.
func (h *Handler) AddFirewall(url, username, password string) {
	h.proxy.AddFirewall(url, username, password)
}

// Op classifies a request for rate limiting.
func (h *Handler) Op(r *http.Request) ratelimit.Op {
	switch {
	case r.Method == http.MethodPut || r.Method == http.MethodDelete:
		return ratelimit.OpPublish
	case strings.HasSuffix(r.URL.Path, "/download"):
		return ratelimit.OpDownload
	}
	return ratelimit.OpRead
}

// writeError uses the errors[].detail shape cargo prints.
func writeError(w http.ResponseWriter, err error) {
	status := registry.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		slog.Error("cargo request failed", "err", err)
	}
	writeJSON(w, status, map[string]any{"errors": []map[string]string{{"detail": registry.PublicMessage(err)}}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", registry.ErrInvalid, fmt.Sprintf(format, args...))
}

var (
	nameRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

// packageKey identifies a crate: names are unique ignoring case and the
// difference between - and _.
func packageKey(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// indexPath is where a crate's index file lives.
func indexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	}
	return n[:2] + "/" + n[2:4] + "/" + n
}

func crateFile(name, version string) string { return packageKey(name) + "-" + version + ".crate" }

type route struct {
	repo    string
	kind    string // config, index, publish, download, yank, unyank, search
	name    string
	version string
	path    string // index path as requested
}

func parse(r *http.Request) (route, bool) {
	rest, ok := strings.CutPrefix(r.URL.Path, Prefix)
	if !ok {
		return route{}, false
	}
	repo, rest, _ := strings.Cut(rest, "/")
	rt := route{repo: repo}
	if idx, ok := strings.CutPrefix(rest, "index/"); ok {
		if idx == "config.json" {
			rt.kind = "config"
			return rt, true
		}
		segs := strings.Split(idx, "/")
		rt.kind, rt.name, rt.path = "index", segs[len(segs)-1], idx
		return rt, nameRE.MatchString(rt.name) && indexPath(rt.name) == strings.ToLower(idx)
	}
	api, ok := strings.CutPrefix(rest, "api/v1/crates")
	if !ok {
		return route{}, false
	}
	if api == "" {
		rt.kind = "search"
		return rt, true
	}
	if api == "/new" {
		rt.kind = "publish"
		return rt, true
	}
	segs := strings.Split(strings.TrimPrefix(api, "/"), "/")
	if len(segs) != 3 || !nameRE.MatchString(segs[0]) || !versionRE.MatchString(segs[1]) {
		return route{}, false
	}
	switch segs[2] {
	case "download", "yank", "unyank":
		rt.kind, rt.name, rt.version = segs[2], segs[0], segs[1]
		return rt, true
	}
	return route{}, false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, ok := parse(r)
	if !ok {
		writeError(w, registry.ErrNotFound)
		return
	}
	p := identity.FromContext(r.Context())
	rv, err := h.svc.Repo(r.Context(), p, rt.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	proxy := rv.Type == registry.TypeProxy
	read := r.Method == http.MethodGet || r.Method == http.MethodHead

	switch {
	case rt.kind == "config" && read:
		writeJSON(w, http.StatusOK, map[string]any{
			"dl":            h.baseURL(r) + Prefix + rt.repo + "/api/v1/crates",
			"api":           h.baseURL(r) + Prefix + rt.repo,
			"auth-required": !rv.AnonymousRead,
		})
	case rt.kind == "index" && read && proxy:
		h.proxyIndex(w, r, p, rt, rv.Repo)
	case rt.kind == "index" && read:
		h.hostedIndex(w, r, p, rt)
	case rt.kind == "download" && read && proxy:
		h.proxyDownload(w, r, p, rt, rv.Repo)
	case rt.kind == "download" && read:
		rc, f, err := h.svc.OpenFile(r.Context(), p, rt.repo, packageKey(rt.name), crateFile(rt.name, rt.version))
		if err != nil {
			writeError(w, err)
			return
		}
		sendCrate(w, r, rc, f, "")
	case rt.kind == "search" && read:
		h.search(w, r, p, rt)
	case proxy:
		writeError(w, registry.ErrReadOnly)
	case rt.kind == "publish" && r.Method == http.MethodPut:
		if err := h.publish(r, p, rt); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"warnings": map[string][]string{"invalid_categories": {}, "invalid_badges": {}, "other": {}}})
	case rt.kind == "yank" && r.Method == http.MethodDelete:
		h.respondOK(w, h.svc.Yank(r.Context(), p, rt.repo, packageKey(rt.name), rt.version, ""))
	case rt.kind == "unyank" && r.Method == http.MethodPut:
		h.respondOK(w, h.svc.Unyank(r.Context(), p, rt.repo, packageKey(rt.name), rt.version))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) respondOK(w http.ResponseWriter, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// sendCrate streams a stored .crate. cache, if set, is reported in
// X-Hextrap-Cache ("hit" or "miss") for proxy repos.
func sendCrate(w http.ResponseWriter, r *http.Request, rc io.ReadCloser, f registry.File, cache string) {
	defer rc.Close()
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, rc); err != nil {
		slog.Error("streaming crate", "file", f.Filename, "err", err)
	}
}

// indexLines renders stored versions as index lines. Each version's
// manifest is its index line; yanked state is current.
func indexLines(versions []registry.Version) ([]byte, error) {
	var buf bytes.Buffer
	for _, v := range versions {
		var line map[string]any
		if err := json.Unmarshal(v.Manifest, &line); err != nil {
			return nil, err
		}
		line["yanked"] = v.Yanked
		b, err := json.Marshal(line)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func writeIndex(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (h *Handler) hostedIndex(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	versions, err := h.svc.Versions(r.Context(), p, rt.repo, packageKey(rt.name))
	if err != nil {
		writeError(w, err)
		return
	}
	if len(versions) == 0 {
		writeError(w, registry.ErrNotFound)
		return
	}
	body, err := indexLines(versions)
	if err != nil {
		writeError(w, err)
		return
	}
	writeIndex(w, r, body)
}

type publishDep struct {
	Name               string   `json:"name"`
	VersionReq         string   `json:"version_req"`
	Features           []string `json:"features"`
	Optional           bool     `json:"optional"`
	DefaultFeatures    bool     `json:"default_features"`
	Target             *string  `json:"target"`
	Kind               string   `json:"kind"`
	Registry           *string  `json:"registry"`
	ExplicitNameInToml *string  `json:"explicit_name_in_toml"`
}

type publishMeta struct {
	Name        string              `json:"name"`
	Vers        string              `json:"vers"`
	Deps        []publishDep        `json:"deps"`
	Features    map[string][]string `json:"features"`
	Links       *string             `json:"links"`
	RustVersion *string             `json:"rust_version"`
}

// readPublish splits cargo's publish body into metadata and the .crate.
func readPublish(body io.Reader) (publishMeta, []byte, error) {
	var meta publishMeta
	readChunk := func(limit uint32) ([]byte, error) {
		var n uint32
		if err := binary.Read(body, binary.LittleEndian, &n); err != nil {
			return nil, invalid("malformed publish request")
		}
		if n > limit {
			return nil, invalid("publish request too large")
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(body, b); err != nil {
			return nil, invalid("malformed publish request")
		}
		return b, nil
	}
	metaJSON, err := readChunk(maxMetaSize)
	if err != nil {
		return meta, nil, err
	}
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return meta, nil, invalid("malformed publish metadata")
	}
	crate, err := readChunk(maxCrateSize)
	return meta, crate, err
}

func (h *Handler) publish(r *http.Request, p identity.Principal, rt route) error {
	meta, crate, err := readPublish(r.Body)
	if err != nil {
		return err
	}
	if !nameRE.MatchString(meta.Name) {
		return invalid("invalid crate name %q", meta.Name)
	}
	if !versionRE.MatchString(meta.Vers) {
		return invalid("invalid version %q", meta.Vers)
	}
	sum := sha256.Sum256(crate)

	deps := make([]map[string]any, 0, len(meta.Deps))
	for _, d := range meta.Deps {
		dep := map[string]any{
			"name": d.Name, "req": d.VersionReq, "features": d.Features, "optional": d.Optional,
			"default_features": d.DefaultFeatures, "target": d.Target, "kind": d.Kind,
		}
		if d.Features == nil {
			dep["features"] = []string{}
		}
		if d.Registry != nil {
			dep["registry"] = *d.Registry
		}
		// A dependency renamed in Cargo.toml is listed under its new name,
		// with the real crate in "package".
		if d.ExplicitNameInToml != nil && *d.ExplicitNameInToml != "" {
			dep["name"], dep["package"] = *d.ExplicitNameInToml, d.Name
		}
		deps = append(deps, dep)
	}
	features := meta.Features
	if features == nil {
		features = map[string][]string{}
	}
	line, err := json.Marshal(map[string]any{
		"name": meta.Name, "vers": meta.Vers, "deps": deps, "cksum": hex.EncodeToString(sum[:]),
		"features": features, "links": meta.Links, "rust_version": meta.RustVersion, "v": 2,
	})
	if err != nil {
		return err
	}
	return h.svc.Publish(r.Context(), p, rt.repo, registry.VersionInput{
		Package: packageKey(meta.Name), DisplayName: meta.Name, Version: meta.Vers, Manifest: line,
		Files: []registry.FileInput{{Filename: crateFile(meta.Name, meta.Vers), Content: bytes.NewReader(crate)}},
	})
}

func (h *Handler) search(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	sums, err := h.svc.PackageSummaries(r.Context(), p, rt.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	crates := []map[string]string{}
	for _, s := range sums {
		if strings.Contains(strings.ToLower(s.DisplayName), q) {
			crates = append(crates, map[string]string{"name": s.DisplayName, "max_version": s.Latest, "description": ""})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"crates": crates, "meta": map[string]int{"total": len(crates)}})
}
