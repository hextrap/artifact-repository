// Package npm serves hosted npm repositories using the npm registry protocol
// as spoken by the npm, yarn and bun CLIs.
package npm

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	Prefix         = "/npm/"
	maxPublishSize = 256 << 20 // base64 tarball in JSON
)

type Handler struct {
	svc *registry.Service
	// baseURL returns the externally visible scheme://host for tarball URLs.
	baseURL func(*http.Request) string
	proxy   *upstream.Proxy
}

func New(svc *registry.Service, baseURL func(*http.Request) string) *Handler {
	return &Handler{svc: svc, baseURL: baseURL, proxy: upstream.New()}
}

// Op classifies a request for rate limiting.
func (h *Handler) Op(r *http.Request) ratelimit.Op {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			return ratelimit.OpDownload
		}
		return ratelimit.OpRead
	}
	return ratelimit.OpPublish
}

var (
	nameRE    = regexp.MustCompile(`^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$`)
	versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status := registry.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		slog.Error("npm request failed", "err", err)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="hextrap"`)
	}
	writeJSON(w, status, map[string]string{"error": registry.PublicMessage(err)})
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", registry.ErrInvalid, fmt.Sprintf(format, args...))
}

// route is a parsed request path below /npm/{repo}/.
type route struct {
	repo string
	kind string // "ping", "whoami", "disttags", "package", "tarball", "rev", "tarball-rev"
	pkg  string
	file string
	tag  string
}

// splitPackage takes "@scope/name/rest..." or "name/rest..." and returns the
// package name and the remaining segments.
func splitPackage(segs []string) (string, []string) {
	if len(segs) >= 2 && strings.HasPrefix(segs[0], "@") {
		return segs[0] + "/" + segs[1], segs[2:]
	}
	if len(segs) == 0 {
		return "", nil
	}
	return segs[0], segs[1:]
}

func parse(r *http.Request) (route, bool) {
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), Prefix)
	if !ok {
		return route{}, false
	}
	repo, rest, _ := strings.Cut(rest, "/")
	// npm sends scoped names as @scope%2fname; treat the escape as a slash.
	rest = strings.NewReplacer("%2f", "/", "%2F", "/").Replace(rest)
	rest, err := url.PathUnescape(rest)
	if err != nil || repo == "" || rest == "" {
		return route{}, false
	}
	segs := strings.Split(rest, "/")
	rt := route{repo: repo}

	if segs[0] == "-" {
		switch {
		case len(segs) == 2 && segs[1] == "ping":
			rt.kind = "ping"
		case len(segs) == 2 && segs[1] == "whoami":
			rt.kind = "whoami"
		case len(segs) >= 4 && segs[1] == "package":
			pkg, tail := splitPackage(segs[2:])
			if len(tail) == 0 || tail[0] != "dist-tags" || len(tail) > 2 {
				return route{}, false
			}
			rt.kind, rt.pkg = "disttags", pkg
			if len(tail) == 2 {
				rt.tag = tail[1]
			}
		default:
			return route{}, false
		}
		return rt, true
	}

	pkg, tail := splitPackage(segs)
	rt.pkg = pkg
	switch {
	case len(tail) == 0:
		rt.kind = "package"
	case len(tail) == 2 && tail[0] == "-":
		rt.kind, rt.file = "tarball", tail[1]
	case len(tail) == 2 && tail[0] == "-rev":
		rt.kind = "rev"
	case len(tail) == 4 && tail[0] == "-" && tail[2] == "-rev":
		rt.kind, rt.file = "tarball-rev", tail[1]
	default:
		return route{}, false
	}
	return rt, true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, ok := parse(r)
	if !ok {
		writeError(w, registry.ErrNotFound)
		return
	}
	p := identity.FromContext(r.Context())

	switch rt.kind {
	case "ping":
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	case "whoami":
		if p.Kind == identity.KindAnonymous {
			writeError(w, registry.ErrUnauthenticated)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"username": p.Actor()})
		return
	}

	rv, err := h.svc.Repo(r.Context(), p, rt.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	if rv.Type == registry.TypeProxy {
		h.serveProxy(w, r, p, rt, rv.Repo)
		return
	}

	switch {
	case rt.kind == "package" && r.Method == http.MethodGet:
		h.getPackument(w, r, p, rt)
	case rt.kind == "package" && r.Method == http.MethodPut, rt.kind == "rev" && r.Method == http.MethodPut:
		h.put(w, r, p, rt)
	case rt.kind == "rev" && r.Method == http.MethodDelete:
		h.unpublishAll(w, r, p, rt)
	case rt.kind == "tarball" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		h.getTarball(w, r, p, rt)
	case rt.kind == "tarball-rev" && r.Method == http.MethodDelete:
		h.deleteTarball(w, r, p, rt)
	case rt.kind == "disttags":
		h.distTags(w, r, p, rt)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func tarballName(pkg, version string) string {
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	return pkg + "-" + version + ".tgz"
}

// effectiveTags drops tags pointing at versions that aren't visible and
// ensures "latest" exists, since npm needs it to install without a range.
func effectiveTags(tags map[string]string, versions []registry.Version) map[string]string {
	visible := map[string]bool{}
	for _, v := range versions {
		visible[v.Version] = true
	}
	out := map[string]string{}
	for t, v := range tags {
		if visible[v] {
			out[t] = v
		}
	}
	if _, ok := out["latest"]; !ok && len(versions) > 0 {
		latest := versions[len(versions)-1].Version
		for i := len(versions) - 1; i >= 0; i-- {
			if !versions[i].Yanked {
				latest = versions[i].Version
				break
			}
		}
		out["latest"] = latest
	}
	return out
}

func (h *Handler) load(r *http.Request, p identity.Principal, rt route) ([]registry.Version, map[string]string, error) {
	versions, err := h.svc.Versions(r.Context(), p, rt.repo, rt.pkg)
	if err != nil {
		return nil, nil, err
	}
	if len(versions) == 0 {
		return nil, nil, registry.ErrNotFound
	}
	tags, err := h.svc.DistTags(r.Context(), p, rt.repo, rt.pkg)
	if err != nil {
		return nil, nil, err
	}
	return versions, effectiveTags(tags, versions), nil
}

func (h *Handler) getPackument(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	versions, tags, err := h.load(r, p, rt)
	if err != nil {
		writeError(w, err)
		return
	}
	docVersions := map[string]any{}
	times := map[string]string{}
	for _, v := range versions {
		m := map[string]any{}
		if len(v.Manifest) > 0 {
			if err := json.Unmarshal(v.Manifest, &m); err != nil {
				writeError(w, err)
				return
			}
		}
		m["name"], m["version"] = v.DisplayName, v.Version
		if len(v.Files) > 0 {
			f := v.Files[0]
			m["dist"] = map[string]any{
				"tarball":   h.baseURL(r) + Prefix + rt.repo + "/" + rt.pkg + "/-/" + f.Filename,
				"shasum":    f.Attrs["shasum"],
				"integrity": f.Attrs["integrity"],
			}
		}
		if v.Yanked {
			m["deprecated"] = deprecationMessage(v)
		}
		docVersions[v.Version] = m
		times[v.Version] = v.PublishedAt.UTC().Format(time.RFC3339Nano)
	}
	times["created"] = versions[0].PublishedAt.UTC().Format(time.RFC3339Nano)
	times["modified"] = versions[len(versions)-1].PublishedAt.UTC().Format(time.RFC3339Nano)

	writeJSON(w, http.StatusOK, map[string]any{
		"_id":       versions[0].DisplayName,
		"name":      versions[0].DisplayName,
		"_rev":      strconv.Itoa(len(versions)) + "-hextrap",
		"dist-tags": tags,
		"versions":  docVersions,
		"time":      times,
	})
}

type putBody struct {
	Name        string                     `json:"name"`
	Versions    map[string]json.RawMessage `json:"versions"`
	DistTags    map[string]string          `json:"dist-tags"`
	Attachments map[string]struct {
		Data   string `json:"data"`
		Length int    `json:"length"`
	} `json:"_attachments"`
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	var body putBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPublishSize)).Decode(&body); err != nil {
		writeError(w, invalid("malformed JSON: %v", err))
		return
	}
	if len(body.Attachments) > 0 {
		h.publish(w, r, p, rt, body)
		return
	}
	h.updateMetadata(w, r, p, rt, body)
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, body putBody) {
	if err := h.publishErr(r, p, rt, body); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"success": true})
}

func (h *Handler) publishErr(r *http.Request, p identity.Principal, rt route, body putBody) error {
	if body.Name != rt.pkg {
		return invalid("package name %q does not match URL %q", body.Name, rt.pkg)
	}
	if !nameRE.MatchString(rt.pkg) || len(rt.pkg) > 214 {
		return invalid("invalid package name %q", rt.pkg)
	}
	if len(body.Versions) != 1 || len(body.Attachments) != 1 {
		return invalid("publish exactly one version with one tarball")
	}
	var version string
	var raw json.RawMessage
	for version, raw = range body.Versions {
	}
	if !versionRE.MatchString(version) {
		return invalid("invalid version %q", version)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return invalid("malformed version manifest")
	}
	if manifest["name"] != rt.pkg || manifest["version"] != version {
		return invalid("version manifest name/version mismatch")
	}

	var data []byte
	for _, a := range body.Attachments {
		var err error
		if data, err = base64.StdEncoding.DecodeString(a.Data); err != nil {
			return invalid("tarball is not valid base64")
		}
		if a.Length != 0 && a.Length != len(data) {
			return invalid("tarball length mismatch")
		}
	}
	sha1sum := sha1.Sum(data)
	sha512sum := sha512.Sum512(data)
	shasum := hex.EncodeToString(sha1sum[:])
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sha512sum[:])
	if dist, ok := manifest["dist"].(map[string]any); ok {
		if s, ok := dist["shasum"].(string); ok && s != shasum {
			return invalid("shasum does not match tarball")
		}
		if s, ok := dist["integrity"].(string); ok && strings.HasPrefix(s, "sha512-") && s != integrity {
			return invalid("integrity does not match tarball")
		}
	}
	// dist is regenerated when serving; deprecation is registry state.
	delete(manifest, "dist")
	delete(manifest, "deprecated")
	stored, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	var tags []string
	for t, v := range body.DistTags {
		if v == version {
			tags = append(tags, t)
		}
	}
	return h.svc.Publish(r.Context(), p, rt.repo, registry.VersionInput{
		Package: rt.pkg, DisplayName: rt.pkg, Version: version, Manifest: stored, DistTags: tags,
		Files: []registry.FileInput{{
			Filename: tarballName(rt.pkg, version),
			Content:  bytes.NewReader(data),
			Attrs:    map[string]string{"shasum": shasum, "integrity": integrity},
		}},
	})
}

// updateMetadata handles the packument PUT that `npm deprecate` and
// `npm unpublish <pkg>@<version>` send: deprecation changes become yanks and
// versions missing from the document are deleted.
func (h *Handler) updateMetadata(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, body putBody) {
	ctx := r.Context()
	versions, err := h.svc.Versions(ctx, p, rt.repo, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(versions) == 0 {
		writeError(w, registry.ErrNotFound)
		return
	}

	type change struct {
		version, deprecated string
		remove              bool
	}
	var changes []change
	needed := rbac.ActionPull
	for _, v := range versions {
		raw, present := body.Versions[v.Version]
		if !present {
			changes = append(changes, change{version: v.Version, remove: true})
			needed = rbac.ActionDelete
			continue
		}
		var m struct {
			Deprecated string `json:"deprecated"`
		}
		_ = json.Unmarshal(raw, &m)
		current := ""
		if v.Yanked {
			current = deprecationMessage(v)
		}
		if m.Deprecated != current {
			changes = append(changes, change{version: v.Version, deprecated: m.Deprecated})
			if needed != rbac.ActionDelete {
				needed = rbac.ActionYank
			}
		}
	}

	// Check permission before changing anything so the update isn't partial.
	repo, err := h.svc.Repo(ctx, p, rt.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	if !repo.Role.Can(needed) {
		writeError(w, registry.ErrForbidden)
		return
	}

	for _, c := range changes {
		switch {
		case c.remove:
			err = h.svc.Delete(ctx, p, rt.repo, rt.pkg, c.version)
		case c.deprecated != "":
			err = h.svc.Yank(ctx, p, rt.repo, rt.pkg, c.version, c.deprecated)
		default:
			err = h.svc.Unyank(ctx, p, rt.repo, rt.pkg, c.version)
		}
		if err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// unpublishAll handles `npm unpublish <pkg> --force`.
func (h *Handler) unpublishAll(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	ctx := r.Context()
	versions, err := h.svc.Versions(ctx, p, rt.repo, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(versions) == 0 {
		writeError(w, registry.ErrNotFound)
		return
	}
	repo, err := h.svc.Repo(ctx, p, rt.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	if !repo.Role.Can(rbac.ActionDelete) {
		writeError(w, registry.ErrForbidden)
		return
	}
	for _, v := range versions {
		if err := h.svc.Delete(ctx, p, rt.repo, rt.pkg, v.Version); err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *Handler) getTarball(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	rc, f, err := h.svc.OpenFile(r.Context(), p, rt.repo, rt.pkg, rt.file)
	if err != nil {
		writeError(w, err)
		return
	}
	sendTarball(w, r, rc, f, "")
}

// sendTarball streams a stored tarball. cache, if set, is reported in
// X-Hextrap-Cache ("hit" or "miss") for proxy repos.
func sendTarball(w http.ResponseWriter, r *http.Request, rc io.ReadCloser, f registry.File, cache string) {
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
		slog.Error("streaming tarball", "file", f.Filename, "err", err)
	}
}

// deleteTarball is the second request of `npm unpublish <pkg>@<version>`.
// The version is normally already deleted by the preceding PUT.
func (h *Handler) deleteTarball(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	ctx := r.Context()
	versions, err := h.svc.Versions(ctx, p, rt.repo, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	for _, v := range versions {
		for _, f := range v.Files {
			if f.Filename == rt.file {
				if err := h.svc.Delete(ctx, p, rt.repo, rt.pkg, v.Version); err != nil {
					writeError(w, err)
					return
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *Handler) distTags(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	ctx := r.Context()
	switch {
	case r.Method == http.MethodGet && rt.tag == "":
		_, tags, err := h.load(r, p, rt)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, tags)
	case r.Method == http.MethodPut && rt.tag != "":
		var version string
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&version); err != nil {
			writeError(w, invalid("body must be a JSON string version"))
			return
		}
		if err := h.svc.SetDistTag(ctx, p, rt.repo, rt.pkg, rt.tag, version); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case r.Method == http.MethodDelete && rt.tag != "":
		if rt.tag == "latest" {
			writeError(w, invalid("the latest tag cannot be removed"))
			return
		}
		if err := h.svc.RemoveDistTag(ctx, p, rt.repo, rt.pkg, rt.tag); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

const defaultDeprecation = "This version has been yanked."

// deprecationMessage is never empty for a yanked version, since npm treats
// an empty "deprecated" as not deprecated.
func deprecationMessage(v registry.Version) string {
	if v.YankReason == "" {
		return defaultDeprecation
	}
	return v.YankReason
}
