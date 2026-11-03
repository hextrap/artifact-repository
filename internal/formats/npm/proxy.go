package npm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

// Proxy repositories serve the upstream registry's packuments with tarball
// links rewritten to this server. A tarball is fetched on its first
// request, checked against the integrity (sha512) or shasum (sha1) the
// packument declares, stored, and served from storage after that.

func (h *Handler) SetClock(now func() time.Time)    { h.proxy.SetClock(now) }
func (h *Handler) SetGate(g upstream.Gate)          { h.proxy.SetGate(g) }
func (h *Handler) SetUpstreamClient(c *http.Client) { h.proxy.SetClient(c) }

// AddFirewall marks a hextrap firewall upstream and sets its credentials.
func (h *Handler) AddFirewall(url, username, password string) {
	h.proxy.AddFirewall(url, username, password)
}

// serveProxy handles requests to a proxy repo. Writes are refused.
func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case rt.kind == "package" && read:
		h.proxyPackument(w, r, p, rt, repo)
	case rt.kind == "tarball" && read:
		h.proxyTarball(w, r, p, rt, repo)
	case rt.kind == "disttags" && r.Method == http.MethodGet && rt.tag == "":
		h.proxyDistTags(w, r, p, rt, repo)
	default:
		writeError(w, registry.ErrReadOnly)
	}
}

// upstreamPath is how the npm registry expects a name in a URL.
func upstreamPath(pkg string) string {
	if scope, name, ok := strings.Cut(pkg, "/"); ok && strings.HasPrefix(scope, "@") {
		return scope + "%2f" + url.PathEscape(name)
	}
	return url.PathEscape(pkg)
}

func (h *Handler) fetchPackument(ctx context.Context, repo registry.Repo, pkg string) (map[string]any, error) {
	resp, err := h.proxy.Get(ctx, repo.Upstream+"/"+upstreamPath(pkg), http.Header{"Accept": {"application/json"}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: malformed packument: %v", registry.ErrUpstreamUnavailable, err)
	}
	if _, ok := doc["versions"].(map[string]any); !ok {
		return nil, fmt.Errorf("%w: packument has no versions", registry.ErrUpstreamUnavailable)
	}
	return doc, nil
}

// upstreamPackument returns the cached upstream packument. It's shared:
// callers must not modify it.
func (h *Handler) upstreamPackument(ctx context.Context, repo registry.Repo, pkg string, force bool) (map[string]any, error) {
	v, err := h.proxy.Cached("npm/"+repo.Tenant+"/"+repo.Name+"/"+pkg, force, func() (any, error) {
		return h.fetchPackument(ctx, repo, pkg)
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]any), nil
}

func tarballFile(version map[string]any) string {
	dist, _ := version["dist"].(map[string]any)
	tarball, _ := dist["tarball"].(string)
	u, err := url.Parse(tarball)
	if err != nil {
		return ""
	}
	return path.Base(u.Path)
}

// rewritePackument copies an upstream packument without removed versions,
// with tarball links pointing at this repository.
func (h *Handler) rewritePackument(r *http.Request, repo registry.Repo, pkg string, doc map[string]any, removed map[string]bool) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[k] = v
	}
	versions := map[string]any{}
	for ver, raw := range doc["versions"].(map[string]any) {
		obj, ok := raw.(map[string]any)
		if !ok || removed[ver] {
			continue
		}
		file := tarballFile(obj)
		if file == "" || file == "." || file == "/" {
			continue
		}
		cp := make(map[string]any, len(obj))
		for k, v := range obj {
			cp[k] = v
		}
		dist := map[string]any{}
		if d, ok := obj["dist"].(map[string]any); ok {
			for k, v := range d {
				dist[k] = v
			}
		}
		dist["tarball"] = h.baseURL(r) + Prefix + repo.Name + "/" + pkg + "/-/" + file
		cp["dist"] = dist
		versions[ver] = cp
	}
	out["versions"] = versions

	tags := map[string]any{}
	if dt, ok := doc["dist-tags"].(map[string]any); ok {
		for tag, v := range dt {
			if s, ok := v.(string); ok && versions[s] != nil {
				tags[tag] = s
			}
		}
	}
	out["dist-tags"] = tags

	if times, ok := doc["time"].(map[string]any); ok {
		t := map[string]any{}
		for k, v := range times {
			if !removed[k] {
				t[k] = v
			}
		}
		out["time"] = t
	}
	return out
}

func (h *Handler) proxyPackument(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	doc, err := h.upstreamPackument(ctx, repo, rt.pkg, false)
	if err != nil {
		h.cachedPackument(w, r, p, rt, repo, err)
		return
	}
	writeJSON(w, http.StatusOK, h.rewritePackument(r, repo, rt.pkg, doc, removed))
}

// cachedPackument serves what's cached when upstream can't be reached or
// doesn't know the package, so installs of cached versions keep working.
func (h *Handler) cachedPackument(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo, upstreamErr error) {
	if !errors.Is(upstreamErr, registry.ErrNotFound) {
		slog.Warn("upstream packument unavailable; serving cached versions", "repo", repo.Name, "package", rt.pkg, "err", upstreamErr)
	}
	versions, err := h.svc.Versions(r.Context(), p, repo.Name, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(versions) == 0 {
		writeError(w, upstreamErr)
		return
	}
	h.getPackument(w, r, p, rt)
}

func (h *Handler) proxyDistTags(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	removed, err := h.svc.RemovedVersions(r.Context(), p, repo.Name, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	doc, err := h.upstreamPackument(r.Context(), repo, rt.pkg, false)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.rewritePackument(r, repo, rt.pkg, doc, removed)["dist-tags"])
}

var sha1HexRE = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// expectedChecksums reads the hashes a packument declares for a tarball:
// the sha512 entry of the SRI integrity string and the sha1 shasum.
func expectedChecksums(obj map[string]any) (registry.Checksums, map[string]string) {
	dist, _ := obj["dist"].(map[string]any)
	sums := registry.Checksums{}
	attrs := map[string]string{}
	if integ, ok := dist["integrity"].(string); ok {
		for _, part := range strings.Fields(integ) {
			if b64, ok := strings.CutPrefix(part, "sha512-"); ok {
				if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) == 64 {
					sums["sha512"] = hex.EncodeToString(raw)
					attrs["integrity"] = part
				}
			}
		}
	}
	if s, ok := dist["shasum"].(string); ok && sha1HexRE.MatchString(s) {
		sums["sha1"] = strings.ToLower(s)
		attrs["shasum"] = strings.ToLower(s)
	}
	return sums, attrs
}

// findVersion returns the version whose tarball is file, refreshing the
// packument once if it isn't there (it may have been published since).
func (h *Handler) findVersion(ctx context.Context, repo registry.Repo, pkg, file string) (string, map[string]any, map[string]any, error) {
	for _, force := range []bool{false, true} {
		doc, err := h.upstreamPackument(ctx, repo, pkg, force)
		if err != nil {
			return "", nil, nil, err
		}
		for ver, raw := range doc["versions"].(map[string]any) {
			if obj, ok := raw.(map[string]any); ok && tarballFile(obj) == file {
				return ver, obj, doc, nil
			}
		}
	}
	return "", nil, nil, registry.ErrNotFound
}

func (h *Handler) proxyTarball(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	rc, f, err := h.svc.OpenFile(ctx, p, repo.Name, rt.pkg, rt.file)
	if err == nil {
		// A firewall repo asks again before serving: the package may have
		// been denied since it was cached.
		if err := h.proxy.Recheck(ctx, repo, firewallTarballURL(repo, rt.pkg, rt.file)); err != nil {
			rc.Close()
			writeError(w, err)
			return
		}
		sendTarball(w, r, rc, f, "hit")
		return
	}
	if !errors.Is(err, registry.ErrNotFound) {
		writeError(w, err)
		return
	}

	version, obj, doc, err := h.findVersion(ctx, repo, rt.pkg, rt.file)
	if err != nil {
		writeError(w, err)
		return
	}
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, rt.pkg)
	if err != nil {
		writeError(w, err)
		return
	}
	if removed[version] {
		writeError(w, registry.ErrNotFound)
		return
	}
	expected, attrs := expectedChecksums(obj)
	if len(expected) == 0 {
		writeError(w, fmt.Errorf("%w: upstream declares no checksum for %s", registry.ErrUpstreamUnavailable, rt.file))
		return
	}
	var published time.Time
	if times, ok := doc["time"].(map[string]any); ok {
		if s, ok := times[version].(string); ok {
			published, _ = time.Parse(time.RFC3339Nano, s)
		}
	}
	if err := h.proxy.Check(ctx, upstream.Request{Repo: repo, Package: rt.pkg, Version: version, Filename: rt.file, Published: published}); err != nil {
		writeError(w, err)
		return
	}

	dist, _ := obj["dist"].(map[string]any)
	src, _ := dist["tarball"].(string)
	src = h.proxy.ViaFirewall(repo, src) // packuments link the public registry
	manifest := make(map[string]any, len(obj))
	for k, v := range obj {
		if k != "dist" && k != "deprecated" {
			manifest[k] = v
		}
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		writeError(w, err)
		return
	}

	// Finish the download even if this requester disconnects; others may
	// be waiting on it.
	err = h.proxy.Once("npm/"+repo.Tenant+"/"+repo.Name+"/"+rt.pkg+"/"+rt.file, func() error {
		ctx := context.WithoutCancel(ctx)
		resp, err := h.proxy.Get(ctx, src, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return h.svc.CacheFile(ctx, p, repo.Name, upstream.Host(repo), registry.VersionInput{
			Package: rt.pkg, DisplayName: rt.pkg, Version: version, Manifest: manifestJSON,
			Files: []registry.FileInput{{
				Filename: rt.file,
				// A truncated (over-limit) body fails the hash check.
				Content:  io.LimitReader(resp.Body, maxPublishSize),
				Attrs:    attrs,
				Expected: expected,
			}},
		})
	})
	if err != nil {
		if errors.Is(err, registry.ErrVersionExists) {
			err = registry.ErrNotFound // removed by an admin meanwhile
		}
		writeError(w, err)
		return
	}
	rc, f, err = h.svc.OpenFile(ctx, p, repo.Name, rt.pkg, rt.file)
	if err != nil {
		writeError(w, err)
		return
	}
	sendTarball(w, r, rc, f, "miss")
}

// firewallTarballURL is where repo's upstream serves a tarball, using the
// npm registry's path layout.
func firewallTarballURL(repo registry.Repo, pkg, file string) string {
	parts := strings.Split(pkg, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return repo.Upstream + "/" + strings.Join(parts, "/") + "/-/" + url.PathEscape(file)
}
