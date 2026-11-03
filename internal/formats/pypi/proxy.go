package pypi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

// Proxy repositories serve an upstream index (PyPI's JSON simple API) with
// download links rewritten to this server. A file is fetched from upstream
// on its first request, checked against the hash the upstream declared,
// stored, and served from storage after that.

type upstreamFile struct {
	Filename         string            `json:"filename"`
	URL              string            `json:"url"`
	Hashes           map[string]string `json:"hashes"`
	RequiresPython   string            `json:"requires-python"`
	Yanked           any               `json:"yanked"`
	CoreMetadata     any               `json:"core-metadata"`
	DistInfoMetadata any               `json:"dist-info-metadata"`
	UploadTime       string            `json:"upload-time"`
	Size             int64             `json:"size"`

	version     string // normalized, from the filename
	metadataSHA string // PEP 658 metadata hash, if declared
}

func (h *Handler) SetClock(now func() time.Time)    { h.proxy.SetClock(now) }
func (h *Handler) SetGate(g upstream.Gate)          { h.proxy.SetGate(g) }
func (h *Handler) SetUpstreamClient(c *http.Client) { h.proxy.SetClient(c) }

// AddFirewall marks a hextrap firewall upstream and sets its credentials.
func (h *Handler) AddFirewall(url, username, password string) {
	h.proxy.AddFirewall(url, username, password)
}

// lookupRepo loads a repo the caller can pull from, writing the error if
// they can't.
func (h *Handler) lookupRepo(w http.ResponseWriter, r *http.Request, name string) (registry.RepoView, bool) {
	rv, err := h.svc.Repo(r.Context(), identity.FromContext(r.Context()), name)
	if err != nil {
		writeError(w, err)
		return rv, false
	}
	return rv, true
}

var sha256RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func metadataHash(v any) string {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["sha256"].(string); ok && sha256RE.MatchString(s) {
			return strings.ToLower(s)
		}
	}
	return ""
}

var upstreamFilenameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// fetchIndex reads a project's files from upstream, keeping only those this
// server can verify and serve.
func (h *Handler) fetchIndex(ctx context.Context, repo registry.Repo, project string) ([]upstreamFile, error) {
	indexURL := repo.Upstream + "/simple/" + project + "/"
	resp, err := h.proxy.Get(ctx, indexURL, http.Header{"Accept": {jsonType}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != jsonType {
		return nil, fmt.Errorf("%w: upstream doesn't serve the JSON simple API (PEP 691)", registry.ErrUpstreamUnavailable)
	}
	var doc struct {
		Files []upstreamFile `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: malformed index: %v", registry.ErrUpstreamUnavailable, err)
	}

	base, _ := url.Parse(indexURL)
	var out []upstreamFile
	for _, f := range doc.Files {
		u, err := base.Parse(f.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		u.Fragment = ""
		f.URL = u.String()
		if !upstreamFilenameRE.MatchString(f.Filename) || !sha256RE.MatchString(f.Hashes["sha256"]) {
			continue
		}
		name, version, _, err := parseFilename(f.Filename)
		if err != nil || NormalizeName(name) != project {
			continue // legacy formats (.egg, .exe) and stray files
		}
		if f.version, err = NormalizeVersion(version); err != nil {
			continue
		}
		f.Hashes = map[string]string{"sha256": strings.ToLower(f.Hashes["sha256"])}
		f.metadataSHA = metadataHash(f.CoreMetadata)
		if f.metadataSHA == "" {
			f.metadataSHA = metadataHash(f.DistInfoMetadata)
		}
		switch f.Yanked.(type) {
		case bool, string:
		default:
			f.Yanked = false
		}
		out = append(out, f)
	}
	return out, nil
}

// index returns a project's upstream files, reusing a recent fetch unless
// force is set.
func (h *Handler) index(ctx context.Context, repo registry.Repo, project string, force bool) ([]upstreamFile, error) {
	v, err := h.proxy.Cached("pypi/"+repo.Tenant+"/"+repo.Name+"/"+project, force, func() (any, error) {
		return h.fetchIndex(ctx, repo, project)
	})
	if err != nil {
		return nil, err
	}
	return v.([]upstreamFile), nil
}

func (h *Handler) proxyProjectPage(w http.ResponseWriter, r *http.Request, repo registry.Repo, project string) {
	ctx, p := r.Context(), identity.FromContext(r.Context())
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, project)
	if err != nil {
		writeError(w, err)
		return
	}
	files, err := h.index(ctx, repo, project, false)
	if err != nil {
		// Upstream is unreachable or doesn't know the project: offer
		// whatever is cached, so installs of cached versions keep working.
		if !errors.Is(err, registry.ErrNotFound) {
			slog.Warn("upstream index unavailable; serving cached files", "repo", repo.Name, "project", project, "err", err)
		}
		versions, verr := h.svc.Versions(ctx, p, repo.Name, project)
		if verr != nil {
			writeError(w, verr)
			return
		}
		if len(versions) == 0 {
			writeError(w, err)
			return
		}
		stored, versionList := h.storedIndexFiles(r, repo.Name, project, versions)
		renderIndex(w, r, project, stored, versionList)
		return
	}

	var out []indexFile
	var versions []string
	seen := map[string]bool{}
	for _, f := range files {
		if removed[f.version] {
			continue
		}
		var core any = false
		if f.metadataSHA != "" {
			core = map[string]string{"sha256": f.metadataSHA}
		}
		out = append(out, indexFile{
			Filename:       f.Filename,
			URL:            h.fileURL(r, repo.Name, project, f.Filename),
			Hashes:         f.Hashes,
			RequiresPython: f.RequiresPython,
			Yanked:         f.Yanked,
			CoreMetadata:   core,
			DistInfoMeta:   core,
			Size:           f.Size,
			UploadTime:     f.UploadTime,
		})
		if !seen[f.version] {
			seen[f.version] = true
			versions = append(versions, f.version)
		}
	}
	renderIndex(w, r, project, out, versions)
}

func findFile(files []upstreamFile, filename string) (upstreamFile, bool) {
	for _, f := range files {
		if f.Filename == filename {
			return f, true
		}
	}
	return upstreamFile{}, false
}

// findUpstreamFile looks a file up in the project index, refreshing it once
// if the file isn't there (it may have been released since).
func (h *Handler) findUpstreamFile(ctx context.Context, repo registry.Repo, project, filename string) (upstreamFile, error) {
	for _, force := range []bool{false, true} {
		files, err := h.index(ctx, repo, project, force)
		if err != nil {
			return upstreamFile{}, err
		}
		if f, ok := findFile(files, filename); ok {
			return f, nil
		}
	}
	return upstreamFile{}, registry.ErrNotFound
}

func (h *Handler) proxyDownload(w http.ResponseWriter, r *http.Request, repo registry.Repo, project, filename string) {
	ctx, p := r.Context(), identity.FromContext(r.Context())
	rc, f, err := h.svc.OpenFile(ctx, p, repo.Name, project, filename)
	if err == nil {
		if err := h.recheck(ctx, repo, project, filename); err != nil {
			rc.Close()
			writeError(w, err)
			return
		}
		serveFile(w, r, rc, f, "hit")
		return
	}
	if !errors.Is(err, registry.ErrNotFound) {
		writeError(w, err)
		return
	}

	base, isMetadata := strings.CutSuffix(filename, metadataExt)
	uf, err := h.findUpstreamFile(ctx, repo, project, base)
	if err != nil {
		writeError(w, err)
		return
	}
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, project)
	if err != nil {
		writeError(w, err)
		return
	}
	if removed[uf.version] {
		writeError(w, registry.ErrNotFound)
		return
	}
	src, expected := h.proxy.ViaFirewall(repo, uf.URL), uf.Hashes["sha256"]
	if isMetadata {
		if uf.metadataSHA == "" {
			writeError(w, registry.ErrNotFound)
			return
		}
		src, expected = uf.URL+metadataExt, uf.metadataSHA
	}

	published, _ := time.Parse(time.RFC3339Nano, uf.UploadTime)
	if err := h.proxy.Check(ctx, upstream.Request{Repo: repo, Package: project, Version: uf.version, Filename: filename, Published: published}); err != nil {
		writeError(w, err)
		return
	}

	// Finish the download even if this requester disconnects; others may
	// be waiting on it.
	err = h.proxy.Once("pypi/"+repo.Tenant+"/"+repo.Name+"/"+filename, func() error {
		return h.downloadAndCache(context.WithoutCancel(ctx), p, repo, project, uf, filename, src, expected)
	})
	if err != nil {
		if errors.Is(err, registry.ErrVersionExists) {
			err = registry.ErrNotFound // removed by an admin meanwhile
		}
		writeError(w, err)
		return
	}
	rc, f, err = h.svc.OpenFile(ctx, p, repo.Name, project, filename)
	if err != nil {
		writeError(w, err)
		return
	}
	serveFile(w, r, rc, f, "miss")
}

// recheck asks a firewall repo's firewall whether a cached file may still be
// served. Metadata files aren't subject to policy. If the file can't be
// found upstream, the cached copy is served.
func (h *Handler) recheck(ctx context.Context, repo registry.Repo, project, filename string) error {
	if !h.proxy.IsFirewall(repo) || strings.HasSuffix(filename, metadataExt) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, upstream.RecheckTimeout)
	defer cancel()
	uf, err := h.findUpstreamFile(ctx, repo, project, filename)
	if err != nil {
		return nil
	}
	return h.proxy.Recheck(ctx, repo, h.proxy.ViaFirewall(repo, uf.URL))
}

func (h *Handler) downloadAndCache(ctx context.Context, p identity.Principal, repo registry.Repo, project string, uf upstreamFile, filename, src, expected string) error {
	resp, err := h.proxy.Get(ctx, src, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var attrs map[string]string
	if !strings.HasSuffix(filename, metadataExt) && uf.RequiresPython != "" {
		attrs = map[string]string{"requires_python": uf.RequiresPython}
	}
	return h.svc.CacheFile(ctx, p, repo.Name, upstream.Host(repo), registry.VersionInput{
		Package: project, DisplayName: project, Version: uf.version,
		Files: []registry.FileInput{{
			Filename: filename,
			// A truncated (over-limit) body fails the hash check.
			Content:  io.LimitReader(resp.Body, maxUploadSize),
			Attrs:    attrs,
			Expected: registry.Checksums{"sha256": expected},
		}},
	})
}
