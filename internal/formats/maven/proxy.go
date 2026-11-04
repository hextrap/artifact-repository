package maven

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

// A proxy repository caches files from an upstream Maven repository such as
// Maven Central. Each file is checked against the upstream's own checksum
// file (sha256 where published, else sha1) before it's stored.

func upstreamURL(repo registry.Repo, mp mavenPath, file string) string {
	return repo.Upstream + "/" + mp.dir() + file
}

func (h *Handler) proxyGet(w http.ResponseWriter, r *http.Request, p identity.Principal, mp mavenPath, repo registry.Repo) {
	ctx := r.Context()
	if mp.metadata {
		h.proxyMetadata(w, r, p, mp, repo)
		return
	}
	rc, f, err := h.svc.OpenFile(ctx, p, repo.Name, mp.pkg(), mp.base)
	if err == nil {
		h.serveStored(w, r, rc, f, mp, "hit")
		return
	}
	if !errors.Is(err, registry.ErrNotFound) {
		writeError(w, err)
		return
	}
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, mp.pkg())
	if err != nil {
		writeError(w, err)
		return
	}
	if removed[mp.version] {
		writeError(w, registry.ErrNotFound)
		return
	}
	if mp.checksum != "" {
		h.passThroughChecksum(w, r, mp, repo)
		return
	}

	expected, published, err := h.upstreamChecksum(ctx, repo, mp)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.proxy.Check(ctx, upstream.Request{Repo: repo, Package: mp.pkg(), Version: mp.version, Filename: mp.base, Published: published}); err != nil {
		writeError(w, err)
		return
	}
	// Finish the download even if this requester disconnects; others may
	// be waiting on it.
	err = h.proxy.Once("maven/"+repo.Tenant+"/"+repo.Name+"/"+mp.dir()+mp.base, func() error {
		ctx := context.WithoutCancel(ctx)
		resp, err := h.proxy.Get(ctx, upstreamURL(repo, mp, mp.base), nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return h.svc.CacheFile(ctx, p, repo.Name, upstream.Host(repo), registry.VersionInput{
			Package: mp.pkg(), DisplayName: mp.pkg(), Version: mp.version,
			Files: []registry.FileInput{{
				Filename: mp.base,
				// A truncated (over-limit) body fails the checksum.
				Content:  io.LimitReader(resp.Body, maxUploadSize),
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
	rc, f, err = h.svc.OpenFile(ctx, p, repo.Name, mp.pkg(), mp.base)
	if err != nil {
		writeError(w, err)
		return
	}
	h.serveStored(w, r, rc, f, mp, "miss")
}

// upstreamChecksum fetches the checksum the upstream publishes for a file,
// preferring sha256. Its Last-Modified date stands in for the publish date.
func (h *Handler) upstreamChecksum(ctx context.Context, repo registry.Repo, mp mavenPath) (registry.Checksums, time.Time, error) {
	for _, algo := range []string{"sha256", "sha1"} {
		resp, err := h.proxy.Get(ctx, upstreamURL(repo, mp, mp.base+"."+algo), nil)
		if errors.Is(err, registry.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
		}
		sum, ok := parseChecksum(body, algo)
		if !ok {
			return nil, time.Time{}, fmt.Errorf("%w: malformed %s for %s", registry.ErrUpstreamUnavailable, algo, mp.base)
		}
		published, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
		return registry.Checksums{algo: sum}, published.UTC(), nil
	}
	return nil, time.Time{}, registry.ErrNotFound
}

// passThroughChecksum serves the upstream's checksum for a file that isn't
// cached yet. Nothing is stored.
func (h *Handler) passThroughChecksum(w http.ResponseWriter, r *http.Request, mp mavenPath, repo registry.Repo) {
	resp, err := h.proxy.Get(r.Context(), upstreamURL(repo, mp, mp.file), nil)
	if err != nil {
		writeError(w, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		writeError(w, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err))
		return
	}
	sum, ok := parseChecksum(body, mp.checksum)
	if !ok {
		writeError(w, fmt.Errorf("%w: malformed upstream checksum", registry.ErrUpstreamUnavailable))
		return
	}
	writeBytes(w, r, []byte(sum), "text/plain; charset=utf-8", "")
}

func (h *Handler) fetchMetadata(ctx context.Context, repo registry.Repo, mp mavenPath) (xmlMetadata, error) {
	resp, err := h.proxy.Get(ctx, upstreamURL(repo, mp, metadataFile), nil)
	if err != nil {
		return xmlMetadata{}, err
	}
	defer resp.Body.Close()
	var m xmlMetadata
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&m); err != nil {
		return xmlMetadata{}, fmt.Errorf("%w: malformed maven-metadata.xml: %v", registry.ErrUpstreamUnavailable, err)
	}
	return m, nil
}

// proxyMetadata serves the upstream's metadata without versions an admin
// removed, or metadata generated from the cache if upstream is unreachable.
func (h *Handler) proxyMetadata(w http.ResponseWriter, r *http.Request, p identity.Principal, mp mavenPath, repo registry.Repo) {
	ctx := r.Context()
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, mp.pkg())
	if err != nil {
		writeError(w, err)
		return
	}
	key := "maven/" + repo.Tenant + "/" + repo.Name + "/" + mp.dir()
	v, err := h.proxy.Cached(key, false, func() (any, error) {
		return h.fetchMetadata(ctx, repo, mp)
	})
	if err != nil && !errors.Is(err, registry.ErrNotFound) {
		// Central rate-limits (429) and has outages; the last copy it
		// served beats metadata rebuilt from the cache, which has only
		// cached versions and no plugin list.
		if stale, ok := h.proxy.Stale(key); ok {
			slog.Warn("upstream metadata unavailable; serving last upstream copy", "repo", repo.Name, "package", mp.pkg(), "err", err)
			v, err = stale, nil
		}
	}
	if err != nil {
		if !errors.Is(err, registry.ErrNotFound) {
			slog.Warn("upstream metadata unavailable; serving cached versions", "repo", repo.Name, "package", mp.pkg(), "err", err)
		}
		versions, verr := h.svc.Versions(ctx, p, repo.Name, mp.pkg())
		if verr != nil {
			writeError(w, verr)
			return
		}
		if len(versions) == 0 {
			writeError(w, err)
			return
		}
		doc, gerr := generateMetadata(mp, versions)
		if gerr != nil {
			writeError(w, gerr)
			return
		}
		serveMetadata(w, r, mp, doc)
		return
	}

	m := v.(xmlMetadata) // a copy; the cached value isn't modified
	var kept []string
	for _, ver := range m.Versioning.Versions {
		if !removed[ver] {
			kept = append(kept, ver)
		}
	}
	m.Versioning.Versions = kept
	if removed[m.Versioning.Latest] || removed[m.Versioning.Release] {
		m.Versioning.Latest, m.Versioning.Release = "", ""
		for _, ver := range kept {
			m.Versioning.Latest = ver
			if !isSnapshot(ver) {
				m.Versioning.Release = ver
			}
		}
	}
	doc, err := marshalMetadata(m)
	if err != nil {
		writeError(w, err)
		return
	}
	serveMetadata(w, r, mp, doc)
}
