package cargo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

// A proxy repository caches crates from an upstream sparse index such as
// index.crates.io. The index is passed through (without versions an admin
// removed); each .crate is checked against the index's cksum before it's
// stored.

type upstreamLine struct {
	raw   json.RawMessage
	name  string
	vers  string
	cksum string
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (h *Handler) upstreamConfig(ctx context.Context, repo registry.Repo) (string, error) {
	v, err := h.proxy.Cached("cargo/"+repo.Tenant+"/"+repo.Name+"/config.json", false, func() (any, error) {
		resp, err := h.proxy.Get(ctx, repo.Upstream+"/config.json", nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var cfg struct {
			DL string `json:"dl"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil || cfg.DL == "" {
			return nil, fmt.Errorf("%w: malformed config.json", registry.ErrUpstreamUnavailable)
		}
		return cfg.DL, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (h *Handler) fetchIndex(ctx context.Context, repo registry.Repo, name string) ([]upstreamLine, error) {
	resp, err := h.proxy.Get(ctx, repo.Upstream+"/"+indexPath(name), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []upstreamLine
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var l struct {
			Name  string `json:"name"`
			Vers  string `json:"vers"`
			Cksum string `json:"cksum"`
		}
		if err := json.Unmarshal(raw, &l); err != nil || !versionRE.MatchString(l.Vers) || !sha256RE.MatchString(l.Cksum) {
			continue
		}
		out = append(out, upstreamLine{raw: append(json.RawMessage(nil), raw...), name: l.Name, vers: l.Vers, cksum: l.Cksum})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading index: %v", registry.ErrUpstreamUnavailable, err)
	}
	return out, nil
}

func (h *Handler) index(ctx context.Context, repo registry.Repo, name string, force bool) ([]upstreamLine, error) {
	v, err := h.proxy.Cached("cargo/"+repo.Tenant+"/"+repo.Name+"/"+packageKey(name), force, func() (any, error) {
		return h.fetchIndex(ctx, repo, name)
	})
	if err != nil {
		return nil, err
	}
	return v.([]upstreamLine), nil
}

func (h *Handler) proxyIndex(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, packageKey(rt.name))
	if err != nil {
		writeError(w, err)
		return
	}
	lines, err := h.index(ctx, repo, rt.name, false)
	if err != nil {
		// Serve what's cached so builds with cached crates keep working.
		if !errors.Is(err, registry.ErrNotFound) {
			slog.Warn("upstream index unavailable; serving cached crates", "repo", repo.Name, "crate", rt.name, "err", err)
		}
		versions, verr := h.svc.Versions(ctx, p, repo.Name, packageKey(rt.name))
		if verr != nil {
			writeError(w, verr)
			return
		}
		if len(versions) == 0 {
			writeError(w, err)
			return
		}
		body, berr := indexLines(versions)
		if berr != nil {
			writeError(w, berr)
			return
		}
		writeIndex(w, r, body)
		return
	}
	var buf bytes.Buffer
	for _, l := range lines {
		if !removed[l.vers] {
			buf.Write(l.raw)
			buf.WriteByte('\n')
		}
	}
	if buf.Len() == 0 {
		writeError(w, registry.ErrNotFound)
		return
	}
	writeIndex(w, r, buf.Bytes())
}

// downloadURL expands the upstream's dl template (RFC 2789 markers, or
// "/{crate}/{version}/download" appended when it has none).
func downloadURL(dl, name, version, cksum string) string {
	lower := strings.ToLower(name)
	prefix := strings.TrimSuffix(indexPath(name), "/"+lower)
	if !strings.Contains(dl, "{") {
		return strings.TrimSuffix(dl, "/") + "/" + name + "/" + version + "/download"
	}
	return strings.NewReplacer(
		"{crate}", name, "{version}", version, "{prefix}", prefix,
		"{lowerprefix}", strings.ToLower(prefix), "{sha256-checksum}", cksum,
	).Replace(dl)
}

func (h *Handler) findLine(ctx context.Context, repo registry.Repo, name, version string) (upstreamLine, error) {
	for _, force := range []bool{false, true} {
		lines, err := h.index(ctx, repo, name, force)
		if err != nil {
			return upstreamLine{}, err
		}
		for _, l := range lines {
			if l.vers == version {
				return l, nil
			}
		}
	}
	return upstreamLine{}, registry.ErrNotFound
}

func (h *Handler) proxyDownload(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	key, file := packageKey(rt.name), crateFile(rt.name, rt.version)
	rc, f, err := h.svc.OpenFile(ctx, p, repo.Name, key, file)
	if err == nil {
		if err := h.recheck(ctx, repo, rt); err != nil {
			rc.Close()
			writeError(w, err)
			return
		}
		sendCrate(w, r, rc, f, "hit")
		return
	}
	if !errors.Is(err, registry.ErrNotFound) {
		writeError(w, err)
		return
	}
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, key)
	if err != nil {
		writeError(w, err)
		return
	}
	if removed[rt.version] {
		writeError(w, registry.ErrNotFound)
		return
	}
	line, err := h.findLine(ctx, repo, rt.name, rt.version)
	if err != nil {
		writeError(w, err)
		return
	}
	dl, err := h.upstreamConfig(ctx, repo)
	if err != nil {
		writeError(w, err)
		return
	}
	// A firewall's dl embeds its credentials; ViaFirewall drops them (we send
	// them) and keeps downloads on the firewall.
	src := h.proxy.ViaFirewall(repo, downloadURL(dl, line.name, line.vers, line.cksum))

	// The index has no dates; the download's Last-Modified stands in for
	// the publish date, read before anything is downloaded. A firewall
	// applies soak time itself, and would log the HEAD as an install.
	var published time.Time
	if !h.proxy.IsFirewall(repo) {
		if hdr, err := h.proxy.Head(ctx, src); err == nil {
			published, _ = http.ParseTime(hdr.Get("Last-Modified"))
		}
	}
	if err := h.proxy.Check(ctx, upstream.Request{Repo: repo, Package: key, Version: rt.version, Filename: file, Published: published.UTC()}); err != nil {
		writeError(w, err)
		return
	}

	// Finish the download even if this requester disconnects; others may
	// be waiting on it.
	err = h.proxy.Once("cargo/"+repo.Tenant+"/"+repo.Name+"/"+file, func() error {
		ctx := context.WithoutCancel(ctx)
		resp, err := h.proxy.Get(ctx, src, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return h.svc.CacheFile(ctx, p, repo.Name, upstream.Host(repo), registry.VersionInput{
			Package: key, DisplayName: line.name, Version: line.vers, Manifest: line.raw,
			Files: []registry.FileInput{{
				Filename: file,
				// A truncated (over-limit) body fails the checksum.
				Content:  io.LimitReader(resp.Body, maxCrateSize),
				Expected: registry.Checksums{"sha256": line.cksum},
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
	rc, f, err = h.svc.OpenFile(ctx, p, repo.Name, key, file)
	if err != nil {
		writeError(w, err)
		return
	}
	sendCrate(w, r, rc, f, "miss")
}

// recheck asks a firewall repo's firewall whether a cached crate may still
// be served. If its download URL can't be worked out, the cached copy is
// served.
func (h *Handler) recheck(ctx context.Context, repo registry.Repo, rt route) error {
	if !h.proxy.IsFirewall(repo) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, upstream.RecheckTimeout)
	defer cancel()
	line, err := h.findLine(ctx, repo, rt.name, rt.version)
	if err != nil {
		return nil
	}
	dl, err := h.upstreamConfig(ctx, repo)
	if err != nil {
		return nil
	}
	return h.proxy.Recheck(ctx, repo, h.proxy.ViaFirewall(repo, downloadURL(dl, line.name, line.vers, line.cksum)))
}
