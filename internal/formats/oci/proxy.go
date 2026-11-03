package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

// A proxy repository caches images from an upstream registry such as
// Docker Hub. Manifests and blobs are content-addressed, so everything
// fetched is checked against its digest before it's stored. Blobs are
// fetched only for manifests already cached in the repository.

var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

func sha256Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func isDockerHub(upstreamURL string) bool {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "registry-1.docker.io", "index.docker.io", "docker.io":
		return true
	}
	return false
}

// upstreamName maps an image name to the upstream's: Docker Hub's official
// images live under library/.
func upstreamName(upstreamURL, image string) string {
	return upstreamNameWith(isDockerHub, upstreamURL, image)
}

func upstreamNameWith(library func(string) bool, upstreamURL, image string) string {
	if !strings.Contains(image, "/") && library(upstreamURL) {
		return "library/" + image
	}
	return image
}

// ---------- Bearer tokens ----------

// tokenCache gets anonymous pull tokens from an upstream's token service,
// as named in its WWW-Authenticate challenge.
type tokenCache struct {
	proxy  *upstream.Proxy
	now    func() time.Time
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

func newTokenCache(p *upstream.Proxy) *tokenCache {
	return &tokenCache{proxy: p, now: time.Now, tokens: map[string]cachedToken{}}
}

func (c *tokenCache) get(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tokens[key]
	if !ok || c.now().After(t.expires) {
		return ""
	}
	return t.token
}

// parseChallenge parses `Bearer realm="...",service="...",scope="..."`.
func parseChallenge(h string) (map[string]string, bool) {
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return nil, false
	}
	params := map[string]string{}
	for rest != "" {
		k, v, ok := strings.Cut(strings.TrimLeft(rest, " ,"), "=")
		if !ok {
			break
		}
		if !strings.HasPrefix(v, `"`) {
			break
		}
		end := strings.Index(v[1:], `"`)
		if end < 0 {
			break
		}
		params[strings.ToLower(strings.TrimSpace(k))] = v[1 : end+1]
		rest = v[end+2:]
	}
	return params, params["realm"] != ""
}

func (c *tokenCache) fetch(ctx context.Context, key, upstreamURL, challenge string) (string, error) {
	params, ok := parseChallenge(challenge)
	if !ok {
		return "", fmt.Errorf("%w: upstream requires credentials", registry.ErrUpstreamUnavailable)
	}
	realm, err := url.Parse(params["realm"])
	up, uerr := url.Parse(upstreamURL)
	// A token service over plain HTTP only for a plain-HTTP upstream.
	if err != nil || uerr != nil || (realm.Scheme != "https" && !(realm.Scheme == "http" && up.Scheme == "http")) {
		return "", fmt.Errorf("%w: unusable token service %q", registry.ErrUpstreamUnavailable, params["realm"])
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	if s := params["scope"]; s != "" {
		q.Set("scope", s)
	}
	realm.RawQuery = q.Encode()
	resp, err := c.proxy.Get(ctx, realm.String(), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("%w: malformed token response", registry.ErrUpstreamUnavailable)
	}
	token := body.Token
	if token == "" {
		token = body.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("%w: token service returned no token", registry.ErrUpstreamUnavailable)
	}
	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl < time.Minute {
		ttl = time.Minute // the spec's minimum
	}
	c.mu.Lock()
	c.tokens[key] = cachedToken{token, c.now().Add(ttl - 10*time.Second)}
	c.mu.Unlock()
	return token, nil
}

// get fetches path ("/manifests/<ref>", ...) for an image from a proxy
// repo's upstream, getting a token if challenged. A 404 is ErrNotFound.
func (h *Handler) get(ctx context.Context, repo registry.Repo, image, path, accept string) (*http.Response, error) {
	name := upstreamNameWith(h.libraryPrefix, repo.Upstream, image)
	rawURL := repo.Upstream + "/v2/" + name + path
	key := repo.Upstream + "|" + name
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if t := h.auth.get(key); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
		resp, err := h.proxy.Do(req)
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			challenge := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			if _, err := h.auth.fetch(ctx, key, repo.Upstream, challenge); err != nil {
				return nil, err
			}
			continue
		case resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			return nil, registry.ErrNotFound
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			resp.Body.Close()
			return nil, fmt.Errorf("%w: upstream returned %s", registry.ErrUpstreamUnavailable, resp.Status)
		}
		return resp, nil
	}
}

// ---------- Manifests ----------

// fetchManifest gets and verifies a manifest from upstream.
func (h *Handler) fetchManifest(ctx context.Context, repo registry.Repo, rt route) (registry.ImageManifest, error) {
	if err := h.proxy.Check(ctx, upstream.Request{Repo: repo, Package: rt.image, Version: rt.ref, Filename: "manifest"}); err != nil {
		return registry.ImageManifest{}, err
	}
	resp, err := h.get(ctx, repo, rt.image, "/manifests/"+rt.ref, manifestAccept)
	if err != nil {
		return registry.ImageManifest{}, err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return registry.ImageManifest{}, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	if len(content) > maxManifestSize {
		return registry.ImageManifest{}, fmt.Errorf("%w: manifest too large", registry.ErrUpstreamUnavailable)
	}
	d := digestOf(content)
	if hd := resp.Header.Get("Docker-Content-Digest"); hd != "" && blob.Digest(hd) != d {
		return registry.ImageManifest{}, fmt.Errorf("%w: manifest doesn't match the digest the upstream declared", registry.ErrDigestMismatch)
	}
	if blob.Digest(rt.ref).Validate() == nil && blob.Digest(rt.ref) != d {
		return registry.ImageManifest{}, fmt.Errorf("%w: manifest doesn't match %s", registry.ErrDigestMismatch, rt.ref)
	}
	mediaType, refs, err := parseManifest(content, strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if err != nil {
		return registry.ImageManifest{}, fmt.Errorf("%w: %v", registry.ErrUpstreamUnavailable, err)
	}
	m := registry.ImageManifest{Package: rt.image, Digest: d, MediaType: mediaType, Content: content, Blobs: refs}
	if blob.Digest(rt.ref).Validate() != nil {
		m.Tags = []string{rt.ref}
	}
	return m, nil
}

func (h *Handler) proxyManifest(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	byDigest := blob.Digest(rt.ref).Validate() == nil
	removed, err := h.svc.RemovedVersions(ctx, p, repo.Name, rt.image)
	if err != nil {
		writeError(w, err, kindManifest, true)
		return
	}
	if byDigest {
		if removed[rt.ref] {
			writeError(w, registry.ErrNotFound, kindManifest, true)
			return
		}
		// Content-addressed: a cached manifest never changes.
		if v, err := h.resolve(r, p, rt); err == nil {
			h.sendManifest(w, r, p, rt, v, "hit")
			return
		}
	}
	key := "oci/" + repo.Tenant + "/" + repo.Name + "/" + rt.image + ":" + rt.ref
	_, err = h.proxy.Cached(key, false, func() (any, error) {
		m, err := h.fetchManifest(ctx, repo, rt)
		if err != nil {
			return nil, err
		}
		if removed[string(m.Digest)] {
			return nil, registry.ErrNotFound
		}
		err = h.proxy.Once(key, func() error {
			return h.svc.CacheManifest(context.WithoutCancel(ctx), p, repo.Name, upstream.Host(repo), m)
		})
		return m.Digest, err
	})
	if err != nil && (errors.Is(err, registry.ErrBlocked) || errors.Is(err, registry.ErrDigestMismatch) || byDigest) {
		writeError(w, err, kindManifest, true)
		return
	}
	if err != nil && !errors.Is(err, registry.ErrNotFound) {
		slog.Warn("upstream unavailable; serving cached image tag", "repo", repo.Name, "image", rt.image, "ref", rt.ref, "err", err)
	}
	// Serve what's cached: the tag was just refreshed, or upstream is down.
	v, rerr := h.resolve(r, p, rt)
	if rerr != nil {
		if err == nil {
			err = rerr
		}
		writeError(w, err, kindManifest, true)
		return
	}
	h.sendManifest(w, r, p, rt, v, "")
}

// ---------- Blobs ----------

// owningManifest finds a cached manifest of the image that references d.
func (h *Handler) owningManifest(ctx context.Context, p identity.Principal, repo, image string, d blob.Digest) (blob.Digest, error) {
	versions, err := h.svc.Versions(ctx, p, repo, image)
	if err != nil {
		return "", err
	}
	for _, v := range versions {
		meta, err := registry.ImageMetaOf(v)
		if err == nil && slices.Contains(meta.Blobs, d) {
			return blob.Digest(v.Version), nil
		}
	}
	return "", registry.ErrNotFound
}

func (h *Handler) proxyBlob(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	d := blob.Digest(rt.ref)
	if _, err := h.svc.StatBlob(ctx, p, repo.Name, d); err == nil {
		h.getBlob(w, r, p, rt, "hit")
		return
	} else if !errors.Is(err, registry.ErrNotFound) {
		writeError(w, err, kindBlob, true)
		return
	}
	manifest, err := h.owningManifest(ctx, p, repo.Name, rt.image, d)
	if err != nil {
		writeError(w, err, kindBlob, true)
		return
	}
	// Finish the download even if this requester disconnects; others may
	// be waiting on it.
	err = h.proxy.Once("oci/"+repo.Tenant+"/"+repo.Name+"/"+string(d), func() error {
		ctx := context.WithoutCancel(ctx)
		resp, err := h.get(ctx, repo, rt.image, "/blobs/"+string(d), "")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return h.svc.CacheBlob(ctx, p, repo.Name, upstream.Host(repo), rt.image, manifest, d, resp.Body)
	})
	if err != nil {
		writeError(w, err, kindBlob, true)
		return
	}
	h.getBlob(w, r, p, rt, "miss")
}

// ---------- Tags ----------

func (h *Handler) proxyTags(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, repo registry.Repo) {
	ctx := r.Context()
	key := "oci/" + repo.Tenant + "/" + repo.Name + "/" + rt.image + "/tags"
	v, err := h.proxy.Cached(key, false, func() (any, error) {
		resp, err := h.get(ctx, repo, rt.image, "/tags/list", "")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
			return nil, fmt.Errorf("%w: malformed tag list", registry.ErrUpstreamUnavailable)
		}
		return body.Tags, nil
	})
	if err != nil {
		if !errors.Is(err, registry.ErrNotFound) {
			slog.Warn("upstream unavailable; listing cached image tags", "repo", repo.Name, "image", rt.image, "err", err)
		}
		h.listTags(w, r, p, rt, nil)
		return
	}
	set := map[string]bool{}
	for _, t := range v.([]string) {
		if registry.ValidImageTag(t) {
			set[t] = true
		}
	}
	writeTags(w, r, rt, set)
}
