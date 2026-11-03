// Package oci serves container image repositories over the OCI
// distribution API, which docker, podman, containerd and helm use:
//
//	/v2/                                          ping and auth challenge
//	/v2/<repo>/<image>/manifests/<tag or digest>  GET, HEAD, PUT, DELETE
//	/v2/<repo>/<image>/blobs/<digest>             GET, HEAD
//	/v2/<repo>/<image>/blobs/uploads/[<id>]       POST, PATCH, PUT, GET, DELETE
//	/v2/<repo>/<image>/tags/list
//
// Images are addressed as <host>/<repo>/<image>, e.g.
// repo.example.com/images/team/app:1.0. Clients sign in with docker login,
// using an access token as the password.
package oci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	Prefix          = "/v2/"
	maxManifestSize = 4 << 20
)

type Handler struct {
	svc   *registry.Service
	proxy *upstream.Proxy
	auth  *tokenCache
	// libraryPrefix reports whether an upstream puts single-name images
	// under library/ (Docker Hub does).
	libraryPrefix func(upstreamURL string) bool
}

func New(svc *registry.Service) *Handler {
	h := &Handler{svc: svc, proxy: upstream.New(), libraryPrefix: isDockerHub}
	h.auth = newTokenCache(h.proxy)
	return h
}

func (h *Handler) SetClock(now func() time.Time) {
	h.proxy.SetClock(now)
	h.auth.now = now
}
func (h *Handler) SetGate(g upstream.Gate)              { h.proxy.SetGate(g) }
func (h *Handler) SetUpstreamClient(c *http.Client)     { h.proxy.SetClient(c) }
func (h *Handler) SetLibraryPrefix(f func(string) bool) { h.libraryPrefix = f }

// Op classifies a request for rate limiting.
func (h *Handler) Op(r *http.Request) ratelimit.Op {
	switch {
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		return ratelimit.OpPublish
	case strings.Contains(r.URL.Path, "/blobs/"):
		return ratelimit.OpDownload
	}
	return ratelimit.OpRead
}

// ---------- Errors ----------

// kind says what a request was about, for the error code.
type kind int

const (
	kindName kind = iota
	kindManifest
	kindBlob
	kindUpload
)

// ErrorBody is the OCI error format, for errors written before a request
// reaches the handler (authentication, rate limits).
func ErrorBody(status int, msg string) any {
	code := "UNKNOWN"
	switch status {
	case http.StatusUnauthorized:
		code = "UNAUTHORIZED"
	case http.StatusForbidden:
		code = "DENIED"
	case http.StatusTooManyRequests:
		code = "TOOMANYREQUESTS"
	case http.StatusNotFound:
		code = "NAME_UNKNOWN"
	}
	return errorBody(code, msg)
}

func errorBody(code, msg string) any {
	return map[string]any{"errors": []map[string]string{{"code": code, "message": msg}}}
}

func writeError(w http.ResponseWriter, err error, k kind, proxy bool) {
	status := registry.HTTPStatus(err)
	code := "UNKNOWN"
	switch {
	case errors.Is(err, registry.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", `Basic realm="hextrap"`)
		code = "UNAUTHORIZED"
	case errors.Is(err, registry.ErrForbidden), errors.Is(err, registry.ErrBlocked),
		errors.Is(err, registry.ErrQuotaExceeded), errors.Is(err, registry.ErrVersionExists):
		code = "DENIED"
	case errors.Is(err, registry.ErrBlobUnknown):
		code = "MANIFEST_BLOB_UNKNOWN"
	case errors.Is(err, registry.ErrDigestMismatch):
		code = "DIGEST_INVALID"
		if !proxy {
			status = http.StatusBadRequest // the client sent it
		}
	case errors.Is(err, registry.ErrReadOnly):
		code = "UNSUPPORTED"
	case errors.Is(err, registry.ErrUpstreamUnavailable):
		code = "UNAVAILABLE"
	case errors.Is(err, registry.ErrNotFound):
		code = [...]string{kindName: "NAME_UNKNOWN", kindManifest: "MANIFEST_UNKNOWN", kindBlob: "BLOB_UNKNOWN", kindUpload: "BLOB_UPLOAD_UNKNOWN"}[k]
	case errors.Is(err, registry.ErrInvalid):
		code = [...]string{kindName: "NAME_INVALID", kindManifest: "MANIFEST_INVALID", kindBlob: "DIGEST_INVALID", kindUpload: "BLOB_UPLOAD_INVALID"}[k]
	}
	if status == http.StatusInternalServerError {
		slog.Error("oci request failed", "err", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody(code, registry.PublicMessage(err)))
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", registry.ErrInvalid, fmt.Sprintf(format, args...))
}

// ---------- Routing ----------

type route struct {
	repo, image string
	op          string // ping, manifest, blob, upload, tags
	ref         string // tag, digest or upload ID
}

var uploadIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func parse(path string) (route, error) {
	rest, ok := strings.CutPrefix(path, Prefix)
	if !ok {
		return route{}, registry.ErrNotFound
	}
	if rest == "" {
		return route{op: "ping"}, nil
	}
	segs := strings.Split(rest, "/")
	n := len(segs)
	var rt route
	var nameEnd int
	switch {
	case n >= 5 && segs[n-3] == "blobs" && segs[n-2] == "uploads":
		rt.op, rt.ref, nameEnd = "upload", segs[n-1], n-3
	case n >= 4 && segs[n-2] == "blobs" && segs[n-1] == "uploads":
		rt.op, nameEnd = "upload", n-2
	case n >= 4 && segs[n-2] == "manifests":
		rt.op, rt.ref, nameEnd = "manifest", segs[n-1], n-2
	case n >= 4 && segs[n-2] == "blobs":
		rt.op, rt.ref, nameEnd = "blob", segs[n-1], n-2
	case n >= 4 && segs[n-2] == "tags" && segs[n-1] == "list":
		rt.op, nameEnd = "tags", n-2
	default:
		return route{}, registry.ErrNotFound
	}
	rt.repo, rt.image = segs[0], strings.Join(segs[1:nameEnd], "/")
	if !registry.ValidImageName(rt.image) {
		return rt, invalid("invalid image name %q", rt.image)
	}
	switch rt.op {
	case "blob":
		if blob.Digest(rt.ref).Validate() != nil {
			return rt, invalid("invalid digest %q", rt.ref)
		}
	case "manifest":
		if blob.Digest(rt.ref).Validate() != nil && !registry.ValidImageTag(rt.ref) {
			return rt, invalid("invalid reference %q", rt.ref)
		}
	case "upload":
		if rt.ref != "" && !uploadIDRE.MatchString(rt.ref) {
			return rt, registry.ErrNotFound
		}
	}
	return rt, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	rt, err := parse(r.URL.Path)
	if err != nil {
		writeError(w, err, kindName, false)
		return
	}
	p := identity.FromContext(r.Context())
	if rt.op == "ping" {
		// Clients learn the auth scheme here, then send credentials.
		if p.Kind == identity.KindAnonymous {
			writeError(w, registry.ErrUnauthenticated, kindName, false)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
		return
	}
	rv, err := h.svc.Repo(r.Context(), p, rt.repo)
	if err == nil && rv.Format != registry.FormatOCI {
		err = registry.ErrNotFound
	}
	if err != nil {
		writeError(w, err, kindName, false)
		return
	}
	proxy := rv.Type == registry.TypeProxy
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case rt.op == "manifest" && read && proxy:
		h.proxyManifest(w, r, p, rt, rv.Repo)
	case rt.op == "manifest" && read:
		h.getManifest(w, r, p, rt)
	case rt.op == "blob" && read && proxy:
		h.proxyBlob(w, r, p, rt, rv.Repo)
	case rt.op == "blob" && read:
		h.getBlob(w, r, p, rt, "")
	case rt.op == "tags" && r.Method == http.MethodGet && proxy:
		h.proxyTags(w, r, p, rt, rv.Repo)
	case rt.op == "tags" && r.Method == http.MethodGet:
		h.listTags(w, r, p, rt, nil)
	case proxy:
		writeError(w, registry.ErrReadOnly, kindName, true)
	case rt.op == "manifest" && r.Method == http.MethodPut:
		h.putManifest(w, r, p, rt)
	case rt.op == "manifest" && r.Method == http.MethodDelete:
		h.deleteManifest(w, r, p, rt)
	case rt.op == "upload":
		h.upload(w, r, p, rt)
	default:
		writeError(w, invalid("%s is not supported here", r.Method), kindName, false)
	}
}

// ---------- Manifests ----------

// resolve finds a manifest version by tag or digest.
func (h *Handler) resolve(r *http.Request, p identity.Principal, rt route) (registry.Version, error) {
	ref := rt.ref
	if blob.Digest(ref).Validate() != nil {
		tags, err := h.svc.DistTags(r.Context(), p, rt.repo, rt.image)
		if err != nil {
			return registry.Version{}, err
		}
		if ref = tags[ref]; ref == "" {
			return registry.Version{}, registry.ErrNotFound
		}
	}
	versions, err := h.svc.Versions(r.Context(), p, rt.repo, rt.image)
	if err != nil {
		return registry.Version{}, err
	}
	for _, v := range versions {
		if v.Version == ref {
			return v, nil
		}
	}
	return registry.Version{}, registry.ErrNotFound
}

func (h *Handler) sendManifest(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, v registry.Version, cache string) {
	meta, err := registry.ImageMetaOf(v)
	if err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	rc, f, err := h.svc.OpenFile(r.Context(), p, rt.repo, rt.image, registry.ManifestFile(v))
	if err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", meta.MediaType)
	w.Header().Set("Docker-Content-Digest", v.Version)
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, rc)
}

func (h *Handler) getManifest(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	v, err := h.resolve(r, p, rt)
	if err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	h.sendManifest(w, r, p, rt, v, "")
}

// parsedManifest is what the registry needs from a manifest or index.
type parsedManifest struct {
	MediaType string `json:"mediaType"`
	Config    *struct {
		Digest blob.Digest `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string      `json:"mediaType"`
		Digest    blob.Digest `json:"digest"`
		URLs      []string    `json:"urls"`
	} `json:"layers"`
	Manifests []struct {
		Digest blob.Digest `json:"digest"`
	} `json:"manifests"`
}

// parseManifest returns the media type and referenced digests. Foreign
// layers (with external URLs) aren't stored in registries.
func parseManifest(content []byte, contentType string) (string, []blob.Digest, error) {
	var m parsedManifest
	if err := json.Unmarshal(content, &m); err != nil {
		return "", nil, invalid("manifest is not valid JSON")
	}
	mediaType := contentType
	if mediaType == "" || mediaType == "application/json" || mediaType == "application/octet-stream" {
		mediaType = m.MediaType
	}
	if mediaType == "" {
		return "", nil, invalid("manifest media type is required")
	}
	var refs []blob.Digest
	if m.Config != nil {
		refs = append(refs, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if len(l.URLs) == 0 {
			refs = append(refs, l.Digest)
		}
	}
	for _, c := range m.Manifests {
		refs = append(refs, c.Digest)
	}
	for _, d := range refs {
		if d.Validate() != nil {
			return "", nil, invalid("invalid digest %q in manifest", d)
		}
	}
	return mediaType, refs, nil
}

func digestOf(b []byte) blob.Digest {
	sum := sha256Sum(b)
	return blob.Digest("sha256:" + sum)
}

func (h *Handler) putManifest(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	content, err := io.ReadAll(io.LimitReader(r.Body, maxManifestSize+1))
	if err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	if len(content) > maxManifestSize {
		writeError(w, invalid("manifest exceeds %d bytes", maxManifestSize), kindManifest, false)
		return
	}
	mediaType, refs, err := parseManifest(content, strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	m := registry.ImageManifest{Package: rt.image, Digest: digestOf(content), MediaType: mediaType, Content: content, Blobs: refs}
	if blob.Digest(rt.ref).Validate() == nil {
		if blob.Digest(rt.ref) != m.Digest {
			writeError(w, fmt.Errorf("%w: manifest digest is %s", registry.ErrDigestMismatch, m.Digest), kindManifest, false)
			return
		}
	} else {
		m.Tags = []string{rt.ref}
	}
	if err := h.svc.PutManifest(r.Context(), p, rt.repo, m); err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	w.Header().Set("Location", Prefix+rt.repo+"/"+rt.image+"/manifests/"+string(m.Digest))
	w.Header().Set("Docker-Content-Digest", string(m.Digest))
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) deleteManifest(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	if blob.Digest(rt.ref).Validate() != nil {
		writeError(w, invalid("delete manifests by digest, not tag"), kindManifest, false)
		return
	}
	if err := h.svc.Delete(r.Context(), p, rt.repo, rt.image, rt.ref); err != nil {
		writeError(w, err, kindManifest, false)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ---------- Blobs ----------

func (h *Handler) getBlob(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, cache string) {
	d := blob.Digest(rt.ref)
	if r.Method == http.MethodHead {
		n, err := h.svc.StatBlob(r.Context(), p, rt.repo, d)
		if err != nil {
			writeError(w, err, kindBlob, false)
			return
		}
		blobHeaders(w, d, n, cache)
		return
	}
	rc, n, err := h.svc.OpenBlob(r.Context(), p, rt.repo, d)
	if err != nil {
		writeError(w, err, kindBlob, false)
		return
	}
	defer rc.Close()
	blobHeaders(w, d, n, cache)
	if _, err := io.Copy(w, rc); err != nil {
		slog.Error("streaming blob", "digest", d, "err", err)
	}
}

func blobHeaders(w http.ResponseWriter, d blob.Digest, n int64, cache string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.Header().Set("Docker-Content-Digest", string(d))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
}

// ---------- Uploads ----------

func uploadLocation(rt route, id string) string {
	return Prefix + rt.repo + "/" + rt.image + "/blobs/uploads/" + id
}

func blobCreated(w http.ResponseWriter, rt route, d blob.Digest) {
	w.Header().Set("Location", Prefix+rt.repo+"/"+rt.image+"/blobs/"+string(d))
	w.Header().Set("Docker-Content-Digest", string(d))
	w.WriteHeader(http.StatusCreated)
}

func uploadAccepted(w http.ResponseWriter, rt route, id string, size int64, status int) {
	w.Header().Set("Location", uploadLocation(rt, id))
	w.Header().Set("Docker-Upload-UUID", id)
	end := size - 1
	if end < 0 {
		end = 0
	}
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route) {
	ctx := r.Context()
	q := r.URL.Query()
	want := blob.Digest(q.Get("digest"))
	switch {
	case r.Method == http.MethodPost && rt.ref == "":
		if mount := blob.Digest(q.Get("mount")); mount != "" {
			if from, ok := mountSource(q.Get("from")); ok && mount.Validate() == nil {
				if _, err := h.svc.MountBlob(ctx, p, from, rt.repo, mount); err == nil {
					blobCreated(w, rt, mount)
					return
				}
			}
			// Otherwise the client uploads the blob as usual.
		}
		if want != "" {
			if _, err := h.svc.StageBlob(ctx, p, rt.repo, r.Body, want); err != nil {
				writeError(w, err, kindUpload, false)
				return
			}
			blobCreated(w, rt, want)
			return
		}
		id, err := h.svc.StartUpload(ctx, p, rt.repo)
		if err != nil {
			writeError(w, err, kindUpload, false)
			return
		}
		uploadAccepted(w, rt, id, 0, http.StatusAccepted)
	case r.Method == http.MethodPatch && rt.ref != "":
		if cr := r.Header.Get("Content-Range"); cr != "" {
			size, err := h.svc.UploadSize(ctx, p, rt.repo, rt.ref)
			if err != nil {
				writeError(w, err, kindUpload, false)
				return
			}
			start, _, _ := strings.Cut(strings.TrimPrefix(cr, "bytes="), "-")
			if s, err := strconv.ParseInt(start, 10, 64); err != nil || s != size {
				w.Header().Set("Range", fmt.Sprintf("0-%d", max(size-1, 0)))
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
		}
		size, err := h.svc.AppendUpload(ctx, p, rt.repo, rt.ref, r.Body)
		if err != nil {
			writeError(w, err, kindUpload, false)
			return
		}
		uploadAccepted(w, rt, rt.ref, size, http.StatusAccepted)
	case r.Method == http.MethodPut && rt.ref != "":
		if want.Validate() != nil {
			writeError(w, invalid("the digest query parameter is required"), kindBlob, false)
			return
		}
		if _, err := h.svc.FinishUpload(ctx, p, rt.repo, rt.ref, r.Body, want); err != nil {
			writeError(w, err, kindUpload, false)
			return
		}
		blobCreated(w, rt, want)
	case r.Method == http.MethodGet && rt.ref != "":
		size, err := h.svc.UploadSize(ctx, p, rt.repo, rt.ref)
		if err != nil {
			writeError(w, err, kindUpload, false)
			return
		}
		uploadAccepted(w, rt, rt.ref, size, http.StatusNoContent)
	case r.Method == http.MethodDelete && rt.ref != "":
		if err := h.svc.CancelUpload(ctx, p, rt.repo, rt.ref); err != nil {
			writeError(w, err, kindUpload, false)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, invalid("%s is not supported here", r.Method), kindUpload, false)
	}
}

// mountSource returns the repository of a mount's "from" image
// (<repo>/<image>).
func mountSource(from string) (string, bool) {
	repo, image, ok := strings.Cut(from, "/")
	return repo, ok && registry.ValidImageName(image)
}

// ---------- Tags ----------

func (h *Handler) listTags(w http.ResponseWriter, r *http.Request, p identity.Principal, rt route, extra []string) {
	tags, err := h.svc.DistTags(r.Context(), p, rt.repo, rt.image)
	if err != nil {
		writeError(w, err, kindName, false)
		return
	}
	versions, err := h.svc.Versions(r.Context(), p, rt.repo, rt.image)
	if err != nil {
		writeError(w, err, kindName, false)
		return
	}
	visible := map[string]bool{}
	for _, v := range versions {
		visible[v.Version] = true
	}
	set := map[string]bool{}
	for t, v := range tags {
		if visible[v] {
			set[t] = true
		}
	}
	for _, t := range extra {
		set[t] = true
	}
	if len(set) == 0 && len(versions) == 0 {
		writeError(w, registry.ErrNotFound, kindName, false)
		return
	}
	writeTags(w, r, rt, set)
}

func writeTags(w http.ResponseWriter, r *http.Request, rt route, set map[string]bool) {
	all := make([]string, 0, len(set))
	for t := range set {
		all = append(all, t)
	}
	sort.Strings(all)
	q := r.URL.Query()
	if last := q.Get("last"); last != "" {
		i := sort.SearchStrings(all, last)
		if i < len(all) && all[i] == last {
			i++
		}
		all = all[i:]
	}
	if n, err := strconv.Atoi(q.Get("n")); err == nil && n >= 0 && n < len(all) {
		all = all[:n]
		next := url.Values{"n": {strconv.Itoa(n)}}
		if n > 0 {
			next.Set("last", all[n-1])
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s%s/%s/tags/list?%s>; rel="next"`, Prefix, rt.repo, rt.image, next.Encode()))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"name": rt.image, "tags": all})
}
