package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
)

// Container images (OCI). Each image manifest is a version of the image,
// named by its digest, and tags are dist-tags. A version's files are the
// manifest and every blob it references, so purging one image never
// removes a blob another still uses.
//
// Blobs are uploaded before the manifest that references them. Until then
// they're "staged" in the repository. A manifest may only reference blobs
// already in the repository or staged there, so pushing a manifest can't
// grant access to content the pusher never had (knowing a digest isn't
// enough). Staged blobs and upload sessions are kept as dist-tags of
// reserved package names, which aren't valid image names, so they work
// across replicas with any store.

var ErrBlobUnknown = errors.New("blob unknown to this repository: upload it first")

const (
	stagedPkg  = "_oci_staged"
	uploadsPkg = "_oci_uploads"
	// StagedBlobTTL is how long an uploaded blob waits for a manifest
	// before it's removed.
	StagedBlobTTL = 24 * time.Hour
	// MaxBlobSize bounds one layer.
	MaxBlobSize     = 10 << 30
	maxUploadChunks = 64
)

var (
	imageNameRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)
	imageTagRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// ValidImageName reports whether name is a valid OCI repository name.
func ValidImageName(name string) bool { return len(name) <= 255 && imageNameRE.MatchString(name) }

// ValidImageTag reports whether tag is a valid OCI tag.
func ValidImageTag(tag string) bool { return imageTagRE.MatchString(tag) }

// ImageManifest is a manifest being pushed or cached.
type ImageManifest struct {
	Package   string
	Digest    blob.Digest
	MediaType string
	Content   []byte
	// Blobs are the config, layers and, for an index, child manifests.
	Blobs []blob.Digest
	Tags  []string
}

// ImageMeta is stored as an image version's manifest field.
type ImageMeta struct {
	MediaType string        `json:"mediaType"`
	Blobs     []blob.Digest `json:"blobs,omitempty"`
}

func manifestFilename(d blob.Digest) string { return "manifest-" + d.Hex() + ".json" }

// Blob files are named per manifest because a filename belongs to one version.
func blobFilename(manifest, d blob.Digest) string {
	return "blob-" + d.Hex() + "-in-" + manifest.Hex()[:12]
}

// ManifestFile returns the stored manifest's filename for an image version.
func ManifestFile(v Version) string { return manifestFilename(blob.Digest(v.Version)) }

type staged struct {
	size int64
	at   time.Time
}

func parseStaged(s string) (staged, bool) {
	sz, at, ok := strings.Cut(s, " ")
	n, err1 := strconv.ParseInt(sz, 10, 64)
	t, err2 := strconv.ParseInt(at, 10, 64)
	return staged{n, time.Unix(t, 0)}, ok && err1 == nil && err2 == nil
}

type chunk struct {
	Digest blob.Digest `json:"d"`
	Size   int64       `json:"n"`
}

type uploadState struct {
	By      string  `json:"by"`
	Started int64   `json:"started"`
	Chunks  []chunk `json:"chunks"`
}

func (u uploadState) size() int64 {
	var n int64
	for _, c := range u.Chunks {
		n += c.Size
	}
	return n
}

func (s *Service) authorizeImagePush(p identity.Principal, repo string) error {
	r, _, err := s.authorize(p, repo, rbac.ActionPublish)
	if err != nil {
		return err
	}
	if r.Type == TypeProxy {
		return ErrReadOnly
	}
	if r.Format != FormatOCI {
		return fmt.Errorf("%w: %s is not a container image repository", ErrInvalid, repo)
	}
	return nil
}

// prune removes a repository's staged blobs and upload sessions older than
// StagedBlobTTL.
func (s *Service) prune(ctx context.Context, tenant, repo string) {
	cutoff := s.now().Add(-StagedBlobTTL)
	if tags, err := s.store.DistTags(tenant, repo, stagedPkg); err == nil {
		for d, v := range tags {
			if st, ok := parseStaged(v); !ok || st.at.Before(cutoff) {
				if s.store.RemoveDistTag(tenant, repo, stagedPkg, d) == nil {
					s.releaseBlobs(ctx, []File{{Digest: blob.Digest(d)}})
				}
			}
		}
	}
	if tags, err := s.store.DistTags(tenant, repo, uploadsPkg); err == nil {
		for id, v := range tags {
			var u uploadState
			if json.Unmarshal([]byte(v), &u) != nil || time.Unix(u.Started, 0).Before(cutoff) {
				if s.store.RemoveDistTag(tenant, repo, uploadsPkg, id) == nil {
					s.releaseChunks(ctx, tenant, repo, u.Chunks, "")
				}
			}
		}
	}
}

// releaseChunks deletes an upload's chunk blobs unless they're in use.
func (s *Service) releaseChunks(ctx context.Context, tenant, repo string, chunks []chunk, keep blob.Digest) {
	stagedTags, _ := s.store.DistTags(tenant, repo, stagedPkg)
	for _, c := range chunks {
		if _, ok := stagedTags[string(c.Digest)]; ok || c.Digest == keep {
			continue
		}
		s.releaseBlobs(ctx, []File{{Digest: c.Digest}})
	}
}

// stagedBytes is the size of a tenant's staged blobs, which count toward
// its quota.
func (s *Service) stagedBytes(tenant string) (int64, error) {
	repos, err := s.store.ListRepos(tenant)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, r := range repos {
		if r.Format != FormatOCI {
			continue
		}
		tags, err := s.store.DistTags(tenant, r.Name, stagedPkg)
		if err != nil {
			return 0, err
		}
		for _, v := range tags {
			if st, ok := parseStaged(v); ok {
				n += st.size
			}
		}
	}
	return n, nil
}

func (s *Service) checkQuota(tenant string, adding int64) error {
	quota := s.quotas.StorageQuota(tenant)
	if quota <= 0 {
		return nil
	}
	used, err := s.store.StorageUsed(tenant)
	if err != nil {
		return err
	}
	st, err := s.stagedBytes(tenant)
	if err != nil {
		return err
	}
	if used+st+adding > quota {
		return ErrQuotaExceeded
	}
	return nil
}

// stageBlob stores content, checks it against want and stages it.
func (s *Service) stageBlob(ctx context.Context, p identity.Principal, repo string, content io.Reader, want blob.Digest) (int64, error) {
	if err := want.Validate(); err != nil {
		return 0, fmt.Errorf("%w: invalid digest %q", ErrInvalid, want)
	}
	d, n, err := s.blobs.Put(ctx, io.LimitReader(content, MaxBlobSize+1))
	if err != nil {
		return 0, err
	}
	release := func() { s.releaseBlobs(ctx, []File{{Digest: d}}) }
	if n > MaxBlobSize {
		release()
		return 0, fmt.Errorf("%w: blob exceeds %d bytes", ErrInvalid, int64(MaxBlobSize))
	}
	if d != want {
		release()
		return 0, fmt.Errorf("%w: uploaded content has digest %s, not %s", ErrDigestMismatch, d, want)
	}
	if err := s.checkQuota(p.Tenant, n); err != nil {
		release()
		return 0, err
	}
	if err := s.store.SetDistTag(p.Tenant, repo, stagedPkg, string(d), fmt.Sprintf("%d %d", n, s.now().Unix())); err != nil {
		release()
		return 0, err
	}
	return n, nil
}

// StageBlob uploads a blob in one request.
func (s *Service) StageBlob(ctx context.Context, p identity.Principal, repo string, content io.Reader, want blob.Digest) (int64, error) {
	if err := s.authorizeImagePush(p, repo); err != nil {
		return 0, err
	}
	s.prune(ctx, p.Tenant, repo)
	return s.stageBlob(ctx, p, repo, content, want)
}

// StartUpload begins an upload session, returning its ID.
func (s *Service) StartUpload(ctx context.Context, p identity.Principal, repo string) (string, error) {
	if err := s.authorizeImagePush(p, repo); err != nil {
		return "", err
	}
	s.prune(ctx, p.Tenant, repo)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	return id, s.saveUpload(p.Tenant, repo, id, uploadState{By: p.Actor(), Started: s.now().Unix()})
}

func (s *Service) saveUpload(tenant, repo, id string, u uploadState) error {
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return s.store.SetDistTag(tenant, repo, uploadsPkg, id, string(b))
}

// loadUpload returns p's upload session. Other principals get ErrNotFound.
func (s *Service) loadUpload(p identity.Principal, repo, id string) (uploadState, error) {
	if err := s.authorizeImagePush(p, repo); err != nil {
		return uploadState{}, err
	}
	tags, err := s.store.DistTags(p.Tenant, repo, uploadsPkg)
	if err != nil {
		return uploadState{}, err
	}
	var u uploadState
	v, ok := tags[id]
	if !ok || json.Unmarshal([]byte(v), &u) != nil || u.By != p.Actor() {
		return uploadState{}, ErrNotFound
	}
	return u, nil
}

// UploadSize returns how many bytes an upload session has received.
func (s *Service) UploadSize(_ context.Context, p identity.Principal, repo, id string) (int64, error) {
	u, err := s.loadUpload(p, repo, id)
	return u.size(), err
}

func (s *Service) appendChunk(ctx context.Context, p identity.Principal, repo, id string, u *uploadState, content io.Reader) error {
	if len(u.Chunks) >= maxUploadChunks {
		return fmt.Errorf("%w: too many chunks; upload in fewer, larger requests", ErrInvalid)
	}
	d, n, err := s.blobs.Put(ctx, io.LimitReader(content, MaxBlobSize-u.size()+1))
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	u.Chunks = append(u.Chunks, chunk{d, n})
	if u.size() > MaxBlobSize {
		s.releaseChunks(ctx, p.Tenant, repo, u.Chunks[len(u.Chunks)-1:], "")
		return fmt.Errorf("%w: blob exceeds %d bytes", ErrInvalid, int64(MaxBlobSize))
	}
	return s.saveUpload(p.Tenant, repo, id, *u)
}

// AppendUpload adds a chunk, returning the bytes received so far.
func (s *Service) AppendUpload(ctx context.Context, p identity.Principal, repo, id string, content io.Reader) (int64, error) {
	u, err := s.loadUpload(p, repo, id)
	if err != nil {
		return 0, err
	}
	if err := s.appendChunk(ctx, p, repo, id, &u, content); err != nil {
		return 0, err
	}
	return u.size(), nil
}

// FinishUpload adds an optional last chunk and stages the blob, which must
// have digest want. The session ends either way.
func (s *Service) FinishUpload(ctx context.Context, p identity.Principal, repo, id string, last io.Reader, want blob.Digest) (int64, error) {
	u, err := s.loadUpload(p, repo, id)
	if err != nil {
		return 0, err
	}
	if err := s.store.RemoveDistTag(p.Tenant, repo, uploadsPkg, id); err != nil {
		return 0, err
	}
	if last != nil {
		if err := s.appendChunk(ctx, p, repo, id, &u, last); err != nil {
			s.releaseChunks(ctx, p.Tenant, repo, u.Chunks, "")
			return 0, err
		}
		_ = s.store.RemoveDistTag(p.Tenant, repo, uploadsPkg, id) // re-saved by appendChunk
	}
	var n int64
	if len(u.Chunks) == 1 && u.Chunks[0].Digest == want {
		// The usual case: the whole blob arrived in one request.
		n, err = u.Chunks[0].Size, nil
		if qerr := s.checkQuota(p.Tenant, n); qerr != nil {
			err = qerr
		} else {
			err = s.store.SetDistTag(p.Tenant, repo, stagedPkg, string(want), fmt.Sprintf("%d %d", n, s.now().Unix()))
		}
	} else {
		readers := make([]io.Reader, 0, len(u.Chunks))
		var closers []io.Closer
		for _, c := range u.Chunks {
			rc, oerr := s.blobs.Open(ctx, c.Digest)
			if oerr != nil {
				err = oerr
				break
			}
			readers, closers = append(readers, rc), append(closers, rc)
		}
		if err == nil {
			n, err = s.stageBlob(ctx, p, repo, io.MultiReader(readers...), want)
		}
		for _, c := range closers {
			c.Close()
		}
	}
	keep := blob.Digest("")
	if err == nil {
		keep = want
	}
	s.releaseChunks(ctx, p.Tenant, repo, u.Chunks, keep)
	return n, err
}

// CancelUpload ends an upload session.
func (s *Service) CancelUpload(ctx context.Context, p identity.Principal, repo, id string) error {
	u, err := s.loadUpload(p, repo, id)
	if err != nil {
		return err
	}
	if err := s.store.RemoveDistTag(p.Tenant, repo, uploadsPkg, id); err != nil {
		return err
	}
	s.releaseChunks(ctx, p.Tenant, repo, u.Chunks, "")
	return nil
}

// repoBlob finds a blob among a repository's visible versions or, with
// staged, its staged uploads.
func (s *Service) repoBlob(tenant, repo string, d blob.Digest, withStaged bool) (int64, bool, error) {
	versions, err := s.store.RepoVersions(tenant, repo)
	if err != nil {
		return 0, false, err
	}
	for _, v := range versions {
		if !v.Visible() {
			continue
		}
		for _, f := range v.Files {
			if f.Digest == d {
				return f.Size, true, nil
			}
		}
	}
	if withStaged {
		tags, err := s.store.DistTags(tenant, repo, stagedPkg)
		if err != nil {
			return 0, false, err
		}
		if st, ok := parseStaged(tags[string(d)]); ok {
			if exists, err := s.blobs.Exists(context.Background(), d); err == nil && exists {
				return st.size, true, nil
			}
		}
	}
	return 0, false, nil
}

// StatBlob returns the size of a blob in the repository. Blobs that exist
// elsewhere are ErrNotFound.
func (s *Service) StatBlob(_ context.Context, p identity.Principal, repo string, d blob.Digest) (int64, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionPull); err != nil {
		return 0, err
	}
	n, ok, err := s.repoBlob(p.Tenant, repo, d, true)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrNotFound
	}
	return n, nil
}

// OpenBlob opens a blob in the repository.
func (s *Service) OpenBlob(ctx context.Context, p identity.Principal, repo string, d blob.Digest) (io.ReadCloser, int64, error) {
	n, err := s.StatBlob(ctx, p, repo, d)
	if err != nil {
		return nil, 0, err
	}
	rc, err := s.blobs.Open(ctx, d)
	if errors.Is(err, blob.ErrNotFound) {
		err = ErrNotFound
	}
	return rc, n, err
}

func validateManifest(m ImageManifest) error {
	if !ValidImageName(m.Package) {
		return fmt.Errorf("%w: invalid image name %q", ErrInvalid, m.Package)
	}
	for _, t := range m.Tags {
		if !ValidImageTag(t) {
			return fmt.Errorf("%w: invalid tag %q", ErrInvalid, t)
		}
	}
	if m.MediaType == "" {
		return fmt.Errorf("%w: manifest media type is required", ErrInvalid)
	}
	sum := sha256.Sum256(m.Content)
	if blob.Digest("sha256:"+hex.EncodeToString(sum[:])) != m.Digest {
		return fmt.Errorf("%w: manifest content doesn't match %s", ErrDigestMismatch, m.Digest)
	}
	return nil
}

// imageVersion builds the version for a manifest from the repository's
// blobs, or ErrBlobUnknown.
func (s *Service) imageVersion(ctx context.Context, p identity.Principal, repo string, m ImageManifest) (Version, error) {
	d, n, err := s.blobs.Put(ctx, bytes.NewReader(m.Content))
	if err != nil {
		return Version{}, err
	}
	files := []File{{Filename: manifestFilename(m.Digest), Digest: d, Size: n}}
	var blobs []blob.Digest
	for _, b := range m.Blobs {
		if slices.Contains(blobs, b) || b == m.Digest {
			continue
		}
		size, ok, err := s.repoBlob(p.Tenant, repo, b, true)
		if err != nil {
			s.releaseBlobs(ctx, files)
			return Version{}, err
		}
		if !ok {
			s.releaseBlobs(ctx, files)
			return Version{}, fmt.Errorf("%w (%s)", ErrBlobUnknown, b)
		}
		blobs = append(blobs, b)
		files = append(files, File{Filename: blobFilename(m.Digest, b), Digest: b, Size: size})
	}
	meta, err := json.Marshal(ImageMeta{MediaType: m.MediaType, Blobs: blobs})
	if err != nil {
		return Version{}, err
	}
	v := s.newVersion(p, repo, VersionInput{Package: m.Package, DisplayName: m.Package, Version: string(m.Digest), Manifest: meta}, files)
	return v, nil
}

// PutManifest pushes a manifest and points its tags at it. Pushing a
// manifest that's already there just updates the tags.
func (s *Service) PutManifest(ctx context.Context, p identity.Principal, repo string, m ImageManifest) error {
	if err := s.authorizeImagePush(p, repo); err != nil {
		return err
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	existing, err := s.store.Versions(p.Tenant, repo, m.Package)
	if err != nil {
		return err
	}
	for _, v := range existing {
		if v.Version != string(m.Digest) {
			continue
		}
		if !v.Visible() {
			return ErrVersionExists
		}
		for _, t := range m.Tags {
			if err := s.setImageTag(ctx, p, repo, m.Package, t, v.Version); err != nil {
				return err
			}
		}
		return nil
	}
	v, err := s.imageVersion(ctx, p, repo, m)
	if err != nil {
		return err
	}
	if err := s.checkQuota(p.Tenant, v.Files[0].Size); err != nil {
		s.releaseBlobs(ctx, v.Files[:1])
		return err
	}
	tags := map[string]string{}
	for _, t := range m.Tags {
		tags[t] = v.Version
	}
	if err := s.store.CreateVersion(v, tags); err != nil {
		s.releaseBlobs(ctx, v.Files[:1])
		return err
	}
	// Referenced blobs are no longer staged.
	for _, f := range v.Files[1:] {
		_ = s.store.RemoveDistTag(p.Tenant, repo, stagedPkg, string(f.Digest))
	}
	s.audit(ctx, p, repo, "version.publish", m.Package+"@"+v.Version, "", strings.Join(m.Tags, ","))
	return nil
}

func (s *Service) setImageTag(ctx context.Context, p identity.Principal, repo, pkg, tag, version string) error {
	before, err := s.store.DistTags(p.Tenant, repo, pkg)
	if err != nil {
		return err
	}
	if before[tag] == version {
		return nil
	}
	if err := s.store.SetDistTag(p.Tenant, repo, pkg, tag, version); err != nil {
		return err
	}
	s.audit(ctx, p, repo, "tag.set", pkg+":"+tag, before[tag], version)
	return nil
}

// CacheManifest stores a manifest fetched from a proxy repo's upstream,
// whose digest the caller verified, and points tag (if any) at it. Its
// blobs are cached separately, as they're requested.
func (s *Service) CacheManifest(ctx context.Context, p identity.Principal, repo, origin string, m ImageManifest) error {
	if err := validateManifest(m); err != nil {
		return err
	}
	meta, err := json.Marshal(ImageMeta{MediaType: m.MediaType, Blobs: m.Blobs})
	if err != nil {
		return err
	}
	err = s.CacheFile(ctx, p, repo, origin, VersionInput{
		Package: m.Package, DisplayName: m.Package, Version: string(m.Digest), Manifest: meta,
		Files: []FileInput{{Filename: manifestFilename(m.Digest), Content: bytes.NewReader(m.Content), Expected: Checksums{"sha256": m.Digest.Hex()}}},
	})
	if err != nil {
		return err
	}
	for _, t := range m.Tags {
		if err := s.store.SetDistTag(p.Tenant, repo, m.Package, t, string(m.Digest)); err != nil {
			return err
		}
	}
	return nil
}

// CacheBlob stores a blob fetched from a proxy repo's upstream as part of
// a cached manifest's version. The content must match the digest.
func (s *Service) CacheBlob(ctx context.Context, p identity.Principal, repo, origin, pkg string, manifest, d blob.Digest, content io.Reader) error {
	return s.CacheFile(ctx, p, repo, origin, VersionInput{
		Package: pkg, DisplayName: pkg, Version: string(manifest),
		Files: []FileInput{{Filename: blobFilename(manifest, d), Content: io.LimitReader(content, MaxBlobSize+1), Expected: Checksums{"sha256": d.Hex()}}},
	})
}

// ImageMetaOf decodes an image version's manifest field.
func ImageMetaOf(v Version) (ImageMeta, error) {
	var m ImageMeta
	err := json.Unmarshal(v.Manifest, &m)
	return m, err
}

// MountBlob stages a blob from another repository the principal can pull
// from, so it needn't be uploaded again.
func (s *Service) MountBlob(ctx context.Context, p identity.Principal, from, to string, d blob.Digest) (int64, error) {
	if err := s.authorizeImagePush(p, to); err != nil {
		return 0, err
	}
	n, err := s.StatBlob(ctx, p, from, d)
	if err != nil {
		return 0, err
	}
	if _, ok, err := s.repoBlob(p.Tenant, to, d, false); err != nil || ok {
		return n, err // already here
	}
	if err := s.checkQuota(p.Tenant, n); err != nil {
		return 0, err
	}
	return n, s.store.SetDistTag(p.Tenant, to, stagedPkg, string(d), fmt.Sprintf("%d %d", n, s.now().Unix()))
}
