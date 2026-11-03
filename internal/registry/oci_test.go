package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/rbac"
)

func digestOf(s string) blob.Digest {
	h := sha256.Sum256([]byte(s))
	return blob.Digest("sha256:" + hex.EncodeToString(h[:]))
}

const ociManifestType = "application/vnd.oci.image.manifest.v1+json"

func manifestFor(pkg string, blobs ...string) ImageManifest {
	content := `{"schemaVersion":2,"layers":"` + strings.Join(blobs, ",") + `"}`
	m := ImageManifest{Package: pkg, MediaType: ociManifestType, Content: []byte(content), Digest: digestOf(content)}
	for _, b := range blobs {
		m.Blobs = append(m.Blobs, digestOf(b))
	}
	return m
}

func (f *fixture) ociRepo(t *testing.T, name string) {
	f.repo(t, name, FormatOCI)
	f.grant(t, name, rbac.SubjectUser, bob.Email, rbac.RoleDeveloper)
}

func (f *fixture) stage(t *testing.T, repo, content string) {
	_, err := f.svc.StageBlob(ctx, bob, repo, strings.NewReader(content), digestOf(content))
	require.NoError(t, err)
}

func TestOCIPushAndPull(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "images")
	f.stage(t, "images", "config")
	f.stage(t, "images", "layer")
	m := manifestFor("team/app", "config", "layer")
	m.Tags = []string{"latest"}
	r.NoError(f.svc.PutManifest(ctx, bob, "images", m))

	tags, err := f.svc.DistTags(ctx, bob, "images", "team/app")
	r.NoError(err)
	r.Equal(map[string]string{"latest": string(m.Digest)}, tags)
	rc, size, err := f.svc.OpenBlob(ctx, bob, "images", digestOf("layer"))
	r.NoError(err)
	r.Equal(int64(5), size)
	r.Equal("layer", read(t, rc))

	// Re-pushing the same manifest under another tag just adds the tag.
	m.Tags = []string{"v1"}
	r.NoError(f.svc.PutManifest(ctx, bob, "images", m))
	tags, _ = f.svc.DistTags(ctx, bob, "images", "team/app")
	r.Len(tags, 2)
	versions, _ := f.svc.Versions(ctx, bob, "images", "team/app")
	r.Len(versions, 1)
}

func TestOCIManifestCantClaimBlobsItNeverUploaded(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "private")
	f.ociRepo(t, "public")
	// alice pushes a secret layer to "private"; bob can't read it.
	f.svc.RemoveGrant(ctx, alice, "private", rbac.SubjectUser, bob.Email)
	_, err := f.svc.StageBlob(ctx, alice, "private", strings.NewReader("secret"), digestOf("secret"))
	r.NoError(err)
	r.NoError(f.svc.PutManifest(ctx, alice, "private", manifestFor("app", "secret")))

	// bob knows the digest. Referencing it from his own repo must not
	// grant him the content: he has to upload it himself.
	err = f.svc.PutManifest(ctx, bob, "public", manifestFor("app", "secret"))
	r.ErrorIs(err, ErrBlobUnknown)
	_, _, err = f.svc.OpenBlob(ctx, bob, "public", digestOf("secret"))
	r.ErrorIs(err, ErrNotFound)
	_, err = f.svc.StatBlob(ctx, bob, "public", digestOf("secret"))
	r.ErrorIs(err, ErrNotFound, "no existence oracle either")

	// Uploading the content proves he has it.
	f.stage(t, "public", "secret")
	r.NoError(f.svc.PutManifest(ctx, bob, "public", manifestFor("app", "secret")))
}

func TestOCIBlobsAreSharedWithinARepo(t *testing.T) {
	f := newFixture(t)
	f.ociRepo(t, "images")
	f.stage(t, "images", "base")
	require.NoError(t, f.svc.PutManifest(ctx, bob, "images", manifestFor("one", "base")))
	// A second image on the same base layer needn't upload it again.
	require.NoError(t, f.svc.PutManifest(ctx, bob, "images", manifestFor("two", "base")))
}

func TestOCIUploadSessions(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "images")
	id, err := f.svc.StartUpload(ctx, bob, "images")
	r.NoError(err)
	n, err := f.svc.AppendUpload(ctx, bob, "images", id, strings.NewReader("hello "))
	r.NoError(err)
	r.Equal(int64(6), n)
	n, err = f.svc.UploadSize(ctx, bob, "images", id)
	r.NoError(err)
	r.Equal(int64(6), n)

	_, err = f.svc.AppendUpload(ctx, carol, "images", id, strings.NewReader("x"))
	r.ErrorIs(err, ErrNotFound, "only the uploader can use the session")
	_, err = f.svc.FinishUpload(ctx, bob, "images", id, strings.NewReader("world"), digestOf("wrong"))
	r.ErrorIs(err, ErrDigestMismatch)

	id, _ = f.svc.StartUpload(ctx, bob, "images")
	f.svc.AppendUpload(ctx, bob, "images", id, strings.NewReader("hello "))
	n, err = f.svc.FinishUpload(ctx, bob, "images", id, strings.NewReader("world"), digestOf("hello world"))
	r.NoError(err)
	r.Equal(int64(11), n)
	_, err = f.svc.UploadSize(ctx, bob, "images", id)
	r.ErrorIs(err, ErrNotFound, "finished sessions are gone")
	r.NoError(f.svc.PutManifest(ctx, bob, "images", manifestFor("app", "hello world")))
	exists, _ := f.blobs.Exists(ctx, digestOf("hello "))
	r.False(exists, "chunks are cleaned up")
}

func TestOCIPushNeedsDeveloper(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "images")
	f.grant(t, "images", rbac.SubjectUser, carol.Email, rbac.RoleReader)
	_, err := f.svc.StageBlob(ctx, carol, "images", strings.NewReader("x"), digestOf("x"))
	r.ErrorIs(err, ErrForbidden)
	_, err = f.svc.StartUpload(ctx, carol, "images")
	r.ErrorIs(err, ErrForbidden)
	r.ErrorIs(f.svc.PutManifest(ctx, carol, "images", manifestFor("app")), ErrForbidden)
}

func TestOCIStagedBlobsCountTowardQuotaAndExpire(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "images")
	f.quota["acme"] = 10
	f.stage(t, "images", "123456")
	_, err := f.svc.StageBlob(ctx, bob, "images", strings.NewReader("78901"), digestOf("78901"))
	r.ErrorIs(err, ErrQuotaExceeded, "unreferenced uploads can't bypass the quota")

	f.now = f.now.Add(StagedBlobTTL + time.Minute)
	f.stage(t, "images", "78901")
	exists, _ := f.blobs.Exists(ctx, digestOf("123456"))
	r.False(exists, "abandoned uploads are removed")
	r.ErrorIs(f.svc.PutManifest(ctx, bob, "images", manifestFor("app", "123456")), ErrBlobUnknown)
}

func TestOCIManifestValidation(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "images")
	m := manifestFor("app")
	m.Digest = digestOf("something else")
	r.ErrorIs(f.svc.PutManifest(ctx, bob, "images", m), ErrDigestMismatch)
	m = manifestFor("app")
	m.Tags = []string{"-bad"}
	r.ErrorIs(f.svc.PutManifest(ctx, bob, "images", m), ErrInvalid)
	r.ErrorIs(f.svc.PutManifest(ctx, bob, "images", manifestFor("_oci_staged")), ErrInvalid)
}

func TestOCIDeleteKeepsSharedBlobs(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "images")
	f.stage(t, "images", "base")
	one, two := manifestFor("one", "base"), manifestFor("two", "base")
	r.NoError(f.svc.PutManifest(ctx, bob, "images", one))
	r.NoError(f.svc.PutManifest(ctx, bob, "images", two))
	r.NoError(f.svc.Delete(ctx, alice, "images", "one", string(one.Digest)))
	r.NoError(f.svc.Purge(ctx, alice, "images", "one", string(one.Digest), "one@"+string(one.Digest)))
	rc, _, err := f.svc.OpenBlob(ctx, bob, "images", digestOf("base"))
	r.NoError(err)
	r.Equal("base", read(t, rc))
}

func TestOCIMountBlob(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.ociRepo(t, "a")
	f.ociRepo(t, "b")
	f.stage(t, "a", "shared")
	r.NoError(f.svc.PutManifest(ctx, bob, "a", manifestFor("app", "shared")))
	n, err := f.svc.MountBlob(ctx, bob, "a", "b", digestOf("shared"))
	r.NoError(err)
	r.Equal(int64(6), n)
	r.NoError(f.svc.PutManifest(ctx, bob, "b", manifestFor("app", "shared")))

	f.ociRepo(t, "c")
	r.NoError(f.svc.RemoveGrant(ctx, alice, "a", rbac.SubjectUser, bob.Email))
	_, err = f.svc.MountBlob(ctx, bob, "a", "c", digestOf("shared"))
	r.ErrorIs(err, ErrNotFound, "mounting needs pull access to the source")
}
