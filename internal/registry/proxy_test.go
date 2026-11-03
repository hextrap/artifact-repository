package registry

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/rbac"
)

const pypiOrg = "https://pypi.org"

func proxyFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.svc.AllowUpstreams(FormatPyPI, pypiOrg)
	require.NoError(t, f.svc.CreateRepo(ctx, alice, RepoInput{Name: "pypi-proxy", Format: FormatPyPI, Type: TypeProxy, Upstream: pypiOrg}))
	f.grant(t, "pypi-proxy", rbac.SubjectUser, "bob@acme.com", rbac.RoleReader)
	return f
}

func sha(content string) string {
	s := sha256.Sum256([]byte(content))
	return hex.EncodeToString(s[:])
}

func cacheInput(version, filename, content string) VersionInput {
	return VersionInput{
		Package: "requests", DisplayName: "requests", Version: version,
		Files: []FileInput{{Filename: filename, Content: strings.NewReader(content), Expected: Checksums{"sha256": sha(content)}}},
	}
}

func TestCreateProxyRepo(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.svc.AllowUpstreams(FormatPyPI, pypiOrg)

	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "py", Format: FormatPyPI, Type: TypeProxy, Upstream: "https://pypi.org/"}))
	repo, err := f.svc.Repo(ctx, alice, "py")
	r.NoError(err)
	r.Equal(TypeProxy, repo.Type)
	r.Equal(pypiOrg, repo.Upstream, "trailing slash normalized")

	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "py2", Format: FormatPyPI, Type: TypeProxy}))
	repo, _ = f.svc.Repo(ctx, alice, "py2")
	r.Equal(pypiOrg, repo.Upstream, "defaults to the first allowed upstream")

	repo2, _ := f.svc.Repo(ctx, alice, "py")
	r.Equal(TypeProxy, repo2.Type)

	err = f.svc.CreateRepo(ctx, alice, RepoInput{Name: "evil", Format: FormatPyPI, Type: TypeProxy, Upstream: "http://169.254.169.254"})
	r.ErrorIs(err, ErrInvalid, "only upstreams the operator allowed in config")
	r.ErrorIs(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "n", Format: FormatNPM, Type: TypeProxy}), ErrInvalid, "no npm upstream is allowed here")
	r.ErrorIs(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "h", Format: FormatPyPI, Type: TypeHosted, Upstream: pypiOrg}), ErrInvalid, "hosted repos have no upstream")
	r.ErrorIs(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "x", Format: FormatPyPI, Type: "mirror"}), ErrInvalid)

	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "plain", Format: FormatPyPI}))
	repo, _ = f.svc.Repo(ctx, alice, "plain")
	r.Equal(TypeHosted, repo.Type, "hosted by default")
}

func TestProxyNeedsAnAllowedUpstream(t *testing.T) {
	f := newFixture(t) // nothing allowed
	err := f.svc.CreateRepo(ctx, alice, RepoInput{Name: "py", Format: FormatPyPI, Type: TypeProxy})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestProxyReposAreReadOnly(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	r.ErrorIs(f.svc.AddFile(ctx, alice, "pypi-proxy", cacheInput("1.0", "requests-1.0.tar.gz", "x")), ErrReadOnly)
	r.ErrorIs(f.svc.Publish(ctx, alice, "pypi-proxy", cacheInput("1.0", "requests-1.0.tar.gz", "x")), ErrReadOnly)
}

func TestCacheFile(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	bob := userIn("acme", "bob@acme.com")

	// A reader's install fills the cache; no publish permission needed.
	r.NoError(f.svc.CacheFile(ctx, bob, "pypi-proxy", "pypi.org", cacheInput("2.32.3", "requests-2.32.3.tar.gz", "sdist")))

	versions, err := f.svc.Versions(ctx, bob, "pypi-proxy", "requests")
	r.NoError(err)
	r.Len(versions, 1)
	r.Equal(SourceUpstream, versions[0].Source)
	r.Equal("pypi.org", versions[0].Origin)
	r.Equal("upstream:pypi.org", versions[0].Publisher)

	rc, _, err := f.svc.OpenFile(ctx, bob, "pypi-proxy", "requests", "requests-2.32.3.tar.gz")
	r.NoError(err)
	rc.Close()

	// Two requests racing to cache the same file both succeed.
	r.NoError(f.svc.CacheFile(ctx, bob, "pypi-proxy", "pypi.org", cacheInput("2.32.3", "requests-2.32.3.tar.gz", "sdist")))
	versions, _ = f.svc.Versions(ctx, bob, "pypi-proxy", "requests")
	r.Len(versions[0].Files, 1)

	entries, _ := f.svc.Audit(ctx, alice, "pypi-proxy", 10)
	r.Equal("version.cache", entries[0].Action)
	r.Equal("bob@acme.com", entries[0].Actor, "who triggered the fetch")
}

func TestCacheFileVerifiesUpstreamHash(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	in := cacheInput("1.0", "requests-1.0.tar.gz", "tampered")
	in.Files[0].Expected = Checksums{"sha256": sha("original")}
	r.ErrorIs(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", in), ErrDigestMismatch)

	versions, _ := f.svc.Versions(ctx, alice, "pypi-proxy", "requests")
	r.Empty(versions, "nothing recorded")
	ok, _ := f.blobs.Exists(ctx, blob.Digest("sha256:"+sha("tampered")))
	r.False(ok, "the mismatched download isn't kept")

	in = cacheInput("1.0", "requests-1.0.tar.gz", "x")
	in.Files[0].Expected = nil
	r.ErrorIs(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", in), ErrInvalid, "cached files must have a known hash")
}

func TestCacheFileAccess(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	r.ErrorIs(f.svc.CacheFile(ctx, userIn("acme", "stranger@acme.com"), "pypi-proxy", "pypi.org", cacheInput("1.0", "requests-1.0.tar.gz", "x")), ErrNotFound)
	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "hosted", Format: FormatPyPI}))
	r.ErrorIs(f.svc.CacheFile(ctx, alice, "hosted", "pypi.org", cacheInput("1.0", "requests-1.0.tar.gz", "x")), ErrInvalid, "only proxy repos cache")
}

func TestPublishedVersionsAreMarked(t *testing.T) {
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	require.NoError(t, f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "x")))
	versions, _ := f.svc.Versions(ctx, alice, "npm", "p")
	require.Equal(t, SourcePublished, versions[0].Source)
	require.Empty(t, versions[0].Origin)
}

func TestPackageSummaries(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	r.NoError(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", cacheInput("2.31.0", "requests-2.31.0.tar.gz", "a")))
	f.now = f.now.Add(1e9)
	r.NoError(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", cacheInput("2.32.3", "requests-2.32.3.tar.gz", "bcd")))

	sums, err := f.svc.PackageSummaries(ctx, alice, "pypi-proxy")
	r.NoError(err)
	r.Equal([]PackageSummary{{
		Name: "requests", DisplayName: "requests", Versions: 2, Latest: "2.32.3",
		Updated: f.now, Size: 4, Source: SourceUpstream, Origin: "pypi.org",
	}}, sums)

	f2 := newFixture(t)
	f2.repo(t, "npm", FormatNPM)
	r.NoError(f2.svc.Publish(ctx, alice, "npm", npmVersion("left-pad", "1.0.0", "x")))
	sums, _ = f2.svc.PackageSummaries(ctx, alice, "npm")
	r.Equal(SourcePublished, sums[0].Source)

	_, err = f.svc.PackageSummaries(ctx, userIn("acme", "stranger@acme.com"), "pypi-proxy")
	r.ErrorIs(err, ErrNotFound)
}

func TestRemovedVersions(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	bob := userIn("acme", "bob@acme.com")
	r.NoError(f.svc.CacheFile(ctx, bob, "pypi-proxy", "pypi.org", cacheInput("1.0", "requests-1.0.tar.gz", "a")))
	r.NoError(f.svc.CacheFile(ctx, bob, "pypi-proxy", "pypi.org", cacheInput("2.0", "requests-2.0.tar.gz", "b")))
	r.NoError(f.svc.Delete(ctx, alice, "pypi-proxy", "requests", "1.0"))

	removed, err := f.svc.RemovedVersions(ctx, bob, "pypi-proxy", "requests")
	r.NoError(err)
	r.Equal(map[string]bool{"1.0": true}, removed, "a reader learns what not to fetch again")

	// Re-caching a removed version is refused.
	err = f.svc.CacheFile(ctx, bob, "pypi-proxy", "pypi.org", cacheInput("1.0", "requests-1.0-py3-none-any.whl", "c"))
	r.ErrorIs(err, ErrVersionExists)

	_, err = f.svc.RemovedVersions(ctx, userIn("acme", "stranger@acme.com"), "pypi-proxy", "requests")
	r.ErrorIs(err, ErrNotFound)
}

func TestCacheFileVerifiesOtherHashes(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t)
	content := "tarball"
	sha512sum := sha512.Sum512([]byte(content))
	sha1sum := sha1.Sum([]byte(content))

	in := cacheInput("1.0", "requests-1.0.tar.gz", content)
	in.Files[0].Expected = Checksums{"sha512": hex.EncodeToString(sha512sum[:]), "sha1": hex.EncodeToString(sha1sum[:])}
	r.NoError(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", in), "npm declares sha512 and sha1")

	for algo, bad := range map[string]string{"sha512": strings.Repeat("0", 128), "sha1": strings.Repeat("0", 40)} {
		in := cacheInput("2.0", "requests-2.0-"+algo+".tar.gz", content)
		in.Files[0].Expected = Checksums{algo: bad}
		r.ErrorIs(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", in), ErrDigestMismatch, algo)
	}

	in = cacheInput("3.0", "requests-3.0.tar.gz", content)
	in.Files[0].Expected = Checksums{"md5": "x"}
	r.ErrorIs(f.svc.CacheFile(ctx, alice, "pypi-proxy", "pypi.org", in), ErrInvalid, "unsupported algorithms aren't silently skipped")
}
