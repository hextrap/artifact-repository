package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
)

type fixture struct {
	svc   *Service
	blobs blob.Store
	now   time.Time
	quota map[string]int64
}

func (f *fixture) clock() time.Time { return f.now }

func newFixture(t *testing.T) *fixture {
	f := &fixture{
		blobs: blob.NewMemory(),
		now:   time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		quota: map[string]int64{},
	}
	f.svc = New(newTestStore(t), f.blobs, f.clock, QuotaFunc(func(tenant string) int64 { return f.quota[tenant] }))
	return f
}

func userIn(tenant, email string, groups ...string) identity.Principal {
	return identity.Principal{Tenant: tenant, Kind: identity.KindUser, Subject: "sub|" + email, Email: email, Groups: groups}
}

var (
	ctx   = context.Background()
	alice = userIn("acme", "alice@acme.com") // repo creator
	bob   = userIn("acme", "bob@acme.com")
	carol = userIn("acme", "carol@acme.com", "release-eng")
	ci    = identity.Principal{Tenant: "acme", Kind: identity.KindServiceToken, Subject: "tok-ci"}
	anon  = identity.Anonymous("acme")
	mallo = userIn("evil", "mallory@evil.com")
)

func (f *fixture) repo(t *testing.T, name string, format Format) {
	require.NoError(t, f.svc.CreateRepo(ctx, alice, RepoInput{Name: name, Format: format}))
}

func (f *fixture) grant(t *testing.T, repo string, kind rbac.SubjectKind, subject string, role rbac.Role) {
	require.NoError(t, f.svc.SetGrant(ctx, alice, repo, rbac.Grant{SubjectKind: kind, Subject: subject, Role: role}))
}

func npmVersion(pkg, ver, content string) VersionInput {
	return VersionInput{
		Package: pkg, DisplayName: pkg, Version: ver,
		Manifest: []byte(`{"name":"` + pkg + `","version":"` + ver + `"}`),
		Files:    []FileInput{{Filename: pkg + "-" + ver + ".tgz", Content: strings.NewReader(content)}},
	}
}

func read(t *testing.T, rc io.ReadCloser) string {
	defer rc.Close()
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	return string(b)
}

func auditActions(t *testing.T, f *fixture, repo string) []string {
	entries, err := f.svc.Audit(ctx, alice, repo, 1000)
	require.NoError(t, err)
	var out []string
	for i := len(entries) - 1; i >= 0; i-- { // oldest first
		out = append(out, entries[i].Action)
	}
	return out
}

// --- Repositories ---

func TestCreatorBecomesAdmin(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "internal-npm", FormatNPM)

	grants, err := f.svc.Grants(ctx, alice, "internal-npm")
	r.NoError(err)
	r.Equal([]rbac.Grant{{SubjectKind: rbac.SubjectUser, Subject: "sub|alice@acme.com", Role: rbac.RoleAdmin}}, grants)
	r.Equal([]string{"repo.create"}, auditActions(t, f, "internal-npm"))
}

func TestCreateRepoValidation(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "internal-npm", FormatNPM)
	r.ErrorIs(f.svc.CreateRepo(ctx, bob, RepoInput{Name: "internal-npm", Format: FormatNPM}), ErrExists)
	r.ErrorIs(f.svc.CreateRepo(ctx, ci, RepoInput{Name: "x", Format: FormatNPM}), ErrForbidden, "service tokens can't create repos")
	r.ErrorIs(f.svc.CreateRepo(ctx, anon, RepoInput{Name: "x", Format: FormatNPM}), ErrUnauthenticated)
	r.ErrorIs(f.svc.CreateRepo(ctx, bob, RepoInput{Name: "x", Format: "rubygems"}), ErrInvalid)
	for _, bad := range []string{"", "has space", "../etc", "UPPER", strings.Repeat("a", 65)} {
		r.ErrorIs(f.svc.CreateRepo(ctx, bob, RepoInput{Name: bad, Format: FormatNPM}), ErrInvalid, bad)
	}
}

func TestListReposOnlyShowsAccessible(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "a", FormatNPM)
	f.repo(t, "b", FormatPyPI)
	f.grant(t, "b", rbac.SubjectUser, "bob@acme.com", rbac.RoleReader)

	repos, err := f.svc.ListRepos(ctx, bob)
	r.NoError(err)
	r.Len(repos, 1)
	r.Equal("b", repos[0].Name)
	r.Equal(rbac.RoleReader, repos[0].Role)
}

func TestDeleteRepoRequiresEmpty(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("left-pad", "1.0.0", "x")))
	r.ErrorIs(f.svc.DeleteRepo(ctx, alice, "npm"), ErrRepoNotEmpty)
	r.NoError(f.svc.Purge(ctx, alice, "npm", "left-pad", "1.0.0", "left-pad@1.0.0"))
	r.NoError(f.svc.DeleteRepo(ctx, alice, "npm"))
	_, err := f.svc.Repo(ctx, alice, "npm")
	r.ErrorIs(err, ErrNotFound)
}

// --- Access control ---

func TestAuthorizationErrors(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleReader)

	r.ErrorIs(f.svc.Publish(ctx, anon, "npm", npmVersion("p", "1.0.0", "x")), ErrUnauthenticated, "prompts clients to log in")
	r.ErrorIs(f.svc.Publish(ctx, carol, "npm", npmVersion("p", "1.0.0", "x")), ErrNotFound, "no access: don't reveal the repo exists")
	r.ErrorIs(f.svc.Publish(ctx, bob, "npm", npmVersion("p", "1.0.0", "x")), ErrForbidden)
	r.ErrorIs(f.svc.Publish(ctx, alice, "missing", npmVersion("p", "1.0.0", "x")), ErrNotFound)
}

func TestAdminsCanAddAdmins(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleAdmin)

	// Bob, now an admin, can grant others.
	r.NoError(f.svc.SetGrant(ctx, bob, "npm", rbac.Grant{SubjectKind: rbac.SubjectGroup, Subject: "release-eng", Role: rbac.RoleAdmin}))
	// Carol is in release-eng, so she's now an admin too.
	_, err := f.svc.Grants(ctx, carol, "npm")
	r.NoError(err)
}

func TestNonAdminsCannotManageAccess(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleMaintainer)
	r.ErrorIs(f.svc.SetGrant(ctx, bob, "npm", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "bob@acme.com", Role: rbac.RoleAdmin}), ErrForbidden)
	_, err := f.svc.Grants(ctx, bob, "npm")
	r.ErrorIs(err, ErrForbidden)
}

func TestLastAdminGuard(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)

	r.ErrorIs(f.svc.RemoveGrant(ctx, alice, "npm", rbac.SubjectUser, "sub|alice@acme.com"), rbac.ErrLastAdmin)
	r.ErrorIs(f.svc.SetGrant(ctx, alice, "npm", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "sub|alice@acme.com", Role: rbac.RoleReader}), rbac.ErrLastAdmin)

	// With a group admin in place, alice can step down.
	f.grant(t, "npm", rbac.SubjectGroup, "release-eng", rbac.RoleAdmin)
	r.NoError(f.svc.RemoveGrant(ctx, alice, "npm", rbac.SubjectUser, "sub|alice@acme.com"))
	r.ErrorIs(f.svc.RemoveGrant(ctx, carol, "npm", rbac.SubjectGroup, "release-eng"), rbac.ErrLastAdmin)
}

func TestServiceTokenCannotBeAdmin(t *testing.T) {
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	err := f.svc.SetGrant(ctx, alice, "npm", rbac.Grant{SubjectKind: rbac.SubjectServiceToken, Subject: "tok-ci", Role: rbac.RoleAdmin})
	require.ErrorIs(t, err, rbac.ErrServiceTokenAdmin)
}

func TestInstanceAdminHasAdminEverywhere(t *testing.T) {
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	root := userIn("acme", "root@acme.com")
	root.InstanceAdmin = true
	_, err := f.svc.Grants(ctx, root, "npm")
	require.NoError(t, err)
}

func TestGrantChangesAreAudited(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleReader)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleDeveloper)
	r.NoError(f.svc.RemoveGrant(ctx, alice, "npm", rbac.SubjectUser, "bob@acme.com"))
	r.Equal([]string{"repo.create", "grant.set", "grant.set", "grant.remove"}, auditActions(t, f, "npm"))

	entries, _ := f.svc.Audit(ctx, alice, "npm", 1)
	r.Equal("user:bob@acme.com", entries[0].Target)
	r.Equal("developer", entries[0].Before)
	r.Equal("", entries[0].After)
	r.Equal("alice@acme.com", entries[0].Actor)
}

// --- Publishing ---

func TestPublishAndRead(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectServiceToken, "tok-ci", rbac.RoleDeveloper)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleReader)

	r.NoError(f.svc.Publish(ctx, ci, "npm", npmVersion("left-pad", "1.0.0", "tarball-bytes")))

	versions, err := f.svc.Versions(ctx, bob, "npm", "left-pad")
	r.NoError(err)
	r.Len(versions, 1)
	r.Equal("1.0.0", versions[0].Version)
	r.Equal("token:tok-ci", versions[0].Publisher)
	r.Equal(f.now, versions[0].PublishedAt)
	r.Equal(int64(13), versions[0].Files[0].Size)

	rc, _, err := f.svc.OpenFile(ctx, bob, "npm", "left-pad", "left-pad-1.0.0.tgz")
	r.NoError(err)
	r.Equal("tarball-bytes", read(t, rc))
	r.Equal([]string{"repo.create", "grant.set", "grant.set", "version.publish"}, auditActions(t, f, "npm"))

	pkgs, err := f.svc.Packages(ctx, bob, "npm")
	r.NoError(err)
	r.Equal([]string{"left-pad"}, pkgs)
}

func TestVersionsAreImmutable(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "one")))
	r.ErrorIs(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "two")), ErrVersionExists)

	rc, _, err := f.svc.OpenFile(ctx, alice, "npm", "p", "p-1.0.0.tgz")
	r.NoError(err)
	r.Equal("one", read(t, rc))
}

func TestDeletedVersionNumberCannotBeReused(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "one")))
	r.NoError(f.svc.Delete(ctx, alice, "npm", "p", "1.0.0"))
	r.ErrorIs(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "evil")), ErrVersionExists)
	r.NoError(f.svc.Purge(ctx, alice, "npm", "p", "1.0.0", "p@1.0.0"))
	r.ErrorIs(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "evil")), ErrVersionExists)
}

func TestAddFileAllowsMultipleFilesPerVersion(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "py", FormatPyPI)
	add := func(filename, content string) error {
		return f.svc.AddFile(ctx, alice, "py", VersionInput{
			Package: "requests", DisplayName: "requests", Version: "2.0.0",
			Files: []FileInput{{Filename: filename, Content: strings.NewReader(content)}},
		})
	}
	r.NoError(add("requests-2.0.0.tar.gz", "sdist"))
	r.NoError(add("requests-2.0.0-py3-none-any.whl", "wheel"))
	r.ErrorIs(add("requests-2.0.0-py3-none-any.whl", "other"), ErrFileExists)

	versions, err := f.svc.Versions(ctx, alice, "py", "requests")
	r.NoError(err)
	r.Len(versions, 1)
	r.Len(versions[0].Files, 2)

	r.NoError(f.svc.Delete(ctx, alice, "py", "requests", "2.0.0"))
	r.ErrorIs(add("requests-2.0.0-cp312-none-any.whl", "x"), ErrVersionExists, "can't add files to a deleted release")
	r.ErrorIs(add("requests-2.0.0.tar.gz", "x"), ErrFileExists)
}

func TestAddFileWithSiblingsIsAtomic(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "py", FormatPyPI)
	in := func(names ...string) VersionInput {
		v := VersionInput{Package: "p", DisplayName: "p", Version: "1.0"}
		for _, n := range names {
			v.Files = append(v.Files, FileInput{Filename: n, Content: strings.NewReader(n)})
		}
		return v
	}
	r.NoError(f.svc.AddFile(ctx, alice, "py", in("p-1.0-py3-none-any.whl", "p-1.0-py3-none-any.whl.metadata")))
	r.ErrorIs(f.svc.AddFile(ctx, alice, "py", in("p-1.0.tar.gz", "p-1.0-py3-none-any.whl.metadata")), ErrFileExists)

	versions, _ := f.svc.Versions(ctx, alice, "py", "p")
	r.Len(versions[0].Files, 2, "nothing from the failed upload was added")
	r.Equal([]string{"repo.create", "version.publish"}, auditActions(t, f, "py"), "one upload, one audit entry")
}

func TestFilenamesAreUniquePerPackage(t *testing.T) {
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	in := func(pkg string) VersionInput {
		return VersionInput{Package: pkg, DisplayName: pkg, Version: "1.0.0",
			Files: []FileInput{{Filename: "utils-1.0.0.tgz", Content: strings.NewReader(pkg)}}}
	}
	require.NoError(t, f.svc.Publish(ctx, alice, "npm", in("@a/utils")))
	require.NoError(t, f.svc.Publish(ctx, alice, "npm", in("@b/utils")), "scoped packages share tarball basenames")
}

func TestStorageQuota(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.quota["acme"] = 10
	f.repo(t, "npm", FormatNPM)

	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "123456")))
	err := f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.1", "abcdef"))
	r.ErrorIs(err, ErrQuotaExceeded)
	ok, _ := f.blobs.Exists(ctx, blob.Digest(fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("abcdef")))))
	r.False(ok, "rejected upload must not leave a blob behind")

	// Soft-deleted versions still use storage; purged ones don't.
	r.NoError(f.svc.Delete(ctx, alice, "npm", "p", "1.0.0"))
	r.ErrorIs(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.1", "abcdef")), ErrQuotaExceeded)
	r.NoError(f.svc.Purge(ctx, alice, "npm", "p", "1.0.0", "p@1.0.0"))
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.1", "abcdef")))

	used, err := f.svc.StorageUsed(ctx, alice)
	r.NoError(err)
	r.Equal(int64(6), used)
}

// --- Deletion lifecycle ---

func TestYank(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleDeveloper)
	f.grant(t, "npm", rbac.SubjectGroup, "release-eng", rbac.RoleMaintainer)
	r.NoError(f.svc.Publish(ctx, bob, "npm", npmVersion("p", "1.0.0", "x")))

	r.ErrorIs(f.svc.Yank(ctx, bob, "npm", "p", "1.0.0", "broken"), ErrForbidden)
	r.NoError(f.svc.Yank(ctx, carol, "npm", "p", "1.0.0", "broken"))

	versions, _ := f.svc.Versions(ctx, bob, "npm", "p")
	r.True(versions[0].Yanked)
	r.Equal("broken", versions[0].YankReason)
	rc, _, err := f.svc.OpenFile(ctx, bob, "npm", "p", "p-1.0.0.tgz")
	r.NoError(err, "pinned installs of yanked versions still work")
	rc.Close()

	r.NoError(f.svc.Unyank(ctx, carol, "npm", "p", "1.0.0"))
	versions, _ = f.svc.Versions(ctx, bob, "npm", "p")
	r.False(versions[0].Yanked)
	r.Equal([]string{"version.yank", "version.unyank"}, auditActions(t, f, "npm")[4:])
}

func TestSoftDeleteAndRestore(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectGroup, "release-eng", rbac.RoleMaintainer)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "x")))

	r.ErrorIs(f.svc.Delete(ctx, carol, "npm", "p", "1.0.0"), ErrForbidden, "only admins delete")
	r.NoError(f.svc.Delete(ctx, alice, "npm", "p", "1.0.0"))

	versions, _ := f.svc.Versions(ctx, alice, "npm", "p")
	r.Empty(versions)
	_, _, err := f.svc.OpenFile(ctx, alice, "npm", "p", "p-1.0.0.tgz")
	r.ErrorIs(err, ErrNotFound)

	trash, err := f.svc.Trash(ctx, alice, "npm")
	r.NoError(err)
	r.Len(trash, 1)

	r.NoError(f.svc.Restore(ctx, alice, "npm", "p", "1.0.0"))
	rc, _, err := f.svc.OpenFile(ctx, alice, "npm", "p", "p-1.0.0.tgz")
	r.NoError(err)
	r.Equal("x", read(t, rc))
	r.ErrorIs(f.svc.Restore(ctx, alice, "npm", "p", "1.0.0"), ErrInvalid, "not deleted")
}

func TestPurge(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "shared-content")))
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("q", "1.0.0", "shared-content")))
	versions, _ := f.svc.Versions(ctx, alice, "npm", "p")
	digest := versions[0].Files[0].Digest

	r.ErrorIs(f.svc.Purge(ctx, alice, "npm", "p", "1.0.0", "p@1.0.1"), ErrConfirmationMismatch)
	r.NoError(f.svc.Purge(ctx, alice, "npm", "p", "1.0.0", "p@1.0.0"))
	ok, _ := f.blobs.Exists(ctx, digest)
	r.True(ok, "blob still referenced by q@1.0.0")

	r.NoError(f.svc.Purge(ctx, alice, "npm", "q", "1.0.0", "q@1.0.0"))
	ok, _ = f.blobs.Exists(ctx, digest)
	r.False(ok)

	r.ErrorIs(f.svc.Restore(ctx, alice, "npm", "q", "1.0.0"), ErrNotFound, "purged versions are gone")
	r.ErrorIs(f.svc.Purge(ctx, alice, "npm", "q", "1.0.0", "q@1.0.0"), ErrNotFound)
}

func TestPurgeExpired(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM) // default 30-day grace
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "x")))
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "2.0.0", "y")))
	r.NoError(f.svc.Delete(ctx, alice, "npm", "p", "1.0.0"))
	f.now = f.now.Add(20 * 24 * time.Hour)
	r.NoError(f.svc.Delete(ctx, alice, "npm", "p", "2.0.0"))

	f.now = f.now.Add(11 * 24 * time.Hour) // 1.0.0 deleted 31 days ago, 2.0.0 11 days ago
	n, err := f.svc.PurgeExpired(ctx)
	r.NoError(err)
	r.Equal(1, n)

	trash, _ := f.svc.Trash(ctx, alice, "npm")
	r.Len(trash, 1)
	r.Equal("2.0.0", trash[0].Version)
	entries, _ := f.svc.Audit(ctx, alice, "npm", 1)
	r.Equal("version.purge", entries[0].Action)
	r.Equal("system", entries[0].Actor)
}

func TestEveryMutationAuditedOnce(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "x")))
	r.NoError(f.svc.Yank(ctx, alice, "npm", "p", "1.0.0", ""))
	r.NoError(f.svc.Unyank(ctx, alice, "npm", "p", "1.0.0"))
	r.NoError(f.svc.SetDistTag(ctx, alice, "npm", "p", "beta", "1.0.0"))
	r.NoError(f.svc.RemoveDistTag(ctx, alice, "npm", "p", "beta"))
	r.NoError(f.svc.Delete(ctx, alice, "npm", "p", "1.0.0"))
	r.NoError(f.svc.Restore(ctx, alice, "npm", "p", "1.0.0"))
	anonRead := true
	r.NoError(f.svc.UpdateSettings(ctx, alice, "npm", SettingsInput{AnonymousRead: &anonRead}))
	r.NoError(f.svc.Purge(ctx, alice, "npm", "p", "1.0.0", "p@1.0.0"))

	r.Equal([]string{"repo.create", "version.publish", "version.yank", "version.unyank",
		"disttag.set", "disttag.remove", "version.delete", "version.restore",
		"repo.settings", "version.purge"}, auditActions(t, f, "npm"))

	// Failed attempts change nothing and aren't recorded as changes.
	_ = f.svc.Publish(ctx, bob, "npm", npmVersion("p", "9.0.0", "x"))
	r.Len(auditActions(t, f, "npm"), 10)
}

func TestAuditRequiresAdmin(t *testing.T) {
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleMaintainer)
	_, err := f.svc.Audit(ctx, bob, "npm", 10)
	require.ErrorIs(t, err, ErrForbidden)
}

func TestDistTags(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	f.grant(t, "npm", rbac.SubjectUser, "bob@acme.com", rbac.RoleDeveloper)
	r.NoError(f.svc.Publish(ctx, bob, "npm", npmVersion("p", "1.0.0", "x")))
	r.ErrorIs(f.svc.SetDistTag(ctx, alice, "npm", "p", "next", "9.9.9"), ErrNotFound, "tag must point at an existing version")
	r.ErrorIs(f.svc.SetDistTag(ctx, bob, "npm", "p", "next", "1.0.0"), ErrForbidden)
	r.NoError(f.svc.SetDistTag(ctx, alice, "npm", "p", "next", "1.0.0"))
	tags, err := f.svc.DistTags(ctx, bob, "npm", "p")
	r.NoError(err)
	r.Equal(map[string]string{"next": "1.0.0"}, tags)
}

func TestAnonymousRead(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "x")))
	_, err := f.svc.Versions(ctx, anon, "npm", "p")
	r.ErrorIs(err, ErrUnauthenticated)

	on := true
	r.NoError(f.svc.UpdateSettings(ctx, alice, "npm", SettingsInput{AnonymousRead: &on}))
	_, err = f.svc.Versions(ctx, anon, "npm", "p")
	r.NoError(err)
	r.ErrorIs(f.svc.Publish(ctx, anon, "npm", npmVersion("p", "2.0.0", "x")), ErrUnauthenticated)
}

// --- Tenant isolation ---

func TestTenantIsolation(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	on := true
	r.NoError(f.svc.UpdateSettings(ctx, alice, "npm", SettingsInput{AnonymousRead: &on}))
	r.NoError(f.svc.Publish(ctx, alice, "npm", npmVersion("secret", "1.0.0", "x")))

	evilAdmin := mallo
	evilAdmin.InstanceAdmin = true // even an admin of another tenant
	evilAnon := identity.Anonymous("evil")

	for _, p := range []identity.Principal{mallo, evilAdmin, evilAnon} {
		_, err := f.svc.Versions(ctx, p, "npm", "secret")
		r.ErrorIs(err, ErrNotFound)
		_, _, err = f.svc.OpenFile(ctx, p, "npm", "secret", "secret-1.0.0.tgz")
		r.ErrorIs(err, ErrNotFound)
		_, err = f.svc.Grants(ctx, p, "npm")
		r.ErrorIs(err, ErrNotFound)
		_, err = f.svc.Audit(ctx, p, "npm", 10)
		r.ErrorIs(err, ErrNotFound)
		r.ErrorIs(f.svc.Delete(ctx, p, "npm", "secret", "1.0.0"), ErrNotFound)
		repos, _ := f.svc.ListRepos(ctx, p)
		r.Empty(repos)
	}

	// The same repo name is independent in another tenant.
	r.NoError(f.svc.CreateRepo(ctx, mallo, RepoInput{Name: "npm", Format: FormatNPM}))
	r.NoError(f.svc.Publish(ctx, mallo, "npm", npmVersion("secret", "1.0.0", "y")))
	rc, _, err := f.svc.OpenFile(ctx, alice, "npm", "secret", "secret-1.0.0.tgz")
	r.NoError(err)
	r.Equal("x", read(t, rc))

	used, _ := f.svc.StorageUsed(ctx, mallo)
	r.Equal(int64(1), used)
}

func TestOpenFileReturnsSize(t *testing.T) {
	f := newFixture(t)
	f.repo(t, "npm", FormatNPM)
	require.NoError(t, f.svc.Publish(ctx, alice, "npm", npmVersion("p", "1.0.0", "12345")))
	rc, file, err := f.svc.OpenFile(ctx, alice, "npm", "p", "p-1.0.0.tgz")
	require.NoError(t, err)
	rc.Close()
	require.Equal(t, int64(5), file.Size)
}
