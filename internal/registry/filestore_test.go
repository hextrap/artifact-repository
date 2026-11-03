package registry

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/rbac"
)

func TestFileStoreSurvivesRestart(t *testing.T) {
	r := require.New(t)
	path := filepath.Join(t.TempDir(), "registry.db")
	ts := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	s, err := NewFileStore(path)
	r.NoError(err)
	admin := rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "alice", Role: rbac.RoleAdmin}
	r.NoError(s.CreateRepo(Repo{Tenant: "acme", Name: "npm", Format: FormatNPM, DeleteGrace: time.Hour, CreatedAt: ts}, admin))
	r.NoError(s.UpdateGrants("acme", "npm", func(g []rbac.Grant) ([]rbac.Grant, error) {
		return append(g, rbac.Grant{SubjectKind: rbac.SubjectGroup, Subject: "dev", Role: rbac.RoleReader}), nil
	}))
	v := Version{Tenant: "acme", Repo: "npm", Package: "p", DisplayName: "p", Version: "1.0.0",
		Manifest: []byte(`{"main":"x"}`), PublishedAt: ts,
		Files: []File{{Filename: "p-1.0.0.tgz", Digest: "sha256:abc", Size: 3, Attrs: map[string]string{"shasum": "abc"}}}}
	r.NoError(s.CreateVersion(v, map[string]string{"latest": "1.0.0"}))
	_, err = s.UpdateVersion(v.Key(), func(v *Version) error { v.Yanked = true; return nil })
	r.NoError(err)
	r.NoError(s.AppendAudit(AuditEntry{Tenant: "acme", Repo: "npm", Action: "version.publish", Time: ts}))

	s2, err := NewFileStore(path)
	r.NoError(err)
	repo, err := s2.GetRepo("acme", "npm")
	r.NoError(err)
	r.Equal(time.Hour, repo.DeleteGrace)
	grants, _ := s2.Grants("acme", "npm")
	r.Len(grants, 2)
	versions, _ := s2.Versions("acme", "npm", "p")
	r.Len(versions, 1)
	r.Equal("acme", versions[0].Tenant)
	r.True(versions[0].Yanked)
	r.Equal("abc", versions[0].Files[0].Attrs["shasum"])
	r.JSONEq(`{"main":"x"}`, string(versions[0].Manifest))
	tags, _ := s2.DistTags("acme", "npm", "p")
	r.Equal(map[string]string{"latest": "1.0.0"}, tags)
	audit, _ := s2.Audit("acme", "npm", 10)
	r.Len(audit, 1)
	r.Equal("acme", audit[0].Tenant)

	// Immutability rules survive a restart.
	v.Version = "1.0.1"
	r.ErrorIs(s2.CreateVersion(v, nil), ErrFileExists, "filename history persisted")
	v.Files[0].Filename = "p-1.0.1.tgz"
	v.Version = "1.0.0"
	r.ErrorIs(s2.CreateVersion(v, nil), ErrVersionExists)
}

func TestFileStoreRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	require.NoError(t, os.WriteFile(path, []byte("garbage"), 0o600))
	_, err := NewFileStore(path)
	require.Error(t, err)
}

func TestFileStoreFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	s, err := NewFileStore(path)
	require.NoError(t, err)
	require.NoError(t, s.AppendAudit(AuditEntry{Tenant: "t"}))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
