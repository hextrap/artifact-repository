package registry

import (
	"fmt"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/postgres/pgtest"
	"hextrap.io/artifacts/internal/rbac"
)

// newTestStore runs the registry tests against Postgres when
// HEXTRAP_TEST_POSTGRES_URL is set, and against MemoryStore otherwise.
func newTestStore(t *testing.T) Store {
	if pgtest.Enabled() {
		return NewPostgresStore(pgtest.DB(t))
	}
	return NewMemoryStore()
}

func TestUniqueViolationMapping(t *testing.T) {
	unique := func(constraint string) error {
		return fmt.Errorf("insert: %w", &pq.Error{Code: "23505", Constraint: constraint})
	}
	require.ErrorIs(t, mapError(unique("artifact_repos_pkey")), ErrExists)
	require.ErrorIs(t, mapError(unique("artifact_versions_pkey")), ErrVersionExists)
	require.ErrorIs(t, mapError(unique("artifact_filenames_pkey")), ErrFileExists)

	other := unique("artifact_something_else")
	require.Equal(t, other, mapError(other))
	fk := &pq.Error{Code: "23503", Constraint: "artifact_versions_repo_fkey"}
	require.ErrorIs(t, mapError(fk), ErrNotFound, "a row referencing a missing repo")
	require.NoError(t, mapError(nil))
}

func TestPostgresStoreSurvivesReconnect(t *testing.T) {
	db := pgtest.DB(t) // skips without Postgres
	s := NewPostgresStore(db)
	r := require.New(t)
	r.NoError(s.CreateRepo(Repo{Tenant: "acme", Name: "npm", Format: FormatNPM}, rbacAdmin("alice")))
	s2 := NewPostgresStore(db)
	repo, err := s2.GetRepo("acme", "npm")
	r.NoError(err)
	r.Equal(FormatNPM, repo.Format)
}

func rbacAdmin(subject string) rbac.Grant {
	return rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: subject, Role: rbac.RoleAdmin}
}
