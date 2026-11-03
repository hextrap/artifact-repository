package tokens

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/postgres/pgtest"
)

// newTestStore runs the token tests against Postgres when
// HEXTRAP_TEST_POSTGRES_URL is set, and against MemoryStore otherwise.
func newTestStore(t *testing.T) Store {
	if pgtest.Enabled() {
		return NewPostgresStore(pgtest.DB(t))
	}
	return NewMemoryStore()
}

func TestFilterWhere(t *testing.T) {
	r := require.New(t)
	where, args, err := Filter{Tenant: "acme", Kind: identity.KindUser, Subject: "sub"}.where(3)
	r.NoError(err)
	r.Equal("tenant = $3 AND kind = $4 AND subject = $5", where)
	r.Equal([]any{"acme", "user", "sub"}, args)

	where, args, err = Filter{Tenant: "acme", ID: "tok_1", Repo: "npm"}.where(1)
	r.NoError(err)
	r.Equal("tenant = $1 AND id = $2 AND repo = $3", where)
	r.Equal([]any{"acme", "tok_1", "npm"}, args)

	_, _, err = Filter{Kind: identity.KindUser}.where(1)
	r.ErrorIs(err, ErrUnscopedFilter)
}

func TestPostgresStoresOnlyHashes(t *testing.T) {
	db := pgtest.DB(t) // skips without Postgres
	m := NewManager(NewPostgresStore(db), time.Now)
	raw, _, err := m.IssuePersonal(alice, "laptop", 0)
	require.NoError(t, err)
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM artifact_tokens WHERE hash = $1 OR id = $1`, raw).Scan(&n))
	require.Zero(t, n)
}
