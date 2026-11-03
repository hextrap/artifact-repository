package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/postgres/pgtest"
)

type sessionStore interface {
	Sessions
	DeleteExpired(now time.Time) error
}

// newTestSessions runs the session tests against Postgres when
// HEXTRAP_TEST_POSTGRES_URL is set, and against MemorySessions otherwise.
func newTestSessions(t *testing.T) sessionStore {
	if pgtest.Enabled() {
		return NewPostgresSessions(pgtest.DB(t))
	}
	return NewMemorySessions()
}

func TestSessionRoundTripAndDelete(t *testing.T) {
	r := require.New(t)
	s := newTestSessions(t)
	p := identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "s", Email: "a@acme.com", Groups: []string{"dev"}}
	id, err := s.Create(p, now.Add(time.Hour))
	r.NoError(err)
	got, ok := s.Get(id, now)
	r.True(ok)
	r.Equal(p, got)

	s.Delete(id)
	_, ok = s.Get(id, now)
	r.False(ok)
	_, ok = s.Get("never-issued", now)
	r.False(ok)
}

func TestDeleteExpiredSessions(t *testing.T) {
	r := require.New(t)
	s := newTestSessions(t)
	old, _ := s.Create(identity.Principal{Kind: identity.KindUser, Subject: "old"}, now.Add(time.Minute))
	fresh, _ := s.Create(identity.Principal{Kind: identity.KindUser, Subject: "fresh"}, now.Add(time.Hour))
	r.NoError(s.DeleteExpired(now.Add(2 * time.Minute)))
	_, ok := s.Get(old, now)
	r.False(ok, "removed even when checked with an earlier clock")
	_, ok = s.Get(fresh, now)
	r.True(ok)
}

func TestPostgresStoresSessionIDsHashed(t *testing.T) {
	db := pgtest.DB(t) // skips without Postgres
	s := NewPostgresSessions(db)
	id, err := s.Create(identity.Principal{Kind: identity.KindUser, Subject: "s"}, now.Add(time.Hour))
	require.NoError(t, err)
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM artifact_sessions WHERE id_hash = $1`, id).Scan(&n))
	require.Zero(t, n)
}
