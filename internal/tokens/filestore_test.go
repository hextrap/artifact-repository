package tokens

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFileStoreSurvivesRestart(t *testing.T) {
	r := require.New(t)
	path := filepath.Join(t.TempDir(), "tokens.db")
	now := func() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC) }

	s, err := NewFileStore(path)
	r.NoError(err)
	m := NewManager(s, now)
	keep, _, err := m.IssuePersonal(alice, "keep", 0)
	r.NoError(err)
	revoke, info, err := m.IssuePersonal(alice, "revoke", 0)
	r.NoError(err)
	r.NoError(m.RevokePersonal(alice, info.ID))

	s2, err := NewFileStore(path)
	r.NoError(err)
	m2 := NewManager(s2, now)
	p, err := m2.Authenticate(keep)
	r.NoError(err)
	r.Equal([]string{"dev"}, p.Groups)
	_, err = m2.Authenticate(revoke)
	r.ErrorIs(err, ErrInvalidToken, "revocation persisted")
}
