package tokens

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newManager(t *testing.T) (*Manager, *clock) {
	c := &clock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	return NewManager(newTestStore(t), c.Now), c
}

var alice = identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub-alice", Email: "alice@acme.com", Groups: []string{"dev"}}

func TestPersonalTokenRoundTrip(t *testing.T) {
	r := require.New(t)
	m, _ := newManager(t)
	raw, info, err := m.IssuePersonal(alice, "laptop", 0)
	r.NoError(err)
	r.True(strings.HasPrefix(raw, "hxr_"))
	r.Equal("laptop", info.Name)

	p, err := m.Authenticate(raw)
	r.NoError(err)
	r.Equal(identity.KindUser, p.Kind)
	r.Equal("acme", p.Tenant)
	r.Equal("sub-alice", p.Subject)
	r.Equal("alice@acme.com", p.Email)
	r.Equal([]string{"dev"}, p.Groups)
	r.Equal(info.ID, p.TokenID)
}

func TestTokensAreStoredHashed(t *testing.T) {
	store := NewMemoryStore()
	m := NewManager(store, time.Now)
	raw, _, err := m.IssuePersonal(alice, "laptop", 0)
	require.NoError(t, err)
	for _, rec := range store.records {
		require.NotContains(t, rec.Hash, raw)
		require.NotEqual(t, raw, rec.Hash)
	}
}

func TestOnlyUsersGetPersonalTokens(t *testing.T) {
	m, _ := newManager(t)
	_, _, err := m.IssuePersonal(identity.Anonymous("acme"), "x", 0)
	require.ErrorIs(t, err, ErrForbidden)
	_, _, err = m.IssuePersonal(identity.Principal{Tenant: "acme", Kind: identity.KindServiceToken, Subject: "t"}, "x", 0)
	require.ErrorIs(t, err, ErrForbidden)
}

func TestExpiry(t *testing.T) {
	r := require.New(t)
	m, c := newManager(t)
	raw, info, err := m.IssuePersonal(alice, "laptop", 0)
	r.NoError(err)
	r.Equal(c.now.Add(DefaultLifetime), info.ExpiresAt)

	c.now = c.now.Add(DefaultLifetime - time.Second)
	_, err = m.Authenticate(raw)
	r.NoError(err)
	c.now = c.now.Add(2 * time.Second)
	_, err = m.Authenticate(raw)
	r.ErrorIs(err, ErrInvalidToken)
}

func TestLifetimeIsCapped(t *testing.T) {
	m, c := newManager(t)
	_, info, err := m.IssuePersonal(alice, "forever", 10*365*24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, c.now.Add(MaxLifetime), info.ExpiresAt)
}

func TestRevoke(t *testing.T) {
	r := require.New(t)
	m, _ := newManager(t)
	raw, info, _ := m.IssuePersonal(alice, "laptop", 0)

	bob := identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub-bob"}
	r.ErrorIs(m.RevokePersonal(bob, info.ID), ErrNotFound, "can't revoke someone else's token")
	r.NoError(m.RevokePersonal(alice, info.ID))
	_, err := m.Authenticate(raw)
	r.ErrorIs(err, ErrInvalidToken)
}

func TestRevokeAllForUser(t *testing.T) {
	m, _ := newManager(t)
	raw1, _, _ := m.IssuePersonal(alice, "a", 0)
	raw2, _, _ := m.IssuePersonal(alice, "b", 0)
	require.NoError(t, m.RevokeAllForUser("acme", "sub-alice"))
	for _, raw := range []string{raw1, raw2} {
		_, err := m.Authenticate(raw)
		require.ErrorIs(t, err, ErrInvalidToken)
	}
}

func TestListPersonalTokens(t *testing.T) {
	m, _ := newManager(t)
	_, _, _ = m.IssuePersonal(alice, "a", 0)
	_, _, _ = m.IssuePersonal(identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub-bob"}, "b", 0)
	list, err := m.ListPersonal(alice)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "a", list[0].Name)
}

func TestGroupSnapshotRefreshedOnLogin(t *testing.T) {
	r := require.New(t)
	m, _ := newManager(t)
	raw, _, _ := m.IssuePersonal(alice, "laptop", 0)

	r.NoError(m.RefreshUser(identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub-alice",
		Email: "alice@acme.com", Groups: []string{"dev", "release-eng"}}))
	p, err := m.Authenticate(raw)
	r.NoError(err)
	r.Equal([]string{"dev", "release-eng"}, p.Groups)

	// Removed from a group in the IdP: the next login drops it from tokens.
	r.NoError(m.RefreshUser(identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub-alice", Email: "alice@acme.com"}))
	p, _ = m.Authenticate(raw)
	r.Empty(p.Groups)
}

func TestServiceTokens(t *testing.T) {
	r := require.New(t)
	m, _ := newManager(t)
	raw, info, err := m.IssueService("acme", "npm-internal", "github-actions", alice, 0)
	r.NoError(err)
	r.Equal("npm-internal", info.Repo)

	p, err := m.Authenticate(raw)
	r.NoError(err)
	r.Equal(identity.KindServiceToken, p.Kind)
	r.Equal(info.ID, p.Subject)
	r.Empty(p.Email)
	r.Empty(p.Groups)

	list, err := m.ListService("acme", "npm-internal")
	r.NoError(err)
	r.Len(list, 1)
	list, _ = m.ListService("other", "npm-internal")
	r.Empty(list, "tenant scoped")

	r.ErrorIs(m.RevokeService("other", "npm-internal", info.ID), ErrNotFound)
	r.NoError(m.RevokeService("acme", "npm-internal", info.ID))
	_, err = m.Authenticate(raw)
	r.ErrorIs(err, ErrInvalidToken)
}

func TestAuthenticateGarbage(t *testing.T) {
	m, _ := newManager(t)
	for _, raw := range []string{"", "hxr_", "hxr_notatoken", "ghp_abc", strings.Repeat("x", 5000)} {
		_, err := m.Authenticate(raw)
		require.ErrorIs(t, err, ErrInvalidToken, raw)
	}
}

func TestFromRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   string
	}{
		{"npm bearer", "Bearer hxr_abc", "hxr_abc"},
		{"pip/twine basic", "Basic " + b64("__token__:hxr_abc"), "hxr_abc"},
		{"basic with any username", "Basic " + b64("alice:hxr_abc"), "hxr_abc"},
		{"none", "", ""},
		{"malformed basic", "Basic !!!", ""},
		{"cargo sends the token with no scheme", "hxr_abc", "hxr_abc"},
		{"other raw values are ignored", "ghp_abc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			require.Equal(t, tc.want, FromRequest(req))
		})
	}
}

func TestFilterRequiresTenant(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Revoke(Filter{})
	require.ErrorIs(t, err, ErrUnscopedFilter, "an empty filter must never revoke every token")
	_, err = s.List(Filter{Kind: identity.KindUser})
	require.ErrorIs(t, err, ErrUnscopedFilter)
	require.ErrorIs(t, s.UpdateIdentity(Filter{Subject: "x"}, "", nil), ErrUnscopedFilter)
}
