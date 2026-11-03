// Package tokens issues and verifies static API tokens for package clients
// (npm, pip, uv, twine), which can't do a browser SSO login. Only a hash of
// each token is stored.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"hextrap.io/artifacts/internal/identity"
)

var (
	ErrInvalidToken = errors.New("invalid or expired token")
	ErrNotFound     = errors.New("token not found")
	ErrForbidden    = errors.New("forbidden")
)

const (
	DefaultLifetime = 90 * 24 * time.Hour
	MaxLifetime     = 365 * 24 * time.Hour
	prefix          = "hxr_"
)

// Info is a token as shown to its owner; it never includes the token itself.
type Info struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Repo      string    `json:"repo,omitempty"` // service tokens only
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Record struct {
	Info
	Hash    string
	Tenant  string
	Kind    identity.Kind
	Subject string // user's OIDC sub; empty for service tokens
	Email   string
	Groups  []string
	Revoked bool
}

// Filter selects token records. Empty fields match anything, except Tenant,
// which is required so no query can span every tenant.
type Filter struct {
	Tenant  string
	Kind    identity.Kind
	ID      string
	Subject string
	Repo    string
}

var ErrUnscopedFilter = errors.New("token filter must include a tenant")

func (f Filter) matches(r Record) bool {
	return r.Tenant == f.Tenant &&
		(f.Kind == "" || r.Kind == f.Kind) &&
		(f.ID == "" || r.ID == f.ID) &&
		(f.Subject == "" || r.Subject == f.Subject) &&
		(f.Repo == "" || r.Repo == f.Repo)
}

type Store interface {
	Create(r Record) error
	ByHash(hash string) (Record, error)
	List(f Filter) ([]Record, error)
	// Revoke marks matching tokens revoked and returns how many matched.
	Revoke(f Filter) (int, error)
	// UpdateIdentity sets the email and groups snapshot on matching tokens.
	UpdateIdentity(f Filter, email string, groups []string) error
}

type Manager struct {
	store Store
	now   func() time.Time
}

func NewManager(store Store, now func() time.Time) *Manager {
	return &Manager{store: store, now: now}
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (m *Manager) issue(r Record, lifetime time.Duration) (string, Info, error) {
	if lifetime <= 0 {
		lifetime = DefaultLifetime
	}
	lifetime = min(lifetime, MaxLifetime)
	secret, err := randomString(32)
	if err != nil {
		return "", Info{}, err
	}
	id, err := randomString(9)
	if err != nil {
		return "", Info{}, err
	}
	raw := prefix + secret
	r.ID = "tok_" + id
	r.Hash = hashToken(raw)
	r.CreatedAt = m.now()
	r.ExpiresAt = r.CreatedAt.Add(lifetime)
	if err := m.store.Create(r); err != nil {
		return "", Info{}, err
	}
	return raw, r.Info, nil
}

// IssuePersonal mints a token that acts as the user, with their groups as
// of this login. The raw token is returned once and never stored.
func (m *Manager) IssuePersonal(p identity.Principal, name string, lifetime time.Duration) (string, Info, error) {
	if p.Kind != identity.KindUser {
		return "", Info{}, ErrForbidden
	}
	return m.issue(Record{
		Info:   Info{Name: name, CreatedBy: p.Actor()},
		Tenant: p.Tenant, Kind: identity.KindUser, Subject: p.Subject, Email: p.Email,
		Groups: slices.Clone(p.Groups),
	}, lifetime)
}

// IssueService mints a token for CI, scoped to one repo. The caller must
// have checked createdBy may manage the repo's access; the token has no
// role until granted one.
func (m *Manager) IssueService(tenant, repo, name string, createdBy identity.Principal, lifetime time.Duration) (string, Info, error) {
	return m.issue(Record{
		Info:   Info{Name: name, Repo: repo, CreatedBy: createdBy.Actor()},
		Tenant: tenant, Kind: identity.KindServiceToken,
	}, lifetime)
}

func (m *Manager) Authenticate(raw string) (identity.Principal, error) {
	if !strings.HasPrefix(raw, prefix) || len(raw) > 256 {
		return identity.Principal{}, ErrInvalidToken
	}
	r, err := m.store.ByHash(hashToken(raw))
	if err != nil || r.Revoked || !m.now().Before(r.ExpiresAt) {
		return identity.Principal{}, ErrInvalidToken
	}
	p := identity.Principal{Tenant: r.Tenant, Kind: r.Kind, TokenID: r.ID}
	if r.Kind == identity.KindServiceToken {
		p.Subject = r.ID
		return p, nil
	}
	p.Subject, p.Email, p.Groups = r.Subject, r.Email, slices.Clone(r.Groups)
	return p, nil
}

// RefreshUser updates the identity snapshot on all of a user's tokens. Call
// it on every SSO login so group changes in the IdP reach tokens.
func (m *Manager) RefreshUser(p identity.Principal) error {
	return m.store.UpdateIdentity(Filter{Tenant: p.Tenant, Kind: identity.KindUser, Subject: p.Subject}, p.Email, p.Groups)
}

func (m *Manager) revokeOne(f Filter) error {
	n, err := m.store.Revoke(f)
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

func (m *Manager) RevokePersonal(owner identity.Principal, id string) error {
	return m.revokeOne(Filter{Tenant: owner.Tenant, Kind: identity.KindUser, Subject: owner.Subject, ID: id})
}

// RevokeAllForUser is for deprovisioning.
func (m *Manager) RevokeAllForUser(tenant, subject string) error {
	_, err := m.store.Revoke(Filter{Tenant: tenant, Kind: identity.KindUser, Subject: subject})
	return err
}

func (m *Manager) RevokeService(tenant, repo, id string) error {
	return m.revokeOne(Filter{Tenant: tenant, Kind: identity.KindServiceToken, Repo: repo, ID: id})
}

func (m *Manager) list(f Filter) ([]Info, error) {
	now := m.now()
	recs, err := m.store.List(f)
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(recs))
	for _, r := range recs {
		if !r.Revoked && now.Before(r.ExpiresAt) {
			out = append(out, r.Info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Manager) ListPersonal(p identity.Principal) ([]Info, error) {
	return m.list(Filter{Tenant: p.Tenant, Kind: identity.KindUser, Subject: p.Subject})
}

func (m *Manager) ListService(tenant, repo string) ([]Info, error) {
	return m.list(Filter{Tenant: tenant, Kind: identity.KindServiceToken, Repo: repo})
}

// FromRequest extracts a token from "Authorization: Bearer <token>" (npm),
// Basic auth with the token as password (pip, uv, twine, Maven), or the
// bare token, which is how Cargo sends it.
func FromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h)
	}
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	if _, pass, ok := r.BasicAuth(); ok {
		return pass
	}
	return ""
}

type MemoryStore struct {
	mu      sync.Mutex
	records map[string]*Record // by ID
	path    string             // snapshot file; set by NewFileStore
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]*Record{}}
}

func (s *MemoryStore) Create(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.ID] = &r
	return s.save()
}

func (s *MemoryStore) ByHash(hash string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.Hash == hash {
			return *r, nil
		}
	}
	return Record{}, ErrNotFound
}

func (s *MemoryStore) List(f Filter) ([]Record, error) {
	if f.Tenant == "" {
		return nil, ErrUnscopedFilter
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for _, r := range s.records {
		if f.matches(*r) {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (s *MemoryStore) update(f Filter, fn func(*Record)) (int, error) {
	if f.Tenant == "" {
		return 0, ErrUnscopedFilter
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.records {
		if f.matches(*r) {
			fn(r)
			n++
		}
	}
	if n > 0 {
		return n, s.save()
	}
	return n, nil
}

func (s *MemoryStore) Revoke(f Filter) (int, error) {
	return s.update(f, func(r *Record) { r.Revoked = true })
}

func (s *MemoryStore) UpdateIdentity(f Filter, email string, groups []string) error {
	_, err := s.update(f, func(r *Record) { r.Email, r.Groups = email, slices.Clone(groups) })
	return err
}
