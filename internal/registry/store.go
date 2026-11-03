package registry

import (
	"slices"
	"sort"
	"strings"
	"sync"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/rbac"
)

// Store persists registry metadata. Each method is atomic; a SQL
// implementation runs each in one transaction.
type Store interface {
	CreateRepo(r Repo, admin rbac.Grant) error
	GetRepo(tenant, name string) (Repo, error)
	ListRepos(tenant string) ([]Repo, error)
	UpdateRepo(r Repo) error
	// DeleteRepo fails with ErrRepoNotEmpty while any unpurged version exists.
	DeleteRepo(tenant, name string) error

	Grants(tenant, repo string) ([]rbac.Grant, error)
	UpdateGrants(tenant, repo string, fn func([]rbac.Grant) ([]rbac.Grant, error)) error

	// CreateVersion fails with ErrVersionExists if the version ever existed,
	// or ErrFileExists if any filename was ever used for the package.
	CreateVersion(v Version, tags map[string]string) error
	// AddFiles adds files to a version, creating it from init if needed. It
	// adds all of them or none.
	AddFiles(init Version, files []File) error
	UpdateVersion(key VersionKey, fn func(*Version) error) (Version, error)
	// Versions returns all versions of a package in every state.
	Versions(tenant, repo, pkg string) ([]Version, error)
	RepoVersions(tenant, repo string) ([]Version, error)
	// TrashedVersions returns soft-deleted, unpurged versions in all tenants.
	TrashedVersions() ([]Version, error)

	DistTags(tenant, repo, pkg string) (map[string]string, error)
	SetDistTag(tenant, repo, pkg, tag, version string) error
	RemoveDistTag(tenant, repo, pkg, tag string) error

	// DigestReferenced reports whether any unpurged version in any tenant
	// uses the blob.
	DigestReferenced(d blob.Digest) (bool, error)
	StorageUsed(tenant string) (int64, error)

	AppendAudit(e AuditEntry) error
	// Audit returns a repo's entries, newest first.
	Audit(tenant, repo string, limit int) ([]AuditEntry, error)
}

type repoKey struct{ tenant, name string }

type pkgKey struct{ tenant, repo, pkg string }

type repoState struct {
	repo      Repo
	grants    []rbac.Grant
	filenames map[string]map[string]bool // package -> every filename ever used
}

type MemoryStore struct {
	mu       sync.Mutex
	repos    map[repoKey]*repoState
	versions map[VersionKey]*Version
	order    []VersionKey // insertion order
	tags     map[pkgKey]map[string]string
	audit    []AuditEntry
	path     string // snapshot file; set by NewFileStore
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		repos:    map[repoKey]*repoState{},
		versions: map[VersionKey]*Version{},
		tags:     map[pkgKey]map[string]string{},
	}
}

func (m *MemoryStore) CreateRepo(r Repo, admin rbac.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := repoKey{r.Tenant, r.Name}
	if _, ok := m.repos[k]; ok {
		return ErrExists
	}
	m.repos[k] = &repoState{repo: r, grants: []rbac.Grant{admin}, filenames: map[string]map[string]bool{}}
	return m.save()
}

func (m *MemoryStore) repo(tenant, name string) (*repoState, error) {
	s, ok := m.repos[repoKey{tenant, name}]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

func (m *MemoryStore) GetRepo(tenant, name string) (Repo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.repo(tenant, name)
	if err != nil {
		return Repo{}, err
	}
	return s.repo, nil
}

func (m *MemoryStore) ListRepos(tenant string) ([]Repo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Repo
	for k, s := range m.repos {
		if k.tenant == tenant {
			out = append(out, s.repo)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) UpdateRepo(r Repo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.repo(r.Tenant, r.Name)
	if err != nil {
		return err
	}
	s.repo = r
	return m.save()
}

func (m *MemoryStore) DeleteRepo(tenant, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.repo(tenant, name); err != nil {
		return err
	}
	for k, v := range m.versions {
		if k.Tenant == tenant && k.Repo == name && v.PurgedAt == nil {
			return ErrRepoNotEmpty
		}
	}
	for k := range m.versions {
		if k.Tenant == tenant && k.Repo == name {
			delete(m.versions, k)
		}
	}
	m.order = slices.DeleteFunc(m.order, func(k VersionKey) bool { return k.Tenant == tenant && k.Repo == name })
	for k := range m.tags {
		if k.tenant == tenant && k.repo == name {
			delete(m.tags, k)
		}
	}
	delete(m.repos, repoKey{tenant, name})
	return m.save()
}

func (m *MemoryStore) Grants(tenant, repo string) ([]rbac.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.repo(tenant, repo)
	if err != nil {
		return nil, err
	}
	return slices.Clone(s.grants), nil
}

func (m *MemoryStore) UpdateGrants(tenant, repo string, fn func([]rbac.Grant) ([]rbac.Grant, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.repo(tenant, repo)
	if err != nil {
		return err
	}
	g, err := fn(slices.Clone(s.grants))
	if err != nil {
		return err
	}
	s.grants = g
	return m.save()
}

func cloneVersion(v *Version) Version {
	c := *v
	c.Files = slices.Clone(v.Files)
	return c
}

func (m *MemoryStore) CreateVersion(v Version, tags map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.repo(v.Tenant, v.Repo)
	if err != nil {
		return err
	}
	if _, ok := m.versions[v.Key()]; ok {
		return ErrVersionExists
	}
	for _, f := range v.Files {
		if s.filenames[v.Package][f.Filename] {
			return ErrFileExists
		}
	}
	for _, f := range v.Files {
		s.fileUsed(v.Package, f.Filename)
	}
	c := cloneVersion(&v)
	m.versions[v.Key()] = &c
	m.order = append(m.order, v.Key())
	for tag, ver := range tags {
		m.setTag(v.Tenant, v.Repo, v.Package, tag, ver)
	}
	return m.save()
}

func (m *MemoryStore) AddFiles(init Version, files []File) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.repo(init.Tenant, init.Repo)
	if err != nil {
		return err
	}
	for _, f := range files {
		if s.filenames[init.Package][f.Filename] {
			return ErrFileExists
		}
	}
	v, ok := m.versions[init.Key()]
	if ok && !v.Visible() {
		return ErrVersionExists
	}
	if !ok {
		c := cloneVersion(&init)
		c.Files = nil
		v = &c
		m.versions[init.Key()] = v
		m.order = append(m.order, init.Key())
	}
	for _, f := range files {
		v.Files = append(v.Files, f)
		s.fileUsed(init.Package, f.Filename)
	}
	return m.save()
}

func (m *MemoryStore) UpdateVersion(key VersionKey, fn func(*Version) error) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.versions[key]
	if !ok {
		return Version{}, ErrNotFound
	}
	c := cloneVersion(v)
	if err := fn(&c); err != nil {
		return Version{}, err
	}
	*v = c
	return cloneVersion(v), m.save()
}

func (m *MemoryStore) filter(match func(VersionKey) bool) []Version {
	var out []Version
	for _, k := range m.order {
		if match(k) {
			out = append(out, cloneVersion(m.versions[k]))
		}
	}
	return out
}

func (m *MemoryStore) Versions(tenant, repo, pkg string) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filter(func(k VersionKey) bool { return k.Tenant == tenant && k.Repo == repo && k.Package == pkg }), nil
}

func (m *MemoryStore) RepoVersions(tenant, repo string) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filter(func(k VersionKey) bool { return k.Tenant == tenant && k.Repo == repo }), nil
}

func (m *MemoryStore) TrashedVersions() ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filter(func(k VersionKey) bool { return m.versions[k].InTrash() }), nil
}

func (m *MemoryStore) DistTags(tenant, repo, pkg string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for t, v := range m.tags[pkgKey{tenant, repo, pkg}] {
		out[t] = v
	}
	return out, nil
}

func (m *MemoryStore) setTag(tenant, repo, pkg, tag, version string) {
	k := pkgKey{tenant, repo, pkg}
	if m.tags[k] == nil {
		m.tags[k] = map[string]string{}
	}
	m.tags[k][tag] = version
}

func (m *MemoryStore) SetDistTag(tenant, repo, pkg, tag, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setTag(tenant, repo, pkg, tag, version)
	return m.save()
}

func (m *MemoryStore) RemoveDistTag(tenant, repo, pkg, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tags := m.tags[pkgKey{tenant, repo, pkg}]
	if _, ok := tags[tag]; !ok {
		return ErrNotFound
	}
	delete(tags, tag)
	return m.save()
}

func (m *MemoryStore) DigestReferenced(d blob.Digest) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.versions {
		if v.PurgedAt != nil {
			continue
		}
		for _, f := range v.Files {
			if f.Digest == d {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *MemoryStore) StorageUsed(tenant string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, v := range m.versions {
		if k.Tenant == tenant && v.PurgedAt == nil {
			n += v.Size()
		}
	}
	return n, nil
}

func (m *MemoryStore) AppendAudit(e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, e)
	return m.save()
}

func (m *MemoryStore) Audit(tenant, repo string, limit int) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AuditEntry
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if e := m.audit[i]; e.Tenant == tenant && e.Repo == repo {
			out = append(out, e)
		}
	}
	return out, nil
}

// sameSubject reports whether a grant is for the given subject. User
// subjects compare case-insensitively since they're often emails.
func sameSubject(g rbac.Grant, kind rbac.SubjectKind, subject string) bool {
	if g.SubjectKind != kind {
		return false
	}
	if kind == rbac.SubjectUser {
		return strings.EqualFold(g.Subject, subject)
	}
	return g.Subject == subject
}

func (s *repoState) fileUsed(pkg, filename string) {
	if s.filenames[pkg] == nil {
		s.filenames[pkg] = map[string]bool{}
	}
	s.filenames[pkg][filename] = true
}
