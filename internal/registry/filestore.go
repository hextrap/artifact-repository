package registry

import (
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/snapshot"
)

// NewFileStore returns a MemoryStore that saves a snapshot to path after
// every change. It suits single-node installs; each write rewrites the whole
// snapshot, including the audit log, so it doesn't scale to large registries.
func NewFileStore(path string) (*MemoryStore, error) {
	m := NewMemoryStore()
	var snap storeSnapshot
	found, err := snapshot.Load(path, &snap)
	if err != nil {
		return nil, err
	}
	if found {
		m.restore(snap)
	}
	m.path = path
	return m, nil
}

type repoSnapshot struct {
	Repo      Repo
	Grants    []rbac.Grant
	Filenames map[string]map[string]bool
}

type tagSnapshot struct {
	Tenant, Repo, Package string
	Tags                  map[string]string
}

// storeSnapshot is gob-encoded, which keeps fields like Version.Tenant that
// are hidden from JSON.
type storeSnapshot struct {
	Repos    []repoSnapshot
	Versions []Version // insertion order
	Tags     []tagSnapshot
	Audit    []AuditEntry
}

func (m *MemoryStore) snapshot() storeSnapshot {
	var s storeSnapshot
	for _, r := range m.repos {
		s.Repos = append(s.Repos, repoSnapshot{Repo: r.repo, Grants: r.grants, Filenames: r.filenames})
	}
	for _, k := range m.order {
		s.Versions = append(s.Versions, *m.versions[k])
	}
	for k, tags := range m.tags {
		s.Tags = append(s.Tags, tagSnapshot{Tenant: k.tenant, Repo: k.repo, Package: k.pkg, Tags: tags})
	}
	s.Audit = m.audit
	return s
}

func (m *MemoryStore) restore(s storeSnapshot) {
	for _, r := range s.Repos {
		if r.Filenames == nil {
			r.Filenames = map[string]map[string]bool{}
		}
		m.repos[repoKey{r.Repo.Tenant, r.Repo.Name}] = &repoState{repo: r.Repo, grants: r.Grants, filenames: r.Filenames}
	}
	for i := range s.Versions {
		v := s.Versions[i]
		m.versions[v.Key()] = &v
		m.order = append(m.order, v.Key())
	}
	for _, t := range s.Tags {
		m.tags[pkgKey{t.Tenant, t.Repo, t.Package}] = t.Tags
	}
	m.audit = s.Audit
}

// save persists the store if it's file-backed. Callers hold m.mu.
func (m *MemoryStore) save() error {
	if m.path == "" {
		return nil
	}
	return snapshot.Save(m.path, m.snapshot())
}
