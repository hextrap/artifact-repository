// Package registry is the format-independent core of hosted repositories:
// repositories, versions, access control, the deletion lifecycle and audit.
// Every operation takes the calling principal and is scoped to its tenant,
// so no caller can reach another tenant's data.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
)

// Quotas returns a tenant's storage quota in bytes; 0 means unlimited.
type Quotas interface {
	StorageQuota(tenant string) int64
}

type QuotaFunc func(tenant string) int64

func (f QuotaFunc) StorageQuota(tenant string) int64 { return f(tenant) }

type Service struct {
	store  Store
	blobs  blob.Store
	now    func() time.Time
	quotas Quotas
	// upstreams are the registries proxy repos may use, per format. They come
	// from the config file so repo creators can't point the server at
	// arbitrary (e.g. internal) addresses.
	upstreams map[Format][]string
	// firewalls are the upstreams that are hextrap firewalls.
	firewalls map[string]bool
	// requireFirewall: every proxy repo must use a firewall (cloud).
	requireFirewall bool
}

// AllowUpstreams permits proxy repos of format to use these registries. The
// first is the default.
func (s *Service) AllowUpstreams(format Format, urls ...string) {
	if s.upstreams == nil {
		s.upstreams = map[Format][]string{}
	}
	for _, u := range urls {
		s.upstreams[format] = append(s.upstreams[format], strings.TrimSuffix(u, "/"))
	}
}

// AllowFirewall permits proxy repos of format to use a hextrap firewall as
// their upstream, and makes it the default for new ones.
func (s *Service) AllowFirewall(format Format, url string) {
	url = strings.TrimSuffix(url, "/")
	if s.upstreams == nil {
		s.upstreams = map[Format][]string{}
	}
	if s.firewalls == nil {
		s.firewalls = map[string]bool{}
	}
	s.upstreams[format] = append([]string{url}, s.upstreams[format]...)
	s.firewalls[url] = true
}

// IsFirewall reports whether url is a hextrap firewall upstream.
func (s *Service) IsFirewall(url string) bool { return s.firewalls[url] }

// RequireFirewall makes every proxy repo use a hextrap firewall, so nothing
// is cached unchecked. The cloud edition sets it.
func (s *Service) RequireFirewall() { s.requireFirewall = true }

// view adds what callers need to know about repo beyond its record.
func (s *Service) view(repo Repo, role rbac.Role) RepoView {
	return RepoView{Repo: repo, Role: role, Firewall: s.firewalls[repo.Upstream]}
}

// Upstreams returns the allowed upstream registries per format.
func (s *Service) Upstreams() map[Format][]string {
	out := map[Format][]string{}
	for f, u := range s.upstreams {
		out[f] = slices.Clone(u)
	}
	return out
}

func New(store Store, blobs blob.Store, now func() time.Time, quotas Quotas) *Service {
	if quotas == nil {
		quotas = QuotaFunc(func(string) int64 { return 0 })
	}
	return &Service{store: store, blobs: blobs, now: now, quotas: quotas}
}

type sourceIPKey struct{}

// WithSourceIP records the client IP for audit entries.
func WithSourceIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceIPKey{}, ip)
}

func (s *Service) audit(ctx context.Context, p identity.Principal, repo, action, target, before, after string) {
	ip, _ := ctx.Value(sourceIPKey{}).(string)
	// Audit write failures don't undo the change; the store is expected to
	// write both in one transaction in the SQL implementation.
	_ = s.store.AppendAudit(AuditEntry{
		Time: s.now(), Tenant: p.Tenant, Repo: repo, Actor: p.Actor(), ActorKind: string(p.Kind),
		Action: action, Target: target, Before: before, After: after, SourceIP: ip,
	})
}

var systemPrincipal = identity.Principal{Kind: identity.KindSystem}

// authorize loads a repo in p's tenant and checks p may perform action. A
// principal with no access gets ErrNotFound so repo names don't leak.
func (s *Service) authorize(p identity.Principal, repoName string, action rbac.Action) (Repo, rbac.Role, error) {
	repo, err := s.store.GetRepo(p.Tenant, repoName)
	if err != nil {
		return Repo{}, rbac.RoleNone, err
	}
	grants, err := s.store.Grants(p.Tenant, repoName)
	if err != nil {
		return Repo{}, rbac.RoleNone, err
	}
	role := rbac.Effective(p, grants, repo.AnonymousRead)
	if role.Can(action) {
		return repo, role, nil
	}
	if p.Kind == identity.KindAnonymous {
		return Repo{}, role, ErrUnauthenticated
	}
	if role == rbac.RoleNone {
		return Repo{}, role, ErrNotFound
	}
	return Repo{}, role, ErrForbidden
}

// --- Repositories ---

var repoNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type RepoInput struct {
	Name          string `json:"name"`
	Format        Format `json:"format"`
	AnonymousRead bool   `json:"anonymous_read"`
	// Type is TypeHosted (default) or TypeProxy.
	Type RepoType `json:"type"`
	// Upstream is a proxy repo's registry; it defaults to the first allowed.
	Upstream string `json:"upstream"`
}

func (s *Service) CreateRepo(ctx context.Context, p identity.Principal, in RepoInput) error {
	switch p.Kind {
	case identity.KindUser:
	case identity.KindAnonymous:
		return ErrUnauthenticated
	default:
		return ErrForbidden
	}
	if !repoNameRE.MatchString(in.Name) {
		return fmt.Errorf("%w: repository name must match %s", ErrInvalid, repoNameRE)
	}
	if !slices.Contains(Formats, in.Format) {
		return fmt.Errorf("%w: unsupported format %q", ErrInvalid, in.Format)
	}
	upstream, err := s.repoUpstream(in)
	if err != nil {
		return err
	}
	if in.Type == "" {
		in.Type = TypeHosted
	}
	repo := Repo{
		Tenant: p.Tenant, Name: in.Name, Format: in.Format, Type: in.Type, Upstream: upstream,
		AnonymousRead: in.AnonymousRead, DeleteGrace: DefaultDeleteGrace,
		CreatedAt: s.now(), CreatedBy: p.Actor(),
	}
	admin := rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: p.Subject, Role: rbac.RoleAdmin}
	if err := s.store.CreateRepo(repo, admin); err != nil {
		return err
	}
	s.audit(ctx, p, in.Name, "repo.create", in.Name, "", string(in.Format))
	return nil
}

func (s *Service) Repo(_ context.Context, p identity.Principal, name string) (RepoView, error) {
	repo, role, err := s.authorize(p, name, rbac.ActionPull)
	if err != nil {
		return RepoView{}, err
	}
	return s.view(repo, role), nil
}

// ListRepos returns the repos p can pull from.
func (s *Service) ListRepos(_ context.Context, p identity.Principal) ([]RepoView, error) {
	repos, err := s.store.ListRepos(p.Tenant)
	if err != nil {
		return nil, err
	}
	var out []RepoView
	for _, r := range repos {
		grants, err := s.store.Grants(p.Tenant, r.Name)
		if err != nil {
			return nil, err
		}
		if role := rbac.Effective(p, grants, r.AnonymousRead); role.Can(rbac.ActionPull) {
			out = append(out, s.view(r, role))
		}
	}
	return out, nil
}

type SettingsInput struct {
	AnonymousRead *bool          `json:"anonymous_read,omitempty"`
	DeleteGrace   *time.Duration `json:"delete_grace,omitempty"`
	// Upstream switches a proxy repo to another configured upstream, such as
	// a hextrap firewall. Cached files stay.
	Upstream *string `json:"upstream,omitempty"`
}

func (s *Service) UpdateSettings(ctx context.Context, p identity.Principal, name string, in SettingsInput) error {
	repo, _, err := s.authorize(p, name, rbac.ActionManageSettings)
	if err != nil {
		return err
	}
	before := settingsString(repo)
	if in.AnonymousRead != nil {
		repo.AnonymousRead = *in.AnonymousRead
	}
	if in.DeleteGrace != nil {
		if *in.DeleteGrace < 0 {
			return fmt.Errorf("%w: delete grace must not be negative", ErrInvalid)
		}
		repo.DeleteGrace = *in.DeleteGrace
	}
	if in.Upstream != nil {
		if repo.Type != TypeProxy {
			return fmt.Errorf("%w: hosted repositories have no upstream", ErrInvalid)
		}
		upstream, err := s.proxyUpstream(repo.Format, strings.TrimSuffix(*in.Upstream, "/"))
		if err != nil {
			return err
		}
		repo.Upstream = upstream
	}
	if err := s.store.UpdateRepo(repo); err != nil {
		return err
	}
	s.audit(ctx, p, name, "repo.settings", name, before, settingsString(repo))
	return nil
}

func settingsString(r Repo) string {
	s := fmt.Sprintf("anonymous_read=%t delete_grace=%s", r.AnonymousRead, r.DeleteGrace)
	if r.Upstream != "" {
		s += " upstream=" + r.Upstream
	}
	return s
}

func (s *Service) DeleteRepo(ctx context.Context, p identity.Principal, name string) error {
	if _, _, err := s.authorize(p, name, rbac.ActionDeleteRepo); err != nil {
		return err
	}
	if err := s.store.DeleteRepo(p.Tenant, name); err != nil {
		return err
	}
	s.audit(ctx, p, name, "repo.delete", name, "", "")
	return nil
}

// --- Access ---

func (s *Service) Grants(_ context.Context, p identity.Principal, repo string) ([]rbac.Grant, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionManageAccess); err != nil {
		return nil, err
	}
	return s.store.Grants(p.Tenant, repo)
}

// SetGrant adds a grant or changes the role of an existing one.
func (s *Service) SetGrant(ctx context.Context, p identity.Principal, repo string, g rbac.Grant) error {
	if _, _, err := s.authorize(p, repo, rbac.ActionManageAccess); err != nil {
		return err
	}
	g.Subject = strings.TrimSpace(g.Subject)
	if err := rbac.ValidateGrant(g); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	before := ""
	err := s.store.UpdateGrants(p.Tenant, repo, func(grants []rbac.Grant) ([]rbac.Grant, error) {
		replaced := false
		for i, existing := range grants {
			if sameSubject(existing, g.SubjectKind, g.Subject) {
				before = existing.Role.String()
				grants[i].Role = g.Role
				replaced = true
			}
		}
		if !replaced {
			grants = append(grants, g)
		}
		return grants, rbac.CheckAdminRemains(grants)
	})
	if err != nil {
		return err
	}
	s.audit(ctx, p, repo, "grant.set", string(g.SubjectKind)+":"+g.Subject, before, g.Role.String())
	return nil
}

func (s *Service) RemoveGrant(ctx context.Context, p identity.Principal, repo string, kind rbac.SubjectKind, subject string) error {
	if _, _, err := s.authorize(p, repo, rbac.ActionManageAccess); err != nil {
		return err
	}
	before := ""
	err := s.store.UpdateGrants(p.Tenant, repo, func(grants []rbac.Grant) ([]rbac.Grant, error) {
		var kept []rbac.Grant
		for _, g := range grants {
			if sameSubject(g, kind, subject) {
				before = g.Role.String()
				continue
			}
			kept = append(kept, g)
		}
		if before == "" {
			return nil, ErrNotFound
		}
		return kept, rbac.CheckAdminRemains(kept)
	})
	if err != nil {
		return err
	}
	s.audit(ctx, p, repo, "grant.remove", string(kind)+":"+subject, before, "")
	return nil
}

// --- Publishing ---

type FileInput struct {
	Filename string
	Content  io.Reader
	Attrs    map[string]string
	// Expected checksums the content must match, e.g. those an upstream
	// registry declared. Required when caching from an upstream.
	Expected Checksums
}

type VersionInput struct {
	Package     string // normalized
	DisplayName string
	Version     string
	Manifest    json.RawMessage
	Files       []FileInput
	// DistTags to point at this version as part of the publish (npm).
	DistTags []string
}

var safeFilenameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func validateVersionInput(in VersionInput) error {
	if in.Package == "" || in.Version == "" || len(in.Files) == 0 {
		return fmt.Errorf("%w: package, version and at least one file are required", ErrInvalid)
	}
	for _, f := range in.Files {
		if !safeFilenameRE.MatchString(f.Filename) || len(f.Filename) > 255 {
			return fmt.Errorf("%w: invalid filename %q", ErrInvalid, f.Filename)
		}
	}
	return nil
}

// storeFiles writes blobs and enforces the tenant's storage quota. On error
// it removes any blobs it wrote that nothing else references.
func (s *Service) storeFiles(ctx context.Context, tenant string, in []FileInput) ([]File, error) {
	var files []File
	var total int64
	for _, fi := range in {
		hashers, err := fi.Expected.hashers()
		if err != nil {
			s.releaseBlobs(ctx, files)
			return nil, err
		}
		content := fi.Content
		for _, h := range hashers {
			content = io.TeeReader(content, h)
		}
		d, n, err := s.blobs.Put(ctx, content)
		if err != nil {
			s.releaseBlobs(ctx, files)
			return nil, err
		}
		files = append(files, File{Filename: fi.Filename, Digest: d, Size: n, Attrs: fi.Attrs})
		total += n
		if !fi.Expected.matches(hashers) {
			s.releaseBlobs(ctx, files)
			return nil, ErrDigestMismatch
		}
	}
	if quota := s.quotas.StorageQuota(tenant); quota > 0 {
		used, err := s.store.StorageUsed(tenant)
		if err != nil {
			s.releaseBlobs(ctx, files)
			return nil, err
		}
		if used+total > quota {
			s.releaseBlobs(ctx, files)
			return nil, ErrQuotaExceeded
		}
	}
	return files, nil
}

// releaseBlobs deletes blobs no unpurged version references. Content is
// deduplicated, so a blob may be shared with other versions or tenants.
func (s *Service) releaseBlobs(ctx context.Context, files []File) {
	for _, f := range files {
		if used, err := s.store.DigestReferenced(f.Digest); err == nil && !used {
			_ = s.blobs.Delete(ctx, f.Digest)
		}
	}
}

func (s *Service) newVersion(p identity.Principal, repo string, in VersionInput, files []File) Version {
	return Version{
		Tenant: p.Tenant, Repo: repo, Package: in.Package, DisplayName: in.DisplayName,
		Version: in.Version, Files: files, Manifest: in.Manifest,
		Publisher: p.Actor(), PublishedAt: s.now(),
		Source: SourcePublished,
	}
}

// Publish creates a complete, immutable version (npm-style).
func (s *Service) Publish(ctx context.Context, p identity.Principal, repo string, in VersionInput) error {
	if err := s.authorizePublish(p, repo); err != nil {
		return err
	}
	if err := validateVersionInput(in); err != nil {
		return err
	}
	existing, err := s.store.Versions(p.Tenant, repo, in.Package)
	if err != nil {
		return err
	}
	for _, v := range existing {
		if v.Version == in.Version {
			return ErrVersionExists
		}
	}
	files, err := s.storeFiles(ctx, p.Tenant, in.Files)
	if err != nil {
		return err
	}
	tags := map[string]string{}
	for _, t := range in.DistTags {
		tags[t] = in.Version
	}
	if err := s.store.CreateVersion(s.newVersion(p, repo, in, files), tags); err != nil {
		s.releaseBlobs(ctx, files)
		return err
	}
	s.audit(ctx, p, repo, "version.publish", in.Package+"@"+in.Version, "", "")
	return nil
}

// AddFile adds a file to a version, creating the version if needed
// (PyPI-style: a release has several files uploaded separately). Extra
// files are siblings stored with the first, e.g. a wheel's .metadata.
func (s *Service) AddFile(ctx context.Context, p identity.Principal, repo string, in VersionInput) error {
	if err := s.authorizePublish(p, repo); err != nil {
		return err
	}
	if err := validateVersionInput(in); err != nil {
		return err
	}
	files, err := s.storeFiles(ctx, p.Tenant, in.Files)
	if err != nil {
		return err
	}
	if err := s.store.AddFiles(s.newVersion(p, repo, in, nil), files); err != nil {
		s.releaseBlobs(ctx, files)
		return err
	}
	s.audit(ctx, p, repo, "version.publish", in.Package+"@"+in.Version+"/"+files[0].Filename, "", "")
	return nil
}

// --- Reading ---

// Versions returns a package's visible (not deleted) versions.
func (s *Service) Versions(_ context.Context, p identity.Principal, repo, pkg string) ([]Version, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionPull); err != nil {
		return nil, err
	}
	all, err := s.store.Versions(p.Tenant, repo, pkg)
	if err != nil {
		return nil, err
	}
	var out []Version
	for _, v := range all {
		if v.Visible() {
			out = append(out, v)
		}
	}
	return out, nil
}

// Packages lists packages with at least one visible version.
func (s *Service) Packages(_ context.Context, p identity.Principal, repo string) ([]string, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionPull); err != nil {
		return nil, err
	}
	all, err := s.store.RepoVersions(p.Tenant, repo)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range all {
		if v.Visible() && !seen[v.Package] {
			seen[v.Package] = true
			out = append(out, v.Package)
		}
	}
	sort.Strings(out)
	return out, nil
}

// OpenFile opens a file of a visible version. Yanked versions stay
// downloadable so pinned installs keep working.
func (s *Service) OpenFile(ctx context.Context, p identity.Principal, repo, pkg, filename string) (io.ReadCloser, File, error) {
	versions, err := s.Versions(ctx, p, repo, pkg)
	if err != nil {
		return nil, File{}, err
	}
	for _, v := range versions {
		for _, f := range v.Files {
			if f.Filename == filename {
				rc, err := s.blobs.Open(ctx, f.Digest)
				if err != nil {
					return nil, File{}, err
				}
				return rc, f, nil
			}
		}
	}
	return nil, File{}, ErrNotFound
}

func (s *Service) StorageUsed(_ context.Context, p identity.Principal) (int64, error) {
	return s.store.StorageUsed(p.Tenant)
}

// --- Dist-tags ---

func (s *Service) DistTags(_ context.Context, p identity.Principal, repo, pkg string) (map[string]string, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionPull); err != nil {
		return nil, err
	}
	return s.store.DistTags(p.Tenant, repo, pkg)
}

func (s *Service) SetDistTag(ctx context.Context, p identity.Principal, repo, pkg, tag, version string) error {
	if _, _, err := s.authorize(p, repo, rbac.ActionYank); err != nil {
		return err
	}
	if tag == "" {
		return fmt.Errorf("%w: tag is required", ErrInvalid)
	}
	versions, err := s.Versions(ctx, p, repo, pkg)
	if err != nil {
		return err
	}
	found := false
	for _, v := range versions {
		found = found || v.Version == version
	}
	if !found {
		return ErrNotFound
	}
	tags, _ := s.store.DistTags(p.Tenant, repo, pkg)
	if err := s.store.SetDistTag(p.Tenant, repo, pkg, tag, version); err != nil {
		return err
	}
	s.audit(ctx, p, repo, "disttag.set", pkg+"#"+tag, tags[tag], version)
	return nil
}

func (s *Service) RemoveDistTag(ctx context.Context, p identity.Principal, repo, pkg, tag string) error {
	if _, _, err := s.authorize(p, repo, rbac.ActionYank); err != nil {
		return err
	}
	tags, _ := s.store.DistTags(p.Tenant, repo, pkg)
	if err := s.store.RemoveDistTag(p.Tenant, repo, pkg, tag); err != nil {
		return err
	}
	s.audit(ctx, p, repo, "disttag.remove", pkg+"#"+tag, tags[tag], "")
	return nil
}

// --- Deletion lifecycle ---

func (s *Service) updateVersion(ctx context.Context, p identity.Principal, repo, pkg, version string, action rbac.Action, auditAction string, fn func(*Version) error) (Version, error) {
	if _, _, err := s.authorize(p, repo, action); err != nil {
		return Version{}, err
	}
	v, err := s.store.UpdateVersion(VersionKey{p.Tenant, repo, pkg, version}, func(v *Version) error {
		if v.PurgedAt != nil {
			return ErrNotFound
		}
		return fn(v)
	})
	if err != nil {
		return Version{}, err
	}
	s.audit(ctx, p, repo, auditAction, pkg+"@"+version, "", "")
	return v, nil
}

func requireVisible(v *Version) error {
	if !v.Visible() {
		return ErrNotFound
	}
	return nil
}

// Yank hides a version from resolution while keeping it downloadable.
func (s *Service) Yank(ctx context.Context, p identity.Principal, repo, pkg, version, reason string) error {
	_, err := s.updateVersion(ctx, p, repo, pkg, version, rbac.ActionYank, "version.yank", func(v *Version) error {
		if err := requireVisible(v); err != nil {
			return err
		}
		v.Yanked, v.YankReason = true, reason
		return nil
	})
	return err
}

func (s *Service) Unyank(ctx context.Context, p identity.Principal, repo, pkg, version string) error {
	_, err := s.updateVersion(ctx, p, repo, pkg, version, rbac.ActionYank, "version.unyank", func(v *Version) error {
		if err := requireVisible(v); err != nil {
			return err
		}
		v.Yanked, v.YankReason = false, ""
		return nil
	})
	return err
}

// Delete soft-deletes a version; it can be restored until purged.
func (s *Service) Delete(ctx context.Context, p identity.Principal, repo, pkg, version string) error {
	_, err := s.updateVersion(ctx, p, repo, pkg, version, rbac.ActionDelete, "version.delete", func(v *Version) error {
		if err := requireVisible(v); err != nil {
			return err
		}
		now := s.now()
		v.DeletedAt = &now
		return nil
	})
	return err
}

func (s *Service) Restore(ctx context.Context, p identity.Principal, repo, pkg, version string) error {
	_, err := s.updateVersion(ctx, p, repo, pkg, version, rbac.ActionDelete, "version.restore", func(v *Version) error {
		if v.DeletedAt == nil {
			return fmt.Errorf("%w: version is not deleted", ErrInvalid)
		}
		v.DeletedAt = nil
		return nil
	})
	return err
}

// Purge permanently removes a version's files. confirm must be
// "package@version". The version number stays reserved.
func (s *Service) Purge(ctx context.Context, p identity.Principal, repo, pkg, version, confirm string) error {
	if confirm != pkg+"@"+version {
		return ErrConfirmationMismatch
	}
	v, err := s.updateVersion(ctx, p, repo, pkg, version, rbac.ActionDelete, "version.purge", func(v *Version) error {
		now := s.now()
		if v.DeletedAt == nil {
			v.DeletedAt = &now
		}
		v.PurgedAt = &now
		return nil
	})
	if err != nil {
		return err
	}
	s.releaseBlobs(ctx, v.Files)
	return nil
}

// Trash lists soft-deleted versions that can still be restored.
func (s *Service) Trash(_ context.Context, p identity.Principal, repo string) ([]Version, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionDelete); err != nil {
		return nil, err
	}
	all, err := s.store.RepoVersions(p.Tenant, repo)
	if err != nil {
		return nil, err
	}
	var out []Version
	for _, v := range all {
		if v.InTrash() {
			out = append(out, v)
		}
	}
	return out, nil
}

// PurgeExpired purges versions deleted longer ago than their repo's grace
// period. Run periodically by the server.
func (s *Service) PurgeExpired(ctx context.Context) (int, error) {
	trashed, err := s.store.TrashedVersions()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range trashed {
		repo, err := s.store.GetRepo(v.Tenant, v.Repo)
		if err != nil || s.now().Sub(*v.DeletedAt) < repo.DeleteGrace {
			continue
		}
		purged, err := s.store.UpdateVersion(v.Key(), func(v *Version) error {
			if !v.InTrash() {
				return ErrNotFound
			}
			now := s.now()
			v.PurgedAt = &now
			return nil
		})
		if err != nil {
			continue
		}
		s.releaseBlobs(ctx, purged.Files)
		sys := systemPrincipal
		sys.Tenant = v.Tenant
		s.audit(ctx, sys, v.Repo, "version.purge", v.Package+"@"+v.Version, "", "")
		n++
	}
	return n, nil
}

func (s *Service) Audit(_ context.Context, p identity.Principal, repo string, limit int) ([]AuditEntry, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionViewAudit); err != nil {
		return nil, err
	}
	return s.store.Audit(p.Tenant, repo, limit)
}
