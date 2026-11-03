package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
)

// Formats are the package formats repositories can hold.
var Formats = []Format{FormatNPM, FormatPyPI, FormatMaven, FormatCargo, FormatGo, FormatOCI}

// proxyFormats are the formats with an upstream proxy implementation.
var proxyFormats = []Format{FormatPyPI, FormatNPM, FormatMaven, FormatCargo, FormatGo, FormatOCI}

// proxyOnlyFormats have no publish protocol, so only proxy repos make sense.
var proxyOnlyFormats = []Format{FormatGo}

// repoUpstream validates a new repo's type and upstream and returns the
// upstream to store.
func (s *Service) repoUpstream(in RepoInput) (string, error) {
	upstream := strings.TrimSuffix(in.Upstream, "/")
	switch in.Type {
	case "", TypeHosted:
		if slices.Contains(proxyOnlyFormats, in.Format) {
			return "", fmt.Errorf("%w: %s repositories can only be proxies: there is no publish command", ErrInvalid, in.Format)
		}
		if upstream != "" {
			return "", fmt.Errorf("%w: hosted repositories have no upstream", ErrInvalid)
		}
		return "", nil
	case TypeProxy:
	default:
		return "", fmt.Errorf("%w: repository type must be %q or %q", ErrInvalid, TypeHosted, TypeProxy)
	}
	if !slices.Contains(proxyFormats, in.Format) {
		return "", fmt.Errorf("%w: %s proxy repositories aren't supported yet", ErrInvalid, in.Format)
	}
	return s.proxyUpstream(in.Format, upstream)
}

// proxyUpstream checks a proxy repo's upstream against the configured ones
// (the default when empty) and returns it.
func (s *Service) proxyUpstream(format Format, upstream string) (string, error) {
	allowed := s.upstreams[format]
	if s.requireFirewall {
		allowed = slices.DeleteFunc(slices.Clone(allowed), func(u string) bool { return !s.firewalls[u] })
		if len(allowed) == 0 {
			return "", fmt.Errorf("%w: %s proxy repositories need a hextrap firewall, and none is available for %s", ErrInvalid, format, format)
		}
	}
	if len(allowed) == 0 {
		return "", fmt.Errorf("%w: no %s upstreams are configured", ErrInvalid, format)
	}
	if upstream == "" {
		return allowed[0], nil
	}
	if !slices.Contains(allowed, upstream) {
		return "", fmt.Errorf("%w: upstream must be one of %s", ErrInvalid, strings.Join(allowed, ", "))
	}
	return upstream, nil
}

// authorizePublish checks p may publish to a hosted repo.
func (s *Service) authorizePublish(p identity.Principal, repo string) error {
	r, _, err := s.authorize(p, repo, rbac.ActionPublish)
	if err != nil {
		return err
	}
	if r.Type == TypeProxy {
		return ErrReadOnly
	}
	return nil
}

// CacheFile stores files fetched from a proxy repo's upstream. Anyone who
// can pull from the repo can fill its cache. Each file's hash must match
// what the upstream declared. Caching a file that's already cached
// succeeds, so concurrent requests can race safely.
func (s *Service) CacheFile(ctx context.Context, p identity.Principal, repo, origin string, in VersionInput) error {
	r, _, err := s.authorize(p, repo, rbac.ActionPull)
	if err != nil {
		return err
	}
	if r.Type != TypeProxy {
		return fmt.Errorf("%w: only proxy repositories cache from upstream", ErrInvalid)
	}
	if err := validateVersionInput(in); err != nil {
		return err
	}
	for _, f := range in.Files {
		if len(f.Expected) == 0 {
			return fmt.Errorf("%w: cached files need a checksum from the upstream", ErrInvalid)
		}
	}
	files, err := s.storeFiles(ctx, p.Tenant, in.Files)
	if err != nil {
		return err
	}
	v := s.newVersion(p, repo, in, nil)
	v.Source, v.Origin, v.Publisher = SourceUpstream, origin, "upstream:"+origin
	if err := s.store.AddFiles(v, files); err != nil {
		s.releaseBlobs(ctx, files)
		if errors.Is(err, ErrFileExists) {
			return nil
		}
		return err
	}
	s.audit(ctx, p, repo, "version.cache", in.Package+"@"+in.Version+"/"+files[0].Filename, "", origin)
	return nil
}

// PackageSummaries describes each package with visible versions.
func (s *Service) PackageSummaries(_ context.Context, p identity.Principal, repo string) ([]PackageSummary, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionPull); err != nil {
		return nil, err
	}
	all, err := s.store.RepoVersions(p.Tenant, repo)
	if err != nil {
		return nil, err
	}
	byName := map[string]*PackageSummary{}
	var names []string
	for _, v := range all { // insertion order, so the last seen is the latest
		if !v.Visible() {
			continue
		}
		sum, ok := byName[v.Package]
		if !ok {
			sum = &PackageSummary{Name: v.Package, Source: v.Source}
			byName[v.Package] = sum
			names = append(names, v.Package)
		}
		sum.Versions++
		sum.DisplayName, sum.Latest = v.DisplayName, v.Version
		sum.Size += v.Size()
		if v.PublishedAt.After(sum.Updated) {
			sum.Updated = v.PublishedAt
		}
		if sum.Source != v.Source {
			sum.Source = "mixed"
		}
		if v.Origin != "" {
			sum.Origin = v.Origin
		}
	}
	sort.Strings(names)
	out := make([]PackageSummary, 0, len(names))
	for _, n := range names {
		out = append(out, *byName[n])
	}
	return out, nil
}

// RemovedVersions lists a package's deleted or purged versions, which a
// proxy must not fetch from upstream again.
func (s *Service) RemovedVersions(_ context.Context, p identity.Principal, repo, pkg string) (map[string]bool, error) {
	if _, _, err := s.authorize(p, repo, rbac.ActionPull); err != nil {
		return nil, err
	}
	all, err := s.store.Versions(p.Tenant, repo, pkg)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range all {
		if !v.Visible() {
			out[v.Version] = true
		}
	}
	return out, nil
}
