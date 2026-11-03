package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const pypiFirewall = "https://pypi.hextrap.com"

func TestFirewallIsTheDefaultUpstream(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.svc.AllowUpstreams(FormatPyPI, pypiOrg)
	f.svc.AllowFirewall(FormatPyPI, pypiFirewall+"/")

	r.Equal([]string{pypiFirewall, pypiOrg}, f.svc.Upstreams()[FormatPyPI])
	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "py", Format: FormatPyPI, Type: TypeProxy}))
	repo, err := f.svc.Repo(ctx, alice, "py")
	r.NoError(err)
	r.Equal(pypiFirewall, repo.Upstream)
	r.True(repo.Firewall)

	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "open", Format: FormatPyPI, Type: TypeProxy, Upstream: pypiOrg}))
	repos, err := f.svc.ListRepos(ctx, alice)
	r.NoError(err)
	r.Len(repos, 2)
	for _, rv := range repos {
		r.Equal(rv.Name == "py", rv.Firewall, rv.Name)
	}
}

func TestConnectExistingProxyToFirewall(t *testing.T) {
	r := require.New(t)
	f := proxyFixture(t) // pypi-proxy on pypi.org; bob is a reader
	f.svc.AllowFirewall(FormatPyPI, pypiFirewall)
	firewall, public := pypiFirewall, pypiOrg

	r.ErrorIs(f.svc.UpdateSettings(ctx, bob, "pypi-proxy", SettingsInput{Upstream: &firewall}), ErrForbidden)
	r.NoError(f.svc.UpdateSettings(ctx, alice, "pypi-proxy", SettingsInput{Upstream: &firewall}))
	repo, _ := f.svc.Repo(ctx, alice, "pypi-proxy")
	r.Equal(pypiFirewall, repo.Upstream)
	r.True(repo.Firewall)

	entries, err := f.svc.Audit(ctx, alice, "pypi-proxy", 10)
	r.NoError(err)
	r.Contains(entries[0].After, "upstream="+pypiFirewall)

	r.NoError(f.svc.UpdateSettings(ctx, alice, "pypi-proxy", SettingsInput{Upstream: &public}), "self-hosted may disconnect")
	evil := "http://169.254.169.254"
	r.ErrorIs(f.svc.UpdateSettings(ctx, alice, "pypi-proxy", SettingsInput{Upstream: &evil}), ErrInvalid)

	f.repo(t, "hosted", FormatPyPI)
	r.ErrorIs(f.svc.UpdateSettings(ctx, alice, "hosted", SettingsInput{Upstream: &firewall}), ErrInvalid, "hosted repos have no upstream")
}

func TestRequireFirewall(t *testing.T) {
	r := require.New(t)
	f := newFixture(t)
	f.svc.RequireFirewall()
	f.svc.AllowUpstreams(FormatPyPI, pypiOrg)
	f.svc.AllowUpstreams(FormatMaven, "https://repo.maven.apache.org/maven2")

	r.ErrorIs(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "py", Format: FormatPyPI, Type: TypeProxy}), ErrInvalid, "no firewall configured")
	f.svc.AllowFirewall(FormatPyPI, pypiFirewall)
	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "py", Format: FormatPyPI, Type: TypeProxy}))
	r.ErrorIs(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "open", Format: FormatPyPI, Type: TypeProxy, Upstream: pypiOrg}), ErrInvalid)
	err := f.svc.CreateRepo(ctx, alice, RepoInput{Name: "mvn", Format: FormatMaven, Type: TypeProxy})
	r.ErrorIs(err, ErrInvalid)
	r.ErrorContains(err, "firewall")

	public := pypiOrg
	r.ErrorIs(f.svc.UpdateSettings(ctx, alice, "py", SettingsInput{Upstream: &public}), ErrInvalid, "can't disconnect")
	r.NoError(f.svc.CreateRepo(ctx, alice, RepoInput{Name: "hosted", Format: FormatPyPI}), "hosted repos need no firewall")
}
