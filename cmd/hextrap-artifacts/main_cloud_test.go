//go:build cloud

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
)

func TestCloudBuildResolvesTenantFromSubdomain(t *testing.T) {
	r := require.New(t)
	cfg := testConfig(t, t.TempDir())
	cfg.Tenant, cfg.TenantDomain, cfg.OIDC.TenantClaim = "", "repo.test", "org"
	app, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	r.NoError(err)

	for host, want := range map[string]int{"acme.repo.test": http.StatusFound, "repo.test": http.StatusNotFound} {
		req := httptest.NewRequest("GET", "/auth/login", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		app.handler.ServeHTTP(rec, req)
		r.Equal(want, rec.Code, host)
	}
}

func TestCloudProxiesRequireAFirewall(t *testing.T) {
	r := require.New(t)
	cfg := testConfig(t, t.TempDir())
	cfg.Upstreams.PyPI = []string{"https://pypi.org"}
	app, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	r.NoError(err)
	admin := identity.Principal{Tenant: "default", Kind: identity.KindUser, Subject: "admin"}
	err = app.registry.CreateRepo(context.Background(), admin, registry.RepoInput{Name: "pypi", Format: registry.FormatPyPI, Type: registry.TypeProxy})
	r.ErrorIs(err, registry.ErrInvalid, "nothing is cached unchecked in the cloud")
}
