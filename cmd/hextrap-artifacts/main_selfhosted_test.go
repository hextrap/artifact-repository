//go:build !cloud

package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSelfHostedBuildRefusesMultiTenant(t *testing.T) {
	cfg := testConfig(t, t.TempDir())
	cfg.Tenant, cfg.TenantDomain = "", "repo.example.com"
	_, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	require.ErrorContains(t, err, "only available in hextrap cloud")
}
