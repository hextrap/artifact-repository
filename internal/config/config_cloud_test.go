//go:build cloud

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const cloudDB = "database_url: postgresql://artifacts@rds.internal:5432/hextrap_artifacts\n"

func cloudConfig(t *testing.T) string {
	clearEnv(t)
	t.Setenv("HEXTRAP_OIDC_COOKIE_SECRET", strings.Repeat("c", 32))
	return strings.Replace(withOIDC, "client_id: hextrap", "client_id: hextrap\n  tenant_claim: org", 1) + cloudDB
}

func TestCloudMode(t *testing.T) {
	r := require.New(t)
	cloud := cloudConfig(t)
	cfg, err := Load(write(t, cloud+"tenant_domain: repo.hextrap.com\n"))
	r.NoError(err)
	r.True(cfg.MultiTenant())

	noDB := strings.Replace(cloud, cloudDB, "", 1)
	_, err = Load(write(t, noDB+"tenant_domain: repo.hextrap.com\n"))
	r.ErrorContains(err, "database_url", "cloud mode runs several replicas, so file snapshots won't do")
	_, err = Load(write(t, cloud+"tenant_domain: repo.hextrap.com\ntenant: acme\n"))
	r.ErrorContains(err, "tenant")
	_, err = Load(write(t, withOIDC+cloudDB+"tenant_domain: repo.hextrap.com\n"))
	r.ErrorContains(err, "oidc.tenant_claim", "logins need a tenant in cloud mode")
}

func TestCloudRequiresS3(t *testing.T) {
	cloud := strings.Replace(cloudConfig(t), "storage:\n  s3:\n    bucket: hextrap-artifacts\n    region: us-east-1\n", "storage:\n  filesystem: /tmp/x\n", 1)
	_, err := Load(write(t, cloud+"tenant_domain: repo.hextrap.com\n"))
	require.ErrorContains(t, err, "s3", "cloud mode always uses S3")
}

func TestCloudRequiresOIDC(t *testing.T) {
	clearEnv(t)
	_, err := Load(write(t, minimal+cloudDB+"tenant_domain: repo.hextrap.com\n"))
	require.ErrorContains(t, err, "oidc", "cloud users sign in through hextrap.com")
}

func TestCloudBuildStillRunsSingleTenant(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(write(t, minimal))
	require.NoError(t, err)
	require.False(t, cfg.MultiTenant())
}
