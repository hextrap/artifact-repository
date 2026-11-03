//go:build !cloud

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelfHostedCannotRunMultiTenant(t *testing.T) {
	clearEnv(t)
	db := "database_url: postgresql://artifacts@db.internal:5432/hextrap_artifacts\n"
	withClaim := strings.Replace(withOIDC, "client_id: hextrap", "client_id: hextrap\n  tenant_claim: org", 1)

	for _, tc := range []struct{ name, cfg, key string }{
		{"tenant domain", minimal + db + "tenant_domain: repo.example.com\n", "tenant_domain"},
		{"tenant claim", withClaim, "oidc.tenant_claim"},
		{"full cloud config", withClaim + db + "tenant_domain: repo.example.com\n", "tenant_domain"},
	} {
		_, err := Load(write(t, tc.cfg))
		require.ErrorContains(t, err, "only available in hextrap cloud", tc.name)
		require.ErrorContains(t, err, tc.key, tc.name)
	}
}
