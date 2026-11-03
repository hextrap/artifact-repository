package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/localauth"
	"hextrap.io/artifacts/internal/ratelimit"
)

var testHash = func() string {
	h, err := localauth.HashPassword("pw")
	if err != nil {
		panic(err)
	}
	return h
}()

// minimal is the smallest self-hosted config: one admin user and storage.
var minimal = fmt.Sprintf(`
users:
  - username: alice
    password_hash: %q
admins: [alice]
storage:
  filesystem: /tmp/hextrap-test-blobs
`, testHash)

// withOIDC replaces the users with an identity provider.
const withOIDC = `
public_url: https://repo.example.com
oidc:
  issuer: https://idp.example.com
  client_id: hextrap
  admin_groups: [hextrap-admins]
storage:
  s3:
    bucket: hextrap-artifacts
    region: us-east-1
`

func write(t *testing.T, content string) string {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"HEXTRAP_OIDC_CLIENT_SECRET", "HEXTRAP_OIDC_COOKIE_SECRET", "HEXTRAP_DATABASE_URL", "HEXTRAP_FIREWALL_PASSWORD"} {
		t.Setenv(k, "")
	}
}

func TestMinimalConfig(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	cfg, err := Load(write(t, minimal))
	r.NoError(err)
	r.Equal(":8080", cfg.Listen)
	r.Equal("default", cfg.Tenant)
	r.Equal("/var/lib/hextrap-artifacts", cfg.DataDir)
	r.Empty(cfg.PublicURL, "optional: links are built from the request host")
	r.Nil(cfg.OIDC)
	r.Equal("/tmp/hextrap-test-blobs", cfg.Storage.Filesystem)
	r.False(cfg.RateLimit.Enabled)
	r.Equal(ratelimit.DefaultCosts(), cfg.RateLimit.Costs)
	r.Equal(identity.InstanceAdmins{Users: []string{"alice"}}, cfg.InstanceAdmins())
}

func TestOIDCConfig(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	cfg, err := Load(write(t, withOIDC))
	r.NoError(err)
	r.NotNil(cfg.OIDC)
	r.Equal("https://repo.example.com/auth/callback", cfg.OIDC.RedirectURL)
	r.Len(cfg.OIDC.CookieSecret, 64, "generated when unset on a single server")
	r.Equal(identity.InstanceAdmins{Groups: []string{"hextrap-admins"}}, cfg.InstanceAdmins())
	r.Equal("hextrap-artifacts", cfg.Storage.S3.Bucket)

	again, err := Load(write(t, withOIDC))
	r.NoError(err)
	r.NotEqual(cfg.OIDC.CookieSecret, again.OIDC.CookieSecret, "random")
}

func TestSecretsFromEnvironment(t *testing.T) {
	t.Setenv("HEXTRAP_OIDC_CLIENT_SECRET", "from-env")
	t.Setenv("HEXTRAP_OIDC_COOKIE_SECRET", strings.Repeat("e", 32))
	t.Setenv("HEXTRAP_DATABASE_URL", "postgresql://from-env/hextrap")
	cfg, err := Load(write(t, withOIDC))
	require.NoError(t, err)
	require.Equal(t, "from-env", cfg.OIDC.ClientSecret)
	require.Equal(t, strings.Repeat("e", 32), cfg.OIDC.CookieSecret)
	require.Equal(t, "postgresql://from-env/hextrap", cfg.DatabaseURL)
}

func TestValidation(t *testing.T) {
	clearEnv(t)
	noUsers := strings.Replace(minimal, "users:\n  - username: alice\n    password_hash: "+fmt.Sprintf("%q", testHash)+"\nadmins: [alice]\n", "", 1)
	require.NotEqual(t, minimal, noUsers)
	for _, tc := range []struct{ name, cfg, want string }{
		{"no sign-in configured", noUsers, "users"},
		{"both users and oidc", minimal + strings.Replace(withOIDC, "storage:\n  s3:\n    bucket: hextrap-artifacts\n    region: us-east-1\n", "", 1), "not both"},
		{"admin must be a user", strings.Replace(minimal, "admins: [alice]", "admins: [bob]", 1), `"bob"`},
		{"at least one admin", strings.Replace(minimal, "admins: [alice]", "admins: []", 1), "admins"},
		{"plaintext password", strings.Replace(minimal, fmt.Sprintf("%q", testHash), "hunter2", 1), "hash-password"},
		{"uppercase username", strings.Replace(minimal, "alice", "Alice", 1), "lowercase"},
		{"oidc admins elsewhere", strings.Replace(withOIDC, "  admin_groups: [hextrap-admins]\n", "", 1) + "admins: [alice]\n", "admin_groups"},
		{"oidc needs an admin", strings.Replace(withOIDC, "  admin_groups: [hextrap-admins]\n", "", 1), "admin_groups"},
		{"oidc needs public_url", strings.Replace(withOIDC, "public_url: https://repo.example.com\n", "", 1), "public_url"},
		{"public_url is a URL", minimal + "public_url: repo.example.com\n", "public_url"},
		{"storage required", strings.Replace(minimal, "storage:\n  filesystem: /tmp/hextrap-test-blobs\n", "", 1), "storage"},
		{"one storage only", minimal + "  s3:\n    bucket: b\n    region: r\n", "storage"},
		{"s3 validated", strings.Replace(withOIDC, "    bucket: hextrap-artifacts\n", "", 1), "s3.bucket"},
		{"unknown field", minimal + "adminz: [alice]\n", "adminz"},
		{"database url", minimal + "database_url: mysql://db/x\n", "database_url"},
		{"database password encoding", minimal + "database_url: postgresql://u:p#ss@db:5432/x\n", "URL-encode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, tc.cfg))
			require.ErrorContains(t, err, tc.want)
			require.NotContains(t, err.Error(), "p#ss", "never echo a password")
		})
	}
}

func TestOIDCCookieSecretRequiredWithDatabase(t *testing.T) {
	clearEnv(t)
	cfg := withOIDC + "database_url: postgresql://db/x\n"
	_, err := Load(write(t, cfg))
	require.ErrorContains(t, err, "cookie_secret", "replicas must share it, so it can't be generated")

	t.Setenv("HEXTRAP_OIDC_COOKIE_SECRET", "short")
	_, err = Load(write(t, cfg))
	require.ErrorContains(t, err, "32")
}

func TestPartialRateLimitKeepsDefaults(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	cfg, err := Load(write(t, minimal+"rate_limit:\n  enabled: true\n  tenant: {rate: 100, burst: 5000}\n"))
	r.NoError(err)
	r.True(cfg.RateLimit.Enabled)
	r.Equal(ratelimit.Limit{Rate: 100, Burst: 5000}, cfg.RateLimit.Tenant)
	r.Equal(0.5, cfg.RateLimit.PrincipalShare)
}

func TestMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	require.Error(t, err)
}

func TestUpstreams(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	cfg, err := Load(write(t, minimal))
	r.NoError(err)
	r.Equal([]string{"https://pypi.org"}, cfg.Upstreams.PyPI, "PyPI proxying works out of the box")
	r.Equal([]string{"https://registry.npmjs.org"}, cfg.Upstreams.NPM, "npm too")
	r.Equal([]string{"https://repo.maven.apache.org/maven2"}, cfg.Upstreams.Maven, "and Maven Central")
	r.Equal([]string{"https://index.crates.io"}, cfg.Upstreams.Cargo, "and crates.io")
	r.Equal([]string{"https://proxy.golang.org"}, cfg.Upstreams.Go, "and the Go module proxy")
	r.Equal([]string{"https://registry-1.docker.io"}, cfg.Upstreams.OCI, "and Docker Hub")
	r.Equal("https://sum.golang.org", cfg.Upstreams.GoChecksumDB, "Go modules are verified by default")

	cfg, err = Load(write(t, minimal+"upstreams:\n  pypi: [\"https://mirror.internal/pypi/\", \"https://pypi.org\"]\n"))
	r.NoError(err)
	r.Equal([]string{"https://mirror.internal/pypi", "https://pypi.org"}, cfg.Upstreams.PyPI)

	cfg, err = Load(write(t, minimal+"upstreams:\n  pypi: []\n"))
	r.NoError(err)
	r.Empty(cfg.Upstreams.PyPI, "an empty list disables proxy repos")

	_, err = Load(write(t, minimal+"upstreams:\n  pypi: [\"pypi.org\"]\n"))
	r.ErrorContains(err, "upstreams.pypi")
	_, err = Load(write(t, minimal+"upstreams:\n  pypi: [\"https://pypi.org/?x=1\"]\n"))
	r.ErrorContains(err, "upstreams.pypi")
}

func TestUpstreamsValidatedForEveryFormat(t *testing.T) {
	clearEnv(t)
	_, err := Load(write(t, minimal+"upstreams:\n  npm: [\"registry.npmjs.org\"]\n"))
	require.ErrorContains(t, err, "upstreams.npm")
}

func TestGoChecksumDB(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	cfg, err := Load(write(t, minimal+"upstreams:\n  go: [\"https://athens.internal\"]\n  go_checksum_db: \"\"\n"))
	r.NoError(err)
	r.Equal([]string{"https://athens.internal"}, cfg.Upstreams.Go)
	r.Empty(cfg.Upstreams.GoChecksumDB, "empty disables verification, for private modules")
	_, err = Load(write(t, minimal+"upstreams:\n  go_checksum_db: \"sum.golang.org\"\n"))
	r.ErrorContains(err, "upstreams.go_checksum_db")
	_, ok := (&UpstreamsConfig{}).ByFormat()["go_checksum_db"]
	r.False(ok, "not an upstream list")
}
