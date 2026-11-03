package config

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/ratelimit"
)

// The examples must stay loadable: unknown keys fail Load, so a renamed or
// removed setting breaks these tests.

const hashPlaceholder = `"PASTE THE OUTPUT OF: hextrap-artifacts hash-password"`

func TestSimpleExample(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	b, err := os.ReadFile("../../config.example.yaml")
	r.NoError(err)

	// As shipped it has no usable password, so nobody runs with a default one.
	_, err = Load(write(t, string(b)))
	r.ErrorContains(err, "hash-password")

	r.Contains(string(b), hashPlaceholder)
	cfg, err := Load(write(t, strings.Replace(string(b), hashPlaceholder, fmt.Sprintf("%q", testHash), 1)))
	r.NoError(err)
	r.Len(cfg.Users, 1)
	r.Equal([]string{cfg.Users[0].Username}, cfg.Admins)
	r.NotEmpty(cfg.Storage.Filesystem)

	lines := 0
	for _, l := range strings.Split(string(b), "\n") {
		if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "#") {
			lines++
		}
	}
	r.LessOrEqual(lines, 8, "the simple example stays simple")
}

func TestFullExample(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	t.Setenv("HEXTRAP_OIDC_CLIENT_SECRET", "example-secret")
	cfg, err := Load("../../config.full.example.yaml")
	r.NoError(err)
	r.False(cfg.MultiTenant(), "self-hosted")
	r.NotNil(cfg.OIDC)
	r.NotNil(cfg.Storage.S3)
	r.NotEmpty(cfg.PublicURL)
	r.Equal(ratelimit.DefaultConfig(), cfg.RateLimit, "the example documents the defaults, so it shouldn't change them")
}
