package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoFirewallByDefault(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(write(t, minimal))
	require.NoError(t, err)
	require.Nil(t, cfg.HextrapFirewall)
}

func TestFirewallDefaults(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	t.Setenv("HEXTRAP_FIREWALL_PASSWORD", "from-env")
	cfg, err := Load(write(t, minimal+"hextrap_firewall:\n  username: acme-ci\n"))
	r.NoError(err)
	fw := cfg.HextrapFirewall
	r.Equal("acme-ci", fw.Username)
	r.Equal("from-env", fw.Password)
	r.Equal(map[string]string{
		"pypi":  "https://pypi.hextrap.com",
		"npm":   "https://npm.hextrap.com",
		"go":    "https://go.hextrap.com",
		"cargo": "https://cargo.hextrap.com",
	}, fw.URLs)
}

func TestFirewallURLOverrides(t *testing.T) {
	r := require.New(t)
	clearEnv(t)
	cfg, err := Load(write(t, minimal+"hextrap_firewall:\n  username: u\n  password: p\n  urls:\n    pypi: https://pypi.staging.hextrap.com/\n"))
	r.NoError(err)
	r.Equal("https://pypi.staging.hextrap.com", cfg.HextrapFirewall.URLs["pypi"])
	r.Equal("https://npm.hextrap.com", cfg.HextrapFirewall.URLs["npm"], "others keep their defaults")
}

func TestFirewallValidation(t *testing.T) {
	clearEnv(t)
	for name, tc := range map[string]struct{ yaml, want string }{
		"no username":    {"hextrap_firewall:\n  password: p\n", "hextrap_firewall.username"},
		"no password":    {"hextrap_firewall:\n  username: u\n", "HEXTRAP_FIREWALL_PASSWORD"},
		"unknown format": {"hextrap_firewall:\n  username: u\n  password: p\n  urls:\n    maven: https://x\n", "hextrap_firewall.urls.maven"},
		"bad url":        {"hextrap_firewall:\n  username: u\n  password: p\n  urls:\n    npm: npm.hextrap.com\n", "hextrap_firewall.urls.npm"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, minimal+tc.yaml))
			require.ErrorContains(t, err, tc.want)
		})
	}
}
