// Package config loads the artifact repository's YAML config file.
//
// A self-hosted install needs only sign-in (a users list with admins, or an
// identity provider) and storage; everything else has defaults.
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/edition"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/localauth"
	"hextrap.io/artifacts/internal/oidc"
	"hextrap.io/artifacts/internal/ratelimit"
)

type Config struct {
	// PublicURL is the externally visible URL. Optional: without it, links
	// are built from each request's host. Required with OIDC.
	PublicURL string `yaml:"public_url"`
	Listen    string `yaml:"listen"`
	DataDir   string `yaml:"data_dir"`
	TLSCert   string `yaml:"tls_cert"`
	TLSKey    string `yaml:"tls_key"`

	// Sign-in: either Users (with Admins) or OIDC.
	Users  []localauth.User `yaml:"users"`
	Admins []string         `yaml:"admins"`
	OIDC   *OIDCConfig      `yaml:"oidc"`

	Storage StorageConfig `yaml:"storage"`

	// Upstreams are the registries proxy repositories may cache from. Only
	// the operator sets these, so repository creators can't point the server
	// at arbitrary (e.g. internal) addresses.
	Upstreams UpstreamsConfig `yaml:"upstreams"`

	// HextrapFirewall connects proxy repositories to a hextrap firewall,
	// which applies policy to every download. Without it, proxies cache from
	// the public registries unchecked.
	HextrapFirewall *FirewallConfig `yaml:"hextrap_firewall"`

	// DatabaseURL selects Postgres for metadata, tokens and sessions; empty
	// uses files under DataDir (single server only).
	DatabaseURL string `yaml:"database_url"`

	// Tenant names the single tenant of a self-hosted install.
	Tenant string `yaml:"tenant"`
	// TenantDomain enables multi-tenant mode (cloud edition only): tenants
	// are subdomains of it.
	TenantDomain      string           `yaml:"tenant_domain"`
	RateLimit         ratelimit.Config `yaml:"rate_limit"`
	StorageQuotaBytes int64            `yaml:"storage_quota_bytes"`
	// TrustProxyHeaders takes the client IP and scheme from X-Forwarded-*
	// headers; enable only behind a load balancer that sets them.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`
}

type OIDCConfig struct {
	oidc.Config `yaml:",inline"`
	// Instance admins, by IdP group or verified email.
	AdminGroups []string `yaml:"admin_groups"`
	AdminEmails []string `yaml:"admin_emails"`
}

type UpstreamsConfig struct {
	PyPI  []string `yaml:"pypi"`
	NPM   []string `yaml:"npm"`
	Maven []string `yaml:"maven"`
	Cargo []string `yaml:"cargo"`
	Go    []string `yaml:"go"`
	OCI   []string `yaml:"oci"`
	// GoChecksumDB verifies Go modules before they're cached. Empty disables
	// it, for upstreams serving private modules.
	GoChecksumDB string `yaml:"go_checksum_db"`
}

// FirewallConfig is a hextrap firewall credential. The same credential works
// for each format's firewall host.
type FirewallConfig struct {
	Username string `yaml:"username"`
	// Password can come from HEXTRAP_FIREWALL_PASSWORD instead.
	Password string `yaml:"password"`
	// URLs overrides the firewall host per format.
	URLs map[string]string `yaml:"urls"`
}

// DefaultFirewallURLs are hextrap's firewall hosts, by format.
var DefaultFirewallURLs = map[string]string{
	"pypi":  "https://pypi.hextrap.com",
	"npm":   "https://npm.hextrap.com",
	"go":    "https://go.hextrap.com",
	"cargo": "https://cargo.hextrap.com",
}

// ByFormat returns the lists keyed by format name.
func (u *UpstreamsConfig) ByFormat() map[string]*[]string {
	return map[string]*[]string{"pypi": &u.PyPI, "npm": &u.NPM, "maven": &u.Maven, "cargo": &u.Cargo, "go": &u.Go, "oci": &u.OCI}
}

// StorageConfig holds exactly one of S3 or Filesystem.
type StorageConfig struct {
	S3 *blob.S3Config `yaml:"s3"`
	// Filesystem is a directory, for testing only. Not allowed in cloud mode.
	Filesystem string `yaml:"filesystem"`
}

func (c Config) MultiTenant() bool { return c.TenantDomain != "" }

// InstanceAdmins are the users with Admin on every repository.
func (c Config) InstanceAdmins() identity.InstanceAdmins {
	if c.OIDC != nil {
		return identity.InstanceAdmins{Groups: c.OIDC.AdminGroups, Emails: c.OIDC.AdminEmails}
	}
	return identity.InstanceAdmins{Users: c.Admins}
}

// Load reads and validates a config file. Secrets can be supplied with
// HEXTRAP_OIDC_CLIENT_SECRET, HEXTRAP_OIDC_COOKIE_SECRET and
// HEXTRAP_DATABASE_URL instead.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Listen: ":8080", DataDir: "/var/lib/hextrap-artifacts", RateLimit: ratelimit.DefaultConfig(),
		Upstreams: UpstreamsConfig{
			PyPI:         []string{"https://pypi.org"},
			NPM:          []string{"https://registry.npmjs.org"},
			Maven:        []string{"https://repo.maven.apache.org/maven2"},
			Cargo:        []string{"https://index.crates.io"},
			Go:           []string{"https://proxy.golang.org"},
			OCI:          []string{"https://registry-1.docker.io"},
			GoChecksumDB: "https://sum.golang.org",
		},
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if v := os.Getenv("HEXTRAP_DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if fw := cfg.HextrapFirewall; fw != nil {
		if v := os.Getenv("HEXTRAP_FIREWALL_PASSWORD"); v != "" {
			fw.Password = v
		}
	}
	if cfg.OIDC != nil {
		if v := os.Getenv("HEXTRAP_OIDC_CLIENT_SECRET"); v != "" {
			cfg.OIDC.ClientSecret = v
		}
		if v := os.Getenv("HEXTRAP_OIDC_COOKIE_SECRET"); v != "" {
			cfg.OIDC.CookieSecret = v
		}
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}

	if !cfg.MultiTenant() && cfg.Tenant == "" {
		cfg.Tenant = "default"
	}
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	if fw := cfg.HextrapFirewall; fw != nil {
		urls := map[string]string{}
		for format, u := range DefaultFirewallURLs {
			urls[format] = u
		}
		for format, u := range fw.URLs {
			urls[format] = strings.TrimSuffix(u, "/")
		}
		fw.URLs = urls
	}
	for _, list := range cfg.Upstreams.ByFormat() {
		for i, u := range *list {
			(*list)[i] = strings.TrimSuffix(u, "/")
		}
	}
	if o := cfg.OIDC; o != nil {
		if o.RedirectURL == "" {
			o.RedirectURL = cfg.PublicURL + "/auth/callback"
		}
		// A single server can make up its own secret; validate() requires
		// one when there's a database, since replicas must share it.
		if o.CookieSecret == "" {
			s := make([]byte, 32)
			if _, err := rand.Read(s); err != nil {
				return Config{}, err
			}
			o.CookieSecret = hex.EncodeToString(s)
		}
	}
	return cfg, nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (c Config) validate() error {
	var errs []error
	if c.PublicURL != "" && !isHTTPURL(c.PublicURL) {
		errs = append(errs, errors.New("public_url must be an http(s) URL"))
	}
	errs = append(errs, c.validateSignIn()...)
	errs = append(errs, c.validateStorage()...)
	upstreams := c.Upstreams
	for format, list := range upstreams.ByFormat() {
		for _, u := range *list {
			if parsed, err := url.Parse(u); !isHTTPURL(u) || err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
				errs = append(errs, fmt.Errorf("upstreams.%s: %q must be an http(s) URL without a query", format, u))
			}
		}
	}
	if db := c.Upstreams.GoChecksumDB; db != "" && !isHTTPURL(db) {
		errs = append(errs, fmt.Errorf("upstreams.go_checksum_db: %q must be an http(s) URL", db))
	}
	errs = append(errs, c.validateFirewall()...)
	if c.DatabaseURL != "" {
		if u, err := url.Parse(c.DatabaseURL); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			errs = append(errs, errors.New("database_url must be a postgres:// URL (URL-encode special characters in the password)"))
		}
	}
	errs = append(errs, c.validateTenancy()...)
	return errors.Join(errs...)
}

func (c Config) validateSignIn() []error {
	var errs []error
	switch {
	case c.OIDC == nil && len(c.Users) == 0:
		return []error{errors.New("sign-in: configure users (with admins) or oidc")}
	case c.OIDC != nil && len(c.Users) > 0:
		return []error{errors.New("sign-in: configure users or oidc, not both")}
	}

	if c.OIDC == nil {
		if err := localauth.ValidateUsers(c.Users); err != nil {
			errs = append(errs, fmt.Errorf("users: %w", err))
		}
		if len(c.Admins) == 0 {
			errs = append(errs, errors.New("admins: list at least one user"))
		}
		for _, a := range c.Admins {
			if !slices.ContainsFunc(c.Users, func(u localauth.User) bool { return u.Username == a }) {
				errs = append(errs, fmt.Errorf("admins: %q is not in users", a))
			}
		}
		return errs
	}

	o := c.OIDC
	if len(c.Admins) > 0 {
		errs = append(errs, errors.New("admins lists local users; with oidc use oidc.admin_groups or oidc.admin_emails"))
	}
	if o.Issuer == "" {
		errs = append(errs, errors.New("oidc.issuer is required"))
	}
	if o.ClientID == "" {
		errs = append(errs, errors.New("oidc.client_id is required"))
	}
	if len(o.AdminGroups) == 0 && len(o.AdminEmails) == 0 {
		errs = append(errs, errors.New("oidc.admin_groups or oidc.admin_emails: at least one instance admin is required"))
	}
	if c.PublicURL == "" && o.RedirectURL == "" {
		errs = append(errs, errors.New("public_url is required with oidc: the identity provider redirects back to it"))
	}
	switch {
	case o.CookieSecret == "" && c.DatabaseURL != "":
		errs = append(errs, errors.New("oidc.cookie_secret (or HEXTRAP_OIDC_COOKIE_SECRET) is required with database_url, so every replica uses the same one"))
	case o.CookieSecret != "" && len(o.CookieSecret) < 32:
		errs = append(errs, errors.New("oidc.cookie_secret must be at least 32 characters"))
	}
	return errs
}

func (c Config) validateStorage() []error {
	s := c.Storage
	switch {
	case s.S3 == nil && s.Filesystem == "":
		return []error{errors.New("storage: configure s3, or filesystem for testing")}
	case s.S3 != nil && s.Filesystem != "":
		return []error{errors.New("storage: configure s3 or filesystem, not both")}
	case s.S3 != nil:
		if err := s.S3.Validate(); err != nil {
			return []error{fmt.Errorf("storage: %w", err)}
		}
	}
	return nil
}

// validateTenancy checks multi-tenant settings, which only the cloud edition
// accepts.
func (c Config) validateTenancy() []error {
	var errs []error
	tenantClaim := c.OIDC != nil && c.OIDC.TenantClaim != ""
	if !edition.MultiTenant {
		if c.TenantDomain != "" {
			errs = append(errs, errors.New("tenant_domain: multi-tenant mode is only available in hextrap cloud"))
		}
		if tenantClaim {
			errs = append(errs, errors.New("oidc.tenant_claim: multi-tenant mode is only available in hextrap cloud"))
		}
		return errs
	}
	if !c.MultiTenant() {
		return nil
	}
	if c.OIDC == nil {
		errs = append(errs, errors.New("tenant_domain requires oidc: cloud users sign in through hextrap.com"))
	} else if !tenantClaim {
		errs = append(errs, errors.New("oidc.tenant_claim is required with tenant_domain: logins must say which tenant they belong to"))
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("database_url is required with tenant_domain: cloud mode runs several replicas"))
	}
	if c.Storage.Filesystem != "" {
		errs = append(errs, errors.New("storage: cloud mode (tenant_domain) requires s3"))
	}
	if c.Tenant != "" {
		errs = append(errs, errors.New("tenant and tenant_domain are mutually exclusive"))
	}
	return errs
}

func (c Config) validateFirewall() []error {
	fw := c.HextrapFirewall
	if fw == nil {
		return nil
	}
	var errs []error
	if fw.Username == "" {
		errs = append(errs, errors.New("hextrap_firewall.username is required"))
	}
	if fw.Password == "" {
		errs = append(errs, errors.New("hextrap_firewall.password (or HEXTRAP_FIREWALL_PASSWORD) is required"))
	}
	for format, u := range fw.URLs {
		if _, ok := DefaultFirewallURLs[format]; !ok {
			errs = append(errs, fmt.Errorf("hextrap_firewall.urls.%s: the hextrap firewall doesn't support %s", format, format))
		} else if !isHTTPURL(u) {
			errs = append(errs, fmt.Errorf("hextrap_firewall.urls.%s: %q must be an http(s) URL", format, u))
		}
	}
	return errs
}
