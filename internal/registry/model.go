package registry

import (
	"encoding/json"
	"errors"
	"time"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/rbac"
)

var (
	ErrNotFound             = errors.New("not found")
	ErrExists               = errors.New("already exists")
	ErrForbidden            = errors.New("forbidden")
	ErrUnauthenticated      = errors.New("authentication required")
	ErrInvalid              = errors.New("invalid request")
	ErrVersionExists        = errors.New("version already exists or previously existed")
	ErrFileExists           = errors.New("file already exists or previously existed")
	ErrQuotaExceeded        = errors.New("storage quota exceeded")
	ErrRepoNotEmpty         = errors.New("repository is not empty")
	ErrConfirmationMismatch = errors.New("confirmation does not match package@version")
	ErrReadOnly             = errors.New("proxy repositories are read-only: packages come from the upstream registry")
	ErrDigestMismatch       = errors.New("file does not match the hash the upstream registry declared")
	ErrUpstreamUnavailable  = errors.New("upstream registry unavailable")
	ErrBlocked              = errors.New("blocked by firewall policy")
)

type Format string

const (
	FormatNPM   Format = "npm"
	FormatPyPI  Format = "pypi"
	FormatMaven Format = "maven"
	FormatCargo Format = "cargo"
	FormatGo    Format = "go"
	FormatOCI   Format = "oci"
)

type RepoType string

const (
	TypeHosted RepoType = "hosted"
	// TypeProxy caches packages from an upstream registry on first request.
	TypeProxy RepoType = "proxy"
)

// Where a version came from.
const (
	SourcePublished = "published"
	SourceUpstream  = "upstream"
)

const DefaultDeleteGrace = 30 * 24 * time.Hour

type Repo struct {
	Tenant string   `json:"-"`
	Name   string   `json:"name"`
	Format Format   `json:"format"`
	Type   RepoType `json:"type"`
	// Upstream is the registry a proxy repo caches from.
	Upstream      string        `json:"upstream,omitempty"`
	AnonymousRead bool          `json:"anonymous_read"`
	DeleteGrace   time.Duration `json:"delete_grace"`
	CreatedAt     time.Time     `json:"created_at"`
	CreatedBy     string        `json:"created_by"`
}

// RepoView is a repo as seen by a principal.
type RepoView struct {
	Repo
	Role rbac.Role `json:"role"`
	// Firewall: a proxy repo whose upstream is a hextrap firewall.
	Firewall bool `json:"firewall"`
}

type File struct {
	Filename string      `json:"filename"`
	Digest   blob.Digest `json:"digest"`
	Size     int64       `json:"size"`
	// Attrs holds format-specific fields (npm shasum/integrity, PyPI
	// requires-python and metadata digest).
	Attrs map[string]string `json:"attrs,omitempty"`
}

type VersionKey struct {
	Tenant, Repo, Package, Version string
}

type Version struct {
	Tenant string `json:"-"`
	Repo   string `json:"repo"`
	// Package is the format-normalized name; DisplayName as published.
	Package     string          `json:"package"`
	DisplayName string          `json:"display_name"`
	Version     string          `json:"version"`
	Files       []File          `json:"files"`
	Manifest    json.RawMessage `json:"manifest,omitempty"`
	Publisher   string          `json:"publisher"`
	// Source is SourcePublished or SourceUpstream; Origin is the upstream
	// host a cached version came from.
	Source      string     `json:"source"`
	Origin      string     `json:"origin,omitempty"`
	PublishedAt time.Time  `json:"published_at"`
	Yanked      bool       `json:"yanked"`
	YankReason  string     `json:"yank_reason,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	PurgedAt    *time.Time `json:"purged_at,omitempty"`
}

func (v Version) Key() VersionKey {
	return VersionKey{Tenant: v.Tenant, Repo: v.Repo, Package: v.Package, Version: v.Version}
}

func (v Version) Visible() bool { return v.DeletedAt == nil && v.PurgedAt == nil }

func (v Version) InTrash() bool { return v.DeletedAt != nil && v.PurgedAt == nil }

func (v Version) Size() int64 {
	var n int64
	for _, f := range v.Files {
		n += f.Size
	}
	return n
}

type AuditEntry struct {
	Time      time.Time `json:"time"`
	Tenant    string    `json:"-"`
	Repo      string    `json:"repo"`
	Actor     string    `json:"actor"`
	ActorKind string    `json:"actor_kind"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Before    string    `json:"before,omitempty"`
	After     string    `json:"after,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
}

// PackageSummary describes a package's visible versions.
type PackageSummary struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Versions    int       `json:"versions"`
	Latest      string    `json:"latest"`
	Updated     time.Time `json:"updated"`
	Size        int64     `json:"size"`
	// Source is SourcePublished, SourceUpstream, or "mixed".
	Source string `json:"source"`
	Origin string `json:"origin,omitempty"`
}
