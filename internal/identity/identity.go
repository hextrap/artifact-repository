// Package identity describes who is making a request.
package identity

import (
	"context"
	"slices"
	"strings"
)

type Kind string

const (
	KindAnonymous    Kind = "anonymous"
	KindUser         Kind = "user"
	KindServiceToken Kind = "service_token"
	// KindSystem is background jobs (e.g. purging expired trash). It never
	// authenticates a request.
	KindSystem Kind = "system"
)

type Principal struct {
	Tenant string
	Kind   Kind
	// Subject is the OIDC "sub" for users, the token ID for service tokens.
	Subject string
	Email   string
	// Groups from the IdP, as of the user's last login.
	Groups        []string
	InstanceAdmin bool
	// TokenID is set when the request authenticated with a token.
	TokenID string
}

func Anonymous(tenant string) Principal {
	return Principal{Tenant: tenant, Kind: KindAnonymous}
}

// RateLimitKey identifies the principal for per-principal limits; empty for
// anonymous requests, which are limited per IP instead.
func (p Principal) RateLimitKey() string {
	if p.Kind == KindAnonymous || p.Kind == "" {
		return ""
	}
	return string(p.Kind) + ":" + p.Subject
}

// Actor is how the principal appears in audit logs.
func (p Principal) Actor() string {
	switch p.Kind {
	case KindUser:
		if p.Email != "" {
			return p.Email
		}
		return p.Subject
	case KindServiceToken:
		return "token:" + p.Subject
	case KindSystem:
		return "system"
	}
	return "anonymous"
}

type ctxKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

func FromContext(ctx context.Context) Principal {
	if p, ok := ctx.Value(ctxKey{}).(Principal); ok {
		return p
	}
	return Principal{Kind: KindAnonymous}
}

// InstanceAdmins comes from the config file only, so it can't be locked out
// from inside the app.
type InstanceAdmins struct {
	Groups []string `yaml:"groups"`
	Emails []string `yaml:"emails"`
	// Users are local usernames (config-file users, not an IdP).
	Users []string `yaml:"users"`
}

func (a InstanceAdmins) Matches(p Principal) bool {
	if p.Kind != KindUser {
		return false
	}
	for _, e := range a.Emails {
		if p.Email != "" && strings.EqualFold(e, p.Email) {
			return true
		}
	}
	if slices.Contains(a.Users, p.Subject) {
		return true
	}
	for _, g := range a.Groups {
		if slices.Contains(p.Groups, g) {
			return true
		}
	}
	return false
}
