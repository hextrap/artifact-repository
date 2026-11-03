// Package rbac defines repository roles and resolves a principal's role from
// grants.
package rbac

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"hextrap.io/artifacts/internal/identity"
)

type Role int

const (
	RoleNone Role = iota
	RoleReader
	RoleDeveloper
	RoleMaintainer
	RoleAdmin
)

var roleNames = map[Role]string{
	RoleNone:       "none",
	RoleReader:     "reader",
	RoleDeveloper:  "developer",
	RoleMaintainer: "maintainer",
	RoleAdmin:      "admin",
}

func (r Role) String() string { return roleNames[r] }

func ParseRole(s string) (Role, error) {
	for r, name := range roleNames {
		if name == s && r != RoleNone {
			return r, nil
		}
	}
	return RoleNone, fmt.Errorf("unknown role %q", s)
}

func (r Role) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Role) UnmarshalText(b []byte) error {
	v, err := ParseRole(string(b))
	*r = v
	return err
}

type Action string

const (
	ActionPull           Action = "pull"
	ActionPublish        Action = "publish"
	ActionYank           Action = "yank" // also deprecate, dist-tags
	ActionDelete         Action = "delete"
	ActionManageSettings Action = "manage_settings"
	ActionManageAccess   Action = "manage_access"
	ActionDeleteRepo     Action = "delete_repo"
	ActionViewAudit      Action = "view_audit"
)

var AllActions = []Action{ActionPull, ActionPublish, ActionYank, ActionDelete,
	ActionManageSettings, ActionManageAccess, ActionDeleteRepo, ActionViewAudit}

// minRole is the lowest role allowed to perform each action.
var minRole = map[Action]Role{
	ActionPull:           RoleReader,
	ActionPublish:        RoleDeveloper,
	ActionYank:           RoleMaintainer,
	ActionDelete:         RoleAdmin,
	ActionManageSettings: RoleAdmin,
	ActionManageAccess:   RoleAdmin,
	ActionDeleteRepo:     RoleAdmin,
	ActionViewAudit:      RoleAdmin,
}

func (r Role) Can(a Action) bool {
	min, ok := minRole[a]
	return ok && r != RoleNone && r >= min
}

type SubjectKind string

const (
	SubjectUser         SubjectKind = "user"  // email or OIDC sub
	SubjectGroup        SubjectKind = "group" // IdP group name
	SubjectServiceToken SubjectKind = "service_token"
)

type Grant struct {
	SubjectKind SubjectKind `json:"subject_kind"`
	Subject     string      `json:"subject"`
	Role        Role        `json:"role"`
}

var (
	ErrServiceTokenAdmin = errors.New("service tokens cannot be granted admin")
	ErrLastAdmin         = errors.New("a repository must keep at least one admin")
)

func ValidateGrant(g Grant) error {
	switch g.SubjectKind {
	case SubjectUser, SubjectGroup, SubjectServiceToken:
	default:
		return fmt.Errorf("unknown subject kind %q", g.SubjectKind)
	}
	if strings.TrimSpace(g.Subject) == "" {
		return errors.New("subject is required")
	}
	if g.Role == RoleNone {
		return errors.New("role is required")
	}
	if g.SubjectKind == SubjectServiceToken && g.Role == RoleAdmin {
		return ErrServiceTokenAdmin
	}
	return nil
}

func matches(p identity.Principal, g Grant) bool {
	switch g.SubjectKind {
	case SubjectUser:
		return p.Kind == identity.KindUser &&
			(g.Subject == p.Subject || (p.Email != "" && strings.EqualFold(g.Subject, p.Email)))
	case SubjectGroup:
		return p.Kind == identity.KindUser && slices.Contains(p.Groups, g.Subject)
	case SubjectServiceToken:
		return p.Kind == identity.KindServiceToken && g.Subject == p.Subject
	}
	return false
}

// Effective returns the highest role p holds on a repository.
func Effective(p identity.Principal, grants []Grant, anonymousRead bool) Role {
	if p.InstanceAdmin && p.Kind == identity.KindUser {
		return RoleAdmin
	}
	role := RoleNone
	if anonymousRead {
		role = RoleReader
	}
	for _, g := range grants {
		if matches(p, g) && g.Role > role {
			role = g.Role
		}
	}
	return role
}

// CheckAdminRemains reports ErrLastAdmin unless grants (as they would be
// after a change) include a user or group Admin.
func CheckAdminRemains(grants []Grant) error {
	for _, g := range grants {
		if g.Role == RoleAdmin && (g.SubjectKind == SubjectUser || g.SubjectKind == SubjectGroup) {
			return nil
		}
	}
	return ErrLastAdmin
}
