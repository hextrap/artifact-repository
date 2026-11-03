package rbac

import (
	"testing"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
)

func TestRoleActionMatrix(t *testing.T) {
	allow := map[Role][]Action{
		RoleNone:       {},
		RoleReader:     {ActionPull},
		RoleDeveloper:  {ActionPull, ActionPublish},
		RoleMaintainer: {ActionPull, ActionPublish, ActionYank},
		RoleAdmin: {ActionPull, ActionPublish, ActionYank, ActionDelete, ActionManageSettings,
			ActionManageAccess, ActionDeleteRepo, ActionViewAudit},
	}
	for role, allowed := range allow {
		for _, action := range AllActions {
			want := false
			for _, a := range allowed {
				if a == action {
					want = true
				}
			}
			require.Equal(t, want, role.Can(action), "%s can %s", role, action)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range []Role{RoleReader, RoleDeveloper, RoleMaintainer, RoleAdmin} {
		got, err := ParseRole(r.String())
		require.NoError(t, err)
		require.Equal(t, r, got)
	}
	_, err := ParseRole("owner")
	require.Error(t, err)
}

func user(email string, groups ...string) identity.Principal {
	return identity.Principal{Tenant: "t", Kind: identity.KindUser, Subject: "sub-" + email, Email: email, Groups: groups}
}

func TestEffectiveRole(t *testing.T) {
	grants := []Grant{
		{SubjectKind: SubjectUser, Subject: "Alice@Example.com", Role: RoleReader},
		{SubjectKind: SubjectGroup, Subject: "platform", Role: RoleMaintainer},
		{SubjectKind: SubjectUser, Subject: "sub-bob@example.com", Role: RoleDeveloper},
		{SubjectKind: SubjectServiceToken, Subject: "tok1", Role: RoleDeveloper},
	}
	for _, tc := range []struct {
		name string
		p    identity.Principal
		anon bool
		want Role
	}{
		{"user grant by email, case-insensitive", user("alice@example.com"), false, RoleReader},
		{"highest of user and group grant wins", user("alice@example.com", "platform"), false, RoleMaintainer},
		{"user grant by subject", user("bob@example.com"), false, RoleDeveloper},
		{"no grant", user("eve@example.com"), false, RoleNone},
		{"group only", user("carol@example.com", "platform"), false, RoleMaintainer},
		{"instance admin implicit admin", identity.Principal{Kind: identity.KindUser, Subject: "x", InstanceAdmin: true}, false, RoleAdmin},
		{"service token", identity.Principal{Kind: identity.KindServiceToken, Subject: "tok1"}, false, RoleDeveloper},
		{"service token doesn't match user grants by subject", identity.Principal{Kind: identity.KindServiceToken, Subject: "sub-bob@example.com"}, false, RoleNone},
		{"anonymous without anonymous read", identity.Anonymous("t"), false, RoleNone},
		{"anonymous with anonymous read", identity.Anonymous("t"), true, RoleReader},
		{"authenticated user with no grant gets anonymous read", user("eve@example.com"), true, RoleReader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, Effective(tc.p, grants, tc.anon))
		})
	}
}

func TestValidateGrant(t *testing.T) {
	r := require.New(t)
	r.NoError(ValidateGrant(Grant{SubjectKind: SubjectUser, Subject: "a@b.c", Role: RoleAdmin}))
	r.NoError(ValidateGrant(Grant{SubjectKind: SubjectGroup, Subject: "g", Role: RoleAdmin}))
	r.NoError(ValidateGrant(Grant{SubjectKind: SubjectServiceToken, Subject: "t", Role: RoleDeveloper}))
	r.ErrorIs(ValidateGrant(Grant{SubjectKind: SubjectServiceToken, Subject: "t", Role: RoleAdmin}), ErrServiceTokenAdmin)
	r.NoError(ValidateGrant(Grant{SubjectKind: SubjectServiceToken, Subject: "t", Role: RoleMaintainer}),
		"CI release tooling manages dist-tags")
	r.Error(ValidateGrant(Grant{SubjectKind: SubjectUser, Subject: "", Role: RoleReader}))
	r.Error(ValidateGrant(Grant{SubjectKind: SubjectUser, Subject: "a", Role: RoleNone}))
	r.Error(ValidateGrant(Grant{SubjectKind: "robot", Subject: "a", Role: RoleReader}))
}

func TestCheckAdminRemains(t *testing.T) {
	r := require.New(t)
	r.ErrorIs(CheckAdminRemains(nil), ErrLastAdmin)
	r.ErrorIs(CheckAdminRemains([]Grant{{SubjectKind: SubjectUser, Subject: "a", Role: RoleMaintainer}}), ErrLastAdmin)
	r.NoError(CheckAdminRemains([]Grant{{SubjectKind: SubjectUser, Subject: "a", Role: RoleAdmin}}))
	r.NoError(CheckAdminRemains([]Grant{{SubjectKind: SubjectGroup, Subject: "g", Role: RoleAdmin}}))
}
