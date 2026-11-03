package identity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextRoundTrip(t *testing.T) {
	p := Principal{Tenant: "t", Kind: KindUser, Subject: "s"}
	got := FromContext(WithPrincipal(context.Background(), p))
	require.Equal(t, p, got)
}

func TestFromContextDefaultsToAnonymous(t *testing.T) {
	require.Equal(t, KindAnonymous, FromContext(context.Background()).Kind)
}

func TestRateLimitKey(t *testing.T) {
	require.Equal(t, "", Anonymous("t").RateLimitKey())
	require.Equal(t, "user:s", Principal{Kind: KindUser, Subject: "s"}.RateLimitKey())
	require.Equal(t, "service_token:s", Principal{Kind: KindServiceToken, Subject: "s"}.RateLimitKey())
}

func TestInstanceAdmins(t *testing.T) {
	a := InstanceAdmins{Groups: []string{"hextrap-admins"}, Emails: []string{"Root@Example.com"}}
	require.True(t, a.Matches(Principal{Kind: KindUser, Email: "root@example.com"}))
	require.True(t, a.Matches(Principal{Kind: KindUser, Email: "x@example.com", Groups: []string{"dev", "hextrap-admins"}}))
	require.False(t, a.Matches(Principal{Kind: KindUser, Email: "x@example.com", Groups: []string{"dev"}}))
	require.False(t, a.Matches(Principal{Kind: KindServiceToken, Subject: "root@example.com", Email: "root@example.com"}),
		"service tokens are never instance admins")
}

func TestInstanceAdminUsers(t *testing.T) {
	a := InstanceAdmins{Users: []string{"alice"}}
	require.True(t, a.Matches(Principal{Kind: KindUser, Subject: "alice"}))
	require.False(t, a.Matches(Principal{Kind: KindUser, Subject: "bob"}))
	require.False(t, a.Matches(Principal{Kind: KindServiceToken, Subject: "alice"}), "never a service token")
}
