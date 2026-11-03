package blob

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func clearAWSEnv(t *testing.T) {
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN"} {
		t.Setenv(k, "")
	}
}

func TestEnvCredentials(t *testing.T) {
	clearAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("AWS_SESSION_TOKEN", "TOKEN")
	p, err := DefaultCredentials(http.DefaultClient, time.Now)
	require.NoError(t, err)
	c, err := p.Retrieve(context.Background())
	require.NoError(t, err)
	require.Equal(t, Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "TOKEN"}, c)
}

type fakeECS struct {
	srv     *httptest.Server
	calls   atomic.Int32
	expires time.Time
	authHdr string
}

func newFakeECS(t *testing.T, expires time.Time) *fakeECS {
	f := &fakeECS{expires: expires}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.authHdr = r.Header.Get("Authorization")
		if r.URL.Path != "/v2/credentials/abc" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"AccessKeyId": "ASIA", "SecretAccessKey": "SECRET", "Token": "SESSION",
			"Expiration": f.expires.Format(time.RFC3339),
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestECSFullURICredentials(t *testing.T) {
	r := require.New(t)
	clearAWSEnv(t)
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ecs := newFakeECS(t, now.Add(time.Hour))
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", ecs.srv.URL+"/v2/credentials/abc")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "pod-token")

	clock := now
	p, err := DefaultCredentials(http.DefaultClient, func() time.Time { return clock })
	r.NoError(err)
	c, err := p.Retrieve(context.Background())
	r.NoError(err)
	r.Equal("ASIA", c.AccessKeyID)
	r.Equal("SESSION", c.SessionToken)
	r.Equal("pod-token", ecs.authHdr)

	_, _ = p.Retrieve(context.Background())
	r.Equal(int32(1), ecs.calls.Load(), "cached while valid")

	clock = now.Add(56 * time.Minute) // within 5 minutes of expiry
	_, err = p.Retrieve(context.Background())
	r.NoError(err)
	r.Equal(int32(2), ecs.calls.Load(), "refreshed before expiry")
}

func TestECSRelativeURIUsesTaskMetadataHost(t *testing.T) {
	clearAWSEnv(t)
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc")
	p, err := DefaultCredentials(http.DefaultClient, time.Now)
	require.NoError(t, err)
	require.Equal(t, "http://169.254.170.2/v2/credentials/abc", p.(*cachedCredentials).src.(*ecsCredentials).url)
}

func TestNoCredentials(t *testing.T) {
	clearAWSEnv(t)
	_, err := DefaultCredentials(http.DefaultClient, time.Now)
	require.ErrorContains(t, err, "AWS_ACCESS_KEY_ID")
}

func TestECSErrorDoesNotReturnStaleCredentials(t *testing.T) {
	clearAWSEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", srv.URL)
	p, err := DefaultCredentials(http.DefaultClient, time.Now)
	require.NoError(t, err)
	_, err = p.Retrieve(context.Background())
	require.Error(t, err)
}
