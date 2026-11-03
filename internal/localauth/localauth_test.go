package localauth

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/oidc"
)

// Hashes are generated once at the minimum cost to keep tests fast.
var (
	aliceHash = mustHash("correct horse")
	bobHash   = mustHash("battery staple")
)

func mustHash(pw string) string {
	h, err := hashWithIterations(pw, MinIterations)
	if err != nil {
		panic(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	r := require.New(t)
	h, err := HashPassword("s3cret!")
	r.NoError(err)
	r.True(strings.HasPrefix(h, "pbkdf2-sha256$600000$"))
	r.NotContains(h, "s3cret")
	r.NoError(ValidateHash(h))

	ok, err := verify(h, "s3cret!")
	r.NoError(err)
	r.True(ok)
	ok, _ = verify(h, "s3cret")
	r.False(ok)

	h2, _ := HashPassword("s3cret!")
	r.NotEqual(h, h2, "salted")
}

func TestValidateHash(t *testing.T) {
	r := require.New(t)
	r.NoError(ValidateHash(aliceHash))
	for _, bad := range []string{
		"", "plaintext", "md5$1$a$b",
		"pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA", // too few iterations
		"pbkdf2-sha256$600000$!!$aGFzaA",
		"pbkdf2-sha256$600000$c2FsdA",
	} {
		r.Error(ValidateHash(bad), bad)
	}
}

func TestNewUsersValidation(t *testing.T) {
	_, err := NewUsers([]User{{Username: "alice", PasswordHash: "plaintext"}})
	require.Error(t, err)
	_, err = NewUsers([]User{{Username: "alice", PasswordHash: aliceHash}, {Username: "alice", PasswordHash: bobHash}})
	require.ErrorContains(t, err, "duplicate")
	_, err = NewUsers([]User{{Username: "Not Valid", PasswordHash: aliceHash}})
	require.Error(t, err)
}

type harness struct {
	srv    *httptest.Server
	client *http.Client
	logins []identity.Principal
	clock  time.Time
}

func newHarness(t *testing.T) *harness {
	users, err := NewUsers([]User{{Username: "alice", PasswordHash: aliceHash}, {Username: "bob", PasswordHash: bobHash}})
	require.NoError(t, err)
	h := &harness{clock: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	var flow *Flow
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) { flow.ServeHTTP(w, r) })
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		p, ok := flow.Authenticate(r)
		if !ok {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, p.Tenant+"/"+string(p.Kind)+"/"+p.Subject)
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	flow = NewFlow(users, oidc.NewMemorySessions(), "default", h.srv.URL, func() time.Time { return h.clock },
		func(p identity.Principal) error { h.logins = append(h.logins, p); return nil })
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

func (h *harness) login(t *testing.T, user, pass string) int {
	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/login", strings.NewReader(url.Values{"username": {user}, "password": {pass}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.srv.URL)
	resp, err := h.client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func (h *harness) whoami(t *testing.T) (int, string) {
	resp, err := h.client.Get(h.srv.URL + "/whoami")
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestLoginForm(t *testing.T) {
	h := newHarness(t)
	resp, err := h.client.Get(h.srv.URL + "/auth/login")
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	require.Equal(t, 200, resp.StatusCode)
	require.Contains(t, string(b), `name="password"`)
	require.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	require.Contains(t, string(b), `<link rel="stylesheet" href="/ui/app.css">`, "styled like the app")
	require.Contains(t, string(b), `points="20,2 35,12 35,28 20,38 5,28 5,12"`, "the hextrap logo")
	require.NotContains(t, string(b), "<style", "no inline styles")
	require.NotContains(t, resp.Header.Get("Content-Security-Policy"), "unsafe-inline")
}

func TestLoginAndLogout(t *testing.T) {
	r := require.New(t)
	h := newHarness(t)
	r.Equal(http.StatusFound, h.login(t, "alice", "correct horse"))
	code, who := h.whoami(t)
	r.Equal(200, code)
	r.Equal("default/user/alice", who)
	r.Len(h.logins, 1, "login hook runs")

	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/logout", nil)
	req.Header.Set("Origin", h.srv.URL)
	resp, err := h.client.Do(req)
	r.NoError(err)
	resp.Body.Close()
	code, _ = h.whoami(t)
	r.Equal(401, code)
}

func TestUsernameIsCaseInsensitive(t *testing.T) {
	h := newHarness(t)
	require.Equal(t, http.StatusFound, h.login(t, "Alice", "correct horse"))
	_, who := h.whoami(t)
	require.Equal(t, "default/user/alice", who)
}

func TestBadCredentials(t *testing.T) {
	r := require.New(t)
	h := newHarness(t)
	r.Equal(http.StatusUnauthorized, h.login(t, "alice", "wrong"))
	r.Equal(http.StatusUnauthorized, h.login(t, "mallory", "correct horse"), "unknown users look the same")
	r.Equal(http.StatusUnauthorized, h.login(t, "bob", "correct horse"), "another user's password")
	code, _ := h.whoami(t)
	r.Equal(401, code)
	r.Empty(h.logins)
}

func TestBruteForceThrottled(t *testing.T) {
	r := require.New(t)
	h := newHarness(t)
	for i := 0; i < MaxAttempts; i++ {
		r.Equal(http.StatusUnauthorized, h.login(t, "alice", "guess"), "attempt %d", i)
	}
	r.Equal(http.StatusTooManyRequests, h.login(t, "alice", "correct horse"), "even the right password is refused while throttled")

	h.clock = h.clock.Add(AttemptWindow)
	r.Equal(http.StatusFound, h.login(t, "alice", "correct horse"))
}

func TestThrottleIsPerUsernameToo(t *testing.T) {
	// Guessing alice's password from many IPs is still limited, because the
	// username has its own bucket. Here one IP guesses against two users.
	r := require.New(t)
	h := newHarness(t)
	for i := 0; i < MaxAttempts; i++ {
		h.login(t, "alice", "guess")
	}
	r.Equal(http.StatusTooManyRequests, h.login(t, "bob", "battery staple"), "the IP is throttled too")
}

func TestCrossSiteLoginRejected(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/login", strings.NewReader("username=alice&password=correct+horse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := h.client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}
