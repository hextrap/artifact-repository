// Package localauth signs in users listed in the config file, for
// self-hosted installs without an identity provider. Only password hashes
// are configured (see HashPassword); passwords never appear in config.
package localauth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/oidc"
	"hextrap.io/artifacts/internal/ratelimit"
)

const (
	hashPrefix        = "pbkdf2-sha256"
	DefaultIterations = 600_000 // OWASP's recommendation for PBKDF2-HMAC-SHA256
	MinIterations     = 100_000
	saltLen           = 16
	keyLen            = 32

	// MaxAttempts sign-in attempts per IP and per username are allowed per
	// AttemptWindow. Throttling is always on, whatever rate_limit says.
	MaxAttempts   = 10
	AttemptWindow = 15 * time.Minute
)

var b64 = base64.RawStdEncoding

// HashPassword returns the value for a user's password_hash setting.
func HashPassword(password string) (string, error) {
	return hashWithIterations(password, DefaultIterations)
}

func hashWithIterations(password string, iterations int) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, iterations, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type parsedHash struct {
	iterations int
	salt, key  []byte
}

func parseHash(h string) (parsedHash, error) {
	parts := strings.Split(h, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return parsedHash{}, errors.New(`password_hash must be generated with "hextrap-artifacts hash-password"`)
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < MinIterations {
		return parsedHash{}, fmt.Errorf("password_hash must use at least %d iterations", MinIterations)
	}
	salt, err1 := b64.DecodeString(parts[2])
	key, err2 := b64.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < saltLen || len(key) != keyLen {
		return parsedHash{}, errors.New("password_hash is malformed")
	}
	return parsedHash{iterations: iter, salt: salt, key: key}, nil
}

func ValidateHash(h string) error {
	_, err := parseHash(h)
	return err
}

func verify(hash, password string) (bool, error) {
	p, err := parseHash(hash)
	if err != nil {
		return false, err
	}
	key, err := pbkdf2.Key(sha256.New, password, p.salt, p.iterations, keyLen)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

type User struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidateUsername reports whether name is a valid (lowercase) username.
func ValidateUsername(name string) error {
	if !usernameRE.MatchString(name) {
		return fmt.Errorf("username %q must be lowercase letters, digits, '.', '_' or '-'", name)
	}
	return nil
}

type Users struct {
	hashes map[string]string
	// dummy is checked for unknown usernames so they take as long to
	// reject as wrong passwords, and can't be discovered by timing.
	dummy string
}

// ValidateUsers checks usernames and password hashes without the cost of
// NewUsers.
func ValidateUsers(users []User) error {
	seen := map[string]bool{}
	for _, user := range users {
		if err := ValidateUsername(user.Username); err != nil {
			return err
		}
		if seen[user.Username] {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		seen[user.Username] = true
		if err := ValidateHash(user.PasswordHash); err != nil {
			return fmt.Errorf("user %q: %w", user.Username, err)
		}
	}
	return nil
}

func NewUsers(users []User) (*Users, error) {
	if err := ValidateUsers(users); err != nil {
		return nil, err
	}
	u := &Users{hashes: map[string]string{}}
	maxIter := MinIterations
	for _, user := range users {
		p, _ := parseHash(user.PasswordHash)
		maxIter = max(maxIter, p.iterations)
		u.hashes[user.Username] = user.PasswordHash
	}
	dummy, err := hashWithIterations(rand.Text(), maxIter)
	if err != nil {
		return nil, err
	}
	u.dummy = dummy
	return u, nil
}

// Check returns the canonical username if the password is right.
func (u *Users) Check(username, password string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(username))
	hash, known := u.hashes[name]
	if !known {
		hash = u.dummy
	}
	ok, err := verify(hash, password)
	return name, ok && err == nil && known
}

// Flow serves /auth/login and /auth/logout for local users.
type Flow struct {
	users    *Users
	sessions oidc.Sessions
	tenant   string
	now      func() time.Time
	onLogin  func(identity.Principal) error
	secure   bool
	attempts *ratelimit.Memory
	// ClientIP identifies the client for throttling; it defaults to the
	// connection's address.
	ClientIP func(*http.Request) string
}

// NewFlow creates the sign-in flow. publicURL may be empty; cookies are
// marked Secure when it's https or the request arrived over TLS.
func NewFlow(users *Users, sessions oidc.Sessions, tenant, publicURL string, now func() time.Time, onLogin func(identity.Principal) error) *Flow {
	return &Flow{
		users: users, sessions: sessions, tenant: tenant, now: now, onLogin: onLogin,
		secure:   strings.HasPrefix(publicURL, "https://"),
		attempts: ratelimit.NewMemory(now),
		ClientIP: func(r *http.Request) string {
			if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				return h
			}
			return r.RemoteAddr
		},
	}
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · hextrap Artifacts</title>
<link rel="icon" type="image/svg+xml" href="/ui/favicon.svg">
<link rel="stylesheet" href="/ui/app.css">
</head>
<body>
<div class="auth-page">
  <main class="auth-card">
    <div class="auth-brand">
      <svg class="brand-mark" viewBox="0 0 40 40" width="40" height="40" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <polygon points="20,2 35,12 35,28 20,38 5,28 5,12" fill="none" stroke="currentColor" stroke-width="2"/>
        <polygon points="20,8 30,16 30,24 20,32 10,24 10,16" fill="currentColor" fill-opacity="0.1"/>
        <polygon points="20,12 26,18 26,22 20,28 14,22 14,18" fill="currentColor"/>
      </svg>
      <span class="brand-text"><span class="brand-name">hextrap</span><span class="brand-product">Artifacts</span></span>
    </div>
    <h1 class="auth-title">Sign in</h1>
    {{if .Error}}<div class="notice notice-danger" role="alert">{{.Error}}</div>{{end}}
    <form class="form" method="post" action="/auth/login">
      <label class="field"><span class="field-label">Username</span>
        <input class="input" name="username" autocomplete="username" value="{{.Username}}" required autofocus></label>
      <label class="field"><span class="field-label">Password</span>
        <input class="input" name="password" type="password" autocomplete="current-password" required></label>
      <button class="button button-primary" type="submit">Sign in</button>
    </form>
  </main>
</div>
</body>
</html>
`))

func (f *Flow) render(w http.ResponseWriter, status int, username, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, map[string]string{"Username": username, "Error": msg})
}

// sameOrigin rejects cross-site form posts. Browsers always send Origin on
// cross-origin POSTs, so its absence means a non-browser client.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (f *Flow) setSession(w http.ResponseWriter, r *http.Request, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: oidc.SessionCookie, Value: id, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: f.secure || r.TLS != nil, SameSite: http.SameSiteLaxMode})
}

func (f *Flow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/auth/login" && r.Method == http.MethodGet:
		f.render(w, http.StatusOK, "", "")
	case r.URL.Path == "/auth/login" && r.Method == http.MethodPost:
		f.login(w, r)
	case r.URL.Path == "/auth/logout" && r.Method == http.MethodPost:
		if !sameOrigin(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if c, err := r.Cookie(oidc.SessionCookie); err == nil {
			f.sessions.Delete(c.Value)
		}
		f.setSession(w, r, "", -1)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *Flow) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	limit := ratelimit.Limit{Rate: MaxAttempts / AttemptWindow.Seconds(), Burst: MaxAttempts}
	d, _ := f.attempts.AllowAll(r.Context(), []ratelimit.Check{
		{Scope: "ip", Key: "ip:" + f.ClientIP(r), Cost: 1, Limit: limit},
		{Scope: "username", Key: "user:" + strings.ToLower(username), Cost: 1, Limit: limit},
	})
	if !d.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
		f.render(w, http.StatusTooManyRequests, username, "Too many sign-in attempts. Try again later.")
		return
	}
	name, ok := f.users.Check(username, password)
	if !ok {
		f.render(w, http.StatusUnauthorized, username, "Invalid username or password.")
		return
	}
	p := identity.Principal{Tenant: f.tenant, Kind: identity.KindUser, Subject: name}
	if f.onLogin != nil {
		if err := f.onLogin(p); err != nil {
			http.Error(w, "sign-in failed", http.StatusInternalServerError)
			return
		}
	}
	id, err := f.sessions.Create(p, f.now().Add(oidc.SessionLifetime))
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	f.setSession(w, r, id, int(oidc.SessionLifetime.Seconds()))
	http.Redirect(w, r, "/", http.StatusFound)
}

// Authenticate returns the principal for a request's session cookie.
func (f *Flow) Authenticate(r *http.Request) (identity.Principal, bool) {
	c, err := r.Cookie(oidc.SessionCookie)
	if err != nil {
		return identity.Principal{}, false
	}
	return f.sessions.Get(c.Value, f.now())
}
