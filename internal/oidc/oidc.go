// Package oidc implements OpenID Connect login (authorization code flow
// with PKCE) and browser sessions, using only the standard library.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hextrap.io/artifacts/internal/identity"
)

type Config struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url"`
	Scopes       []string `yaml:"scopes"`
	// GroupsClaim names the ID token claim holding group names.
	GroupsClaim string `yaml:"groups_claim"`
	// TenantClaim, if set, takes the tenant from a claim (cloud mode).
	TenantClaim string `yaml:"tenant_claim"`
	// CookieSecret signs the login state cookie; at least 32 bytes, shared
	// across replicas.
	CookieSecret string `yaml:"cookie_secret"`
}

const (
	leeway          = 30 * time.Second
	stateLifetime   = 10 * time.Minute
	SessionLifetime = 12 * time.Hour
	stateCookie     = "hextrap_oidc"
	SessionCookie   = "hextrap_session"
)

var ErrInvalidToken = errors.New("invalid ID token")

type Provider struct {
	cfg     Config
	client  *http.Client
	now     func() time.Time
	authURL string
	tokURL  string
	jwksURL string

	mu   sync.Mutex
	keys map[string]crypto.PublicKey
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// NewProvider fetches the issuer's discovery document.
func NewProvider(ctx context.Context, cfg Config, client *http.Client, now func() time.Time) (*Provider, error) {
	if len(cfg.CookieSecret) < 32 {
		return nil, errors.New("oidc: cookie_secret must be at least 32 bytes")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		AuthURL string `json:"authorization_endpoint"`
		TokURL  string `json:"token_endpoint"`
		JWKSURL string `json:"jwks_uri"`
	}
	issuer := strings.TrimSuffix(cfg.Issuer, "/")
	if err := getJSON(ctx, client, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if strings.TrimSuffix(doc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("oidc discovery: issuer %q does not match configured %q", doc.Issuer, cfg.Issuer)
	}
	cfg.Issuer = doc.Issuer
	return &Provider{cfg: cfg, client: client, now: now,
		authURL: doc.AuthURL, tokURL: doc.TokURL, jwksURL: doc.JWKSURL, keys: map[string]crypto.PublicKey{}}, nil
}

func (p *Provider) authCodeURL(state, nonce, challenge string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	return p.authURL + sep + q.Encode()
}

func (p *Provider) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.IDToken == "" {
		return "", fmt.Errorf("token exchange failed: %s %s", resp.Status, body.Error)
	}
	return body.IDToken, nil
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (p *Provider) fetchKeys(ctx context.Context) error {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, p.client, p.jwksURL, &set); err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := b64decode(k.N)
			e, err2 := b64decode(k.E)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := b64decode(k.X)
			y, err2 := b64decode(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	p.mu.Lock()
	p.keys = keys
	p.mu.Unlock()
	return nil
}

func (p *Provider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	k, ok := p.keys[kid]
	p.mu.Unlock()
	if ok {
		return k, nil
	}
	// Unknown key: the IdP may have rotated keys.
	if err := p.fetchKeys(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[kid]; ok {
		return k, nil
	}
	if kid == "" && len(p.keys) == 1 {
		for _, k := range p.keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: unknown signing key %q", ErrInvalidToken, kid)
}

func verifySignature(alg string, key crypto.PublicKey, input, sig []byte) error {
	h := sha256.Sum256(input)
	switch alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidToken
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return ErrInvalidToken
		}
		if !ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return ErrInvalidToken
		}
		return nil
	}
	return fmt.Errorf("%w: unsupported alg %q", ErrInvalidToken, alg)
}

func audienceContains(aud any, clientID string) bool {
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []any:
		for _, v := range a {
			if v == clientID {
				return true
			}
		}
	}
	return false
}

func stringList(v any) []string {
	switch g := v.(type) {
	case string:
		return []string{g}
	case []any:
		var out []string
		for _, x := range g {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// verify checks an ID token and returns the principal it describes.
func (p *Provider) verify(ctx context.Context, raw, nonce, defaultTenant string) (identity.Principal, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return identity.Principal{}, ErrInvalidToken
	}
	hdrJSON, err1 := b64decode(parts[0])
	claimsJSON, err2 := b64decode(parts[1])
	sig, err3 := b64decode(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return identity.Principal{}, ErrInvalidToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return identity.Principal{}, ErrInvalidToken
	}
	key, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return identity.Principal{}, err
	}
	if err := verifySignature(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return identity.Principal{}, fmt.Errorf("%w: bad signature", ErrInvalidToken)
	}

	var c map[string]any
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return identity.Principal{}, ErrInvalidToken
	}
	now := p.now()
	exp, _ := c["exp"].(float64)
	switch {
	case c["iss"] != p.cfg.Issuer:
		return identity.Principal{}, fmt.Errorf("%w: wrong issuer", ErrInvalidToken)
	case !audienceContains(c["aud"], p.cfg.ClientID):
		return identity.Principal{}, fmt.Errorf("%w: wrong audience", ErrInvalidToken)
	case now.After(time.Unix(int64(exp), 0).Add(leeway)):
		return identity.Principal{}, fmt.Errorf("%w: expired", ErrInvalidToken)
	case c["nonce"] != nonce:
		return identity.Principal{}, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
	}
	sub, _ := c["sub"].(string)
	if sub == "" {
		return identity.Principal{}, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}

	pr := identity.Principal{Tenant: defaultTenant, Kind: identity.KindUser, Subject: sub,
		Groups: stringList(c[p.cfg.GroupsClaim])}
	// An explicitly unverified email must not satisfy email-based grants.
	if email, _ := c["email"].(string); email != "" && c["email_verified"] != false && c["email_verified"] != "false" {
		pr.Email = strings.ToLower(email)
	}
	if p.cfg.TenantClaim != "" {
		t, _ := c[p.cfg.TenantClaim].(string)
		if t == "" {
			return identity.Principal{}, fmt.Errorf("%w: missing tenant claim", ErrInvalidToken)
		}
		pr.Tenant = t
	}
	return pr, nil
}

// Sessions stores browser sessions server-side.
type Sessions interface {
	Create(p identity.Principal, expires time.Time) (string, error)
	Get(id string, now time.Time) (identity.Principal, bool)
	Delete(id string)
}

type session struct {
	p       identity.Principal
	expires time.Time
}

type MemorySessions struct {
	mu sync.Mutex
	m  map[string]session
}

func NewMemorySessions() *MemorySessions { return &MemorySessions{m: map[string]session{}} }

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *MemorySessions) Create(p identity.Principal, expires time.Time) (string, error) {
	id := randomString(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = session{p: p, expires: expires}
	return id, nil
}

func (s *MemorySessions) Get(id string, now time.Time) (identity.Principal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok || !now.Before(sess.expires) {
		delete(s.m, id)
		return identity.Principal{}, false
	}
	return sess.p, true
}

func (s *MemorySessions) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// Flow serves /auth/login, /auth/callback and /auth/logout.
type Flow struct {
	p             *Provider
	sessions      Sessions
	defaultTenant string
	onLogin       func(identity.Principal) error
	secure        bool
}

// NewFlow creates the login flow. onLogin runs after every successful login
// (e.g. to refresh personal access tokens' group snapshots).
func NewFlow(p *Provider, sessions Sessions, defaultTenant string, onLogin func(identity.Principal) error) *Flow {
	return &Flow{p: p, sessions: sessions, defaultTenant: defaultTenant, onLogin: onLogin,
		secure: strings.HasPrefix(p.cfg.RedirectURL, "https://")}
}

type loginState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

func (f *Flow) sign(payload []byte) string {
	m := hmac.New(sha256.New, []byte(f.p.cfg.CookieSecret))
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (f *Flow) unsign(v string) ([]byte, bool) {
	enc, mac, ok := strings.Cut(v, ".")
	if !ok {
		return nil, false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(enc)
	got, err2 := base64.RawURLEncoding.DecodeString(mac)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	m := hmac.New(sha256.New, []byte(f.p.cfg.CookieSecret))
	m.Write(payload)
	return payload, hmac.Equal(got, m.Sum(nil))
}

func (f *Flow) setCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: f.secure, SameSite: http.SameSiteLaxMode})
}

func (f *Flow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/auth/login":
		f.login(w, r)
	case "/auth/callback":
		f.callback(w, r)
	case "/auth/logout":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if c, err := r.Cookie(SessionCookie); err == nil {
			f.sessions.Delete(c.Value)
		}
		f.setCookie(w, SessionCookie, "", "/", -1)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *Flow) login(w http.ResponseWriter, r *http.Request) {
	st := loginState{State: randomString(24), Nonce: randomString(24), Verifier: randomString(48),
		Exp: f.p.now().Add(stateLifetime).Unix()}
	payload, _ := json.Marshal(st)
	f.setCookie(w, stateCookie, f.sign(payload), "/auth/", int(stateLifetime.Seconds()))
	challenge := sha256.Sum256([]byte(st.Verifier))
	http.Redirect(w, r, f.p.authCodeURL(st.State, st.Nonce, base64.RawURLEncoding.EncodeToString(challenge[:])), http.StatusFound)
}

func (f *Flow) callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(stateCookie)
	if err != nil {
		http.Error(w, "login expired or started in another browser; try again", http.StatusBadRequest)
		return
	}
	f.setCookie(w, stateCookie, "", "/auth/", -1)
	payload, ok := f.unsign(c.Value)
	var st loginState
	if !ok || json.Unmarshal(payload, &st) != nil || f.p.now().Unix() > st.Exp ||
		!hmac.Equal([]byte(st.State), []byte(r.URL.Query().Get("state"))) {
		http.Error(w, "invalid login state; try again", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "login was not completed: "+e, http.StatusUnauthorized)
		return
	}

	raw, err := f.p.exchange(r.Context(), r.URL.Query().Get("code"), st.Verifier)
	if err != nil {
		slog.Warn("oidc code exchange failed", "err", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	pr, err := f.p.verify(r.Context(), raw, st.Nonce, f.defaultTenant)
	if err != nil {
		slog.Warn("oidc token rejected", "err", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	if f.onLogin != nil {
		if err := f.onLogin(pr); err != nil {
			slog.Error("login hook failed", "err", err)
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
	}
	id, err := f.sessions.Create(pr, f.p.now().Add(SessionLifetime))
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	f.setCookie(w, SessionCookie, id, "/", int(SessionLifetime.Seconds()))
	http.Redirect(w, r, "/", http.StatusFound)
}

// Authenticate returns the principal for a request's session cookie.
func (f *Flow) Authenticate(r *http.Request) (identity.Principal, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return identity.Principal{}, false
	}
	return f.sessions.Get(c.Value, f.p.now())
}

func (s *MemorySessions) DeleteExpired(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.m {
		if !now.Before(sess.expires) {
			delete(s.m, id)
		}
	}
	return nil
}
