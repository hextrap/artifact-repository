package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/identity"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// fakeIdP is a minimal OIDC provider: discovery, JWKS and token endpoint.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	rsaKey *rsa.PrivateKey
	kid    string
	ecKey  *ecdsa.PrivateKey
	// claims for the next token response; nonce is filled from the code.
	claims       map[string]any
	codes        map[string]string // code -> nonce
	verifiers    map[string]string // code -> expected PKCE challenge
	jwksFetches  int
	signWith     string // "rsa", "ec", "wrong-key"
	lastTokenReq url.Values
}

func newIdP(t *testing.T) *fakeIdP {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idp := &fakeIdP{t: t, rsaKey: k, ecKey: ek, kid: "k1", codes: map[string]string{}, verifiers: map[string]string{}, signWith: "rsa"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idp.srv.URL,
			"authorization_endpoint": idp.srv.URL + "/authorize",
			"token_endpoint":         idp.srv.URL + "/token",
			"jwks_uri":               idp.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		idp.jwksFetches++
		x := idp.ecKey.PublicKey.X.FillBytes(make([]byte, 32))
		y := idp.ecKey.PublicKey.Y.FillBytes(make([]byte, 32))
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": idp.kid, "alg": "RS256", "use": "sig",
				"n": b64(idp.rsaKey.N.Bytes()), "e": b64(big.NewInt(int64(idp.rsaKey.E)).Bytes())},
			{"kty": "EC", "kid": "ec1", "crv": "P-256", "x": b64(x), "y": b64(y)},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		idp.mu.Lock()
		defer idp.mu.Unlock()
		idp.lastTokenReq = r.PostForm
		code := r.PostForm.Get("code")
		nonce, ok := idp.codes[code]
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || b64(sum[:]) != idp.verifiers[code] {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		claims := map[string]any{
			"iss": idp.srv.URL, "aud": "hextrap", "sub": "user-123", "nonce": nonce,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"email": "Alice@Acme.com", "email_verified": true, "groups": []string{"dev", "admins"},
		}
		for k, v := range idp.claims {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": idp.sign(claims), "token_type": "Bearer"})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) sign(claims map[string]any) string {
	alg, kid := "RS256", idp.kid
	if idp.signWith == "ec" {
		alg, kid = "ES256", "ec1"
	}
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := b64(hdr) + "." + b64(body)
	h := sha256.Sum256([]byte(input))
	var sig []byte
	switch idp.signWith {
	case "ec":
		r, s, err := ecdsa.Sign(rand.Reader, idp.ecKey, h[:])
		require.NoError(idp.t, err)
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "wrong-key":
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		sig, _ = rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, h[:])
	default:
		sig, _ = rsa.SignPKCS1v15(rand.Reader, idp.rsaKey, crypto.SHA256, h[:])
	}
	return input + "." + b64(sig)
}

type harness struct {
	idp    *fakeIdP
	flow   *Flow
	app    *httptest.Server
	client *http.Client
	logins []identity.Principal
}

func newHarness(t *testing.T, cfg Config) *harness {
	h := &harness{idp: newIdP(t)}
	h.app = httptest.NewServer(nil)
	t.Cleanup(h.app.Close)
	cfg.Issuer = h.idp.srv.URL
	cfg.ClientID = "hextrap"
	cfg.ClientSecret = "s3cret"
	cfg.RedirectURL = h.app.URL + "/auth/callback"
	cfg.CookieSecret = "0123456789abcdef0123456789abcdef"
	p, err := NewProvider(context.Background(), cfg, http.DefaultClient, func() time.Time { return now })
	require.NoError(t, err)
	h.flow = NewFlow(p, NewMemorySessions(), "default", func(pr identity.Principal) error {
		h.logins = append(h.logins, pr)
		return nil
	})
	mux := http.NewServeMux()
	mux.Handle("/auth/", h.flow)
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		pr, ok := h.flow.Authenticate(r)
		if !ok {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(pr)
	})
	h.app.Config.Handler = mux
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

// login runs the browser flow; the fake IdP "approves" by minting a code.
func (h *harness) login(t *testing.T) *http.Response {
	resp, err := h.client.Get(h.app.URL + "/auth/login")
	require.NoError(t, err)
	require.Equal(t, 302, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	q := loc.Query()
	h.idp.mu.Lock()
	h.idp.codes["code-1"] = q.Get("nonce")
	h.idp.verifiers["code-1"] = q.Get("code_challenge")
	h.idp.mu.Unlock()
	resp, err = h.client.Get(h.app.URL + "/auth/callback?code=code-1&state=" + url.QueryEscape(q.Get("state")))
	require.NoError(t, err)
	return resp
}

func (h *harness) whoami(t *testing.T) (int, identity.Principal) {
	resp, err := h.client.Get(h.app.URL + "/whoami")
	require.NoError(t, err)
	defer resp.Body.Close()
	var p identity.Principal
	if resp.StatusCode == 200 {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&p))
	}
	return resp.StatusCode, p
}

func TestLoginRedirect(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, Config{})
	resp, err := h.client.Get(h.app.URL + "/auth/login")
	r.NoError(err)
	r.Equal(302, resp.StatusCode)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	r.Equal(h.idp.srv.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()
	r.Equal("code", q.Get("response_type"))
	r.Equal("hextrap", q.Get("client_id"))
	r.Equal(h.app.URL+"/auth/callback", q.Get("redirect_uri"))
	r.Equal("S256", q.Get("code_challenge_method"))
	r.Contains(q.Get("scope"), "openid")
	r.NotEmpty(q.Get("state"))
	r.NotEmpty(q.Get("nonce"))
	r.NotEmpty(q.Get("code_challenge"))
}

func TestLoginCreatesSession(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, Config{})
	resp := h.login(t)
	r.Equal(302, resp.StatusCode)
	r.Equal("/", resp.Header.Get("Location"))

	code, p := h.whoami(t)
	r.Equal(200, code)
	r.Equal(identity.KindUser, p.Kind)
	r.Equal("default", p.Tenant)
	r.Equal("user-123", p.Subject)
	r.Equal("alice@acme.com", p.Email, "emails are lowercased")
	r.Equal([]string{"dev", "admins"}, p.Groups)
	r.Len(h.logins, 1, "login hook runs (refreshes token group snapshots)")
	r.Equal("s3cret", h.idp.lastTokenReq.Get("client_secret"))
}

func TestES256(t *testing.T) {
	h := newHarness(t, Config{})
	h.idp.signWith = "ec"
	require.Equal(t, 302, h.login(t).StatusCode)
	code, _ := h.whoami(t)
	require.Equal(t, 200, code)
}

func TestRejectedTokens(t *testing.T) {
	for _, tc := range []struct {
		name     string
		claims   map[string]any
		signWith string
	}{
		{"bad signature", nil, "wrong-key"},
		{"wrong audience", map[string]any{"aud": "someone-else"}, ""},
		{"wrong issuer", map[string]any{"iss": "https://evil.example"}, ""},
		{"expired", map[string]any{"exp": now.Add(-time.Minute).Unix()}, ""},
		{"wrong nonce", map[string]any{"nonce": "replayed"}, ""},
		{"no subject", map[string]any{"sub": ""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.idp.claims = tc.claims
			if tc.signWith != "" {
				h.idp.signWith = tc.signWith
			}
			resp := h.login(t)
			require.Equal(t, 401, resp.StatusCode)
			code, _ := h.whoami(t)
			require.Equal(t, 401, code)
			require.Empty(t, h.logins)
		})
	}
}

func TestAudienceArray(t *testing.T) {
	h := newHarness(t, Config{})
	h.idp.claims = map[string]any{"aud": []string{"other", "hextrap"}}
	require.Equal(t, 302, h.login(t).StatusCode)
}

func TestStateMustMatch(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, Config{})
	resp, _ := h.client.Get(h.app.URL + "/auth/login")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	h.idp.codes["c"] = loc.Query().Get("nonce")
	resp, err := h.client.Get(h.app.URL + "/auth/callback?code=c&state=forged")
	r.NoError(err)
	r.Equal(400, resp.StatusCode)

	// Without the state cookie (e.g. a login link sent to someone else).
	fresh := &http.Client{CheckRedirect: h.client.CheckRedirect}
	resp, err = fresh.Get(h.app.URL + "/auth/callback?code=c&state=" + url.QueryEscape(loc.Query().Get("state")))
	r.NoError(err)
	r.Equal(400, resp.StatusCode)
}

func TestUnverifiedEmailIsDropped(t *testing.T) {
	for _, v := range []any{false, "false"} { // some IdPs send a string
		h := newHarness(t, Config{})
		h.idp.claims = map[string]any{"email_verified": v}
		require.Equal(t, 302, h.login(t).StatusCode)
		_, p := h.whoami(t)
		require.Empty(t, p.Email, "an unverified email must not match email grants (%#v)", v)
	}
}

func TestCustomGroupsClaim(t *testing.T) {
	h := newHarness(t, Config{GroupsClaim: "roles"})
	h.idp.claims = map[string]any{"roles": []string{"platform"}, "groups": nil}
	require.Equal(t, 302, h.login(t).StatusCode)
	_, p := h.whoami(t)
	require.Equal(t, []string{"platform"}, p.Groups)
}

func TestMissingGroupsClaimMeansNoGroups(t *testing.T) {
	h := newHarness(t, Config{})
	h.idp.claims = map[string]any{"groups": nil}
	require.Equal(t, 302, h.login(t).StatusCode)
	_, p := h.whoami(t)
	require.Empty(t, p.Groups)
}

func TestTenantClaim(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, Config{TenantClaim: "org"})
	h.idp.claims = map[string]any{"org": "acme"}
	r.Equal(302, h.login(t).StatusCode)
	_, p := h.whoami(t)
	r.Equal("acme", p.Tenant)

	h2 := newHarness(t, Config{TenantClaim: "org"})
	r.Equal(401, h2.login(t).StatusCode, "tenant claim required when configured")
}

func TestKeyRotationRefetchesJWKS(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, Config{})
	r.Equal(302, h.login(t).StatusCode)
	before := h.idp.jwksFetches

	h.idp.mu.Lock()
	h.idp.kid = "k2"
	h.idp.mu.Unlock()
	h.client.Jar, _ = cookiejar.New(nil)
	r.Equal(302, h.login(t).StatusCode)
	r.Equal(before+1, h.idp.jwksFetches)
}

func TestLogout(t *testing.T) {
	h := newHarness(t, Config{})
	h.login(t)
	resp, err := h.client.Post(h.app.URL+"/auth/logout", "", nil)
	require.NoError(t, err)
	require.Equal(t, 302, resp.StatusCode)
	code, _ := h.whoami(t)
	require.Equal(t, 401, code)
}

func TestSessionExpires(t *testing.T) {
	s := newTestSessions(t)
	id, err := s.Create(identity.Principal{Kind: identity.KindUser, Subject: "x"}, now.Add(time.Hour))
	require.NoError(t, err)
	_, ok := s.Get(id, now.Add(59*time.Minute))
	require.True(t, ok)
	_, ok = s.Get(id, now.Add(61*time.Minute))
	require.False(t, ok)
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": "https://other.example", "authorization_endpoint": "x", "token_endpoint": "x", "jwks_uri": "x"})
	}))
	defer srv.Close()
	_, err := NewProvider(context.Background(), Config{Issuer: srv.URL, ClientID: "c", CookieSecret: strings.Repeat("x", 32)}, http.DefaultClient, time.Now)
	require.Error(t, err)
}
