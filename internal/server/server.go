// Package server is the artifact repository's HTTP entry point: it resolves
// the tenant, authenticates, rate limits, and routes to the npm, PyPI and
// management API handlers.
package server

import (
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"

	"hextrap.io/artifacts/internal/formats/cargo"
	"hextrap.io/artifacts/internal/formats/gomod"
	"hextrap.io/artifacts/internal/formats/maven"
	"hextrap.io/artifacts/internal/formats/npm"
	"hextrap.io/artifacts/internal/formats/oci"
	"hextrap.io/artifacts/internal/formats/pypi"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/tokens"
)

// SessionAuth authenticates browser sessions (the OIDC flow).
type SessionAuth interface {
	Authenticate(r *http.Request) (identity.Principal, bool)
}

type Options struct {
	Registry *registry.Service
	Tokens   *tokens.Manager
	// Sessions and Auth are nil when OIDC isn't configured.
	Sessions SessionAuth
	Auth     http.Handler
	UI       http.Handler
	Admins   identity.InstanceAdmins
	Guard    *ratelimit.Guard
	// Tenant resolves the tenant from the request; "" means unknown host.
	Tenant  func(*http.Request) string
	BaseURL func(*http.Request) string
	// ClientIP defaults to the connection's remote address.
	ClientIP func(*http.Request) string
	// GoChecksumDB verifies Go modules before they're cached; empty disables it.
	GoChecksumDB string
	// Firewalls are hextrap firewall upstreams and the credentials to send them.
	Firewalls []Firewall
}

// Firewall is a hextrap firewall a proxy repo can use as its upstream.
type Firewall struct {
	URL, Username, Password string
}

type Server struct {
	opts      Options
	protocols []*area
	api       *http.ServeMux
}

func New(opts Options) *Server {
	if opts.ClientIP == nil {
		opts.ClientIP = RemoteAddrIP
	}
	s := &Server{
		opts: opts,
		api:  http.NewServeMux(),
		protocols: []*area{
			{prefix: npm.Prefix, handler: withFirewalls(npm.New(opts.Registry, opts.BaseURL), opts)},
			{prefix: pypi.Prefix, handler: withFirewalls(pypi.New(opts.Registry, opts.BaseURL), opts), basicAuth: true, textErrors: true},
			{prefix: maven.Prefix, handler: maven.New(opts.Registry), basicAuth: true, textErrors: true},
			{prefix: gomod.Prefix, handler: goHandler(opts), basicAuth: true, textErrors: true},
			{prefix: oci.Prefix, handler: oci.New(opts.Registry), basicAuth: true, errorBody: oci.ErrorBody},
			{prefix: cargo.Prefix, handler: withFirewalls(cargo.New(opts.Registry, opts.BaseURL), opts), errorBody: func(_ int, msg string) any {
				return map[string]any{"errors": []map[string]string{{"detail": msg}}}
			}},
		},
	}
	for _, rt := range s.apiRoutes() {
		s.api.HandleFunc(rt.Method+" "+rt.Pattern, rt.handler)
	}
	if s.opts.UI == nil {
		s.opts.UI = http.HandlerFunc(s.home)
	}
	return s
}

func SingleTenant(name string) func(*http.Request) string {
	return func(*http.Request) string { return name }
}

// SubdomainTenant maps "<tenant>.<base>" to tenant (cloud mode).
func SubdomainTenant(base string) func(*http.Request) string {
	return func(r *http.Request) string {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		t, ok := strings.CutSuffix(strings.ToLower(host), "."+base)
		if !ok || t == "" || strings.Contains(t, ".") {
			return ""
		}
		return t
	}
}

// ForwardedForIP takes the rightmost X-Forwarded-For entry: the one the load
// balancer appended. Entries to its left are client-controlled.
func ForwardedForIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return RemoteAddrIP(r)
	}
	parts := strings.Split(xff, ",")
	return strings.TrimSpace(parts[len(parts)-1])
}

func RemoteAddrIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// protocolHandler serves one package format's client protocol.
type protocolHandler interface {
	http.Handler
	Op(r *http.Request) ratelimit.Op
}

// area is the part of the server a path belongs to. It decides how errors
// are written, so each client can display them.
type area struct {
	prefix  string
	handler protocolHandler // nil for the API, auth and UI
	// basicAuth: the client only sends credentials after a Basic challenge
	// (pip, Maven). Others get a Bearer challenge.
	basicAuth  bool
	textErrors bool
	// errorBody, if set, shapes JSON errors for clients that expect their own
	// format (Cargo prints errors[].detail).
	errorBody func(status int, msg string) any
}

var (
	areaAPI  = &area{prefix: "/api/"}
	areaAuth = &area{prefix: "/auth/", textErrors: true}
	areaUI   = &area{textErrors: true}
)

func (s *Server) areaOf(path string) *area {
	for _, a := range s.protocols {
		if strings.HasPrefix(path, a.prefix) {
			return a
		}
	}
	switch {
	case strings.HasPrefix(path, areaAPI.prefix):
		return areaAPI
	case strings.HasPrefix(path, areaAuth.prefix):
		return areaAuth
	}
	return areaUI
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail writes an error in the format the area's clients display.
func fail(w http.ResponseWriter, a *area, status int, msg string) {
	if status == http.StatusUnauthorized {
		if a.basicAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="hextrap"`)
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="hextrap"`)
		}
	}
	if a.textErrors {
		http.Error(w, msg, status)
		return
	}
	if a.errorBody != nil {
		writeJSON(w, status, a.errorBody(status, msg))
		return
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) op(r *http.Request, a *area) ratelimit.Op {
	if a.handler != nil {
		return a.handler.Op(r)
	}
	if a == areaAuth {
		return ratelimit.OpAuth
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return ratelimit.OpRead
	}
	if r.URL.Path == "/api/v1/tokens" || strings.HasSuffix(r.URL.Path, "/service-tokens") {
		return ratelimit.OpAuth
	}
	return ratelimit.OpPublish
}

// authenticate returns the request's principal. A credential that is
// presented but invalid, or belongs to another tenant, is an error rather
// than a fallback to anonymous.
func (s *Server) authenticate(r *http.Request, tenant string, a *area) (p identity.Principal, viaSession bool, ok bool) {
	if raw := tokens.FromRequest(r); raw != "" {
		p, err := s.opts.Tokens.Authenticate(raw)
		if err != nil || p.Tenant != tenant {
			return identity.Principal{}, false, false
		}
		p.InstanceAdmin = s.opts.Admins.Matches(p)
		return p, false, true
	}
	// Browser sessions only authenticate the API and UI. Package clients
	// use tokens, so a cross-site form post can't publish as the user.
	if s.opts.Sessions != nil && (a == areaAPI || a == areaUI) {
		if p, found := s.opts.Sessions.Authenticate(r); found {
			if p.Tenant != tenant {
				return identity.Principal{}, false, false
			}
			p.InstanceAdmin = s.opts.Admins.Matches(p)
			return p, true, true
		}
	}
	return identity.Anonymous(tenant), false, true
}

// crossSiteSendable reports whether a browser could send this request
// cross-site without a CORS preflight. PUT, PATCH and DELETE always need
// one, and we never grant it.
func crossSiteSendable(r *http.Request) bool {
	return r.Method == http.MethodPost
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}
	a := s.areaOf(r.URL.Path)
	tenant := s.opts.Tenant(r)
	if tenant == "" {
		fail(w, a, http.StatusNotFound, "unknown host")
		return
	}

	p := identity.Anonymous(tenant)
	viaSession := false
	if a != areaAuth {
		var ok bool
		if p, viaSession, ok = s.authenticate(r, tenant, a); !ok {
			fail(w, a, http.StatusUnauthorized, "invalid or expired credentials")
			return
		}
	}

	// Cookie-authenticated POSTs must be JSON: browsers can't send that
	// cross-site without a CORS preflight, which we never grant.
	if viaSession && a == areaAPI && crossSiteSendable(r) {
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mt != "application/json" {
			fail(w, a, http.StatusUnsupportedMediaType, "requests must be application/json")
			return
		}
	}

	ip := s.opts.ClientIP(r)
	if s.opts.Guard != nil {
		d := s.opts.Guard.Check(r.Context(), ratelimit.Request{
			Tenant: tenant, Principal: p.RateLimitKey(), IP: ip, Op: s.op(r, a),
		})
		ratelimit.WriteHeaders(w, d)
		if !d.Allowed {
			fail(w, a, http.StatusTooManyRequests, fmt.Sprintf("rate limit exceeded for %s; retry after %ss", d.Scope, w.Header().Get("Retry-After")))
			return
		}
	}

	ctx := registry.WithSourceIP(identity.WithPrincipal(r.Context(), p), ip)
	r = r.WithContext(ctx)
	if a.handler != nil {
		a.handler.ServeHTTP(w, r)
		return
	}
	switch a {
	case areaAPI:
		s.api.ServeHTTP(w, r)
	case areaAuth:
		if s.opts.Auth == nil {
			fail(w, a, http.StatusNotFound, "login is not configured")
			return
		}
		s.opts.Auth.ServeHTTP(w, r)
	default:
		s.opts.UI.ServeHTTP(w, r)
	}
}

// Route describes an endpoint for documentation and the tenant isolation
// test, which calls every route as another tenant.
type Route struct {
	Method  string
	Pattern string
	// Example is a concrete path with {placeholders} for test values.
	Example string
	// RepoScoped routes act on one repository and must never succeed for a
	// principal without access to it.
	RepoScoped bool
}

// formatRoutes lists the npm and PyPI protocol endpoints. The handlers
// parse their own paths, so keep this list in step with them.
var formatRoutes = []Route{
	{Method: "GET", Example: "/npm/{repo}/{pkg}", RepoScoped: true},
	{Method: "PUT", Example: "/npm/{repo}/{pkg}", RepoScoped: true},
	{Method: "GET", Example: "/npm/{repo}/{pkg}/-/{file}", RepoScoped: true},
	{Method: "PUT", Example: "/npm/{repo}/{pkg}/-rev/1-x", RepoScoped: true},
	{Method: "DELETE", Example: "/npm/{repo}/{pkg}/-rev/1-x", RepoScoped: true},
	{Method: "DELETE", Example: "/npm/{repo}/{pkg}/-/{file}/-rev/1-x", RepoScoped: true},
	{Method: "GET", Example: "/npm/{repo}/-/package/{pkg}/dist-tags", RepoScoped: true},
	{Method: "PUT", Example: "/npm/{repo}/-/package/{pkg}/dist-tags/{tag}", RepoScoped: true},
	{Method: "DELETE", Example: "/npm/{repo}/-/package/{pkg}/dist-tags/beta", RepoScoped: true},
	{Method: "GET", Example: "/npm/{repo}/-/whoami"},
	{Method: "GET", Example: "/npm/{repo}/-/ping"},
	{Method: "POST", Example: "/pypi/{repo}/", RepoScoped: true},
	{Method: "GET", Example: "/pypi/{repo}/simple/", RepoScoped: true},
	{Method: "GET", Example: "/pypi/{repo}/simple/{pkg}/", RepoScoped: true},
	{Method: "GET", Example: "/pypi/{repo}/files/{pkg}/{file}", RepoScoped: true},
	{Method: "GET", Example: "/maven/{repo}/com/acme/{pkg}/1.0.0/{pkg}-1.0.0.jar", RepoScoped: true},
	{Method: "PUT", Example: "/maven/{repo}/com/acme/{pkg}/1.0.0/{pkg}-1.0.0.jar", RepoScoped: true},
	{Method: "GET", Example: "/maven/{repo}/com/acme/{pkg}/maven-metadata.xml", RepoScoped: true},
	{Method: "GET", Example: "/go/{repo}/example.com/secret-pkg/@v/list", RepoScoped: true},
	{Method: "GET", Example: "/v2/{repo}/secret-pkg/manifests/latest", RepoScoped: true},
	{Method: "PUT", Example: "/v2/{repo}/secret-pkg/manifests/latest", RepoScoped: true},
	{Method: "POST", Example: "/v2/{repo}/secret-pkg/blobs/uploads/", RepoScoped: true},
	{Method: "GET", Example: "/v2/{repo}/secret-pkg/tags/list", RepoScoped: true},
	{Method: "GET", Example: "/go/{repo}/example.com/secret-pkg/@v/v1.0.0.zip", RepoScoped: true},
	{Method: "GET", Example: "/cargo/{repo}/index/config.json", RepoScoped: true},
	{Method: "GET", Example: "/cargo/{repo}/index/se/cr/secret-pkg", RepoScoped: true},
	{Method: "PUT", Example: "/cargo/{repo}/api/v1/crates/new", RepoScoped: true},
	{Method: "GET", Example: "/cargo/{repo}/api/v1/crates/secret-pkg/1.0.0/download", RepoScoped: true},
	{Method: "DELETE", Example: "/cargo/{repo}/api/v1/crates/secret-pkg/1.0.0/yank", RepoScoped: true},
}

// Routes returns every endpoint: the API table the server registers, plus
// the protocol endpoints.
func Routes() []Route {
	var out []Route
	for _, rt := range (&Server{}).apiRoutes() {
		out = append(out, rt.Route)
	}
	return append(out, formatRoutes...)
}

func goHandler(opts Options) *gomod.Handler {
	h := withFirewalls(gomod.New(opts.Registry), opts)
	h.SetSumDB(opts.GoChecksumDB)
	return h
}

// withFirewalls gives a format's proxy the firewall credentials. Each is sent
// only to its own host.
func withFirewalls[H interface {
	AddFirewall(url, username, password string)
}](h H, opts Options) H {
	for _, fw := range opts.Firewalls {
		h.AddFirewall(fw.URL, fw.Username, fw.Password)
	}
	return h
}
