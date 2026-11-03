package server

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
	"unicode"

	"hextrap.io/artifacts/internal/edition"
	"hextrap.io/artifacts/internal/identity"
)

// The web UI: a page shell rendered here, plus a script that drives the
// management API. Everything is embedded, so the UI makes no requests
// outside this server.

//go:embed ui
var uiFiles embed.FS

var indexTmpl = template.Must(template.ParseFS(uiFiles, "ui/index.html"))

var uiAssets = map[string]string{
	"/ui/app.js":      "text/javascript; charset=utf-8",
	"/ui/app.css":     "text/css; charset=utf-8",
	"/ui/favicon.svg": "image/svg+xml",
}

const uiCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func uiHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", uiCSP)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
}

func initials(name string) string {
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return strings.ToUpper(string(r))
		}
	}
	return "?"
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	uiHeaders(w)
	if ctype, ok := uiAssets[r.URL.Path]; ok {
		b, err := uiFiles.ReadFile("ui/" + strings.TrimPrefix(r.URL.Path, "/ui/"))
		if err != nil {
			fail(w, areaUI, http.StatusNotFound, "not found")
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
		return
	}
	if r.URL.Path != "/" {
		fail(w, areaUI, http.StatusNotFound, "not found")
		return
	}

	p := identity.FromContext(r.Context())
	if p.Kind != identity.KindUser {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	role := "Member"
	if p.InstanceAdmin {
		role = "Instance admin"
	}
	name := p.Actor()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = indexTmpl.Execute(w, map[string]string{
		"BaseURL":  s.opts.BaseURL(r),
		"Name":     name,
		"Initials": initials(name),
		"Role":     role,
		"Edition":  map[string]string{"self-hosted": "Self-hosted", "cloud": "Cloud"}[edition.Name],
	})
}
