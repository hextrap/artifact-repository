package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"hextrap.io/artifacts/internal/edition"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/tokens"
)

type apiRoute struct {
	Route
	handler http.HandlerFunc
}

func (s *Server) apiRoutes() []apiRoute {
	r := func(method, pattern, example string, repoScoped bool, h http.HandlerFunc) apiRoute {
		return apiRoute{Route{Method: method, Pattern: pattern, Example: example, RepoScoped: repoScoped}, h}
	}
	const repo = "/api/v1/repos/{repo}"
	return []apiRoute{
		r("GET", "/api/v1/me", "/api/v1/me", false, s.me),
		r("GET", "/api/v1/usage", "/api/v1/usage", false, s.usage),
		r("GET", "/api/v1/upstreams", "/api/v1/upstreams", false, s.upstreams),
		r("GET", "/api/v1/tokens", "/api/v1/tokens", false, s.listTokens),
		r("POST", "/api/v1/tokens", "/api/v1/tokens", false, s.createToken),
		r("DELETE", "/api/v1/tokens/{id}", "/api/v1/tokens/{id}", false, s.revokeToken),
		r("GET", "/api/v1/repos", "/api/v1/repos", false, s.listRepos),
		r("POST", "/api/v1/repos", "/api/v1/repos", false, s.createRepo),
		r("GET", repo, repo, true, s.getRepo),
		r("PATCH", repo, repo, true, s.updateRepo),
		r("DELETE", repo, repo, true, s.deleteRepo),
		r("GET", repo+"/grants", repo+"/grants", true, s.listGrants),
		r("PUT", repo+"/grants", repo+"/grants", true, s.setGrant),
		r("DELETE", repo+"/grants", repo+"/grants?subject_kind=user&subject=alice%40acme.com", true, s.removeGrant),
		r("GET", repo+"/packages", repo+"/packages", true, s.listPackages),
		r("GET", repo+"/versions", repo+"/versions?package={pkg}", true, s.listVersions),
		r("POST", repo+"/versions/{action}", repo+"/versions/{action}", true, s.versionAction),
		r("GET", repo+"/trash", repo+"/trash", true, s.trash),
		r("GET", repo+"/audit", repo+"/audit", true, s.audit),
		r("GET", repo+"/service-tokens", repo+"/service-tokens", true, s.listServiceTokens),
		r("POST", repo+"/service-tokens", repo+"/service-tokens", true, s.createServiceToken),
		r("DELETE", repo+"/service-tokens/{id}", repo+"/service-tokens/{id}", true, s.revokeServiceToken),
	}
}

func apiError(w http.ResponseWriter, err error) {
	status := registry.HTTPStatus(err)
	msg := registry.PublicMessage(err)
	switch {
	case errors.Is(err, tokens.ErrNotFound):
		status, msg = http.StatusNotFound, err.Error()
	case errors.Is(err, tokens.ErrForbidden):
		status, msg = http.StatusForbidden, err.Error()
	case errors.Is(err, errBadJSON):
		status, msg = http.StatusBadRequest, err.Error()
	}
	if status == http.StatusInternalServerError {
		slog.Error("api request failed", "err", err)
	}
	fail(w, areaAPI, status, msg)
}

var errBadJSON = errors.New("malformed JSON body")

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		return errBadJSON
	}
	return nil
}

func principal(r *http.Request) identity.Principal { return identity.FromContext(r.Context()) }

// requireUser rejects anonymous and service-token callers.
func requireUser(w http.ResponseWriter, p identity.Principal) bool {
	switch p.Kind {
	case identity.KindUser:
		return true
	case identity.KindAnonymous:
		apiError(w, registry.ErrUnauthenticated)
	default:
		apiError(w, registry.ErrForbidden)
	}
	return false
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind == identity.KindAnonymous {
		apiError(w, registry.ErrUnauthenticated)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": p.Tenant, "kind": p.Kind, "subject": p.Subject, "email": p.Email,
		"groups": nonNil(p.Groups), "instance_admin": p.InstanceAdmin, "edition": edition.Name,
	})
}

func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind == identity.KindAnonymous {
		apiError(w, registry.ErrUnauthenticated)
		return
	}
	n, err := s.opts.Registry.StorageUsed(r.Context(), p)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"storage_bytes": n})
}

// --- Personal tokens ---

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !requireUser(w, p) {
		return
	}
	list, err := s.opts.Tokens.ListPersonal(p)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

type tokenRequest struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	LifetimeDays int    `json:"lifetime_days"`
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !requireUser(w, p) {
		return
	}
	// Only a browser login can mint tokens; otherwise a token could renew
	// itself forever without the IdP being consulted.
	if p.TokenID != "" {
		apiError(w, tokens.ErrForbidden)
		return
	}
	var in tokenRequest
	if err := decode(r, &in); err != nil {
		apiError(w, err)
		return
	}
	raw, info, err := s.opts.Tokens.IssuePersonal(p, in.Name, time.Duration(in.LifetimeDays)*24*time.Hour)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "info": info})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !requireUser(w, p) {
		return
	}
	if err := s.opts.Tokens.RevokePersonal(p, r.PathValue("id")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Repositories ---

func (s *Server) listRepos(w http.ResponseWriter, r *http.Request) {
	repos, err := s.opts.Registry.ListRepos(r.Context(), principal(r))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(repos))
}

func (s *Server) createRepo(w http.ResponseWriter, r *http.Request) {
	var in registry.RepoInput
	if err := decode(r, &in); err != nil {
		apiError(w, err)
		return
	}
	p := principal(r)
	if err := s.opts.Registry.CreateRepo(r.Context(), p, in); err != nil {
		apiError(w, err)
		return
	}
	repo, err := s.opts.Registry.Repo(r.Context(), p, in.Name)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, repo)
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request) {
	repo, err := s.opts.Registry.Repo(r.Context(), principal(r), r.PathValue("repo"))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, repo)
}

func (s *Server) updateRepo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AnonymousRead   *bool   `json:"anonymous_read"`
		DeleteGraceDays *int    `json:"delete_grace_days"`
		Upstream        *string `json:"upstream"`
	}
	if err := decode(r, &in); err != nil {
		apiError(w, err)
		return
	}
	settings := registry.SettingsInput{AnonymousRead: in.AnonymousRead, Upstream: in.Upstream}
	if in.DeleteGraceDays != nil {
		d := time.Duration(*in.DeleteGraceDays) * 24 * time.Hour
		settings.DeleteGrace = &d
	}
	p, name := principal(r), r.PathValue("repo")
	if err := s.opts.Registry.UpdateSettings(r.Context(), p, name, settings); err != nil {
		apiError(w, err)
		return
	}
	repo, err := s.opts.Registry.Repo(r.Context(), p, name)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, repo)
}

func (s *Server) deleteRepo(w http.ResponseWriter, r *http.Request) {
	if err := s.opts.Registry.DeleteRepo(r.Context(), principal(r), r.PathValue("repo")); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Access ---

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.opts.Registry.Grants(r.Context(), principal(r), r.PathValue("repo"))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(grants))
}

func (s *Server) setGrant(w http.ResponseWriter, r *http.Request) {
	var g rbac.Grant
	if err := decode(r, &g); err != nil {
		apiError(w, err)
		return
	}
	if err := s.opts.Registry.SetGrant(r.Context(), principal(r), r.PathValue("repo"), g); err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) removeGrant(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	err := s.opts.Registry.RemoveGrant(r.Context(), principal(r), r.PathValue("repo"),
		rbac.SubjectKind(q.Get("subject_kind")), q.Get("subject"))
	if err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Packages and versions ---

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) {
	pkgs, err := s.opts.Registry.PackageSummaries(r.Context(), principal(r), r.PathValue("repo"))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(pkgs))
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := s.opts.Registry.Versions(r.Context(), principal(r), r.PathValue("repo"), r.URL.Query().Get("package"))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(versions))
}

func (s *Server) versionAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Package string `json:"package"`
		Version string `json:"version"`
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		apiError(w, err)
		return
	}
	ctx, p, repo, reg := r.Context(), principal(r), r.PathValue("repo"), s.opts.Registry
	var err error
	switch r.PathValue("action") {
	case "yank":
		err = reg.Yank(ctx, p, repo, in.Package, in.Version, in.Reason)
	case "unyank":
		err = reg.Unyank(ctx, p, repo, in.Package, in.Version)
	case "delete":
		err = reg.Delete(ctx, p, repo, in.Package, in.Version)
	case "restore":
		err = reg.Restore(ctx, p, repo, in.Package, in.Version)
	case "purge":
		err = reg.Purge(ctx, p, repo, in.Package, in.Version, in.Confirm)
	default:
		err = registry.ErrNotFound
	}
	if err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) trash(w http.ResponseWriter, r *http.Request) {
	versions, err := s.opts.Registry.Trash(r.Context(), principal(r), r.PathValue("repo"))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(versions))
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = 100
	}
	entries, err := s.opts.Registry.Audit(r.Context(), principal(r), r.PathValue("repo"), min(limit, 1000))
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(entries))
}

// --- Service tokens ---

func (s *Server) listServiceTokens(w http.ResponseWriter, r *http.Request) {
	p, repo := principal(r), r.PathValue("repo")
	// Managing service tokens is managing access.
	if _, err := s.opts.Registry.Grants(r.Context(), p, repo); err != nil {
		apiError(w, err)
		return
	}
	list, err := s.opts.Tokens.ListService(p.Tenant, repo)
	if err != nil {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(list))
}

func (s *Server) createServiceToken(w http.ResponseWriter, r *http.Request) {
	ctx, p, repo := r.Context(), principal(r), r.PathValue("repo")
	if _, err := s.opts.Registry.Grants(ctx, p, repo); err != nil {
		apiError(w, err)
		return
	}
	var in tokenRequest
	if err := decode(r, &in); err != nil {
		apiError(w, err)
		return
	}
	role, err := rbac.ParseRole(in.Role)
	if err == nil {
		err = rbac.ValidateGrant(rbac.Grant{SubjectKind: rbac.SubjectServiceToken, Subject: "new", Role: role})
	}
	if err != nil {
		apiError(w, errors.Join(registry.ErrInvalid, err))
		return
	}
	raw, info, err := s.opts.Tokens.IssueService(p.Tenant, repo, in.Name, p, time.Duration(in.LifetimeDays)*24*time.Hour)
	if err != nil {
		apiError(w, err)
		return
	}
	grant := rbac.Grant{SubjectKind: rbac.SubjectServiceToken, Subject: info.ID, Role: role}
	if err := s.opts.Registry.SetGrant(ctx, p, repo, grant); err != nil {
		_ = s.opts.Tokens.RevokeService(p.Tenant, repo, info.ID)
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "info": info, "role": role})
}

func (s *Server) revokeServiceToken(w http.ResponseWriter, r *http.Request) {
	ctx, p, repo, id := r.Context(), principal(r), r.PathValue("repo"), r.PathValue("id")
	if _, err := s.opts.Registry.Grants(ctx, p, repo); err != nil {
		apiError(w, err)
		return
	}
	if err := s.opts.Tokens.RevokeService(p.Tenant, repo, id); err != nil {
		apiError(w, err)
		return
	}
	if err := s.opts.Registry.RemoveGrant(ctx, p, repo, rbac.SubjectServiceToken, id); err != nil && !errors.Is(err, registry.ErrNotFound) {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// upstreams lists the registries proxy repositories may use, per format.
func (s *Server) upstreams(w http.ResponseWriter, r *http.Request) {
	if principal(r).Kind == identity.KindAnonymous {
		apiError(w, registry.ErrUnauthenticated)
		return
	}
	type choice struct {
		URL      string `json:"url"`
		Firewall bool   `json:"firewall"`
	}
	out := map[registry.Format][]choice{}
	for format, urls := range s.opts.Registry.Upstreams() {
		for _, u := range urls {
			out[format] = append(out[format], choice{URL: u, Firewall: s.opts.Registry.IsFirewall(u)})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
