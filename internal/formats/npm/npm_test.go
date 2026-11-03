package npm

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
)

func user(email string) identity.Principal {
	return identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub|" + email, Email: email}
}

var principals = map[string]identity.Principal{
	"admin":      user("admin@acme.com"),
	"maintainer": user("maint@acme.com"),
	"developer":  user("dev@acme.com"),
	"reader":     user("reader@acme.com"),
	"stranger":   user("stranger@acme.com"),
}

type env struct {
	t   *testing.T
	srv *httptest.Server
	svc *registry.Service
}

func newEnv(t *testing.T) *env {
	svc := registry.New(registry.NewMemoryStore(), blob.NewMemory(), func() time.Time {
		return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	}, nil)
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "internal", Format: registry.FormatNPM}))
	for name, role := range map[string]rbac.Role{"maintainer": rbac.RoleMaintainer, "developer": rbac.RoleDeveloper, "reader": rbac.RoleReader} {
		require.NoError(t, svc.SetGrant(ctx, admin, "internal", rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: principals[name].Email, Role: role}))
	}

	e := &env{t: t, svc: svc}
	var h *Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			p = principals[tok]
		}
		h.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	h = New(svc, func(*http.Request) string { return e.srv.URL })
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(method, path, as string, body any) (int, []byte, http.Header) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		require.NoError(e.t, err)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	require.NoError(e.t, err)
	if as != "" {
		req.Header.Set("Authorization", "Bearer "+as)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	return resp.StatusCode, out, resp.Header
}

// publishBody builds the document `npm publish` sends.
func publishBody(name, version, tarball string, tags map[string]string) map[string]any {
	sha1sum := sha1.Sum([]byte(tarball))
	sha512sum := sha512.Sum512([]byte(tarball))
	base := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		base = name[i+1:]
	}
	if tags == nil {
		tags = map[string]string{"latest": version}
	}
	return map[string]any{
		"_id":         name,
		"name":        name,
		"description": "test package",
		"dist-tags":   tags,
		"versions": map[string]any{
			version: map[string]any{
				"name": name, "version": version, "main": "index.js",
				"_id": name + "@" + version, "_npmVersion": "10.8.2", "_nodeVersion": "22.11.0",
				"dist": map[string]any{
					"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sha512sum[:]),
					"shasum":    hex.EncodeToString(sha1sum[:]),
					"tarball":   "http://registry.npmjs.org/" + name + "/-/" + base + "-" + version + ".tgz",
				},
			},
		},
		"access": nil,
		"_attachments": map[string]any{
			name + "-" + version + ".tgz": map[string]any{
				"content_type": "application/octet-stream",
				"data":         base64.StdEncoding.EncodeToString([]byte(tarball)),
				"length":       len(tarball),
			},
		},
	}
}

type packument struct {
	ID       string                    `json:"_id"`
	Name     string                    `json:"name"`
	Rev      string                    `json:"_rev"`
	DistTags map[string]string         `json:"dist-tags"`
	Versions map[string]map[string]any `json:"versions"`
	Time     map[string]string         `json:"time"`
}

func (e *env) packument(path, as string) (int, packument) {
	code, body, _ := e.do("GET", path, as, nil)
	var p packument
	if code == 200 {
		require.NoError(e.t, json.Unmarshal(body, &p))
	}
	return code, p
}

func TestPublishAndInstall(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)

	code, body, _ := e.do("PUT", "/npm/internal/left-pad", "developer", publishBody("left-pad", "1.0.0", "TARBALL", nil))
	r.Equal(201, code, string(body))

	code, p := e.packument("/npm/internal/left-pad", "reader")
	r.Equal(200, code)
	r.Equal("left-pad", p.Name)
	r.Equal(map[string]string{"latest": "1.0.0"}, p.DistTags)
	v := p.Versions["1.0.0"]
	r.Equal("index.js", v["main"], "manifest fields preserved")
	dist := v["dist"].(map[string]any)
	r.Equal(e.srv.URL+"/npm/internal/left-pad/-/left-pad-1.0.0.tgz", dist["tarball"], "tarball URL points at us")
	sum := sha1.Sum([]byte("TARBALL"))
	r.Equal(hex.EncodeToString(sum[:]), dist["shasum"])
	r.True(strings.HasPrefix(dist["integrity"].(string), "sha512-"))
	r.Contains(p.Time, "1.0.0")
	r.Contains(p.Time, "created")
	r.Contains(p.Time, "modified")

	code, tgz, _ := e.do("GET", "/npm/internal/left-pad/-/left-pad-1.0.0.tgz", "reader", nil)
	r.Equal(200, code)
	r.Equal("TARBALL", string(tgz))
}

func TestScopedPackage(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	code, body, _ := e.do("PUT", "/npm/internal/@acme%2futils", "developer", publishBody("@acme/utils", "2.0.0", "SCOPED", nil))
	r.Equal(201, code, string(body))

	for _, path := range []string{"/npm/internal/@acme%2futils", "/npm/internal/@acme%2Futils", "/npm/internal/@acme/utils"} {
		code, p := e.packument(path, "reader")
		r.Equal(200, code, path)
		r.Equal("@acme/utils", p.Name)
		dist := p.Versions["2.0.0"]["dist"].(map[string]any)
		r.Equal(e.srv.URL+"/npm/internal/@acme/utils/-/utils-2.0.0.tgz", dist["tarball"])
	}
	code, tgz, _ := e.do("GET", "/npm/internal/@acme/utils/-/utils-2.0.0.tgz", "reader", nil)
	r.Equal(200, code)
	r.Equal("SCOPED", string(tgz))
}

func TestRepublishRejected(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	code, _, _ := e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "one", nil))
	r.Equal(201, code)
	code, body, _ := e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "two", nil))
	r.Equal(409, code)
	var msg map[string]string
	r.NoError(json.Unmarshal(body, &msg))
	r.Contains(msg["error"], "previously")
}

func TestPublishValidation(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)

	bad := publishBody("p", "1.0.0", "content", nil)
	bad["versions"].(map[string]any)["1.0.0"].(map[string]any)["dist"].(map[string]any)["integrity"] = "sha512-AAAA"
	code, _, _ := e.do("PUT", "/npm/internal/p", "developer", bad)
	r.Equal(400, code, "integrity mismatch")

	bad = publishBody("p", "1.0.0", "content", nil)
	bad["versions"].(map[string]any)["1.0.0"].(map[string]any)["dist"].(map[string]any)["shasum"] = "0000"
	code, _, _ = e.do("PUT", "/npm/internal/p", "developer", bad)
	r.Equal(400, code, "shasum mismatch")

	code, _, _ = e.do("PUT", "/npm/internal/other-name", "developer", publishBody("p", "1.0.0", "content", nil))
	r.Equal(400, code, "URL and body name differ")

	code, _, _ = e.do("PUT", "/npm/internal/Bad-Name", "developer", publishBody("Bad-Name", "1.0.0", "content", nil))
	r.Equal(400, code, "uppercase names are invalid for new packages")

	two := publishBody("p", "1.0.0", "content", nil)
	two["versions"].(map[string]any)["1.0.1"] = two["versions"].(map[string]any)["1.0.0"]
	code, _, _ = e.do("PUT", "/npm/internal/p", "developer", two)
	r.Equal(400, code, "one version per publish")

	code, _, _ = e.do("PUT", "/npm/internal/p", "developer", []byte("{not json"))
	r.Equal(400, code)
}

func TestPublishWithTag(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))
	code, _, _ := e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "2.0.0-beta.1", "b", map[string]string{"beta": "2.0.0-beta.1"}))
	r.Equal(201, code)
	_, p := e.packument("/npm/internal/p", "reader")
	r.Equal(map[string]string{"latest": "1.0.0", "beta": "2.0.0-beta.1"}, p.DistTags)
}

func TestFirstPublishWithTagStillHasLatest(t *testing.T) {
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0-rc.1", "a", map[string]string{"next": "1.0.0-rc.1"}))
	_, p := e.packument("/npm/internal/p", "reader")
	require.Equal(t, "1.0.0-rc.1", p.DistTags["latest"], "npm needs a latest tag to install without a range")
}

func TestDeprecate(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))

	// `npm deprecate` GETs the packument, sets "deprecated", and PUTs it back.
	deprecate := func(as, msg string) int {
		_, body, _ := e.do("GET", "/npm/internal/p", as, nil)
		var doc map[string]any
		r.NoError(json.Unmarshal(body, &doc))
		doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["deprecated"] = msg
		code, _, _ := e.do("PUT", "/npm/internal/p/-rev/"+doc["_rev"].(string), as, doc)
		return code
	}
	r.Equal(403, deprecate("developer", "use q"))
	r.Equal(200, deprecate("maintainer", "use q"))
	_, p := e.packument("/npm/internal/p", "reader")
	r.Equal("use q", p.Versions["1.0.0"]["deprecated"])

	code, _, _ := e.do("GET", "/npm/internal/p/-/p-1.0.0.tgz", "reader", nil)
	r.Equal(200, code, "deprecated versions still install")

	r.Equal(200, deprecate("maintainer", ""))
	_, p = e.packument("/npm/internal/p", "reader")
	r.NotContains(p.Versions["1.0.0"], "deprecated")
}

func TestYankWithoutReasonSurvivesDeprecateRoundTrip(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.1", "b", nil))
	r.NoError(e.svc.Yank(context.Background(), principals["admin"], "internal", "p", "1.0.0", ""))

	_, body, _ := e.do("GET", "/npm/internal/p", "maintainer", nil)
	var doc map[string]any
	r.NoError(json.Unmarshal(body, &doc))
	r.NotEmpty(doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["deprecated"], "npm ignores empty deprecation messages")

	doc["versions"].(map[string]any)["1.0.1"].(map[string]any)["deprecated"] = "also old"
	code, _, _ := e.do("PUT", "/npm/internal/p/-rev/x", "maintainer", doc)
	r.Equal(200, code)
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "internal", "p")
	r.True(versions[0].Yanked, "deprecating 1.0.1 must not un-yank 1.0.0")
	r.True(versions[1].Yanked)
}

func TestUnpublishVersion(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.1", "b", nil))

	// `npm unpublish p@1.0.1` PUTs the packument without that version, then
	// DELETEs the tarball.
	unpublish := func(as string) int {
		_, body, _ := e.do("GET", "/npm/internal/p?write=true", as, nil)
		var doc map[string]any
		r.NoError(json.Unmarshal(body, &doc))
		delete(doc["versions"].(map[string]any), "1.0.1")
		doc["dist-tags"] = map[string]any{"latest": "1.0.0"}
		code, _, _ := e.do("PUT", "/npm/internal/p/-rev/"+doc["_rev"].(string), as, doc)
		if code != 200 {
			return code
		}
		code, _, _ = e.do("DELETE", "/npm/internal/p/-/p-1.0.1.tgz/-rev/"+doc["_rev"].(string), as, nil)
		return code
	}
	r.Equal(403, unpublish("maintainer"), "only admins delete")
	r.Equal(200, unpublish("admin"))

	_, p := e.packument("/npm/internal/p", "reader")
	r.NotContains(p.Versions, "1.0.1")
	r.Equal("1.0.0", p.DistTags["latest"])
	code, _, _ := e.do("GET", "/npm/internal/p/-/p-1.0.1.tgz", "reader", nil)
	r.Equal(404, code)

	// The version number stays reserved.
	code, _, _ = e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.1", "evil", nil))
	r.Equal(409, code)
}

func TestUnpublishWholePackage(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.1", "b", nil))
	code, _, _ := e.do("DELETE", "/npm/internal/p/-rev/1-abc", "maintainer", nil)
	r.Equal(403, code)
	code, _, _ = e.do("DELETE", "/npm/internal/p/-rev/1-abc", "admin", nil)
	r.Equal(200, code)
	code, _ = e.packument("/npm/internal/p", "reader")
	r.Equal(404, code)
}

func TestDeletedTagPointsFallBack(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.1", "b", nil))
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "internal", "p", "1.0.1"))
	_, p := e.packument("/npm/internal/p", "reader")
	r.Equal(map[string]string{"latest": "1.0.0"}, p.DistTags, "tags never point at deleted versions")
}

func TestDistTagEndpoints(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/@acme%2fp", "developer", publishBody("@acme/p", "1.0.0", "a", nil))

	code, _, _ := e.do("PUT", "/npm/internal/-/package/@acme%2fp/dist-tags/stable", "developer", []byte(`"1.0.0"`))
	r.Equal(403, code)
	code, _, _ = e.do("PUT", "/npm/internal/-/package/@acme%2fp/dist-tags/stable", "maintainer", []byte(`"1.0.0"`))
	r.Equal(200, code)

	code, body, _ := e.do("GET", "/npm/internal/-/package/@acme%2fp/dist-tags", "reader", nil)
	r.Equal(200, code)
	r.JSONEq(`{"latest":"1.0.0","stable":"1.0.0"}`, string(body))

	code, _, _ = e.do("DELETE", "/npm/internal/-/package/@acme%2fp/dist-tags/stable", "maintainer", nil)
	r.Equal(200, code)
	code, _, _ = e.do("DELETE", "/npm/internal/-/package/@acme%2fp/dist-tags/latest", "maintainer", nil)
	r.Equal(400, code, "latest can't be removed")
}

func TestAccess(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	e.do("PUT", "/npm/internal/p", "developer", publishBody("p", "1.0.0", "a", nil))

	code, _, hdr := e.do("GET", "/npm/internal/p", "", nil)
	r.Equal(401, code, "npm prompts for login on 401")
	r.NotEmpty(hdr.Get("WWW-Authenticate"))

	code, _, _ = e.do("GET", "/npm/internal/p", "stranger", nil)
	r.Equal(404, code)
	code, _, _ = e.do("PUT", "/npm/internal/q", "reader", publishBody("q", "1.0.0", "a", nil))
	r.Equal(403, code)
	code, _ = e.packument("/npm/internal/missing", "reader")
	r.Equal(404, code)
	code, _, _ = e.do("GET", "/npm/nope/p", "admin", nil)
	r.Equal(404, code)
}

func TestWhoamiAndPing(t *testing.T) {
	r := require.New(t)
	e := newEnv(t)
	code, body, _ := e.do("GET", "/npm/internal/-/whoami", "developer", nil)
	r.Equal(200, code)
	r.JSONEq(`{"username":"dev@acme.com"}`, string(body))
	code, _, _ = e.do("GET", "/npm/internal/-/whoami", "", nil)
	r.Equal(401, code)
	code, _, _ = e.do("GET", "/npm/internal/-/ping", "", nil)
	r.Equal(200, code)
}

func TestOpClassification(t *testing.T) {
	h := New(nil, nil)
	for _, tc := range []struct {
		method, path string
		want         ratelimit.Op
	}{
		{"GET", "/npm/r/p", ratelimit.OpRead},
		{"GET", "/npm/r/p/-/p-1.0.0.tgz", ratelimit.OpDownload},
		{"PUT", "/npm/r/p", ratelimit.OpPublish},
		{"DELETE", "/npm/r/p/-rev/1", ratelimit.OpPublish},
	} {
		require.Equal(t, tc.want, h.Op(httptest.NewRequest(tc.method, tc.path, nil)), fmt.Sprint(tc))
	}
}
