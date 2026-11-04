package maven

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

func user(email string) identity.Principal {
	return identity.Principal{Tenant: "acme", Kind: identity.KindUser, Subject: "sub|" + email, Email: email}
}

var principals = map[string]identity.Principal{
	"admin":     user("admin@acme.com"),
	"developer": user("dev@acme.com"),
	"reader":    user("reader@acme.com"),
	"stranger":  user("stranger@acme.com"),
}

type env struct {
	t       *testing.T
	srv     *httptest.Server
	svc     *registry.Service
	handler *Handler
	mu      sync.Mutex
	clock   time.Time
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func newEnv(t *testing.T, upstreamURL string) *env {
	e := &env{t: t, clock: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	e.svc = registry.New(registry.NewMemoryStore(), blob.NewMemory(), e.now, nil)
	ctx := context.Background()
	admin := principals["admin"]
	require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "releases", Format: registry.FormatMaven}))
	repos := []string{"releases"}
	if upstreamURL != "" {
		e.svc.AllowUpstreams(registry.FormatMaven, upstreamURL)
		require.NoError(t, e.svc.CreateRepo(ctx, admin, registry.RepoInput{Name: "central", Format: registry.FormatMaven, Type: registry.TypeProxy}))
		repos = append(repos, "central")
	}
	for _, repo := range repos {
		require.NoError(t, e.svc.SetGrant(ctx, admin, repo, rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "dev@acme.com", Role: rbac.RoleDeveloper}))
		require.NoError(t, e.svc.SetGrant(ctx, admin, repo, rbac.Grant{SubjectKind: rbac.SubjectUser, Subject: "reader@acme.com", Role: rbac.RoleReader}))
	}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := identity.Anonymous("acme")
		if _, pass, ok := r.BasicAuth(); ok {
			p = principals[pass]
		}
		e.handler.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	}))
	e.handler = New(e.svc)
	e.handler.SetClock(e.now)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(method, path, as string, body []byte) (int, string, http.Header) {
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	require.NoError(e.t, err)
	if as != "" {
		req.SetBasicAuth("token", as)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func hexOf(h interface{ Sum([]byte) []byte }) string { return hex.EncodeToString(h.Sum(nil)) }

func sums(b []byte) map[string]string {
	s1, s5, s256, s512 := sha1.Sum(b), md5.Sum(b), sha256.Sum256(b), sha512.Sum512(b)
	return map[string]string{"sha1": hex.EncodeToString(s1[:]), "md5": hex.EncodeToString(s5[:]),
		"sha256": hex.EncodeToString(s256[:]), "sha512": hex.EncodeToString(s512[:])}
}

const artifactDir = "/maven/releases/com/acme/widgets/1.2.0/"

// deploy sends what `mvn deploy` sends for one file: the file, then its checksums.
func (e *env) deploy(repo, dir, file string, body []byte) {
	code, msg, _ := e.do("PUT", "/maven/"+repo+dir+file, "developer", body)
	require.Contains(e.t, []int{200, 201}, code, "%s: %s", file, msg)
	for _, algo := range []string{"sha1", "md5"} {
		code, msg, _ = e.do("PUT", "/maven/"+repo+dir+file+"."+algo, "developer", []byte(sums(body)[algo]))
		require.Contains(e.t, []int{200, 201}, code, "%s.%s: %s", file, algo, msg)
	}
}

type metadata struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Versioning struct {
		Latest      string   `xml:"latest"`
		Release     string   `xml:"release"`
		Versions    []string `xml:"versions>version"`
		LastUpdated string   `xml:"lastUpdated"`
		Snapshot    struct {
			Timestamp   string `xml:"timestamp"`
			BuildNumber int    `xml:"buildNumber"`
		} `xml:"snapshot"`
		SnapshotVersions []struct {
			Classifier string `xml:"classifier"`
			Extension  string `xml:"extension"`
			Value      string `xml:"value"`
		} `xml:"snapshotVersions>snapshotVersion"`
	} `xml:"versioning"`
}

func (e *env) metadata(path, as string) metadata {
	code, body, _ := e.do("GET", path, as, nil)
	require.Equal(e.t, 200, code, body)
	var m metadata
	require.NoError(e.t, xml.Unmarshal([]byte(body), &m))
	return m
}

// ---------- Hosted ----------

func TestDeployAndResolve(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	jar, pom := []byte("JAR-BYTES"), []byte("<project/>")
	e.deploy("releases", "/com/acme/widgets/1.2.0/", "widgets-1.2.0.jar", jar)
	e.deploy("releases", "/com/acme/widgets/1.2.0/", "widgets-1.2.0.pom", pom)
	e.deploy("releases", "/com/acme/widgets/1.2.0/", "widgets-1.2.0-sources.jar", []byte("SRC"))
	// Clients upload their own metadata; it's accepted and ignored.
	code, _, _ := e.do("PUT", "/maven/releases/com/acme/widgets/maven-metadata.xml", "developer", []byte("<metadata/>"))
	r.Contains([]int{200, 201}, code)

	code, body, hdr := e.do("GET", artifactDir+"widgets-1.2.0.jar", "reader", nil)
	r.Equal(200, code)
	r.Equal("JAR-BYTES", body)
	r.Equal("application/java-archive", hdr.Get("Content-Type"))
	for algo, want := range sums(jar) {
		code, body, _ = e.do("GET", artifactDir+"widgets-1.2.0.jar."+algo, "reader", nil)
		r.Equal(200, code, algo)
		r.Equal(want, body, algo)
	}
	code, _, _ = e.do("HEAD", artifactDir+"widgets-1.2.0.pom", "reader", nil)
	r.Equal(200, code)

	e.deploy("releases", "/com/acme/widgets/1.3.0/", "widgets-1.3.0.jar", []byte("NEWER"))
	m := e.metadata("/maven/releases/com/acme/widgets/maven-metadata.xml", "reader")
	r.Equal("com.acme", m.GroupID)
	r.Equal("widgets", m.ArtifactID)
	r.Equal([]string{"1.2.0", "1.3.0"}, m.Versioning.Versions)
	r.Equal("1.3.0", m.Versioning.Latest)
	r.Equal("1.3.0", m.Versioning.Release)
	r.Equal("20261030120000", m.Versioning.LastUpdated)
	code, body, _ = e.do("GET", "/maven/releases/com/acme/widgets/maven-metadata.xml.sha1", "reader", nil)
	r.Equal(200, code)
	r.Len(body, 40)

	sumsList, err := e.svc.PackageSummaries(context.Background(), principals["admin"], "releases")
	r.NoError(err)
	r.Equal("com.acme:widgets", sumsList[0].Name)
}

func TestReleasesAreImmutable(t *testing.T) {
	e := newEnv(t, "")
	e.deploy("releases", "/com/acme/widgets/1.2.0/", "widgets-1.2.0.jar", []byte("ONE"))
	code, _, _ := e.do("PUT", artifactDir+"widgets-1.2.0.jar", "developer", []byte("TWO"))
	require.Equal(t, http.StatusConflict, code)
	_, body, _ := e.do("GET", artifactDir+"widgets-1.2.0.jar", "reader", nil)
	require.Equal(t, "ONE", body)
}

func TestUploadedChecksumMustMatch(t *testing.T) {
	e := newEnv(t, "")
	e.do("PUT", artifactDir+"widgets-1.2.0.jar", "developer", []byte("JAR"))
	code, _, _ := e.do("PUT", artifactDir+"widgets-1.2.0.jar.sha1", "developer", []byte(strings.Repeat("0", 40)))
	require.Equal(t, http.StatusBadRequest, code, "a mismatched checksum means a corrupted upload")
}

func TestSnapshots(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	dir := "/com/acme/widgets/2.0-SNAPSHOT/"
	e.deploy("releases", dir, "widgets-2.0-20261030.100000-1.jar", []byte("BUILD1"))
	e.deploy("releases", dir, "widgets-2.0-20261030.100000-1.pom", []byte("<project/>"))
	e.deploy("releases", dir, "widgets-2.0-20261030.110000-2.jar", []byte("BUILD2"))
	e.deploy("releases", dir, "widgets-2.0-20261030.110000-2-sources.jar", []byte("SRC2"))

	m := e.metadata("/maven/releases/com/acme/widgets/2.0-SNAPSHOT/maven-metadata.xml", "reader")
	r.Equal("2.0-SNAPSHOT", m.Version)
	r.Equal("20261030.110000", m.Versioning.Snapshot.Timestamp)
	r.Equal(2, m.Versioning.Snapshot.BuildNumber)
	values := map[string]string{}
	for _, sv := range m.Versioning.SnapshotVersions {
		values[sv.Classifier+"|"+sv.Extension] = sv.Value
	}
	r.Equal("2.0-20261030.110000-2", values["|jar"], "the newest build of each file")
	r.Equal("2.0-20261030.100000-1", values["|pom"])
	r.Equal("2.0-20261030.110000-2", values["sources|jar"])

	top := e.metadata("/maven/releases/com/acme/widgets/maven-metadata.xml", "reader")
	r.Equal([]string{"2.0-SNAPSHOT"}, top.Versioning.Versions)
	r.Equal("2.0-SNAPSHOT", top.Versioning.Latest)
	r.Empty(top.Versioning.Release, "snapshots aren't releases")

	code, body, _ := e.do("GET", "/maven/releases"+dir+"widgets-2.0-20261030.110000-2.jar", "reader", nil)
	r.Equal(200, code)
	r.Equal("BUILD2", body)
}

func TestPathValidation(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	for _, path := range []string{
		artifactDir + "other-1.2.0.jar",                   // wrong artifact
		artifactDir + "widgets-9.9.jar",                   // wrong version
		"/maven/releases/widgets/1.2.0/widgets-1.2.0.jar", // no groupId
		"/maven/releases/com/../acme/widgets/1.2.0/widgets-1.2.0.jar",
	} {
		code, _, _ := e.do("PUT", path, "developer", []byte("x"))
		r.Equal(http.StatusBadRequest, code, path)
	}
}

func TestAccess(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	code, _, hdr := e.do("GET", artifactDir+"widgets-1.2.0.jar", "", nil)
	r.Equal(http.StatusUnauthorized, code)
	r.Contains(hdr.Get("WWW-Authenticate"), "Basic", "Maven only sends credentials after a Basic challenge")
	code, _, _ = e.do("PUT", artifactDir+"widgets-1.2.0.jar", "reader", []byte("x"))
	r.Equal(http.StatusForbidden, code)
	code, _, _ = e.do("GET", artifactDir+"widgets-1.2.0.jar", "stranger", nil)
	r.Equal(http.StatusNotFound, code)
}

func TestDeletedVersionDisappears(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, "")
	e.deploy("releases", "/com/acme/widgets/1.2.0/", "widgets-1.2.0.jar", []byte("A"))
	e.deploy("releases", "/com/acme/widgets/1.3.0/", "widgets-1.3.0.jar", []byte("B"))
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "releases", "com.acme:widgets", "1.3.0"))
	m := e.metadata("/maven/releases/com/acme/widgets/maven-metadata.xml", "reader")
	r.Equal([]string{"1.2.0"}, m.Versioning.Versions)
	code, _, _ := e.do("GET", "/maven/releases/com/acme/widgets/1.3.0/widgets-1.3.0.jar", "reader", nil)
	r.Equal(http.StatusNotFound, code)
}

// ---------- Proxy ----------

type fakeCentral struct {
	srv   *httptest.Server
	files map[string][]byte
	evil  map[string][]byte
	hits  sync.Map
	// throttle, when set, is the status Central returns for everything
	// (e.g. 429 when it rate-limits this IP).
	throttle atomic.Int32
}

func newFakeCentral(t *testing.T) *fakeCentral {
	c := &fakeCentral{files: map[string][]byte{
		"/org/example/lib/1.0.0/lib-1.0.0.jar":    []byte("LIB-JAR"),
		"/org/example/lib/1.0.0/lib-1.0.0.pom":    []byte("<project/>"),
		"/org/example/plugins/maven-metadata.xml": []byte(groupMetadata),
		"/org/example/lib/maven-metadata.xml":     []byte(`<metadata><groupId>org.example</groupId><artifactId>lib</artifactId><versioning><latest>1.0.0</latest><release>1.0.0</release><versions><version>0.9.0</version><version>1.0.0</version></versions></versioning></metadata>`),
	}, evil: map[string][]byte{}}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cnt, _ := c.hits.LoadOrStore(r.URL.Path, &atomic.Int32{})
		cnt.(*atomic.Int32).Add(1)
		if code := c.throttle.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		path := r.URL.Path
		for _, algo := range []string{"sha1", "sha256", "sha512", "md5"} {
			if base, ok := strings.CutSuffix(path, "."+algo); ok {
				body, ok := c.files[base]
				if !ok {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Last-Modified", "Mon, 15 Jan 2024 10:00:00 GMT")
				// Central's checksum files sometimes carry the filename too.
				io.WriteString(w, sums(body)[algo]+"  "+base[strings.LastIndex(base, "/")+1:]+"\n")
				return
			}
		}
		body, ok := c.evil[path]
		if !ok {
			body, ok = c.files[path]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeCentral) count(path string) int32 {
	v, ok := c.hits.Load(path)
	if !ok {
		return 0
	}
	return v.(*atomic.Int32).Load()
}

const libJar = "/maven/central/org/example/lib/1.0.0/lib-1.0.0.jar"

func TestProxyCachesFromCentral(t *testing.T) {
	r := require.New(t)
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	for _, want := range []string{"miss", "hit"} {
		code, body, hdr := e.do("GET", libJar, "reader", nil)
		r.Equal(200, code, body)
		r.Equal("LIB-JAR", body)
		r.Equal(want, hdr.Get("X-Hextrap-Cache"))
	}
	r.Equal(int32(1), c.count("/org/example/lib/1.0.0/lib-1.0.0.jar"))
	code, body, _ := e.do("GET", libJar+".sha1", "reader", nil)
	r.Equal(200, code)
	r.Equal(sums([]byte("LIB-JAR"))["sha1"], body)

	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "central", "org.example:lib")
	r.Len(versions, 1)
	r.Equal(registry.SourceUpstream, versions[0].Source)
}

func TestProxyRejectsTamperedFile(t *testing.T) {
	r := require.New(t)
	c := newFakeCentral(t)
	c.evil["/org/example/lib/1.0.0/lib-1.0.0.jar"] = []byte("EVIL")
	e := newEnv(t, c.srv.URL)
	code, _, _ := e.do("GET", libJar, "reader", nil)
	r.Equal(http.StatusBadGateway, code)
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "central", "org.example:lib")
	r.Empty(versions)
}

func TestProxyMetadata(t *testing.T) {
	r := require.New(t)
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	m := e.metadata("/maven/central/org/example/lib/maven-metadata.xml", "reader")
	r.Equal([]string{"0.9.0", "1.0.0"}, m.Versioning.Versions)

	e.do("GET", libJar, "reader", nil)
	r.NoError(e.svc.Delete(context.Background(), principals["admin"], "central", "org.example:lib", "1.0.0"))
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()
	m = e.metadata("/maven/central/org/example/lib/maven-metadata.xml", "reader")
	r.Equal([]string{"0.9.0"}, m.Versioning.Versions, "removed versions are hidden")
	code, _, _ := e.do("GET", libJar, "reader", nil)
	r.Equal(http.StatusNotFound, code)
}

func TestProxyServesCacheWhenCentralIsDown(t *testing.T) {
	r := require.New(t)
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	code, _, _ := e.do("GET", libJar, "reader", nil)
	r.Equal(200, code)
	c.srv.Close()
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()

	code, body, _ := e.do("GET", libJar, "reader", nil)
	r.Equal(200, code)
	r.Equal("LIB-JAR", body)
	m := e.metadata("/maven/central/org/example/lib/maven-metadata.xml", "reader")
	r.Equal([]string{"1.0.0"}, m.Versioning.Versions, "built from the cache")
	code, _, _ = e.do("GET", "/maven/central/org/example/lib/1.0.0/lib-1.0.0.pom", "reader", nil)
	r.Equal(http.StatusBadGateway, code)
}

// Group-level metadata is how Maven resolves a plugin prefix
// (mvn dependency:tree -> maven-dependency-plugin). It lists plugins and has
// no versions.
const groupMetadata = `<metadata><plugins><plugin><name>Apache Maven Dependency Plugin</name><prefix>dependency</prefix><artifactId>maven-dependency-plugin</artifactId></plugin><plugin><name>Apache Maven Clean Plugin</name><prefix>clean</prefix><artifactId>maven-clean-plugin</artifactId></plugin></plugins></metadata>`

func pluginPrefixes(t *testing.T, body string) map[string]string {
	var m struct {
		Plugins []struct {
			Prefix     string `xml:"prefix"`
			ArtifactID string `xml:"artifactId"`
		} `xml:"plugins>plugin"`
	}
	require.NoError(t, xml.Unmarshal([]byte(body), &m))
	out := map[string]string{}
	for _, p := range m.Plugins {
		out[p.Prefix] = p.ArtifactID
	}
	return out
}

const groupMetadataPath = "/maven/central/org/example/plugins/maven-metadata.xml"

func TestProxyGroupMetadataKeepsPluginPrefixes(t *testing.T) {
	r := require.New(t)
	e := newEnv(t, newFakeCentral(t).srv.URL)

	code, body, _ := e.do("GET", groupMetadataPath, "reader", nil)
	r.Equal(200, code, body)
	r.Equal(map[string]string{
		"dependency": "maven-dependency-plugin",
		"clean":      "maven-clean-plugin",
	}, pluginPrefixes(t, body))
}

func TestProxyServesLastGoodMetadataWhileCentralThrottles(t *testing.T) {
	r := require.New(t)
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	e.metadata("/maven/central/org/example/lib/maven-metadata.xml", "reader")
	e.do("GET", groupMetadataPath, "reader", nil)

	c.throttle.Store(http.StatusTooManyRequests)
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()

	// Nothing of lib is cached, so only the last upstream copy can answer.
	m := e.metadata("/maven/central/org/example/lib/maven-metadata.xml", "reader")
	r.Equal([]string{"0.9.0", "1.0.0"}, m.Versioning.Versions)
	code, body, _ := e.do("GET", groupMetadataPath, "reader", nil)
	r.Equal(200, code, body)
	r.Equal("maven-dependency-plugin", pluginPrefixes(t, body)["dependency"])
}

func TestProxyGate(t *testing.T) {
	r := require.New(t)
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	var seen upstream.Request
	e.handler.SetGate(func(_ context.Context, req upstream.Request) error {
		seen = req
		return errors.New("too new")
	})
	code, body, _ := e.do("GET", libJar, "reader", nil)
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "too new")
	r.Equal(int32(0), c.count("/org/example/lib/1.0.0/lib-1.0.0.jar"), "never downloaded")
	r.Equal("org.example:lib", seen.Package)
	r.Equal("1.0.0", seen.Version)
	r.Equal(time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC), seen.Published)
}

func TestProxyIsReadOnly(t *testing.T) {
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	code, _, _ := e.do("PUT", libJar, "admin", []byte("x"))
	require.Equal(t, http.StatusMethodNotAllowed, code)
}

func TestProxyUnknownArtifact(t *testing.T) {
	c := newFakeCentral(t)
	e := newEnv(t, c.srv.URL)
	code, _, _ := e.do("GET", "/maven/central/org/example/nope/1.0/nope-1.0.jar", "reader", nil)
	require.Equal(t, http.StatusNotFound, code)
}
