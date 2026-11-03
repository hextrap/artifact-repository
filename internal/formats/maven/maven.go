// Package maven serves Maven repositories in the standard layout used by
// mvn, Gradle and other JVM build tools:
//
//	/maven/<repo>/<group path>/<artifact>/<version>/<artifact>-<version>[-<classifier>].<ext>
//
// Each package is "groupId:artifactId". Checksum files and
// maven-metadata.xml are generated from what's stored rather than trusted
// from uploads.
package maven

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/rbac"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	Prefix        = "/maven/"
	metadataFile  = "maven-metadata.xml"
	maxUploadSize = 1 << 30
)

var checksumAlgos = map[string]func() hash.Hash{
	"sha1": sha1.New, "md5": md5.New, "sha256": sha256.New, "sha512": sha512.New,
}

type Handler struct {
	svc   *registry.Service
	proxy *upstream.Proxy
}

func New(svc *registry.Service) *Handler {
	return &Handler{svc: svc, proxy: upstream.New()}
}

func (h *Handler) SetClock(now func() time.Time)    { h.proxy.SetClock(now) }
func (h *Handler) SetGate(g upstream.Gate)          { h.proxy.SetGate(g) }
func (h *Handler) SetUpstreamClient(c *http.Client) { h.proxy.SetClient(c) }

// Op classifies a request for rate limiting.
func (h *Handler) Op(r *http.Request) ratelimit.Op {
	switch {
	case r.Method == http.MethodPut:
		return ratelimit.OpPublish
	case strings.Contains(r.URL.Path, metadataFile), isChecksum(r.URL.Path):
		return ratelimit.OpRead
	}
	return ratelimit.OpDownload
}

func isChecksum(path string) bool {
	for algo := range checksumAlgos {
		if strings.HasSuffix(path, "."+algo) {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, err error) {
	status := registry.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		slog.Error("maven request failed", "err", err)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="hextrap"`)
	}
	http.Error(w, registry.PublicMessage(err), status)
}

// A path segment: no leading dot, so ".." and hidden names are refused.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

type mavenPath struct {
	repo     string
	group    []string
	artifact string
	version  string // empty for artifact-level metadata
	file     string // as requested, maybe with a checksum suffix
	base     string // file without the checksum suffix
	checksum string // "sha1", "md5", ... or ""
	metadata bool
}

func (p mavenPath) groupID() string { return strings.Join(p.group, ".") }
func (p mavenPath) pkg() string     { return p.groupID() + ":" + p.artifact }
func (p mavenPath) dir() string {
	d := strings.Join(p.group, "/") + "/" + p.artifact + "/"
	if p.version != "" {
		d += p.version + "/"
	}
	return d
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", registry.ErrInvalid, fmt.Sprintf(format, args...))
}

func isSnapshot(version string) bool { return strings.HasSuffix(version, "-SNAPSHOT") }

func parsePath(urlPath string) (mavenPath, error) {
	rest, ok := strings.CutPrefix(urlPath, Prefix)
	if !ok {
		return mavenPath{}, registry.ErrNotFound
	}
	repo, rest, _ := strings.Cut(rest, "/")
	segs := strings.Split(rest, "/")
	for _, s := range segs {
		if !segmentRE.MatchString(s) {
			return mavenPath{}, invalid("invalid path segment %q", s)
		}
	}
	p := mavenPath{repo: repo, file: segs[len(segs)-1]}
	p.base = p.file
	for algo := range checksumAlgos {
		if b, ok := strings.CutSuffix(p.file, "."+algo); ok {
			p.base, p.checksum = b, algo
		}
	}

	if p.base == metadataFile {
		p.metadata = true
		switch {
		case len(segs) >= 4 && isSnapshot(segs[len(segs)-2]):
			p.version, p.artifact, p.group = segs[len(segs)-2], segs[len(segs)-3], segs[:len(segs)-3]
		case len(segs) >= 3:
			p.artifact, p.group = segs[len(segs)-2], segs[:len(segs)-2]
		default:
			return mavenPath{}, invalid("metadata path needs a groupId and artifactId")
		}
		return p, nil
	}

	if len(segs) < 4 {
		return mavenPath{}, invalid("expected <group>/<artifact>/<version>/<file>")
	}
	p.version, p.artifact, p.group = segs[len(segs)-2], segs[len(segs)-3], segs[:len(segs)-3]
	prefix := p.artifact + "-" + p.version
	if isSnapshot(p.version) {
		prefix = p.artifact + "-" + strings.TrimSuffix(p.version, "SNAPSHOT")
	}
	if !strings.HasPrefix(p.base, prefix) {
		return mavenPath{}, invalid("file %q doesn't belong to %s %s", p.base, p.artifact, p.version)
	}
	return p, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mp, err := parsePath(r.URL.Path)
	if err != nil {
		writeError(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	rv, err := h.svc.Repo(r.Context(), p, mp.repo)
	if err != nil {
		writeError(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if rv.Type == registry.TypeProxy {
			h.proxyGet(w, r, p, mp, rv.Repo)
		} else {
			h.hostedGet(w, r, p, mp)
		}
	case http.MethodPut:
		if rv.Type == registry.TypeProxy {
			writeError(w, registry.ErrReadOnly)
			return
		}
		if !rv.Role.Can(rbac.ActionPublish) {
			writeError(w, registry.ErrForbidden)
			return
		}
		if err := h.put(r, p, mp); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func contentType(file string) string {
	switch {
	case strings.HasSuffix(file, ".jar"), strings.HasSuffix(file, ".war"), strings.HasSuffix(file, ".ear"):
		return "application/java-archive"
	case strings.HasSuffix(file, ".pom"), strings.HasSuffix(file, ".xml"):
		return "text/xml; charset=utf-8"
	case strings.HasSuffix(file, ".module"):
		return "application/json"
	}
	return "application/octet-stream"
}

func writeBytes(w http.ResponseWriter, r *http.Request, b []byte, ctype, cache string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
	if r.Method != http.MethodHead {
		_, _ = w.Write(b)
	}
}

// serveStored streams a stored file, or its checksum when one was asked for.
func (h *Handler) serveStored(w http.ResponseWriter, r *http.Request, rc io.ReadCloser, f registry.File, mp mavenPath, cache string) {
	defer rc.Close()
	if mp.checksum != "" {
		hh := checksumAlgos[mp.checksum]()
		if _, err := io.Copy(hh, rc); err != nil {
			writeError(w, err)
			return
		}
		writeBytes(w, r, []byte(hex.EncodeToString(hh.Sum(nil))), "text/plain; charset=utf-8", "")
		return
	}
	w.Header().Set("Content-Type", contentType(f.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	if cache != "" {
		w.Header().Set("X-Hextrap-Cache", cache)
	}
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, rc); err != nil {
		slog.Error("streaming file", "file", f.Filename, "err", err)
	}
}

// serveMetadata writes generated metadata, or its checksum.
func serveMetadata(w http.ResponseWriter, r *http.Request, mp mavenPath, doc []byte) {
	if mp.checksum != "" {
		hh := checksumAlgos[mp.checksum]()
		hh.Write(doc)
		writeBytes(w, r, []byte(hex.EncodeToString(hh.Sum(nil))), "text/plain; charset=utf-8", "")
		return
	}
	writeBytes(w, r, doc, "text/xml; charset=utf-8", "")
}

func (h *Handler) hostedGet(w http.ResponseWriter, r *http.Request, p identity.Principal, mp mavenPath) {
	if mp.metadata {
		versions, err := h.svc.Versions(r.Context(), p, mp.repo, mp.pkg())
		if err != nil {
			writeError(w, err)
			return
		}
		doc, err := generateMetadata(mp, versions)
		if err != nil {
			writeError(w, err)
			return
		}
		serveMetadata(w, r, mp, doc)
		return
	}
	rc, f, err := h.svc.OpenFile(r.Context(), p, mp.repo, mp.pkg(), mp.base)
	if err != nil {
		writeError(w, err)
		return
	}
	h.serveStored(w, r, rc, f, mp, "")
}

func (h *Handler) put(r *http.Request, p identity.Principal, mp mavenPath) error {
	ctx := r.Context()
	switch {
	case mp.metadata:
		// Clients upload their merged view of the metadata; it's generated
		// from what's stored instead.
		_, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		return err
	case mp.checksum != "":
		return h.verifyUploadedChecksum(ctx, r.Body, p, mp)
	}
	return h.svc.AddFile(ctx, p, mp.repo, registry.VersionInput{
		Package: mp.pkg(), DisplayName: mp.pkg(), Version: mp.version,
		Files: []registry.FileInput{{Filename: mp.base, Content: io.LimitReader(r.Body, maxUploadSize)}},
	})
}

// parseChecksum takes the first token of a checksum file, which some tools
// follow with the filename.
func parseChecksum(body []byte, algo string) (string, bool) {
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return "", false
	}
	sum := strings.ToLower(fields[0])
	if _, err := hex.DecodeString(sum); err != nil || len(sum) != checksumAlgos[algo]().Size()*2 {
		return "", false
	}
	return sum, true
}

// verifyUploadedChecksum checks a deployed checksum against the stored
// file, catching uploads corrupted in transit.
func (h *Handler) verifyUploadedChecksum(ctx context.Context, body io.Reader, p identity.Principal, mp mavenPath) error {
	b, err := io.ReadAll(io.LimitReader(body, 1024))
	if err != nil {
		return err
	}
	want, ok := parseChecksum(b, mp.checksum)
	if !ok {
		return invalid("malformed %s checksum", mp.checksum)
	}
	rc, _, err := h.svc.OpenFile(ctx, p, mp.repo, mp.pkg(), mp.base)
	if errors.Is(err, registry.ErrNotFound) {
		return nil // checksum sent before its file; checked when served
	}
	if err != nil {
		return err
	}
	defer rc.Close()
	hh := checksumAlgos[mp.checksum]()
	if _, err := io.Copy(hh, rc); err != nil {
		return err
	}
	if hex.EncodeToString(hh.Sum(nil)) != want {
		return invalid("%s of %s does not match the uploaded file", mp.checksum, mp.base)
	}
	return nil
}

// ---------- maven-metadata.xml ----------

type xmlSnapshot struct {
	Timestamp   string `xml:"timestamp,omitempty"`
	BuildNumber int    `xml:"buildNumber,omitempty"`
}

type xmlSnapshotVersion struct {
	Classifier string `xml:"classifier,omitempty"`
	Extension  string `xml:"extension"`
	Value      string `xml:"value"`
	Updated    string `xml:"updated"`
}

type xmlVersioning struct {
	Latest           string               `xml:"latest,omitempty"`
	Release          string               `xml:"release,omitempty"`
	Snapshot         *xmlSnapshot         `xml:"snapshot,omitempty"`
	Versions         []string             `xml:"versions>version,omitempty"`
	LastUpdated      string               `xml:"lastUpdated,omitempty"`
	SnapshotVersions []xmlSnapshotVersion `xml:"snapshotVersions>snapshotVersion,omitempty"`
}

type xmlMetadata struct {
	XMLName    xml.Name      `xml:"metadata"`
	Model      string        `xml:"modelVersion,attr,omitempty"`
	GroupID    string        `xml:"groupId"`
	ArtifactID string        `xml:"artifactId"`
	Version    string        `xml:"version,omitempty"`
	Versioning xmlVersioning `xml:"versioning"`
}

func marshalMetadata(m xmlMetadata) ([]byte, error) {
	b, err := xml.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(b, '\n')...), nil
}

const mavenTime = "20060102150405"

var snapshotFileRE = regexp.MustCompile(`^(\d{8}\.\d{6})-(\d+)(?:-([^.]+))?\.(.+)$`)

// generateMetadata builds artifact-level metadata (all versions) or, for a
// SNAPSHOT version, the list of its timestamped builds.
func generateMetadata(mp mavenPath, versions []registry.Version) ([]byte, error) {
	if len(versions) == 0 {
		return nil, registry.ErrNotFound
	}
	m := xmlMetadata{Model: "1.1.0", GroupID: mp.groupID(), ArtifactID: mp.artifact}
	var updated time.Time

	if mp.version == "" {
		for _, v := range versions {
			m.Versioning.Versions = append(m.Versioning.Versions, v.Version)
			m.Versioning.Latest = v.Version
			if !isSnapshot(v.Version) {
				m.Versioning.Release = v.Version
			}
			if v.PublishedAt.After(updated) {
				updated = v.PublishedAt
			}
		}
		m.Versioning.LastUpdated = updated.UTC().Format(mavenTime)
		return marshalMetadata(m)
	}

	var ver *registry.Version
	for i := range versions {
		if versions[i].Version == mp.version {
			ver = &versions[i]
		}
	}
	if ver == nil {
		return nil, registry.ErrNotFound
	}
	m.Version = mp.version
	base := strings.TrimSuffix(mp.version, "SNAPSHOT") // "2.0-"
	prefix := mp.artifact + "-" + base
	type build struct {
		value    string
		buildNum int
	}
	newest := map[[2]string]build{} // (classifier, extension) -> newest build
	snap := xmlSnapshot{}
	for _, f := range ver.Files {
		rest, ok := strings.CutPrefix(f.Filename, prefix)
		if !ok || isChecksum(f.Filename) {
			continue
		}
		sm := snapshotFileRE.FindStringSubmatch(rest)
		if sm == nil {
			continue
		}
		n, _ := strconv.Atoi(sm[2])
		key := [2]string{sm[3], sm[4]}
		if n >= newest[key].buildNum {
			newest[key] = build{value: base + sm[1] + "-" + sm[2], buildNum: n}
		}
		if n > snap.BuildNumber {
			snap = xmlSnapshot{Timestamp: sm[1], BuildNumber: n}
		}
	}
	keys := make([][2]string, 0, len(newest))
	for k := range newest {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"|"+keys[i][1] < keys[j][0]+"|"+keys[j][1] })
	stamp := ver.PublishedAt.UTC().Format(mavenTime)
	for _, k := range keys {
		m.Versioning.SnapshotVersions = append(m.Versioning.SnapshotVersions,
			xmlSnapshotVersion{Classifier: k[0], Extension: k[1], Value: newest[k].value, Updated: stamp})
	}
	if snap.BuildNumber > 0 {
		m.Versioning.Snapshot = &snap
	}
	m.Versioning.LastUpdated = stamp
	return marshalMetadata(m)
}
