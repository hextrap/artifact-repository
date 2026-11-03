package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var s3TestCreds = Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "secret-test"}

// fakeS3 is a path-style S3 endpoint that re-verifies every signature.
type fakeS3 struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	objects map[string][]byte
	headers map[string]http.Header // last PUT headers per key
	puts    int
	deny    bool
}

func newFakeS3(t *testing.T) *fakeS3 {
	f := &fakeS3{t: t, objects: map[string][]byte{}, headers: map[string]http.Header{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3) verify(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	_, signedPart, ok := strings.Cut(auth, "SignedHeaders=")
	if !ok {
		return fmt.Errorf("unsigned request")
	}
	signedNames, _, _ := strings.Cut(signedPart, ",")
	if !strings.Contains(auth, "Credential=AKIDTEST/") || !strings.Contains(auth, "/us-east-1/s3/aws4_request") {
		return fmt.Errorf("bad credential scope: %s", auth)
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if body != nil {
		sum := sha256.Sum256(body)
		if payload != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("payload hash doesn't match body")
		}
	}
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return err
	}
	// Rebuild the request from only the signed headers and sign it again.
	check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	check.Host = r.Host
	for _, name := range strings.Split(signedNames, ";") {
		switch name {
		case "host", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token":
		default:
			check.Header.Set(name, r.Header.Get(name))
		}
	}
	creds := s3TestCreds
	creds.SessionToken = r.Header.Get("X-Amz-Security-Token")
	signV4(check, creds, "us-east-1", at, payload)
	if check.Header.Get("Authorization") != auth {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Method == http.MethodPut {
		body, _ = io.ReadAll(r.Body)
	}
	if err := f.verify(r, body); err != nil || f.deny {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>`)
		if err != nil {
			f.t.Errorf("%s %s: %v", r.Method, r.URL.Path, err)
		}
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[key]
	switch r.Method {
	case http.MethodPut:
		f.objects[key] = body
		f.headers[key] = r.Header.Clone()
		f.puts++
	case http.MethodGet, http.MethodHead:
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(obj)))
		if r.Method == http.MethodGet {
			w.Write(obj)
		}
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakeS3) store(t *testing.T, cfg S3Config) *S3 {
	cfg.Endpoint = f.srv.URL
	cfg.ForcePathStyle = true
	if cfg.Bucket == "" {
		cfg.Bucket = "artifacts"
	}
	cfg.Region = "us-east-1"
	s, err := NewS3(cfg, StaticCredentials(s3TestCreds), http.DefaultClient, time.Now, t.TempDir())
	require.NoError(t, err)
	return s
}

func TestS3StoreContract(t *testing.T) {
	runStoreContract(t, func(t *testing.T) Store { return newFakeS3(t).store(t, S3Config{}) })
}

func TestS3KeysAndPrefix(t *testing.T) {
	f := newFakeS3(t)
	s := f.store(t, S3Config{Bucket: "artifacts", Prefix: "prod/blobs/"})
	d, _, err := s.Put(context.Background(), strings.NewReader("hello"))
	require.NoError(t, err)
	h := d.Hex()
	require.Contains(t, f.objects, "artifacts/prod/blobs/sha256/"+h[:2]+"/"+h[2:4]+"/"+h)
}

func TestS3SkipsUploadOfExistingContent(t *testing.T) {
	f := newFakeS3(t)
	s := f.store(t, S3Config{})
	for i := 0; i < 3; i++ {
		_, _, err := s.Put(context.Background(), strings.NewReader("same"))
		require.NoError(t, err)
	}
	require.Equal(t, 1, f.puts)
}

func TestS3ServerSideEncryption(t *testing.T) {
	f := newFakeS3(t)
	s := f.store(t, S3Config{ServerSideEncryption: "aws:kms", KMSKeyID: "arn:aws:kms:us-east-1:111:key/abc"})
	d, _, err := s.Put(context.Background(), strings.NewReader("secret"))
	require.NoError(t, err)
	h := d.Hex()
	hdr := f.headers["artifacts/sha256/"+h[:2]+"/"+h[2:4]+"/"+h]
	require.Equal(t, "aws:kms", hdr.Get("X-Amz-Server-Side-Encryption"))
	require.Equal(t, "arn:aws:kms:us-east-1:111:key/abc", hdr.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"))
	require.Contains(t, hdr.Get("Authorization"), "x-amz-server-side-encryption", "SSE headers are signed")
}

func TestS3DetectsCorruption(t *testing.T) {
	f := newFakeS3(t)
	s := f.store(t, S3Config{})
	d, _, err := s.Put(context.Background(), strings.NewReader("original"))
	require.NoError(t, err)
	for k := range f.objects {
		f.objects[k] = []byte("tampered")
	}
	rc, err := s.Open(context.Background(), d)
	require.NoError(t, err)
	_, err = io.ReadAll(rc)
	require.ErrorIs(t, err, ErrCorrupt)
}

func TestS3AccessDeniedIsNotNotFound(t *testing.T) {
	r := require.New(t)
	f := newFakeS3(t)
	s := f.store(t, S3Config{})
	d, _, err := s.Put(context.Background(), strings.NewReader("x"))
	r.NoError(err)
	f.deny = true
	_, err = s.Open(context.Background(), d)
	r.Error(err)
	r.NotErrorIs(err, ErrNotFound, "a permissions problem must not look like a missing package")
	r.Contains(err.Error(), "AccessDenied")
	_, err = s.Exists(context.Background(), d)
	r.Error(err)
	r.Error(s.Check(context.Background()))
}

func TestS3Check(t *testing.T) {
	f := newFakeS3(t)
	require.NoError(t, f.store(t, S3Config{}).Check(context.Background()))
}

func TestS3SpoolFilesAreRemoved(t *testing.T) {
	f := newFakeS3(t)
	tmp := t.TempDir()
	s, err := NewS3(S3Config{Bucket: "b", Region: "us-east-1", Endpoint: f.srv.URL, ForcePathStyle: true},
		StaticCredentials(s3TestCreds), http.DefaultClient, time.Now, tmp)
	require.NoError(t, err)
	_, _, err = s.Put(context.Background(), bytes.NewReader(make([]byte, 1<<20)))
	require.NoError(t, err)
	entries, _ := os.ReadDir(tmp)
	require.Empty(t, entries)
}

func TestS3ObjectURL(t *testing.T) {
	s, err := NewS3(S3Config{Bucket: "hextrap-artifacts", Region: "us-west-2"}, StaticCredentials(s3TestCreds), http.DefaultClient, time.Now, "")
	require.NoError(t, err)
	require.Equal(t, "https://hextrap-artifacts.s3.us-west-2.amazonaws.com/sha256/ab/cd/x", s.objectURL("sha256/ab/cd/x"))

	s, err = NewS3(S3Config{Bucket: "b", Region: "us-east-1", Endpoint: "https://minio.internal:9000/", ForcePathStyle: true},
		StaticCredentials(s3TestCreds), http.DefaultClient, time.Now, "")
	require.NoError(t, err)
	require.Equal(t, "https://minio.internal:9000/b/k", s.objectURL("k"))
}

func TestS3ConfigValidation(t *testing.T) {
	ok := S3Config{Bucket: "b", Region: "us-east-1"}
	require.NoError(t, ok.Validate())
	for name, c := range map[string]S3Config{
		"bucket required":        {Region: "us-east-1"},
		"region required":        {Bucket: "b"},
		"prefix leading slash":   {Bucket: "b", Region: "r", Prefix: "/x/"},
		"prefix trailing slash":  {Bucket: "b", Region: "r", Prefix: "x"},
		"unknown sse":            {Bucket: "b", Region: "r", ServerSideEncryption: "rot13"},
		"kms key needs aws:kms":  {Bucket: "b", Region: "r", ServerSideEncryption: "AES256", KMSKeyID: "k"},
		"endpoint must be a URL": {Bucket: "b", Region: "r", Endpoint: "minio:9000"},
		"bucket name not a path": {Bucket: "b/../c", Region: "r"},
	} {
		require.Error(t, c.Validate(), name)
	}
}
