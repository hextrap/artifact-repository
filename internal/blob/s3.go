package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// S3Config configures an S3 or S3-compatible bucket.
type S3Config struct {
	Bucket string `yaml:"bucket"`
	Region string `yaml:"region"`
	// Prefix is prepended to every key, e.g. "prod/blobs/".
	Prefix string `yaml:"prefix"`
	// Endpoint overrides AWS for S3-compatible services (MinIO, R2, ...).
	Endpoint       string `yaml:"endpoint"`
	ForcePathStyle bool   `yaml:"force_path_style"`
	// ServerSideEncryption is "", "AES256" or "aws:kms".
	ServerSideEncryption string `yaml:"server_side_encryption"`
	KMSKeyID             string `yaml:"kms_key_id"`
}

var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

func (c S3Config) Validate() error {
	var errs []error
	if !bucketRE.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") {
		errs = append(errs, errors.New("s3.bucket must be a valid bucket name"))
	}
	if c.Region == "" {
		errs = append(errs, errors.New("s3.region is required"))
	}
	if c.Prefix != "" && (strings.HasPrefix(c.Prefix, "/") || !strings.HasSuffix(c.Prefix, "/")) {
		errs = append(errs, errors.New(`s3.prefix must not start with "/" and must end with "/"`))
	}
	switch c.ServerSideEncryption {
	case "", "AES256", "aws:kms":
	default:
		errs = append(errs, errors.New(`s3.server_side_encryption must be "AES256" or "aws:kms"`))
	}
	if c.KMSKeyID != "" && c.ServerSideEncryption != "aws:kms" {
		errs = append(errs, errors.New(`s3.kms_key_id requires server_side_encryption: aws:kms`))
	}
	if c.Endpoint != "" {
		if u, err := url.Parse(c.Endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, errors.New("s3.endpoint must be an http(s) URL"))
		}
	}
	return errors.Join(errs...)
}

// S3 stores blobs in a bucket under <prefix>sha256/<aa>/<bb>/<hex>.
type S3 struct {
	cfg    S3Config
	creds  CredentialsProvider
	client *http.Client
	now    func() time.Time
	tmpDir string
}

// NewS3 returns an S3 store. Uploads are spooled to tmpDir ("" for the OS
// default) to compute their digest, which is the object key.
func NewS3(cfg S3Config, creds CredentialsProvider, client *http.Client, now func() time.Time, tmpDir string) (*S3, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")
	return &S3{cfg: cfg, creds: creds, client: client, now: now, tmpDir: tmpDir}, nil
}

func (s *S3) key(d Digest) string {
	h := d.Hex()
	return s.cfg.Prefix + "sha256/" + h[0:2] + "/" + h[2:4] + "/" + h
}

func (s *S3) objectURL(key string) string {
	switch {
	case s.cfg.Endpoint != "" && s.cfg.ForcePathStyle:
		return s.cfg.Endpoint + "/" + s.cfg.Bucket + "/" + key
	case s.cfg.Endpoint != "":
		u, _ := url.Parse(s.cfg.Endpoint)
		return u.Scheme + "://" + s.cfg.Bucket + "." + u.Host + "/" + key
	}
	return "https://" + s.cfg.Bucket + ".s3." + s.cfg.Region + ".amazonaws.com/" + key
}

func (s *S3) do(ctx context.Context, method, key string, body io.Reader, size int64, payloadHash string, hdr http.Header) (*http.Response, error) {
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, s.objectURL(key), body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.ContentLength = size
	}
	signV4(req, creds, s.cfg.Region, s.now(), payloadHash)
	return s.client.Do(req)
}

// s3Error describes a failed response without echoing the full body.
func s3Error(op string, resp *http.Response) error {
	var e struct {
		Code string `xml:"Code"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = xml.Unmarshal(b, &e)
	if e.Code == "" {
		e.Code = "no error code"
	}
	return fmt.Errorf("s3 %s: %s (%s)", op, resp.Status, e.Code)
}

func (s *S3) head(ctx context.Context, key string) (bool, error) {
	resp, err := s.do(ctx, http.MethodHead, key, nil, 0, emptySHA256, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	if resp.StatusCode == http.StatusForbidden {
		// HEAD responses have no body; name the likely cause.
		return false, fmt.Errorf("s3 head: %s (AccessDenied or missing s3:ListBucket permission)", resp.Status)
	}
	return false, s3Error("head", resp)
}

func (s *S3) Put(ctx context.Context, r io.Reader) (Digest, int64, error) {
	tmp, err := os.CreateTemp(s.tmpDir, "hextrap-upload-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		return "", 0, err
	}
	d := digestOf(h)
	key := s.key(d)
	if exists, err := s.head(ctx, key); err != nil {
		return "", 0, err
	} else if exists {
		return d, n, nil
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}

	hdr := http.Header{"Content-Type": {"application/octet-stream"}}
	if s.cfg.ServerSideEncryption != "" {
		hdr.Set("X-Amz-Server-Side-Encryption", s.cfg.ServerSideEncryption)
	}
	if s.cfg.KMSKeyID != "" {
		hdr.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", s.cfg.KMSKeyID)
	}
	// The digest doubles as the signed payload hash, so S3 rejects a body
	// that changed in transit.
	resp, err := s.do(ctx, http.MethodPut, key, tmp, n, hex.EncodeToString(h.Sum(nil)), hdr)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, s3Error("put", resp)
	}
	return d, n, nil
}

func (s *S3) Open(ctx context.Context, d Digest) (io.ReadCloser, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	resp, err := s.do(ctx, http.MethodGet, s.key(d), nil, 0, emptySHA256, nil)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return newVerifyingReader(resp.Body, d), nil
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, ErrNotFound
	}
	defer resp.Body.Close()
	return nil, s3Error("get", resp)
}

func (s *S3) Exists(ctx context.Context, d Digest) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	return s.head(ctx, s.key(d))
}

func (s *S3) Delete(ctx context.Context, d Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodDelete, s.key(d), nil, 0, emptySHA256, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return s3Error("delete", resp)
	}
	return nil
}

// Check verifies the bucket is reachable with the configured credentials,
// so a misconfiguration fails at startup rather than on the first publish.
func (s *S3) Check(ctx context.Context) error {
	_, err := s.head(ctx, s.cfg.Prefix+"hextrap-healthcheck")
	return err
}
