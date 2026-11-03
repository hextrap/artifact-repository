// Package blob stores package files addressed by their sha256 digest.
package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrNotFound      = errors.New("blob not found")
	ErrCorrupt       = errors.New("blob content does not match digest")
	ErrInvalidDigest = errors.New("invalid digest")
)

// Digest is "sha256:<64 hex chars>".
type Digest string

func (d Digest) Hex() string {
	return strings.TrimPrefix(string(d), "sha256:")
}

func (d Digest) Validate() error {
	h, ok := strings.CutPrefix(string(d), "sha256:")
	if !ok || len(h) != 64 {
		return ErrInvalidDigest
	}
	if _, err := hex.DecodeString(h); err != nil {
		return ErrInvalidDigest
	}
	return nil
}

func digestOf(h hash.Hash) Digest {
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

type Store interface {
	// Put stores content and returns its digest and size. Storing content that
	// already exists is a no-op.
	Put(ctx context.Context, r io.Reader) (Digest, int64, error)
	// Open returns the content. Reading returns ErrCorrupt at EOF if the
	// content no longer matches its digest.
	Open(ctx context.Context, d Digest) (io.ReadCloser, error)
	Exists(ctx context.Context, d Digest) (bool, error)
	Delete(ctx context.Context, d Digest) error
}

// verifyingReader hashes content as it's read and checks it at EOF.
type verifyingReader struct {
	r      io.ReadCloser
	h      hash.Hash
	digest Digest
}

func newVerifyingReader(r io.ReadCloser, d Digest) *verifyingReader {
	return &verifyingReader{r: r, h: sha256.New(), digest: d}
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	if err == io.EOF && digestOf(v.h) != v.digest {
		return n, ErrCorrupt
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.r.Close() }

// Memory is an in-memory Store for tests and small installs.
type Memory struct {
	mu    sync.RWMutex
	blobs map[Digest][]byte
}

func NewMemory() *Memory {
	return &Memory{blobs: map[Digest][]byte{}}
}

func (m *Memory) Put(_ context.Context, r io.Reader) (Digest, int64, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", 0, err
	}
	d := Digest(fmt.Sprintf("sha256:%x", sha256.Sum256(b)))
	m.mu.Lock()
	m.blobs[d] = b
	m.mu.Unlock()
	return d, int64(len(b)), nil
}

func (m *Memory) Open(_ context.Context, d Digest) (io.ReadCloser, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	b, ok := m.blobs[d]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	return newVerifyingReader(io.NopCloser(bytes.NewReader(b)), d), nil
}

func (m *Memory) Exists(_ context.Context, d Digest) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blobs[d]
	return ok, nil
}

func (m *Memory) Delete(_ context.Context, d Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.blobs, d)
	m.mu.Unlock()
	return nil
}

// Filesystem stores blobs under root/sha256/<aa>/<bb>/<hex>.
type Filesystem struct {
	root string
}

func NewFilesystem(root string) (*Filesystem, error) {
	for _, dir := range []string{"tmp", "sha256"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			return nil, err
		}
	}
	return &Filesystem{root: root}, nil
}

func (f *Filesystem) path(d Digest) string {
	h := d.Hex()
	return filepath.Join(f.root, "sha256", h[0:2], h[2:4], h)
}

func (f *Filesystem) Put(_ context.Context, r io.Reader) (Digest, int64, error) {
	tmp, err := os.CreateTemp(filepath.Join(f.root, "tmp"), "upload-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}

	d := digestOf(h)
	dst := f.path(d)
	if _, err := os.Stat(dst); err == nil {
		return d, n, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", 0, err
	}
	// Rename is atomic, so readers never see a partial blob.
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", 0, err
	}
	return d, n, nil
}

func (f *Filesystem) Open(_ context.Context, d Digest) (io.ReadCloser, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	fh, err := os.Open(f.path(d))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return newVerifyingReader(fh, d), nil
}

func (f *Filesystem) Exists(_ context.Context, d Digest) (bool, error) {
	if err := d.Validate(); err != nil {
		return false, err
	}
	_, err := os.Stat(f.path(d))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (f *Filesystem) Delete(_ context.Context, d Digest) error {
	if err := d.Validate(); err != nil {
		return err
	}
	err := os.Remove(f.path(d))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
