package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// runStoreContract is run against every Store implementation so they all
// behave identically.
func runStoreContract(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()

	t.Run("put then open round-trips content", func(t *testing.T) {
		r := require.New(t)
		s := newStore(t)
		d, n, err := s.Put(ctx, bytes.NewReader([]byte("hello")))
		r.NoError(err)
		r.Equal(int64(5), n)
		r.Equal(Digest(fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("hello")))), d)

		rc, err := s.Open(ctx, d)
		r.NoError(err)
		b, err := io.ReadAll(rc)
		r.NoError(err)
		r.NoError(rc.Close())
		r.Equal("hello", string(b))
	})

	t.Run("same content stored once", func(t *testing.T) {
		r := require.New(t)
		s := newStore(t)
		d1, _, err := s.Put(ctx, bytes.NewReader([]byte("same")))
		r.NoError(err)
		d2, _, err := s.Put(ctx, bytes.NewReader([]byte("same")))
		r.NoError(err)
		r.Equal(d1, d2)
	})

	t.Run("exists and delete", func(t *testing.T) {
		r := require.New(t)
		s := newStore(t)
		d, _, err := s.Put(ctx, bytes.NewReader([]byte("x")))
		r.NoError(err)
		ok, err := s.Exists(ctx, d)
		r.NoError(err)
		r.True(ok)

		r.NoError(s.Delete(ctx, d))
		ok, err = s.Exists(ctx, d)
		r.NoError(err)
		r.False(ok)
		_, err = s.Open(ctx, d)
		r.ErrorIs(err, ErrNotFound)
	})

	t.Run("open missing digest", func(t *testing.T) {
		s := newStore(t)
		_, err := s.Open(ctx, Digest(fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("nope")))))
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("malformed digest rejected", func(t *testing.T) {
		s := newStore(t)
		for _, d := range []Digest{"", "md5:abc", "sha256:../../etc/passwd", "sha256:zz"} {
			_, err := s.Open(ctx, d)
			require.ErrorIs(t, err, ErrInvalidDigest, string(d))
		}
	})
}

func TestMemoryStore(t *testing.T) {
	runStoreContract(t, func(t *testing.T) Store { return NewMemory() })
}

func TestFilesystemStore(t *testing.T) {
	runStoreContract(t, func(t *testing.T) Store {
		s, err := NewFilesystem(t.TempDir())
		require.NoError(t, err)
		return s
	})
}

func TestFilesystemDetectsCorruption(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	s, err := NewFilesystem(dir)
	r.NoError(err)

	d, _, err := s.Put(context.Background(), bytes.NewReader([]byte("original")))
	r.NoError(err)

	// Tamper with the file on disk.
	var path string
	r.NoError(filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Base(p) == d.Hex() {
			path = p
		}
		return nil
	}))
	r.NotEmpty(path)
	r.NoError(os.WriteFile(path, []byte("tampered"), 0o644))

	rc, err := s.Open(context.Background(), d)
	r.NoError(err)
	_, err = io.ReadAll(rc)
	r.ErrorIs(err, ErrCorrupt)
}
