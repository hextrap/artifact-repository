// Package snapshot persists a value to a file atomically. It backs the
// single-node file stores until SQL stores replace them.
package snapshot

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Save writes v to path via a temp file and rename, so a crash leaves
// either the old or the new snapshot, never a partial one.
func Save(path string, v any) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := gob.NewEncoder(tmp).Encode(v); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads a snapshot into v. It returns false if path doesn't exist.
func Load(path string, v any) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := gob.NewDecoder(f).Decode(v); err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	return true, nil
}
