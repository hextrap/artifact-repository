package registry

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// Checksums maps an algorithm ("sha256", "sha512" or "sha1") to the
// expected hex digest.
type Checksums map[string]string

var hashAlgorithms = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
	"sha1":   sha1.New,
}

func (c Checksums) hashers() (map[string]hash.Hash, error) {
	out := map[string]hash.Hash{}
	for algo := range c {
		newHash, ok := hashAlgorithms[algo]
		if !ok {
			return nil, fmt.Errorf("%w: unsupported checksum algorithm %q", ErrInvalid, algo)
		}
		out[algo] = newHash()
	}
	return out, nil
}

// matches reports whether every expected digest matches the content the
// hashers saw.
func (c Checksums) matches(hashers map[string]hash.Hash) bool {
	for algo, want := range c {
		if !strings.EqualFold(hex.EncodeToString(hashers[algo].Sum(nil)), want) {
			return false
		}
	}
	return true
}
