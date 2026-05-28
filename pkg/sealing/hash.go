package sealing

import (
	"crypto/sha256"
	"hash"
)

// sha256New is the hash factory for HKDF. Pulled out so future
// scheme rotations (e.g. SHA-512) just swap this constant.
func sha256New() hash.Hash {
	return sha256.New()
}
