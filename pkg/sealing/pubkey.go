package sealing

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// KeyAlgorithm is the only agent wire-key algorithm (skills#116).
const KeyAlgorithm = "x25519"

// PublicKeySize is the length of a raw X25519 public key.
const PublicKeySize = 32

// FingerprintPrefix starts every key fingerprint.
const FingerprintPrefix = "sha256:"

// ErrInvalidPublicKey is returned for a key that is not a usable X25519
// recipient: wrong algorithm, wrong encoding or length, the all-zero
// key, or a low-order point.
var ErrInvalidPublicKey = errors.New("sealing: invalid public key")

// checkScalar is a fixed, non-zero X25519 scalar. ECDH with a low-order
// point (the all-zero key among them) yields the all-zero shared
// secret whatever the scalar, after clamping, and crypto/ecdh refuses
// that with an error.
var checkScalar = sha256.Sum256([]byte("secrets-bridge.public-key-check.v1"))

// ValidatePublicKey reports whether raw is a 32-byte X25519 public key
// that a wrap can be sealed to: not all zero and not of low order.
func ValidatePublicKey(raw []byte) error {
	if len(raw) != PublicKeySize {
		return ErrInvalidPublicKey
	}
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(raw)
	if err != nil {
		return ErrInvalidPublicKey
	}
	priv, err := curve.NewPrivateKey(checkScalar[:])
	if err != nil {
		return ErrInvalidPublicKey
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return ErrInvalidPublicKey
	}
	zero(shared)
	return nil
}

// ParsePublicKey decodes a std-base64 public key with its algorithm
// ("x25519"; empty means x25519) and validates it.
func ParsePublicKey(b64, algorithm string) ([]byte, error) {
	if algorithm != "" && algorithm != KeyAlgorithm {
		return nil, ErrInvalidPublicKey
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	// Only the canonical encoding: the decoder skips newlines.
	if err != nil || base64.StdEncoding.EncodeToString(raw) != b64 {
		return nil, ErrInvalidPublicKey
	}
	if err := ValidatePublicKey(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Fingerprint is "sha256:" plus the lowercase hex SHA-256 of the raw
// public key bytes.
func Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return FingerprintPrefix + hex.EncodeToString(sum[:])
}

// IsFingerprint reports whether s has the shape of a key fingerprint.
func IsFingerprint(s string) bool {
	if len(s) != len(FingerprintPrefix)+2*sha256.Size || s[:len(FingerprintPrefix)] != FingerprintPrefix {
		return false
	}
	for _, c := range s[len(FingerprintPrefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
