// Package sealing implements the wire-envelope encryption used by
// CP→Agent responses (Piece 8b).
//
// Scheme: X25519 ECDH + HKDF-SHA256 + AES-256-GCM (a libsodium "box"-
// shaped hybrid encryption). Per-call ephemeral keypair on the CP
// side; the agent's static public key is registered at mint time.
//
//	CP sealing:
//	    eph_priv, eph_pub = X25519.GenerateKey()
//	    shared = X25519(eph_priv, agent_static_pub)
//	    aes_key = HKDF(shared, salt=eph_pub||agent_pub, info="secrets-bridge wrap")
//	    ciphertext = AES-256-GCM(aes_key, plaintext, nonce)
//	    envelope = { ciphertext, nonce, eph_pub, algorithm="x25519-hkdf-aes-gcm" }
//
//	Agent opening (in the agent repo, not this package):
//	    shared = X25519(agent_static_priv, eph_pub)
//	    aes_key = HKDF(shared, salt=eph_pub||agent_pub, info="secrets-bridge wrap")
//	    plaintext = AES-256-GCM-Open(aes_key, ciphertext, nonce)
//
// Why this scheme:
//   - X25519 is constant-time + well-implemented in stdlib (crypto/ecdh)
//   - HKDF separates the ECDH shared secret from the AES key, mixing
//     in both keys so an attacker swapping ephemeral keys breaks the
//     KDF input
//   - AES-256-GCM provides authenticated encryption; the ciphertext
//     includes the tag, so a tampered ciphertext fails to open
//   - Per-call ephemerality means a compromised AES key only affects
//     one call; the agent's static private key is the only long-term
//     secret on the agent side
//
// Forward secrecy isn't perfect — if the agent's static private key
// is compromised, all prior sealed responses captured on the wire can
// be decrypted. That's an acceptable trade-off for v1; a fully PFS
// scheme would require both sides to generate ephemeral keys and add
// a round trip.
package sealing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Algorithm is the only scheme this package currently implements.
// Exposed so callers (handlers) can echo it back to the agent for
// future-proofing against scheme rotation.
const Algorithm = "x25519-hkdf-aes-gcm"

// hkdfInfo is the domain-separation tag mixed into HKDF. Changing it
// invalidates every previously-issued ephemeral key — only do that as
// part of an explicit scheme rotation.
var hkdfInfo = []byte("secrets-bridge.wrap.v1")

// Envelope is the on-the-wire shape of a sealed response.
type Envelope struct {
	Ciphertext         []byte
	Nonce              []byte
	EphemeralPublicKey []byte
	Algorithm          string
}

// Seal encrypts plaintext for a recipient whose X25519 public key is
// recipientPubKey (32 bytes). Returns an Envelope safe to ship over
// the wire — even a network attacker with the TLS keys learns
// nothing about the plaintext from the envelope alone.
//
// Caller is responsible for zeroing plaintext after the call.
func Seal(plaintext, recipientPubKey []byte) (*Envelope, error) {
	curve := ecdh.X25519()
	recipientPub, err := curve.NewPublicKey(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: parse recipient public key: %w", err)
	}

	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sealing: generate ephemeral key: %w", err)
	}
	ephPub := ephPriv.PublicKey().Bytes()

	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("sealing: ecdh: %w", err)
	}
	defer zero(shared)

	aesKey, err := deriveAESKey(shared, ephPub, recipientPubKey)
	if err != nil {
		return nil, err
	}
	defer zero(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealing: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("sealing: random nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &Envelope{
		Ciphertext:         ciphertext,
		Nonce:              nonce,
		EphemeralPublicKey: ephPub,
		Algorithm:          Algorithm,
	}, nil
}

// Open is the inverse of Seal. It's implemented here so tests can
// round-trip the package without depending on the agent repo. The
// agent's production-side implementation lives in
// secrets-bridge/agent so it can keep the private key entirely
// inside the agent boundary.
//
// recipientPrivKey is the X25519 private key (32 bytes).
func Open(env *Envelope, recipientPrivKey, recipientPubKey []byte) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("sealing: envelope is nil")
	}
	if env.Algorithm != Algorithm {
		return nil, fmt.Errorf("sealing: unknown algorithm %q", env.Algorithm)
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: parse recipient private key: %w", err)
	}
	ephPub, err := curve.NewPublicKey(env.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: parse ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("sealing: ecdh: %w", err)
	}
	defer zero(shared)

	aesKey, err := deriveAESKey(shared, env.EphemeralPublicKey, recipientPubKey)
	if err != nil {
		return nil, err
	}
	defer zero(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("sealing: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealing: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("sealing: open: %w", err)
	}
	return plaintext, nil
}

// deriveAESKey runs HKDF-SHA256 with a salt of (eph_pub || recipient_pub)
// so the AES key is bound to BOTH parties' public material — a network
// attacker can't swap one of the public keys mid-flight without
// invalidating the KDF output.
func deriveAESKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	kdf := hkdf.New(sha256New, shared, salt, hkdfInfo)
	out := make([]byte, 32)
	if _, err := io.ReadFull(kdf, out); err != nil {
		return nil, fmt.Errorf("sealing: hkdf: %w", err)
	}
	return out, nil
}

// GenerateRecipientKey returns a fresh X25519 keypair encoded as raw
// 32-byte slices. Used by tests and by callers (e.g. the agent at
// boot) that need a recipient identity.
func GenerateRecipientKey() (pub, priv []byte, err error) {
	curve := ecdh.X25519()
	p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing: generate key: %w", err)
	}
	return p.PublicKey().Bytes(), p.Bytes(), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
