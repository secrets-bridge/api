package sealing_test

import (
	"bytes"
	"testing"

	"github.com/secrets-bridge/api/pkg/sealing"
)

func TestSealOpen_RoundTrip(t *testing.T) {
	pub, priv, err := sealing.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	plaintext := []byte("hunter2-the-actual-prod-password")

	env, err := sealing.Seal(plaintext, pub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env.Algorithm != sealing.Algorithm {
		t.Fatalf("Algorithm = %q", env.Algorithm)
	}
	if len(env.EphemeralPublicKey) != 32 {
		t.Fatalf("ephemeral pub key len = %d", len(env.EphemeralPublicKey))
	}
	if bytes.Equal(env.Ciphertext, plaintext) {
		t.Fatal("ciphertext == plaintext (no encryption happened)")
	}

	got, err := sealing.Open(env, priv, pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, plaintext)
	}
}

func TestSeal_DifferentEphemeralKeyEveryCall(t *testing.T) {
	// Sealing the same plaintext twice must produce different
	// ephemeral public keys (and therefore different ciphertexts) —
	// otherwise we'd leak repetition over the wire.
	pub, _, _ := sealing.GenerateRecipientKey()
	plaintext := []byte("same plaintext")
	a, _ := sealing.Seal(plaintext, pub)
	b, _ := sealing.Seal(plaintext, pub)
	if bytes.Equal(a.EphemeralPublicKey, b.EphemeralPublicKey) {
		t.Fatal("ephemeral public key reused across calls")
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("ciphertext is deterministic — nonce or key reused")
	}
}

func TestOpen_TamperedCiphertextRejected(t *testing.T) {
	pub, priv, _ := sealing.GenerateRecipientKey()
	env, _ := sealing.Seal([]byte("hello"), pub)

	// Flip a bit in the ciphertext — GCM tag verification must fail.
	env.Ciphertext[0] ^= 0x01
	if _, err := sealing.Open(env, priv, pub); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestOpen_WrongPrivKeyRejected(t *testing.T) {
	pub, _, _ := sealing.GenerateRecipientKey()
	env, _ := sealing.Seal([]byte("hello"), pub)

	_, otherPriv, _ := sealing.GenerateRecipientKey()
	if _, err := sealing.Open(env, otherPriv, pub); err == nil {
		t.Fatal("wrong private key was accepted")
	}
}

func TestOpen_UnknownAlgorithmRejected(t *testing.T) {
	pub, priv, _ := sealing.GenerateRecipientKey()
	env, _ := sealing.Seal([]byte("hello"), pub)
	env.Algorithm = "rsa-pkcs1-v15-md5"
	if _, err := sealing.Open(env, priv, pub); err == nil {
		t.Fatal("unknown algorithm was accepted")
	}
}

func TestSeal_BadRecipientPubKey(t *testing.T) {
	bad := []byte{1, 2, 3} // too short
	if _, err := sealing.Seal([]byte("hello"), bad); err == nil {
		t.Fatal("expected error for malformed recipient pub key")
	}
}
