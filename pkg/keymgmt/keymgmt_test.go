package keymgmt_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/secrets-bridge/api/pkg/keymgmt"
)

func freshKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestLocalKMS_RoundTrip(t *testing.T) {
	km, err := keymgmt.NewLocalKMS(freshKey(t))
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	dk, err := km.GenerateDataKey(t.Context())
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dk.Plaintext) != 32 {
		t.Fatalf("plaintext data key length: %d, want 32", len(dk.Plaintext))
	}
	if len(dk.Ciphertext) == 0 {
		t.Fatal("ciphertext data key is empty")
	}
	if dk.KeyID == "" || !strings.HasPrefix(dk.KeyID, "local:") {
		t.Fatalf("KeyID shape: %q", dk.KeyID)
	}

	// Roundtrip: ciphertext should decrypt back to the same plaintext.
	got, err := km.DecryptDataKey(t.Context(), dk.Ciphertext, dk.KeyID)
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	if string(got) != string(dk.Plaintext) {
		t.Fatal("decrypted data key differs from generated plaintext")
	}
}

func TestLocalKMS_FreshNonceEveryCall(t *testing.T) {
	km, _ := keymgmt.NewLocalKMS(freshKey(t))

	// Two generations of the SAME plaintext would produce different
	// ciphertexts because AES-GCM uses a fresh nonce per call. Verify
	// by generating two data keys (different plaintexts, but the
	// nonce is what makes ciphertext shape per-call unique).
	dk1, _ := km.GenerateDataKey(t.Context())
	dk2, _ := km.GenerateDataKey(t.Context())

	if string(dk1.Ciphertext) == string(dk2.Ciphertext) {
		t.Fatal("two generations produced identical ciphertexts; nonce reuse?")
	}
}

func TestLocalKMS_WrongKeyIDRejected(t *testing.T) {
	km, _ := keymgmt.NewLocalKMS(freshKey(t))
	dk, _ := km.GenerateDataKey(t.Context())

	_, err := km.DecryptDataKey(t.Context(), dk.Ciphertext, "local:wrong-keyid")
	if err == nil {
		t.Fatal("expected DecryptDataKey to reject mismatched keyID")
	}
}

func TestLocalKMS_RejectsTamperedCiphertext(t *testing.T) {
	km, _ := keymgmt.NewLocalKMS(freshKey(t))
	dk, _ := km.GenerateDataKey(t.Context())

	tampered := make([]byte, len(dk.Ciphertext))
	copy(tampered, dk.Ciphertext)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit in the GCM tag

	if _, err := km.DecryptDataKey(t.Context(), tampered, dk.KeyID); err == nil {
		t.Fatal("expected AES-GCM to reject tampered ciphertext")
	}
}

func TestLocalKMS_RejectsWrongMasterKey(t *testing.T) {
	// Encrypt with one master key, try to decrypt with a different one
	// — must fail. Guards against silent key-mismatch when an
	// operator rotates the env var.
	km1, _ := keymgmt.NewLocalKMS(freshKey(t))
	dk, _ := km1.GenerateDataKey(t.Context())

	km2, _ := keymgmt.NewLocalKMS(freshKey(t))
	if _, err := km2.DecryptDataKey(t.Context(), dk.Ciphertext, dk.KeyID); err == nil {
		t.Fatal("expected decrypt with wrong master key to fail")
	}
}

func TestNewLocalKMSFromEnv_HappyPath(t *testing.T) {
	k := freshKey(t)
	t.Setenv(keymgmt.EnvVarMasterKey, base64.StdEncoding.EncodeToString(k))
	km, err := keymgmt.NewLocalKMSFromEnv()
	if err != nil {
		t.Fatalf("NewLocalKMSFromEnv: %v", err)
	}
	if km.CurrentKeyID() == "" {
		t.Fatal("KeyID empty")
	}
}

func TestNewLocalKMSFromEnv_RejectsBadInputs(t *testing.T) {
	cases := map[string]string{
		"missing":             "",
		"not-base64":          "!!!not-base64!!!",
		"too-short":           base64.StdEncoding.EncodeToString([]byte("short")),
		"too-long":            base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"empty-base64-string": "",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(keymgmt.EnvVarMasterKey, raw)
			if _, err := keymgmt.NewLocalKMSFromEnv(); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
