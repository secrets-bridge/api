package keymgmt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

// fakeLogical is the test double for vaultLogical. It captures every
// Write call so tests can assert path + payload, and lets the test
// install per-call responses.
type fakeLogical struct {
	responses map[string]*vaultapi.Secret
	err       error
	calls     []fakeCall
}

type fakeCall struct {
	path string
	data map[string]any
}

func (f *fakeLogical) Write(path string, data map[string]any) (*vaultapi.Secret, error) {
	f.calls = append(f.calls, fakeCall{path: path, data: data})
	if f.err != nil {
		return nil, f.err
	}
	return f.responses[path], nil
}

func TestVaultTransit_GenerateDataKey_RoundTrip(t *testing.T) {
	// Vault returns a 32-byte plaintext + an opaque "vault:v1:..."
	// ciphertext. The CP unpacks plaintext from base64 and stores
	// ciphertext as-is.
	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	plaintextB64 := base64.StdEncoding.EncodeToString(rawKey)

	fake := &fakeLogical{
		responses: map[string]*vaultapi.Secret{
			"transit/datakey/plaintext/sb-wrap": {
				Data: map[string]any{
					"plaintext":   plaintextB64,
					"ciphertext":  "vault:v1:ABC123",
					"key_version": float64(3),
				},
			},
		},
	}
	v := &VaultTransit{logical: fake, keyName: "sb-wrap", mountPath: "transit"}

	dk, err := v.GenerateDataKey(context.Background())
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dk.Plaintext) != 32 {
		t.Fatalf("plaintext len = %d", len(dk.Plaintext))
	}
	if string(dk.Ciphertext) != "vault:v1:ABC123" {
		t.Fatalf("ciphertext = %q", dk.Ciphertext)
	}
	if dk.KeyID != "vault-transit:transit/sb-wrap" {
		t.Fatalf("KeyID = %q", dk.KeyID)
	}
	// Confirm Vault was asked for 256-bit keys, not 128.
	if got := fake.calls[0].data["bits"]; got != 256 {
		t.Fatalf("bits = %v want 256", got)
	}
}

func TestVaultTransit_DecryptDataKey_RoundTrip(t *testing.T) {
	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	plaintextB64 := base64.StdEncoding.EncodeToString(rawKey)

	fake := &fakeLogical{
		responses: map[string]*vaultapi.Secret{
			"transit/decrypt/sb-wrap": {
				Data: map[string]any{"plaintext": plaintextB64},
			},
		},
	}
	v := &VaultTransit{logical: fake, keyName: "sb-wrap", mountPath: "transit"}

	got, err := v.DecryptDataKey(context.Background(), []byte("vault:v1:ABC"), "vault-transit:transit/sb-wrap")
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	if string(got) != string(rawKey) {
		t.Fatal("round-trip key mismatch")
	}
	if fake.calls[0].data["ciphertext"] != "vault:v1:ABC" {
		t.Fatalf("ciphertext sent to Vault = %v", fake.calls[0].data["ciphertext"])
	}
}

func TestVaultTransit_DecryptDataKey_RejectsNonVaultCiphertext(t *testing.T) {
	v := &VaultTransit{logical: &fakeLogical{}, keyName: "k", mountPath: "transit"}
	_, err := v.DecryptDataKey(context.Background(), []byte("local-format-blob"), "")
	if err == nil {
		t.Fatal("expected refusal")
	}
	if !strings.Contains(err.Error(), "Vault transit envelope") {
		t.Fatalf("error wording: %v", err)
	}
}

func TestVaultTransit_GenerateDataKey_VaultError(t *testing.T) {
	fake := &fakeLogical{err: errors.New("403 permission denied")}
	v := &VaultTransit{logical: fake, keyName: "k", mountPath: "transit"}
	_, err := v.GenerateDataKey(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "vault transit datakey") {
		t.Fatalf("error: %v", err)
	}
}

func TestVaultTransit_GenerateDataKey_MissingFields(t *testing.T) {
	fake := &fakeLogical{
		responses: map[string]*vaultapi.Secret{
			"transit/datakey/plaintext/k": {Data: map[string]any{"plaintext": "abc"}}, // no ciphertext
		},
	}
	v := &VaultTransit{logical: fake, keyName: "k", mountPath: "transit"}
	_, err := v.GenerateDataKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "missing plaintext or ciphertext") {
		t.Fatalf("error: %v", err)
	}
}

func TestVaultTransit_GenerateDataKey_WrongKeyLength(t *testing.T) {
	// Vault returns a 16-byte key (e.g. 128 bits when we asked for 256
	// — a misconfigured Vault key type). Fail fast.
	tooShort := make([]byte, 16)
	fake := &fakeLogical{
		responses: map[string]*vaultapi.Secret{
			"transit/datakey/plaintext/k": {
				Data: map[string]any{
					"plaintext":  base64.StdEncoding.EncodeToString(tooShort),
					"ciphertext": "vault:v1:xx",
				},
			},
		},
	}
	v := &VaultTransit{logical: fake, keyName: "k", mountPath: "transit"}
	_, err := v.GenerateDataKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("error: %v", err)
	}
}

func TestVaultTransit_CustomMountPath(t *testing.T) {
	rawKey := make([]byte, 32)
	_, _ = rand.Read(rawKey)
	fake := &fakeLogical{
		responses: map[string]*vaultapi.Secret{
			"my-transit/datakey/plaintext/k": {
				Data: map[string]any{
					"plaintext":  base64.StdEncoding.EncodeToString(rawKey),
					"ciphertext": "vault:v1:xx",
				},
			},
		},
	}
	v := &VaultTransit{logical: fake, keyName: "k", mountPath: "my-transit"}
	dk, err := v.GenerateDataKey(context.Background())
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if dk.KeyID != "vault-transit:my-transit/k" {
		t.Fatalf("KeyID = %q", dk.KeyID)
	}
}

func TestVaultTransit_CurrentKeyID(t *testing.T) {
	v := &VaultTransit{keyName: "sb-wrap", mountPath: "transit"}
	if v.CurrentKeyID() != "vault-transit:transit/sb-wrap" {
		t.Fatalf("KeyID = %q", v.CurrentKeyID())
	}
}

// --- resolver tests -------------------------------------------------

func TestFromEnv_DefaultsToLocal(t *testing.T) {
	// LocalKMS needs a real master key — set one for this test.
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	t.Setenv(EnvVarMasterKey, base64.StdEncoding.EncodeToString(master))
	t.Setenv(EnvVarBackend, "") // explicit empty = default

	km, err := FromEnv(context.Background(), "dev")
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if _, ok := km.(*LocalKMS); !ok {
		t.Fatalf("got %T want *LocalKMS", km)
	}
}

func TestFromEnv_ExplicitLocal(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	t.Setenv(EnvVarMasterKey, base64.StdEncoding.EncodeToString(master))
	t.Setenv(EnvVarBackend, BackendLocal)

	km, err := FromEnv(context.Background(), "dev")
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if _, ok := km.(*LocalKMS); !ok {
		t.Fatalf("got %T want *LocalKMS", km)
	}
}

func TestFromEnv_VaultTransit(t *testing.T) {
	t.Setenv(EnvVarBackend, BackendVaultTransit)
	t.Setenv(EnvVaultAddr, "http://localhost:8200")
	t.Setenv(EnvVaultToken, "devroot")
	t.Setenv(EnvVaultKeyName, "sb-wrap")

	km, err := FromEnv(context.Background(), "dev")
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if _, ok := km.(*VaultTransit); !ok {
		t.Fatalf("got %T want *VaultTransit", km)
	}
}

func TestFromEnv_UnknownBackend(t *testing.T) {
	t.Setenv(EnvVarBackend, "wat")
	_, err := FromEnv(context.Background(), "dev")
	if err == nil || !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("error: %v", err)
	}
}

func TestNewVaultTransitFromEnv_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{
			"missing address",
			map[string]string{EnvVaultToken: "t", EnvVaultKeyName: "k"},
			"SB_KMS_VAULT_ADDR",
		},
		{
			"missing token",
			map[string]string{EnvVaultAddr: "http://x", EnvVaultKeyName: "k"},
			"SB_KMS_VAULT_TOKEN",
		},
		{
			"missing key name",
			map[string]string{EnvVaultAddr: "http://x", EnvVaultToken: "t"},
			"SB_KMS_VAULT_KEY",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the inherited values.
			t.Setenv(EnvVaultAddr, "")
			t.Setenv(EnvVaultToken, "")
			t.Setenv(EnvVaultKeyName, "")
			t.Setenv(EnvVaultMount, "")
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			_, err := NewVaultTransitFromEnv(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not contain %q", err, tc.want)
			}
		})
	}
}
