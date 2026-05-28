package keymgmt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

// VaultTransit implements KeyManager using HashiCorp Vault's Transit
// secrets engine. The Vault server holds the master key; this struct
// holds only an authenticated client + the key name.
//
// Why Vault Transit for OSS deployments:
//   - HashiCorp Vault is open source (BSL-1.1 / MPL-2.0)
//   - Transit engine is purpose-built for envelope encryption:
//     POST transit/datakey/plaintext/<key> → {plaintext, ciphertext}
//     POST transit/decrypt/<key> → {plaintext}
//   - Already deployed in many environments running secrets-bridge
//   - Master key never leaves Vault
//
// Auth: TODO support k8s auth (the Vault provider already does it).
// For now, token auth via env var SB_KMS_VAULT_TOKEN is the only path;
// covers the common dev + bootstrap case and the test suite. k8s auth
// can be added incrementally without changing the interface.
type VaultTransit struct {
	logical   vaultLogical
	keyName   string
	mountPath string // e.g. "transit"; allows non-default mounts
}

// vaultLogical is the small slice of the Vault API client this
// implementation calls. Defining it as an interface lets unit tests
// inject a fake; the real *vaultapi.Logical satisfies the same shape.
type vaultLogical interface {
	Write(path string, data map[string]any) (*vaultapi.Secret, error)
}

// Env var names. Documented here in one place so the helm chart /
// operator docs can mirror them.
const (
	EnvVaultAddr    = "SB_KMS_VAULT_ADDR"
	EnvVaultToken   = "SB_KMS_VAULT_TOKEN"
	EnvVaultMount   = "SB_KMS_VAULT_MOUNT" // default "transit"
	EnvVaultKeyName = "SB_KMS_VAULT_KEY"   // required
)

const defaultTransitMount = "transit"

// NewVaultTransitFromEnv reads the SB_KMS_VAULT_* env vars and builds
// a VaultTransit. Errors if address / token / key name are missing.
//
// Mount path defaults to "transit" (Vault's default for the transit
// engine).
func NewVaultTransitFromEnv(_ context.Context) (*VaultTransit, error) {
	addr := os.Getenv(EnvVaultAddr)
	if addr == "" {
		return nil, fmt.Errorf("keymgmt: %s is required for vault-transit", EnvVaultAddr)
	}
	token := os.Getenv(EnvVaultToken)
	if token == "" {
		return nil, fmt.Errorf("keymgmt: %s is required (only token auth is wired today)", EnvVaultToken)
	}
	keyName := os.Getenv(EnvVaultKeyName)
	if keyName == "" {
		return nil, fmt.Errorf("keymgmt: %s is required (the transit key Vault will use to wrap data keys)", EnvVaultKeyName)
	}
	mount := os.Getenv(EnvVaultMount)
	if mount == "" {
		mount = defaultTransitMount
	}

	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	if err := cfg.Error; err != nil {
		return nil, fmt.Errorf("keymgmt: vault config: %w", err)
	}
	cli, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: vault client: %w", err)
	}
	cli.SetToken(token)

	return &VaultTransit{
		logical:   cli.Logical(),
		keyName:   keyName,
		mountPath: mount,
	}, nil
}

// GenerateDataKey calls Vault's transit datakey API. Vault returns a
// freshly generated random AES-256 key in two forms:
//   - plaintext: the base64-encoded key bytes (used in-process)
//   - ciphertext: Vault's opaque envelope, e.g. "vault:v1:abc123..."
//
// The plaintext key never persists anywhere — it lives in CP API
// process memory between Wrap and the immediate AES-GCM encrypt call.
func (v *VaultTransit) GenerateDataKey(_ context.Context) (DataKey, error) {
	path := fmt.Sprintf("%s/datakey/plaintext/%s", v.mountPath, v.keyName)
	secret, err := v.logical.Write(path, map[string]any{
		"bits": 256,
	})
	if err != nil {
		return DataKey{}, fmt.Errorf("keymgmt: vault transit datakey: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return DataKey{}, errors.New("keymgmt: vault transit returned no data")
	}

	plaintextB64, _ := secret.Data["plaintext"].(string)
	ciphertext, _ := secret.Data["ciphertext"].(string)
	if plaintextB64 == "" || ciphertext == "" {
		return DataKey{}, errors.New("keymgmt: vault transit response missing plaintext or ciphertext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return DataKey{}, fmt.Errorf("keymgmt: decode plaintext datakey: %w", err)
	}
	if len(plaintext) != 32 {
		return DataKey{}, fmt.Errorf("keymgmt: expected 32-byte datakey, got %d", len(plaintext))
	}

	return DataKey{
		Plaintext:  plaintext,
		Ciphertext: []byte(ciphertext), // store the "vault:v1:..." form verbatim
		KeyID:      "vault-transit:" + v.mountPath + "/" + v.keyName,
	}, nil
}

// DecryptDataKey unwraps a Vault-transit-encrypted data key. The
// ciphertext is the literal "vault:v1:..." string we stored at wrap
// time; Vault knows which underlying key version produced it.
func (v *VaultTransit) DecryptDataKey(_ context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	if !looksLikeVaultCiphertext(ciphertext) {
		return nil, fmt.Errorf("keymgmt: ciphertext does not look like a Vault transit envelope (got %d bytes; expected vault:vN:... prefix)", len(ciphertext))
	}
	// keyID is informational here — Vault transit handles version
	// selection internally via the embedded version number in the
	// ciphertext.
	_ = keyID

	path := fmt.Sprintf("%s/decrypt/%s", v.mountPath, v.keyName)
	secret, err := v.logical.Write(path, map[string]any{
		"ciphertext": string(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("keymgmt: vault transit decrypt: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("keymgmt: vault transit decrypt returned no data")
	}
	plaintextB64, _ := secret.Data["plaintext"].(string)
	if plaintextB64 == "" {
		return nil, errors.New("keymgmt: vault transit decrypt missing plaintext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: decode unwrapped datakey: %w", err)
	}
	return plaintext, nil
}

// CurrentKeyID returns a stable identifier for the configured key.
// The actual version is tracked inside the Vault ciphertext blob.
func (v *VaultTransit) CurrentKeyID() string {
	return "vault-transit:" + v.mountPath + "/" + v.keyName
}

// looksLikeVaultCiphertext is a cheap sanity check on the stored
// envelope. Vault transit always produces "vault:vN:..." (or
// "vault:vN:abc:..." for derived keys). We just gate the obvious
// shape so a misconfigured operator (mixing LocalKMS + VaultTransit
// in the same DB) gets a clear error rather than a 500 from Vault.
func looksLikeVaultCiphertext(b []byte) bool {
	if len(b) < len("vault:v1:") {
		return false
	}
	return string(b[:6]) == "vault:"
}
