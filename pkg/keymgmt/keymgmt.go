// Package keymgmt is the Control Plane's key-management interface.
//
// The Control Plane stores secret values (after admin/dev submission)
// as KMS-encrypted blobs in Postgres. This package abstracts "the KMS"
// so the operator can choose between:
//
//   - LocalKMS:    master key from env var. Dev / single-cluster.
//   - AWSKMS:      AWS KMS via SDK (IRSA-friendly). Production AWS.
//   - VaultTransit: Vault's Transit secrets engine. Self-hosted clouds.
//   - GCPKMS / AzureKeyVault: future.
//
// All implementations follow the **envelope encryption** pattern:
//
//  1. For each value the CP needs to protect, GenerateDataKey returns
//     a fresh per-secret AES-256 key in TWO forms — plaintext (for
//     immediate use) and ciphertext (KMS-wrapped, safe to store).
//  2. The plaintext data key is used IN-PROCESS to AES-GCM the secret
//     value. Both the ciphertext and the AEAD nonce land in Postgres.
//  3. Retrieval: pull the row, ask the KMS to decrypt the data key,
//     AES-GCM the encrypted value back to plaintext, return to caller.
//
// The plaintext data key lives in CP API process memory only for the
// duration of the encrypt/decrypt call. The master key NEVER leaves
// the KMS (that's the whole point).
package keymgmt

import "context"

// KeyManager is the operator-pluggable interface.
type KeyManager interface {
	// GenerateDataKey returns a fresh data key suitable for AES-256-GCM
	// encryption. Plaintext is the in-process AES key; Ciphertext is the
	// KMS-wrapped form to persist alongside the encrypted value.
	GenerateDataKey(ctx context.Context) (DataKey, error)

	// DecryptDataKey unwraps a previously stored data key ciphertext.
	// keyID is the identifier the KMS returned at wrap time — passing
	// it back lets the KMS use the right master key during rotation
	// transitions (when keys overlap).
	DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)

	// CurrentKeyID returns the identifier of the master key currently
	// used for new wraps. Surfaced so callers can persist it on the
	// row for rotation tracking.
	CurrentKeyID() string
}

// DataKey is what GenerateDataKey returns.
type DataKey struct {
	// Plaintext is the 32-byte AES-256 key to use immediately. Caller
	// should overwrite it after use; the keymgmt impl does not retain
	// a copy.
	Plaintext []byte

	// Ciphertext is the KMS-wrapped form to store in Postgres.
	Ciphertext []byte

	// KeyID identifies which master key wrapped this data key.
	KeyID string
}
