package keymgmt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// LocalKMS implements KeyManager using a single master key held in the
// CP API process's memory (sourced from the SB_WRAP_MASTER_KEY env
// var). The master key wraps fresh data keys via AES-256-GCM.
//
// Use when:
//   - dev / docker-compose local stacks
//   - single-cluster installs where the operator has no KMS provider
//     and is OK relying on a K8s Secret to deliver the master key
//
// Do NOT use when:
//   - production multi-tenant / regulated environments — pick
//     AWSKMS / VaultTransit / GCPKMS instead so the master key is
//     never in the CP process's memory.
type LocalKMS struct {
	masterKey []byte
	keyID     string
}

// EnvVarMasterKey is the env var the CP reads to load the master key.
// Value must be a base64-standard-encoded 32 bytes (AES-256).
const EnvVarMasterKey = "SB_WRAP_MASTER_KEY"

// NewLocalKMSFromEnv reads SB_WRAP_MASTER_KEY and returns a LocalKMS.
// Errors when the env var is missing or not 32 raw bytes after base64
// decode.
func NewLocalKMSFromEnv() (*LocalKMS, error) {
	raw := os.Getenv(EnvVarMasterKey)
	if raw == "" {
		return nil, fmt.Errorf("keymgmt: %s is not set", EnvVarMasterKey)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: %s is not valid base64: %w", EnvVarMasterKey, err)
	}
	return NewLocalKMS(key)
}

// NewLocalKMS constructs a LocalKMS from a 32-byte master key. Used
// directly by tests; production code uses NewLocalKMSFromEnv.
func NewLocalKMS(masterKey []byte) (*LocalKMS, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("keymgmt: master key must be 32 bytes, got %d", len(masterKey))
	}
	// keyID = base64(SHA-256(masterKey)) — derivable but doesn't
	// reveal the key itself; lets the operator track which master key
	// wrapped a given row, useful during rotation.
	sum := sha256.Sum256(masterKey)
	id := "local:" + base64.RawURLEncoding.EncodeToString(sum[:])
	// Defensive copy so a caller mutating their slice doesn't change
	// the underlying key.
	mk := make([]byte, len(masterKey))
	copy(mk, masterKey)
	return &LocalKMS{masterKey: mk, keyID: id}, nil
}

// GenerateDataKey returns a fresh 32-byte AES-256 key encrypted under
// the master key via AES-GCM. The on-the-wire shape is:
//
//	ciphertext = [12-byte nonce] || [AES-GCM(dataKey)]
//
// Packing the nonce inline keeps DecryptDataKey single-argument.
func (k *LocalKMS) GenerateDataKey(_ context.Context) (DataKey, error) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return DataKey{}, fmt.Errorf("keymgmt: read random data key: %w", err)
	}
	ciphertext, err := k.wrap(dataKey)
	if err != nil {
		return DataKey{}, err
	}
	return DataKey{
		Plaintext:  dataKey,
		Ciphertext: ciphertext,
		KeyID:      k.keyID,
	}, nil
}

// DecryptDataKey reverses GenerateDataKey's wrap step. keyID is checked
// against the current master key — if it doesn't match, the call
// returns an error rather than silently using the wrong key.
func (k *LocalKMS) DecryptDataKey(_ context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	if keyID != k.keyID {
		return nil, fmt.Errorf("keymgmt: data key was wrapped by a different master key (got %q, current %q); rotation needed", keyID, k.keyID)
	}
	return k.unwrap(ciphertext)
}

// CurrentKeyID returns the master key's identifier.
func (k *LocalKMS) CurrentKeyID() string { return k.keyID }

func (k *LocalKMS) wrap(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keymgmt: random nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func (k *LocalKMS) unwrap(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("keymgmt: ciphertext shorter than nonce")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	body := ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: open: %w", err)
	}
	return plaintext, nil
}
