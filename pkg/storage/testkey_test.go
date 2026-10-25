package storage_test

import (
	"testing"

	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

// keyedStorageAgent gives a test row the X25519 key every agent that is
// not revoked must carry (migration 0051).
func keyedStorageAgent(t *testing.T, a *storage.Agent) *storage.Agent {
	t.Helper()
	pub, _, err := sealing.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	a.PublicKey, a.PublicKeyAlgorithm, a.PublicKeyFingerprint = pub, sealing.KeyAlgorithm, sealing.Fingerprint(pub)
	return a
}
