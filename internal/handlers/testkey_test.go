package handlers_test

import (
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/sealing"
)

// Every agent that is not revoked has an X25519 key (skills#116). Test
// agents share one.
var (
	testAgentPub         = mustTestKey()
	testAgentFingerprint = sealing.Fingerprint(testAgentPub)
)

func mustTestKey() []byte {
	pub, _, err := sealing.GenerateRecipientKey()
	if err != nil {
		panic(err)
	}
	return pub
}

// keyedMint fills in the shared test key when the input has none.
func keyedMint(in services.MintInput) services.MintInput {
	if in.PublicKey == nil {
		in.PublicKey, in.PublicKeyAlgorithm = testAgentPub, sealing.KeyAlgorithm
	}
	return in
}
