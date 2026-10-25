package main

import (
	"encoding/base64"
	"encoding/json"

	"github.com/secrets-bridge/api/pkg/sealing"
)

// Every agent has an X25519 key (skills#116). Live test agents minted
// through POST /api/v1/agents share this one and send its fingerprint.
var (
	liveAgentPub         = mustLiveKey()
	liveAgentFingerprint = sealing.Fingerprint(liveAgentPub)
)

func mustLiveKey() []byte {
	pub, _, err := sealing.GenerateRecipientKey()
	if err != nil {
		panic(err)
	}
	return pub
}

// agentMintBody is the POST /api/v1/agents body for a test agent.
func agentMintBody(name string) map[string]any {
	return map[string]any{
		"name":                 name,
		"public_key":           base64.StdEncoding.EncodeToString(liveAgentPub),
		"public_key_algorithm": sealing.KeyAlgorithm,
	}
}

// agentHeaders are the headers an agent sends under /agents/:id/*.
func agentHeaders(secret string) map[string]string {
	return map[string]string{"X-Agent-Secret": secret, "X-Agent-Key-Fingerprint": liveAgentFingerprint}
}

// enrollClient does what `secrets-bridge-agent enroll` does, over any
// POST function: a fresh key, the challenge, opening it, the enroll.
type enrollClient struct {
	pub, priv []byte
}

func newEnrollClient(t interface {
	Helper()
	Fatalf(string, ...any)
}) *enrollClient {
	t.Helper()
	pub, priv, err := sealing.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return &enrollClient{pub: pub, priv: priv}
}

func (c *enrollClient) fingerprint() string { return sealing.Fingerprint(c.pub) }

func (c *enrollClient) challengeBody(token string) map[string]any {
	return map[string]any{
		"schema_version": "2", "enrollment_token": token,
		"public_key": base64.StdEncoding.EncodeToString(c.pub), "public_key_algorithm": "x25519",
	}
}

// open decodes a challenge response body and returns the challenge id
// and the base64 response.
func (c *enrollClient) open(body []byte) (string, string, error) {
	var ch struct {
		ChallengeID     string `json:"challenge_id"`
		SealedChallenge struct {
			Algorithm          string `json:"algorithm"`
			EphemeralPublicKey string `json:"ephemeral_public_key"`
			Nonce              string `json:"nonce"`
			Ciphertext         string `json:"ciphertext"`
		} `json:"sealed_challenge"`
	}
	if err := json.Unmarshal(body, &ch); err != nil {
		return "", "", err
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	nonce, err := sealing.Open(&sealing.Envelope{
		Algorithm: ch.SealedChallenge.Algorithm, EphemeralPublicKey: dec(ch.SealedChallenge.EphemeralPublicKey),
		Nonce: dec(ch.SealedChallenge.Nonce), Ciphertext: dec(ch.SealedChallenge.Ciphertext),
	}, c.priv, c.pub)
	if err != nil {
		return "", "", err
	}
	return ch.ChallengeID, base64.StdEncoding.EncodeToString(nonce), nil
}
