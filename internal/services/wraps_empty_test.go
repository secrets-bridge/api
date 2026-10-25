package services_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
)

// api#286: provider bundles often hold keys set to "". An empty value is
// sealed like any other: its own data key and nonce, a ciphertext that
// is just the 16-byte GCM tag, SHA-256 of the empty input as content
// hash and byte_length 0.

var emptySHA256 = sha256.Sum256(nil)

// Seal needs only the KMS, so this runs without Postgres.
func TestSeal_EmptyPlaintext(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	km, err := keymgmt.NewLocalKMS(master)
	if err != nil {
		t.Fatal(err)
	}
	svc := services.NewWrapService(nil, nil, km)
	for name, pt := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			w, err := svc.Seal(t.Context(), services.WrapRequest{Plaintext: pt, TTL: time.Hour, KeyName: "OPTIONAL_TOKEN"})
			if err != nil {
				t.Fatalf("Seal(empty) = %v; want an empty value to seal", err)
			}
			if w.ByteLength != 0 {
				t.Errorf("byte_length = %d; want 0", w.ByteLength)
			}
			if len(w.EncryptedValue) != 16 {
				t.Errorf("ciphertext = %d bytes; want the 16-byte GCM tag", len(w.EncryptedValue))
			}
			if len(w.Nonce) != 12 || len(w.DataKeyCiphertext) == 0 {
				t.Errorf("nonce %d bytes, data key %d bytes; want a fresh nonce and data key", len(w.Nonce), len(w.DataKeyCiphertext))
			}
			if !bytes.Equal(w.ContentHash, emptySHA256[:]) {
				t.Errorf("content_hash = %x; want SHA-256 of the empty input", w.ContentHash)
			}
		})
	}
}

// Round trip through Postgres and KMS for both consumers: the agent
// (patch flow) and the requester (read flow). Each gets back a non-nil,
// zero-length value, and the wrap.create audit row keeps byte_length 0.
func TestWrap_EmptyPlaintextRoundTrip(t *testing.T) {
	svc, agents, pool := bootstrapWraps(t)
	ctx := t.Context()
	minted, err := agents.Mint(ctx, keyedMint(services.MintInput{Name: "agent-1"}))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	forAgent, err := svc.Wrap(ctx, services.WrapRequest{Plaintext: []byte{}, TTL: time.Hour, Actor: "user:alice"})
	if err != nil {
		t.Fatalf("Wrap(empty) = %v; want an empty value to seal", err)
	}
	if forAgent.ByteLength != 0 || len(forAgent.EncryptedValue) != 16 {
		t.Fatalf("stored wrap byte_length=%d ciphertext=%d; want 0 and 16", forAgent.ByteLength, len(forAgent.EncryptedValue))
	}
	got, w, err := svc.Retrieve(ctx, forAgent.ID, minted.ID)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got == nil || len(got) != 0 || w.ByteLength != 0 {
		t.Fatalf("agent retrieve = %v (nil=%t), byte_length %d; want a non-nil empty value", got, got == nil, w.ByteLength)
	}

	forUser, err := svc.Wrap(ctx, services.WrapRequest{Plaintext: nil, TTL: time.Hour, Actor: "user:alice"})
	if err != nil {
		t.Fatalf("Wrap(nil) = %v", err)
	}
	got, _, err = svc.RetrieveByUser(ctx, forUser.ID, "alice")
	if err != nil {
		t.Fatalf("RetrieveByUser: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("user retrieve = %v (nil=%t); want a non-nil empty value", got, got == nil)
	}

	rows, err := pool.Query(ctx, `SELECT metadata FROM audit_events WHERE action = 'wrap.create'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatal(err)
		}
		if bl, ok := meta["byte_length"].(float64); !ok || bl != 0 {
			t.Errorf("wrap.create byte_length = %v; want 0 kept in the audit row", meta["byte_length"])
		}
		if meta["content_hash"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("wrap.create content_hash = %v; want SHA-256 of the empty input", meta["content_hash"])
		}
		n++
	}
	if n != 2 {
		t.Fatalf("wrap.create audit rows = %d; want 2", n)
	}
}
