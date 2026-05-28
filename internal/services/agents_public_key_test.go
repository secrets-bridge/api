package services_test

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
)

func TestSetPublicKey_HappyPath_Idempotent(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()

	minted, err := svc.Mint(ctx, services.MintInput{Name: "agent-pk-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	pk := make([]byte, 32)
	_, _ = rand.Read(pk)

	if err := svc.SetPublicKey(ctx, minted.ID, pk, "x25519"); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	// Idempotent — calling it again with the same key returns nil.
	if err := svc.SetPublicKey(ctx, minted.ID, pk, "x25519"); err != nil {
		t.Fatalf("SetPublicKey idempotent: %v", err)
	}
	// Rotating to a different key is also OK.
	pk2 := make([]byte, 32)
	_, _ = rand.Read(pk2)
	if err := svc.SetPublicKey(ctx, minted.ID, pk2, "x25519"); err != nil {
		t.Fatalf("SetPublicKey rotate: %v", err)
	}
}

func TestSetPublicKey_WrongLength(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, services.MintInput{Name: "agent-pk-2"})

	err := svc.SetPublicKey(ctx, minted.ID, []byte{1, 2, 3}, "x25519")
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("got %v want length error", err)
	}
}

func TestSetPublicKey_UnsupportedAlgorithm(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, services.MintInput{Name: "agent-pk-3"})
	pk := make([]byte, 32)
	_, _ = rand.Read(pk)
	err := svc.SetPublicKey(ctx, minted.ID, pk, "rsa-pkcs1")
	if err == nil || !strings.Contains(err.Error(), "rsa-pkcs1") {
		t.Fatalf("got %v want algorithm error", err)
	}
}

func TestSetPublicKey_NotFound(t *testing.T) {
	svc, _, _ := bootstrap(t)
	pk := make([]byte, 32)
	err := svc.SetPublicKey(t.Context(), uuid.New(), pk, "x25519")
	if err == nil {
		t.Fatal("expected error for unknown agent id")
	}
	// Storage returns ErrNotFound; service wraps it.
	if !errors.Is(err, errors.Unwrap(err)) {
		// just confirm there's an error path
		t.Log("got:", err)
	}
}
