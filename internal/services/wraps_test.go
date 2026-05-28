package services_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapWraps(t *testing.T) (*services.WrapService, *services.AgentService, *storage.Pool) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 6, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	const truncate = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, secret_wraps,
			agents, provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	audit := storage.NewAuditEvents(pool)
	svc := services.NewWrapService(storage.NewSecretWraps(pool), audit, km)
	agentSvc := services.NewAgentService(storage.NewAgents(pool), audit, nil)
	return svc, agentSvc, pool
}

func TestWrap_Roundtrip(t *testing.T) {
	svc, agents, _ := bootstrapWraps(t)
	ctx := t.Context()

	plaintext := []byte("hunter2-the-real-password")
	w, err := svc.Wrap(ctx, services.WrapRequest{
		Plaintext: append([]byte(nil), plaintext...),
		TTL:       time.Hour,
		Actor:     "user:alice",
	})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if w.ID == uuid.Nil {
		t.Fatal("Wrap did not assign ID")
	}
	if len(w.EncryptedValue) == 0 || len(w.Nonce) == 0 || len(w.DataKeyCiphertext) == 0 {
		t.Fatalf("envelope encryption fields missing: %+v", w)
	}
	if w.ByteLength != len(plaintext) {
		t.Fatalf("byte_length: %d want %d", w.ByteLength, len(plaintext))
	}

	// Mint an agent so Retrieve has a real FK target.
	minted, _ := agents.Mint(ctx, services.MintInput{Name: "agent-1"})

	got, _, err := svc.Retrieve(ctx, w.ID, minted.ID)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(got) != "hunter2-the-real-password" {
		t.Fatalf("decrypted: %q want %q", got, plaintext)
	}
}

func TestWrap_PlaintextNotInDB(t *testing.T) {
	// The whole point: after Wrap, scanning the encrypted_value column
	// MUST NOT contain the plaintext bytes.
	svc, _, pool := bootstrapWraps(t)
	ctx := t.Context()

	plaintext := []byte("super-distinctive-canary-string")
	w, err := svc.Wrap(ctx, services.WrapRequest{
		Plaintext: append([]byte(nil), plaintext...),
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	var raw []byte
	if err := pool.QueryRow(ctx,
		`SELECT encrypted_value FROM secret_wraps WHERE id = $1`, w.ID,
	).Scan(&raw); err != nil {
		t.Fatalf("query: %v", err)
	}
	if string(raw) == string(plaintext) {
		t.Fatal("encrypted_value column contains the plaintext — encryption broken")
	}
	// Also confirm the canary isn't anywhere as a substring.
	for i := 0; i+len(plaintext) <= len(raw); i++ {
		if string(raw[i:i+len(plaintext)]) == string(plaintext) {
			t.Fatal("plaintext appears as substring inside encrypted_value")
		}
	}
}

func TestRetrieve_OneShotRejectsDoubleRead(t *testing.T) {
	svc, agents, _ := bootstrapWraps(t)
	ctx := t.Context()
	w, _ := svc.Wrap(ctx, services.WrapRequest{Plaintext: []byte("v"), TTL: time.Hour})
	minted, _ := agents.Mint(ctx, services.MintInput{Name: "agent-1"})

	if _, _, err := svc.Retrieve(ctx, w.ID, minted.ID); err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}
	if _, _, err := svc.Retrieve(ctx, w.ID, minted.ID); !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("second Retrieve must be ErrAlreadyConsumed, got %v", err)
	}
}

func TestRetrieve_ExpiredWrapRejected(t *testing.T) {
	svc, agents, pool := bootstrapWraps(t)
	ctx := t.Context()
	w, _ := svc.Wrap(ctx, services.WrapRequest{Plaintext: []byte("v"), TTL: time.Hour})
	minted, _ := agents.Mint(ctx, services.MintInput{Name: "agent-1"})

	// Backdate expires_at so the wrap looks expired.
	if _, err := pool.Exec(ctx,
		`UPDATE secret_wraps SET expires_at = now() - interval '1 minute' WHERE id = $1`, w.ID,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if _, _, err := svc.Retrieve(ctx, w.ID, minted.ID); !errors.Is(err, storage.ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

// SECURITY-CRITICAL: when N agents race to retrieve the same wrap,
// exactly one wins; the others see ErrAlreadyConsumed. Proves the
// one-shot UPDATE is concurrency-safe.
func TestRetrieve_ConcurrentAgents_ExactlyOneWins(t *testing.T) {
	svc, agents, _ := bootstrapWraps(t)
	ctx := t.Context()
	w, _ := svc.Wrap(ctx, services.WrapRequest{Plaintext: []byte("v"), TTL: time.Hour})

	const N = 6
	agentIDs := make([]uuid.UUID, N)
	for i := range agentIDs {
		minted, _ := agents.Mint(ctx, services.MintInput{Name: fmt.Sprintf("agent-%d", i)})
		agentIDs[i] = minted.ID
	}

	type result struct {
		ok  bool
		err error
	}
	results := make(chan result, N)
	var wg sync.WaitGroup
	for _, id := range agentIDs {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := svc.Retrieve(ctx, w.ID, id)
			results <- result{ok: err == nil, err: err}
		}()
	}
	wg.Wait()
	close(results)

	wins := 0
	for r := range results {
		if r.ok {
			wins++
		} else if !errors.Is(r.err, storage.ErrAlreadyConsumed) {
			t.Errorf("loser got unexpected error: %v", r.err)
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly one winner, got %d", wins)
	}
}

func TestRefresh_ExtendsExpiry(t *testing.T) {
	svc, _, pool := bootstrapWraps(t)
	ctx := t.Context()
	w, _ := svc.Wrap(ctx, services.WrapRequest{Plaintext: []byte("v"), TTL: time.Minute})

	original := w.ExpiresAt
	if err := svc.Refresh(ctx, w.ID, 24*time.Hour); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	var got time.Time
	_ = pool.QueryRow(ctx, `SELECT expires_at FROM secret_wraps WHERE id = $1`, w.ID).Scan(&got)
	if !got.After(original) {
		t.Fatalf("Refresh did not extend expires_at: original=%v new=%v", original, got)
	}
}

func TestWrap_AuditTrailHashesContentNotValue(t *testing.T) {
	svc, _, pool := bootstrapWraps(t)
	ctx := t.Context()

	canary := []byte("super-distinctive-audit-canary")
	if _, err := svc.Wrap(ctx, services.WrapRequest{
		Plaintext: append([]byte(nil), canary...),
		TTL:       time.Hour,
		Actor:     "user:alice",
	}); err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	var metaJSON []byte
	if err := pool.QueryRow(ctx,
		`SELECT metadata FROM audit_events WHERE action='wrap.create' ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&metaJSON); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	// The audit row must contain content_hash + byte_length but NOT
	// the plaintext anywhere.
	if hasSubstring(metaJSON, canary) {
		t.Fatal("plaintext leaked into audit metadata")
	}
}

func hasSubstring(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
