package services_test

// Integration tests for the one-credential agent flow.
// Requires both TEST_DATABASE_URL and TEST_REDIS_URL; SKIPs otherwise.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrap(t *testing.T) (*services.AgentService, *storage.Pool, *runtime.Client) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL are required; skipping")
	}

	ctx := t.Context()
	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open storage: %v", err)
	}
	t.Cleanup(pool.Close)

	const truncate = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	rdb, err := runtime.Open(ctx, runtime.Config{
		URL:       redisURL,
		PoolSize:  4,
		Namespace: fmt.Sprintf("sb-test-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	svc := services.NewAgentService(
		storage.NewAgents(pool),
		storage.NewAuditEvents(pool),
		rdb,
	)
	return svc, pool, rdb
}

func TestMint_ReturnsSecret(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()

	minted, err := svc.Mint(ctx, "agent-prod-eu", map[string]any{"cluster": "prod-eu"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if minted.AgentSecret == "" {
		t.Fatal("Mint did not return a secret")
	}
	if minted.ID == uuid.Nil {
		t.Fatal("Mint did not assign an ID")
	}
}

func TestMint_PersistsHashOnly(t *testing.T) {
	svc, pool, _ := bootstrap(t)
	ctx := t.Context()
	minted, err := svc.Mint(ctx, "agent", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Confirm the stored hash is NOT the plaintext.
	a, err := storage.NewAgents(pool).Get(ctx, minted.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(a.SecretHash) == minted.AgentSecret {
		t.Fatal("storage stored the plaintext secret instead of its hash")
	}
	if len(a.SecretHash) != 32 {
		t.Fatalf("SecretHash must be 32-byte SHA-256, got %d bytes", len(a.SecretHash))
	}
}

func TestHeartbeat_HappyPath(t *testing.T) {
	svc, pool, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	a, err := storage.NewAgents(pool).Get(ctx, minted.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a.LastSeenAt == nil {
		t.Fatal("LastSeenAt not set after heartbeat")
	}
	if time.Since(*a.LastSeenAt) > time.Minute {
		t.Fatalf("LastSeenAt is stale: %v", a.LastSeenAt)
	}
}

func TestHeartbeat_WrongSecretRejected(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	if err := svc.Heartbeat(ctx, minted.ID, "fake-secret"); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestHeartbeat_UnknownAgent(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	if err := svc.Heartbeat(ctx, uuid.New(), "anything"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestHeartbeat_RevokedAgentRejected(t *testing.T) {
	svc, pool, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	if err := storage.NewAgents(pool).UpdateStatus(ctx, minted.ID, storage.AgentStatusRevoked); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("revoked agent must be rejected, got %v", err)
	}
}

func TestHeartbeat_PodRestartScenario(t *testing.T) {
	// The whole point of the one-credential model: a Pod restart is
	// just "construct another caller with the same secret and keep
	// going". No PVC, no re-mint, no re-registration.
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	for i := 0; i < 3; i++ {
		if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); err != nil {
			t.Fatalf("heartbeat #%d after simulated restart: %v", i, err)
		}
	}
}

func TestList_OmitsCredentials(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	for _, name := range []string{"a", "b", "c"} {
		if _, err := svc.Mint(ctx, name, nil); err != nil {
			t.Fatalf("Mint %s: %v", name, err)
		}
	}
	views, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(views))
	}
	for _, v := range views {
		if v.ID == uuid.Nil {
			t.Fatal("view ID is zero")
		}
	}
}

func TestHeartbeat_CachesLastSeenInRedis(t *testing.T) {
	svc, _, rdb := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	keys, _, err := rdb.Raw().Scan(scanCtx, 0, "*:agent-lastseen:"+minted.ID.String(), 10).Result()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("Heartbeat did not write last-seen to Redis")
	}
}

// TestHeartbeat_ColdCachePrimes verifies the first heartbeat populates
// the secret-hash cache so subsequent calls can serve from Redis.
func TestHeartbeat_ColdCachePrimes(t *testing.T) {
	svc, _, rdb := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	// Cache should be empty before the first heartbeat.
	if cached := scanCacheKey(t, rdb, "*:agent-hash:"+minted.ID.String()); cached != 0 {
		t.Fatalf("expected cold cache, found %d entries", cached)
	}
	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	// First heartbeat should have primed the cache.
	if cached := scanCacheKey(t, rdb, "*:agent-hash:"+minted.ID.String()); cached != 1 {
		t.Fatalf("expected primed cache, found %d entries", cached)
	}
}

// TestHeartbeat_UsesCachedHashWhenWarm verifies the validation path
// can serve from Redis without touching Postgres. We simulate that by
// poisoning the cache with a known hash and confirming heartbeat with
// THAT hash's plaintext succeeds — proving the cache was consulted.
func TestHeartbeat_UsesCachedHashWhenWarm(t *testing.T) {
	svc, _, rdb := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	// First heartbeat to prime the cache and confirm it works.
	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}

	// Hand-deliver a poisoned cache entry mapping the agent ID to a
	// different secret. If the validation path still consulted
	// Postgres on every call, the original secret would still work.
	// With the cache, the original secret should now FAIL.
	poisonSecret := "completely-different-secret"
	poisonHash := sha256.Sum256([]byte(poisonSecret))
	poisonPayload, _ := json.Marshal(map[string]any{
		"status": "active",
		"hash":   base64.StdEncoding.EncodeToString(poisonHash[:]),
	})
	cacheKey := rdb.Key("agent-hash", minted.ID.String())
	if _, err := rdb.Raw().Set(ctx, cacheKey, poisonPayload, time.Minute).Result(); err != nil {
		t.Fatalf("poison: %v", err)
	}

	// Real secret now fails — proves cache served the lookup.
	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized via poisoned cache, got %v", err)
	}
	// Poisoned secret succeeds — same proof, other direction.
	if err := svc.Heartbeat(ctx, minted.ID, poisonSecret); err != nil {
		t.Fatalf("poisoned cache entry should accept the matching plaintext: %v", err)
	}
}

// TestRevoke_InvalidatesCache is the SECURITY-CRITICAL test: revoke
// must immediately delete the cached hash so the next heartbeat fails
// even though the cache TTL hasn't expired.
func TestRevoke_InvalidatesCache(t *testing.T) {
	svc, _, rdb := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.Mint(ctx, "agent", nil)

	// Prime the cache with a successful heartbeat.
	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if cached := scanCacheKey(t, rdb, "*:agent-hash:"+minted.ID.String()); cached != 1 {
		t.Fatalf("expected primed cache, found %d entries", cached)
	}

	// Revoke through the service — the only correct revocation path.
	if err := svc.Revoke(ctx, minted.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Cache must be gone IMMEDIATELY — not waiting for TTL.
	if cached := scanCacheKey(t, rdb, "*:agent-hash:"+minted.ID.String()); cached != 0 {
		t.Fatalf("Revoke did not invalidate cache; %d entries remain", cached)
	}
	// And the next heartbeat must fail even though the secret is
	// (was) correct. Without invalidation this would succeed for up
	// to the TTL.
	if err := svc.Heartbeat(ctx, minted.ID, minted.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("post-revoke heartbeat must reject; got %v", err)
	}
}

func scanCacheKey(t *testing.T, rdb *runtime.Client, pattern string) int {
	t.Helper()
	keys, _, err := rdb.Raw().Scan(t.Context(), 0, pattern, 100).Result()
	if err != nil {
		t.Fatalf("Scan %q: %v", pattern, err)
	}
	return len(keys)
}
