package services_test

// Integration tests for the one-credential agent flow.
// Requires both TEST_DATABASE_URL and TEST_REDIS_URL; SKIPs otherwise.

import (
	"context"
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
	keys, _, err := rdb.Raw().Scan(scanCtx, 0, "*:agent:lastseen:"+minted.ID.String(), 10).Result()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("Heartbeat did not write last-seen to Redis")
	}
}
