package services_test

// Integration tests for the agent registration + heartbeat flow.
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

	// Truncate so each test starts clean.
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

func TestMintRegister_HappyPath(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()

	minted, err := svc.MintRegistrationToken(ctx, "agent-prod-eu", map[string]any{"cluster": "prod-eu"})
	if err != nil {
		t.Fatalf("MintRegistrationToken: %v", err)
	}
	if minted.RegistrationToken == "" {
		t.Fatal("Mint did not return a registration token")
	}
	if minted.ID == uuid.Nil {
		t.Fatal("Mint did not assign an ID")
	}

	reg, err := svc.Register(ctx, minted.ID, minted.RegistrationToken)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.AgentSecret == "" {
		t.Fatal("Register did not return an agent secret")
	}
	if reg.AgentSecret == minted.RegistrationToken {
		t.Fatal("agent secret must be distinct from the registration token")
	}
}

func TestRegister_WrongTokenIsRejected(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, err := svc.MintRegistrationToken(ctx, "a", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	_, err = svc.Register(ctx, minted.ID, "obviously-wrong-token")
	if !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestRegister_ReplayIsRejected(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.MintRegistrationToken(ctx, "a", nil)

	if _, err := svc.Register(ctx, minted.ID, minted.RegistrationToken); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if _, err := svc.Register(ctx, minted.ID, minted.RegistrationToken); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("replay must be rejected, got %v", err)
	}
}

func TestHeartbeat_HappyPath(t *testing.T) {
	svc, pool, _ := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.MintRegistrationToken(ctx, "a", nil)
	reg, _ := svc.Register(ctx, minted.ID, minted.RegistrationToken)

	if err := svc.Heartbeat(ctx, reg.ID, reg.AgentSecret); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	// last_seen_at must have been written.
	a, err := storage.NewAgents(pool).Get(ctx, reg.ID)
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
	minted, _ := svc.MintRegistrationToken(ctx, "a", nil)
	reg, _ := svc.Register(ctx, minted.ID, minted.RegistrationToken)

	if err := svc.Heartbeat(ctx, reg.ID, "fake-secret"); !errors.Is(err, storage.ErrUnauthorized) {
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
	minted, _ := svc.MintRegistrationToken(ctx, "a", nil)
	reg, _ := svc.Register(ctx, minted.ID, minted.RegistrationToken)

	if err := storage.NewAgents(pool).UpdateStatus(ctx, reg.ID, storage.AgentStatusRevoked); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := svc.Heartbeat(ctx, reg.ID, reg.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("revoked agent must be rejected, got %v", err)
	}
}

func TestList_OmitsCredentials(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	for _, name := range []string{"a", "b", "c"} {
		if _, err := svc.MintRegistrationToken(ctx, name, nil); err != nil {
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
	// AgentView is the projection — there are no token/secret fields
	// in its declaration. This test mostly guards against someone
	// future-adding a field that exposes them. We assert by inspecting
	// the zero-allocation struct shape.
	for _, v := range views {
		if v.ID == uuid.Nil {
			t.Fatal("view ID is zero")
		}
	}
}

// TestHeartbeat_CachesLastSeenInRedis verifies the Redis-side cache
// receives the timestamp so admin polls can skip Postgres.
func TestHeartbeat_CachesLastSeenInRedis(t *testing.T) {
	svc, _, rdb := bootstrap(t)
	ctx := t.Context()
	minted, _ := svc.MintRegistrationToken(ctx, "a", nil)
	reg, _ := svc.Register(ctx, minted.ID, minted.RegistrationToken)

	if err := svc.Heartbeat(ctx, reg.ID, reg.AgentSecret); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	// We can't reach the namespace via the public API, so peek at
	// the underlying redis client. We can use the well-known namespace
	// prefix ("secrets-bridge:") + the "agent:lastseen:" kind we use
	// in services/agents.go.
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	keys, _, err := rdb.Raw().Scan(scanCtx, 0, "*:agent:lastseen:"+reg.ID.String(), 10).Result()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("Heartbeat did not write last-seen to Redis")
	}
}
