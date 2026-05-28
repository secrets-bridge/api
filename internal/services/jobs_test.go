package services_test

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapJobs(t *testing.T) (*services.JobService, *services.AgentService, *storage.Pool) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL are required; skipping")
	}

	ctx := t.Context()
	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 8, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
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
		URL: redisURL, PoolSize: 4,
		Namespace: fmt.Sprintf("sb-test-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	auditRepo := storage.NewAuditEvents(pool)
	jobs := services.NewJobService(storage.NewSyncJobs(pool), auditRepo)
	agents := services.NewAgentService(storage.NewAgents(pool), auditRepo, rdb)
	return jobs, agents, pool
}

func mintAgent(t *testing.T, agents *services.AgentService, name string) uuid.UUID {
	t.Helper()
	m, err := agents.Mint(t.Context(), services.MintInput{Name: name})
	if err != nil {
		t.Fatalf("Mint %s: %v", name, err)
	}
	return m.ID
}

func TestEnqueueClaimComplete_HappyPath(t *testing.T) {
	jobs, agents, _ := bootstrapJobs(t)
	ctx := t.Context()
	agentID := mintAgent(t, agents, "agent-1")

	job, err := jobs.Enqueue(ctx, services.EnqueueRequest{
		JobType: storage.JobTypeSync,
		Payload: map[string]any{"ref": "secret-123"},
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if job.Status != storage.JobStatusQueued {
		t.Fatalf("initial status: %q", job.Status)
	}

	claimed, err := jobs.Claim(ctx, agentID)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.ID != job.ID || claimed.Status != storage.JobStatusClaimed {
		t.Fatalf("claimed: %+v", claimed)
	}
	if claimed.ClaimedBy == nil || *claimed.ClaimedBy != agentID {
		t.Fatalf("claimed_by: %+v want %s", claimed.ClaimedBy, agentID)
	}

	if err := jobs.Complete(ctx, agentID, services.CompleteRequest{
		JobID:  claimed.ID,
		Status: storage.JobStatusSucceeded,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestClaim_EmptyQueueReturnsErrNoJobs(t *testing.T) {
	jobs, agents, _ := bootstrapJobs(t)
	ctx := t.Context()
	agentID := mintAgent(t, agents, "agent-1")

	_, err := jobs.Claim(ctx, agentID)
	if !errors.Is(err, storage.ErrNoJobs) {
		t.Fatalf("expected ErrNoJobs, got %v", err)
	}
}

func TestComplete_IdempotentOnTerminalRow(t *testing.T) {
	jobs, agents, _ := bootstrapJobs(t)
	ctx := t.Context()
	agentID := mintAgent(t, agents, "agent-1")

	job, _ := jobs.Enqueue(ctx, services.EnqueueRequest{JobType: storage.JobTypeSync})
	claimed, _ := jobs.Claim(ctx, agentID)
	if err := jobs.Complete(ctx, agentID, services.CompleteRequest{
		JobID: claimed.ID, Status: storage.JobStatusSucceeded,
	}); err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	// Re-complete the same row — must NOT error. Same-shape repeat
	// also accepted (allows the agent to safely retry a network
	// blip during the response phase).
	if err := jobs.Complete(ctx, agentID, services.CompleteRequest{
		JobID: claimed.ID, Status: storage.JobStatusSucceeded,
	}); err != nil {
		t.Fatalf("second Complete must be idempotent, got: %v", err)
	}
	_ = job
}

func TestComplete_RejectsOtherAgent(t *testing.T) {
	jobs, agents, _ := bootstrapJobs(t)
	ctx := t.Context()
	agentA := mintAgent(t, agents, "agent-a")
	agentB := mintAgent(t, agents, "agent-b")

	_, _ = jobs.Enqueue(ctx, services.EnqueueRequest{JobType: storage.JobTypeSync})
	claimed, _ := jobs.Claim(ctx, agentA)

	if err := jobs.Complete(ctx, agentB, services.CompleteRequest{
		JobID: claimed.ID, Status: storage.JobStatusSucceeded,
	}); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// TestClaim_ConcurrentAgents_NoDuplicateAssignment: when N agents
// race to claim one job, exactly one wins. Postgres' FOR UPDATE
// SKIP LOCKED is what guarantees this; the test pins the property.
func TestClaim_ConcurrentAgents_NoDuplicateAssignment(t *testing.T) {
	jobs, agents, _ := bootstrapJobs(t)
	ctx := t.Context()

	const N = 6
	agentIDs := make([]uuid.UUID, N)
	for i := range agentIDs {
		agentIDs[i] = mintAgent(t, agents, fmt.Sprintf("agent-%d", i))
	}
	if _, err := jobs.Enqueue(ctx, services.EnqueueRequest{JobType: storage.JobTypeSync}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	type claimResult struct {
		agentID uuid.UUID
		job     *storage.SyncJob
		err     error
	}
	results := make(chan claimResult, N)
	var wg sync.WaitGroup
	for _, id := range agentIDs {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := jobs.Claim(ctx, id)
			results <- claimResult{agentID: id, job: job, err: err}
		}()
	}
	wg.Wait()
	close(results)

	wins := 0
	for r := range results {
		switch {
		case errors.Is(r.err, storage.ErrNoJobs):
			// loser — fine
		case r.err != nil:
			t.Errorf("agent %s got unexpected error: %v", r.agentID, r.err)
		case r.job != nil:
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly one agent to claim the job, got %d", wins)
	}
}

// TestClaim_ExpiredLeaseReturnsToQueue: a stale claim (claim_expires_at
// < now) is treated as queued by the next Claim call.
func TestClaim_ExpiredLeaseReturnsToQueue(t *testing.T) {
	jobs, agents, pool := bootstrapJobs(t)
	ctx := t.Context()
	agentA := mintAgent(t, agents, "agent-a")
	agentB := mintAgent(t, agents, "agent-b")

	_, _ = jobs.Enqueue(ctx, services.EnqueueRequest{JobType: storage.JobTypeSync})
	claimed, _ := jobs.Claim(ctx, agentA)

	// Backdate the claim so it looks expired. (We can't wait 30s in a
	// unit test; rewriting claim_expires_at directly is the standard
	// pattern for these tests.)
	if _, err := pool.Exec(ctx,
		`UPDATE sync_jobs SET claim_expires_at = now() - interval '1 minute' WHERE id = $1`,
		claimed.ID,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// Agent B's claim must pick up the stale row.
	again, err := jobs.Claim(ctx, agentB)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if again.ID != claimed.ID {
		t.Fatalf("expected stale row to be re-claimed, got different id: %s != %s", again.ID, claimed.ID)
	}
	if again.ClaimedBy == nil || *again.ClaimedBy != agentB {
		t.Fatalf("re-claim ownership: %+v want %s", again.ClaimedBy, agentB)
	}
}
