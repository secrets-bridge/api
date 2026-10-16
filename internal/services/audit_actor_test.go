package services_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// API-15: the audit actor on job / agent actions comes from the request
// context, never a hard-coded "admin". The HTTP path (session user) is
// covered end to end in cmd/api; this pins the other two context shapes.
func TestAuditActor_FromContext(t *testing.T) {
	jobs, agents, pool := bootstrapJobs(t)

	actorOf := func(action, resource string) string {
		t.Helper()
		var actor string
		if err := pool.QueryRow(t.Context(),
			`SELECT actor FROM audit_events WHERE action = $1 AND resource = $2`, action, resource).Scan(&actor); err != nil {
			t.Fatalf("audit %s %s: %v", action, resource, err)
		}
		return actor
	}

	// Session user (what middleware.AuthWith stores for a signed-in caller).
	userCtx := context.WithValue(t.Context(), middleware.CtxKeyActor, "00000000-0000-4000-8000-0000000000c1")
	m, err := agents.Mint(userCtx, services.MintInput{Name: "tenant-a-uat"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if got := actorOf("agent.mint", "agent:"+m.ID.String()); got != "user:00000000-0000-4000-8000-0000000000c1" {
		t.Errorf("agent.mint actor = %q", got)
	}

	// Agent-authenticated context: the session layer marks it anonymous,
	// AgentAuth stores the agent id.
	agentID := uuid.New()
	agentCtx := context.WithValue(t.Context(), middleware.CtxKeyActor, "anonymous")
	agentCtx = context.WithValue(agentCtx, middleware.CtxKeyAgentID, agentID)
	job, err := jobs.Enqueue(agentCtx, services.EnqueueRequest{JobType: storage.JobTypeSync})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got := actorOf("job.enqueue", "job:"+job.ID.String()); got != "agent:"+agentID.String() {
		t.Errorf("agent-context job.enqueue actor = %q", got)
	}

	// No identity at all (background work) is "system", not "admin".
	job, err = jobs.Enqueue(t.Context(), services.EnqueueRequest{JobType: storage.JobTypeSync})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got := actorOf("job.enqueue", "job:"+job.ID.String()); got != "system" {
		t.Errorf("background job.enqueue actor = %q, want system", got)
	}

	// Revoke with no revoking user used to fall back to "admin".
	if err := agents.Revoke(t.Context(), m.ID, "", "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := actorOf("agent.revoked", "agent:"+m.ID.String()); got != "system" {
		t.Errorf("agent.revoked without a revoker = %q, want system", got)
	}

	// An unauthenticated HTTP request (session layer stored "anonymous")
	// is attributed as such, not as system.
	anonCtx := context.WithValue(t.Context(), middleware.CtxKeyActor, "anonymous")
	job, err = jobs.Enqueue(anonCtx, services.EnqueueRequest{JobType: storage.JobTypeSync})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got := actorOf("job.enqueue", "job:"+job.ID.String()); got != "anonymous" {
		t.Errorf("anonymous-request job.enqueue actor = %q, want anonymous", got)
	}
}
