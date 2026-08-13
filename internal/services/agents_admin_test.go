package services_test

// Agent Onboarding MVP api-2 (api#179) — richer heartbeat, revoke-with-reason,
// admin projection, and enrollment-token revoke. Reuses the DB-only enroll
// harness (nil runtime client; Authenticate falls back to Postgres on a cache
// miss, so heartbeat auth works without Redis).

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// enroll a fresh agent and return (agentID, agentToken).
func (h *enrollHarness) enroll(t *testing.T, name string) (uuid.UUID, string) {
	t.Helper()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	res, err := h.svc.Enroll(t.Context(), services.EnrollInput{
		Token: tok.Token, AgentName: name, ProviderType: "aws-sm",
		ClusterName: "eks-x", AgentVersion: "v0.1.0", Capabilities: []string{"discover"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return res.AgentID, res.AgentToken
}

// richer heartbeat flips enrolled→active and records reported fields.
func TestRecordHeartbeat_EnrolledToActive_UpdatesFields(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	id, token := h.enroll(t, "hb-agent")

	// precondition: enrolled + no last_seen.
	var status string
	if err := h.pool.QueryRow(ctx, `SELECT status FROM agents WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "enrolled" {
		t.Fatalf("precondition status = %s want enrolled", status)
	}

	if err := h.svc.RecordHeartbeat(ctx, id, token, services.HeartbeatInput{
		AgentVersion: "v0.2.0",
		LastStatus:   "active",
		Capabilities: []string{"discover", "read", "patch"},
	}); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	var version, lastStatus string
	var caps []byte
	var lastSeen *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT status, agent_version, COALESCE(last_status,''), capabilities, last_seen_at FROM agents WHERE id=$1`, id).
		Scan(&status, &version, &lastStatus, &caps, &lastSeen); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "active" {
		t.Errorf("status = %s want active (enrolled→active on first heartbeat)", status)
	}
	if version != "v0.2.0" {
		t.Errorf("agent_version = %s want v0.2.0", version)
	}
	if lastStatus != "active" {
		t.Errorf("last_status = %s want active", lastStatus)
	}
	if lastSeen == nil {
		t.Error("last_seen_at not set")
	}
	if string(caps) == "" || string(caps) == "[]" {
		t.Errorf("capabilities not updated: %s", caps)
	}
}

// a revoked agent cannot heartbeat (Authenticate rejects it).
func TestRecordHeartbeat_RevokedAgentRejected(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	id, token := h.enroll(t, "hb-revoked")

	// first heartbeat OK.
	if err := h.svc.RecordHeartbeat(ctx, id, token, services.HeartbeatInput{}); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	if err := h.svc.Revoke(ctx, id, "admin-user-1", "rotating"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// now rejected.
	err := h.svc.RecordHeartbeat(ctx, id, token, services.HeartbeatInput{})
	if err == nil || !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("post-revoke heartbeat err = %v; want ErrUnauthorized", err)
	}
}

// revoke records revoked_at + revoked_by + a metadata-only audit with reason.
func TestRevoke_RecordsReasonAndActor(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	id, _ := h.enroll(t, "rev-agent")

	if err := h.svc.Revoke(ctx, id, "admin-user-9", "credential rotation"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	var status, revokedBy string
	var revokedAt *time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT status, COALESCE(revoked_by,''), revoked_at FROM agents WHERE id=$1`, id).
		Scan(&status, &revokedBy, &revokedAt); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "revoked" || revokedBy != "admin-user-9" || revokedAt == nil {
		t.Errorf("revoke state wrong: status=%s revoked_by=%s revoked_at=%v", status, revokedBy, revokedAt)
	}
	// audit: agent.revoked with reason + agent_id + provider_connection_id
	// (QA follow-up), no credential.
	var meta string
	if err := h.pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_events WHERE action='agent.revoked'`).Scan(&meta); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(meta, "credential rotation") {
		t.Errorf("revoke audit missing reason: %s", meta)
	}
	if !strings.Contains(meta, id.String()) {
		t.Errorf("revoke audit missing agent_id: %s", meta)
	}
	if !strings.Contains(meta, h.connID.String()) {
		t.Errorf("revoke audit missing provider_connection_id: %s", meta)
	}
}

// a safe enrollment rejection emits a metadata-only agent.enrollment.rejected
// audit (reason code only, never the token) — QA follow-up.
func TestEnroll_RejectionEmitsAudit(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()

	_, err := h.svc.Enroll(ctx, services.EnrollInput{
		Token: "totally-bogus-token", AgentName: "x", ProviderType: "aws-sm",
	})
	if !errors.Is(err, services.ErrEnrollmentTokenInvalid) {
		t.Fatalf("bad-token enroll err = %v; want ErrEnrollmentTokenInvalid", err)
	}
	var meta string
	if err := h.pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_events WHERE action='agent.enrollment.rejected'`).Scan(&meta); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(meta, "token_invalid") {
		t.Errorf("enrollment.rejected audit missing reason: %s", meta)
	}
	if strings.Contains(meta, "totally-bogus-token") {
		t.Errorf("token plaintext leaked into audit: %s", meta)
	}
}

// a rejected agent auth emits a metadata-only agent.auth.rejected audit
// (reason code only, never the presented secret) — QA follow-up.
func TestAuthenticate_RejectionEmitsAudit(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	id, _ := h.enroll(t, "auth-rej")

	err := h.svc.RecordHeartbeat(ctx, id, "not-the-real-token", services.HeartbeatInput{})
	if !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("wrong-secret heartbeat err = %v; want ErrUnauthorized", err)
	}
	var meta string
	if err := h.pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_events WHERE action='agent.auth.rejected'`).Scan(&meta); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if !strings.Contains(meta, "bad_secret") {
		t.Errorf("auth.rejected audit missing reason: %s", meta)
	}
	if strings.Contains(meta, "not-the-real-token") {
		t.Errorf("presented secret leaked into audit: %s", meta)
	}
}

// admin projection returns onboarding metadata (incl. connection name) and
// no credential fields.
func TestListAgents_AdminProjection(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	id, _ := h.enroll(t, "proj-agent")

	rows, err := h.svc.ListAgents(ctx, storage.AgentAdminFilter{ProviderConnectionID: &h.connID})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d want 1", len(rows))
	}
	r := rows[0]
	if r.ID != id || r.ProviderConnectionName != "enroll-conn" || r.ProviderType != "aws-sm" || r.ClusterName != "eks-x" {
		t.Errorf("projection wrong: %+v", r)
	}
	if r.Status != storage.AgentStatusEnrolled {
		t.Errorf("status = %s want enrolled", r.Status)
	}

	// status filter narrows.
	none, err := h.svc.ListAgents(ctx, storage.AgentAdminFilter{Status: "active"})
	if err != nil {
		t.Fatalf("ListAgents(active): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("active filter returned %d; want 0 (agent is enrolled)", len(none))
	}

	// GetAgent by id.
	got, err := h.svc.GetAgent(ctx, id)
	if err != nil || got.ID != id {
		t.Fatalf("GetAgent = %v, %v", got, err)
	}
	if _, err := h.svc.GetAgent(ctx, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetAgent(random) err = %v want ErrNotFound", err)
	}
}

// a revoked enrollment token can no longer enroll.
func TestRevokeEnrollmentToken_ThenEnrollRejected(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})

	var tokID uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT id FROM agent_enrollment_tokens`).Scan(&tokID); err != nil {
		t.Fatalf("query token id: %v", err)
	}
	if err := h.svc.RevokeEnrollmentToken(ctx, tokID, "admin-user-1", "mis-issued"); err != nil {
		t.Fatalf("RevokeEnrollmentToken: %v", err)
	}
	_, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "aws-sm"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentTokenRevoked) {
		t.Fatalf("enroll after revoke err = %v; want ErrEnrollmentTokenRevoked", err)
	}
	// revoking again (now revoked) → not found / not revocable.
	if err := h.svc.RevokeEnrollmentToken(ctx, tokID, "admin-user-1", "again"); !errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
		t.Errorf("double-revoke err = %v; want ErrEnrollmentTokenNotFound", err)
	}
	// audit event present, metadata-only (no token plaintext).
	var meta string
	if err := h.pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_events WHERE action='agent.enrollment_token.revoked'`).Scan(&meta); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if strings.Contains(meta, tok.Token) {
		t.Fatalf("token plaintext leaked into revoke audit: %s", meta)
	}
}
