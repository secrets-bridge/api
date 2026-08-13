package services_test

// Agent Onboarding MVP (api#178) — enrollment-token + enroll service tests.
// DB-only (the enrollment methods never touch Redis), so this harness needs
// only TEST_DATABASE_URL and constructs the service with a nil runtime client.

import (
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

type enrollHarness struct {
	svc    *services.AgentService
	pool   *storage.Pool
	connID uuid.UUID
}

func bootstrapEnroll(t *testing.T, connType string, connStatus string) *enrollHarness {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
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
			audit_events, agent_enrollment_tokens, sync_jobs, agents,
			provider_connections
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ($1, $2, 'token', '{}'::jsonb, $3) RETURNING id`,
		"enroll-conn", connType, connStatus).Scan(&connID); err != nil {
		t.Fatalf("seed provider connection: %v", err)
	}

	// nil runtime client: the enrollment methods do not use Redis.
	svc := services.NewAgentService(storage.NewAgents(pool), storage.NewAuditEvents(pool), nil).
		WithEnrollment(storage.NewAgentEnrollmentTokens(pool), storage.NewProviderConnections(pool))

	return &enrollHarness{svc: svc, pool: pool, connID: connID}
}

func (h *enrollHarness) generate(t *testing.T, in services.GenerateEnrollmentTokenInput) *services.GeneratedEnrollmentToken {
	t.Helper()
	if in.ProviderConnectionID == uuid.Nil {
		in.ProviderConnectionID = h.connID
	}
	if in.CreatedBy == "" {
		in.CreatedBy = "admin-user-1"
	}
	res, err := h.svc.GenerateEnrollmentToken(t.Context(), in)
	if err != nil {
		t.Fatalf("GenerateEnrollmentToken: %v", err)
	}
	return res
}

// 1/2/3: token minted; only its hash is stored, never the plaintext.
func TestGenerateEnrollmentToken_HashOnly_NoPlaintext(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	res := h.generate(t, services.GenerateEnrollmentTokenInput{ExpectedClusterName: "eks-x", ExpectedProviderType: "aws-sm"})
	if res.Token == "" {
		t.Fatal("token not returned")
	}

	// token_hash equals sha256(token); no column holds the plaintext.
	want := sha256.Sum256([]byte(res.Token))
	var hash []byte
	var rowText string
	if err := h.pool.QueryRow(ctx,
		`SELECT token_hash, agent_enrollment_tokens::text FROM agent_enrollment_tokens`).Scan(&hash, &rowText); err != nil {
		t.Fatalf("query token: %v", err)
	}
	if string(hash) != string(want[:]) {
		t.Errorf("stored token_hash != sha256(token)")
	}
	if strings.Contains(rowText, res.Token) {
		t.Fatalf("plaintext token leaked into agent_enrollment_tokens row: %s", rowText)
	}
}

// 7/8/9/10: successful enrollment creates a bound agent, consumes the
// token, returns the credential once, stores only its hash.
func TestEnroll_HappyPath(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{ExpectedClusterName: "eks-x", ExpectedProviderType: "aws-sm"})

	res, err := h.svc.Enroll(ctx, services.EnrollInput{
		Token:        tok.Token,
		AgentName:    "agent-01",
		AgentVersion: "v0.1.0",
		ClusterName:  "eks-x",
		ProviderType: "aws-sm",
		Region:       "eu-central-1",
		Capabilities: []string{"discover", "read", "patch"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.AgentToken == "" || res.AgentID == uuid.Nil {
		t.Fatal("enroll did not return credential + agent id")
	}
	if res.ProviderConnectionID != h.connID {
		t.Errorf("bound connection = %s want %s", res.ProviderConnectionID, h.connID)
	}
	if res.HeartbeatIntervalSeconds != 30 || res.JobPollIntervalSeconds != 5 {
		t.Errorf("intervals = %d/%d want 30/5", res.HeartbeatIntervalSeconds, res.JobPollIntervalSeconds)
	}

	// agent row: enrolled + bound + metadata; secret_hash not the plaintext.
	var status, provType, cluster string
	var boundConn uuid.UUID
	var caps []byte
	var secretHash []byte
	if err := h.pool.QueryRow(ctx, `
		SELECT status, provider_type, cluster_name, provider_connection_id, capabilities, secret_hash
		FROM agents WHERE id = $1`, res.AgentID).
		Scan(&status, &provType, &cluster, &boundConn, &caps, &secretHash); err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if status != "enrolled" {
		t.Errorf("agent status = %s want enrolled", status)
	}
	if provType != "aws-sm" || cluster != "eks-x" || boundConn != h.connID {
		t.Errorf("agent binding wrong: provider=%s cluster=%s conn=%s", provType, cluster, boundConn)
	}
	if string(caps) == "" || string(caps) == "[]" {
		t.Errorf("capabilities not persisted: %s", caps)
	}
	if string(secretHash) == res.AgentToken {
		t.Fatal("agent_token plaintext stored as secret_hash")
	}
	wantHash := sha256.Sum256([]byte(res.AgentToken))
	if string(secretHash) != string(wantHash[:]) {
		t.Error("secret_hash != sha256(agent_token)")
	}

	// token consumed + linked to the agent.
	var consumedAt *time.Time
	var consumedBy *uuid.UUID
	if err := h.pool.QueryRow(ctx,
		`SELECT consumed_at, consumed_by_agent_id FROM agent_enrollment_tokens`).Scan(&consumedAt, &consumedBy); err != nil {
		t.Fatalf("query token: %v", err)
	}
	if consumedAt == nil {
		t.Error("token not marked consumed")
	}
	if consumedBy == nil || *consumedBy != res.AgentID {
		t.Errorf("consumed_by_agent_id = %v want %s", consumedBy, res.AgentID)
	}
}

// 6: a consumed token cannot enroll a second time.
func TestEnroll_ConsumedTokenRejected(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	if _, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "aws-sm"}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	_, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a2", ProviderType: "aws-sm"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentTokenConsumed) {
		t.Fatalf("second enroll err = %v; want ErrEnrollmentTokenConsumed", err)
	}
}

// 4: an expired token cannot enroll.
func TestEnroll_ExpiredTokenRejected(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	// Backdate created_at too so the expires_at > created_at CHECK holds.
	if _, err := h.pool.Exec(ctx,
		`UPDATE agent_enrollment_tokens SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute'`); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	_, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "aws-sm"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentTokenExpired) {
		t.Fatalf("enroll err = %v; want ErrEnrollmentTokenExpired", err)
	}
}

// 5: a revoked token cannot enroll.
func TestEnroll_RevokedTokenRejected(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	if _, err := h.pool.Exec(ctx,
		`UPDATE agent_enrollment_tokens SET revoked_at = now(), revoked_by = 'admin-user-1'`); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	_, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "aws-sm"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentTokenRevoked) {
		t.Fatalf("enroll err = %v; want ErrEnrollmentTokenRevoked", err)
	}
}

// provider mismatch (agent type != connection type, and != expected).
func TestEnroll_ProviderTypeMismatch(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{ExpectedProviderType: "aws-sm"})
	_, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "vault"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentProviderMismatch) {
		t.Fatalf("enroll err = %v; want ErrEnrollmentProviderMismatch", err)
	}
}

// cluster mismatch when the token pins an expected cluster.
func TestEnroll_ClusterMismatch(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{ExpectedClusterName: "cluster-a"})
	_, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "aws-sm", ClusterName: "cluster-b"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentClusterMismatch) {
		t.Fatalf("enroll err = %v; want ErrEnrollmentClusterMismatch", err)
	}
}

// an unknown token is invalid (no enumeration).
func TestEnroll_InvalidToken(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	_, err := h.svc.Enroll(t.Context(), services.EnrollInput{Token: "not-a-real-token", AgentName: "a1", ProviderType: "aws-sm"})
	if err == nil || !errors.Is(err, services.ErrEnrollmentTokenInvalid) {
		t.Fatalf("enroll err = %v; want ErrEnrollmentTokenInvalid", err)
	}
}

// a disabled connection cannot mint an enrollment token.
func TestGenerateEnrollmentToken_DisabledConnection(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "disabled")
	_, err := h.svc.GenerateEnrollmentToken(t.Context(), services.GenerateEnrollmentTokenInput{
		ProviderConnectionID: h.connID, CreatedBy: "admin-user-1",
	})
	if err == nil || !errors.Is(err, services.ErrEnrollmentConnectionUnusable) {
		t.Fatalf("generate err = %v; want ErrEnrollmentConnectionUnusable", err)
	}
}

// 16: audit is metadata-only — neither the enrollment token nor the agent
// credential appears in any audit_events row.
func TestEnroll_AuditMetadataOnly_NoLeak(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	res, err := h.svc.Enroll(ctx, services.EnrollInput{Token: tok.Token, AgentName: "a1", ProviderType: "aws-sm", Capabilities: []string{"discover"}})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	rows, err := h.pool.Query(ctx, `SELECT action, metadata::text FROM audit_events ORDER BY occurred_at`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, meta string
		if err := rows.Scan(&action, &meta); err != nil {
			t.Fatalf("scan: %v", err)
		}
		actions = append(actions, action)
		if strings.Contains(meta, tok.Token) {
			t.Fatalf("enrollment token leaked into audit metadata (%s): %s", action, meta)
		}
		if strings.Contains(meta, res.AgentToken) {
			t.Fatalf("agent token leaked into audit metadata (%s): %s", action, meta)
		}
	}
	if !sliceContains(actions, "agent.enrollment_token.created") || !sliceContains(actions, "agent.enrolled") {
		t.Fatalf("audit actions = %v; want both agent.enrollment_token.created and agent.enrolled", actions)
	}
}
