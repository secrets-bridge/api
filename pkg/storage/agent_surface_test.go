package storage_test

// SQL-level guards behind the agent surface fixes: the enrollment-token
// consume (API-18) and the ciphertext scrub on wrap consume (API-S-24).

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func seedEnrollmentToken(t *testing.T, pool *storage.Pool, alter string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ($1, 'aws-sm', 'token', '{}'::jsonb, 'active') RETURNING id`,
		"tenant-a-uat-"+uuid.NewString()[:8]).Scan(&connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	tok := &storage.AgentEnrollmentToken{
		ProviderConnectionID: connID,
		TokenHash:            []byte(uuid.NewString()),
		ExpiresAt:            time.Now().Add(15 * time.Minute),
		CreatedBy:            "admin-user-1",
	}
	if err := storage.NewAgentEnrollmentTokens(pool).Create(ctx, tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if alter != "" {
		if _, err := pool.Exec(ctx, alter, tok.ID); err != nil {
			t.Fatalf("alter token: %v", err)
		}
	}
	return tok.ID
}

const (
	revokeTokenSQL = `UPDATE agent_enrollment_tokens SET revoked_at = now(), revoked_by = 'admin-user-1' WHERE id = $1`
	expireTokenSQL = `UPDATE agent_enrollment_tokens SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute' WHERE id = $1`
)

// The single-use consume refuses revoked and expired tokens, not only
// consumed ones.
func TestEnrollmentTokens_MarkConsumed_RefusesRevokedAndExpired(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	agents := storage.NewAgents(pool)
	a := &storage.Agent{Name: "agent-x", SecretHash: []byte("h")}
	if err := agents.Create(ctx, a); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	repo := storage.NewAgentEnrollmentTokens(pool)

	for name, alter := range map[string]string{"revoked": revokeTokenSQL, "expired": expireTokenSQL} {
		id := seedEnrollmentToken(t, pool, alter)
		if err := repo.MarkConsumed(ctx, id, a.ID, time.Now()); !errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
			t.Fatalf("%s token: MarkConsumed err = %v; want ErrEnrollmentTokenNotFound", name, err)
		}
	}
	id := seedEnrollmentToken(t, pool, "")
	if err := repo.MarkConsumed(ctx, id, a.ID, time.Now()); err != nil {
		t.Fatalf("live token: %v", err)
	}
}

// ConsumeAndCreateAgent never inserts an agent for a token it cannot
// consume, and links the agent when it can.
func TestEnrollmentTokens_ConsumeAndCreateAgent(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewAgentEnrollmentTokens(pool)
	newAgent := func(name string, connID uuid.UUID) *storage.Agent {
		return &storage.Agent{Name: name, SecretHash: []byte("h"), ProviderConnectionID: &connID}
	}
	connOf := func(id uuid.UUID) uuid.UUID {
		tok, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("get token: %v", err)
		}
		return tok.ProviderConnectionID
	}

	for name, alter := range map[string]string{"revoked": revokeTokenSQL, "expired": expireTokenSQL} {
		id := seedEnrollmentToken(t, pool, alter)
		if err := repo.ConsumeAndCreateAgent(ctx, id, time.Now(), newAgent("agent-"+name, connOf(id))); !errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
			t.Fatalf("%s token: err = %v; want ErrEnrollmentTokenNotFound", name, err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused consumes left %d agent rows (err=%v)", n, err)
	}

	id := seedEnrollmentToken(t, pool, "")
	a := newAgent("agent-ok", connOf(id))
	if err := repo.ConsumeAndCreateAgent(ctx, id, time.Now(), a); err != nil {
		t.Fatalf("live token: %v", err)
	}
	tok, _ := repo.Get(ctx, id)
	if tok.ConsumedAt == nil || tok.ConsumedByAgentID == nil || *tok.ConsumedByAgentID != a.ID {
		t.Fatalf("token not consumed by the new agent: %+v", tok)
	}
	if err := repo.ConsumeAndCreateAgent(ctx, id, time.Now(), newAgent("agent-again", connOf(id))); !errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
		t.Fatalf("second consume: err = %v; want ErrEnrollmentTokenNotFound", err)
	}
}

// Consuming a wrap (agent or user) leaves no ciphertext on the row.
func TestSecretWraps_ConsumeClearsCiphertext(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	agents := storage.NewAgents(pool)
	a := &storage.Agent{Name: "agent-y", SecretHash: []byte("h")}
	if err := agents.Create(ctx, a); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	wraps := storage.NewSecretWraps(pool)
	mk := func() *storage.SecretWrap {
		w := &storage.SecretWrap{
			EncryptedValue: []byte("ciphertext-bytes"), Nonce: []byte("nonce-123456"),
			DataKeyCiphertext: []byte("dek-ciphertext"), KMSKeyID: "local:test",
			ContentHash: []byte("h"), ByteLength: 5, ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := wraps.Create(ctx, w); err != nil {
			t.Fatalf("create wrap: %v", err)
		}
		return w
	}
	agentWrap, userWrap := mk(), mk()
	if err := wraps.MarkConsumed(ctx, agentWrap.ID, a.ID, time.Now()); err != nil {
		t.Fatalf("MarkConsumed: %v", err)
	}
	if err := wraps.MarkConsumedByUser(ctx, userWrap.ID, "alice", time.Now()); err != nil {
		t.Fatalf("MarkConsumedByUser: %v", err)
	}
	for _, id := range []uuid.UUID{agentWrap.ID, userWrap.ID} {
		got, err := wraps.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(got.EncryptedValue) != 0 || len(got.DataKeyCiphertext) != 0 {
			t.Fatalf("consumed wrap still holds %d ciphertext / %d dek bytes", len(got.EncryptedValue), len(got.DataKeyCiphertext))
		}
		if got.ConsumedAt == nil {
			t.Fatal("wrap not marked consumed")
		}
	}
	// A second consume still reports single-shot, not a scan error.
	if err := wraps.MarkConsumed(ctx, agentWrap.ID, a.ID, time.Now()); !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("second consume: %v; want ErrAlreadyConsumed", err)
	}
}
