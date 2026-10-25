package services_test

// Agent Onboarding MVP (api#178) — enrollment-token + enroll service tests.
// DB-only (the enrollment methods never touch Redis), so this harness needs
// only TEST_DATABASE_URL and constructs the service with a nil runtime client.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/sealing"
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

// enrollKey is a customer-side X25519 key for one enrollment.
type enrollKey struct{ pub, priv []byte }

func newEnrollKey(t *testing.T) enrollKey {
	t.Helper()
	pub, priv, err := sealing.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return enrollKey{pub, priv}
}

func (k enrollKey) b64() string { return base64.StdEncoding.EncodeToString(k.pub) }

// open decrypts a challenge as the enroll CLI does.
func (k enrollKey) open(t *testing.T, ch *services.KeyChallenge) string {
	t.Helper()
	nonce, err := sealing.Open(ch.Sealed, k.priv, k.pub)
	if err != nil {
		t.Fatalf("open challenge: %v", err)
	}
	return base64.StdEncoding.EncodeToString(nonce)
}

func (h *enrollHarness) challenge(t *testing.T, token string, k enrollKey) *services.KeyChallenge {
	t.Helper()
	ch, err := h.svc.EnrollChallenge(t.Context(), services.EnrollChallengeInput{
		SchemaVersion: "2", Token: token, PublicKey: k.b64(), PublicKeyAlgorithm: "x25519",
	})
	if err != nil {
		t.Fatalf("EnrollChallenge: %v", err)
	}
	return ch
}

// enroll runs both steps with a fresh key.
func (h *enrollHarness) enroll(t *testing.T, token, name string) (*services.EnrolledAgent, enrollKey, error) {
	t.Helper()
	k := newEnrollKey(t)
	ch := h.challenge(t, token, k)
	res, err := h.svc.Enroll(t.Context(), services.EnrollInput{
		SchemaVersion: "2", Token: token, ChallengeID: ch.ChallengeID.String(),
		ChallengeResponse: k.open(t, ch), Name: name, ProviderType: "aws-sm", ClusterName: "eks-x",
	})
	return res, k, err
}

func wantReason(t *testing.T, err error, base error, reason string) {
	t.Helper()
	if !errors.Is(err, base) || services.RejectionReason(err) != reason {
		t.Fatalf("err = %v (reason %q); want %v with reason %q", err, services.RejectionReason(err), base, reason)
	}
}

// Happy path with a real X25519 key: the agent is bound to the token's
// connection and to the challenged key, the token and challenge are
// used, and only the secret's hash is stored.
func TestEnroll_HappyPath(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{ExpectedClusterName: "eks-x", ExpectedProviderType: "aws-sm"})
	k := newEnrollKey(t)
	ch := h.challenge(t, tok.Token, k)
	if ch.Sealed.Algorithm != sealing.Algorithm || time.Until(ch.ExpiresAt) > 121*time.Second {
		t.Fatalf("challenge algorithm %q, expires %s", ch.Sealed.Algorithm, ch.ExpiresAt)
	}
	res, err := h.svc.Enroll(ctx, services.EnrollInput{
		SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(), ChallengeResponse: k.open(t, ch),
		Name: "agent-01", ClusterName: "eks-x", ProviderType: "aws-sm", Region: "eu-central-1",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.AgentSecret == "" || res.AgentID == uuid.Nil || res.ProviderConnectionID != h.connID {
		t.Fatalf("enroll result %+v", res)
	}
	if res.PublicKeyFingerprint != sealing.Fingerprint(k.pub) || res.PublicKeyVersion != 1 {
		t.Fatalf("fingerprint %q version %d", res.PublicKeyFingerprint, res.PublicKeyVersion)
	}
	if res.HeartbeatIntervalSeconds != 30 || res.ClaimIntervalSeconds != 5 {
		t.Errorf("intervals = %d/%d want 30/5", res.HeartbeatIntervalSeconds, res.ClaimIntervalSeconds)
	}

	var (
		status, provType, cluster, fp string
		boundConn                     uuid.UUID
		pub, secretHash               []byte
		version                       int
	)
	if err := h.pool.QueryRow(ctx, `
		SELECT status, provider_type, cluster_name, provider_connection_id, public_key,
		       public_key_fingerprint, public_key_version, secret_hash
		FROM agents WHERE id = $1`, res.AgentID).
		Scan(&status, &provType, &cluster, &boundConn, &pub, &fp, &version, &secretHash); err != nil {
		t.Fatalf("query agent: %v", err)
	}
	if status != "enrolled" || provType != "aws-sm" || cluster != "eks-x" || boundConn != h.connID {
		t.Errorf("agent binding wrong: %s %s %s %s", status, provType, cluster, boundConn)
	}
	if string(pub) != string(k.pub) || fp != res.PublicKeyFingerprint || version != 1 {
		t.Errorf("bound key wrong: fp=%s version=%d", fp, version)
	}
	wantHash := sha256.Sum256([]byte(res.AgentSecret))
	if string(secretHash) != string(wantHash[:]) {
		t.Error("secret_hash != sha256(agent_secret)")
	}

	var consumedBy *uuid.UUID
	var usedAt *time.Time
	var usedBy *uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT consumed_by_agent_id FROM agent_enrollment_tokens`).Scan(&consumedBy); err != nil {
		t.Fatalf("query token: %v", err)
	}
	if consumedBy == nil || *consumedBy != res.AgentID {
		t.Errorf("consumed_by_agent_id = %v want %s", consumedBy, res.AgentID)
	}
	if err := h.pool.QueryRow(ctx, `SELECT used_at, used_by_agent_id FROM agent_enrollment_challenges WHERE id = $1`, ch.ChallengeID).
		Scan(&usedAt, &usedBy); err != nil {
		t.Fatalf("query challenge: %v", err)
	}
	if usedAt == nil || usedBy == nil || *usedBy != res.AgentID {
		t.Errorf("challenge used_at=%v used_by=%v", usedAt, usedBy)
	}
	// The nonce is stored only as its hash: the stored value is not the
	// response the client sent.
	var nonceHash []byte
	if err := h.pool.QueryRow(ctx, `SELECT nonce_hash FROM agent_enrollment_challenges`).Scan(&nonceHash); err != nil {
		t.Fatalf("nonce hash: %v", err)
	}
	if base64.StdEncoding.EncodeToString(nonceHash) == k.open(t, ch) {
		t.Fatal("nonce stored in plaintext")
	}
}

// The challenge step validates the token without consuming it.
func TestEnrollChallenge_DoesNotConsumeToken(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	h.challenge(t, tok.Token, newEnrollKey(t))
	h.challenge(t, tok.Token, newEnrollKey(t))
	var consumed *time.Time
	if err := h.pool.QueryRow(t.Context(), `SELECT consumed_at FROM agent_enrollment_tokens`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != nil {
		t.Fatal("challenge consumed the token")
	}
}

// Expired, reused, revoked and unknown tokens are refused at both steps.
func TestEnroll_BadTokens(t *testing.T) {
	cases := []struct {
		name   string
		alter  string
		reason string
	}{
		{"expired", `UPDATE agent_enrollment_tokens SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute'`, "token_expired"},
		{"revoked", `UPDATE agent_enrollment_tokens SET revoked_at = now(), revoked_by = 'admin-user-1'`, "token_revoked"},
		{"used", `UPDATE agent_enrollment_tokens SET consumed_at = now()`, "token_already_consumed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := bootstrapEnroll(t, "aws-sm", "active")
			ctx := t.Context()
			tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
			k := newEnrollKey(t)
			ch := h.challenge(t, tok.Token, k)
			if _, err := h.pool.Exec(ctx, tc.alter); err != nil {
				t.Fatal(err)
			}
			_, err := h.svc.EnrollChallenge(ctx, services.EnrollChallengeInput{SchemaVersion: "2", Token: tok.Token, PublicKey: k.b64(), PublicKeyAlgorithm: "x25519"})
			wantReason(t, err, services.ErrEnrollmentRejected, tc.reason)
			_, err = h.svc.Enroll(ctx, services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
				ChallengeResponse: k.open(t, ch), Name: "a1", ProviderType: "aws-sm"})
			wantReason(t, err, services.ErrEnrollmentRejected, tc.reason)
			var agents int
			_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&agents)
			if agents != 0 {
				t.Fatalf("%d agents created", agents)
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		_, err := h.svc.EnrollChallenge(t.Context(), services.EnrollChallengeInput{SchemaVersion: "2", Token: "not-a-real-token", PublicKey: newEnrollKey(t).b64(), PublicKeyAlgorithm: "x25519"})
		wantReason(t, err, services.ErrEnrollmentRejected, "token_invalid")
	})
	t.Run("reused after enroll", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
		if _, _, err := h.enroll(t, tok.Token, "a1"); err != nil {
			t.Fatalf("first enroll: %v", err)
		}
		_, err := h.svc.EnrollChallenge(t.Context(), services.EnrollChallengeInput{SchemaVersion: "2", Token: tok.Token, PublicKey: newEnrollKey(t).b64(), PublicKeyAlgorithm: "x25519"})
		wantReason(t, err, services.ErrEnrollmentRejected, "token_already_consumed")
	})
}

// A challenge from another token, a wrong response, a reused challenge,
// an expired one and an unknown id are all refused, and none creates an
// agent or burns the token.
func TestEnroll_ChallengeFailures(t *testing.T) {
	t.Run("from another token", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		a := h.generate(t, services.GenerateEnrollmentTokenInput{})
		b := h.generate(t, services.GenerateEnrollmentTokenInput{})
		k := newEnrollKey(t)
		chA := h.challenge(t, a.Token, k)
		_, err := h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: "2", Token: b.Token, ChallengeID: chA.ChallengeID.String(),
			ChallengeResponse: k.open(t, chA), Name: "x", ProviderType: "aws-sm"})
		wantReason(t, err, services.ErrEnrollmentRejected, "challenge_token_mismatch")
		// Token b is not burned, and challenge a still works with token a.
		if _, err := h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: "2", Token: a.Token, ChallengeID: chA.ChallengeID.String(),
			ChallengeResponse: k.open(t, chA), Name: "x", ProviderType: "aws-sm"}); err != nil {
			t.Fatalf("challenge a with token a: %v", err)
		}
		if _, _, err := h.enroll(t, b.Token, "y"); err != nil {
			t.Fatalf("token b after the refused attempt: %v", err)
		}
	})
	t.Run("wrong response burns the challenge", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
		k := newEnrollKey(t)
		ch := h.challenge(t, tok.Token, k)
		wrong := base64.StdEncoding.EncodeToString(make([]byte, 32))
		_, err := h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
			ChallengeResponse: wrong, Name: "x", ProviderType: "aws-sm"})
		wantReason(t, err, services.ErrEnrollmentRejected, "challenge_mismatch")
		// One guess per challenge: the right answer no longer works.
		_, err = h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
			ChallengeResponse: k.open(t, ch), Name: "x", ProviderType: "aws-sm"})
		wantReason(t, err, services.ErrEnrollmentRejected, "challenge_invalidated")
		// The token survives: a new challenge enrolls.
		if _, _, err := h.enroll(t, tok.Token, "x"); err != nil {
			t.Fatalf("enroll with a fresh challenge: %v", err)
		}
	})
	t.Run("someone else's key cannot answer", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
		victim, attacker := newEnrollKey(t), newEnrollKey(t)
		ch := h.challenge(t, tok.Token, victim)
		if _, err := sealing.Open(ch.Sealed, attacker.priv, attacker.pub); err == nil {
			t.Fatal("a challenge opened with another key")
		}
	})
	t.Run("reused after enroll", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
		tok2 := h.generate(t, services.GenerateEnrollmentTokenInput{})
		k := newEnrollKey(t)
		ch := h.challenge(t, tok.Token, k)
		in := services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
			ChallengeResponse: k.open(t, ch), Name: "x", ProviderType: "aws-sm"}
		if _, err := h.svc.Enroll(t.Context(), in); err != nil {
			t.Fatalf("enroll: %v", err)
		}
		// Even unburned, the used challenge is refused on the same token,
		// which is consumed, and on another.
		in.Name = "y"
		_, err := h.svc.Enroll(t.Context(), in)
		wantReason(t, err, services.ErrEnrollmentRejected, "token_already_consumed")
		if _, err := h.pool.Exec(t.Context(), `UPDATE agent_enrollment_challenges SET enrollment_token_id = $1`, tok2.ID); err != nil {
			t.Fatal(err)
		}
		in.Token = tok2.Token
		_, err = h.svc.Enroll(t.Context(), in)
		wantReason(t, err, services.ErrEnrollmentRejected, "challenge_used")
	})
	t.Run("expired", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
		k := newEnrollKey(t)
		ch := h.challenge(t, tok.Token, k)
		if _, err := h.pool.Exec(t.Context(),
			`UPDATE agent_enrollment_challenges SET created_at = now() - interval '5 minutes', expires_at = now() - interval '1 minute'`); err != nil {
			t.Fatal(err)
		}
		_, err := h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
			ChallengeResponse: k.open(t, ch), Name: "x", ProviderType: "aws-sm"})
		wantReason(t, err, services.ErrEnrollmentRejected, "challenge_expired")
	})
	t.Run("unknown id", func(t *testing.T) {
		h := bootstrapEnroll(t, "aws-sm", "active")
		tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
		_, err := h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: uuid.NewString(),
			ChallengeResponse: base64.StdEncoding.EncodeToString(make([]byte, 32)), Name: "x", ProviderType: "aws-sm"})
		wantReason(t, err, services.ErrEnrollmentRejected, "challenge_not_found")
	})
}

// The low-order and all-zero keys, wrong lengths, bad base64 and other
// algorithms are refused before any challenge is made.
func TestEnrollChallenge_InvalidKeys(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	order1 := make([]byte, 32)
	order1[0] = 1 // u = 1: a low-order point
	cases := map[string]services.EnrollChallengeInput{
		"all zero":      {PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), PublicKeyAlgorithm: "x25519"},
		"low order u=1": {PublicKey: base64.StdEncoding.EncodeToString(order1), PublicKeyAlgorithm: "x25519"},
		"31 bytes":      {PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 31)), PublicKeyAlgorithm: "x25519"},
		"not base64":    {PublicKey: "!!!", PublicKeyAlgorithm: "x25519"},
		"ed25519":       {PublicKey: newEnrollKey(t).b64(), PublicKeyAlgorithm: "ed25519"},
		"no algorithm":  {PublicKey: newEnrollKey(t).b64()},
	}
	for name, in := range cases {
		in.SchemaVersion, in.Token = "2", tok.Token
		if _, err := h.svc.EnrollChallenge(t.Context(), in); !errors.Is(err, services.ErrInvalidPublicKey) {
			t.Errorf("%s: err = %v; want ErrInvalidPublicKey", name, err)
		}
	}
	var n int
	_ = h.pool.QueryRow(t.Context(), `SELECT count(*) FROM agent_enrollment_challenges`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d challenges made for invalid keys", n)
	}
}

// Without schema_version "2" both steps are refused: no legacy fallback.
func TestEnroll_SchemaVersionRequired(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	for _, v := range []string{"", "1", "3"} {
		_, err := h.svc.EnrollChallenge(t.Context(), services.EnrollChallengeInput{SchemaVersion: v, Token: tok.Token, PublicKey: newEnrollKey(t).b64(), PublicKeyAlgorithm: "x25519"})
		if !errors.Is(err, services.ErrUnsupportedSchemaVersion) {
			t.Errorf("challenge schema %q: err = %v", v, err)
		}
		_, err = h.svc.Enroll(t.Context(), services.EnrollInput{SchemaVersion: v, Token: tok.Token, Name: "a"})
		if !errors.Is(err, services.ErrUnsupportedSchemaVersion) {
			t.Errorf("enroll schema %q: err = %v", v, err)
		}
	}
}

// The agent is bound to the token's connection: a provider type other
// than the connection's, or a cluster other than the token's, is refused.
func TestEnroll_ConnectionBinding(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	var other uuid.UUID
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ('other-conn', 'vault', 'token', '{}'::jsonb, 'active') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{ExpectedClusterName: "cluster-a"})
	k := newEnrollKey(t)
	ch := h.challenge(t, tok.Token, k)
	in := services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
		ChallengeResponse: k.open(t, ch), Name: "x", ProviderType: "vault", ClusterName: "cluster-a"}
	_, err := h.svc.Enroll(ctx, in)
	wantReason(t, err, services.ErrEnrollmentRejected, "provider_type_mismatch")
	in.ProviderType, in.ClusterName = "aws-sm", "cluster-b"
	_, err = h.svc.Enroll(ctx, in)
	wantReason(t, err, services.ErrEnrollmentRejected, "cluster_name_mismatch")
	in.ClusterName = "cluster-a"
	res, err := h.svc.Enroll(ctx, in)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	var bound uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT provider_connection_id FROM agents WHERE id = $1`, res.AgentID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != h.connID || bound == other {
		t.Fatalf("agent bound to %s; want the token's connection %s", bound, h.connID)
	}
}

// Audit is metadata only: the token, the agent secret and the nonce
// appear in no audit row; both steps are audited with the fingerprint
// and the connection.
func TestEnroll_AuditMetadataOnly_NoLeak(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	k := newEnrollKey(t)
	ch := h.challenge(t, tok.Token, k)
	nonce := k.open(t, ch)
	res, err := h.svc.Enroll(ctx, services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
		ChallengeResponse: nonce, Name: "a1", ProviderType: "aws-sm"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// and one denied attempt
	_, _ = h.svc.Enroll(ctx, services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
		ChallengeResponse: nonce, Name: "a2", ProviderType: "aws-sm"})

	rows, err := h.pool.Query(ctx, `SELECT action, status, metadata::text FROM audit_events ORDER BY occurred_at`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	rawNonce, _ := base64.StdEncoding.DecodeString(nonce)
	got := map[string]string{}
	for rows.Next() {
		var action, status, meta string
		if err := rows.Scan(&action, &status, &meta); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[action+"/"+status] = meta
		for _, secret := range []string{tok.Token, res.AgentSecret, nonce, fmt.Sprintf("%x", rawNonce), k.b64()} {
			if strings.Contains(meta, secret) {
				t.Fatalf("secret material in audit metadata (%s): %s", action, meta)
			}
		}
	}
	for _, want := range []string{"agent.enrollment_token.created/success", "agent.enroll.challenge/success", "agent.enroll/success", "agent.enroll/denied"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("audit rows %v; missing %s", got, want)
		}
	}
	for _, key := range []string{"public_key_fingerprint", "provider_connection_id"} {
		if !strings.Contains(got["agent.enroll/success"], key) || !strings.Contains(got["agent.enroll.challenge/success"], key) {
			t.Errorf("enroll audit lacks %s: %v", key, got)
		}
	}
	if !strings.Contains(got["agent.enroll/success"], res.PublicKeyFingerprint) {
		t.Errorf("enroll audit lacks the fingerprint: %s", got["agent.enroll/success"])
	}
	if !strings.Contains(got["agent.enroll/denied"], "token_already_consumed") {
		t.Errorf("denied enroll audit lacks error_kind: %s", got["agent.enroll/denied"])
	}
}

// barrierTokens holds every GetByHash caller until n of them have read
// the token, so n enrollments all pass the unconsumed/unrevoked/unexpired
// pre-checks before any of them consumes: the API-18 race, made
// deterministic.
type barrierTokens struct {
	storage.AgentEnrollmentTokenRepository
	n       int
	mu      sync.Mutex
	arrived int
	all     chan struct{}
}

func (b *barrierTokens) GetByHash(ctx context.Context, h []byte) (*storage.AgentEnrollmentToken, error) {
	tok, err := b.AgentEnrollmentTokenRepository.GetByHash(ctx, h)
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.n {
		close(b.all)
	}
	b.mu.Unlock()
	<-b.all
	return tok, err
}

// API-18: N concurrent enrolls with one token, each with its own valid
// challenge and all past the pre-checks, yield exactly one agent.
func TestEnroll_ConcurrentSameToken_ExactlyOneWins(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})

	const n = 8
	inputs := make([]services.EnrollInput, n)
	for i := range inputs {
		k := newEnrollKey(t)
		ch := h.challenge(t, tok.Token, k)
		inputs[i] = services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
			ChallengeResponse: k.open(t, ch), Name: fmt.Sprintf("race-%d", i), ProviderType: "aws-sm"}
	}
	barrier := &barrierTokens{AgentEnrollmentTokenRepository: storage.NewAgentEnrollmentTokens(h.pool), n: n, all: make(chan struct{})}
	svc := services.NewAgentService(storage.NewAgents(h.pool), storage.NewAuditEvents(h.pool), nil).
		WithEnrollment(barrier, storage.NewProviderConnections(h.pool))

	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Enroll(ctx, inputs[i])
		}(i)
	}
	wg.Wait()

	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case services.RejectionReason(err) == "token_already_consumed":
		default:
			t.Fatalf("unexpected enroll error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d enrollments succeeded with one token; want 1", ok)
	}
	var agents, used int
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&agents)
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM agent_enrollment_challenges WHERE used_at IS NOT NULL`).Scan(&used)
	if agents != 1 || used != 1 {
		t.Fatalf("agents=%d used challenges=%d after the race; want 1 and 1", agents, used)
	}
}

// staleLookupTokens returns the token as it was read, then changes it in
// Postgres before the caller acts: the token is revoked (or expires)
// after Enroll's pre-checks but before its consume.
type staleLookupTokens struct {
	storage.AgentEnrollmentTokenRepository
	pool  *storage.Pool
	alter string
}

func (s *staleLookupTokens) GetByHash(ctx context.Context, h []byte) (*storage.AgentEnrollmentToken, error) {
	tok, err := s.AgentEnrollmentTokenRepository.GetByHash(ctx, h)
	if err == nil {
		if _, xerr := s.pool.Exec(ctx, s.alter, tok.ID); xerr != nil {
			return nil, xerr
		}
	}
	return tok, err
}

// API-18: the consume itself refuses a revoked or expired token, so one
// that turns bad after the pre-checks still cannot enroll an agent.
func TestEnroll_TokenRevokedOrExpiredAfterCheck_Refused(t *testing.T) {
	cases := []struct {
		name   string
		alter  string
		reason string
	}{
		{"revoked", `UPDATE agent_enrollment_tokens SET revoked_at = now(), revoked_by = 'admin-user-1' WHERE id = $1`, "token_revoked"},
		{"expired", `UPDATE agent_enrollment_tokens SET created_at = now() - interval '2 minutes', expires_at = now() - interval '1 minute' WHERE id = $1`, "token_expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := bootstrapEnroll(t, "aws-sm", "active")
			ctx := t.Context()
			tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
			k := newEnrollKey(t)
			ch := h.challenge(t, tok.Token, k)
			svc := services.NewAgentService(storage.NewAgents(h.pool), storage.NewAuditEvents(h.pool), nil).
				WithEnrollment(&staleLookupTokens{AgentEnrollmentTokenRepository: storage.NewAgentEnrollmentTokens(h.pool), pool: h.pool, alter: tc.alter},
					storage.NewProviderConnections(h.pool))

			_, err := svc.Enroll(ctx, services.EnrollInput{SchemaVersion: "2", Token: tok.Token, ChallengeID: ch.ChallengeID.String(),
				ChallengeResponse: k.open(t, ch), Name: "late-" + tc.name, ProviderType: "aws-sm"})
			wantReason(t, err, services.ErrEnrollmentRejected, tc.reason)
			var agents int
			_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&agents)
			if agents != 0 {
				t.Fatalf("a %s token created %d agent rows", tc.name, agents)
			}
		})
	}
}

// API-18: a failed agent insert (name already taken) rolls the consume
// back, so the operator can retry the same token with another name.
func TestEnroll_FailedInsertLeavesTokenUsable(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	first := h.generate(t, services.GenerateEnrollmentTokenInput{})
	if _, _, err := h.enroll(t, first.Token, "taken"); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	second := h.generate(t, services.GenerateEnrollmentTokenInput{})
	if _, _, err := h.enroll(t, second.Token, "taken"); !errors.Is(err, services.ErrAgentNameTaken) {
		t.Fatalf("enroll with a duplicate agent name: %v; want ErrAgentNameTaken", err)
	}
	if _, _, err := h.enroll(t, second.Token, "fresh-name"); err != nil {
		t.Fatalf("retry with the same token after a failed insert: %v", err)
	}
}

// Revoking an enrollment token invalidates its open challenges.
func TestRevokeEnrollmentToken_InvalidatesChallenges(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	h.challenge(t, tok.Token, newEnrollKey(t))
	if err := h.svc.RevokeEnrollmentToken(t.Context(), tok.ID, "admin-user-1", ""); err != nil {
		t.Fatal(err)
	}
	var open int
	_ = h.pool.QueryRow(t.Context(), `SELECT count(*) FROM agent_enrollment_challenges WHERE invalidated_at IS NULL`).Scan(&open)
	if open != 0 {
		t.Fatalf("%d challenges still open after the token was revoked", open)
	}
}
