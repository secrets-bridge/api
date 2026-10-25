package services_test

// Agent key rotation and the wire-key check (skills#116), with real
// X25519 keys through pkg/sealing.

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

func rotationService(h *enrollHarness) *services.AgentService {
	return h.svc.WithKeyRotation(storage.NewAgentKeyRotations(h.pool))
}

// rotate runs the agent side of a rotation with a fresh key.
func rotate(t *testing.T, svc *services.AgentService, agentID uuid.UUID, token string) (enrollKey, *services.RotatedKey, error) {
	t.Helper()
	k := newEnrollKey(t)
	ch, err := svc.KeyRotationChallenge(t.Context(), agentID, services.KeyRotationChallengeInput{SchemaVersion: "2",
		RotationToken: token, PublicKey: k.b64(), PublicKeyAlgorithm: "x25519",
	})
	if err != nil {
		return k, nil, err
	}
	res, err := svc.ConfirmKeyRotation(t.Context(), agentID, services.KeyRotationConfirmInput{SchemaVersion: "2",
		RotationToken: token, ChallengeID: ch.ChallengeID.String(), ChallengeResponse: k.open(t, ch),
	})
	return k, res, err
}

// End to end: the key and version change, the old fingerprint is
// refused, the new one is accepted, the secret is unchanged, and the
// audit row names both fingerprints.
func TestKeyRotation_EndToEnd(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	svc := rotationService(h)
	ctx := t.Context()
	tok := h.generate(t, services.GenerateEnrollmentTokenInput{})
	agent, oldKey, err := h.enroll(t, tok.Token, "rot-1")
	if err != nil {
		t.Fatal(err)
	}
	oldFP := sealing.Fingerprint(oldKey.pub)
	if err := svc.AuthenticateAgentKey(ctx, agent.AgentID, agent.AgentSecret, oldFP); err != nil {
		t.Fatalf("old key before rotation: %v", err)
	}

	rt, err := svc.RequestKeyRotation(ctx, agent.AgentID, "admin-user-1")
	if err != nil {
		t.Fatalf("RequestKeyRotation: %v", err)
	}
	newKey, res, err := rotate(t, svc, agent.AgentID, rt.Token)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	newFP := sealing.Fingerprint(newKey.pub)
	if res.PublicKeyVersion != 2 || res.PublicKeyFingerprint != newFP {
		t.Fatalf("rotated to %+v", res)
	}
	if err := svc.AuthenticateAgentKey(ctx, agent.AgentID, agent.AgentSecret, oldFP); !errors.Is(err, services.ErrAgentKeyMismatch) {
		t.Fatalf("old key after rotation: %v; want ErrAgentKeyMismatch", err)
	}
	if err := svc.AuthenticateAgentKey(ctx, agent.AgentID, agent.AgentSecret, newFP); err != nil {
		t.Fatalf("new key with the same secret: %v", err)
	}
	// A wrap sealed now goes to the new key only.
	row, err := storage.NewAgents(h.pool).Get(ctx, agent.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	env, err := sealing.Seal([]byte("v"), row.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealing.Open(env, oldKey.priv, oldKey.pub); err == nil {
		t.Fatal("a wrap sealed after rotation opened with the old key")
	}
	if pt, err := sealing.Open(env, newKey.priv, newKey.pub); err != nil || string(pt) != "v" {
		t.Fatalf("new key cannot open: %v", err)
	}

	var meta string
	if err := h.pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE action = 'agent.key.rotated' AND status = 'success'`).Scan(&meta); err != nil {
		t.Fatalf("rotated audit: %v", err)
	}
	for _, want := range []string{oldFP, newFP, `"new_public_key_version": 2`} {
		if !strings.Contains(meta, want) {
			t.Errorf("rotated audit lacks %s: %s", want, meta)
		}
	}
	if strings.Contains(meta, rt.Token) {
		t.Fatal("rotation token in audit")
	}
	var requested int
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'agent.key_rotation.requested'`).Scan(&requested)
	if requested != 1 {
		t.Fatalf("agent.key_rotation.requested rows = %d", requested)
	}

	// The token is single use.
	if _, _, err := rotate(t, svc, agent.AgentID, rt.Token); services.RejectionReason(err) != "token_already_consumed" {
		t.Fatalf("reused rotation token: %v", err)
	}
}

// A rotation token is bound to its agent, a wrong response is refused,
// the same key is refused, and an expired token is refused.
func TestKeyRotation_Refusals(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	svc := rotationService(h)
	ctx := t.Context()
	a1, k1, err := h.enroll(t, h.generate(t, services.GenerateEnrollmentTokenInput{}).Token, "rot-a")
	if err != nil {
		t.Fatal(err)
	}
	a2, _, err := h.enroll(t, h.generate(t, services.GenerateEnrollmentTokenInput{}).Token, "rot-b")
	if err != nil {
		t.Fatal(err)
	}
	rt, err := svc.RequestKeyRotation(ctx, a1.AgentID, "admin-user-1")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("other agent", func(t *testing.T) {
		if _, _, err := rotate(t, svc, a2.AgentID, rt.Token); services.RejectionReason(err) != "token_invalid" {
			t.Fatalf("token of a1 used by a2: %v", err)
		}
	})
	t.Run("same key", func(t *testing.T) {
		_, err := svc.KeyRotationChallenge(ctx, a1.AgentID, services.KeyRotationChallengeInput{SchemaVersion: "2",
			RotationToken: rt.Token, PublicKey: k1.b64(), PublicKeyAlgorithm: "x25519"})
		if !errors.Is(err, services.ErrInvalidPublicKey) {
			t.Fatalf("same key: %v", err)
		}
	})
	t.Run("low order key", func(t *testing.T) {
		_, err := svc.KeyRotationChallenge(ctx, a1.AgentID, services.KeyRotationChallengeInput{SchemaVersion: "2",
			RotationToken: rt.Token, PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), PublicKeyAlgorithm: "x25519"})
		if !errors.Is(err, services.ErrInvalidPublicKey) {
			t.Fatalf("all-zero key: %v", err)
		}
	})
	t.Run("wrong response", func(t *testing.T) {
		k := newEnrollKey(t)
		ch, err := svc.KeyRotationChallenge(ctx, a1.AgentID, services.KeyRotationChallengeInput{SchemaVersion: "2",
			RotationToken: rt.Token, PublicKey: k.b64(), PublicKeyAlgorithm: "x25519"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ConfirmKeyRotation(ctx, a1.AgentID, services.KeyRotationConfirmInput{SchemaVersion: "2",
			RotationToken: rt.Token, ChallengeID: ch.ChallengeID.String(),
			ChallengeResponse: base64.StdEncoding.EncodeToString(make([]byte, 32))})
		if services.RejectionReason(err) != "challenge_mismatch" {
			t.Fatalf("wrong response: %v", err)
		}
		var version int
		_ = h.pool.QueryRow(ctx, `SELECT public_key_version FROM agents WHERE id = $1`, a1.AgentID).Scan(&version)
		if version != 1 {
			t.Fatalf("key changed on a wrong response: version %d", version)
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := h.pool.Exec(ctx, `UPDATE agent_key_rotation_tokens SET created_at = now() - interval '1 hour', expires_at = now() - interval '1 minute'`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := rotate(t, svc, a1.AgentID, rt.Token); services.RejectionReason(err) != "token_expired" {
			t.Fatalf("expired token: %v", err)
		}
	})
}

// A new rotation token supersedes the open one.
func TestKeyRotation_NewTokenSupersedes(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	svc := rotationService(h)
	a, _, err := h.enroll(t, h.generate(t, services.GenerateEnrollmentTokenInput{}).Token, "rot-s")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := svc.RequestKeyRotation(t.Context(), a.AgentID, "admin-user-1")
	second, _ := svc.RequestKeyRotation(t.Context(), a.AgentID, "admin-user-1")
	if _, _, err := rotate(t, svc, a.AgentID, first.Token); services.RejectionReason(err) != "token_revoked" {
		t.Fatalf("superseded token: %v", err)
	}
	if _, _, err := rotate(t, svc, a.AgentID, second.Token); err != nil {
		t.Fatalf("current token: %v", err)
	}
}

// Revoking the agent kills an open rotation: the token is revoked, its
// challenge invalidated, and the confirm can no longer change the key.
func TestKeyRotation_RevokeKillsOpenRotation(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	svc := rotationService(h)
	ctx := t.Context()
	a, _, err := h.enroll(t, h.generate(t, services.GenerateEnrollmentTokenInput{}).Token, "rot-r")
	if err != nil {
		t.Fatal(err)
	}
	rt, err := svc.RequestKeyRotation(ctx, a.AgentID, "admin-user-1")
	if err != nil {
		t.Fatal(err)
	}
	k := newEnrollKey(t)
	ch, err := svc.KeyRotationChallenge(ctx, a.AgentID, services.KeyRotationChallengeInput{SchemaVersion: "2",
		RotationToken: rt.Token, PublicKey: k.b64(), PublicKeyAlgorithm: "x25519"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, a.AgentID, "admin-user-1", "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	var openTokens, openChallenges int
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM agent_key_rotation_tokens WHERE revoked_at IS NULL AND consumed_at IS NULL`).Scan(&openTokens)
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM agent_key_rotation_challenges WHERE invalidated_at IS NULL AND used_at IS NULL`).Scan(&openChallenges)
	if openTokens != 0 || openChallenges != 0 {
		t.Fatalf("open after revoke: tokens=%d challenges=%d", openTokens, openChallenges)
	}
	_, err = svc.ConfirmKeyRotation(ctx, a.AgentID, services.KeyRotationConfirmInput{SchemaVersion: "2",
		RotationToken: rt.Token, ChallengeID: ch.ChallengeID.String(), ChallengeResponse: k.open(t, ch)})
	if !errors.Is(err, services.ErrKeyRotationRejected) {
		t.Fatalf("confirm after revoke: %v", err)
	}
	if _, err := svc.RequestKeyRotation(ctx, a.AgentID, "admin-user-1"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("rotation token for a revoked agent: %v", err)
	}
	var meta string
	_ = h.pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE action = 'agent.revoked'`).Scan(&meta)
	if !strings.Contains(meta, `"rotation_tokens_revoked": 1`) || !strings.Contains(meta, `"rotation_challenges_invalidated": 1`) {
		t.Fatalf("revoke audit: %s", meta)
	}
}

// The key cannot be changed by a plain UPDATE: the schema refuses a key
// change without a version bump of one, a version change without a key
// change, and a fingerprint that is not the key's.
func TestAgentKey_SchemaGuards(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()
	a, _, err := h.enroll(t, h.generate(t, services.GenerateEnrollmentTokenInput{}).Token, "guard")
	if err != nil {
		t.Fatal(err)
	}
	other := newEnrollKey(t)
	for name, q := range map[string]string{
		"key without version": `UPDATE agents SET public_key = $2, public_key_fingerprint = 'sha256:' || encode(sha256($2), 'hex') WHERE id = $1`,
		"version without key": `UPDATE agents SET public_key_version = public_key_version + 1 WHERE id = $1 AND $2::bytea IS NOT NULL`,
		"fingerprint drift":   `UPDATE agents SET public_key_fingerprint = 'sha256:' || encode(sha256($2), 'hex') WHERE id = $1`,
		"fingerprint removed": `UPDATE agents SET public_key_fingerprint = NULL WHERE id = $1 AND $2::bytea IS NOT NULL`,
		"key removed":         `UPDATE agents SET public_key = NULL, public_key_fingerprint = NULL, public_key_version = public_key_version + 1 WHERE id = $1 AND $2::bytea IS NOT NULL`,
	} {
		if _, err := h.pool.Exec(ctx, q, a.AgentID, other.pub); err == nil {
			t.Errorf("%s: the schema accepted it", name)
		}
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO agents (name, scope, status, secret_hash) VALUES ('keyless', '{}', 'active', '\x01')`); err == nil {
		t.Error("an agent without a key was inserted")
	}
}
