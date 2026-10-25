package services

// Agent key rotation (skills#116). The wire key changes only through
// this flow, never through an overwrite:
//
//  1. An admin with agent.mint and a fresh second factor asks for a
//     one-time rotation token (15 min, hash only), bound to the agent
//     and its current key version. Issuing one revokes any earlier
//     open token for the agent.
//  2. The operator's CLI, holding the agent secret and the rotation
//     token, sends the new public key and gets a challenge sealed to it.
//  3. With the decrypted challenge, the CLI confirms: in one
//     transaction the token is consumed, the challenge checked, the key
//     replaced and public_key_version bumped.
//
// The agent secret does not change. Wraps are sealed at retrieval time,
// so a queued wrap is sealed to whatever key is current when it is
// fetched, and an Agent still on the old key gets 409 agent_key_mismatch
// from AgentAuth until it restarts with the new key. Revoking the agent
// revokes any open rotation token and invalidates its challenges.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

const keyRotationTokenTTL = 15 * time.Minute

// Key rotation sentinels.
var (
	ErrKeyRotationNotConfigured = errors.New("services: key rotation not configured")
	// ErrKeyRotationRejected covers a bad, expired, used or revoked
	// rotation token, a stale key version and any challenge failure.
	// The reason is in the audit row only.
	ErrKeyRotationRejected = errors.New("services: key rotation rejected")
)

// WithKeyRotation wires the rotation repository. Unwired, the rotation
// methods return ErrKeyRotationNotConfigured.
func (s *AgentService) WithKeyRotation(r storage.AgentKeyRotationRepository) *AgentService {
	s.rotations = r
	return s
}

// KeyRotationToken is the admin's one-time rotation token. Token is the
// plaintext, returned exactly once.
type KeyRotationToken struct {
	ID               uuid.UUID
	AgentID          uuid.UUID
	Token            string
	ExpiresAt        time.Time
	PublicKeyVersion int
}

// RequestKeyRotation issues a rotation token for an agent that is not
// revoked. storage.ErrNotFound: no such agent, or it is revoked.
func (s *AgentService) RequestKeyRotation(ctx context.Context, agentID uuid.UUID, requestedBy string) (*KeyRotationToken, error) {
	if s.rotations == nil {
		return nil, ErrKeyRotationNotConfigured
	}
	if requestedBy == "" {
		return nil, errors.New("agents: requested_by is required")
	}
	raw, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random rotation token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	row := &storage.AgentKeyRotationToken{
		AgentID:   agentID,
		TokenHash: hash[:],
		ExpiresAt: now.Add(keyRotationTokenTTL),
		CreatedBy: requestedBy,
	}
	if err := s.rotations.CreateToken(ctx, row, now); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("agents: create rotation token: %w", err)
	}

	meta := map[string]any{
		"agent_id":                agentID.String(),
		"rotation_token_id":       row.ID.String(),
		"expires_at":              row.ExpiresAt.Format(time.RFC3339),
		"public_key_version":      row.ExpectedPublicKeyVersion,
		"rotation_tokens_revoked": len(row.SupersededOpenRotationIDs),
	}
	if a, err := s.agents.Get(ctx, agentID); err == nil {
		meta["public_key_fingerprint"] = a.PublicKeyFingerprint
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         auditActor(ctx, requestedBy),
		Action:        "agent.key_rotation.requested",
		Resource:      "agent:" + agentID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: row.ID,
		Metadata:      meta,
	})
	return &KeyRotationToken{
		ID:               row.ID,
		AgentID:          agentID,
		Token:            token,
		ExpiresAt:        row.ExpiresAt,
		PublicKeyVersion: row.ExpectedPublicKeyVersion,
	}, nil
}

// KeyRotationChallengeInput is the agent-side rotation step 1.
type KeyRotationChallengeInput struct {
	SchemaVersion      string // "2", as for enrollment
	RotationToken      string
	PublicKey          string // std base64, 32 bytes
	PublicKeyAlgorithm string
}

// KeyRotationConfirmInput is the agent-side rotation step 2.
type KeyRotationConfirmInput struct {
	SchemaVersion     string // "2", as for enrollment
	RotationToken     string
	ChallengeID       string
	ChallengeResponse string // std base64 of the decrypted nonce
}

// RotatedKey is the result of a confirmed rotation.
type RotatedKey struct {
	AgentID              uuid.UUID
	PublicKeyFingerprint string
	PublicKeyVersion     int
}

// rotationAudit is what the rotation rows may carry.
type rotationAudit struct {
	tokenID        uuid.UUID
	challengeID    uuid.UUID
	newFingerprint string
}

func (m rotationAudit) fill(meta map[string]any) {
	if m.tokenID != uuid.Nil {
		meta["rotation_token_id"] = m.tokenID.String()
	}
	if m.challengeID != uuid.Nil {
		meta["challenge_id"] = m.challengeID.String()
	}
	if m.newFingerprint != "" {
		meta["new_public_key_fingerprint"] = m.newFingerprint
	}
}

// auditRotationDenied writes a rolled-up denied row (one per agent,
// action and reason per window).
func (s *AgentService) auditRotationDenied(ctx context.Context, action string, agentID uuid.UUID, err error, m rotationAudit) {
	kind := rejectionKind(err)
	if kind == "" || !s.claimRejectAuditSlot(ctx, cacheKindRotationRejectAudit, agentID.String(), action+":"+kind) {
		return
	}
	meta := map[string]any{
		"agent_id":              agentID.String(),
		"error_kind":            kind,
		"rollup_window_seconds": int(rejectAuditWindow / time.Second),
	}
	m.fill(meta)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + agentID.String(),
		Action:   action,
		Resource: "agent:" + agentID.String(),
		Status:   storage.AuditStatusDenied,
		Metadata: meta,
	})
}

// usableRotationToken resolves a presented rotation token for agentID.
func (s *AgentService) usableRotationToken(ctx context.Context, agentID uuid.UUID, token string, now time.Time) (*storage.AgentKeyRotationToken, error) {
	if token == "" {
		return nil, reject(ErrKeyRotationRejected, "token_invalid")
	}
	hash := sha256.Sum256([]byte(token))
	tok, err := s.rotations.GetTokenByHash(ctx, hash[:])
	if err != nil {
		if errors.Is(err, storage.ErrRotationTokenNotFound) {
			return nil, reject(ErrKeyRotationRejected, "token_invalid")
		}
		return nil, fmt.Errorf("agents: resolve rotation token: %w", err)
	}
	switch {
	case tok.AgentID != agentID:
		// Same answer as an unknown token: a token for another agent
		// says nothing about that agent.
		return nil, reject(ErrKeyRotationRejected, "token_invalid")
	case tok.RevokedAt != nil:
		return tok, reject(ErrKeyRotationRejected, "token_revoked")
	case tok.ConsumedAt != nil:
		return tok, reject(ErrKeyRotationRejected, "token_already_consumed")
	case !tok.ExpiresAt.After(now):
		return tok, reject(ErrKeyRotationRejected, "token_expired")
	}
	return tok, nil
}

// KeyRotationChallenge validates the rotation token and the new key and
// returns a challenge sealed to the new key. The caller is the agent
// authenticated by its secret (AgentSecretAuth).
func (s *AgentService) KeyRotationChallenge(ctx context.Context, agentID uuid.UUID, in KeyRotationChallengeInput) (*KeyChallenge, error) {
	var m rotationAudit
	res, err := s.keyRotationChallenge(ctx, agentID, in, &m)
	if err != nil {
		s.auditRotationDenied(ctx, "agent.key_rotation.challenge", agentID, err, m)
		return nil, err
	}
	meta := map[string]any{"agent_id": agentID.String(), "expires_at": res.ExpiresAt.Format(time.RFC3339)}
	m.fill(meta)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "agent:" + agentID.String(),
		Action:        "agent.key_rotation.challenge",
		Resource:      "agent:" + agentID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: m.tokenID,
		Metadata:      meta,
	})
	return res, nil
}

func (s *AgentService) keyRotationChallenge(ctx context.Context, agentID uuid.UUID, in KeyRotationChallengeInput, m *rotationAudit) (*KeyChallenge, error) {
	if s.rotations == nil {
		return nil, ErrKeyRotationNotConfigured
	}
	if in.SchemaVersion != EnrollSchemaVersion {
		return nil, ErrUnsupportedSchemaVersion
	}
	pub, err := sealing.ParsePublicKey(in.PublicKey, in.PublicKeyAlgorithm)
	if err != nil || in.PublicKeyAlgorithm != sealing.KeyAlgorithm {
		return nil, ErrInvalidPublicKey
	}
	m.newFingerprint = sealing.Fingerprint(pub)

	now := s.now().UTC()
	tok, err := s.usableRotationToken(ctx, agentID, in.RotationToken, now)
	if tok != nil {
		m.tokenID = tok.ID
	}
	if err != nil {
		return nil, err
	}
	agent, err := s.agents.Get(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("agents: load agent: %w", err)
	}
	if agent.Status == storage.AgentStatusRevoked || agent.PublicKeyVersion != tok.ExpectedPublicKeyVersion {
		return nil, reject(ErrKeyRotationRejected, "rotation_stale")
	}
	if bytes.Equal(pub, agent.PublicKey) {
		return nil, reject(ErrInvalidPublicKey, "same_public_key")
	}

	env, nonceHash, err := newSealedChallenge(pub)
	if err != nil {
		return nil, err
	}
	ch := &storage.KeyChallenge{
		ParentID:           tok.ID,
		AgentID:            agentID,
		PublicKey:          pub,
		PublicKeyAlgorithm: sealing.KeyAlgorithm,
		NonceHash:          nonceHash,
		ExpiresAt:          now.Add(keyChallengeTTL),
	}
	if err := s.rotations.CreateChallenge(ctx, ch); err != nil {
		return nil, fmt.Errorf("agents: create rotation challenge: %w", err)
	}
	m.challengeID = ch.ID
	return &KeyChallenge{ChallengeID: ch.ID, Sealed: env, ExpiresAt: ch.ExpiresAt}, nil
}

// ConfirmKeyRotation checks the challenge response and replaces the
// agent's key, bumping public_key_version.
func (s *AgentService) ConfirmKeyRotation(ctx context.Context, agentID uuid.UUID, in KeyRotationConfirmInput) (*RotatedKey, error) {
	var m rotationAudit
	res, old, err := s.confirmKeyRotation(ctx, agentID, in, &m)
	if err != nil {
		s.auditRotationDenied(ctx, "agent.key.rotated", agentID, err, m)
		return nil, err
	}
	meta := map[string]any{
		"agent_id":                   agentID.String(),
		"old_public_key_fingerprint": sealing.Fingerprint(old.OldPublicKey),
		"old_public_key_version":     old.OldVersion,
		"new_public_key_version":     old.NewVersion,
	}
	if old.ProviderConnectionID != nil {
		meta["provider_connection_id"] = old.ProviderConnectionID.String()
	}
	m.fill(meta)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "agent:" + agentID.String(),
		Action:        "agent.key.rotated",
		Resource:      "agent:" + agentID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: m.tokenID,
		Metadata:      meta,
	})
	return res, nil
}

func (s *AgentService) confirmKeyRotation(ctx context.Context, agentID uuid.UUID, in KeyRotationConfirmInput, m *rotationAudit) (*RotatedKey, *storage.RotateKeyResult, error) {
	if s.rotations == nil {
		return nil, nil, ErrKeyRotationNotConfigured
	}
	if in.SchemaVersion != EnrollSchemaVersion {
		return nil, nil, ErrUnsupportedSchemaVersion
	}
	now := s.now().UTC()
	tok, err := s.usableRotationToken(ctx, agentID, in.RotationToken, now)
	if tok != nil {
		m.tokenID = tok.ID
	}
	if err != nil {
		return nil, nil, err
	}
	chID, responseHash, err := decodeChallengeResponse(ErrKeyRotationRejected, in.ChallengeID, in.ChallengeResponse)
	m.challengeID = chID
	if err != nil {
		if rejectionKind(err) == "challenge_mismatch" && chID != uuid.Nil {
			_ = s.rotations.InvalidateChallenge(ctx, chID, tok.ID, now)
		}
		return nil, nil, err
	}

	res, err := s.rotations.Rotate(ctx, storage.RotateKeyInput{
		AgentID:     agentID,
		TokenID:     tok.ID,
		ChallengeID: chID,
		At:          now,
		Verify: func(ch *storage.KeyChallenge) error {
			m.newFingerprint = sealing.Fingerprint(ch.PublicKey)
			return verifyChallenge(ch, ErrKeyRotationRejected, tok.ID, agentID, responseHash, now)
		},
	})
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrRotationTokenNotFound):
		// Lost a race with another confirm, a revoke or the expiry.
		return nil, nil, reject(ErrKeyRotationRejected, "token_already_consumed")
	case errors.Is(err, storage.ErrChallengeNotFound):
		return nil, nil, reject(ErrKeyRotationRejected, "challenge_not_found")
	case errors.Is(err, storage.ErrRotationStale):
		return nil, nil, reject(ErrKeyRotationRejected, "rotation_stale")
	case rejectionKind(err) == "challenge_mismatch":
		_ = s.rotations.InvalidateChallenge(ctx, chID, tok.ID, now)
		return nil, nil, err
	case rejectionKind(err) != "":
		return nil, nil, err
	default:
		return nil, nil, fmt.Errorf("agents: rotate key: %w", err)
	}

	// The cached credential carries the bound fingerprint: drop it so
	// the next request reads the new key. A fill racing this is caught
	// by its re-read (fillSecretHashCache compares the fingerprint).
	s.cache.invalidate(ctx, agentID)

	return &RotatedKey{
		AgentID:              agentID,
		PublicKeyFingerprint: sealing.Fingerprint(res.NewPublicKey),
		PublicKeyVersion:     res.NewVersion,
	}, res, nil
}
