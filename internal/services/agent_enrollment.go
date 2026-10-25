package services

// Agent enrollment (api#178, v2 in skills#116): enrollment-token
// generation and the two-step enroll with proof of possession of a
// customer-generated X25519 key.
//
//  1. EnrollChallenge: a valid token and a valid public key get a
//     random 32-byte nonce sealed to that key (pkg/sealing). Only the
//     nonce's SHA-256 is stored, bound to the token and the key, for
//     120s, single use. The token is not consumed.
//  2. Enroll: in one transaction the token is consumed, the challenge
//     is checked (bound to this token, unused, unexpired, SHA-256 of
//     the response equal to the stored hash, constant time), the agent
//     is created with the challenge's key at version 1 and the
//     provider connection of the token, and the challenge is marked
//     used.
//
// The agent secret (agents.secret_hash) is returned once by Enroll.
// Errors are generic; the reason is in the audit row only.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Enrollment tuning.
const (
	enrollTokenDefaultTTLSeconds = 900   // 15m
	enrollTokenMinTTLSeconds     = 60    // 1m
	enrollTokenMaxTTLSeconds     = 86400 // 24h
	enrollHeartbeatIntervalSec   = 30
	enrollClaimIntervalSec       = 5
	keyChallengeTTL              = 120 * time.Second
	keyChallengeNonceSize        = 32

	// EnrollSchemaVersion is the only enrollment request version. A
	// request without it is refused; there is no legacy fallback.
	EnrollSchemaVersion = "2"
)

// Enrollment sentinels, mapped to HTTP status in the handler layer.
var (
	ErrEnrollmentNotConfigured      = errors.New("services: enrollment not configured")
	ErrEnrollmentConnectionUnusable = errors.New("services: provider connection unavailable for enrollment")
	// ErrEnrollmentRejected covers a bad, expired, used or revoked
	// token, a provider or cluster mismatch and any challenge failure.
	// The specific reason is only in the audit row (rejectionKind).
	ErrEnrollmentRejected       = errors.New("services: enrollment rejected")
	ErrInvalidPublicKey         = errors.New("services: invalid public key")
	ErrUnsupportedSchemaVersion = errors.New("services: unsupported schema version")
	ErrAgentNameTaken           = errors.New("services: agent name already in use")
)

// rejection carries an audit-only reason code under a generic sentinel.
type rejection struct {
	base error
	kind string
}

func (r *rejection) Error() string { return r.base.Error() }
func (r *rejection) Unwrap() error { return r.base }

func reject(base error, kind string) error { return &rejection{base: base, kind: kind} }

// rejectionKind returns the audit reason for err, or "" for an internal
// error (a 5xx, not a rejection).
func rejectionKind(err error) string {
	var r *rejection
	switch {
	case errors.As(err, &r):
		return r.kind
	case errors.Is(err, ErrInvalidPublicKey):
		return "invalid_public_key"
	case errors.Is(err, ErrUnsupportedSchemaVersion):
		return "unsupported_schema_version"
	case errors.Is(err, ErrAgentNameTaken):
		return "agent_name_taken"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_request"
	}
	return ""
}

// GenerateEnrollmentTokenInput is the admin request to mint a one-time
// enrollment token bound to a provider connection.
type GenerateEnrollmentTokenInput struct {
	ProviderConnectionID uuid.UUID
	Name                 string
	ExpiresInSeconds     int
	ExpectedClusterName  string
	ExpectedProviderType string
	CreatedBy            string // actor identity (session subject)
}

// GeneratedEnrollmentToken is returned by GenerateEnrollmentToken. Token is
// the plaintext, returned exactly ONCE; only its hash is persisted.
type GeneratedEnrollmentToken struct {
	// ID is the token row's id, which POST
	// /agent-enrollment-tokens/:id/revoke takes.
	ID                   uuid.UUID
	Token                string
	ProviderConnectionID uuid.UUID
	ExpiresAt            time.Time
	// The bound connection's type, cluster name and scope, so the
	// handler can fill the install hint. Scope holds no credentials
	// (provider connections refuse credential-shaped keys).
	ProviderType string
	ClusterName  string
	Scope        map[string]string
}

// GenerateEnrollmentToken validates the connection, mints a one-time token,
// stores only its SHA-256 hash, and returns the plaintext once.
func (s *AgentService) GenerateEnrollmentToken(ctx context.Context, in GenerateEnrollmentTokenInput) (*GeneratedEnrollmentToken, error) {
	if s.enrollTokens == nil || s.provConns == nil {
		return nil, ErrEnrollmentNotConfigured
	}
	if in.ProviderConnectionID == uuid.Nil {
		return nil, errors.New("agents: provider_connection_id is required")
	}
	if in.CreatedBy == "" {
		return nil, errors.New("agents: created_by is required")
	}

	conn, err := s.provConns.Get(ctx, in.ProviderConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return nil, storage.ErrConnectionNotFound
		}
		return nil, fmt.Errorf("agents: resolve provider connection: %w", err)
	}
	if conn.Status != storage.ProviderConnectionStatusActive {
		return nil, ErrEnrollmentConnectionUnusable
	}

	ttl := in.ExpiresInSeconds
	if ttl <= 0 {
		ttl = enrollTokenDefaultTTLSeconds
	}
	if ttl < enrollTokenMinTTLSeconds {
		ttl = enrollTokenMinTTLSeconds
	}
	if ttl > enrollTokenMaxTTLSeconds {
		ttl = enrollTokenMaxTTLSeconds
	}

	tokenBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))

	expiresAt := s.now().UTC().Add(time.Duration(ttl) * time.Second)
	row := &storage.AgentEnrollmentToken{
		ProviderConnectionID: in.ProviderConnectionID,
		Name:                 in.Name,
		TokenHash:            hash[:],
		ExpectedClusterName:  in.ExpectedClusterName,
		ExpectedProviderType: in.ExpectedProviderType,
		ExpiresAt:            expiresAt,
		CreatedBy:            in.CreatedBy,
	}
	if err := s.enrollTokens.Create(ctx, row); err != nil {
		return nil, fmt.Errorf("agents: create enrollment token: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + in.CreatedBy,
		Action:   "agent.enrollment_token.created",
		Resource: "provider_connection:" + in.ProviderConnectionID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"provider_connection_id": in.ProviderConnectionID.String(),
			"enrollment_token_id":    row.ID.String(),
			"expires_at":             expiresAt.Format(time.RFC3339),
			"expected_cluster_name":  in.ExpectedClusterName,
			"expected_provider_type": in.ExpectedProviderType,
		},
	})

	return &GeneratedEnrollmentToken{
		ID:                   row.ID,
		Token:                token,
		ProviderConnectionID: in.ProviderConnectionID,
		ExpiresAt:            expiresAt,
		ProviderType:         string(conn.Type),
		ClusterName:          conn.ClusterName,
		Scope:                conn.Scope,
	}, nil
}

// RevokeEnrollmentToken revokes an UNUSED enrollment token so it can never
// be redeemed, and invalidates its open challenges. Metadata-only audit.
// api#179.
func (s *AgentService) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, revokedBy, reason string) error {
	if s.enrollTokens == nil {
		return ErrEnrollmentNotConfigured
	}
	tok, err := s.enrollTokens.Get(ctx, id)
	if err != nil {
		return err // ErrEnrollmentTokenNotFound → 404 at the handler
	}
	if err := s.enrollTokens.Revoke(ctx, id, revokedBy, s.now().UTC()); err != nil {
		return err // already consumed/revoked → ErrEnrollmentTokenNotFound → 409
	}
	actor := auditActor(ctx, revokedBy)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actor,
		Action:        "agent.enrollment_token.revoked",
		Resource:      "provider_connection:" + tok.ProviderConnectionID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: id,
		Metadata: map[string]any{
			"enrollment_token_id":    id.String(),
			"provider_connection_id": tok.ProviderConnectionID.String(),
			"reason":                 reason,
		},
	})
	return nil
}

// KeyChallenge is the challenge returned to the enrolling or rotating
// client: the nonce sealed to the submitted public key.
type KeyChallenge struct {
	ChallengeID uuid.UUID
	Sealed      *sealing.Envelope
	ExpiresAt   time.Time
}

// EnrollChallengeInput is step 1 of the enrollment.
type EnrollChallengeInput struct {
	SchemaVersion      string
	Token              string
	PublicKey          string // std base64, 32 bytes
	PublicKeyAlgorithm string
}

// EnrollInput is step 2 of the enrollment.
type EnrollInput struct {
	SchemaVersion     string
	Token             string
	ChallengeID       string
	ChallengeResponse string // std base64 of the decrypted nonce
	Name              string
	ClusterName       string
	ProviderType      string
	Region            string
}

// EnrolledAgent is returned by Enroll. AgentSecret is the persistent
// agent credential, returned exactly ONCE; only its hash is stored.
type EnrolledAgent struct {
	AgentID                  uuid.UUID
	ProviderConnectionID     uuid.UUID
	AgentSecret              string
	PublicKeyFingerprint     string
	PublicKeyVersion         int
	HeartbeatIntervalSeconds int
	ClaimIntervalSeconds     int
}

// enrollAuditMeta is what both enrollment audit rows may carry. Never
// the token, the secret or the nonce.
type enrollAuditMeta struct {
	fingerprint  string
	connectionID uuid.UUID
	challengeID  uuid.UUID
	agentID      uuid.UUID
	tokenID      uuid.UUID
}

func (m enrollAuditMeta) fill(meta map[string]any) {
	if m.fingerprint != "" {
		meta["public_key_fingerprint"] = m.fingerprint
	}
	if m.connectionID != uuid.Nil {
		meta["provider_connection_id"] = m.connectionID.String()
	}
	if m.challengeID != uuid.Nil {
		meta["challenge_id"] = m.challengeID.String()
	}
	if m.agentID != uuid.Nil {
		meta["agent_id"] = m.agentID.String()
	}
	if m.tokenID != uuid.Nil {
		meta["enrollment_token_id"] = m.tokenID.String()
	}
}

// auditEnrollDenied writes a denied enrollment row with its error_kind.
// The routes are unauthenticated, so denials are rolled up: one row per
// (action, reason) per rejectAuditWindow (API-N-07).
func (s *AgentService) auditEnrollDenied(ctx context.Context, action string, err error, m enrollAuditMeta) {
	kind := rejectionKind(err)
	if kind == "" {
		return
	}
	if !s.claimRejectAuditSlot(ctx, cacheKindEnrollRejectAudit, "unknown", action+":"+kind) {
		return
	}
	meta := map[string]any{
		"error_kind":            kind,
		"rollup_window_seconds": int(rejectAuditWindow / time.Second),
	}
	m.fill(meta)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:enroll",
		Action:   action,
		Resource: "agent_enrollment_token",
		Status:   storage.AuditStatusDenied,
		Metadata: meta,
	})
}

// usableEnrollmentToken resolves a presented token and checks it is
// unrevoked, unconsumed, unexpired and on an active connection.
func (s *AgentService) usableEnrollmentToken(ctx context.Context, token string, now time.Time) (*storage.AgentEnrollmentToken, *storage.ProviderConnection, error) {
	if token == "" {
		return nil, nil, reject(ErrEnrollmentRejected, "token_invalid")
	}
	hash := sha256.Sum256([]byte(token))
	tok, err := s.enrollTokens.GetByHash(ctx, hash[:])
	if err != nil {
		if errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
			return nil, nil, reject(ErrEnrollmentRejected, "token_invalid")
		}
		return nil, nil, fmt.Errorf("agents: resolve enrollment token: %w", err)
	}
	switch {
	case tok.RevokedAt != nil:
		return tok, nil, reject(ErrEnrollmentRejected, "token_revoked")
	case tok.ConsumedAt != nil:
		return tok, nil, reject(ErrEnrollmentRejected, "token_already_consumed")
	case !tok.ExpiresAt.After(now):
		return tok, nil, reject(ErrEnrollmentRejected, "token_expired")
	}
	conn, err := s.provConns.Get(ctx, tok.ProviderConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return tok, nil, reject(ErrEnrollmentRejected, "provider_connection_unavailable")
		}
		return tok, nil, fmt.Errorf("agents: resolve provider connection: %w", err)
	}
	if conn.Status != storage.ProviderConnectionStatusActive {
		return tok, conn, reject(ErrEnrollmentRejected, "provider_connection_unavailable")
	}
	return tok, conn, nil
}

// newSealedChallenge makes a fresh nonce, seals it to pub and returns
// the envelope and the nonce's SHA-256. The nonce itself is zeroed.
func newSealedChallenge(pub []byte) (*sealing.Envelope, []byte, error) {
	nonce, err := randomBytes(keyChallengeNonceSize)
	if err != nil {
		return nil, nil, fmt.Errorf("agents: random challenge: %w", err)
	}
	defer zeroBytes(nonce)
	env, err := sealing.Seal(nonce, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("agents: seal challenge: %w", err)
	}
	sum := sha256.Sum256(nonce)
	return env, sum[:], nil
}

// EnrollChallenge is step 1: validate the token (without consuming it)
// and the key, and return a challenge sealed to the key.
func (s *AgentService) EnrollChallenge(ctx context.Context, in EnrollChallengeInput) (*KeyChallenge, error) {
	var m enrollAuditMeta
	res, err := s.enrollChallenge(ctx, in, &m)
	if err != nil {
		s.auditEnrollDenied(ctx, "agent.enroll.challenge", err, m)
		return nil, err
	}
	meta := map[string]any{"expires_at": res.ExpiresAt.Format(time.RFC3339)}
	m.fill(meta)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:enroll",
		Action:   "agent.enroll.challenge",
		Resource: "agent_enrollment_token",
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})
	return res, nil
}

func (s *AgentService) enrollChallenge(ctx context.Context, in EnrollChallengeInput, m *enrollAuditMeta) (*KeyChallenge, error) {
	if s.enrollTokens == nil || s.provConns == nil {
		return nil, ErrEnrollmentNotConfigured
	}
	if in.SchemaVersion != EnrollSchemaVersion {
		return nil, ErrUnsupportedSchemaVersion
	}
	pub, err := sealing.ParsePublicKey(in.PublicKey, in.PublicKeyAlgorithm)
	if err != nil || in.PublicKeyAlgorithm != sealing.KeyAlgorithm {
		return nil, ErrInvalidPublicKey
	}
	m.fingerprint = sealing.Fingerprint(pub)

	now := s.now().UTC()
	tok, _, err := s.usableEnrollmentToken(ctx, in.Token, now)
	if tok != nil {
		m.connectionID, m.tokenID = tok.ProviderConnectionID, tok.ID
	}
	if err != nil {
		return nil, err
	}

	env, nonceHash, err := newSealedChallenge(pub)
	if err != nil {
		return nil, err
	}
	ch := &storage.KeyChallenge{
		ParentID:           tok.ID,
		PublicKey:          pub,
		PublicKeyAlgorithm: sealing.KeyAlgorithm,
		NonceHash:          nonceHash,
		ExpiresAt:          now.Add(keyChallengeTTL),
	}
	if err := s.enrollTokens.CreateEnrollmentChallenge(ctx, ch); err != nil {
		return nil, fmt.Errorf("agents: create enrollment challenge: %w", err)
	}
	m.challengeID = ch.ID
	return &KeyChallenge{ChallengeID: ch.ID, Sealed: env, ExpiresAt: ch.ExpiresAt}, nil
}

// verifyChallenge is the shared check for an enrollment or rotation
// challenge, run with the row locked: bound to parentID (and agentID
// for a rotation), unused, not invalidated, unexpired, and SHA-256 of
// the response equal to the stored hash in constant time. The public
// key is validated again before it is bound.
func verifyChallenge(ch *storage.KeyChallenge, base error, parentID, agentID uuid.UUID, responseHash []byte, now time.Time) error {
	switch {
	case ch.ParentID != parentID || (agentID != uuid.Nil && ch.AgentID != agentID):
		return reject(base, "challenge_token_mismatch")
	case ch.UsedAt != nil:
		return reject(base, "challenge_used")
	case ch.InvalidatedAt != nil:
		return reject(base, "challenge_invalidated")
	case !ch.ExpiresAt.After(now):
		return reject(base, "challenge_expired")
	case subtle.ConstantTimeCompare(ch.NonceHash, responseHash) != 1:
		return reject(base, "challenge_mismatch")
	case sealing.ValidatePublicKey(ch.PublicKey) != nil:
		return reject(base, "invalid_public_key")
	}
	return nil
}

// decodeChallengeResponse parses the challenge id and returns the
// SHA-256 of the decoded response. A malformed response hashes to
// nothing that can match, so it fails as challenge_mismatch.
func decodeChallengeResponse(base error, id, response string) (uuid.UUID, []byte, error) {
	chID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, nil, reject(base, "challenge_not_found")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(response)
	if err != nil || len(raw) != keyChallengeNonceSize {
		return chID, nil, reject(base, "challenge_mismatch")
	}
	defer zeroBytes(raw)
	sum := sha256.Sum256(raw)
	return chID, sum[:], nil
}

// Enroll is step 2: consume the token, check the challenge, create the
// agent bound to the token's provider connection and the challenge's
// key, and return the agent secret once.
func (s *AgentService) Enroll(ctx context.Context, in EnrollInput) (*EnrolledAgent, error) {
	var m enrollAuditMeta
	res, err := s.enroll(ctx, in, &m)
	if err != nil {
		s.auditEnrollDenied(ctx, "agent.enroll", err, m)
		return nil, err
	}
	meta := map[string]any{
		"public_key_version": res.PublicKeyVersion,
		"cluster_name":       in.ClusterName,
		"provider_type":      in.ProviderType,
	}
	m.fill(meta)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + res.AgentID.String(),
		Action:   "agent.enroll",
		Resource: "agent:" + res.AgentID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})
	return res, nil
}

// unconsumableTokenErr names why the transactional consume matched no
// row. It re-reads the token so a revoke or expiry that landed after the
// pre-checks is reported as such; a lost race reads as consumed.
func (s *AgentService) unconsumableTokenErr(ctx context.Context, id uuid.UUID, now time.Time) error {
	tok, err := s.enrollTokens.Get(ctx, id)
	switch {
	case err != nil:
		return reject(ErrEnrollmentRejected, "token_invalid")
	case tok.RevokedAt != nil:
		return reject(ErrEnrollmentRejected, "token_revoked")
	case tok.ConsumedAt != nil:
		return reject(ErrEnrollmentRejected, "token_already_consumed")
	case !tok.ExpiresAt.After(now):
		return reject(ErrEnrollmentRejected, "token_expired")
	default:
		return reject(ErrEnrollmentRejected, "token_already_consumed")
	}
}

func (s *AgentService) enroll(ctx context.Context, in EnrollInput, m *enrollAuditMeta) (*EnrolledAgent, error) {
	if s.enrollTokens == nil || s.provConns == nil {
		return nil, ErrEnrollmentNotConfigured
	}
	if in.SchemaVersion != EnrollSchemaVersion {
		return nil, ErrUnsupportedSchemaVersion
	}
	if in.Name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}

	now := s.now().UTC()
	tok, conn, err := s.usableEnrollmentToken(ctx, in.Token, now)
	if tok != nil {
		m.connectionID, m.tokenID = tok.ProviderConnectionID, tok.ID
	}
	if err != nil {
		return nil, err
	}
	chID, responseHash, err := decodeChallengeResponse(ErrEnrollmentRejected, in.ChallengeID, in.ChallengeResponse)
	m.challengeID = chID
	if err != nil {
		if rejectionKind(err) == "challenge_mismatch" {
			s.invalidateEnrollChallenge(ctx, chID, tok.ID, now)
		}
		return nil, err
	}

	// The provider type must agree with the bound connection (and the
	// token's expected value when set). Empty means the connection's.
	connType := string(conn.Type)
	providerType := in.ProviderType
	if providerType == "" {
		providerType = connType
	}
	if providerType != connType || (tok.ExpectedProviderType != "" && tok.ExpectedProviderType != providerType) {
		return nil, reject(ErrEnrollmentRejected, "provider_type_mismatch")
	}
	if tok.ExpectedClusterName != "" && tok.ExpectedClusterName != in.ClusterName {
		return nil, reject(ErrEnrollmentRejected, "cluster_name_mismatch")
	}

	secretBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random agent secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	secretHash := sha256.Sum256([]byte(secret))

	connID := tok.ProviderConnectionID
	agent := &storage.Agent{
		Name:                 in.Name,
		Status:               storage.AgentStatusEnrolled,
		SecretHash:           secretHash[:],
		ProviderConnectionID: &connID,
		ClusterName:          in.ClusterName,
		ProviderType:         providerType,
		Region:               in.Region,
		Capabilities:         []string{},
	}
	verify := func(ch *storage.KeyChallenge) error {
		m.fingerprint = sealing.Fingerprint(ch.PublicKey)
		if err := verifyChallenge(ch, ErrEnrollmentRejected, tok.ID, uuid.Nil, responseHash, now); err != nil {
			return err
		}
		agent.PublicKeyFingerprint = m.fingerprint
		return nil
	}
	err = s.enrollTokens.EnrollWithChallenge(ctx, tok.ID, chID, now, verify, agent)
	switch {
	case err == nil:
	case errors.Is(err, storage.ErrEnrollmentTokenNotFound):
		return nil, s.unconsumableTokenErr(ctx, tok.ID, now)
	case errors.Is(err, storage.ErrChallengeNotFound):
		return nil, reject(ErrEnrollmentRejected, "challenge_not_found")
	case rejectionKind(err) == "challenge_mismatch":
		s.invalidateEnrollChallenge(ctx, chID, tok.ID, now)
		return nil, err
	case rejectionKind(err) != "":
		return nil, err
	case isUniqueViolation(err):
		return nil, ErrAgentNameTaken
	default:
		return nil, fmt.Errorf("agents: enroll agent: %w", err)
	}
	m.agentID = agent.ID

	return &EnrolledAgent{
		AgentID:                  agent.ID,
		ProviderConnectionID:     connID,
		AgentSecret:              secret,
		PublicKeyFingerprint:     agent.PublicKeyFingerprint,
		PublicKeyVersion:         1,
		HeartbeatIntervalSeconds: enrollHeartbeatIntervalSec,
		ClaimIntervalSeconds:     enrollClaimIntervalSec,
	}, nil
}

// invalidateEnrollChallenge burns a challenge after a wrong response,
// so each challenge gets one guess. Only a challenge of this token is
// burned, so another token's holder cannot burn it. Best-effort.
func (s *AgentService) invalidateEnrollChallenge(ctx context.Context, chID, tokenID uuid.UUID, now time.Time) {
	if chID == uuid.Nil {
		return
	}
	_ = s.enrollTokens.InvalidateEnrollmentChallenge(ctx, chID, tokenID, now)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RejectionReason is the audit-only reason code of an enrollment or
// rotation rejection ("" for anything else). Never sent to the client.
func RejectionReason(err error) string { return rejectionKind(err) }
