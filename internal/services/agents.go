// Package services holds the business-logic layer of the api.
//
// AgentService owns the one-credential agent flow:
//
//  1. Admin calls Mint → returns {id, agent_secret}. The plaintext
//     secret is returned ONCE; only its SHA-256 hash is persisted.
//  2. Admin (or the chart that wraps this call) lands those values
//     in the agent's K8s Secret / env vars.
//  3. Agent reads the values at startup and presents agent_secret in
//     the X-Agent-Secret header on every heartbeat.
//
// There is intentionally no separate registration step — the Pod can
// restart at will, re-read the same Secret, and keep heartbeating
// without a PVC for state persistence.
package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

// AgentService owns the agent mint + heartbeat flow.
//
// The heartbeat path uses a Redis cache for the agent's secret hash so
// validation is one Redis GET (cache hit) instead of one Postgres
// SELECT under load. Revocation MUST go through Revoke(), which writes a
// cache tombstone (skills#104); a direct status update in the storage
// layer would leave a cached entry valid for up to secretHashCacheTTL.
type AgentService struct {
	agents storage.AgentRepository
	audit  storage.AuditEventRepository
	rdb    *runtime.Client
	now    func() time.Time

	// heartbeatCacheTTL bounds how long the last-seen TIMESTAMP is
	// cached in Redis (for the admin GET /agents path).
	heartbeatCacheTTL time.Duration

	// secretHashCacheTTL bounds how long the secret_hash is cached in
	// Redis for heartbeat validation. Short enough to cap the
	// revocation propagation window when an admin bypasses Revoke();
	// long enough to give meaningful cache hit rates at scale.
	secretHashCacheTTL time.Duration

	// Agent Onboarding MVP (api#178). Both nil unless WithEnrollment is
	// called — the certified mint/heartbeat/auth paths never touch them.
	enrollTokens storage.AgentEnrollmentTokenRepository
	provConns    AgentProviderConnectionLookup

	// rotations backs the audited key rotation flow (skills#116). Nil
	// unless WithKeyRotation is called.
	rotations storage.AgentKeyRotationRepository

	// cache fronts the secret-hash check with a revocation tombstone and
	// a negative entry for unknown ids (skills#104).
	cache *credCache
}

// AgentProviderConnectionLookup is the narrow Get-only slice of the
// provider-connections repository the enrollment flow needs (validate the
// connection exists + is active, and read its type for the binding check).
type AgentProviderConnectionLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.ProviderConnection, error)
}

// WithEnrollment wires the enrollment-token repository + provider-connection
// lookup so GenerateEnrollmentToken + Enroll are operative. Returns the
// service for chaining. Unwired (the default), those methods return an error.
func (s *AgentService) WithEnrollment(tokens storage.AgentEnrollmentTokenRepository, provConns AgentProviderConnectionLookup) *AgentService {
	s.enrollTokens = tokens
	s.provConns = provConns
	return s
}

// NewAgentService constructs an AgentService.
func NewAgentService(agents storage.AgentRepository, audit storage.AuditEventRepository, rdb *runtime.Client) *AgentService {
	s := &AgentService{
		agents:             agents,
		audit:              audit,
		rdb:                rdb,
		now:                time.Now,
		heartbeatCacheTTL:  5 * time.Minute,
		secretHashCacheTTL: 60 * time.Second,
	}
	s.cache = newCredCache(rdb, cacheKindSecretHash, s.secretHashCacheTTL)
	return s
}

// Redis key prefixes — `kind` slot for the runtime namespace builder.
const (
	cacheKindSecretHash = "agent-hash"
	cacheKindLastSeen   = "agent-lastseen"
	// Rollup slots for rejected agent auth / enrollment audits (API-N-07).
	cacheKindAuthRejectAudit     = "agent-auth-reject-audit"
	cacheKindEnrollRejectAudit   = "agent-enroll-reject-audit"
	cacheKindRotationRejectAudit = "agent-rotation-reject-audit"
	cacheKindKeyMismatchAudit    = "agent-key-mismatch-audit"
)

// cachedSecretHash holds the marshalled form stored in Redis. We track
// the agent's status alongside the hash so a `revoked` row whose cache
// hasn't been invalidated yet still fails the validation check.
//
// Fingerprint is the bound wire key's fingerprint (skills#116), so the
// AgentAuth key check costs no extra read. An entry without one (written
// before it existed) reads as a miss.
type cachedSecretHash struct {
	Status      string `json:"status"`
	Hash        []byte `json:"hash"`
	Fingerprint string `json:"fingerprint"`
}

// MintedAgent is returned by Mint. AgentSecret is the plaintext
// long-lived credential — it is returned exactly ONCE and not
// recoverable from the database afterwards.
type MintedAgent struct {
	ID                   uuid.UUID
	Name                 string
	AgentSecret          string
	PublicKeyFingerprint string
	PublicKeyVersion     int
}

// MintInput captures everything Mint accepts. PublicKey is required
// (skills#116) and validated like an enrollment key: 32 bytes, x25519,
// not all zero and not of low order. Wraps are sealed to it.
type MintInput struct {
	Name               string
	Scope              map[string]any
	PublicKey          []byte
	PublicKeyAlgorithm string // "x25519"
}

// Mint creates a new agent and returns its long-lived credential. The
// returned struct should be handed to the agent through whatever
// secret-distribution mechanism the deployment uses (mounted K8s
// Secret, env vars, SOPS-encrypted Helm values).
func (s *AgentService) Mint(ctx context.Context, in MintInput) (*MintedAgent, error) {
	if in.Name == "" {
		return nil, errors.New("agents: name is required")
	}
	if in.PublicKeyAlgorithm != sealing.KeyAlgorithm || sealing.ValidatePublicKey(in.PublicKey) != nil {
		return nil, ErrInvalidPublicKey
	}
	fingerprint := sealing.Fingerprint(in.PublicKey)

	secretBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hash := sha256.Sum256([]byte(secret))

	agent := &storage.Agent{
		Name:               in.Name,
		Scope:              in.Scope,
		Status:             storage.AgentStatusActive,
		SecretHash:         hash[:],
		PublicKey:          in.PublicKey,
		PublicKeyAlgorithm: in.PublicKeyAlgorithm,
		// The schema checks the fingerprint column against the key.
		PublicKeyFingerprint: fingerprint,
	}
	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("agents: create: %w", err)
	}

	meta := map[string]any{
		"name":                   in.Name,
		"public_key_algorithm":   in.PublicKeyAlgorithm,
		"public_key_fingerprint": fingerprint,
		"public_key_version":     1,
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    auditActorFromContext(ctx),
		Action:   "agent.mint",
		Resource: "agent:" + agent.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})

	return &MintedAgent{
		ID:                   agent.ID,
		Name:                 agent.Name,
		AgentSecret:          secret,
		PublicKeyFingerprint: fingerprint,
		PublicKeyVersion:     1,
	}, nil
}

// Authenticate validates the agent secret without any side effects on
// last_seen_at. Shared by Heartbeat (which also bumps last_seen) and
// by the agent-auth middleware (which guards /jobs/* endpoints).
//
// Hot path:
//
//  1. Read the secret hash + status, the revocation tombstone and the
//     unknown-id entry from Redis in one round trip. A tombstone rejects
//     whatever the entry says (skills#104).
//  2. On cache miss: read from Postgres and prime the cache (or the
//     unknown-id entry).
//  3. ConstantTimeCompare against the cached/loaded hash.
func (s *AgentService) Authenticate(ctx context.Context, id uuid.UUID, agentSecret string) error {
	_, err := s.authenticate(ctx, id, agentSecret)
	return err
}

// ErrAgentKeyMismatch: the agent secret is right, but the request's
// X-Agent-Key-Fingerprint is missing or is not the bound key's.
var ErrAgentKeyMismatch = errors.New("services: agent key mismatch")

// AuthenticateAgentKey is Authenticate plus the wire-key check
// (skills#116): after the secret check, the presented fingerprint must
// equal the bound key's, compared in constant time. A mismatch or a
// missing header is ErrAgentKeyMismatch and an agent.key.mismatch audit
// row, at most one per agent per minute.
func (s *AgentService) AuthenticateAgentKey(ctx context.Context, id uuid.UUID, agentSecret, fingerprint string) error {
	cached, err := s.authenticate(ctx, id, agentSecret)
	if err != nil {
		return err
	}
	kind := ""
	switch {
	case fingerprint == "":
		kind = "missing"
	case !sealing.IsFingerprint(fingerprint):
		kind = "malformed"
	case subtle.ConstantTimeCompare([]byte(fingerprint), []byte(cached.Fingerprint)) != 1:
		kind = "mismatch"
	}
	if kind == "" {
		return nil
	}
	if s.claimRejectAuditSlot(ctx, cacheKindKeyMismatchAudit, id.String(), "key") {
		meta := map[string]any{
			"agent_id":               id.String(),
			"error_kind":             kind,
			"public_key_fingerprint": cached.Fingerprint,
			"rollup_window_seconds":  int(rejectAuditWindow / time.Second),
		}
		if kind == "mismatch" {
			meta["presented_key_fingerprint"] = fingerprint
		}
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "agent:" + id.String(),
			Action:   "agent.key.mismatch",
			Resource: "agent:" + id.String(),
			Status:   storage.AuditStatusDenied,
			Metadata: meta,
		})
	}
	return ErrAgentKeyMismatch
}

func (s *AgentService) authenticate(ctx context.Context, id uuid.UUID, agentSecret string) (cachedSecretHash, error) {
	var cached cachedSecretHash
	r := s.cache.read(ctx, id)
	if r.revoked != "" {
		s.auditAuthRejected(ctx, id, "revoked")
		return cached, storage.ErrUnauthorized
	}
	if r.missing {
		s.auditAuthRejected(ctx, id, "unknown_agent")
		return cached, storage.ErrNotFound
	}
	if !r.hit || json.Unmarshal(r.entry, &cached) != nil || cached.Fingerprint == "" {
		agent, err := s.agents.Get(ctx, id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				s.cache.markMissing(ctx, id)
				s.auditAuthRejected(ctx, id, "unknown_agent")
			}
			return cached, err
		}
		cached = cachedSecretHash{Status: string(agent.Status), Hash: agent.SecretHash, Fingerprint: agent.PublicKeyFingerprint}
		s.fillSecretHashCache(ctx, id, cached) // best-effort
	}

	if cached.Status == string(storage.AgentStatusRevoked) {
		s.auditAuthRejected(ctx, id, "revoked")
		return cached, storage.ErrUnauthorized
	}
	if len(cached.Hash) == 0 {
		s.auditAuthRejected(ctx, id, "no_credential")
		return cached, storage.ErrUnauthorized
	}
	presented := sha256.Sum256([]byte(agentSecret))
	if subtle.ConstantTimeCompare(presented[:], cached.Hash) != 1 {
		s.auditAuthRejected(ctx, id, "bad_secret")
		return cached, storage.ErrUnauthorized
	}
	return cached, nil
}

// auditAuthRejected records a metadata-only agent.auth.rejected event
// (QA follow-up). No secret, hash, or header material — only the agent id
// and a coarse reason code. Best-effort; never blocks the auth decision.
//
// Rolled up (API-N-07): the agent routes are reachable without a
// credential, so at most one row per (agent id, reason) per
// rejectAuditWindow is written. An unknown agent id is caller-chosen, so
// those all share the "unknown" bucket; otherwise random ids would still
// flood the append-only table.
func (s *AgentService) auditAuthRejected(ctx context.Context, id uuid.UUID, reason string) {
	subject := id.String()
	if reason == "unknown_agent" {
		subject = "unknown"
	}
	if !s.claimRejectAuditSlot(ctx, cacheKindAuthRejectAudit, subject, reason) {
		return
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + id.String(),
		Action:   "agent.auth.rejected",
		Resource: "agent:" + id.String(),
		Status:   storage.AuditStatusDenied,
		Metadata: map[string]any{
			"reason":                reason,
			"rollup_window_seconds": int(rejectAuditWindow / time.Second),
		},
	})
}

// rejectAuditWindow is how long one rejected-auth audit row stands for
// every identical rejection after it (API-N-07).
const rejectAuditWindow = 60 * time.Second

// claimRejectAuditSlot reports whether this (subject, reason) rejection
// should be written to audit_events: the first one in each
// rejectAuditWindow wins a Redis SET NX EX slot and the rest are folded
// into it. Without Redis, or on any Redis error, it returns true:
// auditability must not depend on the cache being up.
func (s *AgentService) claimRejectAuditSlot(ctx context.Context, kind, subject, reason string) bool {
	if s.rdb == nil {
		return true
	}
	key := s.rdb.Key(kind, subject+":"+reason)
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	ok, err := s.rdb.Raw().SetNX(cctx, key, "1", rejectAuditWindow).Result()
	_ = countTimeout(err)
	if err != nil {
		return true
	}
	return ok
}

// Heartbeat authenticates the agent and bumps last_seen_at. Best-effort
// writes the timestamp to Redis for the admin LIST path.
func (s *AgentService) Heartbeat(ctx context.Context, id uuid.UUID, agentSecret string) error {
	if err := s.Authenticate(ctx, id, agentSecret); err != nil {
		return err
	}

	now := s.now().UTC()
	if err := s.agents.TouchLastSeen(ctx, id, now); err != nil {
		return err
	}

	if s.rdb != nil {
		key := s.rdb.Key(cacheKindLastSeen, id.String())
		cctx, cancel := withCacheDeadline(ctx)
		_ = countTimeout(s.rdb.Raw().Set(cctx, key, now.Format(time.RFC3339Nano), s.heartbeatCacheTTL).Err())
		cancel()
	}
	return nil
}

// Revoke transitions an agent to status=revoked, stamps revoked_at +
// revoked_by (the acting admin's identity), AND deletes its cached secret
// hash so the next heartbeat is rejected immediately. Direct calls to
// storage UpdateStatus bypass the cache invalidation; callers must use this
// entry point. reason is recorded in audit metadata only (api#179).
func (s *AgentService) Revoke(ctx context.Context, id uuid.UUID, revokedBy, reason string) error {
	// Load via the admin read path so the audit can name the provider
	// connection binding (metadata-only, QA follow-up) — the certified Get
	// doesn't project provider_connection_id. Missing agent → ErrNotFound.
	row, err := s.agents.GetAdmin(ctx, id)
	if err != nil {
		return err
	}
	// A first tombstone write before the commit stops a fill whose read
	// predates it (skills#104). ensureRevoked confirms the tombstone after
	// the commit and keeps retrying while Redis is unavailable.
	_ = s.cache.markRevoked(ctx, id, tombstoneRevoked)
	// The same statement revokes any open key rotation token and
	// invalidates its challenges (skills#116).
	rev, err := s.agents.Revoke(ctx, id, revokedBy, s.now().UTC())
	if err != nil {
		return err
	}
	cacheErr := s.cache.ensureRevoked(ctx, id, tombstoneRevoked, finalState(tombstoneRevoked))

	actor := auditActor(ctx, revokedBy)
	meta := map[string]any{
		"agent_id":                        id.String(),
		"reason":                          reason,
		"rotation_tokens_revoked":         rev.RotationTokensRevoked,
		"rotation_challenges_invalidated": rev.RotationChallengesInvalidated,
	}
	if row.ProviderConnectionID != nil {
		meta["provider_connection_id"] = row.ProviderConnectionID.String()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    actor,
		Action:   "agent.revoked",
		Resource: "agent:" + id.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})
	if cacheErr != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    actor,
			Action:   "agent.revoke.cache_unconfirmed",
			Resource: "agent:" + id.String(),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{"agent_id": id.String(), "error_kind": "cache_unconfirmed"},
		})
		return cacheErr
	}
	return nil
}

// fillSecretHashCache primes the cache after a Postgres read, unless the
// agent carries a revocation tombstone, then re-reads the row and drops
// the entry if it changed (API-S-21). A failed re-read also drops it.
func (s *AgentService) fillSecretHashCache(ctx context.Context, id uuid.UUID, c cachedSecretHash) {
	raw, err := json.Marshal(c)
	if err != nil {
		return
	}
	s.cache.fill(ctx, id, raw, func() bool {
		fresh, err := s.agents.Get(ctx, id)
		return err == nil && string(fresh.Status) == c.Status && bytes.Equal(fresh.SecretHash, c.Hash) &&
			fresh.PublicKeyFingerprint == c.Fingerprint
	})
}

// List returns every agent, with last-seen pulled from Redis when
// available.
func (s *AgentService) List(ctx context.Context) ([]*AgentView, error) {
	agents, err := s.agents.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*AgentView, 0, len(agents))
	for _, a := range agents {
		v := &AgentView{
			ID:         a.ID,
			Name:       a.Name,
			Status:     a.Status,
			Scope:      a.Scope,
			CreatedAt:  a.CreatedAt,
			LastSeenAt: a.LastSeenAt,
		}
		if s.rdb != nil && a.LastSeenAt == nil {
			cctx, cancel := withCacheDeadline(ctx)
			// The same key Heartbeat writes (the namespace and kind come
			// from the runtime client, api#306).
			cached, err := s.rdb.Raw().Get(cctx, s.rdb.Key(cacheKindLastSeen, a.ID.String())).Result()
			cancel()
			_ = countTimeout(err)
			if err == nil && cached != "" {
				if t, err := time.Parse(time.RFC3339Nano, cached); err == nil {
					v.LastSeenAt = &t
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// AgentView is the read-side projection returned by List. The secret
// hash is intentionally NOT exposed.
type AgentView struct {
	ID         uuid.UUID
	Name       string
	Status     storage.AgentStatus
	Scope      map[string]any
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// IsKeyMismatch reports whether err is ErrAgentKeyMismatch, for the
// AgentAuth middleware (which cannot import this package).
func (s *AgentService) IsKeyMismatch(err error) bool { return errors.Is(err, ErrAgentKeyMismatch) }
