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
	cacheKindAuthRejectAudit   = "agent-auth-reject-audit"
	cacheKindEnrollRejectAudit = "agent-enroll-reject-audit"
)

// cachedSecretHash holds the marshalled form stored in Redis. We track
// the agent's status alongside the hash so a `revoked` row whose cache
// hasn't been invalidated yet still fails the validation check.
type cachedSecretHash struct {
	Status string `json:"status"`
	Hash   []byte `json:"hash"`
}

// MintedAgent is returned by Mint. AgentSecret is the plaintext
// long-lived credential — it is returned exactly ONCE and not
// recoverable from the database afterwards.
type MintedAgent struct {
	ID          uuid.UUID
	Name        string
	AgentSecret string
}

// MintInput captures everything Mint accepts. PublicKey is optional;
// when present (Piece 8b agents that ran key generation at startup),
// the CP will SEAL wrap retrieval responses to that key instead of
// returning plaintext-over-TLS.
type MintInput struct {
	Name               string
	Scope              map[string]any
	PublicKey          []byte
	PublicKeyAlgorithm string // "x25519" today; future schemes slot in
}

// Mint creates a new agent and returns its long-lived credential. The
// returned struct should be handed to the agent through whatever
// secret-distribution mechanism the deployment uses (mounted K8s
// Secret, env vars, SOPS-encrypted Helm values).
func (s *AgentService) Mint(ctx context.Context, in MintInput) (*MintedAgent, error) {
	if in.Name == "" {
		return nil, errors.New("agents: name is required")
	}
	if len(in.PublicKey) > 0 && in.PublicKeyAlgorithm == "" {
		return nil, errors.New("agents: public_key_algorithm is required when public_key is provided")
	}
	if in.PublicKeyAlgorithm != "" && in.PublicKeyAlgorithm != "x25519" {
		return nil, fmt.Errorf("agents: unsupported public_key_algorithm %q", in.PublicKeyAlgorithm)
	}
	if in.PublicKeyAlgorithm == "x25519" && len(in.PublicKey) != 32 {
		return nil, fmt.Errorf("agents: x25519 public key must be 32 bytes, got %d", len(in.PublicKey))
	}

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
	}
	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("agents: create: %w", err)
	}

	meta := map[string]any{"name": in.Name}
	if len(in.PublicKey) > 0 {
		meta["public_key_algorithm"] = in.PublicKeyAlgorithm
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    auditActorFromContext(ctx),
		Action:   "agent.mint",
		Resource: "agent:" + agent.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})

	return &MintedAgent{
		ID:          agent.ID,
		Name:        agent.Name,
		AgentSecret: secret,
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
	r := s.cache.read(ctx, id)
	if r.revoked != "" {
		s.auditAuthRejected(ctx, id, "revoked")
		return storage.ErrUnauthorized
	}
	if r.missing {
		s.auditAuthRejected(ctx, id, "unknown_agent")
		return storage.ErrNotFound
	}
	var cached cachedSecretHash
	if !r.hit || json.Unmarshal(r.entry, &cached) != nil {
		agent, err := s.agents.Get(ctx, id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				s.cache.markMissing(ctx, id)
				s.auditAuthRejected(ctx, id, "unknown_agent")
			}
			return err
		}
		cached = cachedSecretHash{Status: string(agent.Status), Hash: agent.SecretHash}
		s.fillSecretHashCache(ctx, id, cached) // best-effort
	}

	if cached.Status == string(storage.AgentStatusRevoked) {
		s.auditAuthRejected(ctx, id, "revoked")
		return storage.ErrUnauthorized
	}
	if len(cached.Hash) == 0 {
		s.auditAuthRejected(ctx, id, "no_credential")
		return storage.ErrUnauthorized
	}
	presented := sha256.Sum256([]byte(agentSecret))
	if subtle.ConstantTimeCompare(presented[:], cached.Hash) != 1 {
		s.auditAuthRejected(ctx, id, "bad_secret")
		return storage.ErrUnauthorized
	}
	return nil
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
	ok, err := s.rdb.Raw().SetNX(ctx, key, "1", rejectAuditWindow).Result()
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
		_, _ = s.rdb.Raw().Set(ctx, key, now.Format(time.RFC3339Nano), s.heartbeatCacheTTL).Result()
	}
	return nil
}

// Revoke transitions an agent to status=revoked AND deletes its cached
// secret hash so the next heartbeat is rejected immediately. Direct
// calls to storage.AgentRepository.UpdateStatus bypass the cache
// invalidation; callers must use this entry point.
// SetPublicKey upserts the agent's wire-envelope public key. The
// agent calls this after generating its X25519 keypair at startup so
// future GetWrap responses come sealed (Piece 8b). Validates the
// key shape; emits an audit event with the new key id so an operator
// can spot a key rotation in the audit log.
func (s *AgentService) SetPublicKey(ctx context.Context, id uuid.UUID, publicKey []byte, algorithm string) error {
	if len(publicKey) == 0 {
		return errors.New("agents: public_key is required")
	}
	if algorithm == "" {
		algorithm = "x25519"
	}
	if algorithm != "x25519" {
		return fmt.Errorf("agents: unsupported public_key_algorithm %q", algorithm)
	}
	if len(publicKey) != 32 {
		return fmt.Errorf("agents: x25519 public key must be 32 bytes, got %d", len(publicKey))
	}
	if err := s.agents.UpdatePublicKey(ctx, id, publicKey, algorithm); err != nil {
		return fmt.Errorf("agents: update public key: %w", err)
	}
	// content_hash-style identifier for the new key — useful in audit
	// without revealing the key itself.
	sum := sha256.Sum256(publicKey)
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + id.String(),
		Action:   "agent.public_key.set",
		Resource: "agent:" + id.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"algorithm":      algorithm,
			"public_key_sha": base64.RawURLEncoding.EncodeToString(sum[:8]),
		},
	})
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
	if err := s.agents.Revoke(ctx, id, revokedBy, s.now().UTC()); err != nil {
		return err
	}
	cacheErr := s.cache.ensureRevoked(ctx, id, tombstoneRevoked)

	actor := auditActor(ctx, revokedBy)
	meta := map[string]any{
		"agent_id": id.String(),
		"reason":   reason,
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
		return err == nil && string(fresh.Status) == c.Status && bytes.Equal(fresh.SecretHash, c.Hash)
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
			if cached, err := s.rdb.Raw().Get(ctx, "secrets-bridge:agent:lastseen:"+a.ID.String()).Result(); err == nil && cached != "" {
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
