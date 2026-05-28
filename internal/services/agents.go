// Package services holds the business-logic layer of the api.
//
// AgentService owns the one-credential agent flow:
//
//   1. Admin calls Mint → returns {id, agent_secret}. The plaintext
//      secret is returned ONCE; only its SHA-256 hash is persisted.
//   2. Admin (or the chart that wraps this call) lands those values
//      in the agent's K8s Secret / env vars.
//   3. Agent reads the values at startup and presents agent_secret in
//      the X-Agent-Secret header on every heartbeat.
//
// There is intentionally no separate registration step — the Pod can
// restart at will, re-read the same Secret, and keep heartbeating
// without a PVC for state persistence.
package services

import (
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
// SELECT under load. Revocation MUST go through Revoke() — direct
// status updates to the storage layer would leave the cache stale and
// let a revoked agent keep heartbeating for up to secretHashCacheTTL.
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
}

// NewAgentService constructs an AgentService.
func NewAgentService(agents storage.AgentRepository, audit storage.AuditEventRepository, rdb *runtime.Client) *AgentService {
	return &AgentService{
		agents:             agents,
		audit:              audit,
		rdb:                rdb,
		now:                time.Now,
		heartbeatCacheTTL:  5 * time.Minute,
		secretHashCacheTTL: 60 * time.Second,
	}
}

// Redis key prefixes — `kind` slot for the runtime namespace builder.
const (
	cacheKindSecretHash = "agent-hash"
	cacheKindLastSeen   = "agent-lastseen"
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

// Mint creates a new agent and returns its long-lived credential. The
// returned struct should be handed to the agent through whatever
// secret-distribution mechanism the deployment uses (mounted K8s
// Secret, env vars, SOPS-encrypted Helm values).
func (s *AgentService) Mint(ctx context.Context, name string, scope map[string]any) (*MintedAgent, error) {
	if name == "" {
		return nil, errors.New("agents: name is required")
	}

	secretBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hash := sha256.Sum256([]byte(secret))

	agent := &storage.Agent{
		Name:       name,
		Scope:      scope,
		Status:     storage.AgentStatusActive,
		SecretHash: hash[:],
	}
	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("agents: create: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin", // wired to real auth in #10
		Action:   "agent.mint",
		Resource: "agent:" + agent.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"name": name},
	})

	return &MintedAgent{
		ID:          agent.ID,
		Name:        agent.Name,
		AgentSecret: secret,
	}, nil
}

// Heartbeat validates the agent secret and updates last_seen_at.
//
// Hot path:
//
//	1. Read the secret hash + status from Redis.
//	2. On cache miss: read from Postgres and prime the cache.
//	3. ConstantTimeCompare against the cached/loaded hash.
//	4. UPDATE last_seen_at in Postgres (no-op on revoked rows).
//	5. Best-effort write of last_seen_at to Redis for the admin
//	   LIST endpoint.
func (s *AgentService) Heartbeat(ctx context.Context, id uuid.UUID, agentSecret string) error {
	cached, hadCache, err := s.readSecretHashCache(ctx, id)
	if err != nil {
		return err
	}
	if !hadCache {
		agent, err := s.agents.Get(ctx, id)
		if err != nil {
			return err
		}
		cached = cachedSecretHash{Status: string(agent.Status), Hash: agent.SecretHash}
		s.writeSecretHashCache(ctx, id, cached) // best-effort
	}

	if cached.Status == string(storage.AgentStatusRevoked) {
		return storage.ErrUnauthorized
	}
	if len(cached.Hash) == 0 {
		return storage.ErrUnauthorized
	}
	presented := sha256.Sum256([]byte(agentSecret))
	if subtle.ConstantTimeCompare(presented[:], cached.Hash) != 1 {
		return storage.ErrUnauthorized
	}

	now := s.now().UTC()
	if err := s.agents.TouchLastSeen(ctx, id, now); err != nil {
		return err
	}

	// Cache last-seen so admin GET /agents doesn't hit Postgres for
	// every row. Best-effort; failure here is non-fatal.
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
func (s *AgentService) Revoke(ctx context.Context, id uuid.UUID) error {
	if err := s.agents.UpdateStatus(ctx, id, storage.AgentStatusRevoked); err != nil {
		return err
	}
	s.invalidateSecretHashCache(ctx, id)

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin",
		Action:   "agent.revoke",
		Resource: "agent:" + id.String(),
		Status:   storage.AuditStatusSuccess,
	})
	return nil
}

// readSecretHashCache returns the cached entry and whether the cache
// served the lookup. A nil rdb (test injection / boot path) reports
// "no cache" without erroring.
func (s *AgentService) readSecretHashCache(ctx context.Context, id uuid.UUID) (cachedSecretHash, bool, error) {
	if s.rdb == nil {
		return cachedSecretHash{}, false, nil
	}
	key := s.rdb.Key(cacheKindSecretHash, id.String())
	raw, err := s.rdb.Raw().Get(ctx, key).Bytes()
	if err != nil {
		// redis.Nil is the "miss" sentinel; anything else is a real
		// Redis problem. We treat real Redis errors as cache miss so
		// the caller falls through to Postgres rather than failing
		// every heartbeat when Redis flakes.
		return cachedSecretHash{}, false, nil //nolint:nilerr // intentional cache-miss-on-error
	}
	var c cachedSecretHash
	if err := json.Unmarshal(raw, &c); err != nil {
		return cachedSecretHash{}, false, nil
	}
	return c, true, nil
}

func (s *AgentService) writeSecretHashCache(ctx context.Context, id uuid.UUID, c cachedSecretHash) {
	if s.rdb == nil {
		return
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return
	}
	key := s.rdb.Key(cacheKindSecretHash, id.String())
	_, _ = s.rdb.Raw().Set(ctx, key, raw, s.secretHashCacheTTL).Result()
}

func (s *AgentService) invalidateSecretHashCache(ctx context.Context, id uuid.UUID) {
	if s.rdb == nil {
		return
	}
	key := s.rdb.Key(cacheKindSecretHash, id.String())
	_, _ = s.rdb.Raw().Del(ctx, key).Result()
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
