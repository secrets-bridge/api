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
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// AgentService owns the agent mint + heartbeat flow.
type AgentService struct {
	agents storage.AgentRepository
	audit  storage.AuditEventRepository
	rdb    *runtime.Client
	now    func() time.Time

	// HeartbeatCacheTTL bounds how long the last-seen timestamp is
	// cached in Redis. Defaults to 5 × HeartbeatInterval.
	heartbeatCacheTTL time.Duration
}

// NewAgentService constructs an AgentService.
func NewAgentService(agents storage.AgentRepository, audit storage.AuditEventRepository, rdb *runtime.Client) *AgentService {
	return &AgentService{
		agents:            agents,
		audit:             audit,
		rdb:               rdb,
		now:               time.Now,
		heartbeatCacheTTL: 5 * time.Minute,
	}
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
func (s *AgentService) Heartbeat(ctx context.Context, id uuid.UUID, agentSecret string) error {
	agent, err := s.agents.Get(ctx, id)
	if err != nil {
		return err
	}
	if agent.Status == storage.AgentStatusRevoked {
		return storage.ErrUnauthorized
	}
	if len(agent.SecretHash) == 0 {
		return storage.ErrUnauthorized
	}
	presented := sha256.Sum256([]byte(agentSecret))
	if subtle.ConstantTimeCompare(presented[:], agent.SecretHash) != 1 {
		return storage.ErrUnauthorized
	}

	now := s.now().UTC()
	if err := s.agents.TouchLastSeen(ctx, id, now); err != nil {
		return err
	}

	// Cache last-seen so admin GET /agents doesn't hit Postgres for
	// every row. Best-effort; failure here is non-fatal.
	if s.rdb != nil {
		key := "lastseen:" + id.String()
		_, _ = s.rdb.Raw().Set(ctx, "secrets-bridge:agent:"+key, now.Format(time.RFC3339Nano), s.heartbeatCacheTTL).Result()
	}
	return nil
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
