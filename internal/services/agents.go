// Package services holds the business-logic layer of the api.
//
// This file owns the agent identity flow: mint a one-time registration
// token, validate it on /agents/register, hand back a long-lived agent
// secret, and validate the agent secret on every heartbeat.
//
// Token shape (MVP):
//   - registration_token: 32 random bytes, base64-encoded; presented
//     ONCE; SHA-256-hashed at rest in agents.registration_token_hash
//   - agent_secret:       32 random bytes, base64-encoded; presented
//     on every heartbeat; the bcrypt of this string is stored in a
//     dedicated row column on first successful Register (Phase 2 —
//     today we still use the registration_token_hash slot, cleared
//     once the secret is issued)
//
// Future iteration (issue: TBD) replaces the per-request secret with a
// short-lived signed identity (JWT) or mTLS. The MVP form is enough
// to demonstrate the registration → heartbeat flow end-to-end.
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

// AgentService owns the agent registration + heartbeat flows.
type AgentService struct {
	agents      storage.AgentRepository
	audit       storage.AuditEventRepository
	rdb         *runtime.Client
	now         func() time.Time

	// HeartbeatCacheTTL controls how long an agent's last-seen
	// timestamp is cached in Redis to spare Postgres on List polls.
	// Defaults to 5 × HeartbeatInterval.
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

// MintRegistrationToken creates a new pending agent and returns the
// plaintext registration token to the admin. The token is returned
// EXACTLY ONCE — only its hash is persisted.
func (s *AgentService) MintRegistrationToken(ctx context.Context, name string, scope map[string]any) (*MintedAgent, error) {
	if name == "" {
		return nil, errors.New("agents: name is required")
	}

	tokenBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))

	agent := &storage.Agent{
		Name:                  name,
		Scope:                 scope,
		Status:                storage.AgentStatusPending,
		RegistrationTokenHash: hash[:],
	}
	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("agents: create: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin", // wired to real auth in #6
		Action:   "agent.mint_token",
		Resource: "agent:" + agent.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"name": name},
	})

	return &MintedAgent{
		ID:                agent.ID,
		Name:              agent.Name,
		RegistrationToken: token,
	}, nil
}

// MintedAgent is returned by MintRegistrationToken. The
// RegistrationToken is the plaintext that the admin hands to the agent
// — it is never stored and never recoverable from the database.
type MintedAgent struct {
	ID                uuid.UUID
	Name              string
	RegistrationToken string
}

// Register redeems a registration token: it verifies the presented
// token matches what was minted, mints a fresh long-lived agent
// secret, stores its hash, and returns the plaintext secret to the
// agent. The registration token hash is cleared on success — replays
// return ErrUnauthorized because the row no longer matches.
func (s *AgentService) Register(ctx context.Context, id uuid.UUID, registrationToken string) (*RegisteredAgent, error) {
	regHash := sha256.Sum256([]byte(registrationToken))

	secretBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	secretHash := sha256.Sum256([]byte(secret))

	err = s.agents.RedeemRegistrationToken(ctx, id, regHash[:], secretHash[:])
	if err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "agent:" + id.String(),
			Action:   "agent.register",
			Resource: "agent:" + id.String(),
			Status:   statusFor(err),
			Metadata: map[string]any{"error_kind": errorKind(err)},
		})
		return nil, err
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + id.String(),
		Action:   "agent.register",
		Resource: "agent:" + id.String(),
		Status:   storage.AuditStatusSuccess,
	})

	return &RegisteredAgent{
		ID:          id,
		AgentSecret: secret,
	}, nil
}

// RegisteredAgent is returned to the agent after a successful Register.
// The AgentSecret is the identity material the agent presents on every
// heartbeat.
type RegisteredAgent struct {
	ID          uuid.UUID
	AgentSecret string
}

// Heartbeat validates the agent secret and updates last_seen. The
// successful path writes to Redis FIRST (cheap, the heartbeat polls
// can be fast) and to Postgres async-ish — we still do it inline but a
// future iteration can batch with a worker.
func (s *AgentService) Heartbeat(ctx context.Context, id uuid.UUID, agentSecret string) error {
	agent, err := s.agents.Get(ctx, id)
	if err != nil {
		return err
	}

	// MVP: after Register, registration_token_hash is cleared. We
	// fall back to checking the bcrypt of the secret IF a future
	// migration adds a dedicated agent_secret_hash column. For now,
	// the simpler design is: only the just-registered token is
	// accepted, and after registration the agent must use that
	// token. The hash is re-derived from the secret on every call
	// using a constant-time comparison; the call short-circuits if
	// the agent's status is revoked.
	if agent.Status == storage.AgentStatusRevoked {
		return storage.ErrUnauthorized
	}
	if len(agent.SecretHash) == 0 {
		// Pending agent that has not yet redeemed its registration
		// token — it cannot heartbeat.
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

	// Cache last-seen so admin GET /agents doesn't need to hit
	// Postgres for every row. Best-effort; failure here is non-fatal.
	if s.rdb != nil {
		key := "lastseen:" + id.String()
		_, _ = s.rdb.Raw().Set(ctx, "secrets-bridge:agent:"+key, now.Format(time.RFC3339Nano), s.heartbeatCacheTTL).Result()
	}

	return nil
}

// List returns every agent, with last-seen pulled from Redis when
// available so the response is fast and Postgres is spared.
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

// AgentView is the read-side projection returned by List. The
// registration token hash is intentionally NOT exposed.
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

func statusFor(err error) storage.AuditStatus {
	if err == nil {
		return storage.AuditStatusSuccess
	}
	if errors.Is(err, storage.ErrUnauthorized) {
		return storage.AuditStatusDenied
	}
	return storage.AuditStatusFailure
}

func errorKind(err error) string {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return "not_found"
	case errors.Is(err, storage.ErrUnauthorized):
		return "unauthorized"
	default:
		return "other"
	}
}
