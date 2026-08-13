package services

// Agent Onboarding MVP api-2 (api#179) — richer heartbeat + admin read
// surface. All metadata-only; no credential material is ever returned.

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// HeartbeatInput carries the OPTIONAL runtime fields an agent may report on
// heartbeat. Empty fields leave the stored value unchanged. cluster_name /
// provider_connection are identity (fixed at enroll) and are NOT updatable
// here.
type HeartbeatInput struct {
	AgentVersion string
	LastStatus   string
	Capabilities []string
}

// RecordHeartbeat authenticates the agent (belt-and-suspenders over the
// AgentAuth middleware) and records the heartbeat plus any reported runtime
// fields. An enrolled agent's first heartbeat flips it active. Revoked
// agents are rejected by Authenticate before any write.
func (s *AgentService) RecordHeartbeat(ctx context.Context, id uuid.UUID, agentSecret string, in HeartbeatInput) error {
	if err := s.Authenticate(ctx, id, agentSecret); err != nil {
		return err
	}
	now := s.now().UTC()

	var ver, st *string
	var caps *[]string
	if in.AgentVersion != "" {
		ver = &in.AgentVersion
	}
	if in.LastStatus != "" {
		st = &in.LastStatus
	}
	if in.Capabilities != nil {
		caps = &in.Capabilities
	}
	if err := s.agents.RecordHeartbeat(ctx, id, now, ver, st, caps); err != nil {
		return err
	}

	if s.rdb != nil {
		key := s.rdb.Key(cacheKindLastSeen, id.String())
		_, _ = s.rdb.Raw().Set(ctx, key, now.Format(time.RFC3339Nano), s.heartbeatCacheTTL).Result()
	}
	return nil
}

// ListAgents returns the admin projection (onboarding columns + provider
// connection name; never credentials), narrowed by the filter.
func (s *AgentService) ListAgents(ctx context.Context, f storage.AgentAdminFilter) ([]*storage.AgentAdminRow, error) {
	return s.agents.ListAdmin(ctx, f)
}

// GetAgent returns one agent's admin projection. ErrNotFound when missing.
func (s *AgentService) GetAgent(ctx context.Context, id uuid.UUID) (*storage.AgentAdminRow, error) {
	return s.agents.GetAdmin(ctx, id)
}
