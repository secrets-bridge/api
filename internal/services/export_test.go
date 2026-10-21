package services

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CredCacheSeams are test hooks into the agent and Gateway credential
// cache (skills#104). BeforeFill runs after the database read and before
// the cache write; AfterWrite runs after the write and before the re-read;
// Del replaces the Redis delete.
type CredCacheSeams struct {
	BeforeFill func()
	AfterWrite func()
	Del        func(ctx context.Context, key string) error
}

func setSeams(c *credCache, s CredCacheSeams) {
	c.beforeFill, c.afterWrite, c.del = s.BeforeFill, s.AfterWrite, s.Del
}

// SetAgentCacheSeams installs test hooks on an AgentService's cache.
func SetAgentCacheSeams(svc *AgentService, s CredCacheSeams) { setSeams(svc.cache, s) }

// SetGatewayCacheSeams installs test hooks on a GatewayService's cache.
func SetGatewayCacheSeams(svc *GatewayService, s CredCacheSeams) { setSeams(svc.cache, s) }

// SetAgentCacheRetry shortens the background tombstone retry for tests.
func SetAgentCacheRetry(svc *AgentService, d time.Duration) { svc.cache.retryEvery = d }

// SetGatewayCacheRetry shortens the background tombstone retry for tests.
func SetGatewayCacheRetry(svc *GatewayService, d time.Duration) { svc.cache.retryEvery = d }

// WriteGatewayTombstone writes a tombstone the way a revoke or disable does.
func WriteGatewayTombstone(ctx context.Context, svc *GatewayService, id uuid.UUID, reason string) error {
	return svc.cache.markRevoked(ctx, id, reason)
}

// GatewayTombstone reads a Gateway's tombstone ("" when there is none).
func GatewayTombstone(ctx context.Context, svc *GatewayService, id uuid.UUID) string {
	v, _ := svc.cache.rdb.Raw().Get(ctx, svc.cache.key(svc.cache.revokedKind, id)).Result()
	return v
}

// AgentTombstone reads an agent's tombstone ("" when there is none).
func AgentTombstone(ctx context.Context, svc *AgentService, id uuid.UUID) string {
	v, _ := svc.cache.rdb.Raw().Get(ctx, svc.cache.key(svc.cache.revokedKind, id)).Result()
	return v
}
