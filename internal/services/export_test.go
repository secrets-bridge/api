package services

import "context"

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
