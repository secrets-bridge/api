// Package runtime owns Redis-backed coordination primitives for the
// Control Plane: idempotency keys, distributed locks, rate limiters,
// and pub/sub. Public surface is importable from the `worker` repo per
// REFACTOR_PLAN §4.
//
// Hard rules (BRD §10.1, §13 FR-15, §24, CLAUDE.md):
//
//   1. Redis is a Control Plane runtime dependency only. Agents and the
//      controller MUST NOT import this package.
//   2. NO SECRET VALUES IN REDIS. Not in keys, not in values, not in
//      pub/sub payloads. Redis is for coordination and short-lived
//      caches; secret values stay in the providers.
//   3. Every primitive in this package is safe to use under failover —
//      keys carry TTLs, locks carry leases, idempotency entries expire.
//      A stale Redis instance can degrade but never deadlock the CP.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config carries everything runtime needs to connect.
type Config struct {
	// URL is a redis:// or rediss:// connection string.
	URL string

	// PoolSize caps the number of connections. Defaults to 10.
	PoolSize int

	// DialTimeout bounds the initial connect. Defaults to 5s.
	DialTimeout time.Duration

	// Namespace prefixes every key so dev/staging/prod sharing a
	// Redis don't collide. Defaults to "secrets-bridge" — short
	// enough not to bloat keys at scale, descriptive enough that
	// `KEYS *` immediately tells the operator what app owns them.
	Namespace string
}

// ErrConfigMissing is returned by LoadConfig when REDIS_URL is unset.
var ErrConfigMissing = errors.New("runtime: REDIS_URL is required")

// LoadConfig reads the standard env vars. URL is required; the rest
// default to safe values.
func LoadConfig() (Config, error) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return Config{}, ErrConfigMissing
	}
	cfg := Config{
		URL:         url,
		PoolSize:    10,
		DialTimeout: 5 * time.Second,
		Namespace:   "secrets-bridge",
	}
	if v := os.Getenv("REDIS_POOL_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			cfg.PoolSize = n
		}
	}
	if v := os.Getenv("REDIS_DIAL_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil && d > 0 {
			cfg.DialTimeout = d
		}
	}
	if v := os.Getenv("REDIS_NAMESPACE"); v != "" {
		cfg.Namespace = v
	}
	return cfg, nil
}

// Client wraps a *redis.Client with the configured namespace so every
// primitive in this package speaks in already-prefixed keys.
type Client struct {
	cfg Config
	rdb *redis.Client
}

// Open builds a redis client and Pings to confirm reachability.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("runtime: parse URL: %w", err)
	}
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("runtime: ping: %w", err)
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "secrets-bridge"
	}
	return &Client{cfg: cfg, rdb: rdb}, nil
}

// Close releases the connection pool. Idempotent.
func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

// Ping is exposed so callers can register it as a readiness check
// without having to reach for the underlying client.
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.rdb == nil {
		return errors.New("runtime: client not initialized")
	}
	return c.rdb.Ping(ctx).Err()
}

// Raw exposes the underlying go-redis client for advanced operations
// (Lua scripts, custom commands) that this package doesn't surface.
// Prefer the typed primitives where they exist.
func (c *Client) Raw() *redis.Client { return c.rdb }

// key produces a namespaced key. The shape is "<ns>:<kind>:<rest>".
// kind is a static category name owned by each primitive ("idem",
// "lock", "rate", "ch") so a wildcard scan or MIGRATION can address a
// single subsystem.
func (c *Client) key(kind, rest string) string {
	return c.cfg.Namespace + ":" + kind + ":" + rest
}

// Key is the public exposure of the namespaced-key builder so callers
// outside this package (the agent + workflow services that need their
// own kinds — "agent-hash", "agent-lastseen", "approval-cache" — can
// use the same shape without reaching into the internals.
func (c *Client) Key(kind, rest string) string { return c.key(kind, rest) }
