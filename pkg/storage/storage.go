// Package storage owns the api service's durable state in PostgreSQL.
//
// Public surface (the Pool, the repositories) is importable from the
// `worker` repo per REFACTOR_PLAN §4 — `agent` and `controller` must
// never import this package.
//
// Hard rule (BRD §11, §13 FR-04, CLAUDE.md):
//
//   NO COLUMN ON ANY TABLE STORES AN ACTUAL SECRET VALUE.
//
// Only references, opaque content hashes, version IDs, statuses, and
// metadata. Secret values stay inside the providers (Vault, AWS SM,
// GCP SM, Azure KV) and are read by the agent at execution time only.
// The schema itself does not declare any column that could plausibly
// hold one.
package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config carries everything storage needs to connect. Populated by
// LoadConfig from environment variables; injected explicitly in tests.
type Config struct {
	// DSN is the Postgres connection string (pgx URL form).
	DSN string

	// MaxConns caps the connection pool. Defaults to 10 — appropriate
	// for a stateless API replica behind an HPA. Bump for worker.
	MaxConns int32

	// ConnLifetime bounds how long an idle connection lives. Defaults
	// to 30 minutes so transient PgBouncer / cloud failovers recycle
	// pool entries on their own.
	ConnLifetime time.Duration
}

// ErrConfigMissing is returned by LoadConfig when DATABASE_URL is unset.
var ErrConfigMissing = errors.New("storage: DATABASE_URL is required")

// LoadConfig reads the standard env vars. The DSN is required; the
// pool sizing knobs default to safe values when unset.
func LoadConfig() (Config, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return Config{}, ErrConfigMissing
	}

	cfg := Config{
		DSN:          dsn,
		MaxConns:     10,
		ConnLifetime: 30 * time.Minute,
	}
	if v := os.Getenv("DATABASE_MAX_CONNS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err == nil && n > 0 {
			cfg.MaxConns = int32(n)
		}
	}
	if v := os.Getenv("DATABASE_CONN_LIFETIME"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil && d > 0 {
			cfg.ConnLifetime = d
		}
	}
	return cfg, nil
}

// Pool wraps *pgxpool.Pool so callers depend on this package, not pgx
// directly. Concrete repositories embed it.
type Pool struct {
	*pgxpool.Pool
}

// Open builds a pgx connection pool from the Config and Pings to confirm
// reachability before returning. Context is honored for the initial
// dial + ping.
func Open(ctx context.Context, cfg Config) (*Pool, error) {
	pcfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("storage: parse DSN: %w", err)
	}
	pcfg.MaxConns = cfg.MaxConns
	pcfg.MaxConnLifetime = cfg.ConnLifetime

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("storage: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	return &Pool{Pool: pool}, nil
}

// Close shuts the pool down. Idempotent; safe to call in deferred
// cleanup even when Open returned an error.
func (p *Pool) Close() {
	if p == nil || p.Pool == nil {
		return
	}
	p.Pool.Close()
}
