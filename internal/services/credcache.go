package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/secrets-bridge/api/pkg/runtime"
)

// credCache is the Redis cache in front of a machine credential check
// (agents and Gateways, skills#104). It holds three keys per id:
//
//   - the credential entry (status + secret hash), for hashTTL;
//   - a revocation tombstone, written by revoke (or disable) BEFORE the
//     database update, for revokedTTL. A read that sees it treats the id
//     as revoked whatever the entry or the database says, and a fill that
//     sees it writes nothing. revokedTTL outlives hashTTL, so a stale entry
//     left by a failed delete, or by a fill racing the revoke, expires
//     while the tombstone still blocks it;
//   - a short negative entry for an id the database doesn't know, so a
//     stream of random ids doesn't reach Postgres on every request.
//
// All three are read in one MGET. Any Redis error reads as a miss, so the
// caller falls back to the database, which is authoritative.
type credCache struct {
	rdb                             *runtime.Client
	hashKind, revokedKind, missKind string
	hashTTL, revokedTTL, missingTTL time.Duration

	// Test seams (export_test.go); nil in production.
	beforeFill func()
	afterWrite func()
	del        func(ctx context.Context, key string) error
}

// credCacheRead is what one MGET found for an id.
type credCacheRead struct {
	entry   []byte
	hit     bool   // entry present
	revoked string // tombstone value ("revoked", "disabled"), empty if none
	missing bool   // negative entry present
}

func newCredCache(rdb *runtime.Client, hashKind string, hashTTL time.Duration) *credCache {
	return &credCache{
		rdb:         rdb,
		hashKind:    hashKind,
		revokedKind: hashKind + "-revoked",
		missKind:    hashKind + "-missing",
		hashTTL:     hashTTL,
		revokedTTL:  2 * hashTTL,
		missingTTL:  30 * time.Second,
	}
}

func (c *credCache) key(kind string, id uuid.UUID) string { return c.rdb.Key(kind, id.String()) }

func (c *credCache) read(ctx context.Context, id uuid.UUID) credCacheRead {
	if c.rdb == nil {
		return credCacheRead{}
	}
	vals, err := c.rdb.Raw().MGet(ctx, c.key(c.hashKind, id), c.key(c.revokedKind, id), c.key(c.missKind, id)).Result()
	if err != nil || len(vals) != 3 {
		return credCacheRead{}
	}
	var r credCacheRead
	if s, ok := vals[0].(string); ok {
		r.entry, r.hit = []byte(s), true
	}
	if s, ok := vals[1].(string); ok {
		r.revoked = s
	}
	if _, ok := vals[2].(string); ok {
		r.missing = true
	}
	return r
}

// fill writes entry unless the id carries a tombstone, then calls
// unchanged, a re-read of the database row, and drops the entry if it
// reports a change (API-S-21).
func (c *credCache) fill(ctx context.Context, id uuid.UUID, entry []byte, unchanged func() bool) {
	if c.rdb == nil {
		return
	}
	if c.beforeFill != nil {
		c.beforeFill()
	}
	// A tombstone, or a failed check, means no write: the next call goes
	// back to the database.
	if n, err := c.rdb.Raw().Exists(ctx, c.key(c.revokedKind, id)).Result(); err != nil || n > 0 {
		return
	}
	_, _ = c.rdb.Raw().Set(ctx, c.key(c.hashKind, id), entry, c.hashTTL).Result()
	if c.afterWrite != nil {
		c.afterWrite()
	}
	if !unchanged() {
		c.invalidate(ctx, id)
	}
}

// markRevoked writes the tombstone. Revoke and disable call it before
// they update the database.
func (c *credCache) markRevoked(ctx context.Context, id uuid.UUID, reason string) error {
	if c.rdb == nil {
		return nil
	}
	return c.rdb.Raw().Set(ctx, c.key(c.revokedKind, id), reason, c.revokedTTL).Err()
}

// clearRevoked drops the tombstone when a disabled Gateway is enabled again.
func (c *credCache) clearRevoked(ctx context.Context, id uuid.UUID) {
	if c.rdb == nil {
		return
	}
	_ = c.delKey(ctx, c.key(c.revokedKind, id))
}

func (c *credCache) markMissing(ctx context.Context, id uuid.UUID) {
	if c.rdb == nil {
		return
	}
	_, _ = c.rdb.Raw().Set(ctx, c.key(c.missKind, id), "1", c.missingTTL).Result()
}

// invalidate drops the credential entry. A failure is tolerated: after a
// revoke the tombstone still blocks the entry until it expires.
func (c *credCache) invalidate(ctx context.Context, id uuid.UUID) {
	if c.rdb == nil {
		return
	}
	_ = c.delKey(ctx, c.key(c.hashKind, id))
}

func (c *credCache) delKey(ctx context.Context, key string) error {
	if c.del != nil {
		return c.del(ctx, key)
	}
	err := c.rdb.Raw().Del(ctx, key).Err()
	if err == redis.Nil {
		return nil
	}
	return err
}
