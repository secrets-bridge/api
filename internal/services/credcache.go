package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/secrets-bridge/api/pkg/runtime"
)

// ErrCredentialCacheUnconfirmed: the revoke (or disable) is committed in
// the database, but the cache tombstone could not be written, so a cached
// entry may still let the credential in until it expires. The service
// keeps retrying the tombstone in the background for as long as such an
// entry could live, and the handler answers 503 so the admin knows.
// Retrying the revoke is safe.
var ErrCredentialCacheUnconfirmed = errors.New("services: revoked, but the credential cache could not be cleared yet")

// credCache is the Redis cache in front of a machine credential check
// (agents and Gateways, skills#104). It holds three keys per id:
//
//   - the credential entry (status + secret hash), for hashTTL;
//   - a revocation tombstone ("revoked" or "disabled"), for revokedTTL. A
//     read that sees it treats the id as revoked whatever the entry or the
//     database says, and a fill never writes past it (one Lua call checks
//     and writes). revokedTTL outlives hashTTL, so an entry left by a
//     failed delete expires while the tombstone still blocks it;
//   - a short negative entry for an id the database doesn't know, so a
//     stream of random ids doesn't reach Postgres on every request. Its
//     size is bounded by the request rate times missingTTL; the keys are
//     small and expire on their own.
//
// All three are read in one MGET. Any Redis error reads as a miss, so the
// caller falls back to the database, which is authoritative. The cache
// relies on Redis not evicting keys early (maxmemory-policy noeviction):
// an evicted tombstone would stop blocking an entry that is still there.
type credCache struct {
	rdb                             *runtime.Client
	hashKind, revokedKind, missKind string
	hashTTL, revokedTTL, missingTTL time.Duration
	retryEvery                      time.Duration

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

const (
	tombstoneRevoked  = "revoked"
	tombstoneDisabled = "disabled"
)

var (
	// KEYS[1] tombstone. ARGV[1] reason, ARGV[2] ttl ms. A "disabled"
	// never replaces a "revoked": both block, but the reason must stay.
	setTombstoneScript = redis.NewScript(`
if ARGV[1] ~= 'revoked' and redis.call('GET', KEYS[1]) == 'revoked' then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1`)
	// KEYS[1] tombstone. Deletes it only while it says "disabled", so
	// enabling a Gateway can never lift a revoke's tombstone.
	clearDisabledScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == 'disabled' then return redis.call('DEL', KEYS[1]) end
return 0`)
	// KEYS[1] entry, KEYS[2] tombstone. ARGV[1] entry, ARGV[2] ttl ms.
	// Check and write in one step: no write once a tombstone exists.
	fillScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1`)
)

func newCredCache(rdb *runtime.Client, hashKind string, hashTTL time.Duration) *credCache {
	return &credCache{
		rdb:         rdb,
		hashKind:    hashKind,
		revokedKind: hashKind + "-revoked",
		missKind:    hashKind + "-missing",
		hashTTL:     hashTTL,
		revokedTTL:  2 * hashTTL,
		missingTTL:  30 * time.Second,
		retryEvery:  500 * time.Millisecond,
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

// fill writes entry unless the id carries a tombstone (one atomic call),
// then calls unchanged, a re-read of the database row, and drops the
// entry if it reports a change (API-S-21). A failed call writes nothing.
func (c *credCache) fill(ctx context.Context, id uuid.UUID, entry []byte, unchanged func() bool) {
	if c.rdb == nil {
		return
	}
	if c.beforeFill != nil {
		c.beforeFill()
	}
	wrote, err := fillScript.Run(ctx, c.rdb.Raw(),
		[]string{c.key(c.hashKind, id), c.key(c.revokedKind, id)},
		entry, c.hashTTL.Milliseconds()).Int()
	if err != nil || wrote != 1 {
		return
	}
	if c.afterWrite != nil {
		c.afterWrite()
	}
	if !unchanged() {
		c.invalidate(ctx, id)
	}
}

// markRevoked writes the tombstone. Revoke and disable call it before the
// database update, so a fill whose read predates the commit can't write
// past it. If the database update then fails, the tombstone still blocks
// the (live) credential until it expires: an availability cost on a
// failed revoke, never a security one.
func (c *credCache) markRevoked(ctx context.Context, id uuid.UUID, reason string) error {
	if c.rdb == nil {
		return nil
	}
	return setTombstoneScript.Run(ctx, c.rdb.Raw(), []string{c.key(c.revokedKind, id)}, reason, c.revokedTTL.Milliseconds()).Err()
}

// ensureRevoked runs after the database change. It writes the tombstone
// (a few quick tries) and drops the entry. When Redis won't take the
// tombstone, it keeps trying in the background for revokedTTL, the
// longest a stale entry could still be served once Redis is back, and
// returns ErrCredentialCacheUnconfirmed.
func (c *credCache) ensureRevoked(ctx context.Context, id uuid.UUID, reason string) error {
	if c.rdb == nil {
		return nil
	}
	for _, wait := range []time.Duration{0, 20 * time.Millisecond, 100 * time.Millisecond} {
		time.Sleep(wait)
		if c.markRevoked(ctx, id, reason) == nil {
			c.invalidate(ctx, id)
			return nil
		}
	}
	go c.retryRevoked(id, reason)
	return ErrCredentialCacheUnconfirmed
}

func (c *credCache) retryRevoked(id uuid.UUID, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), c.revokedTTL)
	defer cancel()
	t := time.NewTicker(c.retryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if c.markRevoked(ctx, id, reason) == nil {
				c.invalidate(ctx, id)
				return
			}
		}
	}
}

// clearRevoked drops a "disabled" tombstone when the Gateway is enabled
// again. A "revoked" one stays.
func (c *credCache) clearRevoked(ctx context.Context, id uuid.UUID) {
	if c.rdb == nil {
		return
	}
	_ = clearDisabledScript.Run(ctx, c.rdb.Raw(), []string{c.key(c.revokedKind, id)}).Err()
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
	if errors.Is(err, redis.Nil) {
		return nil
	}
	return err
}
