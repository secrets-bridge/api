package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/secrets-bridge/api/pkg/runtime"
)

// ErrCredentialCacheUnconfirmed: the revoke, disable or enable is
// committed in the database, but the cache could not be brought in line
// with it yet. After a revoke or disable a cached entry may still let the
// credential in; after an enable a stale tombstone may still keep the
// Gateway out. The service keeps retrying in the background for as long
// as such a key could live, and the handler answers 503 so the admin
// knows. Retrying the call is safe.
var ErrCredentialCacheUnconfirmed = errors.New("services: committed, but the credential cache could not be updated yet")

// cacheCallTimeout bounds each Redis call the auth and revoke paths make.
// Redis answers in well under a millisecond; one that drops packets would
// otherwise hold every agent and Gateway call, and every revoke, for the
// client's read timeout times its retries (api#304). A call that runs out
// reads as a miss, and the caller falls back to the database.
const cacheCallTimeout = 300 * time.Millisecond

func withCacheDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, cacheCallTimeout)
}

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
	beforeFill    func()
	afterWrite    func()
	beforeConfirm func()
	beforeClear   func()
	del           func(ctx context.Context, key string) error
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
		retryEvery:  100 * time.Millisecond,
	}
}

func (c *credCache) key(kind string, id uuid.UUID) string { return c.rdb.Key(kind, id.String()) }

func (c *credCache) read(ctx context.Context, id uuid.UUID) credCacheRead {
	if c.rdb == nil {
		return credCacheRead{}
	}
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	vals, err := c.rdb.Raw().MGet(cctx, c.key(c.hashKind, id), c.key(c.revokedKind, id), c.key(c.missKind, id)).Result()
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
	cctx, cancel := withCacheDeadline(ctx)
	wrote, err := fillScript.Run(cctx, c.rdb.Raw(),
		[]string{c.key(c.hashKind, id), c.key(c.revokedKind, id)},
		entry, c.hashTTL.Milliseconds()).Int()
	cancel()
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
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	return setTombstoneScript.Run(cctx, c.rdb.Raw(), []string{c.key(c.revokedKind, id)}, reason, c.revokedTTL.Milliseconds()).Err()
}

// quickTries spaces the synchronous attempts of ensureRevoked and
// ensureCleared.
var quickTries = []time.Duration{0, 20 * time.Millisecond, 100 * time.Millisecond}

// ensureRevoked runs after the database change. It writes the tombstone
// (a few quick tries) and drops the entry. When Redis won't take the
// tombstone, it keeps trying in the background for revokedTTL, the
// longest a stale entry could still be served once Redis is back, and
// returns ErrCredentialCacheUnconfirmed.
//
// blocked re-reads the database: true while the id should still be kept
// out. A revoke is final and passes nil. A disable passes a check, so a
// retry that outlives a later enable stops instead of shutting the
// Gateway out again (api#304).
func (c *credCache) ensureRevoked(ctx context.Context, id uuid.UUID, reason string, blocked func(context.Context) bool) error {
	if c.rdb == nil {
		return nil
	}
	for _, wait := range quickTries {
		time.Sleep(wait)
		if c.confirmRevoked(ctx, id, reason, blocked) {
			return nil
		}
	}
	go c.retryInBackground(func(ctx context.Context) bool {
		if blocked != nil && !blocked(ctx) {
			return true // enabled again since: nothing left to confirm
		}
		return c.confirmRevoked(ctx, id, reason, blocked)
	})
	return ErrCredentialCacheUnconfirmed
}

// confirmRevoked writes the tombstone and drops the entry. If the
// database stopped blocking the id while it wrote, it lifts the
// tombstone again (an enable that committed and cleared just before this
// write would otherwise be undone). Reports whether the tombstone write
// went through.
func (c *credCache) confirmRevoked(ctx context.Context, id uuid.UUID, reason string, blocked func(context.Context) bool) bool {
	if c.beforeConfirm != nil {
		c.beforeConfirm()
	}
	if c.markRevoked(ctx, id, reason) != nil {
		return false
	}
	c.invalidate(ctx, id)
	if blocked != nil && !blocked(ctx) {
		_ = c.clearRevoked(ctx, id)
	}
	return true
}

// ensureCleared runs after a Gateway is enabled. It lifts a "disabled"
// tombstone and drops the entry, which may still say "disabled". When
// Redis won't take both, it keeps trying in the background while the
// database still has the Gateway live, and returns
// ErrCredentialCacheUnconfirmed: until then the Gateway may still be
// refused, which is an availability cost only.
func (c *credCache) ensureCleared(ctx context.Context, id uuid.UUID, blocked func(context.Context) bool) error {
	if c.rdb == nil {
		return nil
	}
	for _, wait := range quickTries {
		time.Sleep(wait)
		if c.confirmCleared(ctx, id, blocked) {
			return nil
		}
	}
	go c.retryInBackground(func(ctx context.Context) bool {
		if blocked(ctx) {
			return true // disabled or revoked again since: leave it
		}
		return c.confirmCleared(ctx, id, blocked)
	})
	return ErrCredentialCacheUnconfirmed
}

// confirmCleared lifts the tombstone and drops the entry. If a disable
// committed meanwhile, it puts a "disabled" tombstone back (never over a
// "revoked" one). Reports whether both Redis calls went through.
func (c *credCache) confirmCleared(ctx context.Context, id uuid.UUID, blocked func(context.Context) bool) bool {
	if c.beforeClear != nil {
		c.beforeClear()
	}
	if c.clearRevoked(ctx, id) != nil || c.delKey(ctx, c.key(c.hashKind, id)) != nil {
		return false
	}
	if blocked(ctx) {
		_ = c.markRevoked(ctx, id, tombstoneDisabled)
	}
	return true
}

// retryInBackground calls attempt every retryEvery until it reports done
// or revokedTTL passes; by then any key it was correcting has expired.
func (c *credCache) retryInBackground(attempt func(context.Context) bool) {
	ctx, cancel := context.WithTimeout(context.Background(), c.revokedTTL)
	defer cancel()
	t := time.NewTicker(c.retryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if attempt(ctx) {
				return
			}
		}
	}
}

// clearRevoked drops a "disabled" tombstone. A "revoked" one stays.
func (c *credCache) clearRevoked(ctx context.Context, id uuid.UUID) error {
	if c.rdb == nil {
		return nil
	}
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	return clearDisabledScript.Run(cctx, c.rdb.Raw(), []string{c.key(c.revokedKind, id)}).Err()
}

func (c *credCache) markMissing(ctx context.Context, id uuid.UUID) {
	if c.rdb == nil {
		return
	}
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	_, _ = c.rdb.Raw().Set(cctx, c.key(c.missKind, id), "1", c.missingTTL).Result()
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
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	err := c.rdb.Raw().Del(cctx, key).Err()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	return err
}
