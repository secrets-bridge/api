package services

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/secrets-bridge/api/internal/observability"
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
	attemptTimeout                  time.Duration // one background attempt, row read included

	pendingMu sync.Mutex
	pending   map[uuid.UUID]*pendingFix
	running   atomic.Int32 // reconcile goroutines alive

	// Test seams (export_test.go); nil in production.
	beforeFill    func()
	afterWrite    func()
	beforeConfirm func()
	beforeClear   func()
	failClear     func() bool
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
		rdb:            rdb,
		hashKind:       hashKind,
		revokedKind:    hashKind + "-revoked",
		missKind:       hashKind + "-missing",
		hashTTL:        hashTTL,
		revokedTTL:     2 * hashTTL,
		missingTTL:     30 * time.Second,
		retryEvery:     100 * time.Millisecond,
		attemptTimeout: 5 * time.Second,
		pending:        map[uuid.UUID]*pendingFix{},
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
	_ = countTimeout(err)
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
	_ = countTimeout(err)
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
	return countTimeout(setTombstoneScript.Run(cctx, c.rdb.Raw(), []string{c.key(c.revokedKind, id)}, reason, c.revokedTTL.Milliseconds()).Err())
}

// cacheState reads what the database says the cache should hold for an
// id: tombstoneRevoked or tombstoneDisabled to keep it out, "" for any
// other status. An error means the row couldn't be read.
type cacheState func(ctx context.Context) (string, error)

// finalState is the cacheState of a revoke. A revoke is final, so it
// never needs the database.
func finalState(reason string) cacheState {
	return func(context.Context) (string, error) { return reason, nil }
}

// quickTries spaces the synchronous attempts of ensureRevoked and
// ensureCleared.
var quickTries = []time.Duration{0, 20 * time.Millisecond, 100 * time.Millisecond}

// ensureRevoked runs after a revoke or disable commits. It writes the
// tombstone and drops the entry, a few quick tries. When it can't confirm
// that the cache matches the row, it hands the id to reconcileLater and
// returns ErrCredentialCacheUnconfirmed.
func (c *credCache) ensureRevoked(ctx context.Context, id uuid.UUID, reason string, state cacheState) error {
	if c.rdb == nil {
		return nil
	}
	for _, wait := range quickTries {
		time.Sleep(wait)
		if c.confirmRevoked(ctx, id, reason, state) {
			return nil
		}
	}
	c.reconcileLater(id, state)
	return ErrCredentialCacheUnconfirmed
}

// confirmRevoked writes the tombstone and drops the entry, then re-reads
// the row: if an enable committed meanwhile, it lifts the tombstone again,
// and if a revoke did, it writes "revoked" over "disabled".
// It reports true only when every Redis call went through and the row
// could be read; anything else is left to the retry (api#306).
func (c *credCache) confirmRevoked(ctx context.Context, id uuid.UUID, reason string, state cacheState) bool {
	if c.beforeConfirm != nil {
		c.beforeConfirm()
	}
	if c.markRevoked(ctx, id, reason) != nil {
		return false
	}
	c.invalidate(ctx, id)
	want, err := state(ctx)
	if err != nil {
		return false
	}
	switch {
	case want == "":
		if c.clearRevoked(ctx, id) != nil {
			return false
		}
	case want != reason:
		// Revoked since the disable committed: keep the reason right.
		if c.markRevoked(ctx, id, want) != nil {
			return false
		}
	}
	return true
}

// ensureCleared runs after a Gateway is enabled. It lifts a "disabled"
// tombstone and drops the entry, which may still say "disabled". When it
// can't confirm, it hands the id to reconcileLater and returns
// ErrCredentialCacheUnconfirmed: the Gateway may still be refused until
// then, which costs availability only.
func (c *credCache) ensureCleared(ctx context.Context, id uuid.UUID, state cacheState) error {
	if c.rdb == nil {
		return nil
	}
	for _, wait := range quickTries {
		time.Sleep(wait)
		if c.confirmCleared(ctx, id, state) {
			return nil
		}
	}
	c.reconcileLater(id, state)
	return ErrCredentialCacheUnconfirmed
}

// confirmCleared lifts the tombstone and drops the entry, then re-reads
// the row: if a disable committed meanwhile, it puts the tombstone back
// (never over a "revoked" one). Same rule for true as confirmRevoked.
func (c *credCache) confirmCleared(ctx context.Context, id uuid.UUID, state cacheState) bool {
	if c.beforeClear != nil {
		c.beforeClear()
	}
	if c.clearRevoked(ctx, id) != nil || c.delKey(ctx, c.key(c.hashKind, id)) != nil {
		return false
	}
	want, err := state(ctx)
	if err != nil {
		return false
	}
	if want != "" && c.markRevoked(ctx, id, want) != nil {
		return false
	}
	return true
}

// pendingFix is one id that reconcileLater is still bringing in line.
type pendingFix struct {
	state    cacheState
	deadline time.Time
	again    bool // a newer call came in while an attempt ran
}

// reconcileLater brings an id's cache keys in line with its row in the
// background. There is one goroutine per id: a repeated call swaps in its
// state and extends the deadline. Swapping is safe because a Gateway's
// state re-reads the row, so it ends up where the latest revoke, disable or
// enable left it, and a revoke is final. It also means a revoke's
// tombstone lands without the row read, even while Postgres is failing.
// An attempt reads the database only after Redis answers a PING, so an
// outage costs no queries. It gives up revokedTTL after the last call,
// when every key it could correct has expired.
func (c *credCache) reconcileLater(id uuid.UUID, state cacheState) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if p, ok := c.pending[id]; ok {
		p.state, p.deadline, p.again = state, time.Now().Add(c.revokedTTL), true
		return
	}
	p := &pendingFix{state: state, deadline: time.Now().Add(c.revokedTTL)}
	c.pending[id] = p
	go c.reconcile(id, p)
}

// maxReconcileWait caps the backoff between attempts that reached Redis
// and still failed.
const maxReconcileWait = 2 * time.Second

func (c *credCache) reconcile(id uuid.UUID, p *pendingFix) {
	c.running.Add(1)
	defer c.running.Add(-1)
	wait := c.retryEvery
	for {
		time.Sleep(wait)
		c.pendingMu.Lock()
		deadline := p.deadline
		if time.Now().After(deadline) {
			delete(c.pending, id)
			c.pendingMu.Unlock()
			return
		}
		state := p.state
		p.again = false
		c.pendingMu.Unlock()
		done, redisUp := c.reconcileOnce(id, state, deadline)
		if !done {
			// Redis down: keep the short tick, it costs no queries. Redis
			// up and the attempt still failed (the row unreadable, or
			// writes refused): back off, since each attempt reads the row.
			if redisUp {
				wait = min(2*wait, maxReconcileWait)
			} else {
				wait = c.retryEvery
			}
			continue
		}
		c.pendingMu.Lock()
		if p.again {
			c.pendingMu.Unlock()
			wait = c.retryEvery
			continue
		}
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return
	}
}

// reconcileOnce is one attempt, bounded by attemptTimeout and the
// pending deadline so a hung Postgres or Redis call can't stall the id's
// only retry (api#307). done is true once the keys match the row;
// redisUp is false when Redis didn't answer the PING.
func (c *credCache) reconcileOnce(id uuid.UUID, state cacheState, deadline time.Time) (done, redisUp bool) {
	ctx, cancel := context.WithDeadline(context.Background(), minTime(time.Now().Add(c.attemptTimeout), deadline))
	defer cancel()
	if c.ping(ctx) != nil {
		return false, false
	}
	want, err := state(ctx)
	if err != nil {
		return false, true
	}
	if want != "" {
		return c.confirmRevoked(ctx, id, want, state), true
	}
	return c.confirmCleared(ctx, id, state), true
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (c *credCache) ping(ctx context.Context) error {
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	return countTimeout(c.rdb.Raw().Ping(cctx).Err())
}

// countTimeout records a Redis call on the auth paths that ran out of its
// deadline (observability.RedisCallTimeouts) and returns err unchanged.
func countTimeout(err error) error {
	return observability.CountRedisTimeout(observability.RedisSiteAuthCache, err)
}

// clearRevoked drops a "disabled" tombstone. A "revoked" one stays.
func (c *credCache) clearRevoked(ctx context.Context, id uuid.UUID) error {
	if c.rdb == nil {
		return nil
	}
	if c.failClear != nil && c.failClear() {
		return errors.New("credcache: clear failed (test seam)")
	}
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	return countTimeout(clearDisabledScript.Run(cctx, c.rdb.Raw(), []string{c.key(c.revokedKind, id)}).Err())
}

func (c *credCache) markMissing(ctx context.Context, id uuid.UUID) {
	if c.rdb == nil {
		return
	}
	cctx, cancel := withCacheDeadline(ctx)
	defer cancel()
	_ = countTimeout(c.rdb.Raw().Set(cctx, c.key(c.missKind, id), "1", c.missingTTL).Err())
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
	err := countTimeout(c.rdb.Raw().Del(cctx, key).Err())
	if errors.Is(err, redis.Nil) {
		return nil
	}
	return err
}
