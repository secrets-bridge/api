package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// IdempotencyResult is returned by WithIdempotencyKey along with the
// caller's payload. ResultFromCache is true when a previous successful
// execution under the same key was replayed instead of running fn.
type IdempotencyResult[T any] struct {
	Value           T
	ResultFromCache bool
}

// ErrIdempotencyInFlight is returned when WithIdempotencyKey is called
// for a key that is currently being executed by another caller. The
// caller should not retry immediately — the in-flight execution will
// either complete and cache its result, or fail and release the slot.
var ErrIdempotencyInFlight = errors.New("runtime: idempotency key in flight")

// WithIdempotencyKey guarantees fn runs at most once per (key, ttl)
// window. The contract is:
//
//   - First caller acquires the slot, runs fn, and caches the result.
//   - Concurrent callers with the same key receive ErrIdempotencyInFlight.
//   - Subsequent callers (after fn completed) get the cached result
//     without running fn.
//
// CRITICAL: T must not be a secret value. The result is round-tripped
// through Redis as JSON; per CLAUDE.md hard rule §38 nothing in Redis
// may contain provider secret bytes. Use this for things like
// "did we already create sync_job X for request Y", not for secrets.
//
// This is the typed wrapper; ttl defaults to 1 hour if zero.
func WithIdempotencyKey[T any](
	ctx context.Context,
	c *Client,
	key string,
	ttl time.Duration,
	fn func(context.Context) (T, error),
) (IdempotencyResult[T], error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	slot, err := c.idempotencyAcquire(ctx, key, ttl)
	if err != nil {
		return IdempotencyResult[T]{}, err
	}

	switch slot.state {
	case idempotencyStateAcquired:
		// We own the slot — execute and cache.
		value, runErr := fn(ctx)
		if runErr != nil {
			// Release the slot so the next caller can retry without
			// waiting for the TTL to expire.
			_ = c.idempotencyAbort(ctx, key, slot.token)
			return IdempotencyResult[T]{}, runErr
		}
		if err := c.idempotencyComplete(ctx, key, slot.token, value, ttl); err != nil {
			return IdempotencyResult[T]{}, err
		}
		return IdempotencyResult[T]{Value: value, ResultFromCache: false}, nil

	case idempotencyStateCompleted:
		var value T
		if err := slot.decode(&value); err != nil {
			return IdempotencyResult[T]{}, fmt.Errorf("runtime: decode cached idempotency result: %w", err)
		}
		return IdempotencyResult[T]{Value: value, ResultFromCache: true}, nil

	default:
		return IdempotencyResult[T]{}, ErrIdempotencyInFlight
	}
}

// idempotencyState distinguishes the three possible outcomes of the
// Redis-side slot acquisition: we got it; someone else has it
// in-flight; the slot is already completed and we have the cached
// result.
type idempotencyState int

const (
	idempotencyStateInFlight idempotencyState = iota
	idempotencyStateAcquired
	idempotencyStateCompleted
)

type idempotencySlot struct {
	state idempotencyState
	token string // our random ownership token; only valid when state == Acquired
	raw   []byte // cached result body when state == Completed
}

// decode JSON-unmarshals the cached result body into dst.
func (s idempotencySlot) decode(dst any) error { return jsonDecode(s.raw, dst) }

// idempotencyAcquire executes the slot-acquisition state machine
// atomically via a small Lua script. The script understands three
// states:
//   - key does not exist        → set "INFLIGHT:<token>" with TTL; return ACQUIRED
//   - key starts with "INFLIGHT" → return INFLIGHT
//   - key starts with "DONE:"   → return DONE + payload
//
// Encoding the state inline in the value (vs. two separate keys) keeps
// the operation atomic without MULTI/EXEC overhead.
func (c *Client) idempotencyAcquire(ctx context.Context, key string, ttl time.Duration) (idempotencySlot, error) {
	tok, err := randomToken(16)
	if err != nil {
		return idempotencySlot{}, err
	}
	script := redis.NewScript(`
		local cur = redis.call("GET", KEYS[1])
		if cur == false or cur == nil then
			redis.call("SET", KEYS[1], "INFLIGHT:" .. ARGV[1], "PX", ARGV[2])
			return {"ACQUIRED"}
		end
		if string.sub(cur, 1, 9) == "INFLIGHT:" then
			return {"INFLIGHT"}
		end
		if string.sub(cur, 1, 5) == "DONE:" then
			return {"DONE", string.sub(cur, 6)}
		end
		return {"INFLIGHT"}
	`)
	raw, err := script.Run(ctx, c.rdb, []string{c.key("idem", key)}, tok, ttl.Milliseconds()).Result()
	if err != nil {
		return idempotencySlot{}, fmt.Errorf("runtime: idempotency acquire: %w", err)
	}
	arr, ok := raw.([]any)
	if !ok || len(arr) == 0 {
		return idempotencySlot{}, fmt.Errorf("runtime: idempotency: unexpected script response: %T", raw)
	}
	state, _ := arr[0].(string)
	switch state {
	case "ACQUIRED":
		return idempotencySlot{state: idempotencyStateAcquired, token: tok}, nil
	case "INFLIGHT":
		return idempotencySlot{state: idempotencyStateInFlight}, nil
	case "DONE":
		var payload []byte
		if len(arr) >= 2 {
			if s, ok := arr[1].(string); ok {
				payload = []byte(s)
			}
		}
		return idempotencySlot{state: idempotencyStateCompleted, raw: payload}, nil
	default:
		return idempotencySlot{}, fmt.Errorf("runtime: idempotency: unknown state %q", state)
	}
}

// idempotencyComplete swaps the INFLIGHT placeholder for the cached
// DONE result. The token guard prevents a stuck caller from overwriting
// a slot that was rotated to someone else via TTL expiry.
func (c *Client) idempotencyComplete(ctx context.Context, key, token string, value any, ttl time.Duration) error {
	payload, err := jsonEncode(value)
	if err != nil {
		return fmt.Errorf("runtime: encode idempotency result: %w", err)
	}
	script := redis.NewScript(`
		local cur = redis.call("GET", KEYS[1])
		if cur ~= "INFLIGHT:" .. ARGV[1] then
			return 0
		end
		redis.call("SET", KEYS[1], "DONE:" .. ARGV[2], "PX", ARGV[3])
		return 1
	`)
	_, err = script.Run(ctx, c.rdb,
		[]string{c.key("idem", key)},
		token, string(payload), ttl.Milliseconds(),
	).Result()
	if err != nil {
		return fmt.Errorf("runtime: idempotency complete: %w", err)
	}
	return nil
}

// idempotencyAbort releases the slot when fn errored. Token-guarded.
func (c *Client) idempotencyAbort(ctx context.Context, key, token string) error {
	script := redis.NewScript(`
		local cur = redis.call("GET", KEYS[1])
		if cur == "INFLIGHT:" .. ARGV[1] then
			redis.call("DEL", KEYS[1])
			return 1
		end
		return 0
	`)
	_, err := script.Run(ctx, c.rdb, []string{c.key("idem", key)}, token).Result()
	if err != nil {
		return fmt.Errorf("runtime: idempotency abort: %w", err)
	}
	return nil
}

// randomToken returns a hex-encoded random ID for slot ownership.
func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("runtime: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
