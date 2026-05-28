package runtime

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimit checks whether a bucket has capacity within a sliding
// window. The implementation is a ZSET keyed by bucket name with
// member = unique request token, score = epoch micro-seconds; calls
// older than (now - window) are evicted before the cardinality check.
//
// Returns ok = true when the request is admitted; false when over the
// limit. The Retry hint estimates when the next slot will free up so
// callers can return a useful Retry-After header.
type RateLimit struct {
	Ok       bool
	Remaining int
	Retry    time.Duration
}

// AllowN evaluates the rate limit for bucket against (limit per window).
// The bucket name is typically "<actor>:<scope>", e.g. "user:alice:
// /api/v1/requests". Atomic — single Lua call per Allow.
func (c *Client) AllowN(ctx context.Context, bucket string, limit int, window time.Duration) (RateLimit, error) {
	if limit <= 0 {
		return RateLimit{Ok: false}, nil
	}
	tok, err := randomToken(8)
	if err != nil {
		return RateLimit{}, err
	}
	now := time.Now().UnixMicro()
	cutoff := now - window.Microseconds()

	script := redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local cutoff = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])
		local windowMs = tonumber(ARGV[4])
		local token = ARGV[5]

		redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)
		local count = redis.call("ZCARD", key)
		if count >= limit then
			-- Look up the oldest entry to compute retry-after.
			local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
			local retryAtUs = tonumber(oldest[2]) + (windowMs * 1000)
			return {0, count, retryAtUs - now}
		end
		redis.call("ZADD", key, now, token)
		-- Keep the key alive long enough to cover one full window after
		-- the most recent admission; auto-cleans up cold buckets.
		redis.call("PEXPIRE", key, windowMs * 2)
		return {1, count + 1, 0}
	`)
	raw, err := script.Run(ctx, c.rdb,
		[]string{c.key("rate", bucket)},
		now, cutoff, limit, window.Milliseconds(), tok,
	).Result()
	if err != nil {
		return RateLimit{}, fmt.Errorf("runtime: rate-limit: %w", err)
	}
	arr, ok := raw.([]any)
	if !ok || len(arr) < 3 {
		return RateLimit{}, fmt.Errorf("runtime: rate-limit: unexpected response %T", raw)
	}
	ok1 := toInt(arr[0]) == 1
	count := toInt(arr[1])
	retryUs := toInt(arr[2])

	return RateLimit{
		Ok:        ok1,
		Remaining: max(0, limit-count),
		Retry:     time.Duration(retryUs) * time.Microsecond,
	}, nil
}

// toInt coerces Redis script returns (int64, string) into int.
func toInt(v any) int {
	switch t := v.(type) {
	case int64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return int(n)
	default:
		return 0
	}
}
