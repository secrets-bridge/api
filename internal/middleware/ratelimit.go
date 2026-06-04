// Rate-limit middleware. Slim Fiber wrapper around runtime.Client's
// sliding-window ZSET limiter (pkg/runtime/ratelimit.go). The bucket
// key is per-actor: per-IP for unauthenticated paths (/auth/login,
// /auth/oidc/callback), per-agent for /agents/:id/heartbeat, per-user
// for the wrap retrieval path.
//
// Limits per architect's Q7 decision (see project_secrets_bridge_resume_state.md),
// adjusted for shared-NAT environments (Iraqi ISPs put many users
// behind one CGNAT public IP — a strict per-IP cap would lock out
// every legitimate user behind the same egress):
//
//   - login        30 /  60s per-IP    (anti-scan; per-account lockout
//                                       in Postgres handles brute force)
//   - callback     60 /  60s per-IP    (anti-scan; auth code is single-use)
//   - heartbeat     6 /  60s per-agent (per-agent — NAT-safe by definition)
//   - wrap         20 /  60s per-user  (per-user — NAT-safe by definition)
//
// Per-account brute force is defended at the AuthService layer via
// `LockoutPolicy` (5 wrong passwords → 15 min lock, durably in
// Postgres). That layer is IP-independent, so an attacker can't
// circumvent it by rotating source IPs; legitimate users behind a
// shared NAT aren't penalised by other users' attempts.
//
// Posture: fail OPEN on Redis errors. Locking real users out because a
// runtime dependency is degraded would be worse than briefly relaxing
// the limiter. Per-event slog WARN keeps the degradation visible.

package middleware

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
)

// BucketFunc derives the bucket key from the inbound request. Returns
// (key, true) to apply the limit; (_, false) to skip — useful for
// endpoints where the actor identity is genuinely unresolvable (e.g.
// the wrap retrieval path before the temporary `user_id` query stub
// is supplied).
type BucketFunc func(c fiber.Ctx) (string, bool)

// RateLimitConfig describes one bucket.
type RateLimitConfig struct {
	// Name prefixes the bucket key in Redis, e.g. "auth:login".
	// Surfaces in `redis-cli KEYS 'secrets-bridge:rate:<name>:*'`.
	Name string
	// Bucket derives the per-actor identifier appended after Name.
	Bucket BucketFunc
	// Limit is the maximum admissions per Window.
	Limit int
	// Window is the sliding-window duration.
	Window time.Duration
}

// RateLimit returns a Fiber middleware that admits or rejects requests
// based on the configured bucket. On admission, the request flows
// through. On rejection, the middleware returns 429 with a
// Retry-After header derived from the limiter's hint.
//
// `rdb` may be nil — useful in unit tests; the middleware degrades to
// a pass-through when no client is wired.
func RateLimit(rdb *runtime.Client, logger *slog.Logger, cfg RateLimitConfig) fiber.Handler {
	if cfg.Limit <= 0 || cfg.Window <= 0 {
		// Mis-config: the safest posture is to pass-through. The boot-time
		// wiring should have caught this; we don't want to wedge a route
		// because someone forgot to set a limit.
		return func(c fiber.Ctx) error { return c.Next() }
	}
	return func(c fiber.Ctx) error {
		if rdb == nil {
			return c.Next()
		}
		key, ok := cfg.Bucket(c)
		if !ok || key == "" {
			return c.Next()
		}
		fullBucket := cfg.Name + ":" + key
		rl, err := rdb.AllowN(c.Context(), fullBucket, cfg.Limit, cfg.Window)
		if err != nil {
			// Fail open. Log so operators see the degradation; never
			// translate a Redis blip into 5xx for legit traffic.
			if logger != nil {
				logger.Warn("rate-limit redis error, failing open",
					"bucket", cfg.Name, "error", err)
			}
			return c.Next()
		}
		if !rl.Ok {
			retryAfter := int(rl.Retry.Round(time.Second).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			c.Set("Retry-After", strconv.Itoa(retryAfter))
			return fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded")
		}
		return c.Next()
	}
}

// --- Bucket helpers --------------------------------------------------

// ByIP keys the bucket on the request's client IP, honouring Fiber's
// trusted-proxy resolution (X-Forwarded-For). Suitable for endpoints
// without an authenticated identity: /auth/login, /auth/oidc/callback.
func ByIP() BucketFunc {
	return func(c fiber.Ctx) (string, bool) {
		ip := c.IP()
		if ip == "" {
			return "", false
		}
		return ip, true
	}
}

// ByPathAgentID keys the bucket on the `:id` URL parameter parsed as
// a UUID. Used by the /agents/:id/heartbeat path BEFORE the AgentAuth
// middleware so we can shed spammers without paying the secret-compare
// cost. UUID parsing keeps the key shape stable and rejects garbage.
func ByPathAgentID() BucketFunc {
	return func(c fiber.Ctx) (string, bool) {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return "", false
		}
		return id.String(), true
	}
}

// ByQueryUserID keys the bucket on a `user_id` query param. Used by
// the user-bound wrap retrieval path which carries identity in a
// stub-auth query param until OIDC + a real session middleware land
// (architect's A2 slice). When the param is absent we fall back to
// per-IP so anonymous probing is still constrained.
func ByQueryUserID() BucketFunc {
	return func(c fiber.Ctx) (string, bool) {
		u := c.Query("user_id")
		if u == "" {
			ip := c.IP()
			if ip == "" {
				return "", false
			}
			return "anon:" + ip, true
		}
		return "user:" + u, true
	}
}

