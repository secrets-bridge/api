// Package runtime will hold the Redis client and short-lived
// coordination primitives used by the Control Plane.
//
// Per BRD §10.1 and FR-15, this package will own: idempotency helpers,
// distributed locks (with lease + renewal), rate limiters, pub/sub
// primitives for worker notifications, and the agent heartbeat cache.
//
// CRITICAL: Redis is a Control Plane runtime dependency only. No
// secret values may be written to Redis (keys, values, or pub/sub
// payloads). Agents must not import this package — CI enforces it.
//
// Public surface of this package is importable by `worker`. `agent`
// and `controller` must never import it.
//
// Scaffold placeholder; concrete types land with secrets-bridge/api#3.
package runtime
