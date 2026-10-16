// TOTP attempt guard (api#191 M4, API-S-11).
//
// Two per-factor controls sit in front of every TOTP verification:
//
//  1. Lockout. After `threshold` attempts in a row without a success
//     the factor refuses every code, the correct one included, until
//     the lockout window has passed. The attempt is taken from the
//     budget before the code is checked, so parallel requests cannot
//     squeeze in extra guesses. A success resets the budget. Without
//     this the audit sent 300 wrong guesses through
//     /auth/mfa/challenge + /verify and the right code was still
//     accepted afterwards.
//
//  2. Step reuse. RFC 6238 §5.2: a verifier MUST NOT accept the same
//     code twice. The last accepted time step is stored per factor and
//     any code whose matched step is <= it is refused. With the ±1
//     step skew window one code was otherwise valid for ~90 seconds on
//     any number of challenges.
//
// State lives in Redis with a TTL, no schema change. Both checks are
// per-user auth controls, so a Redis error FAILS CLOSED: the attempt
// is refused with ErrMFAGuardUnavailable. That is deliberately the
// opposite of the per-IP limiters, which fail open (M5 decision).
//
// Lockout time is measured on the TOTP service clock (stored as an
// absolute "locked until"), so tests with a frozen clock are exact.
// The Redis TTL only garbage-collects idle state.

package services

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
)

const (
	// DefaultTOTPLockoutThreshold is the number of consecutive wrong
	// codes that lock a factor. Same number as the password lockout.
	DefaultTOTPLockoutThreshold = 5

	// DefaultTOTPLockoutDuration is how long a locked factor refuses
	// every code. Same window as the password lockout.
	DefaultTOTPLockoutDuration = 15 * time.Minute

	// totpUsedStepTTL keeps the last accepted step for as long as a
	// code from that step could still verify: the step itself plus
	// the ±1 skew on each side, plus one step of margin.
	totpUsedStepTTL = (2*totpSkewSteps + 2) * totpStepSecs * time.Second
)

var (
	// ErrTOTPLocked means the factor hit the consecutive-failure
	// threshold and is inside its lockout window.
	ErrTOTPLocked = errors.New("mfa/totp: factor locked after repeated failures")

	// ErrTOTPCodeReused means the code matched, but its time step was
	// already used (or an older one). Wraps ErrTOTPInvalidCode so
	// callers that only check for an invalid code still match.
	ErrTOTPCodeReused = fmt.Errorf("%w: code already used", ErrTOTPInvalidCode)

	// ErrMFAGuardUnavailable means the attempt guard could not read or
	// write its Redis state. The attempt is refused (fail closed).
	ErrMFAGuardUnavailable = errors.New("mfa: attempt guard unavailable")

	// ErrMFALocked is the verify-layer form of ErrTOTPLocked. The HTTP
	// layer maps it to 429.
	ErrMFALocked = errors.New("mfa/verify: factor temporarily locked")
)

// totpGuard holds the lockout + step-reuse state for TOTP factors.
type totpGuard struct {
	rdb       *runtime.Client
	threshold int
	lockFor   time.Duration
}

func newTOTPGuard(rdb *runtime.Client, threshold int, lockFor time.Duration) *totpGuard {
	if threshold <= 0 {
		threshold = DefaultTOTPLockoutThreshold
	}
	if lockFor <= 0 {
		lockFor = DefaultTOTPLockoutDuration
	}
	return &totpGuard{rdb: rdb, threshold: threshold, lockFor: lockFor}
}

func (g *totpGuard) failKey(factorID uuid.UUID) string {
	return g.rdb.Key("mfa:totp:fail", factorID.String())
}

func (g *totpGuard) stepKey(factorID uuid.UUID) string {
	return g.rdb.Key("mfa:totp:step", factorID.String())
}

// reserveAttemptScript takes one attempt out of the factor's budget
// BEFORE the code is checked, so parallel requests cannot run more than
// `threshold` guesses between two lockouts. The attempt that uses the
// last slot sets `until`; every later attempt is refused until then.
// An expired lock starts a fresh budget. A success deletes the hash.
// KEYS[1] fail hash; ARGV now_ms, threshold, lock_ms, ttl_ms.
// Returns -1 when locked, else the attempt number in this budget.
const reserveAttemptScript = `
local now = tonumber(ARGV[1])
local untilv = tonumber(redis.call('HGET', KEYS[1], 'until') or '0')
if untilv > now then
  return -1
end
if untilv ~= 0 then
  redis.call('HDEL', KEYS[1], 'until')
  redis.call('HSET', KEYS[1], 'n', 0)
end
local n = redis.call('HINCRBY', KEYS[1], 'n', 1)
if n >= tonumber(ARGV[2]) then
  redis.call('HSET', KEYS[1], 'until', now + tonumber(ARGV[3]))
end
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return n`

// reserveAttempt claims one verification attempt for the factor at
// now. Returns ErrTOTPLocked when the factor is locked. `last` is true
// when this attempt used the final slot: if it fails, the factor is
// now locked.
func (g *totpGuard) reserveAttempt(ctx context.Context, factorID uuid.UUID, now time.Time) (last bool, err error) {
	if g == nil || g.rdb == nil {
		return false, ErrMFAGuardUnavailable
	}
	// Idle state lives one lockout window past the lock itself.
	ttl := 2 * g.lockFor
	n, err := g.rdb.Raw().Eval(ctx, reserveAttemptScript, []string{g.failKey(factorID)},
		now.UnixMilli(), g.threshold, g.lockFor.Milliseconds(), ttl.Milliseconds(),
	).Int64()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrMFAGuardUnavailable, err)
	}
	if n < 0 {
		return false, ErrTOTPLocked
	}
	return n >= int64(g.threshold), nil
}

// clearFailures resets the attempt budget after a success.
func (g *totpGuard) clearFailures(ctx context.Context, factorID uuid.UUID) error {
	if g == nil || g.rdb == nil {
		return ErrMFAGuardUnavailable
	}
	if err := g.rdb.Raw().Del(ctx, g.failKey(factorID)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrMFAGuardUnavailable, err)
	}
	return nil
}

// claimStepScript stores ARGV[1] as the last used step unless the
// stored one is already >= it. Atomic, so two concurrent requests with
// the same code cannot both win. Returns 1 when claimed.
const claimStepScript = `
local cur = redis.call('GET', KEYS[1])
if cur and tonumber(cur) >= tonumber(ARGV[1]) then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1`

// claimStep marks `step` as used for the factor. Returns false when
// that step (or a later one) was already used.
func (g *totpGuard) claimStep(ctx context.Context, factorID uuid.UUID, step uint64) (bool, error) {
	if g == nil || g.rdb == nil {
		return false, ErrMFAGuardUnavailable
	}
	res, err := g.rdb.Raw().Eval(ctx, claimStepScript, []string{g.stepKey(factorID)},
		strconv.FormatUint(step, 10), totpUsedStepTTL.Milliseconds(),
	).Int64()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrMFAGuardUnavailable, err)
	}
	return res == 1, nil
}
