// Session service — owns the cookie-auth flow (architect Q2 + Q3 + Q8).
//
// Slice A2 scope: create sessions on successful login, validate them
// on every authenticated request, slide the idle TTL forward, revoke
// on logout. The plaintext cookie value is generated here, returned
// to the caller exactly ONCE, and hashed before persistence — same
// pattern as agents.SecretHash.
//
// Hard rules:
//   - Cookie value = 32 random bytes, base64url. Never logged. Never
//     stored in plaintext. SHA-256 is the on-disk shape.
//   - `Validate` runs sliding-window: every successful validation
//     pushes idle_expires_at forward by SessionPolicy.IdleTTL. The
//     absolute lifetime (`expires_at`) is immutable.
//   - Revocation is idempotent. Logging out twice doesn't error.

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// SessionPolicy controls the TTLs the session lifecycle obeys.
// Defaults match architect Q3 + Q6:
//   - IdleTTL      = 30 minutes (slides forward on every request)
//   - AbsoluteTTL  =  8 hours   (immutable from create time)
//   - StepUpTTL    = 15 minutes (`last_mfa_at` freshness window for
//                                Tier 2 operations: approve/reject/
//                                reveal/rotate/role-edit/provider-edit)
type SessionPolicy struct {
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	StepUpTTL   time.Duration
}

// DefaultSessionPolicy is what cmd/api wires.
func DefaultSessionPolicy() SessionPolicy {
	return SessionPolicy{
		IdleTTL:     30 * time.Minute,
		AbsoluteTTL: 8 * time.Hour,
		StepUpTTL:   15 * time.Minute,
	}
}

// SessionService coordinates the sessions repo + audit pipe.
type SessionService struct {
	sessions storage.SessionRepository
	audit    storage.AuditEventRepository
	policy   SessionPolicy
}

// NewSessionService binds the dependencies.
func NewSessionService(
	sessions storage.SessionRepository,
	audit storage.AuditEventRepository,
) *SessionService {
	return &SessionService{
		sessions: sessions,
		audit:    audit,
		policy:   DefaultSessionPolicy(),
	}
}

// WithPolicy overrides the default TTLs. Returns the receiver so
// wiring stays a one-liner.
func (s *SessionService) WithPolicy(p SessionPolicy) *SessionService {
	if p.IdleTTL > 0 && p.AbsoluteTTL > 0 {
		if p.StepUpTTL <= 0 {
			p.StepUpTTL = s.policy.StepUpTTL
		}
		s.policy = p
	}
	return s
}

// MarkMFA stamps last_mfa_at on a session. Called from the OIDC
// callback when the ID token's `amr` claim indicates a strong factor
// (mfa / otp / hwk / fido / ...). Safe to call repeatedly; idempotent
// at the user-visible level (the stamp moves forward).
func (s *SessionService) MarkMFA(ctx context.Context, sessionID uuid.UUID, at time.Time) error {
	if err := s.sessions.TouchLastMFA(ctx, sessionID, at); err != nil {
		return fmt.Errorf("services: touch last_mfa_at: %w", err)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "session:" + sessionID.String(),
		Action:   "session.mfa_stamped",
		Resource: "session:" + sessionID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"at": at.UTC().Format(time.RFC3339Nano)},
	})
	return nil
}

// HasFreshMFA reports whether the session's `last_mfa_at` is within
// the configured step-up window. Sessions with a nil last_mfa_at
// (local-admin sign-in, IdP without MFA) are NOT fresh.
func (s *SessionService) HasFreshMFA(session *storage.Session) bool {
	if session == nil || session.LastMFAAt == nil {
		return false
	}
	return time.Since(*session.LastMFAAt) <= s.policy.StepUpTTL
}

// StepUpMaxAge exposes the configured window in seconds for the
// WWW-Authenticate header.
func (s *SessionService) StepUpMaxAge() int {
	return int(s.policy.StepUpTTL.Seconds())
}

// SessionFromCookie returns the live session row associated with the
// cookie. Wraps Validate so callers that need the session pointer
// (e.g. the cookie auth middleware writing it into context) don't
// have to repeat the GET-by-hash work.
func (s *SessionService) SessionFromCookie(ctx context.Context, cookieValue string) (*storage.Session, error) {
	return s.Validate(ctx, cookieValue)
}

// Policy exposes the current TTLs for cookie-side wiring (cmd/api
// sets the Cookie's MaxAge from AbsoluteTTL).
func (s *SessionService) Policy() SessionPolicy { return s.policy }

// IssuedSession is what Login returns: the live row + the ONE-TIME
// plaintext cookie value the caller hands to the HTTP layer.
type IssuedSession struct {
	Session         *storage.Session
	CookieValue     string // base64url-encoded; returned ONCE
	AbsoluteExpiry  time.Time
}

// ErrSessionInvalid is the only validation failure exposed.
var ErrSessionInvalid = errors.New("services: session invalid")

// Issue creates a new session for `userID`. The cookie value is
// returned plaintext exactly once — callers must put it in the
// Set-Cookie response immediately and forget it.
func (s *SessionService) Issue(ctx context.Context, userID uuid.UUID, ip, userAgent string) (*IssuedSession, error) {
	cookie, hash, err := newSessionToken()
	if err != nil {
		return nil, fmt.Errorf("services: mint session token: %w", err)
	}
	now := time.Now().UTC()
	row := &storage.Session{
		UserID:        userID,
		TokenHash:     hash,
		ExpiresAt:     now.Add(s.policy.AbsoluteTTL),
		IdleExpiresAt: now.Add(s.policy.IdleTTL),
		IP:            ip,
		UserAgent:     userAgent,
	}
	if err := s.sessions.Create(ctx, row); err != nil {
		return nil, fmt.Errorf("services: persist session: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "session.create",
		Resource: "session:" + row.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"session_id":      row.ID.String(),
			"expires_at":      row.ExpiresAt.Format(time.RFC3339Nano),
			"idle_expires_at": row.IdleExpiresAt.Format(time.RFC3339Nano),
			"ip":              ip,
			"user_agent":      userAgent,
		},
	})

	return &IssuedSession{
		Session:        row,
		CookieValue:    cookie,
		AbsoluteExpiry: row.ExpiresAt,
	}, nil
}

// Validate looks up the cookie value, enforces revocation + both
// expiry checks, and slides the idle TTL forward on success.
//
// Failure modes (returned as `ErrSessionInvalid`):
//   - Empty / malformed cookie value
//   - No row matches the hash (cookie forged or session predates a
//     fresh deploy)
//   - `revoked_at` is set
//   - `expires_at` or `idle_expires_at` is in the past
//
// On success the returned `*Session` reflects the bumped idle TTL.
func (s *SessionService) Validate(ctx context.Context, cookieValue string) (*storage.Session, error) {
	if cookieValue == "" {
		return nil, ErrSessionInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookieValue)
	if err != nil || len(raw) != sessionTokenBytes {
		return nil, ErrSessionInvalid
	}
	digest := sha256.Sum256(raw)
	session, err := s.sessions.GetByTokenHash(ctx, digest[:])
	if err != nil {
		return nil, ErrSessionInvalid
	}
	// Constant-time confirmation that the hash matches the digest we
	// just computed. The DB lookup is exact-equality so this is a
	// belt-and-braces guard against a future repository change.
	if subtle.ConstantTimeCompare(session.TokenHash, digest[:]) != 1 {
		return nil, ErrSessionInvalid
	}
	now := time.Now().UTC()
	if session.RevokedAt != nil {
		return nil, ErrSessionInvalid
	}
	if !session.ExpiresAt.After(now) || !session.IdleExpiresAt.After(now) {
		return nil, ErrSessionInvalid
	}

	newIdle := now.Add(s.policy.IdleTTL)
	// Don't let the idle TTL slide past the absolute lifetime.
	if newIdle.After(session.ExpiresAt) {
		newIdle = session.ExpiresAt
	}
	if err := s.sessions.TouchIdleExpiry(ctx, session.ID, newIdle); err != nil {
		// Best-effort: the validation already succeeded; a Postgres
		// flake on the slide must not 401 the request. Audit and
		// continue.
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "user:" + session.UserID.String(),
			Action:   "session.touch_failed",
			Resource: "session:" + session.ID.String(),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{"error": err.Error()},
		})
	} else {
		session.IdleExpiresAt = newIdle
	}
	return session, nil
}

// Revoke marks the session referenced by the cookie value dead. The
// caller's HTTP layer is responsible for clearing the Set-Cookie
// header. Idempotent on already-revoked sessions.
func (s *SessionService) Revoke(ctx context.Context, cookieValue string) error {
	if cookieValue == "" {
		return nil // nothing to do, treat as success for logout idempotency
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookieValue)
	if err != nil || len(raw) != sessionTokenBytes {
		return nil // malformed cookie, nothing to revoke
	}
	digest := sha256.Sum256(raw)
	session, err := s.sessions.GetByTokenHash(ctx, digest[:])
	if err != nil {
		return nil // unknown session — already gone
	}
	if session.RevokedAt != nil {
		return nil // idempotent: already revoked, no audit duplicate
	}
	now := time.Now().UTC()
	if err := s.sessions.Revoke(ctx, session.ID, now); err != nil {
		return fmt.Errorf("services: revoke session: %w", err)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + session.UserID.String(),
		Action:   "session.revoke",
		Resource: "session:" + session.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"session_id": session.ID.String()},
	})
	return nil
}

// RevokeAllForUser marks every live session owned by `userID` dead.
// Returns the count of newly revoked sessions. Used by the OIDC
// back-channel logout (RFC 8417) endpoint and the future "force
// logout user" admin action.
func (s *SessionService) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int, error) {
	now := time.Now().UTC()
	n, err := s.sessions.RevokeAllForUser(ctx, userID, now)
	if err != nil {
		return 0, fmt.Errorf("services: revoke user sessions: %w", err)
	}
	if n > 0 {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "user:" + userID.String(),
			Action:   "session.revoke_all",
			Resource: "user:" + userID.String(),
			Status:   storage.AuditStatusSuccess,
			Metadata: map[string]any{"count": n},
		})
	}
	return n, nil
}

// SubjectFromCookie satisfies the `middleware.SessionLooker` interface.
// Returns the authenticated user's UUID string on success; surfaces
// `ErrSessionInvalid` on any failure mode so the middleware falls
// through to anonymous rather than 401-ing the request.
func (s *SessionService) SubjectFromCookie(ctx context.Context, cookieValue string) (string, error) {
	session, err := s.Validate(ctx, cookieValue)
	if err != nil {
		return "", err
	}
	return session.UserID.String(), nil
}

// --- token mint helpers ----------------------------------------------

const sessionTokenBytes = 32

// newSessionToken returns (base64url-plaintext, sha256-digest).
func newSessionToken() (string, []byte, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(b), digest[:], nil
}
