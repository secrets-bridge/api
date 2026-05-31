// Authentication service — the smallest possible local-admin login
// surface that exists to drop the LoginStub from the UI.
//
// Two responsibilities:
//
//  1. **Login**: email + password -> bcrypt verify -> issue JWT
//  2. **Bootstrap**: on api boot, when no local users exist AND the
//     operator has set the SB_BOOTSTRAP_ADMIN_EMAIL + _PASSWORD env
//     vars, create the seed admin user and bind it to the seed admin
//     role. Idempotent — re-running is a no-op once any user exists.
//
// The OIDC swap (api#26) replaces step 1; step 2 stays in place as
// the "you can always log in as a local admin if your IdP is down"
// break-glass posture.
//
// Hard rules:
//   - Bcrypt cost 12 (current OWASP-recommended floor for 2020s
//     hardware).
//   - Generic "invalid credentials" error on every failure shape
//     (unknown email, wrong password, disabled user) so a probe can't
//     enumerate. Audit log holds the specifics with error_kind.
//   - JWT is HS256 with a SB_JWT_SECRET-backed key. The secret must
//     be at least 32 bytes; the config layer fails loud if not.
//   - Plaintext password NEVER persisted; the input string is
//     overwritten with zeros after bcrypt.

package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// LockoutPolicy governs the account-lockout state machine. The
// architect-blessed defaults are 5 wrong-password attempts → 15 min
// lock; constructors that take no policy use these.
//
// The threshold counts CONSECUTIVE wrong-password attempts. A
// successful login resets the counter via ClearLockout.
type LockoutPolicy struct {
	Threshold int
	Duration  time.Duration
}

// DefaultLockoutPolicy is what cmd/api wires.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{Threshold: 5, Duration: 15 * time.Minute}
}

// AuthService wires the local-users repo + JWT signer + audit pipe.
type AuthService struct {
	users     storage.LocalUserRepository
	roles     storage.RoleRepository
	userRoles storage.UserRoleRepository
	audit     storage.AuditEventRepository
	signer    *auth.Signer
	tokenTTL  time.Duration
	lockout   LockoutPolicy
}

// NewAuthService binds the dependencies. Lockout policy defaults to
// `DefaultLockoutPolicy()`; override via `WithLockoutPolicy` for
// tests or operator overrides.
func NewAuthService(
	users storage.LocalUserRepository,
	roles storage.RoleRepository,
	userRoles storage.UserRoleRepository,
	audit storage.AuditEventRepository,
	signer *auth.Signer,
	tokenTTL time.Duration,
) *AuthService {
	return &AuthService{
		users:     users,
		roles:     roles,
		userRoles: userRoles,
		audit:     audit,
		signer:    signer,
		tokenTTL:  tokenTTL,
		lockout:   DefaultLockoutPolicy(),
	}
}

// WithLockoutPolicy overrides the default lockout policy. Mutates and
// returns the receiver so the wiring stays a one-liner.
func (s *AuthService) WithLockoutPolicy(p LockoutPolicy) *AuthService {
	if p.Threshold <= 0 || p.Duration <= 0 {
		return s
	}
	s.lockout = p
	return s
}

// ErrInvalidCredentials is the only login failure exposed to callers.
// The audit log captures the specifics (`error_kind`).
var ErrInvalidCredentials = errors.New("services: invalid credentials")

// LoginResult is what the handler returns to the UI on success.
type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	User      LoggedInUser
}

// LoggedInUser is the value-free projection of LocalUser used in
// the login response.
type LoggedInUser struct {
	ID          uuid.UUID
	Email       string
	DisplayName string
}

// Login verifies email + password and returns a signed JWT on
// success. Failure modes (unknown email / wrong password / disabled
// / locked) all return `ErrInvalidCredentials` with the same generic
// message — audit metadata carries the specific `error_kind` for
// triage without disclosure on the wire.
//
// Lockout state machine: each wrong-password failure bumps
// `local_users.failed_login_count`; reaching the configured threshold
// pins `locked_until = now + Duration`. While locked, even a correct
// password returns `ErrInvalidCredentials` and emits an
// `account_locked` audit event.
//
// Successful login emits a `BREAK_GLASS_LOGIN` audit event with
// `severity=CRITICAL` so operators monitoring for local-admin sign-ins
// (architect Q1) can wire that one event into an alert pipeline even
// before the OIDC swap lands.
//
// The `password` []byte is zeroed after the bcrypt compare regardless
// of outcome.
func (s *AuthService) Login(ctx context.Context, email string, password []byte) (*LoginResult, error) {
	defer zero(password)

	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || len(password) == 0 {
		s.auditFailure(ctx, email, "missing_fields")
		return nil, ErrInvalidCredentials
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		// Constant-time-ish branch: do a dummy bcrypt compare so an
		// attacker can't distinguish "unknown email" from "wrong
		// password" by request latency.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, password)
		s.auditFailure(ctx, email, "user_not_found")
		return nil, ErrInvalidCredentials
	}

	if user.Disabled {
		_ = bcrypt.CompareHashAndPassword(user.PasswordHash, password)
		s.auditFailure(ctx, email, "user_disabled")
		return nil, ErrInvalidCredentials
	}

	// Lockout check before the bcrypt compare. Burning bcrypt cost on
	// a locked account would let an attacker keep an account locked
	// indefinitely with negligible cost on their end.
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now().UTC()) {
		_ = bcrypt.CompareHashAndPassword(user.PasswordHash, password)
		s.auditLocked(ctx, user)
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, password); err != nil {
		s.recordFailedLogin(ctx, user)
		return nil, ErrInvalidCredentials
	}

	// Clear the counter + any stale lock — happy path resets state.
	if user.FailedLoginCount > 0 || user.LockedUntil != nil {
		if clearErr := s.users.ClearLockout(ctx, user.ID); clearErr != nil {
			// Don't fail the login because we couldn't reset state —
			// audit and continue. The next failed attempt will simply
			// see an over-threshold counter and re-lock immediately.
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:    "user:" + user.ID.String(),
				Action:   "auth.lockout.clear_failed",
				Resource: "user:" + user.ID.String(),
				Status:   storage.AuditStatusFailure,
				Metadata: map[string]any{"error": clearErr.Error()},
			})
		}
	}

	claims := auth.Claims{
		Subject: user.ID.String(),
		Email:   user.Email,
		Name:    user.DisplayName,
	}
	token, expires, err := s.signer.SignToken(claims, s.tokenTTL)
	if err != nil {
		return nil, fmt.Errorf("services: sign token: %w", err)
	}

	s.auditSuccess(ctx, user)
	s.auditBreakGlass(ctx, user)

	return &LoginResult{
		Token:     token,
		ExpiresAt: expires,
		User: LoggedInUser{
			ID:          user.ID,
			Email:       user.Email,
			DisplayName: user.DisplayName,
		},
	}, nil
}

// recordFailedLogin atomically increments the wrong-password counter
// and pins the account when the threshold is crossed. Errors are
// audited but never bubbled — a Postgres flake must not silently
// permit unbounded retries, but it also must not 5xx a wrong-password
// path which is the most common failure on the login surface.
func (s *AuthService) recordFailedLogin(ctx context.Context, user *storage.LocalUser) {
	n, err := s.users.IncrementFailedLogins(ctx, user.ID)
	if err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "anonymous",
			Action:   "auth.login",
			Resource: "user:" + user.ID.String(),
			Status:   storage.AuditStatusDenied,
			Metadata: map[string]any{
				"error_kind":     "wrong_password",
				"increment_err":  err.Error(),
				"email_length":   len(user.Email),
				"user_id_redact": user.ID.String(),
			},
		})
		return
	}
	s.auditFailureWithCount(ctx, user, "wrong_password", n)
	if n >= s.lockout.Threshold {
		until := time.Now().UTC().Add(s.lockout.Duration)
		if lockErr := s.users.Lock(ctx, user.ID, until); lockErr != nil {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:    "anonymous",
				Action:   "auth.lockout.apply_failed",
				Resource: "user:" + user.ID.String(),
				Status:   storage.AuditStatusFailure,
				Metadata: map[string]any{
					"error":              lockErr.Error(),
					"failed_login_count": n,
				},
			})
			return
		}
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "anonymous",
			Action:   "auth.lockout.applied",
			Resource: "user:" + user.ID.String(),
			Status:   storage.AuditStatusDenied,
			Metadata: map[string]any{
				"failed_login_count": n,
				"locked_until":       until.Format(time.RFC3339Nano),
				"threshold":          s.lockout.Threshold,
				"duration_seconds":   int(s.lockout.Duration.Seconds()),
			},
		})
	}
}

// BootstrapLocalAdmin creates the seed admin user if and only if NO
// local users exist yet. Idempotent — on a second boot the count is
// nonzero and the function no-ops.
//
// After creating the row, the user is bound to the seed `admin` role
// via user_roles (global scope) so they can immediately drive every
// admin endpoint.
//
// Returns the created user ID (or empty when no user was created).
func (s *AuthService) BootstrapLocalAdmin(ctx context.Context, email, password string) (string, error) {
	if email == "" || password == "" {
		return "", nil
	}
	n, err := s.users.Count(ctx)
	if err != nil {
		return "", fmt.Errorf("services: count users: %w", err)
	}
	if n > 0 {
		return "", nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("services: hash password: %w", err)
	}

	user := &storage.LocalUser{
		Email:        strings.ToLower(strings.TrimSpace(email)),
		PasswordHash: hash,
		DisplayName:  "Admin",
	}
	if err := s.users.Create(ctx, user); err != nil {
		return "", fmt.Errorf("services: create admin: %w", err)
	}

	adminRole, err := s.roles.GetByName(ctx, "admin")
	if err != nil {
		return user.ID.String(), fmt.Errorf("services: lookup admin role: %w", err)
	}
	grant := &storage.UserRole{
		UserID: user.ID.String(),
		RoleID: adminRole.ID,
		Scope:  map[string]any{},
	}
	if err := s.userRoles.Grant(ctx, grant); err != nil {
		return user.ID.String(), fmt.Errorf("services: grant admin role: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "system:bootstrap",
		Action:   "auth.bootstrap_admin",
		Resource: "user:" + user.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"email": user.Email},
	})

	return user.ID.String(), nil
}

// DevSeededUser is the value-free projection the dev seeder returns
// to main.go so it can print a one-time WARN block with the seeded
// credentials.
type DevSeededUser struct {
	Email    string
	Role     string
	Password string
}

// BootstrapDevUsers creates three seed users — admin, approver,
// requester — bound to the matching system roles, when AND ONLY WHEN
// `local_users` is empty. Idempotent: a second call with any user
// already present returns an empty slice and `nil`.
//
// `sharedPassword` is optional. When empty, the seeder generates a
// distinct random password per user; the caller is expected to log
// these ONCE at WARN level so the operator can capture them from the
// boot output. When non-empty, all three users get the same password
// (typical UAT pattern — operator sets one env var).
//
// This step runs only when SB_ENV=dev. main.go gates the call; the
// service-layer function itself does not re-check, so tests can
// exercise the seeding logic without depending on env vars.
func (s *AuthService) BootstrapDevUsers(ctx context.Context, sharedPassword string) ([]DevSeededUser, error) {
	n, err := s.users.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("services: count users: %w", err)
	}
	if n > 0 {
		return nil, nil
	}

	specs := []struct {
		email       string
		displayName string
		role        string
	}{
		{"admin@secrets-bridge.dev", "Admin", "admin"},
		{"approver@secrets-bridge.dev", "Approver", "approver"},
		{"requester@secrets-bridge.dev", "Requester", "developer"},
	}

	created := make([]DevSeededUser, 0, len(specs))
	for _, spec := range specs {
		password := sharedPassword
		if password == "" {
			password, err = randomDevPassword()
			if err != nil {
				return nil, fmt.Errorf("services: generate dev password: %w", err)
			}
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			return nil, fmt.Errorf("services: hash password for %s: %w", spec.email, err)
		}

		user := &storage.LocalUser{
			Email:        spec.email,
			PasswordHash: hash,
			DisplayName:  spec.displayName,
		}
		if err := s.users.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("services: create %s: %w", spec.email, err)
		}

		role, err := s.roles.GetByName(ctx, spec.role)
		if err != nil {
			return nil, fmt.Errorf("services: lookup role %q for %s: %w", spec.role, spec.email, err)
		}
		grant := &storage.UserRole{
			UserID: user.ID.String(),
			RoleID: role.ID,
			Scope:  map[string]any{},
		}
		if err := s.userRoles.Grant(ctx, grant); err != nil {
			return nil, fmt.Errorf("services: grant role %q to %s: %w", spec.role, spec.email, err)
		}

		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "system:bootstrap",
			Action:   "auth.bootstrap_dev_user",
			Resource: "user:" + user.ID.String(),
			Status:   storage.AuditStatusSuccess,
			Metadata: map[string]any{
				"email": user.Email,
				"role":  spec.role,
			},
		})

		created = append(created, DevSeededUser{
			Email:    user.Email,
			Role:     spec.role,
			Password: password,
		})
	}

	return created, nil
}

// randomDevPassword generates a 24-byte random URL-safe password
// (~32 base64url characters). Used by BootstrapDevUsers when the
// operator hasn't pinned one via SB_DEV_SEED_PASSWORD.
func randomDevPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// --- audit helpers --------------------------------------------------

func (s *AuthService) auditSuccess(ctx context.Context, u *storage.LocalUser) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + u.ID.String(),
		Action:   "auth.login",
		Resource: "user:" + u.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"email": u.Email},
	})
}

func (s *AuthService) auditFailure(ctx context.Context, email, kind string) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		// We deliberately don't echo the supplied email into the
		// `actor` field — an attacker could otherwise fill the audit
		// table with noise that looks like real user activity.
		Actor:    "anonymous",
		Action:   "auth.login",
		Resource: "auth:login",
		Status:   storage.AuditStatusDenied,
		Metadata: map[string]any{
			"error_kind":   kind,
			"email_length": len(email),
		},
	})
}

func (s *AuthService) auditFailureWithCount(ctx context.Context, u *storage.LocalUser, kind string, count int) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "anonymous",
		Action:   "auth.login",
		Resource: "user:" + u.ID.String(),
		Status:   storage.AuditStatusDenied,
		Metadata: map[string]any{
			"error_kind":         kind,
			"failed_login_count": count,
		},
	})
}

func (s *AuthService) auditLocked(ctx context.Context, u *storage.LocalUser) {
	var until string
	if u.LockedUntil != nil {
		until = u.LockedUntil.UTC().Format(time.RFC3339Nano)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "anonymous",
		Action:   "auth.login",
		Resource: "user:" + u.ID.String(),
		Status:   storage.AuditStatusDenied,
		Metadata: map[string]any{
			"error_kind":   "account_locked",
			"locked_until": until,
		},
	})
}

// auditBreakGlass emits the architect-mandated `BREAK_GLASS_LOGIN`
// event (Q1) on every successful local sign-in. The
// `severity=CRITICAL` metadata field lets log pipelines route this
// stream into an alert without having to grep for the action string.
//
// Once OIDC lands (Slice B) this fires only when the local-admin
// fallback path is used; right now every successful login flows
// through this same surface, so every login is by definition
// break-glass relative to the eventual OIDC primary.
func (s *AuthService) auditBreakGlass(ctx context.Context, u *storage.LocalUser) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + u.ID.String(),
		Action:   "BREAK_GLASS_LOGIN",
		Resource: "user:" + u.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"severity": "CRITICAL",
			"path":     "local",
			"email":    u.Email,
		},
	})
}

// dummyBcryptHash is a bcrypt hash for an unguessable random string —
// it exists so the "user not found" path still pays bcrypt cost,
// hiding email enumeration via timing.
var dummyBcryptHash = mustGenerateDummyHash()

func mustGenerateDummyHash() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy-bcrypt-anti-enumeration-target"), 12)
	if err != nil {
		panic(fmt.Errorf("services: dummy bcrypt: %w", err))
	}
	return h
}

// SubjectFromToken is a thin pass-through to `Signer.VerifyToken`
// returning just the `sub` claim. Middleware uses this to extract the
// user id without exposing the full claims struct outside this
// package.
func (s *AuthService) SubjectFromToken(token string) (string, error) {
	if s.signer == nil {
		return "", auth.ErrInvalidToken
	}
	claims, err := s.signer.VerifyToken(token)
	if err != nil {
		return "", err
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		// Sub MUST be a UUID for local users; OIDC may relax this
		// later but the field stays opaque to the rest of the
		// platform either way.
		return "", auth.ErrInvalidToken
	}
	return claims.Subject, nil
}

// Constant-time helper used by other auth flows; exposed here to keep
// the import surface tidy.
var _ = subtle.ConstantTimeCompare
