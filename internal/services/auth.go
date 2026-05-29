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
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// AuthService wires the local-users repo + JWT signer + audit pipe.
type AuthService struct {
	users     storage.LocalUserRepository
	roles     storage.RoleRepository
	userRoles storage.UserRoleRepository
	audit     storage.AuditEventRepository
	signer    *auth.Signer
	tokenTTL  time.Duration
}

// NewAuthService binds the dependencies.
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
	}
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
// success. Failure modes (unknown email / wrong password / disabled)
// all return `ErrInvalidCredentials` with the same generic message.
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

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, password); err != nil {
		s.auditFailure(ctx, email, "wrong_password")
		return nil, ErrInvalidCredentials
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
