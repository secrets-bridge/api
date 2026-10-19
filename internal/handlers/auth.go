// Auth handler: the local-admin login endpoint behind
// /api/v1/auth/login and its sibling /auth/logout. A successful login
// sets the `sb_session` cookie, which is the only credential.

package handlers

import (
	"context"
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
)

// Auth is the HTTP-side wrapper around AuthService + the
// SessionService. Without a SessionService, login answers 503: there
// is no other credential to hand out.
type Auth struct {
	svc        *services.AuthService
	sessions   *services.SessionService
	cookieMode CookieMode
}

// CookieMode flips between dev (no Secure flag — required for
// http://localhost during local Vite dev) and prod. Production
// MUST set Secure=true; the SameSite=Strict + HttpOnly attributes
// are always on regardless of mode.
type CookieMode string

const (
	CookieModeDev  CookieMode = "dev"
	CookieModeProd CookieMode = "prod"
)

func NewAuth(svc *services.AuthService) *Auth { return &Auth{svc: svc, cookieMode: CookieModeProd} }

// WithSessions enables the cookie-auth path. Returns the receiver so
// the wiring stays a one-liner in `cmd/api/main.go`.
func (h *Auth) WithSessions(sessions *services.SessionService, mode CookieMode) *Auth {
	h.sessions = sessions
	if mode != "" {
		h.cookieMode = mode
	}
	return h
}

// LoginBody is the inbound JSON shape. `password` is value-bearing —
// the handler hands it straight to the service which zeroes the slice
// after bcrypt verification.
type LoginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is the outbound shape. There is no token: the HttpOnly
// session cookie set with it is the only credential (M1, api#191).
// ExpiresAt is the session's absolute expiry.
type LoginResponse struct {
	ExpiresAt string        `json:"expires_at"`
	User      LoginRespUser `json:"user"`
}

// LoginRespUser is the value-free projection returned with the
// session cookie.
type LoginRespUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Login handles POST /api/v1/auth/login. Public route, no auth
// middleware in front. Generic 401 on every failure shape; the audit
// log carries the specific error kind so triage stays possible
// without disclosing it on the wire.
//
// A successful login starts a server-side session and sets the
// `sb_session` cookie. The service records the sign-in as a success
// only after the session exists; if the session can't be started the
// answer is 500 and the audit row is a failure.
func (h *Auth) Login(c fiber.Ctx) error {
	var body LoginBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	password := []byte(body.Password)
	body.Password = "" // best-effort drop the original string ref

	// The session is the credential: without a session service the
	// login fails rather than falling back to anything else.
	if h.sessions == nil {
		zero(password)
		return fiber.NewError(fiber.StatusServiceUnavailable, "sign-in is not available")
	}

	var issued *services.IssuedSession
	start := func(ctx context.Context, userID uuid.UUID) error {
		s, err := h.sessions.Issue(ctx, userID, c.IP(), c.Get("User-Agent"))
		if err != nil {
			return err
		}
		issued = s
		return nil
	}
	result, err := h.svc.Login(c.Context(), body.Email, password, start)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}
		if errors.Is(err, services.ErrSessionStart) {
			logInternalError(c, "login: start session", err)
			return fiber.NewError(fiber.StatusInternalServerError, "could not start a session")
		}
		logInternalError(c, "login", err)
		return fiber.NewError(fiber.StatusInternalServerError, "sign-in failed")
	}
	h.setSessionCookie(c, issued.CookieValue, issued.AbsoluteExpiry)

	return c.JSON(LoginResponse{
		ExpiresAt: issued.AbsoluteExpiry.UTC().Format("2006-01-02T15:04:05Z"),
		User: LoginRespUser{
			ID:          result.User.ID.String(),
			Email:       result.User.Email,
			DisplayName: result.User.DisplayName,
		},
	})
}

// Logout handles POST /api/v1/auth/logout. Revokes the server-side
// session referenced by the `sb_session` cookie and clears the
// cookie. Idempotent: a logout with no cookie / expired cookie /
// already-revoked session is a 204, never a 4xx — clients should be
// able to "force logout" without inspecting the response.
func (h *Auth) Logout(c fiber.Ctx) error {
	if h.sessions != nil {
		cookie := c.Cookies(middleware.SessionCookieName)
		if cookie != "" {
			_ = h.sessions.Revoke(c.Context(), cookie)
		}
	}
	h.clearSessionCookie(c)
	return c.SendStatus(fiber.StatusNoContent)
}

// setSessionCookie writes the HttpOnly + SameSite=Strict cookie. The
// Secure flag depends on `cookieMode`: required in prod, omitted in
// dev so http://localhost:5173 (Vite) works without TLS.
func (h *Auth) setSessionCookie(c fiber.Ctx, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     middleware.SessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HTTPOnly: true,
		Secure:   h.cookieMode == CookieModeProd,
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}

// clearSessionCookie writes a Max-Age=0 cookie of the same name so
// the browser drops it. Same attribute set as the issue path so the
// clear is accepted by every conforming browser.
func (h *Auth) clearSessionCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     middleware.SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   h.cookieMode == CookieModeProd,
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}
