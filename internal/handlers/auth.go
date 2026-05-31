// Auth handler — exposes the local-admin login endpoint behind
// /api/v1/auth/login. Slice A2 adds a sibling /auth/logout endpoint
// and a Set-Cookie path so the SPA can drop JWT-in-sessionStorage.

package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
)

// Auth is the HTTP-side wrapper around AuthService + the optional
// SessionService. When `sessions` is nil the JWT-only path stays in
// effect (test harnesses keep working unchanged).
type Auth struct {
	svc         *services.AuthService
	sessions    *services.SessionService
	cookieMode  CookieMode
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

// LoginResponse is the outbound shape. The UI persists the token in
// memory only (see ui src/auth/AuthContext.tsx); never localStorage.
type LoginResponse struct {
	Token     string       `json:"token"`
	ExpiresAt string       `json:"expires_at"`
	User      LoginRespUser `json:"user"`
}

// LoginRespUser is the value-free projection returned alongside the
// token.
type LoginRespUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Login handles POST /api/v1/auth/login. Public route — no auth
// middleware in front. Generic 401 on every failure shape; the audit
// log carries the specific error kind so triage stays possible
// without disclosing it on the wire.
//
// When the SessionService is wired (Slice A2), a successful login
// ALSO mints a server-side session and sets the `sb_session` cookie.
// The JWT in the response body stays for backwards compatibility —
// the SPA flips to cookie-only in Slice C, after which we drop the
// token field.
func (h *Auth) Login(c fiber.Ctx) error {
	var body LoginBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	password := []byte(body.Password)
	body.Password = "" // best-effort drop the original string ref

	result, err := h.svc.Login(c.Context(), body.Email, password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if h.sessions != nil {
		issued, err := h.sessions.Issue(c.Context(), result.User.ID, c.IP(), c.Get("User-Agent"))
		if err != nil {
			// Session mint failed but the user proved their credentials.
			// Don't refuse the login — fall back to the JWT-only shape
			// the UI already handles. Audit will carry the failure.
		} else {
			h.setSessionCookie(c, issued.CookieValue, issued.AbsoluteExpiry)
		}
	}

	return c.JSON(LoginResponse{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
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

// Compile-time confirmation that uuid is consumed (kept for the
// session-id projection we'll add when the /auth/sessions admin
// endpoint lands in a follow-up).
var _ = uuid.Nil
