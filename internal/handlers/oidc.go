// OIDC HTTP layer — handles the browser-facing redirects and the
// IdP-facing callback + back-channel logout endpoints. Mounted under
// /api/v1/auth/oidc by cmd/api when SB_OIDC_ISSUER is set.
//
// Slice B routes:
//
//   GET  /auth/oidc/start            redirect to IdP authorize endpoint
//   GET  /auth/oidc/callback         handle the IdP redirect with code+state
//   POST /auth/oidc/logout           RP-initiated logout (revoke local + redirect)
//   POST /auth/oidc/backchannel      RFC 8417 back-channel logout
//
// The cookie-emission shape is shared with the local-admin /auth/login
// path — both go through SessionService.Issue + handlers.Auth's
// cookie helpers.

package handlers

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
)

// OIDC is the HTTP-side wrapper around OIDCService + the local
// session helpers from the Auth handler.
type OIDC struct {
	svc        *services.OIDCService
	sessions   *services.SessionService
	cookieMode CookieMode
}

// NewOIDC binds the handler.
func NewOIDC(svc *services.OIDCService, sessions *services.SessionService, mode CookieMode) *OIDC {
	if mode == "" {
		mode = CookieModeProd
	}
	return &OIDC{svc: svc, sessions: sessions, cookieMode: mode}
}

// Start handles GET /api/v1/auth/oidc/start. Generates fresh PKCE +
// state + nonce, persists them in Redis under the state key, and
// 302s the browser to the IdP's authorize endpoint.
//
// Query params:
//   - `return_to` — post-login destination (preserved across the
//     round-trip)
//   - `step_up=mfa` — Slice D. Adds `prompt=login&max_age=0&
//     acr_values=mfa` to the authorize call so the IdP re-prompts
//     for a strong second factor even when a SSO session is alive.
//     The SPA hits this path when a Tier 2 endpoint returned
//     `401 step_up_required`.
func (h *OIDC) Start(c fiber.Ctx) error {
	returnTo := strings.TrimSpace(c.Query("return_to"))
	stepUp := strings.TrimSpace(c.Query("step_up"))

	var opts services.StepUpOptions
	if stepUp == "mfa" {
		opts = services.StepUpOptions{
			Prompt:    "login",
			MaxAgeSet: true,
			MaxAge:    0,
			ACRValues: "mfa",
		}
	}

	authz, err := h.svc.StartAuthorizeWith(c.Context(), returnTo, opts)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "oidc start failed")
	}
	return c.Redirect().Status(fiber.StatusFound).To(authz.RedirectURL)
}

// Callback handles GET /api/v1/auth/oidc/callback. Validates the
// state + code, completes the exchange, JIT-provisions if needed,
// issues a server-side session, sets the cookie, and 302s to the
// caller's original return_to (or to "/" when none was supplied).
//
// Errors return a generic 401 to the browser; the audit log carries
// the specific failure mode.
func (h *OIDC) Callback(c fiber.Ctx) error {
	if errStr := strings.TrimSpace(c.Query("error")); errStr != "" {
		// The IdP rejected the authorize call (user cancelled, MFA
		// failure, etc.). Audit happens in the service when callback
		// reaches it; here just surface 401.
		return fiber.NewError(fiber.StatusUnauthorized, "oidc rejected: "+errStr)
	}
	state := strings.TrimSpace(c.Query("state"))
	code := strings.TrimSpace(c.Query("code"))
	result, err := h.svc.HandleCallback(c.Context(), state, code, c.IP(), c.Get("User-Agent"))
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "oidc callback failed")
	}
	h.setSessionCookie(c, result.Issued.CookieValue, result.Issued.AbsoluteExpiry)

	target := result.ReturnTo
	if target == "" {
		target = "/"
	}
	return c.Redirect().Status(fiber.StatusFound).To(target)
}

// Logout handles POST /api/v1/auth/oidc/logout. RP-initiated:
//
//  1. Revoke the local session (if the request carried the cookie).
//  2. Clear the cookie.
//  3. Redirect to the IdP's end_session_endpoint when discovery
//     exposed one; otherwise return 204.
func (h *OIDC) Logout(c fiber.Ctx) error {
	if h.sessions != nil {
		cookie := c.Cookies(middleware.SessionCookieName)
		if cookie != "" {
			_ = h.sessions.Revoke(c.Context(), cookie)
		}
	}
	h.clearSessionCookie(c)
	if endSession := h.svc.BuildEndSessionURL(""); endSession != "" {
		return c.Redirect().Status(fiber.StatusFound).To(endSession)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// BackchannelLogout handles POST /api/v1/auth/oidc/backchannel. IdP
// posts an application/x-www-form-urlencoded body with a
// `logout_token` parameter (RFC 8417).
//
// Response: 200 on success, 400 on shape failures, 401 on token
// verification failures, 500 on persistence failures.
func (h *OIDC) BackchannelLogout(c fiber.Ctx) error {
	logoutToken := strings.TrimSpace(c.FormValue("logout_token"))
	if logoutToken == "" {
		return fiber.NewError(fiber.StatusBadRequest, "logout_token required")
	}
	if err := h.svc.HandleBackchannelLogout(c.Context(), logoutToken); err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "logout_token rejected")
	}
	return c.SendStatus(fiber.StatusOK)
}

// --- cookie helpers (duplicated from Auth so we don't take a hard
// dependency on the *Auth pointer just to share two functions).

func (h *OIDC) setSessionCookie(c fiber.Ctx, value string, expires time.Time) {
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

func (h *OIDC) clearSessionCookie(c fiber.Ctx) {
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
