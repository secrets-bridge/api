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
//
// `return_to` is reduced to a same-origin relative path (anything else
// becomes "/") before it is stored. The state value is also set in a
// short-lived HttpOnly cookie that Callback requires, so a callback
// URL started in another browser can't sign this one in.
func (h *OIDC) Start(c fiber.Ctx) error {
	returnTo := services.SafeReturnTo(strings.TrimSpace(c.Query("return_to")))
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
	h.setStateCookie(c, authz.State)
	return c.Redirect().Status(fiber.StatusFound).To(authz.RedirectURL)
}

// Callback handles GET /api/v1/auth/oidc/callback. Validates the
// state + code, completes the exchange, JIT-provisions if needed,
// issues a server-side session, sets the cookie, and 302s to the
// caller's original return_to (or to "/" when none was supplied).
//
// The state query param must match the state cookie set by Start;
// the cookie is cleared on every callback, success or not.
//
// Errors return a generic 401 to the browser; the audit log carries
// the specific failure mode.
func (h *OIDC) Callback(c fiber.Ctx) error {
	boundState := c.Cookies(OIDCStateCookieName)
	h.clearStateCookie(c)
	if errStr := strings.TrimSpace(c.Query("error")); errStr != "" {
		// The IdP rejected the authorize call (user cancelled, MFA
		// failure, etc.). Audit happens in the service when callback
		// reaches it; here just surface 401.
		return fiber.NewError(fiber.StatusUnauthorized, "oidc rejected: "+errStr)
	}
	state := strings.TrimSpace(c.Query("state"))
	code := strings.TrimSpace(c.Query("code"))
	result, err := h.svc.HandleCallback(c.Context(), state, boundState, code, c.IP(), c.Get("User-Agent"))
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "oidc callback failed")
	}
	h.setSessionCookie(c, result.Issued.CookieValue, result.Issued.AbsoluteExpiry)

	return c.Redirect().Status(fiber.StatusFound).To(services.SafeReturnTo(result.ReturnTo))
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

// OIDCStateCookieName carries the OIDC `state` from /start to
// /callback so the callback can prove it was started by the same
// browser (API-N-08, login CSRF).
const OIDCStateCookieName = "sb_oidc_state"

// setStateCookie binds the authorize state to this browser. SameSite
// is Lax, not Strict: the IdP sends the browser back with a
// cross-site top-level GET, which Strict would strip. Scoped to the
// callback path and to the state TTL; Secure follows the session
// cookie (off only for SB_ENV=dev).
func (h *OIDC) setStateCookie(c fiber.Ctx, state string) {
	ttl := h.svc.StateTTL()
	c.Cookie(&fiber.Cookie{
		Name:     OIDCStateCookieName,
		Value:    state,
		Path:     h.svc.StateCookiePath(),
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HTTPOnly: true,
		Secure:   h.cookieMode == CookieModeProd,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

func (h *OIDC) clearStateCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     OIDCStateCookieName,
		Value:    "",
		Path:     h.svc.StateCookiePath(),
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   h.cookieMode == CookieModeProd,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
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
