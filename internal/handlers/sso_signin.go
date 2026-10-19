// Package handlers, sso_signin.go: signing in with Google configured from
// the console, connecting it to an account, and testing a provider
// (api#267 part 2).
//
//	GET    /auth/providers              public: sign-in options for the login page
//	GET    /auth/sso/:type/start        public: begin a sign-in
//	GET    /auth/sso/:type/callback     public: Google comes back here
//	POST   /auth/sso/:type/connect      signed in + fresh second factor: begin Connect Google
//	POST   /auth/sso/:type/finish       signed in: redeem a Connect or Test ticket
//	POST   /sso/providers/:id/test      auth.sso.edit + fresh second factor: begin a test
//	GET    /users/me/identities         signed in: connected accounts
//	DELETE /users/me/identities/:type   signed in + fresh second factor: disconnect,
//	                                    unless it created the account (409 identity_required)
//
// A refused sign-in always lands on the same page, /login?error=sso,
// whatever the reason, so it can't tell an outsider which emails have
// accounts; the reason goes to the audit log. Connect and Test come back
// with a one-time ticket in the URL fragment (never sent to a server or
// in a Referer), which the console redeems on the session that started
// them.
package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// SSOStateCookieName binds a Google round trip to the browser that
// started it.
const SSOStateCookieName = "sb_sso_state"

const (
	ssoStateCookiePath = "/api/v1/auth/sso/"
	ssoRefusedPage     = "/login?error=sso"
)

// SSOSignIn serves the sign-in routes.
type SSOSignIn struct {
	svc        *services.SSOSignIn
	config     *services.SSOService
	envOIDC    bool
	cookieMode CookieMode
}

// NewSSOSignIn binds the handler. envOIDC lists the env-var provider on
// the login page as well.
func NewSSOSignIn(svc *services.SSOSignIn, config *services.SSOService, envOIDC bool, mode CookieMode) *SSOSignIn {
	return &SSOSignIn{svc: svc, config: config, envOIDC: envOIDC, cookieMode: mode}
}

type providersResponse struct {
	Providers []services.SSOListedProvider `json:"providers"`
}

// Providers handles GET /auth/providers.
func (h *SSOSignIn) Providers(c fiber.Ctx) error {
	out, err := h.svc.Enabled(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not list sign-in options")
	}
	if h.envOIDC {
		out = append(out, services.SSOListedProvider{Type: "oidc", DisplayName: "Single sign-on", StartURL: "/api/v1/auth/oidc/start"})
	}
	return c.JSON(providersResponse{Providers: out})
}

// Start handles GET /auth/sso/:type/start.
func (h *SSOSignIn) Start(c fiber.Ctx) error {
	typ := c.Params("type")
	start, err := h.svc.Start(c.Context(), typ, services.SSOPurposeSignIn, c.Query("return_to"), "")
	if err != nil {
		h.svc.AuditRefusal(c.Context(), auth.AuditActor(c.Context()), typ, services.SSOPurposeSignIn, err)
		return c.Redirect().Status(fiber.StatusFound).To(ssoRefusedPage)
	}
	h.setStateCookie(c, start.State)
	return c.Redirect().Status(fiber.StatusFound).To(start.RedirectURL)
}

// Callback handles GET /auth/sso/:type/callback.
func (h *SSOSignIn) Callback(c fiber.Ctx) error {
	typ := c.Params("type")
	bound := c.Cookies(SSOStateCookieName)
	h.clearStateCookie(c)
	code := c.Query("code")
	if c.Query("error") != "" {
		code = "" // cancelled or refused at Google; the state is still consumed
	}
	res, purpose, err := h.svc.Callback(c.Context(), typ, c.Query("state"), bound, code, c.IP(), c.Get("User-Agent"))
	if err != nil {
		h.svc.AuditRefusal(c.Context(), auth.AuditActor(c.Context()), typ, purpose, err)
		return c.Redirect().Status(fiber.StatusFound).To(ssoRefusedPage)
	}
	switch res.Purpose {
	case services.SSOPurposeLink:
		return c.Redirect().Status(fiber.StatusFound).To("/me#sso_ticket=" + res.Ticket)
	case services.SSOPurposeTest:
		return c.Redirect().Status(fiber.StatusFound).To("/admin/sign-in#sso_ticket=" + res.Ticket)
	}
	h.svc.AuditSuccess(c.Context(), "user:"+res.User.ID.String(), typ, res)
	h.setSessionCookie(c, res.Issued.CookieValue, res.Issued.AbsoluteExpiry)
	return c.Redirect().Status(fiber.StatusFound).To(res.ReturnTo)
}

type redirectResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// Connect handles POST /auth/sso/:type/connect: Connect Google for the
// caller's own account.
func (h *SSOSignIn) Connect(c fiber.Ctx) error {
	return h.beginBound(c, c.Params("type"), services.SSOPurposeLink)
}

// Test handles POST /sso/providers/:id/test.
func (h *SSOSignIn) Test(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	p, err := h.config.GetProvider(c.Context(), id)
	if err != nil {
		return ssoErr(c, err)
	}
	return h.beginBound(c, p.Type, services.SSOPurposeTest)
}

func (h *SSOSignIn) beginBound(c fiber.Ctx, typ, purpose string) error {
	sessionID := currentSessionID(c)
	if sessionID == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "a signed-in session is required")
	}
	start, err := h.svc.Start(c.Context(), typ, purpose, "", sessionID)
	if err != nil {
		var r *services.SSORefusal
		if errors.As(err, &r) {
			return stableErr(c, fiber.StatusConflict, "sso_unavailable", "sign-in with this provider isn't available", map[string]any{"reason": r.Reason})
		}
		return fiber.NewError(fiber.StatusInternalServerError, "could not start")
	}
	h.setStateCookie(c, start.State)
	return c.JSON(redirectResponse{RedirectURL: start.RedirectURL})
}

// FinishBody is the body for POST /auth/sso/:type/finish.
type FinishBody struct {
	Ticket string `json:"ticket"`
}

type finishResponse struct {
	Purpose string `json:"purpose"`
	Result  string `json:"result"`           // linked, ok, failed
	Reason  string `json:"reason,omitempty"` // test: why it failed
}

// Finish handles POST /auth/sso/:type/finish.
func (h *SSOSignIn) Finish(c fiber.Ctx) error {
	typ := c.Params("type")
	var body FinishBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	userID, _ := auth.IdentityFromContext(c.Context())
	res, err := h.svc.Finish(c.Context(), typ, body.Ticket, currentSessionID(c), userID)
	purpose := ""
	if res != nil {
		purpose = res.Purpose
	}
	// The caller is signed in here, so failed links and tests, and
	// passing tests, are audited as that user (not anonymous).
	actor := auth.AuditActor(c.Context())
	if err != nil {
		h.svc.AuditRefusal(c.Context(), actor, typ, purpose, err)
		var r *services.SSORefusal
		if !errors.As(err, &r) {
			return fiber.NewError(fiber.StatusInternalServerError, "could not finish")
		}
		switch {
		case r.Reason == "ticket_unknown" || r.Reason == "other_session":
			return fiber.NewError(fiber.StatusForbidden, "sso_ticket_refused")
		case purpose == services.SSOPurposeTest:
			return c.JSON(finishResponse{Purpose: purpose, Result: "failed", Reason: r.Reason})
		default:
			return stableErr(c, fiber.StatusConflict, "link_refused", "Google couldn't be connected to this account", map[string]any{"reason": r.Reason})
		}
	}
	h.svc.AuditSuccess(c.Context(), actor, typ, &services.SSOCallbackResult{Purpose: res.Purpose, User: res.User})
	result := "ok"
	if res.Purpose == services.SSOPurposeLink {
		result = "linked"
	}
	return c.JSON(finishResponse{Purpose: res.Purpose, Result: result})
}

type identityBody struct {
	ProviderType string    `json:"provider_type"`
	Email        string    `json:"email"`
	LinkedAt     time.Time `json:"linked_at"`
}

// Identities handles GET /users/me/identities.
func (h *SSOSignIn) Identities(c fiber.Ctx) error {
	uid, err := currentUserUUID(c)
	if err != nil {
		return err
	}
	ids, err := h.svc.Identities(c.Context(), uid)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not list connected accounts")
	}
	out := make([]identityBody, 0, len(ids))
	for _, id := range ids {
		out = append(out, identityBody{ProviderType: id.ProviderType, Email: id.EmailAtLink, LinkedAt: id.LinkedAt})
	}
	return c.JSON(out)
}

// Unlink handles DELETE /users/me/identities/:type.
func (h *SSOSignIn) Unlink(c fiber.Ctx) error {
	uid, err := currentUserUUID(c)
	if err != nil {
		return err
	}
	removed, err := h.svc.Unlink(c.Context(), uid, c.Params("type"))
	if errors.Is(err, storage.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "not connected")
	}
	if errors.Is(err, storage.ErrIdentityRequired) {
		return stableErr(c, fiber.StatusConflict, "identity_required",
			"this account signs in only with this provider, so it can't be disconnected", nil)
	}
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "could not disconnect")
	}
	auditWrite(c, h.svcAudit(), "user.identity_unlink", "user:"+uid.String(), map[string]any{
		"provider_type": removed.ProviderType, "email_at_link": removed.EmailAtLink,
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SSOSignIn) svcAudit() storage.AuditEventRepository { return h.svc.AuditRepo() }

func currentSessionID(c fiber.Ctx) string {
	if s, ok := c.Context().Value(middleware.CtxKeySession).(*storage.Session); ok && s != nil {
		return s.ID.String()
	}
	return ""
}

func currentUserUUID(c fiber.Ctx) (uuid.UUID, error) {
	id, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	uid, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	return uid, nil
}

func (h *SSOSignIn) setStateCookie(c fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name: SSOStateCookieName, Value: state, Path: ssoStateCookiePath,
		MaxAge: 300, HTTPOnly: true, Secure: h.cookieMode == CookieModeProd, SameSite: fiber.CookieSameSiteLaxMode,
	})
}

func (h *SSOSignIn) clearStateCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name: SSOStateCookieName, Value: "", Path: ssoStateCookiePath,
		MaxAge: -1, HTTPOnly: true, Secure: h.cookieMode == CookieModeProd, SameSite: fiber.CookieSameSiteLaxMode,
	})
}

func (h *SSOSignIn) setSessionCookie(c fiber.Ctx, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name: middleware.SessionCookieName, Value: value, Path: "/",
		MaxAge: int(time.Until(expires).Seconds()), HTTPOnly: true,
		Secure: h.cookieMode == CookieModeProd, SameSite: fiber.CookieSameSiteStrictMode,
	})
}
