// Package handlers, sso.go: managing sign-in providers and the sign-in
// settings from the console (api#267).
//
//	GET    /sso/providers               list
//	POST   /sso/providers               create (disabled)
//	GET    /sso/providers/:id           one
//	PUT    /sso/providers/:id           edit (not the secret, not enabled)
//	PUT    /sso/providers/:id/secret    replace the client secret
//	POST   /sso/providers/:id/enable    turn on (needs public address, secret, domains)
//	POST   /sso/providers/:id/disable   turn off
//	DELETE /sso/providers/:id           remove
//	GET    /sso/settings                public address and waiting-account cap
//	PUT    /sso/settings                change them
//
// Main gates every route on a global auth.sso.edit, and every write also
// on a fresh second factor (RequireFreshMFA). Responses never carry the
// client secret, only client_secret_set. Each write is audited with the
// old and new values; the secret never appears in audit metadata.
package handlers

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// SSO serves the sign-in configuration routes.
type SSO struct {
	svc   *services.SSOService
	audit storage.AuditEventRepository
}

// NewSSO binds the handler. audit may be nil in tests.
func NewSSO(svc *services.SSOService, audit storage.AuditEventRepository) *SSO {
	return &SSO{svc: svc, audit: audit}
}

// SSOProviderBody is a provider as the console sees it.
type SSOProviderBody struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	DisplayName     string    `json:"display_name"`
	ClientID        string    `json:"client_id"`
	ClientSecretSet bool      `json:"client_secret_set"`
	AllowedDomains  []string  `json:"allowed_domains"`
	RequireApproval bool      `json:"require_approval"`
	DefaultRoleID   *string   `json:"default_role_id"`
	Enabled         bool      `json:"enabled"`
	RedirectURL     string    `json:"redirect_url"` // empty until a public address is set
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SSOProviderInputBody is the body for create and edit. client_secret is
// read on create only; require_approval defaults to true.
type SSOProviderInputBody struct {
	Type            string     `json:"type"`
	DisplayName     string     `json:"display_name"`
	ClientID        string     `json:"client_id"`
	ClientSecret    string     `json:"client_secret,omitempty"`
	AllowedDomains  []string   `json:"allowed_domains"`
	RequireApproval *bool      `json:"require_approval,omitempty"`
	DefaultRoleID   *uuid.UUID `json:"default_role_id,omitempty"`
}

// SSOSecretBody is the body for PUT /sso/providers/:id/secret.
type SSOSecretBody struct {
	ClientSecret string `json:"client_secret"`
}

// SSOSettingsBody is the sign-in settings. public_url_source is "env"
// when SB_PUBLIC_URL sets the address (then it can't be edited here),
// "console" when it was saved here, and "" when unset.
type SSOSettingsBody struct {
	PublicURL       string `json:"public_url"`
	PublicURLSource string `json:"public_url_source"`
	PendingCap      int    `json:"pending_cap"`
}

// SSOSettingsInputBody changes the settings; omitted fields stay as they
// are, and an empty public_url clears it.
type SSOSettingsInputBody struct {
	PublicURL  *string `json:"public_url,omitempty"`
	PendingCap *int    `json:"pending_cap,omitempty"`
}

func (h *SSO) toBody(ctx context.Context, p *storage.SSOProvider) SSOProviderBody {
	b := SSOProviderBody{
		ID: p.ID.String(), Type: p.Type, DisplayName: p.DisplayName, ClientID: p.ClientID,
		ClientSecretSet: p.Secret != nil, AllowedDomains: p.AllowedDomains,
		RequireApproval: p.RequireApproval, Enabled: p.Enabled,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if b.AllowedDomains == nil {
		b.AllowedDomains = []string{}
	}
	if p.DefaultRoleID != nil {
		id := p.DefaultRoleID.String()
		b.DefaultRoleID = &id
	}
	b.RedirectURL, _ = h.svc.RedirectURL(ctx, p.Type)
	return b
}

func (b SSOProviderInputBody) input() services.SSOProviderInput {
	requireApproval := true
	if b.RequireApproval != nil {
		requireApproval = *b.RequireApproval
	}
	return services.SSOProviderInput{
		Type: b.Type, DisplayName: b.DisplayName, ClientID: b.ClientID, ClientSecret: b.ClientSecret,
		AllowedDomains: b.AllowedDomains, RequireApproval: requireApproval, DefaultRoleID: b.DefaultRoleID,
	}
}

// providerAuditValues is what the audit trail records about a provider:
// everything an admin can change except the secret, of which only its
// presence is recorded.
func providerAuditValues(p *storage.SSOProvider) map[string]any {
	v := map[string]any{
		"display_name":      p.DisplayName,
		"client_id":         p.ClientID,
		"allowed_domains":   slices.Clone(p.AllowedDomains),
		"require_approval":  p.RequireApproval,
		"default_role_id":   nil,
		"enabled":           p.Enabled,
		"client_secret_set": p.Secret != nil,
	}
	if p.DefaultRoleID != nil {
		v["default_role_id"] = p.DefaultRoleID.String()
	}
	return v
}

// ListProviders handles GET /sso/providers.
func (h *SSO) ListProviders(c fiber.Ctx) error {
	ps, err := h.svc.ListProviders(c.Context())
	if err != nil {
		return ssoErr(c, err)
	}
	out := make([]SSOProviderBody, 0, len(ps))
	for _, p := range ps {
		out = append(out, h.toBody(c.Context(), p))
	}
	return c.JSON(out)
}

// GetProvider handles GET /sso/providers/:id.
func (h *SSO) GetProvider(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	p, err := h.svc.GetProvider(c.Context(), id)
	if err != nil {
		return ssoErr(c, err)
	}
	return c.JSON(h.toBody(c.Context(), p))
}

// CreateProvider handles POST /sso/providers.
func (h *SSO) CreateProvider(c fiber.Ctx) error {
	var body SSOProviderInputBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	p, err := h.svc.CreateProvider(c.Context(), body.input(), sessionActor(c))
	if err != nil {
		return ssoErr(c, err)
	}
	auditWrite(c, h.audit, "sso_provider.create", "sso_provider:"+p.ID.String(), map[string]any{
		"provider_id": p.ID.String(), "type": p.Type, "new": providerAuditValues(p),
	})
	return c.Status(fiber.StatusCreated).JSON(h.toBody(c.Context(), p))
}

// UpdateProvider handles PUT /sso/providers/:id.
func (h *SSO) UpdateProvider(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body SSOProviderInputBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	before, after, err := h.svc.UpdateProvider(c.Context(), id, body.input(), sessionActor(c))
	if err != nil {
		return ssoErr(c, err)
	}
	auditWrite(c, h.audit, "sso_provider.update", "sso_provider:"+id.String(), map[string]any{
		"provider_id": id.String(), "type": after.Type,
		"old": providerAuditValues(before), "new": providerAuditValues(after),
	})
	return c.JSON(h.toBody(c.Context(), after))
}

// SetSecret handles PUT /sso/providers/:id/secret.
func (h *SSO) SetSecret(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	var body SSOSecretBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := h.svc.SetSecret(c.Context(), id, body.ClientSecret, sessionActor(c)); err != nil {
		return ssoErr(c, err)
	}
	auditWrite(c, h.audit, "sso_provider.secret_rotate", "sso_provider:"+id.String(), map[string]any{
		"provider_id": id.String(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// Enable handles POST /sso/providers/:id/enable.
func (h *SSO) Enable(c fiber.Ctx) error { return h.setEnabled(c, true) }

// Disable handles POST /sso/providers/:id/disable.
func (h *SSO) Disable(c fiber.Ctx) error { return h.setEnabled(c, false) }

func (h *SSO) setEnabled(c fiber.Ctx, enabled bool) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	if err := h.svc.SetEnabled(c.Context(), id, enabled, sessionActor(c)); err != nil {
		return ssoErr(c, err)
	}
	action := "sso_provider.disable"
	if enabled {
		action = "sso_provider.enable"
	}
	auditWrite(c, h.audit, action, "sso_provider:"+id.String(), map[string]any{"provider_id": id.String()})
	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteProvider handles DELETE /sso/providers/:id.
func (h *SSO) DeleteProvider(c fiber.Ctx) error {
	id, err := parseID(c, "id")
	if err != nil {
		return err
	}
	before, err := h.svc.DeleteProvider(c.Context(), id)
	if err != nil {
		return ssoErr(c, err)
	}
	auditWrite(c, h.audit, "sso_provider.delete", "sso_provider:"+id.String(), map[string]any{
		"provider_id": id.String(), "type": before.Type, "old": providerAuditValues(before),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

// GetSettings handles GET /sso/settings.
func (h *SSO) GetSettings(c fiber.Ctx) error {
	st, source, err := h.svc.Settings(c.Context())
	if err != nil {
		return ssoErr(c, err)
	}
	return c.JSON(SSOSettingsBody{PublicURL: st.PublicURL, PublicURLSource: source, PendingCap: st.PendingCap})
}

// UpdateSettings handles PUT /sso/settings.
func (h *SSO) UpdateSettings(c fiber.Ctx) error {
	var body SSOSettingsInputBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	before, after, err := h.svc.UpdateSettings(c.Context(), body.PublicURL, body.PendingCap, sessionActor(c))
	if err != nil {
		return ssoErr(c, err)
	}
	auditWrite(c, h.audit, "sso_settings.update", "sso_settings", map[string]any{
		"old": map[string]any{"public_url": before.PublicURL, "pending_cap": before.PendingCap},
		"new": map[string]any{"public_url": after.PublicURL, "pending_cap": after.PendingCap},
	})
	return h.GetSettings(c)
}

func ssoErr(c fiber.Ctx, err error) error {
	var input *services.SSOInputError
	var notReady *services.SSONotReadyError
	switch {
	case errors.As(err, &input):
		return stableErr(c, fiber.StatusBadRequest, "invalid_input", input.Reason, map[string]any{"field": input.Field})
	case errors.Is(err, services.ErrSSOPrivilegedDefaultRole):
		return stableErr(c, fiber.StatusBadRequest, "default_role_privileged",
			"the default role may only hold these permissions", map[string]any{"allowed": services.NonPrivilegedPermissions})
	case errors.Is(err, services.ErrSSODefaultRoleNeedsOff):
		return stableErr(c, fiber.StatusBadRequest, "default_role_needs_approval_off",
			"a default role is only used when new users don't need approval", nil)
	case errors.Is(err, services.ErrSSOEnvProviderIsGoogle):
		return stableErr(c, fiber.StatusConflict, "env_provider_is_google",
			"this install already signs in with Google through SB_OIDC_*", nil)
	case errors.Is(err, storage.ErrSSOProviderExists):
		return stableErr(c, fiber.StatusConflict, "provider_exists", "a provider of this type already exists", nil)
	case errors.As(err, &notReady):
		return stableErr(c, fiber.StatusConflict, "provider_not_ready", "set these before enabling",
			map[string]any{"missing": notReady.Missing})
	case errors.Is(err, services.ErrSSOPublicURLFromEnv):
		return stableErr(c, fiber.StatusConflict, "public_url_from_env",
			"the public address is set by SB_PUBLIC_URL for this install", nil)
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, "could not update sign-in settings")
	}
}
