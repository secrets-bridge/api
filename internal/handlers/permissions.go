package handlers

import (
	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
)

// Permissions exposes the platform's canonical permission catalog
// (auth.Catalog) over HTTP. The Roles admin UI calls this so the
// permission picker is hydrated from a stable source rather than
// guessing from observed role data.
//
// Future companion (when api#27 / P0-2 lands): `GET /can-i/...` for
// per-identity capability queries — same shape as ArgoCD's
// `/account/can-i/<resource>/<action>/<object>`. Out of scope here;
// that endpoint depends on the identity middleware (api#26).
type Permissions struct{}

// NewPermissions constructs the handler. No dependencies — the
// catalog is a compile-time package-level value.
func NewPermissions() *Permissions { return &Permissions{} }

// List handles GET /api/v1/permissions. Returns the full catalog as
// a JSON array of `Descriptor` rows. Order is preserved from the
// auth.Catalog source so the UI sees a stable, presentation-ready
// list (no per-call shuffling).
//
// Cacheable for the lifetime of an api binary — the catalog is a
// compile-time constant. Clients can safely cache aggressively.
func (h *Permissions) List(c fiber.Ctx) error {
	c.Set("Cache-Control", "public, max-age=300")
	return c.JSON(auth.Catalog)
}
