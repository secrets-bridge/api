// Package handlers — me.go: "current user" projections.
//
// GET /api/v1/users/me/projects returns the project list the caller
// can act on, joined from the projects table by the project_ids in
// their user_roles.scope. Drives the UI's project switcher dropdown
// (ui#26 Slice H).
//
// Global admins (any unscoped grant for secret.list OR secret.request)
// see every project; tenancy-scoped callers see only their granted
// set. The shape is the same in both cases so the UI doesn't branch.
package handlers

import (
	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Me is the HTTP layer for "current user" projections.
type Me struct {
	projects storage.ProjectRepository
	resolver auth.Resolver
}

// NewMe wires the handler. Both args required.
func NewMe(p storage.ProjectRepository, r auth.Resolver) *Me {
	return &Me{projects: p, resolver: r}
}

// ProjectSummary is the wire shape for the user-projects projection.
type ProjectSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// ListProjects handles GET /api/v1/users/me/projects.
func (h *Me) ListProjects(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	// Prefer secret.list when computing access (the catalog-side
	// permission). Most users will have both; admins will have
	// either at global scope. If a caller only has secret.request
	// (write-only) the projection still returns the same set —
	// EffectiveProjectAccess falls back to ProjectIDs from any grant.
	access, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermSecretList, h.resolver)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if !access.IsGlobal && len(access.ProjectIDs) == 0 {
		// Try secret.request as a fallback signal.
		alt, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermSecretRequest, h.resolver)
		if err == nil && (alt.IsGlobal || len(alt.ProjectIDs) > 0) {
			access = alt
		}
	}

	all, err := h.projects.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	out := make([]ProjectSummary, 0, len(all))
	for _, p := range all {
		if !access.IsGlobal {
			inSet := false
			for _, pid := range access.ProjectIDs {
				if pid == p.ID {
					inSet = true
					break
				}
			}
			if !inSet {
				continue
			}
		}
		out = append(out, ProjectSummary{
			ID:     p.ID.String(),
			Name:   p.Name,
			Status: string(p.Status),
		})
	}
	return c.JSON(out)
}
