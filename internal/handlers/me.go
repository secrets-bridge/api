// Package handlers — me.go: "current user" projections.
//
// GET /api/v1/users/me                returns the full profile shape
//                                      the UI needs to render
//                                      identity + nav state in one
//                                      call: id / email / display_name
//                                      / deduped permissions / team
//                                      memberships / accessible
//                                      project IDs.
// GET /api/v1/users/me/projects       project switcher dropdown (the
//                                      original endpoint — same data
//                                      as me.projects but inlined).
//
// Global admins (any unscoped grant for secret.list OR secret.request)
// see every project; tenancy-scoped callers see only their granted
// set. The shape is the same in both cases so the UI doesn't branch.
package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Me is the HTTP layer for "current user" projections.
type Me struct {
	projects  storage.ProjectRepository
	resolver  auth.Resolver
	teamScope auth.TeamScopeResolver
	users     storage.LocalUserRepository
	teams     storage.TeamRepository
}

// NewMe wires the handler. Both args required. Call WithTeamScope to
// expand team-scoped role grants into the descendant project set; when
// not set, only project_id-scoped grants are honoured. WithIdentity
// wires the optional user + team repositories so GET /users/me can
// hydrate the full profile shape.
func NewMe(p storage.ProjectRepository, r auth.Resolver) *Me {
	return &Me{projects: p, resolver: r}
}

// WithTeamScope plumbs the team-aware access resolver. Optional.
func (h *Me) WithTeamScope(tr auth.TeamScopeResolver) *Me {
	h.teamScope = tr
	return h
}

// WithIdentity wires the user + team repositories so GET /users/me
// can return identity (email, display_name) + team memberships in
// addition to the permission + project rollup. Optional: when nil,
// the GetMe endpoint returns 503 — the only consumer today is the UI
// hydration path and main always wires it.
func (h *Me) WithIdentity(u storage.LocalUserRepository, t storage.TeamRepository) *Me {
	h.users = u
	h.teams = t
	return h
}

// ProjectSummary is the wire shape for the user-projects projection.
type ProjectSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// TeamSummary is the slim shape returned for each team in the user's
// membership list.
type TeamSummary struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ParentTeamID *string `json:"parent_team_id"`
	Status       string  `json:"status"`
}

// MeResponse is the JSON shape returned by GET /users/me. Single
// round-trip for the UI's post-login hydration: identity + nav-gating
// permissions + tenancy boundaries in one call.
type MeResponse struct {
	ID          string           `json:"id"`
	Email       string           `json:"email"`
	DisplayName string           `json:"display_name"`
	// Permissions is the deduped set of permission strings (e.g.
	// "secret.list") collected across every active role grant the
	// user holds. The UI uses this to gate sidebar nav items + buttons.
	Permissions []string         `json:"permissions"`
	// Teams the user is a direct member of. Hierarchical access (a
	// section head seeing reports' work) is computed server-side via
	// the team-scope resolver — the UI doesn't need the subtree here.
	Teams       []TeamSummary    `json:"teams"`
	// Projects the user can read or request against. Same projection
	// as GET /users/me/projects; inlined here so login hydration is
	// one HTTP call.
	Projects    []ProjectSummary `json:"projects"`
}

// GetMe handles GET /api/v1/users/me. Returns the bundle the UI needs
// to render identity + sidebar gating + tenancy boundaries in one
// trip.
func (h *Me) GetMe(c fiber.Ctx) error {
	if h.users == nil || h.teams == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "identity hydration not wired")
	}
	sub, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	uid, err := uuid.Parse(sub)
	if err != nil {
		// Identity isn't a UUID — the legacy stub may have stamped a
		// free-text identifier. The endpoint can't resolve it through
		// local_users; return 422 so the UI knows hydration is
		// unavailable for this session.
		return fiber.NewError(fiber.StatusUnprocessableEntity, "identity is not a user id")
	}
	user, err := h.users.Get(c.Context(), uid)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "user not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Permission rollup — dedup across grants. The Resolver returns
	// one Grant per (role × permission) so a permission appearing in
	// two granted roles surfaces twice; the set dedups.
	grants, err := h.resolver.Resolve(c.Context(), sub)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	permSet := map[string]struct{}{}
	for _, g := range grants {
		permSet[g.Permission] = struct{}{}
	}
	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}

	teams, err := h.teams.ListTeamsForUser(c.Context(), uid)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	teamsOut := make([]TeamSummary, 0, len(teams))
	for _, t := range teams {
		var parent *string
		if t.ParentTeamID != nil {
			s := t.ParentTeamID.String()
			parent = &s
		}
		teamsOut = append(teamsOut, TeamSummary{
			ID:           t.ID.String(),
			Name:         t.Name,
			ParentTeamID: parent,
			Status:       string(t.Status),
		})
	}

	projects, err := h.projectsForUser(c, sub)
	if err != nil {
		return err
	}

	return c.JSON(MeResponse{
		ID:          user.ID.String(),
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Permissions: perms,
		Teams:       teamsOut,
		Projects:    projects,
	})
}

// projectsForUser is the shared helper between GetMe and ListProjects.
// Same access semantics as ListProjects.
func (h *Me) projectsForUser(c fiber.Ctx, userID string) ([]ProjectSummary, error) {
	access, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermSecretList, h.resolver, h.teamScope)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if !access.IsGlobal && len(access.ProjectIDs) == 0 {
		alt, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermSecretRequest, h.resolver, h.teamScope)
		if err == nil && (alt.IsGlobal || len(alt.ProjectIDs) > 0) {
			access = alt
		}
	}
	all, err := h.projects.List(c.Context())
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
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
	return out, nil
}

// ListProjects handles GET /api/v1/users/me/projects.
func (h *Me) ListProjects(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	out, err := h.projectsForUser(c, userID)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
