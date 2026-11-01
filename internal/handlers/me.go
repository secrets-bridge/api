// Package handlers — me.go: "current user" projections.
//
// GET /api/v1/users/me                returns the full profile shape
//
//	the UI needs to render
//	identity + nav state in one
//	call: id / email / display_name
//	/ deduped permissions / team
//	memberships / accessible
//	project IDs.
//
// GET /api/v1/users/me/projects       project switcher dropdown (the
//
//	original endpoint — same data
//	as me.projects but inlined).
//
// Global admins (any unscoped grant for secret.list OR secret.request)
// see every project; tenancy-scoped callers see only their granted
// set. The shape is the same in both cases so the UI doesn't branch.
package handlers

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// MFAEnrollmentLookup reports whether a user has any factor enrolled.
// Implemented by `services.MFAVerifyService.AnyEnrolled`. Optional —
// when unset, `mfa_enrolled` is reported as `false` on /users/me
// (safe default — the SPA will then route the user to /me/mfa).
type MFAEnrollmentLookup interface {
	AnyEnrolled(ctx context.Context, userID uuid.UUID) (bool, error)
}

// Me is the HTTP layer for "current user" projections.
type Me struct {
	projects     storage.ProjectRepository
	environments storage.EnvironmentRepository // Slice L4 — nullable
	resolver     auth.Resolver
	teamScope    auth.TeamScopeResolver
	users        storage.LocalUserRepository
	teams        storage.TeamRepository
	mfa          MFAEnrollmentLookup
	logos        LogoVersionLookup
	passwords    PasswordLookup
}

// PasswordLookup tells whether an account can sign in with a password:
// an account that a Google sign-in created has none anyone knows.
type PasswordLookup interface {
	HasPassword(ctx context.Context, userID uuid.UUID) (bool, error)
}

// WithPasswordLookup adds has_password to GET /users/me. Returns the
// handler for chaining.
func (h *Me) WithPasswordLookup(p PasswordLookup) *Me {
	h.passwords = p
	return h
}

// LogoVersionLookup is the slice of the logo service /users/me needs:
// logo_version for many projects or teams in one query.
type LogoVersionLookup interface {
	Versions(ctx context.Context, kind storage.LogoKind, entityIDs []uuid.UUID) (map[uuid.UUID]string, error)
}

// WithLogos adds logo_version to the project and team summaries.
// Returns the handler for chaining.
func (h *Me) WithLogos(l LogoVersionLookup) *Me {
	h.logos = l
	return h
}

// logoVersions looks up logo versions, or none when logos aren't wired.
func (h *Me) logoVersions(c fiber.Ctx, kind storage.LogoKind, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	if h.logos == nil {
		return map[uuid.UUID]string{}, nil
	}
	v, err := h.logos.Versions(c.Context(), kind, ids)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return v, nil
}

// WithEnvironments wires the EnvironmentRepository so the projection
// endpoints include each project's environments in the response.
// Slice L4. When nil, the `environments` field stays omitted via
// omitempty — back-compat for callers that pre-date L1.
func (h *Me) WithEnvironments(e storage.EnvironmentRepository) *Me {
	h.environments = e
	return h
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

// WithMFAEnrollment attaches the lookup that powers the
// `mfa_enrolled` boolean on /users/me (Slice H5). Optional — when
// nil, the field is always false, which is the safe default for
// boot paths that haven't reached the MFA verification service yet.
func (h *Me) WithMFAEnrollment(svc MFAEnrollmentLookup) *Me {
	h.mfa = svc
	return h
}

// ProjectSummary is the wire shape for the user-projects projection.
//
// Slice L4 added the `Environments` field so the dev-facing sidebar
// can render a "My Projects" tree with per-project env drilldown.
// The list comes from `project_environments` (Slice L1) ordered by
// name ascending. Empty when the project has no environments
// configured.
type ProjectSummary struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Status       string               `json:"status"`
	Environments []EnvironmentSummary `json:"environments,omitempty"`
	// LogoVersion is set when the project has a logo (GET
	// /projects/:id/logo?v=<logo_version>); null otherwise.
	LogoVersion *string `json:"logo_version"`
}

// EnvironmentSummary is the per-env shape returned alongside a
// project. Carries the load-bearing `kind` field so the SPA can
// render a badge + pick the right CTA (Reveal vs Request) without
// a per-env round trip.
type EnvironmentSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	RiskLevel int    `json:"risk_level"`
}

// TeamSummary is the slim shape returned for each team in the user's
// membership list.
type TeamSummary struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ParentTeamID *string `json:"parent_team_id"`
	Status       string  `json:"status"`
	// LogoVersion is set when the team has a logo; null otherwise.
	LogoVersion *string `json:"logo_version"`
}

// MeResponse is the JSON shape returned by GET /users/me. Single
// round-trip for the UI's post-login hydration: identity + nav-gating
// permissions + tenancy boundaries in one call.
type MeResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	// Permissions is the deduped set of permission strings (e.g.
	// "secret.list") collected across every active role grant the
	// user holds. The UI uses this to gate sidebar nav items + buttons.
	Permissions []string `json:"permissions"`
	// GlobalPermissions is the subset of Permissions held through an
	// unscoped grant, which is what auth.Require asks for. The UI uses it
	// where a team-scoped grant isn't enough, so it doesn't offer an
	// action that answers 403.
	GlobalPermissions []string `json:"global_permissions"`
	// Teams the user is a direct member of. Hierarchical access (a
	// section head seeing reports' work) is computed server-side via
	// the team-scope resolver — the UI doesn't need the subtree here.
	Teams []TeamSummary `json:"teams"`
	// Projects the user can read or request against. Same projection
	// as GET /users/me/projects; inlined here so login hydration is
	// one HTTP call.
	Projects []ProjectSummary `json:"projects"`
	// MFAEnrolled — true when the user has at least one factor
	// (TOTP or WebAuthn) enrolled. Slice H5. The SPA reads this
	// after login to decide whether to:
	//   - immediately route the user to /me/mfa (false = no
	//     factor enrolled, app-MFA can't grant step-up)
	//   - leave them on the Dashboard until they trigger a
	//     Tier-2 op (true = at least one factor, the step-up
	//     modal will have something to verify against)
	// When the boot path hasn't wired the MFA service, the field
	// is reported as false (safe default — pushes user to enroll).
	MFAEnrolled bool `json:"mfa_enrolled"`
	// PendingApproval is true while the account waits for an admin's
	// approval. Such an account can only read this and sign out; the
	// console shows a "waiting for approval" page.
	PendingApproval bool `json:"pending_approval"`
	// HasPassword is false for an account that a Google sign-in
	// created: it has no password anyone knows, so its Google identity
	// is its only way in and can't be disconnected.
	HasPassword bool `json:"has_password"`
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
	globalSet := map[string]struct{}{}
	for _, g := range grants {
		permSet[g.Permission] = struct{}{}
		if len(g.Scope) == 0 {
			globalSet[g.Permission] = struct{}{}
		}
	}
	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}
	globalPerms := make([]string, 0, len(globalSet))
	for p := range globalSet {
		globalPerms = append(globalPerms, p)
	}

	teams, err := h.teams.ListTeamsForUser(c.Context(), uid)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	teamIDs := make([]uuid.UUID, 0, len(teams))
	for _, t := range teams {
		teamIDs = append(teamIDs, t.ID)
	}
	teamLogos, err := h.logoVersions(c, storage.LogoKindTeam, teamIDs)
	if err != nil {
		return err
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
			LogoVersion:  logoVersionPtr(teamLogos, t.ID),
		})
	}

	projects, err := h.projectsForUser(c, sub)
	if err != nil {
		return err
	}

	mfaEnrolled := false
	if h.mfa != nil {
		// Failure here shouldn't fail the whole hydration call —
		// degrade to false (push user to /me/mfa) and let an admin
		// see the audit row from the underlying CountForUser lookup.
		if enrolled, err := h.mfa.AnyEnrolled(c.Context(), uid); err == nil {
			mfaEnrolled = enrolled
		}
	}

	hasPassword := true
	if h.passwords != nil {
		// Like mfa_enrolled, a failed lookup doesn't fail the call. The
		// api refuses the disconnect on its own either way.
		if v, err := h.passwords.HasPassword(c.Context(), uid); err == nil {
			hasPassword = v
		}
	}

	return c.JSON(MeResponse{
		ID:                user.ID.String(),
		Email:             user.Email,
		DisplayName:       user.DisplayName,
		Permissions:       perms,
		GlobalPermissions: globalPerms,
		Teams:             teamsOut,
		Projects:          projects,
		MFAEnrolled:       mfaEnrolled,

		PendingApproval: user.PendingApproval,
		HasPassword:     hasPassword,
	})
}

// projectsForUser is the shared helper between GetMe and ListProjects.
// Same access semantics as ListProjects.
func (h *Me) projectsForUser(c fiber.Ctx, userID string) ([]ProjectSummary, error) {
	access, err := auth.ReadableProjectAccess(c.Context(), userID, h.resolver, h.teamScope)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	all, err := h.projects.List(c.Context())
	if err != nil {
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	ids := make([]uuid.UUID, 0, len(all))
	for _, p := range all {
		if access.Covers(p.ID) {
			ids = append(ids, p.ID)
		}
	}
	logos, err := h.logoVersions(c, storage.LogoKindProject, ids)
	if err != nil {
		return nil, err
	}
	out := make([]ProjectSummary, 0, len(all))
	for _, p := range all {
		if !access.Covers(p.ID) {
			continue
		}
		summary := ProjectSummary{
			ID:          p.ID.String(),
			Name:        p.Name,
			Status:      string(p.Status),
			LogoVersion: logoVersionPtr(logos, p.ID),
		}
		if h.environments != nil {
			envs, err := h.environments.ListByProject(c.Context(), p.ID)
			if err != nil {
				return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
			}
			summary.Environments = make([]EnvironmentSummary, 0, len(envs))
			for _, env := range envs {
				summary.Environments = append(summary.Environments, EnvironmentSummary{
					ID:        env.ID.String(),
					Name:      env.Name,
					Kind:      string(env.Kind),
					RiskLevel: env.RiskLevel,
				})
			}
		}
		out = append(out, summary)
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
