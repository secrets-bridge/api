// R-follow-up #3 (api#126) slice 1c — coverage endpoint for the SPA's
// scope-aware sidebar + canAuthorTeamPolicy capability helper.
//
// GET /api/v1/users/me/policy-author-team-coverage returns the resolved
// team set the caller's policy.author grants cover (subtree-expanded
// via EffectiveTeamAccess). The SPA reads this to:
//
//   - Decide whether to render the "Team policies" sidebar entry
//   - Gate canAuthorTeamPolicy(teamID) helper without walking the
//     team tree client-side
//
// Permission: bearer-only. The endpoint exposes ONLY the caller's own
// coverage — not enumerable across other users. EffectiveTeamAccess
// is the source of truth; server-side computation means the SPA
// doesn't need separate /teams + role-grants requests to compute
// coverage.

package handlers

import (
	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
)

// PolicyAuthorTeamCoverage handles the new /me endpoint.
type PolicyAuthorTeamCoverage struct {
	resolver  auth.Resolver
	teamScope auth.TeamScopeResolver
}

// NewPolicyAuthorTeamCoverage constructs the handler. resolver MUST be
// the same RBAC resolver wired everywhere else (rbacResolver in main);
// teamScope MUST expand team-scoped grants through their subtree.
func NewPolicyAuthorTeamCoverage(r auth.Resolver, ts auth.TeamScopeResolver) *PolicyAuthorTeamCoverage {
	return &PolicyAuthorTeamCoverage{resolver: r, teamScope: ts}
}

// policyAuthorTeamCoverageResponse is the wire shape consumed by the
// SPA's useMyPolicyAuthorTeamCoverage hook.
type policyAuthorTeamCoverageResponse struct {
	Global  bool     `json:"global"`
	TeamIDs []string `json:"team_ids"`
}

// Get handles GET /api/v1/users/me/policy-author-team-coverage.
func (h *PolicyAuthorTeamCoverage) Get(c fiber.Ctx) error {
	actor := identityFromCtx(c)
	if actor == "" {
		return stableErr(c, fiber.StatusUnauthorized, "unauthenticated",
			"missing identity", nil)
	}
	access, err := auth.EffectiveTeamAccess(c.Context(), actor, auth.PermPolicyAuthor,
		h.resolver, h.teamScope)
	if err != nil {
		return stableErr(c, fiber.StatusInternalServerError, "internal_error",
			"could not resolve team access", nil)
	}
	teamIDs := make([]string, 0, len(access.TeamIDs))
	for _, id := range access.TeamIDs {
		teamIDs = append(teamIDs, id.String())
	}
	return c.JSON(policyAuthorTeamCoverageResponse{
		Global:  access.IsGlobal,
		TeamIDs: teamIDs,
	})
}
