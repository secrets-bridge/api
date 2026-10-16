package handlers

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
)

// projectReadScope is the read-path project gate for the project-anchored
// reads api#155 did not cover (API-N-04): the per-env dev secret list,
// the project policy-rule reads and the project provider-connection
// binding list. A caller whose grants don't cover the project gets 404
// (never 403) so another project's existence stays hidden.
//
// perms is the set whose union decides coverage. Every gate starts from
// auth.ReadableProjectAccess (secret.list ∪ secret.request), the same
// visibility /users/me and the tenancy reads use; a gate may add the
// permission that manages the resource so its scoped owners keep reading
// it.
//
// When resolver is nil the gate allows everything, matching the other
// read guards' legacy mode for tests that don't seed grants. main always
// wires it.
type projectReadScope struct {
	resolver  auth.Resolver
	teamScope auth.TeamScopeResolver
	perms     []auth.Permission
}

func newProjectReadScope(r auth.Resolver, tr auth.TeamScopeResolver, extra ...auth.Permission) projectReadScope {
	perms := append([]auth.Permission{auth.PermSecretList, auth.PermSecretRequest}, extra...)
	return projectReadScope{resolver: r, teamScope: tr, perms: perms}
}

// covers reports whether the caller may read projectID. The error is a
// ready-to-return 401 (no identity) or 500 (resolver failure).
func (s projectReadScope) covers(c fiber.Ctx, projectID uuid.UUID) (bool, error) {
	if s.resolver == nil {
		return true, nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return false, fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	access, err := auth.ProjectAccessForAny(c.Context(), userID, s.resolver, s.teamScope, s.perms...)
	if err != nil {
		return false, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return access.Covers(projectID), nil
}
