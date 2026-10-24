package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
)

// structureCheck refuses a team re-parent or a project move that widens
// a team-scoped gateway.bind grant of the caller (api#308, ADR 0002 C4,
// skills#103 phase 1): 403 self_scope_expansion_not_allowed. Without a
// resolver the check is skipped.
func structureCheck(c fiber.Ctx, r auth.Resolver, tr auth.TeamScopeResolver, movedTeam, prevTeam, dest *uuid.UUID) error {
	if r == nil || tr == nil {
		return nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	err := auth.CheckGatewayBindStructureChange(c.Context(), userID, r, tr, movedTeam, prevTeam, dest)
	switch {
	case errors.Is(err, auth.ErrSelfScopeExpansion):
		return fiber.NewError(fiber.StatusForbidden, "self_scope_expansion_not_allowed")
	case err != nil:
		return err
	}
	return nil
}
