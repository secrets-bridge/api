package handlers

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// structureMove is a team re-parent or a project move for structureCheck.
type structureMove struct {
	action, resource          string // the write's audit action and resource
	movedTeam, prevTeam, dest *uuid.UUID
}

// structureCheck refuses a team re-parent or a project move that widens
// one of the caller's team-scoped grants (api#308, api#192, ADR 0002
// C4): 403 self_scope_expansion_not_allowed, audited as
// denied. Without a resolver the check is skipped.
func structureCheck(c fiber.Ctx, r auth.Resolver, tr auth.TeamScopeResolver, repo storage.AuditEventRepository, m structureMove) error {
	if r == nil || tr == nil {
		return nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	err := auth.CheckStructureChange(c.Context(), userID, r, tr, m.movedTeam, m.prevTeam, m.dest)
	switch {
	case errors.Is(err, auth.ErrSelfScopeExpansion):
		if repo != nil {
			evt := &storage.AuditEvent{
				Actor: auth.AuditActor(c.Context()), Action: m.action, Resource: m.resource,
				Status: storage.AuditStatusDenied, Metadata: map[string]any{
					"error_kind":     "self_scope_expansion_not_allowed",
					"target_team_id": uuidPtrMeta(m.dest),
				},
			}
			if aerr := repo.Append(c.Context(), evt); aerr != nil {
				slog.WarnContext(c.Context(), "audit append failed", "action", m.action, "err", aerr)
			}
		}
		return fiber.NewError(fiber.StatusForbidden, "self_scope_expansion_not_allowed")
	case err != nil:
		return err
	}
	return nil
}
