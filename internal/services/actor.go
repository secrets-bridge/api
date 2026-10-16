package services

import (
	"context"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

// auditActorFromContext names who caused a service action, read from the
// request context the handler passed down (API-15): "user:<id>" for a
// session or bearer caller, "agent:<id>" for an agent-authenticated call,
// and "system" when neither is present (boot, background work). It
// replaces the hard-coded "admin" these audit rows used to carry.
func auditActorFromContext(ctx context.Context) string {
	if id, ok := auth.IdentityFromContext(ctx); ok {
		return "user:" + id
	}
	if agentID, ok := middleware.AgentIDFromContext(ctx); ok {
		return "agent:" + agentID.String()
	}
	return "system"
}
