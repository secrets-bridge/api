package services

import (
	"context"

	"github.com/secrets-bridge/api/internal/auth"
)

// auditActorFromContext names who caused a service action from the
// request context the handler passed down (API-15). See auth.AuditActor.
func auditActorFromContext(ctx context.Context) string {
	return auth.AuditActor(ctx)
}

// auditActor formats an explicit acting user id for the audit actor
// column ("user:<id>"); with no id it falls back to the request context
// (agent / anonymous / system). It replaces actorOrAdmin, which wrote the
// bare id (unresolvable in the audit UI) or a literal "admin".
func auditActor(ctx context.Context, userID string) string {
	if userID != "" {
		return "user:" + userID
	}
	return auditActorFromContext(ctx)
}
