package middleware

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// AgentAuthenticator is the slice of AgentService that agent-auth
// middleware actually needs. Defining the interface here lets handler
// tests inject a stub without pulling the full service.
type AgentAuthenticator interface {
	Authenticate(ctx context.Context, id uuid.UUID, agentSecret string) error
}

// CtxKeyAgentID is the typed context key carrying the authenticated
// agent's UUID downstream to job handlers.
const CtxKeyAgentID ctxKey = "authenticated_agent_id"

// AgentAuth validates the X-Agent-Secret header against the agent
// referenced by the `:id` URL parameter. On success the authenticated
// agent's UUID is stashed in the request context for downstream
// handlers to read via AgentIDFromContext.
//
// The middleware preserves the generic-401 contract: an unknown agent
// AND a wrong secret both return 401 to the client so an attacker
// probing the API can't enumerate agents. The audit log holds the
// distinction (handled at the service layer).
func AgentAuth(authn AgentAuthenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid agent id")
		}
		secret := c.Get("X-Agent-Secret")
		if secret == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "X-Agent-Secret header required")
		}
		err = authn.Authenticate(c.Context(), id, secret)
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrUnauthorized):
			return fiber.NewError(fiber.StatusUnauthorized, "agent auth rejected")
		case err != nil:
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		c.SetContext(context.WithValue(c.Context(), CtxKeyAgentID, id))
		return c.Next()
	}
}

// AgentIDFromContext returns the authenticated agent UUID written by
// AgentAuth. ok is false when the middleware was not applied — handlers
// behind AgentAuth can rely on ok being true.
func AgentIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v := ctx.Value(CtxKeyAgentID)
	id, ok := v.(uuid.UUID)
	return id, ok
}
