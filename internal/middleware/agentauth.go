package middleware

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// AgentAuthenticator is the slice of AgentService that the secret-only
// agent auth needs. Defining the interface here lets handler tests
// inject a stub without pulling the full service.
type AgentAuthenticator interface {
	Authenticate(ctx context.Context, id uuid.UUID, agentSecret string) error
}

// AgentKeyAuthenticator adds the wire-key check (skills#116): the
// secret first, then the presented key fingerprint against the bound
// key. It returns ErrAgentKeyMismatch (any error for which IsKeyMismatch
// reports true) when only the key check fails.
type AgentKeyAuthenticator interface {
	AgentAuthenticator
	AuthenticateAgentKey(ctx context.Context, id uuid.UUID, agentSecret, fingerprint string) error
	IsKeyMismatch(err error) bool
}

// CtxKeyAgentID is the typed context key carrying the authenticated
// agent's UUID downstream to job handlers.
const CtxKeyAgentID ctxKey = "authenticated_agent_id"

// CtxKeyAgentKeyFingerprint carries the key fingerprint AgentAuth
// checked, so a handler that seals to the agent's key can confirm the
// key did not change since (a rotation between the two reads).
const CtxKeyAgentKeyFingerprint ctxKey = "authenticated_agent_key_fingerprint"

// HeaderAgentKeyFingerprint is the header every Agent request under
// /agents/:id/* carries: "sha256:" plus the hex SHA-256 of its public key.
const HeaderAgentKeyFingerprint = "X-Agent-Key-Fingerprint"

// AgentAuth validates the X-Agent-Secret header against the agent
// referenced by the `:id` URL parameter, then the X-Agent-Key-Fingerprint
// header against the agent's bound public key. On success the
// authenticated agent's UUID (and the checked fingerprint) are stashed
// in the request context for downstream handlers.
//
// An unknown agent AND a wrong secret both return 401 so an attacker
// probing the API can't enumerate agents. A right secret with a missing
// or wrong fingerprint returns 409 {"error":"agent_key_mismatch"}: the
// Agent runs with a key that is not (or no longer) the bound one and
// must restart with the current Secret. The audit log holds the
// distinction (handled at the service layer).
func AgentAuth(authn AgentKeyAuthenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, secret, err := agentCredential(c)
		if err != nil {
			return err
		}
		fp := c.Get(HeaderAgentKeyFingerprint)
		err = authn.AuthenticateAgentKey(c.Context(), id, secret, fp)
		switch {
		case err == nil:
		case authn.IsKeyMismatch(err):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "agent_key_mismatch"})
		default:
			return agentAuthErr(err)
		}
		ctx := context.WithValue(c.Context(), CtxKeyAgentID, id)
		c.SetContext(context.WithValue(ctx, CtxKeyAgentKeyFingerprint, fp))
		return c.Next()
	}
}

// AgentSecretAuth checks X-Agent-Secret only. It guards the key
// rotation endpoints alone: the operator's rotate-key run holds the
// agent credential and the rotation token, and may be replacing a lost
// private key, so it cannot prove the old key.
func AgentSecretAuth(authn AgentAuthenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, secret, err := agentCredential(c)
		if err != nil {
			return err
		}
		if err := authn.Authenticate(c.Context(), id, secret); err != nil {
			return agentAuthErr(err)
		}
		c.SetContext(context.WithValue(c.Context(), CtxKeyAgentID, id))
		return c.Next()
	}
}

func agentCredential(c fiber.Ctx) (uuid.UUID, string, error) {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, "", fiber.NewError(fiber.StatusBadRequest, "invalid agent id")
	}
	secret := c.Get("X-Agent-Secret")
	if secret == "" {
		return uuid.Nil, "", fiber.NewError(fiber.StatusUnauthorized, "X-Agent-Secret header required")
	}
	return id, secret, nil
}

func agentAuthErr(err error) error {
	if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrUnauthorized) {
		return fiber.NewError(fiber.StatusUnauthorized, "agent auth rejected")
	}
	return fiber.NewError(fiber.StatusInternalServerError, "agent auth failed")
}

// AgentIDFromContext returns the authenticated agent UUID written by
// AgentAuth. ok is false when the middleware was not applied — handlers
// behind AgentAuth can rely on ok being true.
func AgentIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v := ctx.Value(CtxKeyAgentID)
	id, ok := v.(uuid.UUID)
	return id, ok
}

// AgentKeyFingerprintFromContext returns the fingerprint AgentAuth
// checked. ok is false behind AgentSecretAuth or without AgentAuth.
func AgentKeyFingerprintFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(CtxKeyAgentKeyFingerprint).(string)
	return v, ok && v != ""
}
