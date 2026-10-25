package middleware

import (
	"context"
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// GatewaySecretHeader carries the gateway secret on the gateway machine
// routes (api#293). It is not X-Agent-Secret, and AgentAuth never reads
// it: the two credentials authenticate disjoint route groups.
const GatewaySecretHeader = "X-Gateway-Secret"

// GatewayAuthenticator is the slice of GatewayService GatewayAuth needs.
type GatewayAuthenticator interface {
	Authenticate(ctx context.Context, id uuid.UUID, secret string) error
}

// CtxKeyGatewayID carries the authenticated Gateway's id.
const CtxKeyGatewayID ctxKey = "authenticated_gateway_id"

// GatewayAuth validates X-Gateway-Secret against the Gateway named by the
// `:id` path parameter. A malformed id, a missing header, an unknown
// Gateway, a revoked one and a wrong secret all get the same generic
// 401 `{"error":"unauthorized"}`; the reason goes to the audit log.
func GatewayAuth(authn GatewayAuthenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil || id.String() != c.Params("id") {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		secret := c.Get(GatewaySecretHeader)
		if secret == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		err = authn.Authenticate(c.Context(), id, secret)
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrUnauthorized):
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		case err != nil:
			return err // 500, generic body from the error handler
		}
		c.SetContext(context.WithValue(c.Context(), CtxKeyGatewayID, id))
		return c.Next()
	}
}

// GatewayIDFromContext returns the Gateway id GatewayAuth authenticated.
func GatewayIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(CtxKeyGatewayID).(uuid.UUID)
	return id, ok
}

// ByAuthenticatedGateway keys a rate-limit bucket on the Gateway that
// GatewayAuth authenticated, never on the path id, so an unauthenticated
// caller cannot spend a real Gateway's budget. It must run after
// GatewayAuth; without an authenticated Gateway the request is not
// bucketed (GatewayAuth has refused it already).
func ByAuthenticatedGateway() BucketFunc {
	return func(c fiber.Ctx) (string, bool) {
		id, ok := GatewayIDFromContext(c.Context())
		if !ok {
			return "", false
		}
		return id.String(), true
	}
}

// BodyLimit answers 413 `{"error":"payload_too_large"}` for a body over
// n bytes, before any decoding.
func BodyLimit(n int) fiber.Handler { return BodyLimitCode(n, "payload_too_large") }

// BodyLimitCode is BodyLimit answering code instead. The E8 discovery
// upload answers catalog_too_large (api#308).
func BodyLimitCode(n int, code string) fiber.Handler {
	return func(c fiber.Ctx) error {
		if cl := c.Get(fiber.HeaderContentLength); cl != "" {
			if v, err := strconv.Atoi(cl); err == nil && v > n {
				return fiber.NewError(fiber.StatusRequestEntityTooLarge, code)
			}
		}
		if len(c.Body()) > n {
			return fiber.NewError(fiber.StatusRequestEntityTooLarge, code)
		}
		return c.Next()
	}
}
