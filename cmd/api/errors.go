package main

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
)

// jsonErrorHandler renders every error as a JSON body so typed clients
// (the SPA's client.ts) can parse `{"error": ...}` instead of Fiber v3's
// default plain-text output, which the SPA would otherwise surface as the
// literal `HTTP <status>` placeholder.
//
// 5xx bodies are GENERIC. A raw err.Error() on the 500 path can carry
// wrapped Go/pgx text (database structure, provider config, internal
// paths), so the real error is logged server-side with the request's
// correlation ID and the client receives only a generic message plus that
// ID for support correlation. 4xx errors carry intentional, safe,
// human-facing messages (for example the step-up modal reason) that the
// SPA relies on, so those pass through unchanged.
func jsonErrorHandler(logger *slog.Logger) func(fiber.Ctx, error) error {
	return func(c fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		var fe *fiber.Error
		if errors.As(err, &fe) {
			code = fe.Code
		}

		// Preserve any headers the route handler set (for example
		// RequireFreshMFA's `WWW-Authenticate: step-up` challenge).
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

		if code >= fiber.StatusInternalServerError {
			rid, _ := c.Locals(string(middleware.CtxKeyRequestID)).(string)
			logger.Error("request failed",
				"err", err.Error(),
				"status", code,
				"method", c.Method(),
				"path", c.Path(),
				"request_id", rid,
			)
			return c.Status(code).JSON(fiber.Map{
				"error":          "internal server error",
				"correlation_id": rid,
			})
		}

		return c.Status(code).JSON(fiber.Map{"error": err.Error()})
	}
}
