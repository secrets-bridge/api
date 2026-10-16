package handlers

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/pkg/sanitize"
)

// logInternalError records the detail of an internal failure (storage,
// KMS, Redis, provider, network) server side, for the paths that answer
// the client with a stable message of their own instead of handing the
// error to the app error handler (API-16). The text goes through
// sanitize.LogError and is tagged with the request ID the client also
// sees, so support can correlate without the client ever seeing the
// detail.
//
// slog.Default is the process JSON logger (main calls slog.SetDefault).
func logInternalError(c fiber.Ctx, msg string, err error) {
	if err == nil {
		return
	}
	rid, _ := c.Locals(string(middleware.CtxKeyRequestID)).(string)
	slog.Default().Error(msg,
		"err", sanitize.LogError(err.Error()),
		"method", c.Method(),
		"path", c.Path(),
		"request_id", rid,
	)
}
