package middleware

import "github.com/gofiber/fiber/v3"

// NoStore marks every response on the routes it wraps as uncacheable:
// `Cache-Control: no-store` plus `Pragma: no-cache` for HTTP/1.0
// caches (API-S-20).
//
// It is mounted on the whole /api/v1 group rather than on a hand-kept
// list of secret-bearing routes. The API serves JSON only, so nothing
// relies on HTTP caching of its responses, and a global header means a
// route added later (one more token, one more wrap) is covered without
// anyone remembering to opt in. Responses that matter most: wrap and
// reveal value pickup, login tokens, enrollment tokens, agent
// credentials, DEK issuance and the TOTP enrollment seed.
//
// The headers are set BEFORE the handler runs so error responses
// rendered by the app error handler carry them too. A handler that
// deliberately sets its own Cache-Control (the static permission
// catalog) keeps it; the Pragma header is dropped in that case so the
// two never disagree.
func NoStore() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set(fiber.HeaderCacheControl, "no-store")
		c.Set(fiber.HeaderPragma, "no-cache")
		err := c.Next()
		if string(c.Response().Header.Peek(fiber.HeaderCacheControl)) != "no-store" {
			c.Response().Header.Del(fiber.HeaderPragma)
		}
		return err
	}
}
