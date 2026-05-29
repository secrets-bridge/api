// Package middleware holds the Fiber middleware stack for the api.
//
// Most middleware in this file is a deliberate STUB during scaffolding:
// the auth, RBAC, and audit handlers wire the request flow without
// implementing real policy. Real implementations land with their
// owning issues (auth/RBAC with storage, audit with workflow).
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

type ctxKey string

const (
	// CtxKeyRequestID is the typed context key for the per-request
	// correlation ID propagated through middleware and handlers.
	CtxKeyRequestID ctxKey = "request_id"

	// CtxKeyActor is the typed context key for the authenticated
	// principal. Stubbed today; populated by real auth later.
	CtxKeyActor ctxKey = "actor"

	headerRequestID = "X-Request-Id"
)

// RequestID assigns a correlation ID to every request, either echoing the
// inbound X-Request-Id header (so callers can supply their own for
// distributed tracing) or generating a fresh one. The ID is set on the
// Fiber locals, the response header, and the underlying context so
// downstream code reads it from whichever surface is most convenient.
func RequestID() fiber.Handler {
	return func(c fiber.Ctx) error {
		id := strings.TrimSpace(c.Get(headerRequestID))
		if id == "" || len(id) > 128 {
			id = newRequestID()
		}
		c.Locals(string(CtxKeyRequestID), id)
		c.Set(headerRequestID, id)
		c.SetContext(context.WithValue(c.Context(), CtxKeyRequestID, id))
		return c.Next()
	}
}

// Logger emits one structured access-log line per request with status,
// duration, and the request ID for correlation with audit events.
func Logger(base *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		base.LogAttrs(c.Context(), slog.LevelInfo, "request",
			slog.String("request_id", requestID(c)),
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Int("status", c.Response().StatusCode()),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote_ip", c.IP()),
		)
		return err
	}
}

// Recover converts a panic into a 500 response and a structured error
// log line so a single bad handler can't take down the process.
func Recover(logger *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.ErrorContext(c.Context(), "panic recovered",
					"request_id", requestID(c),
					"panic", r,
				)
				err = fiber.NewError(fiber.StatusInternalServerError, "internal server error")
			}
		}()
		return c.Next()
	}
}

// Auth is a STUB upgrade ahead of real OIDC (api#26). The middleware
// reads an `X-User-Id` header — when present, it's used verbatim as
// the actor identity; when absent, falls back to the legacy
// "anonymous" placeholder so existing tests + UI flows that don't yet
// know about identity keep working.
//
// This is NOT a security boundary. The header is trivially spoofable
// from any caller and exists ONLY to let downstream RBAC middleware
// (`internal/auth.Require`) be exercised end-to-end before the OIDC
// swap lands. The header reading code is the only piece that changes
// when OIDC arrives — the rest of the platform reads identity from
// `CtxKeyActor` and is agnostic to how it got there.
func Auth() fiber.Handler {
	return func(c fiber.Ctx) error {
		actor := "anonymous"
		if v := c.Get("X-User-Id"); v != "" {
			actor = v
		}
		c.SetContext(context.WithValue(c.Context(), CtxKeyActor, actor))
		return c.Next()
	}
}

// RBAC is a stub. Real RBAC enforces policy by project, environment,
// role, provider, and secret path. Today it allows everything.
func RBAC() fiber.Handler {
	return func(c fiber.Ctx) error {
		return c.Next()
	}
}

// Audit is a stub. Real audit appends an immutable event with the full
// correlation chain. Today it logs a TODO line so missing audit
// coverage is visible during development.
func Audit(logger *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		err := c.Next()
		logger.LogAttrs(c.Context(), slog.LevelDebug, "audit_stub",
			slog.String("request_id", requestID(c)),
			slog.String("actor", actor(c)),
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.Int("status", c.Response().StatusCode()),
			slog.String("note", "TODO: emit immutable audit event with correlation_id"),
		)
		return err
	}
}

// requestID returns the correlation ID from Fiber locals, falling back
// to an empty string if RequestID middleware wasn't registered.
func requestID(c fiber.Ctx) string {
	if v, ok := c.Locals(string(CtxKeyRequestID)).(string); ok {
		return v
	}
	return ""
}

func actor(c fiber.Ctx) string {
	if v, ok := c.Context().Value(CtxKeyActor).(string); ok {
		return v
	}
	return ""
}

// newRequestID returns a 128-bit hex-encoded random ID. The format is
// independent of UUID v4 so we never accidentally claim semantics we
// don't guarantee; downstream consumers should treat it as opaque.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand only returns an error if the OS RNG fails,
		// which is fatal — fall back to a coarse timestamp so the
		// request still gets _some_ ID for log correlation.
		return "fallback-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return hex.EncodeToString(b[:])
}
