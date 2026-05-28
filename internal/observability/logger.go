// Package observability provides structured logging, metrics, and (later)
// tracing primitives shared across the api binary.
package observability

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger builds a JSON structured logger writing to stderr at the
// level requested by the LOG_LEVEL env var (debug | info | warn | error).
// Anything unrecognized falls back to info.
func NewLogger(levelStr string) *slog.Logger {
	level := parseLevel(levelStr)
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     level,
		AddSource: false,
	})
	return slog.New(h).With("service", "secrets-bridge-api")
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
