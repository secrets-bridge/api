package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
)

// accessLogResolver grants `policy.edit` to "admin" and nothing to
// anyone else.
type accessLogResolver struct{}

func (accessLogResolver) Resolve(_ context.Context, userID string) ([]auth.Grant, error) {
	if userID == "admin" {
		return []auth.Grant{{Permission: "policy.edit"}}, nil
	}
	return nil, nil
}

// newAccessLogTestApp mounts the production middleware order (request
// ID, logger, recover, session gate) in front of routes that fail in
// each way a real route can fail. Every log line goes to `logs`.
func newAccessLogTestApp(logs *bytes.Buffer) *fiber.App {
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	app := fiber.New(fiber.Config{ErrorHandler: jsonErrorHandler(logger)})
	app.Use(middleware.RequestID())
	app.Use(middleware.Logger(logger))
	app.Use(middleware.Recover(logger))

	// Identity comes from a test header here; the real AuthWith writes
	// the same context key.
	app.Use(func(c fiber.Ctx) error {
		actor := "anonymous"
		if v := c.Get("X-Test-Actor"); v != "" {
			actor = v
		}
		c.SetContext(context.WithValue(c.Context(), middleware.CtxKeyActor, actor))
		return c.Next()
	})
	app.Use(middleware.RequireAuthedExcept(map[string]bool{"/ok": true, "/written": true}))

	ok := func(c fiber.Ctx) error { return c.SendString("ok") }
	app.Get("/ok", ok)
	app.Get("/written", func(c fiber.Ctx) error {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "conflict"})
	})
	app.Get("/policies", auth.Require("policy.edit", accessLogResolver{}), ok)
	app.Get("/wrapped", func(c fiber.Ctx) error {
		return fmt.Errorf("lookup: %w", fiber.NewError(fiber.StatusNotFound, "not found"))
	})
	app.Get("/plain", func(c fiber.Ctx) error { return errors.New("db down") })
	app.Get("/panic", func(c fiber.Ctx) error { panic("boom") })
	return app
}

// logLines returns the log lines in logs whose msg is `msg`.
func logLines(t *testing.T, logs *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(logs.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", sc.Text())
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// The access log must record the status the client actually received,
// including errors that the app error handler renders after the
// middleware chain returns (api#248).
func TestAccessLog_StatusMatchesResponse(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		actor  string
		status int
	}{
		{name: "normal 200", path: "/ok", status: 200},
		{name: "status written by handler", path: "/written", status: 409},
		{name: "401 from session gate", path: "/policies", status: 401},
		{name: "403 from auth.Require", path: "/policies", actor: "viewer", status: 403},
		{name: "200 through auth.Require", path: "/policies", actor: "admin", status: 200},
		{name: "wrapped fiber error", path: "/wrapped", actor: "admin", status: 404},
		{name: "plain error is 500", path: "/plain", actor: "admin", status: 500},
		{name: "recovered panic is 500", path: "/panic", actor: "admin", status: 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			app := newAccessLogTestApp(&logs)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.actor != "" {
				req.Header.Set("X-Test-Actor", tc.actor)
			}
			resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("response status = %d, want %d (body %s)", resp.StatusCode, tc.status, body)
			}
			if tc.status >= 400 && !strings.Contains(resp.Header.Get(fiber.HeaderContentType), "json") {
				t.Fatalf("error response must still be rendered by the JSON error handler, got %q", resp.Header.Get(fiber.HeaderContentType))
			}

			lines := logLines(t, &logs, "request")
			if len(lines) != 1 {
				t.Fatalf("got %d access log lines, want exactly 1: %s", len(lines), logs.String())
			}
			got, _ := lines[0]["status"].(float64)
			if int(got) != resp.StatusCode {
				t.Fatalf("access log status = %v, response status = %d", lines[0]["status"], resp.StatusCode)
			}
			// The error handler ran exactly once: one server-side
			// "request failed" line per 5xx, none otherwise.
			wantFailed := 0
			if tc.status >= 500 {
				wantFailed = 1
			}
			if n := len(logLines(t, &logs, "request failed")); n != wantFailed {
				t.Fatalf("got %d \"request failed\" lines, want %d: %s", n, wantFailed, logs.String())
			}
			// The access log carries no body or error text.
			for _, k := range []string{"body", "error", "err"} {
				if _, present := lines[0][k]; present {
					t.Fatalf("access log line must not carry %q: %v", k, lines[0])
				}
			}
		})
	}
}
