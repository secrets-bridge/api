package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/middleware"
)

func newErrorHandlerTestApp() *fiber.App {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := fiber.New(fiber.Config{ErrorHandler: jsonErrorHandler(logger)})
	app.Use(middleware.RequestID())
	// A fiber error on the 500 path whose message carries internal detail.
	app.Get("/boom", func(c fiber.Ctx) error {
		return fiber.NewError(fiber.StatusInternalServerError,
			`pgx: relation "secret_wraps" does not exist at /internal/path`)
	})
	// A non-fiber error → defaults to 500 in the handler.
	app.Get("/rawboom", func(c fiber.Ctx) error {
		return io.ErrUnexpectedEOF
	})
	// A 4xx carrying an intentional, client-facing message.
	app.Get("/client", func(c fiber.Ctx) error {
		return fiber.NewError(fiber.StatusBadRequest, "step-up required")
	})
	return app
}

func doGet(t *testing.T, app *fiber.App, path string) (int, string, http.Header) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b), resp.Header
}

// 5xx bodies must be generic, JSON, carry a correlation ID matching the
// response header, and never echo the internal error text.
func TestErrorHandler_5xxIsGenericAndLeaksNothing(t *testing.T) {
	app := newErrorHandlerTestApp()
	for _, path := range []string{"/boom", "/rawboom"} {
		code, body, hdr := doGet(t, app, path)
		if code != http.StatusInternalServerError {
			t.Fatalf("%s: status = %d; want 500", path, code)
		}
		for _, leak := range []string{"pgx", "secret_wraps", "/internal/path", "EOF"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: 500 body leaks %q: %s", path, leak, body)
			}
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("%s: body not JSON: %v (%s)", path, err, body)
		}
		if m["error"] != "internal server error" {
			t.Errorf("%s: error field = %v; want generic message", path, m["error"])
		}
		rid, _ := m["correlation_id"].(string)
		if rid == "" {
			t.Errorf("%s: missing correlation_id in body", path)
		}
		if h := hdr.Get("X-Request-Id"); h == "" || h != rid {
			t.Errorf("%s: body correlation_id %q != X-Request-Id header %q", path, rid, h)
		}
		if ct := hdr.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s: content-type = %q; want application/json", path, ct)
		}
	}
}

// 4xx messages are intentional and must reach the client unchanged.
func TestErrorHandler_4xxMessagePassesThrough(t *testing.T) {
	app := newErrorHandlerTestApp()
	code, body, _ := doGet(t, app, "/client")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", code)
	}
	if !strings.Contains(body, "step-up required") {
		t.Errorf("4xx body should keep the client message; got %s", body)
	}
}
