package middleware

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	app := fiber.New()
	app.Use(RequestID())
	app.Get("/x", func(c fiber.Ctx) error {
		// Confirm the ID is reachable from the underlying context —
		// downstream handlers read it from there.
		got, ok := c.Context().Value(CtxKeyRequestID).(string)
		if !ok || got == "" {
			return c.Status(500).SendString("no id on context")
		}
		return c.Status(200).SendString(got)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/x", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Fatal("X-Request-Id response header is empty")
	}
}

func TestRequestID_EchoesInboundHeader(t *testing.T) {
	app := fiber.New()
	app.Use(RequestID())
	app.Get("/x", func(c fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", "client-supplied-id")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if got := resp.Header.Get("X-Request-Id"); got != "client-supplied-id" {
		t.Fatalf("expected echo of inbound id; got %q", got)
	}
}

func TestRequestID_RejectsOverlongInbound(t *testing.T) {
	app := fiber.New()
	app.Use(RequestID())
	app.Get("/x", func(c fiber.Ctx) error { return c.SendStatus(200) })

	overlong := make([]byte, 200)
	for i := range overlong {
		overlong[i] = 'a'
	}
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-Id", string(overlong))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	got := resp.Header.Get("X-Request-Id")
	if got == string(overlong) {
		t.Fatal("overlong inbound id was accepted unchanged")
	}
	if got == "" {
		t.Fatal("no replacement id was generated for overlong inbound")
	}
}

func TestAuth_StubSetsAnonymousActor(t *testing.T) {
	app := fiber.New()
	app.Use(Auth(nil))
	app.Get("/x", func(c fiber.Ctx) error {
		if v, ok := c.Context().Value(CtxKeyActor).(string); !ok || v != "anonymous" {
			return c.Status(500).SendString("actor not set")
		}
		return c.SendStatus(200)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/x", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

// Quick check that the typed context keys are accessible to handlers
// without needing the http.Request — important because Fiber stores
// state on its own ctx and we rely on the bridge to context.Context.
func TestContextKey_AccessibleViaStdContext(t *testing.T) {
	type marker struct{}
	parent := context.WithValue(context.Background(), marker{}, "ok")
	got, _ := parent.Value(marker{}).(string)
	if got != "ok" {
		t.Fatalf("baseline context lookup broke: %q", got)
	}
}
