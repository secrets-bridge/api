package handlers

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestProbes_Healthz_AlwaysOK(t *testing.T) {
	app := fiber.New()
	p := NewProbes()
	app.Get("/healthz", p.Healthz)

	// Healthz must return 200 even when readiness is explicitly off —
	// liveness probes failing trigger pod restarts, which is the
	// wrong response to a dependency outage.
	p.SetReady(false)

	resp, err := app.Test(httptest.NewRequest("GET", "/healthz", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("healthz status: got %d want %d", resp.StatusCode, fiber.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("healthz body: %q", body)
	}
}

func TestProbes_Readyz_GatedByState(t *testing.T) {
	app := fiber.New()
	p := NewProbes()
	app.Get("/readyz", p.Readyz)

	// Default constructor state is ready=true.
	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("ready=true status: got %d want %d", resp.StatusCode, fiber.StatusOK)
	}

	// Flip the gate and confirm we return 503 — kubelet should remove
	// the pod from the Service endpoints during a real outage.
	p.SetReady(false)
	resp2, err := app.Test(httptest.NewRequest("GET", "/readyz", nil))
	if err != nil {
		t.Fatalf("Test (not ready): %v", err)
	}
	if resp2.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("ready=false status: got %d want %d", resp2.StatusCode, fiber.StatusServiceUnavailable)
	}
}

func TestMetrics_ServesPromText(t *testing.T) {
	app := fiber.New()
	app.Get("/metrics", Metrics)

	resp, err := app.Test(httptest.NewRequest("GET", "/metrics", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("metrics status: got %d want %d", resp.StatusCode, fiber.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	// promhttp default registry surfaces process_* and go_* metrics
	// from runtime instrumentation; one of these is enough proof the
	// expfmt encoder ran.
	if !strings.Contains(string(body), "go_") && !strings.Contains(string(body), "process_") {
		t.Fatalf("metrics body looks empty: %q", string(body[:min(200, len(body))]))
	}
}
