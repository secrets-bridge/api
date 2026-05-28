// Package handlers contains the HTTP handlers exposed by the api.
//
// Handlers are intentionally thin: they parse the request, call into a
// service, and serialize the response. Business logic belongs in
// internal/services; persistence belongs in pkg/storage.
package handlers

import (
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
)

// Probes serves Kubernetes liveness and readiness probes.
//
// Healthz is unconditionally 200 once the process can answer HTTP — its
// only job is to detect a deadlocked or paniced process. Readyz returns
// 200 only after every backing dependency the api needs (Postgres,
// Redis, OIDC issuer) reports healthy. During scaffolding the readiness
// gate is open by default; real checks are registered as their owning
// packages land.
type Probes struct {
	ready atomic.Bool
}

// NewProbes returns a Probes handler that starts in the ready state.
// Once real dependencies are wired, the constructor will accept their
// health-check functions and the readiness gate will default closed
// until the first successful check.
func NewProbes() *Probes {
	p := &Probes{}
	p.ready.Store(true)
	return p
}

// Healthz reports process liveness. It must never block on a backing
// dependency, otherwise a transient Redis outage would loop-restart
// every api pod.
func (p *Probes) Healthz(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
}

// Readyz reports whether the api can serve real traffic. Today every
// scaffolded api returns ready=true; once pkg/storage and pkg/runtime
// land they will register checks via SetReady.
func (p *Probes) Readyz(c fiber.Ctx) error {
	if !p.ready.Load() {
		return c.Status(fiber.StatusServiceUnavailable).
			JSON(fiber.Map{"status": "not_ready"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ready"})
}

// SetReady toggles the readiness gate. Wiring will move to a check
// registry once pkg/storage and pkg/runtime exist; the setter is
// exported now so wiring code can flip the gate without touching the
// internals.
func (p *Probes) SetReady(v bool) { p.ready.Store(v) }
