// Package handlers contains the HTTP handlers exposed by the api.
//
// Handlers are intentionally thin: they parse the request, call into a
// service, and serialize the response. Business logic belongs in
// internal/services; persistence belongs in pkg/storage.
package handlers

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
)

// ReadinessCheck reports whether a backing dependency (Postgres, Redis,
// OIDC issuer, ...) is currently usable. The implementation should be
// cheap — Readyz runs every registered check on every probe — and
// must respect the supplied context's deadline.
type ReadinessCheck func(ctx context.Context) error

// Probes serves Kubernetes liveness and readiness probes.
//
// Healthz is unconditionally 200 once the process can answer HTTP —
// its only job is to detect a deadlocked or paniced process. Readyz
// runs every registered ReadinessCheck and reports 200 only when they
// all return nil. A nil-check registry is treated as "ready" so the
// scaffold-only api in early development still answers green.
type Probes struct {
	gate atomic.Bool

	mu     sync.RWMutex
	checks map[string]ReadinessCheck
}

// NewProbes returns a Probes handler that starts in the gated-ready
// state with no registered dependency checks. Callers that need a
// dependency gate call AddReadinessCheck before the manager starts.
func NewProbes() *Probes {
	p := &Probes{checks: map[string]ReadinessCheck{}}
	p.gate.Store(true)
	return p
}

// AddReadinessCheck registers fn under name. Re-registering a name
// replaces the previous check.
func (p *Probes) AddReadinessCheck(name string, fn ReadinessCheck) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checks[name] = fn
}

// SetReady toggles the manual readiness gate. Useful during graceful
// shutdown — main can flip the gate to drain in-flight requests.
func (p *Probes) SetReady(v bool) { p.gate.Store(v) }

// Healthz reports process liveness. It must never block on a backing
// dependency, otherwise a transient Redis outage would loop-restart
// every api pod.
func (p *Probes) Healthz(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
}

// Readyz reports whether the api can serve real traffic. Each
// registered check runs against a 2-second context deadline so a
// stuck Postgres connect can't hold Readyz hostage. A single failed
// check produces a 503 with per-check details so kubectl describe
// surfaces which dependency is the problem.
func (p *Probes) Readyz(c fiber.Ctx) error {
	if !p.gate.Load() {
		return c.Status(fiber.StatusServiceUnavailable).
			JSON(fiber.Map{"status": "not_ready", "reason": "manual_gate"})
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.checks) == 0 {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ready"})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
	defer cancel()

	failures := map[string]string{}
	for name, fn := range p.checks {
		if err := fn(ctx); err != nil {
			failures[name] = err.Error()
		}
	}
	if len(failures) > 0 {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":   "not_ready",
			"failures": failures,
		})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ready"})
}
