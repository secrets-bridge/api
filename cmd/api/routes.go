package main

import "github.com/gofiber/fiber/v3"

// hs is sugar for building a handler chain (middleware first, final
// handler last) in the literal below. Fiber takes variadic handlers
// per route and drives `c.Next()` between them, so the chain must be
// handed over intact rather than composed by hand.
func hs(h ...fiber.Handler) []fiber.Handler { return h }

// requestRoutes bundles the handler chains for the `/requests`
// family. Fields are handler slices rather than the concrete handler
// structs so registration ORDER can be exercised in a test without a
// database — see routes_test.go.
type requestRoutes struct {
	submit     []fiber.Handler
	submitRead []fiber.Handler
	list       []fiber.Handler
	get        []fiber.Handler
	approve    []fiber.Handler
	reject     []fiber.Handler
	cancel     []fiber.Handler

	// Slice N3 — cross-team flow.
	inbox           []fiber.Handler
	inboxCount      []fiber.Handler
	crossTeamSubmit []fiber.Handler
	fill            []fiber.Handler
	refuse          []fiber.Handler
	verify          []fiber.Handler
}

// register wires the `/requests` family onto r.
//
// ORDERING IS LOAD-BEARING. Fiber matches in registration order, so
// every LITERAL path segment (`read`, `inbox`, `cross-team`) MUST be
// registered before the `/requests/:id` param route. Register `:id`
// first and Fiber matches it for `/requests/inbox`, binding
// id="inbox", which fails UUID parsing and returns `400 invalid id` —
// the literal route becomes unreachable.
//
// This is not hypothetical: it shipped that way and blocked Team B
// from listing cross-team fill work. Keep every literal registration
// above the `:id` divider.
// mount adapts a handler chain onto Fiber v3's
// `(path, handler any, middleware ...any)` router signature, which a
// []fiber.Handler cannot spread into directly.
func mount(m func(string, any, ...any) fiber.Router, path string, chain []fiber.Handler) {
	if len(chain) == 0 {
		return
	}
	rest := make([]any, 0, len(chain)-1)
	for _, h := range chain[1:] {
		rest = append(rest, h)
	}
	m(path, chain[0], rest...)
}

func (rr requestRoutes) register(r fiber.Router) {
	// ---- literal paths — MUST stay above the :id divider ----------
	mount(r.Post, "/requests", rr.submit)
	mount(r.Get, "/requests", rr.list)
	mount(r.Post, "/requests/read", rr.submitRead)
	mount(r.Get, "/requests/inbox", rr.inbox)
	mount(r.Get, "/requests/inbox/count", rr.inboxCount)
	mount(r.Post, "/requests/cross-team", rr.crossTeamSubmit)

	// ---- :id divider — nothing literal below this line ------------
	mount(r.Get, "/requests/:id", rr.get)
	mount(r.Post, "/requests/:id/approve", rr.approve)
	mount(r.Post, "/requests/:id/reject", rr.reject)
	mount(r.Post, "/requests/:id/cancel", rr.cancel)
	mount(r.Post, "/requests/:id/fill", rr.fill)
	mount(r.Post, "/requests/:id/refuse", rr.refuse)
	mount(r.Post, "/requests/:id/verify", rr.verify)
}
