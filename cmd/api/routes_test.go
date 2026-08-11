package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

// Fiber matches routes in registration order, so a literal path
// segment registered AFTER a `/:param` route on the same prefix is
// unreachable — the param route wins and the literal segment arrives
// as the parameter value.
//
// That shipped: `GET /requests/inbox` was registered after
// `GET /requests/:id`, so it resolved to the Get handler with
// id="inbox", failed UUID parsing, and returned `400 invalid id`.
// Team B could not list fill work at all.
//
// `/requests/inbox/count` escaped only because no three-segment
// `/requests/:id/...` GET route existed to shadow it — which is why
// the bug looked like an auth quirk on one route rather than a
// routing fault.
func newRequestRoutesTestApp() *fiber.App {
	app := fiber.New()
	mark := func(name string) fiber.Handler {
		return func(c fiber.Ctx) error { return c.SendString(name) }
	}
	requestRoutes{
		submit:          hs(mark("submit")),
		submitRead:      hs(mark("submitRead")),
		list:            hs(mark("list")),
		get:             hs(mark("get")),
		approve:         hs(mark("approve")),
		reject:          hs(mark("reject")),
		cancel:          hs(mark("cancel")),
		inbox:           hs(mark("inbox")),
		inboxCount:      hs(mark("inboxCount")),
		crossTeamSubmit: hs(mark("crossTeamSubmit")),
		fill:            hs(mark("fill")),
		refuse:          hs(mark("refuse")),
		verify:          hs(mark("verify")),
	}.register(app)
	return app
}

func resolve(t *testing.T, app *fiber.App, method, path string) string {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(method, path, nil),
		fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func TestRequestRoutes_LiteralSegmentsWinOverParamRoute(t *testing.T) {
	app := newRequestRoutesTestApp()

	for _, tc := range []struct {
		method, path, want string
	}{
		{http.MethodGet, "/requests/inbox", "inbox"},
		{http.MethodGet, "/requests/inbox/count", "inboxCount"},
		{http.MethodPost, "/requests/read", "submitRead"},
		{http.MethodPost, "/requests/cross-team", "crossTeamSubmit"},
	} {
		if got := resolve(t, app, tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s resolved to %q, want %q (shadowed by a param route?)",
				tc.method, tc.path, got, tc.want)
		}
	}
}

func TestRequestRoutes_ParamRoutesStillResolve(t *testing.T) {
	app := newRequestRoutesTestApp()
	id := "3f2b1c4d-0000-4000-8000-000000000000"

	for _, tc := range []struct {
		method, path, want string
	}{
		{http.MethodGet, "/requests/" + id, "get"},
		{http.MethodPost, "/requests/" + id + "/approve", "approve"},
		{http.MethodPost, "/requests/" + id + "/fill", "fill"},
		{http.MethodPost, "/requests/" + id + "/verify", "verify"},
	} {
		if got := resolve(t, app, tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s resolved to %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}
