package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

// Identity-from-session tests for the API-01 (approve) and API-02
// (wrap-list) findings. They reuse the scope-isolation fixture, which
// wires the real Auth middleware + the request handlers. DB-backed:
// SKIP without TEST_DATABASE_URL, same as the sibling suites.

func (fx *scopeIsoFixture) doPostJSON(t *testing.T, path string, userID uuid.UUID, jsonBody string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", userID.String())
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// API-01: the approver is the authenticated session identity, never a
// body field. An earlier version read `approver_id` from the JSON body,
// so an authenticated user could approve any request as any borrowed
// approver — including their own. The field is gone; a spoofed
// `approver_id` in the body must be ignored.
//
//   - The requester approving their OWN request (with a spoofed
//     approver_id naming a different user) must be refused as
//     self-approval — proving the acting identity is the session, not
//     the body.
//   - A different authenticated user is the real approver and succeeds.
func TestApprove_UsesSessionIdentityNotBody(t *testing.T) {
	fx := bootstrapScopeIso(t)

	// billingDev owns billingDevReq. Approving it while authenticated as
	// billingDev must be a self-approval 403 even though the body names a
	// different approver — the body value is ignored.
	st, body := fx.doPostJSON(t,
		"/api/v1/requests/"+fx.billingDevReq.String()+"/approve",
		fx.billingDev,
		`{"approver_id":"`+uuid.New().String()+`","comment":"spoof attempt"}`)
	if st != http.StatusForbidden {
		t.Fatalf("self-approve with spoofed approver_id = %d body=%s; want 403 (body id must be ignored)", st, body)
	}

	// A different authenticated user is the real approver: the vote is
	// recorded under THEIR session identity and the single-approver
	// workflow transitions the request to approved.
	st, body = fx.doPostJSON(t,
		"/api/v1/requests/"+fx.billingDevReq.String()+"/approve",
		fx.policyAuthor,
		`{}`)
	if st != http.StatusOK {
		t.Fatalf("approver POST /approve = %d body=%s; want 200", st, body)
	}
	if !strings.Contains(body, "approved") {
		t.Errorf("approve response did not report approved status: %s", body)
	}
}

// API-02: the wrap-list endpoint authorizes on the session identity, not
// a `user_id` query param. An earlier version compared ownership against
// the caller-supplied query value, so any authenticated user could pass
// the owner's id and read their wrap metadata. The query param must now
// be ignored.
//
//   - A non-owner passing the owner's id in ?user_id= is still refused.
//   - The owner (whatever the query param says) is allowed.
func TestListWraps_UsesSessionIdentityNotQueryParam(t *testing.T) {
	fx := bootstrapScopeIso(t)

	// policyAuthor is NOT the owner of billingDevReq. Spoofing
	// ?user_id=<billingDev> must not grant access — the session identity
	// (policyAuthor) is what's checked.
	st, body := fx.doGet(t,
		"/api/v1/requests/"+fx.billingDevReq.String()+"/wraps?user_id="+fx.billingDev.String(),
		fx.policyAuthor)
	if st != http.StatusForbidden {
		t.Fatalf("non-owner list wraps with spoofed user_id = %d body=%s; want 403", st, body)
	}

	// The owner is allowed even when the query param names someone else —
	// the param is ignored, the session identity governs.
	st, body = fx.doGet(t,
		"/api/v1/requests/"+fx.billingDevReq.String()+"/wraps?user_id="+uuid.New().String(),
		fx.billingDev)
	if st != http.StatusOK {
		t.Fatalf("owner list wraps = %d body=%s; want 200 (query param ignored)", st, body)
	}
}
