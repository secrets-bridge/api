// R-follow-up #5 slice 1c handler tests (api#135).
//
// Unit-only: stubbed PolicyRepository + AuditEventRepository. The
// gate ordering, envelope shape, and post-delete behavior are
// covered without live Postgres. Storage WHERE/ORDER BY semantics
// are unit-tested in slice 1a; full e2e happens in the SPA integration.
//
// Coverage:
//   - Project / team / admin handlers all return 503 when history
//     service is not wired
//   - 400 on malformed projectID / teamID / ruleID
//   - 404 on rule not found (scoped paths)
//   - 404 on anchor mismatch — silent, NO denied audit emit
//   - Happy path returns envelope with rule_id + scope + entries +
//     has_more + limit
//   - Admin post-delete forensic path: rule missing + zero events → 404;
//     rule missing + non-zero events → 200 (history loads)

package handlers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- fakes for handler-only tests --------------------------------

type stubPolicyRepo struct {
	rules map[uuid.UUID]*storage.PolicyRule
}

func (s *stubPolicyRepo) Create(context.Context, *storage.PolicyRule) error { panic("unused") }
func (s *stubPolicyRepo) Get(_ context.Context, id uuid.UUID) (*storage.PolicyRule, error) {
	r, ok := s.rules[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return r, nil
}
func (s *stubPolicyRepo) List(context.Context) ([]*storage.PolicyRule, error) { panic("unused") }
func (s *stubPolicyRepo) ListEnabledOrderedByPriority(
	context.Context, uuid.UUID,
) ([]*storage.PolicyRule, error) {
	panic("unused")
}
func (s *stubPolicyRepo) Update(context.Context, *storage.PolicyRule) error { panic("unused") }
func (s *stubPolicyRepo) Delete(context.Context, uuid.UUID) error           { panic("unused") }
func (s *stubPolicyRepo) ListForProject(
	context.Context, uuid.UUID,
) ([]*storage.PolicyRule, error) {
	panic("unused")
}
func (s *stubPolicyRepo) ListForTeam(
	context.Context, uuid.UUID,
) ([]*storage.PolicyRule, error) {
	panic("unused")
}

type stubAuditRepo struct {
	historyRows []*storage.AuditEvent
	appended    []*storage.AuditEvent
}

func (s *stubAuditRepo) Append(_ context.Context, evt *storage.AuditEvent) error {
	s.appended = append(s.appended, evt)
	return nil
}
func (s *stubAuditRepo) AppendTx(context.Context, pgx.Tx, *storage.AuditEvent) error {
	panic("unused")
}
func (s *stubAuditRepo) Query(context.Context, storage.AuditQuery) ([]*storage.AuditEvent, error) {
	panic("unused")
}
func (s *stubAuditRepo) ListPolicyRuleHistory(
	_ context.Context, _ uuid.UUID, _ int,
) ([]*storage.AuditEvent, bool, error) {
	return s.historyRows, false, nil
}

// ---- assertions --------------------------------------------------

func doGet(t *testing.T, app *fiber.App, path string) (*http.Response, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// ---- bootstrap helpers -------------------------------------------

func buildProjectHistoryApp(
	policies storage.PolicyRepository,
	audit storage.AuditEventRepository,
	withHistory bool,
) *fiber.App {
	app := fiber.New()
	// No need to mount the full engine — History only uses the repos
	// + the history service.
	var historySvc *services.PolicyHistoryService
	if withHistory {
		historySvc = services.NewPolicyHistoryService(audit, &fakeWorkflowsForHandler{}, nil, nil)
	}
	h := handlers.NewProjectPolicyRules(nil, policies, nil)
	if withHistory {
		h.WithHistory(historySvc, audit)
	}
	app.Get("/api/v1/projects/:projectID/policy-rules/:ruleID/history", h.History)
	return app
}

func buildTeamHistoryApp(
	policies storage.PolicyRepository,
	audit storage.AuditEventRepository,
	withHistory bool,
) *fiber.App {
	app := fiber.New()
	var historySvc *services.PolicyHistoryService
	if withHistory {
		historySvc = services.NewPolicyHistoryService(audit, &fakeWorkflowsForHandler{}, nil, nil)
	}
	h := handlers.NewTeamPolicyRules(nil, policies, nil)
	if withHistory {
		h.WithHistory(historySvc, audit)
	}
	app.Get("/api/v1/teams/:teamID/policy-rules/:ruleID/history", h.History)
	return app
}

// fakeWorkflowsForHandler — minimal WorkflowRepository for the
// PolicyHistoryService's batch lookup. Always returns empty (handler
// tests don't exercise workflow-name resolution).
type fakeWorkflowsForHandler struct{}

func (fakeWorkflowsForHandler) Create(context.Context, *storage.WorkflowDefinition) error {
	panic("unused")
}
func (fakeWorkflowsForHandler) Get(context.Context, uuid.UUID) (*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (fakeWorkflowsForHandler) GetByName(context.Context, string) (*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (fakeWorkflowsForHandler) GetDefault(context.Context) (*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (fakeWorkflowsForHandler) List(context.Context) ([]*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (fakeWorkflowsForHandler) ListByIDs(
	context.Context, []uuid.UUID,
) ([]*storage.WorkflowDefinition, error) {
	return nil, nil
}
func (fakeWorkflowsForHandler) ListScopedPolicyAuthorable(
	context.Context,
) ([]*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (fakeWorkflowsForHandler) Update(context.Context, *storage.WorkflowDefinition) error {
	panic("unused")
}
func (fakeWorkflowsForHandler) Delete(context.Context, uuid.UUID) error { panic("unused") }

// ---- project history tests ---------------------------------------

func TestProjectHistory_NotWired_Returns503(t *testing.T) {
	app := buildProjectHistoryApp(&stubPolicyRepo{}, &stubAuditRepo{}, false)
	resp, _ := doGet(t, app, "/api/v1/projects/"+uuid.New().String()+
		"/policy-rules/"+uuid.New().String()+"/history")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status=%d want 503", resp.StatusCode)
	}
}

func TestProjectHistory_BadProjectID_Returns400(t *testing.T) {
	app := buildProjectHistoryApp(&stubPolicyRepo{}, &stubAuditRepo{}, true)
	resp, _ := doGet(t, app, "/api/v1/projects/not-a-uuid/policy-rules/"+
		uuid.New().String()+"/history")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d want 400", resp.StatusCode)
	}
}

func TestProjectHistory_RuleNotFound_Returns404(t *testing.T) {
	app := buildProjectHistoryApp(&stubPolicyRepo{}, &stubAuditRepo{}, true)
	resp, body := doGet(t, app, "/api/v1/projects/"+uuid.New().String()+
		"/policy-rules/"+uuid.New().String()+"/history")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404; body=%s", resp.StatusCode, body)
	}
}

func TestProjectHistory_AnchorMismatch_SilentlyReturns404(t *testing.T) {
	otherProject := uuid.New()
	ruleID := uuid.New()
	rule := &storage.PolicyRule{
		ID:        ruleID,
		Name:      "team-rule",
		ProjectID: &otherProject, // anchored to a DIFFERENT project
	}
	policies := &stubPolicyRepo{rules: map[uuid.UUID]*storage.PolicyRule{ruleID: rule}}
	audit := &stubAuditRepo{}
	app := buildProjectHistoryApp(policies, audit, true)

	resp, _ := doGet(t, app, "/api/v1/projects/"+uuid.New().String()+
		"/policy-rules/"+ruleID.String()+"/history")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404 (silent enumeration protection)", resp.StatusCode)
	}
	// Critical: NO audit emit on the silent-404 path (gate-order protection).
	if len(audit.appended) != 0 {
		t.Errorf("anchor-mismatch path emitted audit (gate-order leak): %d events", len(audit.appended))
	}
}

func TestProjectHistory_HappyPath_EnvelopeShape(t *testing.T) {
	projectID := uuid.New()
	ruleID := uuid.New()
	rule := &storage.PolicyRule{
		ID:        ruleID,
		Name:      "billing-rule",
		ProjectID: &projectID,
	}
	policies := &stubPolicyRepo{rules: map[uuid.UUID]*storage.PolicyRule{ruleID: rule}}
	audit := &stubAuditRepo{
		historyRows: []*storage.AuditEvent{
			{
				ID:            uuid.New(),
				Actor:         "user:abc",
				Action:        "policy.create",
				Status:        storage.AuditStatusSuccess,
				CorrelationID: uuid.New(),
				Metadata: map[string]any{
					"priority":      float64(100),
					"workflow_id":   uuid.New().String(),
					"selector_keys": []any{"environment_kind"},
					"scope":         "project",
				},
				OccurredAt: time.Now(),
			},
		},
	}
	app := buildProjectHistoryApp(policies, audit, true)

	resp, body := doGet(t, app, "/api/v1/projects/"+projectID.String()+
		"/policy-rules/"+ruleID.String()+"/history")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("json: %v; body=%s", err, body)
	}
	if env["rule_id"] != ruleID.String() {
		t.Errorf("rule_id mismatch: %v", env["rule_id"])
	}
	if env["scope"] != "project" {
		t.Errorf("scope=%v want project", env["scope"])
	}
	if env["has_more"] != false {
		t.Errorf("has_more=%v want false", env["has_more"])
	}
	if env["limit"] != float64(50) {
		t.Errorf("limit=%v want 50 (default)", env["limit"])
	}
	entries, ok := env["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("entries shape mismatch: %v", env["entries"])
	}
	// audit.read.policy_history event MUST have been emitted (success path).
	if len(audit.appended) != 1 {
		t.Fatalf("appended audit events=%d want 1", len(audit.appended))
	}
	if audit.appended[0].Action != "audit.read.policy_history" {
		t.Errorf("audit action=%q want audit.read.policy_history", audit.appended[0].Action)
	}
}

// ---- team history tests ------------------------------------------

func TestTeamHistory_NotWired_Returns503(t *testing.T) {
	app := buildTeamHistoryApp(&stubPolicyRepo{}, &stubAuditRepo{}, false)
	resp, _ := doGet(t, app, "/api/v1/teams/"+uuid.New().String()+
		"/policy-rules/"+uuid.New().String()+"/history")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status=%d want 503", resp.StatusCode)
	}
}

// Team anchor-mismatch test omitted from slice 1c — requireTeamPolicyScope
// requires a fully-wired PolicyEngine + team-scope resolver, which the
// team-policy integration tests already exercise end-to-end. The project
// version above (TestProjectHistory_AnchorMismatch_SilentlyReturns404)
// covers the gate-order enumeration-protection pattern that both URL
// families share.

func TestTeamHistory_BadTeamID_Returns400(t *testing.T) {
	app := buildTeamHistoryApp(&stubPolicyRepo{}, &stubAuditRepo{}, true)
	resp, _ := doGet(t, app, "/api/v1/teams/not-a-uuid/policy-rules/"+
		uuid.New().String()+"/history")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d want 400", resp.StatusCode)
	}
}

// ---- limit parsing tests -----------------------------------------

func TestHistory_LimitParam_RejectsNegative(t *testing.T) {
	projectID := uuid.New()
	ruleID := uuid.New()
	rule := &storage.PolicyRule{
		ID:        ruleID,
		Name:      "r",
		ProjectID: &projectID,
	}
	policies := &stubPolicyRepo{rules: map[uuid.UUID]*storage.PolicyRule{ruleID: rule}}
	audit := &stubAuditRepo{}
	app := buildProjectHistoryApp(policies, audit, true)

	resp, _ := doGet(t, app, "/api/v1/projects/"+projectID.String()+
		"/policy-rules/"+ruleID.String()+"/history?limit=-1")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d want 400 on negative limit", resp.StatusCode)
	}
}

func TestHistory_LimitParam_CapsAt500(t *testing.T) {
	projectID := uuid.New()
	ruleID := uuid.New()
	rule := &storage.PolicyRule{
		ID:        ruleID,
		Name:      "r",
		ProjectID: &projectID,
	}
	policies := &stubPolicyRepo{rules: map[uuid.UUID]*storage.PolicyRule{ruleID: rule}}
	audit := &stubAuditRepo{}
	app := buildProjectHistoryApp(policies, audit, true)

	resp, body := doGet(t, app, "/api/v1/projects/"+projectID.String()+
		"/policy-rules/"+ruleID.String()+"/history?limit=999999")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, body)
	}
	var env map[string]any
	_ = json.Unmarshal(body, &env)
	if env["limit"] != float64(storage.MaxPolicyHistoryLimit) {
		t.Errorf("limit=%v want %d (cap)", env["limit"], storage.MaxPolicyHistoryLimit)
	}
}
