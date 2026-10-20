package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// skills#103: separation of duties. A requester can never approve or
// reject their own request, whatever their role (the seeded admin role
// here) or the workflow says. The workflow below has allow_self_approval
// stored as true, the way an older install may have saved it.

type sodFixture struct {
	l          *liveApp
	proj, env  uuid.UUID
	workflowID uuid.UUID
	admin      uuid.UUID
	adminCK    string
	approverCK string
}

func newSoDFixture(t *testing.T) *sodFixture {
	t.Helper()
	l := newLiveApp(t)
	ctx := t.Context()
	fx := &sodFixture{l: l, proj: uuid.New(), env: uuid.New(), admin: uuid.New()}
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1, 'tenant-a')`, fx.proj); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := l.pool.Exec(ctx, `INSERT INTO environments (id, project_id, name, type, kind) VALUES ($1, $2, 'uat', 'uat', 'non_prod')`, fx.env, fx.proj); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	sec := &storage.Secret{ClusterName: "tenant-a-uat", ProviderType: "vault", SecretRef: "team-alpha/uat/db", Status: "present"}
	if err := storage.NewSecrets(l.pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if err := storage.NewProjectSecrets(l.pool).Bind(ctx, &storage.ProjectSecret{
		ProjectID: fx.proj, SecretID: sec.ID, EnvironmentID: &fx.env,
		AllowedKeys: []string{"DB_USER", "DB_PASSWORD"}, AllowedOps: []string{storage.OpRead, storage.OpPatch}, CreatedBy: "seed",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	wf := &storage.WorkflowDefinition{
		Name: "sod-wf-" + uuid.NewString()[:8], MinApprovers: 1, AllowSelfApproval: true,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := storage.NewWorkflows(l.pool).Create(ctx, wf); err != nil {
		t.Fatalf("seed workflow: %v", err)
	}
	t.Cleanup(func() { _, _ = l.pool.Exec(t.Context(), `DELETE FROM workflow_definitions WHERE id = $1`, wf.ID) })
	if err := storage.NewPolicies(l.pool).Create(ctx, &storage.PolicyRule{
		Name: "sod-rule", Selector: map[string]any{"project_id": fx.proj.String(), "environment": "uat"},
		WorkflowID: wf.ID, Priority: 500, Enabled: true,
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	fx.workflowID = wf.ID

	role, err := storage.NewRoles(l.pool).GetByName(ctx, "admin")
	if err != nil {
		t.Fatalf("admin role: %v", err)
	}
	fx.adminCK = l.sessionFor(t, fx.admin, "sod-admin@example.com")
	if err := storage.NewUserRoles(l.pool).Grant(ctx, &storage.UserRole{UserID: fx.admin.String(), RoleID: role.ID, Scope: map[string]any{}}); err != nil {
		t.Fatalf("grant admin: %v", err)
	}
	approver := uuid.New()
	l.addGrant(t, approver.String(), []string{"secret.approve"}, `{}`)
	fx.approverCK = l.sessionFor(t, approver, "sod-approver@example.com")
	return fx
}

func (fx *sodFixture) as(t *testing.T, cookie, method, path string, body any) (int, []byte) {
	t.Helper()
	return fx.l.callAs(t, method, path, map[string]string{"Cookie": cookie}, body)
}

func (fx *sodFixture) status(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := fx.l.pool.QueryRow(t.Context(), `SELECT status FROM access_requests WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return s
}

// refusedAudit is the denied row for one self-decision, or fails.
func (fx *sodFixture) refusedAudit(t *testing.T, action string, id uuid.UUID) map[string]any {
	t.Helper()
	var actor string
	var meta map[string]any
	err := fx.l.pool.QueryRow(t.Context(), `SELECT actor, metadata FROM audit_events
		WHERE action = $1 AND resource = $2 AND status = 'denied'`, action, "request:"+id.String()).Scan(&actor, &meta)
	if err != nil {
		t.Fatalf("%s denied audit row for %s: %v", action, id, err)
	}
	if actor != "user:"+fx.admin.String() {
		t.Errorf("%s denied actor = %q", action, actor)
	}
	if meta["error_kind"] != "self_approval" || meta["workflow_id"] != fx.workflowID.String() || meta["request_id"] != id.String() {
		t.Errorf("%s denied metadata = %v", action, meta)
	}
	return meta
}

// sodCode is the stable error code of a refusal body.
func sodCode(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	mustJSON(t, body, &e)
	return e.Error
}

func (fx *sodFixture) submit(t *testing.T, kind string) uuid.UUID {
	t.Helper()
	path, body := "/api/v1/requests/read", map[string]any{
		"project_id": fx.proj.String(), "environment": "uat",
		"target_provider_type": "vault", "target_secret_ref": "team-alpha/uat/db",
		"target_keys": []string{"DB_USER", "DB_PASSWORD"}, "justification": "sod read",
	}
	if kind == "patch" {
		path, body = "/api/v1/requests", map[string]any{
			"project_id": fx.proj.String(), "environment": "uat",
			"target_provider_type": "vault", "target_secret_ref": "team-alpha/uat/db",
			"key_values": map[string]string{"DB_PASSWORD": "fake-sod-password"}, "justification": "sod patch",
		}
	}
	code, resp := fx.as(t, fx.adminCK, http.MethodPost, path, body)
	if code != http.StatusCreated {
		t.Fatalf("%s submit = %d %s", kind, code, resp)
	}
	var out struct {
		ID        uuid.UUID `json:"id"`
		RequestID uuid.UUID `json:"request_id"`
	}
	mustJSON(t, resp, &out)
	if out.ID == uuid.Nil {
		out.ID = out.RequestID
	}
	return out.ID
}

func TestLive_SelfApproval_RefusedForAdminEvenWhenTheWorkflowAllowsIt(t *testing.T) {
	fx := newSoDFixture(t)
	for _, kind := range []string{"read", "patch"} {
		t.Run(kind, func(t *testing.T) {
			id := fx.submit(t, kind)
			base := "/api/v1/requests/" + id.String()

			if code, body := fx.as(t, fx.adminCK, http.MethodPost, base+"/approve", map[string]any{"comment": "mine"}); code != http.StatusForbidden || sodCode(t, body) != "separation_of_duties_violated" {
				t.Fatalf("admin approving own %s request = %d %s, want 403 separation_of_duties_violated", kind, code, body)
			}
			fx.refusedAudit(t, "request.approve", id)
			if s := fx.status(t, id); s != "pending" {
				t.Fatalf("status after a refused self-approval = %q, want pending", s)
			}

			if code, body := fx.as(t, fx.adminCK, http.MethodPost, base+"/reject", map[string]any{"reason": "mine to close"}); code != http.StatusForbidden || sodCode(t, body) != "separation_of_duties_violated" {
				t.Fatalf("admin rejecting own %s request = %d %s, want 403 separation_of_duties_violated", kind, code, body)
			}
			fx.refusedAudit(t, "request.reject", id)
			if s := fx.status(t, id); s != "pending" {
				t.Fatalf("status after a refused self-reject = %q, want pending", s)
			}

			// An independent approver still can.
			if code, body := fx.as(t, fx.approverCK, http.MethodPost, base+"/approve", map[string]any{"comment": "independent"}); code != http.StatusOK {
				t.Fatalf("independent approver = %d %s, want 200", code, body)
			}
			if s := fx.status(t, id); s != "approved" {
				t.Fatalf("status after an independent approval = %q, want approved", s)
			}
		})
	}
}

func TestLive_Workflows_SelfApprovalCannotBeTurnedOn(t *testing.T) {
	fx := newSoDFixture(t)
	wfBody := map[string]any{
		"name": "sod-api-wf-" + uuid.NewString()[:8], "min_approvers": 1, "enabled": true,
		"wrap_ttl_created_seconds": 3600, "wrap_ttl_approved_seconds": 3600,
		"wrap_ttl_claimed_seconds": 300, "request_ttl_seconds": 3600,
		"allow_self_approval": true,
	}
	code, body := fx.as(t, fx.adminCK, http.MethodPost, "/api/v1/workflows", wfBody)
	var refusal struct {
		ErrorCode string `json:"error_code"`
	}
	mustJSON(t, body, &refusal)
	if code != http.StatusBadRequest || refusal.ErrorCode != "self_approval_not_allowed" {
		t.Fatalf("create with allow_self_approval=true = %d %s, want 400 self_approval_not_allowed", code, body)
	}

	// A workflow stored with the flag set reads back as false, refuses
	// being set to true, and any other save clears the stored flag.
	path := "/api/v1/workflows/" + fx.workflowID.String()
	code, body = fx.as(t, fx.adminCK, http.MethodGet, path, nil)
	var got struct {
		AllowSelfApproval *bool `json:"allow_self_approval"`
	}
	mustJSON(t, body, &got)
	if code != http.StatusOK || got.AllowSelfApproval == nil || *got.AllowSelfApproval {
		t.Fatalf("GET stored-true workflow = %d %s, want allow_self_approval false", code, body)
	}
	if code, body := fx.as(t, fx.adminCK, http.MethodPut, path, map[string]any{"allow_self_approval": true}); code != http.StatusBadRequest {
		t.Fatalf("PUT allow_self_approval=true = %d %s, want 400", code, body)
	}
	stored := func() bool {
		var v bool
		if err := fx.l.pool.QueryRow(t.Context(), `SELECT allow_self_approval FROM workflow_definitions WHERE id = $1`, fx.workflowID).Scan(&v); err != nil {
			t.Fatalf("read flag: %v", err)
		}
		return v
	}
	if !stored() {
		t.Fatal("a refused PUT changed the stored row")
	}
	// The boot notice counts the stored flags that are now ignored.
	before, err := storage.CountWorkflowsAllowingSelfApproval(t.Context(), fx.l.pool)
	if err != nil || before < 1 {
		t.Fatalf("count before save = %d, %v; want >= 1", before, err)
	}
	if code, body := fx.as(t, fx.adminCK, http.MethodPut, path, map[string]any{"description": "saved again"}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("PUT description = %d %s", code, body)
	}
	if stored() {
		t.Fatal("saving the workflow left allow_self_approval set")
	}
	if after, err := storage.CountWorkflowsAllowingSelfApproval(t.Context(), fx.l.pool); err != nil || after != before-1 {
		t.Fatalf("count after save = %d, %v; want %d", after, err, before-1)
	}
}
