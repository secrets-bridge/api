package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// bindSecretToEnv upserts a vault catalog row for ref (with the
// provider_config discovery would record) and binds it to env with the
// given allowlist and the read + patch ops. The binding is removed on
// cleanup so later wipes that delete environments are not blocked by its
// environment FK.
func bindSecretToEnv(t *testing.T, pool *storage.Pool, env *storage.Environment, ref string, allowedKeys []string) *storage.Secret {
	t.Helper()
	ctx := t.Context()
	sec := &storage.Secret{
		ClusterName: "tenant-a-uat", ProviderType: "vault", SecretRef: ref,
		ProviderConfig: map[string]any{"address": "https://vault.example.com", "kvMount": "kv", "kvPrefix": "team-alpha"},
		Status:         storage.SecretStatusPresent,
	}
	if err := storage.NewSecrets(pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("secret Upsert %s: %v", ref, err)
	}
	bindings := storage.NewProjectSecrets(pool)
	if err := bindings.Bind(ctx, &storage.ProjectSecret{
		ProjectID: env.ProjectID, SecretID: sec.ID, EnvironmentID: &env.ID,
		AllowedKeys: allowedKeys, AllowedOps: []string{storage.OpRead, storage.OpPatch}, CreatedBy: "services-test",
	}); err != nil {
		t.Fatalf("Bind %s: %v", ref, err)
	}
	t.Cleanup(func() {
		_ = bindings.Unbind(context.Background(), env.ProjectID, sec.ID)
	})
	return sec
}

// tightenEnvBinding narrows the allowlist of the binding bindSecretToEnv
// created for (env.ProjectID, ref) — the "allowlist tightened after
// submit" scenario.
func tightenEnvBinding(t *testing.T, pool *storage.Pool, env *storage.Environment, ref string, allowedKeys []string) {
	t.Helper()
	ctx := t.Context()
	rows, err := storage.NewSecrets(pool).ListByRef(ctx, "vault", ref)
	if err != nil {
		t.Fatalf("ListByRef %s: %v", ref, err)
	}
	bindings := storage.NewProjectSecrets(pool)
	for _, sec := range rows {
		if sec.ClusterName != "tenant-a-uat" {
			continue
		}
		if err := bindings.Update(ctx, env.ProjectID, sec.ID, allowedKeys, []string{storage.OpRead, storage.OpPatch}, nil); err != nil {
			t.Fatalf("tighten binding %s: %v", ref, err)
		}
		return
	}
	t.Fatalf("no tenant-a-uat catalog row for %s", ref)
}

// API-S-04 / API-18 (config part), legacy rows: a read or patch request
// written BEFORE the fix still carries the requester's
// target_provider_config on its row. When it is approved after the fix,
// the enqueued job must carry the config derived from the bound catalog
// row (agent-accepted keys only), never the stored body value. A row no
// binding governs gets no job at all: it fails (see
// TestApprove_NoGoverningBindingFailsRequest).
func TestApprove_LegacyRowProviderConfigNotForwarded(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "legacy-cfg")
	env := newUATEnv(t, envRepo, projectID)

	wf := &storage.WorkflowDefinition{
		Name: "legacy-cfg-wf", MinApprovers: 1, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	if err := policies.Create(ctx, &storage.PolicyRule{
		Name:       "legacy-cfg-rule",
		Selector:   map[string]any{"project_id": projectID.String()},
		WorkflowID: wf.ID,
		Priority:   500,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("policy Create: %v", err)
	}

	bindSecretToEnv(t, pool, env, "team-alpha/uat/db", nil)

	attacker := map[string]any{"kvMount": "attacker-mount", "kvPrefix": "team-beta"}
	repo := storage.NewAccessRequests(pool)
	cases := []struct {
		name string
		typ  storage.AccessRequestType
		ref  string
		want map[string]any
	}{
		{"bound read", storage.AccessRequestTypeRead, "team-alpha/uat/db", map[string]any{"kvMount": "kv", "kvPrefix": "team-alpha"}},
		{"bound patch", storage.AccessRequestTypePatch, "team-alpha/uat/db", map[string]any{"kvMount": "kv", "kvPrefix": "team-alpha"}},
	}
	for _, tc := range cases {
		wfID, envID := wf.ID, env.ID
		row := &storage.AccessRequest{
			RequesterID:          "legacy-requester@example.com",
			Type:                 tc.typ,
			Justification:        "row written before the fix",
			Status:               storage.AccessRequestStatusPending,
			WorkflowID:           &wfID,
			EnvironmentID:        &envID,
			TargetProviderType:   "vault",
			TargetProviderConfig: attacker,
			TargetSecretRef:      tc.ref,
			TargetKeys:           []string{"DB_PASSWORD"},
			TargetScope:          map[string]any{"project_id": projectID.String(), "environment": "uat"},
		}
		if err := repo.Create(ctx, row); err != nil {
			t.Fatalf("%s: seed legacy row: %v", tc.name, err)
		}
		if _, err := reqSvc.Approve(ctx, row.ID, "approver-"+uuid.NewString()[:8], "ok"); err != nil {
			t.Fatalf("%s: Approve: %v", tc.name, err)
		}

		var raw []byte
		if err := pool.QueryRow(ctx,
			`SELECT payload->'target_provider_config' FROM sync_jobs WHERE request_id = $1`, row.ID).Scan(&raw); err != nil {
			t.Fatalf("%s: load job payload: %v", tc.name, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: decode payload config %s: %v", tc.name, raw, err)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: job target_provider_config = %v; want %v", tc.name, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: job target_provider_config = %v; want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

// B-1: the provider config a job carries comes only from the binding
// that governs the request in its own environment. When none governs at
// approve time (the binding was removed, or only a binding scoped to
// another environment matches the ref), no job is enqueued and the
// request fails with a metadata-only audit row. Before the fix the
// lookup fell back to the first candidate, so a uat request was
// dispatched with the prod binding's kvMount / kvPrefix.
func TestApprove_NoGoverningBindingFailsRequest(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "b1-strict")
	uat := newUATEnv(t, envRepo, projectID)
	prod := &storage.Environment{
		ProjectID: projectID, Name: "prod",
		Type: storage.EnvironmentTypeProd, Kind: storage.EnvironmentKindProd,
	}
	if err := envRepo.Create(ctx, prod); err != nil {
		t.Fatalf("prod env Create: %v", err)
	}

	wf := &storage.WorkflowDefinition{
		Name: "b1-strict-wf", MinApprovers: 1, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(ctx, wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	if err := policies.Create(ctx, &storage.PolicyRule{
		Name:       "b1-strict-rule",
		Selector:   map[string]any{"project_id": projectID.String()},
		WorkflowID: wf.ID,
		Priority:   500,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("policy Create: %v", err)
	}

	// "team-alpha/shared/db" exists only as a prod-cluster catalog row
	// bound to the prod environment, with a prod kvPrefix.
	prodSec := &storage.Secret{
		ClusterName: "tenant-a-prod", ProviderType: "vault", SecretRef: "team-alpha/shared/db",
		ProviderConfig: map[string]any{"kvMount": "kv", "kvPrefix": "team-alpha-prod"},
		Status:         storage.SecretStatusPresent,
	}
	if err := storage.NewSecrets(pool).Upsert(ctx, prodSec); err != nil {
		t.Fatalf("prod secret Upsert: %v", err)
	}
	bindings := storage.NewProjectSecrets(pool)
	if err := bindings.Bind(ctx, &storage.ProjectSecret{
		ProjectID: projectID, SecretID: prodSec.ID, EnvironmentID: &prod.ID,
		AllowedOps: []string{storage.OpRead, storage.OpPatch}, CreatedBy: "services-test",
	}); err != nil {
		t.Fatalf("prod Bind: %v", err)
	}
	t.Cleanup(func() { _ = bindings.Unbind(context.Background(), projectID, prodSec.ID) })

	repo := storage.NewAccessRequests(pool)
	cases := []struct {
		name string
		typ  storage.AccessRequestType
		ref  string
	}{
		{"read, only another env's binding", storage.AccessRequestTypeRead, "team-alpha/shared/db"},
		{"patch, only another env's binding", storage.AccessRequestTypePatch, "team-alpha/shared/db"},
		{"read, no binding at all", storage.AccessRequestTypeRead, "team-alpha/uat/unbound"},
	}
	for _, tc := range cases {
		wfID, envID := wf.ID, uat.ID
		row := &storage.AccessRequest{
			RequesterID:        "b1-requester@example.com",
			Type:               tc.typ,
			Justification:      "approved after the binding stopped governing",
			Status:             storage.AccessRequestStatusPending,
			WorkflowID:         &wfID,
			EnvironmentID:      &envID,
			TargetProviderType: "vault",
			TargetSecretRef:    tc.ref,
			TargetKeys:         []string{"DB_PASSWORD"},
			TargetScope:        map[string]any{"project_id": projectID.String(), "environment": "uat"},
		}
		if err := repo.Create(ctx, row); err != nil {
			t.Fatalf("%s: seed row: %v", tc.name, err)
		}
		got, err := reqSvc.Approve(ctx, row.ID, "approver-"+uuid.NewString()[:8], "ok")
		if err != nil {
			t.Fatalf("%s: Approve: %v", tc.name, err)
		}
		if got.Status != storage.AccessRequestStatusFailed {
			t.Errorf("%s: returned status = %s; want failed", tc.name, got.Status)
		}
		stored, err := repo.Get(ctx, row.ID)
		if err != nil {
			t.Fatalf("%s: reload: %v", tc.name, err)
		}
		if stored.Status != storage.AccessRequestStatusFailed {
			t.Errorf("%s: stored status = %s; want failed", tc.name, stored.Status)
		}
		var jobs int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM sync_jobs WHERE request_id = $1`, row.ID).Scan(&jobs); err != nil {
			t.Fatalf("%s: count jobs: %v", tc.name, err)
		}
		if jobs != 0 {
			var raw []byte
			_ = pool.QueryRow(ctx, `SELECT payload->'target_provider_config' FROM sync_jobs WHERE request_id = $1`, row.ID).Scan(&raw)
			t.Errorf("%s: %d job(s) enqueued with target_provider_config %s; want none", tc.name, jobs, raw)
		}
		var reason string
		if err := pool.QueryRow(ctx,
			`SELECT metadata->>'reason' FROM audit_events
			  WHERE action = 'request.execute.binding_rejected' AND correlation_id = $1`, row.ID).Scan(&reason); err != nil {
			t.Fatalf("%s: binding_rejected audit row: %v", tc.name, err)
		}
		if reason != "no_governing_binding" {
			t.Errorf("%s: audit reason = %q; want no_governing_binding", tc.name, reason)
		}
	}
}

// B-1, submit side: POST /requests and /requests/read derive the config
// at submit through the same strict lookup, so a submit no binding
// governs is refused with ErrSecretNotBound before any row is written,
// even if the handler's tenancy gate is not wired.
func TestSubmit_NoGoverningBindingRefused(t *testing.T) {
	reqSvc, pool, envRepo, _, _ := buildL3Harness(t)
	ctx := t.Context()

	projectID := makeProjectForSvc(t, pool, "b1-submit")
	newUATEnv(t, envRepo, projectID)
	prod := &storage.Environment{
		ProjectID: projectID, Name: "prod",
		Type: storage.EnvironmentTypeProd, Kind: storage.EnvironmentKindProd,
	}
	if err := envRepo.Create(ctx, prod); err != nil {
		t.Fatalf("prod env Create: %v", err)
	}
	bindSecretToEnv(t, pool, prod, "team-alpha/prod-only/db", nil)

	_, err := reqSvc.SubmitRead(ctx, services.ReadInput{
		RequesterID: "b1-submitter@example.com", ProjectID: projectID.String(), Environment: "uat",
		TargetProviderType: "vault", TargetSecretRef: "team-alpha/prod-only/db",
		TargetKeys: []string{"DB_PASSWORD"}, Justification: "uat read of a prod-only binding",
	})
	if !errors.Is(err, services.ErrSecretNotBound) {
		t.Fatalf("SubmitRead err = %v; want ErrSecretNotBound", err)
	}
	_, err = reqSvc.Submit(ctx, services.PatchInput{
		RequesterID: "b1-submitter@example.com", ProjectID: projectID.String(), Environment: "uat",
		TargetProviderType: "vault", TargetSecretRef: "team-alpha/prod-only/db",
		KeyValues: map[string][]byte{"DB_PASSWORD": []byte("not-a-real-value")}, Justification: "uat patch of a prod-only binding",
	})
	if !errors.Is(err, services.ErrSecretNotBound) {
		t.Fatalf("Submit err = %v; want ErrSecretNotBound", err)
	}
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM access_requests WHERE target_secret_ref = 'team-alpha/prod-only/db'`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("%d request row(s) written for a refused submit; want 0", rows)
	}
}

// seedApproveRule gives projectID a one-approver workflow so Approve on a
// seeded pending row crosses the threshold and enqueues.
func seedApproveRule(t *testing.T, workflows *storage.Workflows, policies *storage.Policies, projectID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	wf := &storage.WorkflowDefinition{
		Name: name + "-wf", MinApprovers: 1, AllowSelfApproval: false,
		WrapTTLCreated: 24 * time.Hour, WrapTTLApproved: time.Hour,
		WrapTTLClaimed: 5 * time.Minute, RequestTTL: 7 * 24 * time.Hour, Enabled: true,
	}
	if err := workflows.Create(t.Context(), wf); err != nil {
		t.Fatalf("wf Create: %v", err)
	}
	if err := policies.Create(t.Context(), &storage.PolicyRule{
		Name: name + "-rule", Selector: map[string]any{"project_id": projectID.String()},
		WorkflowID: wf.ID, Priority: 500, Enabled: true,
	}); err != nil {
		t.Fatalf("policy Create: %v", err)
	}
	return wf.ID
}

// seedPending writes a pending read/patch row the way submit would have.
func seedPending(t *testing.T, pool *storage.Pool, wfID uuid.UUID, envID *uuid.UUID, projectID uuid.UUID, typ storage.AccessRequestType, ref string, keys []string) *storage.AccessRequest {
	t.Helper()
	row := &storage.AccessRequest{
		RequesterID: "binding-requester@example.com", Type: typ,
		Justification: "binding changed before approve", Status: storage.AccessRequestStatusPending,
		WorkflowID: &wfID, EnvironmentID: envID, TargetProviderType: "vault",
		TargetSecretRef: ref, TargetKeys: keys,
		TargetScope: map[string]any{"project_id": projectID.String(), "environment": "uat"},
	}
	if err := storage.NewAccessRequests(pool).Create(t.Context(), row); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	return row
}

// The enqueue-time check covers the whole binding, not just its
// environment: a binding narrowed to read-only after a patch was
// submitted, or whose key allowlist dropped a requested key, fails the
// request instead of dispatching a job with the old scope.
func TestApprove_BindingNarrowedAfterSubmitFailsRequest(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	ctx := t.Context()
	projectID := makeProjectForSvc(t, pool, "b1-narrowed")
	uat := newUATEnv(t, envRepo, projectID)
	wfID := seedApproveRule(t, workflows, policies, projectID, "b1-narrowed")
	sec := bindSecretToEnv(t, pool, uat, "team-alpha/uat/narrowed", nil)
	bindings := storage.NewProjectSecrets(pool)

	cases := []struct {
		name   string
		typ    storage.AccessRequestType
		keys   []string
		ops    []string
		reason string
	}{
		{"patch after the binding went read-only", storage.AccessRequestTypePatch, nil, []string{storage.OpRead}, "op_not_allowed"},
		{"read of a key the allowlist dropped", storage.AccessRequestTypeRead, []string{"OTHER_KEY"}, []string{storage.OpRead, storage.OpPatch}, "key_not_allowed"},
	}
	for _, tc := range cases {
		if err := bindings.Update(ctx, projectID, sec.ID, nil, []string{storage.OpRead, storage.OpPatch}, nil); err != nil {
			t.Fatalf("%s: reset binding: %v", tc.name, err)
		}
		envID := uat.ID
		row := seedPending(t, pool, wfID, &envID, projectID, tc.typ, "team-alpha/uat/narrowed", []string{"DB_PASSWORD"})
		if err := bindings.Update(ctx, projectID, sec.ID, tc.keys, tc.ops, nil); err != nil {
			t.Fatalf("%s: narrow binding: %v", tc.name, err)
		}
		got, err := reqSvc.Approve(ctx, row.ID, "approver-"+uuid.NewString()[:8], "ok")
		if err != nil {
			t.Fatalf("%s: Approve: %v", tc.name, err)
		}
		if got.Status != storage.AccessRequestStatusFailed {
			t.Errorf("%s: status = %s; want failed", tc.name, got.Status)
		}
		var jobs int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM sync_jobs WHERE request_id = $1`, row.ID).Scan(&jobs)
		if jobs != 0 {
			t.Errorf("%s: %d job(s) enqueued; want none", tc.name, jobs)
		}
		var reason string
		if err := pool.QueryRow(ctx, `SELECT metadata->>'reason' FROM audit_events
			WHERE action = 'request.execute.binding_rejected' AND correlation_id = $1`, row.ID).Scan(&reason); err != nil {
			t.Fatalf("%s: binding_rejected audit row: %v", tc.name, err)
		}
		if reason != tc.reason {
			t.Errorf("%s: audit reason = %q; want %q", tc.name, reason, tc.reason)
		}
	}
}

// A patch refused at approve keeps no long-lived wraps: approve sets them
// to WrapTTLApproved (1h here) before the enqueue, and the refusal caps
// them at 5 minutes like Reject and Cancel. Before the fix they stayed at
// the approved TTL.
func TestApprove_UnboundPatchShortensWraps(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	ctx := t.Context()
	projectID := makeProjectForSvc(t, pool, "b1-wrapttl")
	uat := newUATEnv(t, envRepo, projectID)
	seedApproveRule(t, workflows, policies, projectID, "b1-wrapttl")
	sec := bindSecretToEnv(t, pool, uat, "team-alpha/uat/wrapttl", nil)

	req, err := reqSvc.Submit(ctx, services.PatchInput{
		RequesterID: "b1-wrapttl@example.com", ProjectID: projectID.String(), Environment: "uat",
		TargetProviderType: "vault", TargetSecretRef: "team-alpha/uat/wrapttl",
		KeyValues:     map[string][]byte{"DB_PASSWORD": []byte("not-a-real-value"), "DB_USER": []byte("not-a-real-user")},
		Justification: "patch refused at approve",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// the binding goes read-only before anyone approves
	if err := storage.NewProjectSecrets(pool).Update(ctx, projectID, sec.ID, nil, []string{storage.OpRead}, nil); err != nil {
		t.Fatalf("narrow binding: %v", err)
	}
	got, err := reqSvc.Approve(ctx, req.ID, "approver-"+uuid.NewString()[:8], "ok")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.Status != storage.AccessRequestStatusFailed {
		t.Fatalf("status = %s; want failed", got.Status)
	}

	var wraps int
	var latest time.Time
	if err := pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(expires_at), now()) FROM secret_wraps WHERE request_id = $1`, req.ID).Scan(&wraps, &latest); err != nil {
		t.Fatalf("read wraps: %v", err)
	}
	if wraps != 2 {
		t.Fatalf("wraps = %d; want 2", wraps)
	}
	if limit := time.Now().Add(5*time.Minute + 30*time.Second); latest.After(limit) {
		t.Errorf("latest wrap expires in %s; want <= 5m after the refusal", time.Until(latest).Round(time.Second))
	}
}

// A legacy binding with no environment still governs, with or without an
// environment on the request, so approve dispatches as before.
func TestApprove_LegacyNullEnvBindingDispatches(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	ctx := t.Context()
	projectID := makeProjectForSvc(t, pool, "b1-legacy")
	uat := newUATEnv(t, envRepo, projectID)
	wfID := seedApproveRule(t, workflows, policies, projectID, "b1-legacy")
	bindSecretWithAllowedKeys(t, pool, projectID, "billing/uat/legacy", nil)

	envID := uat.ID
	for name, env := range map[string]*uuid.UUID{"with environment": &envID, "without environment": nil} {
		row := seedPending(t, pool, wfID, env, projectID, storage.AccessRequestTypeRead, "billing/uat/legacy", []string{"DB_PASSWORD"})
		got, err := reqSvc.Approve(ctx, row.ID, "approver-"+uuid.NewString()[:8], "ok")
		if err != nil {
			t.Fatalf("%s: Approve: %v", name, err)
		}
		if got.Status != storage.AccessRequestStatusApproved {
			t.Errorf("%s: status = %s; want approved", name, got.Status)
		}
		var jobs int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM sync_jobs WHERE request_id = $1`, row.ID).Scan(&jobs)
		if jobs != 1 {
			t.Errorf("%s: jobs = %d; want 1", name, jobs)
		}
	}
}

// dropAfterFirstGet finds a binding once and reports it gone afterwards:
// the binding disappears between the direct-reveal gate and the enqueue.
type dropAfterFirstGet struct {
	storage.ProjectSecretRepository
	calls atomic.Int32
}

func (d *dropAfterFirstGet) Get(ctx context.Context, projectID, secretID uuid.UUID) (*storage.ProjectSecret, error) {
	if d.calls.Add(1) > 1 {
		return nil, storage.ErrNotFound
	}
	return d.ProjectSecretRepository.Get(ctx, projectID, secretID)
}

// If the binding goes away after the direct-reveal gate passed, the
// request is failed and the caller gets the gate's refusal. No
// secret.reveal.direct.issued row claims success for it.
func TestSubmitDirectReveal_BindingGoneBeforeEnqueue(t *testing.T) {
	reqSvc, pool, envRepo, workflows, policies := buildL3Harness(t)
	reqSvc.WithProjectBindings(&dropAfterFirstGet{ProjectSecretRepository: storage.NewProjectSecrets(pool)}, storage.NewSecrets(pool))
	ctx := t.Context()
	projectID := makeProjectForSvc(t, pool, "dr-race")
	env := newUATEnv(t, envRepo, projectID)
	seedDirectRevealRule(t, pool, workflows, policies, projectID)
	bindSecretToEnv(t, pool, env, "billing/uat/race", nil)

	_, err := reqSvc.SubmitDirectReveal(ctx, services.DirectRevealInput{
		RequesterID: "dr-race@example.com", Environment: env, TargetProviderType: "vault",
		TargetSecretRef: "billing/uat/race", TargetKeys: []string{"DB_PASSWORD"}, Justification: "binding removed mid-flight",
	})
	if !errors.Is(err, services.ErrSecretNotBound) {
		t.Fatalf("SubmitDirectReveal err = %v; want ErrSecretNotBound", err)
	}
	var id uuid.UUID
	var status string
	if err := pool.QueryRow(ctx, `SELECT id, status FROM access_requests WHERE target_secret_ref = 'billing/uat/race'`).Scan(&id, &status); err != nil {
		t.Fatalf("load request row: %v", err)
	}
	if status != string(storage.AccessRequestStatusFailed) {
		t.Errorf("request status = %s; want failed", status)
	}
	var jobs, issued, rejected int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM sync_jobs WHERE request_id = $1`, id).Scan(&jobs)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE correlation_id = $1 AND action = 'secret.reveal.direct.issued'`, id).Scan(&issued)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE correlation_id = $1 AND action = 'request.execute.binding_rejected'`, id).Scan(&rejected)
	if jobs != 0 || issued != 0 || rejected != 1 {
		t.Errorf("jobs=%d issued=%d binding_rejected=%d; want 0/0/1", jobs, issued, rejected)
	}
}
