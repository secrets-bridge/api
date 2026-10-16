package services_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

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
// row (agent-accepted keys only), never the stored body value. An unbound
// legacy row gets an empty config (the agent's pinned defaults).
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
		{"unbound read", storage.AccessRequestTypeRead, "team-alpha/uat/other", map[string]any{}},
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
