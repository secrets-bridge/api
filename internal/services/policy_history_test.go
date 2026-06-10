// R-follow-up #5 slice 1a unit tests (api#133) — PolicyHistoryService.
//
// Pure unit tests: fakes for audit + workflows; no live Postgres.
// Storage-layer WHERE/ORDER BY semantics are covered by the existing
// audit integration tests + the live e2e in slice 1c.
//
// Coverage:
//   - Chain create → 3× update → delete, full diff vector verified
//   - Legacy action names normalized at boundary
//   - Legacy snapshots missing name/enabled render as nil pointers
//   - selector_keys set-based diff: reorder ≠ change
//   - workflow_id change emits both names; missing-from-batch → nil names
//   - policy.delete carries prior snapshot (last-known state)
//   - chain head emits no Changes regardless of action
//   - empty chain → nil entries, no error
//   - workflow lookup batched (one call per ListForRule, NOT per entry)
//   - actor_display: nil repos fall back to raw actor (no panic)

package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- fakes -------------------------------------------------------

type fakeAuditRepo struct {
	rows    []*storage.AuditEvent
	hasMore bool
	calls   int
}

func (f *fakeAuditRepo) Append(context.Context, *storage.AuditEvent) error { panic("unused") }
func (f *fakeAuditRepo) AppendTx(context.Context, pgx.Tx, *storage.AuditEvent) error {
	panic("unused")
}
func (f *fakeAuditRepo) Query(context.Context, storage.AuditQuery) ([]*storage.AuditEvent, error) {
	panic("unused")
}
func (f *fakeAuditRepo) ListPolicyRuleHistory(
	_ context.Context, _ uuid.UUID, _ int,
) ([]*storage.AuditEvent, bool, error) {
	f.calls++
	return f.rows, f.hasMore, nil
}

type fakeWorkflowRepo struct {
	byID  map[uuid.UUID]*storage.WorkflowDefinition
	calls int
}

func (f *fakeWorkflowRepo) Create(context.Context, *storage.WorkflowDefinition) error {
	panic("unused")
}
func (f *fakeWorkflowRepo) Get(_ context.Context, _ uuid.UUID) (*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (f *fakeWorkflowRepo) GetByName(_ context.Context, _ string) (*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (f *fakeWorkflowRepo) GetDefault(context.Context) (*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (f *fakeWorkflowRepo) List(context.Context) ([]*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (f *fakeWorkflowRepo) ListByIDs(
	_ context.Context, ids []uuid.UUID,
) ([]*storage.WorkflowDefinition, error) {
	f.calls++
	out := make([]*storage.WorkflowDefinition, 0, len(ids))
	for _, id := range ids {
		if w, ok := f.byID[id]; ok {
			out = append(out, w)
		}
	}
	return out, nil
}
func (f *fakeWorkflowRepo) ListScopedPolicyAuthorable(context.Context) ([]*storage.WorkflowDefinition, error) {
	panic("unused")
}
func (f *fakeWorkflowRepo) Update(context.Context, *storage.WorkflowDefinition) error {
	panic("unused")
}
func (f *fakeWorkflowRepo) Delete(context.Context, uuid.UUID) error { panic("unused") }

// ---- helpers -----------------------------------------------------

func mkEvent(
	when time.Time,
	action, actor string,
	meta map[string]any,
) *storage.AuditEvent {
	if meta == nil {
		meta = map[string]any{}
	}
	return &storage.AuditEvent{
		ID:            uuid.New(),
		Actor:         actor,
		Action:        action,
		Status:        storage.AuditStatusSuccess,
		CorrelationID: uuid.New(),
		Metadata:      meta,
		OccurredAt:    when,
	}
}

func sParse(t *testing.T, s string) any {
	t.Helper()
	return s // alias for readability
}

// ---- tests -------------------------------------------------------

func TestPolicyHistoryService_FullChain_CreateUpdatesDelete(t *testing.T) {
	ctx := context.Background()
	wfA := uuid.New()
	wfB := uuid.New()

	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			mkEvent(base, "policy.create", "user:11111111-1111-1111-1111-111111111111",
				map[string]any{
					"name":                  "billing-rule",
					"enabled":               true,
					"priority":              float64(100),
					"workflow_id":           wfA.String(),
					"selector_keys":         []any{"environment_kind", "secret_ref_prefix"},
					"actor_permission_used": "policy.author",
					"scope":                 "project",
				}),
			// Priority bump
			mkEvent(base.Add(1*time.Hour), "policy.update", "user:22222222-2222-2222-2222-222222222222",
				map[string]any{
					"name":          "billing-rule",
					"enabled":       true,
					"priority":      float64(200),
					"workflow_id":   wfA.String(),
					"selector_keys": []any{"environment_kind", "secret_ref_prefix"},
					"scope":         "project",
				}),
			// Disable + rename + workflow swap + selector keys widened
			mkEvent(base.Add(2*time.Hour), "policy.update", "user:22222222-2222-2222-2222-222222222222",
				map[string]any{
					"name":          "billing-rule-prod",
					"enabled":       false,
					"priority":      float64(200),
					"workflow_id":   wfB.String(),
					"selector_keys": []any{"environment_kind", "provider_type", "secret_ref_prefix"},
					"scope":         "project",
				}),
			// Delete
			mkEvent(base.Add(3*time.Hour), "policy.delete", "user:22222222-2222-2222-2222-222222222222",
				map[string]any{
					"name":          "billing-rule-prod",
					"enabled":       false,
					"priority":      float64(200),
					"workflow_id":   wfB.String(),
					"selector_keys": []any{"environment_kind", "provider_type", "secret_ref_prefix"},
					"scope":         "project",
				}),
		},
	}
	workflows := &fakeWorkflowRepo{
		byID: map[uuid.UUID]*storage.WorkflowDefinition{
			wfA: {ID: wfA, Name: "approval-v1"},
			wfB: {ID: wfB, Name: "approval-v2"},
		},
	}

	svc := services.NewPolicyHistoryService(audit, workflows, nil, nil)
	entries, hasMore, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}
	if hasMore {
		t.Fatalf("hasMore = true; want false")
	}
	if got := len(entries); got != 4 {
		t.Fatalf("entries = %d; want 4", got)
	}

	// Workflow batch lookup happens ONCE per ListForRule.
	if workflows.calls != 1 {
		t.Fatalf("workflows.ListByIDs called %d times; want exactly 1", workflows.calls)
	}

	// 1) create — no Changes (chain head)
	if len(entries[0].Changes) != 0 {
		t.Errorf("create entry: Changes = %v; want empty", entries[0].Changes)
	}
	if entries[0].Action != "policy.create" {
		t.Errorf("create entry action = %q", entries[0].Action)
	}
	if entries[0].SnapshotAfter.WorkflowName == nil || *entries[0].SnapshotAfter.WorkflowName != "approval-v1" {
		t.Errorf("create entry SnapshotAfter.WorkflowName = %v", entries[0].SnapshotAfter.WorkflowName)
	}

	// 2) update — priority only
	want := map[string]bool{"priority": true}
	if got := changeKeys(entries[1].Changes); !equalKeySet(got, want) {
		t.Errorf("update#1 keys = %v; want %v", got, want)
	}
	for _, c := range entries[1].Changes {
		if c.Key == "priority" {
			if c.Before != 100 || c.After != 200 {
				t.Errorf("priority diff: before=%v after=%v", c.Before, c.After)
			}
		}
	}

	// 3) update — name + enabled + workflow_id + selector_keys all changed
	want = map[string]bool{"name": true, "enabled": true, "workflow_id": true, "selector_keys": true}
	if got := changeKeys(entries[2].Changes); !equalKeySet(got, want) {
		t.Errorf("update#2 keys = %v; want %v", got, want)
	}
	for _, c := range entries[2].Changes {
		if c.Key == "workflow_id" {
			if c.BeforeWorkflowName == nil || *c.BeforeWorkflowName != "approval-v1" {
				t.Errorf("workflow_id Before name = %v", c.BeforeWorkflowName)
			}
			if c.AfterWorkflowName == nil || *c.AfterWorkflowName != "approval-v2" {
				t.Errorf("workflow_id After name = %v", c.AfterWorkflowName)
			}
		}
	}

	// 4) delete — no Changes; SnapshotAfter carries PRIOR snapshot
	if len(entries[3].Changes) != 0 {
		t.Errorf("delete entry: Changes = %v; want empty", entries[3].Changes)
	}
	if entries[3].SnapshotAfter.Priority != 200 {
		t.Errorf("delete carries prior snapshot priority = %d; want 200", entries[3].SnapshotAfter.Priority)
	}
}

func TestPolicyHistoryService_LegacyActionNamesNormalized(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)

	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			mkEvent(base, "policy.created_for_scope", "user:legacy-1",
				map[string]any{"priority": float64(100), "selector_keys": []any{"environment_kind"}}),
			mkEvent(base.Add(time.Hour), "policy.updated_for_scope", "user:legacy-1",
				map[string]any{"priority": float64(150), "selector_keys": []any{"environment_kind"}}),
			mkEvent(base.Add(2*time.Hour), "policy.deleted_for_scope", "user:legacy-1",
				map[string]any{"priority": float64(150), "selector_keys": []any{"environment_kind"}}),
		},
	}

	svc := services.NewPolicyHistoryService(audit, &fakeWorkflowRepo{}, nil, nil)
	entries, _, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}

	want := []string{"policy.create", "policy.update", "policy.delete"}
	for i, w := range want {
		if entries[i].Action != w {
			t.Errorf("entries[%d].Action = %q; want %q", i, entries[i].Action, w)
		}
	}
}

func TestPolicyHistoryService_LegacyMetadataMissingFields(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	wf := uuid.New()

	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			// Pre-§5 legacy event — no name, no enabled, no scope
			mkEvent(base, "policy.create", "user:legacy",
				map[string]any{"priority": float64(100), "workflow_id": wf.String(), "selector_keys": []any{"environment_kind"}}),
			// Same priority but now name + enabled present (post-slice-1b emit)
			mkEvent(base.Add(time.Hour), "policy.update", "user:legacy",
				map[string]any{
					"name":          "newly-named",
					"enabled":       true,
					"priority":      float64(100),
					"workflow_id":   wf.String(),
					"selector_keys": []any{"environment_kind"},
				}),
		},
	}

	svc := services.NewPolicyHistoryService(audit, &fakeWorkflowRepo{}, nil, nil)
	entries, _, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}

	// Legacy event: Name + Enabled are nil pointers
	if entries[0].SnapshotAfter.Name != nil {
		t.Errorf("legacy SnapshotAfter.Name = %v; want nil", *entries[0].SnapshotAfter.Name)
	}
	if entries[0].SnapshotAfter.Enabled != nil {
		t.Errorf("legacy SnapshotAfter.Enabled = %v; want nil", *entries[0].SnapshotAfter.Enabled)
	}

	// Update diff catches name + enabled as having "appeared" (nil → set)
	gotKeys := changeKeys(entries[1].Changes)
	if !gotKeys["name"] || !gotKeys["enabled"] {
		t.Errorf("update diff keys = %v; want name+enabled to surface", gotKeys)
	}
}

func TestPolicyHistoryService_SelectorKeysSetBased_ReorderIsNotAChange(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	wf := uuid.New()
	common := map[string]any{"name": "r", "enabled": true, "priority": float64(100), "workflow_id": wf.String()}

	mkWith := func(when time.Time, keys ...string) *storage.AuditEvent {
		meta := map[string]any{}
		for k, v := range common {
			meta[k] = v
		}
		anys := make([]any, len(keys))
		for i, k := range keys {
			anys[i] = k
		}
		meta["selector_keys"] = anys
		return mkEvent(when, "policy.update", "user:u", meta)
	}

	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			mkEvent(base, "policy.create", "user:u", merge(common, map[string]any{"selector_keys": []any{"a", "b"}})),
			// Reorder ONLY — should produce ZERO changes
			mkWith(base.Add(time.Hour), "b", "a"),
			// Add one key — should produce ONE change (selector_keys)
			mkWith(base.Add(2*time.Hour), "a", "b", "c"),
		},
	}

	svc := services.NewPolicyHistoryService(audit, &fakeWorkflowRepo{}, nil, nil)
	entries, _, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}

	// 2nd event: reorder only → no changes
	if len(entries[1].Changes) != 0 {
		t.Errorf("reorder-only Changes = %v; want empty", entries[1].Changes)
	}
	// 3rd event: addition → exactly selector_keys
	gotKeys := changeKeys(entries[2].Changes)
	if !gotKeys["selector_keys"] || len(gotKeys) != 1 {
		t.Errorf("addition Changes keys = %v; want selector_keys only", gotKeys)
	}
}

func TestPolicyHistoryService_WorkflowIdChange_DeletedWorkflowResolvesAsNilName(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	wfLive := uuid.New()
	wfGone := uuid.New() // not registered in fakeWorkflowRepo

	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			mkEvent(base, "policy.create", "user:u",
				map[string]any{"priority": float64(100), "workflow_id": wfGone.String(), "selector_keys": []any{"environment_kind"}}),
			mkEvent(base.Add(time.Hour), "policy.update", "user:u",
				map[string]any{"priority": float64(100), "workflow_id": wfLive.String(), "selector_keys": []any{"environment_kind"}}),
		},
	}
	workflows := &fakeWorkflowRepo{byID: map[uuid.UUID]*storage.WorkflowDefinition{
		wfLive: {ID: wfLive, Name: "live-wf"},
	}}

	svc := services.NewPolicyHistoryService(audit, workflows, nil, nil)
	entries, _, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}

	// Create snapshot: deleted workflow → WorkflowName nil
	if entries[0].SnapshotAfter.WorkflowName != nil {
		t.Errorf("create SnapshotAfter.WorkflowName = %v; want nil (deleted)", *entries[0].SnapshotAfter.WorkflowName)
	}

	// Update diff: workflow_id change carries After name, Before name nil
	gotKeys := changeKeys(entries[1].Changes)
	if !gotKeys["workflow_id"] {
		t.Errorf("update diff keys = %v; want workflow_id", gotKeys)
	}
	for _, c := range entries[1].Changes {
		if c.Key == "workflow_id" {
			if c.BeforeWorkflowName != nil {
				t.Errorf("Before workflow name = %v; want nil (deleted)", *c.BeforeWorkflowName)
			}
			if c.AfterWorkflowName == nil || *c.AfterWorkflowName != "live-wf" {
				t.Errorf("After workflow name = %v; want live-wf", c.AfterWorkflowName)
			}
		}
	}
}

func TestPolicyHistoryService_EmptyChain(t *testing.T) {
	ctx := context.Background()
	svc := services.NewPolicyHistoryService(&fakeAuditRepo{}, &fakeWorkflowRepo{}, nil, nil)
	entries, hasMore, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}
	if entries != nil {
		t.Errorf("entries = %v; want nil", entries)
	}
	if hasMore {
		t.Errorf("hasMore = true; want false")
	}
}

func TestPolicyHistoryService_HasMoreFlagPropagates(t *testing.T) {
	ctx := context.Background()
	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			mkEvent(time.Now(), "policy.create", "user:u",
				map[string]any{"priority": float64(100), "selector_keys": []any{"environment_kind"}}),
		},
		hasMore: true,
	}
	svc := services.NewPolicyHistoryService(audit, &fakeWorkflowRepo{}, nil, nil)
	_, hasMore, err := svc.ListForRule(ctx, uuid.New(), 1)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}
	if !hasMore {
		t.Errorf("hasMore = false; want true (storage returned true)")
	}
}

func TestPolicyHistoryService_ActorDisplay_NilReposFallToRaw(t *testing.T) {
	ctx := context.Background()
	audit := &fakeAuditRepo{
		rows: []*storage.AuditEvent{
			mkEvent(time.Now(), "policy.create", "user:11111111-1111-1111-1111-111111111111",
				map[string]any{"priority": float64(100), "selector_keys": []any{"environment_kind"}}),
		},
	}
	svc := services.NewPolicyHistoryService(audit, &fakeWorkflowRepo{}, nil, nil)
	entries, _, err := svc.ListForRule(ctx, uuid.New(), 50)
	if err != nil {
		t.Fatalf("ListForRule: %v", err)
	}
	// Nil users repo → user:<uuid> falls back to short form via ShortFallback
	// (matches the audit handler's historical behavior; preserves wire compat)
	if entries[0].ActorDisplay == "" {
		t.Errorf("ActorDisplay empty; want a non-empty fallback")
	}
	if entries[0].Actor != "user:11111111-1111-1111-1111-111111111111" {
		t.Errorf("raw Actor changed: %q", entries[0].Actor)
	}
}

// ---- small helpers ----------------------------------------------

func changeKeys(changes []services.FieldChange) map[string]bool {
	out := map[string]bool{}
	for _, c := range changes {
		out[c.Key] = true
	}
	return out
}

func equalKeySet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

var _ = sParse // keep helper available without firing a lint warning
