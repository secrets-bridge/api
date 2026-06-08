// R-follow-up #1 (api#118) — storage-level tests for the new
// scoped_policy_authorable field + ListScopedPolicyAuthorable query.
// Migration 0035 adds the column and partial index.

package storage_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func makeWorkflowForAuthorableTest(t *testing.T, repo *storage.Workflows, name string, enabled, authorable bool) *storage.WorkflowDefinition {
	t.Helper()
	w := &storage.WorkflowDefinition{
		Name:                   name,
		MinApprovers:           1,
		WrapTTLCreated:         5 * time.Minute,
		WrapTTLApproved:        10 * time.Minute,
		WrapTTLClaimed:         5 * time.Minute,
		RequestTTL:             24 * time.Hour,
		RequireJustification:   true,
		NotificationChannels:   []string{},
		Enabled:                enabled,
		ScopedPolicyAuthorable: authorable,
	}
	if err := repo.Create(t.Context(), w); err != nil {
		t.Fatalf("Create %s: %v", name, err)
	}
	return w
}

func TestWorkflows_Create_PersistsScopedPolicyAuthorable(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewWorkflows(pool)

	wTrue := makeWorkflowForAuthorableTest(t, repo, "create-true", true, true)
	wFalse := makeWorkflowForAuthorableTest(t, repo, "create-false", true, false)

	rt, err := repo.Get(t.Context(), wTrue.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !rt.ScopedPolicyAuthorable {
		t.Fatal("Create with authorable=true did not persist")
	}
	rf, err := repo.Get(t.Context(), wFalse.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rf.ScopedPolicyAuthorable {
		t.Fatal("Create with authorable=false stored true")
	}
}

func TestWorkflows_Create_DefaultDeny(t *testing.T) {
	// Mirror the default-deny posture migration 0035 establishes:
	// a workflow created without setting the field stays opted-out
	// (Go zero value flows through and matches the column DEFAULT).
	pool := freshDB(t)
	repo := storage.NewWorkflows(pool)
	w := makeWorkflowForAuthorableTest(t, repo, "default-deny", true, false)

	rb, err := repo.Get(t.Context(), w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rb.ScopedPolicyAuthorable {
		t.Fatal("default-deny posture violated — workflow opted in by default")
	}
}

func TestWorkflows_Update_PersistsScopedPolicyAuthorableFlip(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewWorkflows(pool)
	w := makeWorkflowForAuthorableTest(t, repo, "update-flip", true, false)

	// Flip to true.
	w.ScopedPolicyAuthorable = true
	if err := repo.Update(t.Context(), w); err != nil {
		t.Fatal(err)
	}
	r1, err := repo.Get(t.Context(), w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.ScopedPolicyAuthorable {
		t.Fatal("flip to true did not persist")
	}

	// Flip back to false.
	w.ScopedPolicyAuthorable = false
	if err := repo.Update(t.Context(), w); err != nil {
		t.Fatal(err)
	}
	r2, err := repo.Get(t.Context(), w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ScopedPolicyAuthorable {
		t.Fatal("flip to false did not persist")
	}
}

func TestWorkflows_ListScopedPolicyAuthorable_FiltersToEnabledAndAuthorable(t *testing.T) {
	// Predicate must match the partial index from migration 0035:
	//   WHERE enabled = true AND scoped_policy_authorable = true
	pool := freshDB(t)
	repo := storage.NewWorkflows(pool)

	wAA := makeWorkflowForAuthorableTest(t, repo, "enabled-authorable", true, true)
	makeWorkflowForAuthorableTest(t, repo, "enabled-NOT-authorable", true, false)
	makeWorkflowForAuthorableTest(t, repo, "DISABLED-authorable", false, true)
	makeWorkflowForAuthorableTest(t, repo, "disabled-not-authorable", false, false)

	out, err := repo.ListScopedPolicyAuthorable(t.Context())
	if err != nil {
		t.Fatalf("ListScopedPolicyAuthorable: %v", err)
	}
	// Match by ID — the freshDB helper may have already inserted
	// system seed workflows (we don't assume the seed's flag state).
	found := map[uuid.UUID]bool{}
	for _, w := range out {
		found[w.ID] = true
	}
	if !found[wAA.ID] {
		t.Fatalf("expected enabled+authorable workflow in result; got %d workflows", len(out))
	}
	// Other three combinations must NOT appear.
	for _, w := range out {
		if !w.Enabled {
			t.Fatalf("disabled workflow leaked into ListScopedPolicyAuthorable: %s", w.Name)
		}
		if !w.ScopedPolicyAuthorable {
			t.Fatalf("not-authorable workflow leaked: %s", w.Name)
		}
	}
}
