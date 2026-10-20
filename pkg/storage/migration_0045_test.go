package storage_test

import (
	"io/fs"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// skills#103 / api#288 follow-up: 0045 clears every stored
// allow_self_approval and writes one audit row per workflow it changes.
// It leaves other workflows alone, and a second run changes nothing.
func TestMigration0045_ClearsStoredSelfApproval(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewWorkflows(pool)
	mk := func(name string) *storage.WorkflowDefinition {
		wf := &storage.WorkflowDefinition{
			Name: name + "-" + uuid.NewString()[:8], MinApprovers: 1,
			WrapTTLCreated: time.Hour, WrapTTLApproved: time.Hour,
			WrapTTLClaimed: time.Minute, RequestTTL: time.Hour, Enabled: true,
		}
		if err := repo.Create(ctx, wf); err != nil {
			t.Fatalf("create workflow: %v", err)
		}
		return wf
	}
	flagged, clean := mk("m45-flagged"), mk("m45-clean")
	if _, err := pool.Exec(ctx, `UPDATE workflow_definitions SET allow_self_approval = true WHERE id = $1`, flagged.ID); err != nil {
		t.Fatalf("store the old flag: %v", err)
	}

	up, err := fs.ReadFile(storage.MigrationsFS(), "migrations/0045_clear_stored_self_approval.up.sql")
	if err != nil {
		t.Fatalf("read 0045: %v", err)
	}
	for run := 1; run <= 2; run++ {
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("run %d of 0045: %v", run, err)
		}
	}

	var stillSet int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM workflow_definitions WHERE allow_self_approval`).Scan(&stillSet); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stillSet != 0 {
		t.Fatalf("%d workflows still have allow_self_approval after 0045", stillSet)
	}

	type row struct {
		actor, status string
		meta          map[string]any
	}
	rowsFor := func(id uuid.UUID) []row {
		rs, err := pool.Query(ctx, `SELECT actor, status, metadata FROM audit_events
			WHERE action = 'workflow.update' AND resource = $1`, "workflow:"+id.String())
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		defer rs.Close()
		var out []row
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.actor, &r.status, &r.meta); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, r)
		}
		return out
	}
	got := rowsFor(flagged.ID)
	if len(got) != 1 {
		t.Fatalf("audit rows for the cleared workflow = %d, want exactly 1 across two runs", len(got))
	}
	keys, _ := got[0].meta["changed_keys"].([]any)
	if got[0].actor != "system:migration" || got[0].status != "success" ||
		got[0].meta["workflow_id"] != flagged.ID.String() || len(keys) != 1 || keys[0] != "allow_self_approval" {
		t.Fatalf("audit row = %+v", got[0])
	}
	if n := len(rowsFor(clean.ID)); n != 0 {
		t.Fatalf("audit rows for a workflow 0045 didn't change = %d, want 0", n)
	}
}
