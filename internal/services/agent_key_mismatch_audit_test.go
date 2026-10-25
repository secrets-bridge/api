package services_test

// The agent.key.mismatch audit rollup (skills#116): one slot per
// (agent, error_kind), and the events a slot folds are counted onto
// the next row it writes. Needs TEST_DATABASE_URL and TEST_REDIS_URL.

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

type keyMismatchRow struct {
	ErrorKind  string `json:"error_kind"`
	Presented  string `json:"presented_key_fingerprint"`
	Bound      string `json:"public_key_fingerprint"`
	Suppressed *int64 `json:"suppressed_count"`
}

func keyMismatchRows(t *testing.T, pool *storage.Pool, id uuid.UUID) []keyMismatchRow {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT metadata FROM audit_events
		WHERE action = 'agent.key.mismatch' AND resource = $1
		ORDER BY occurred_at, id`, "agent:"+id.String())
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var out []keyMismatchRow
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var r keyMismatchRow
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// endKeyMismatchWindow drops the rollup slot for (agent, kind), which is
// what the slot's 60 s expiry does, so the test need not sleep.
func endKeyMismatchWindow(t *testing.T, rdb *runtime.Client, id uuid.UUID, kind string) {
	t.Helper()
	if err := rdb.Raw().Del(t.Context(), rdb.Key("agent-key-mismatch-audit", id.String()+":"+kind)).Err(); err != nil {
		t.Fatalf("del slot: %v", err)
	}
}

func mintKeyedAgent(t *testing.T, svc *services.AgentService) *services.MintedAgent {
	t.Helper()
	minted, err := svc.Mint(t.Context(), keyedMint(services.MintInput{Name: "key-audit"}))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return minted
}

func wantKeyMismatch(t *testing.T, svc *services.AgentService, a *services.MintedAgent, fp string) {
	t.Helper()
	if err := svc.AuthenticateAgentKey(t.Context(), a.ID, a.AgentSecret, fp); !errors.Is(err, services.ErrAgentKeyMismatch) {
		t.Fatalf("AuthenticateAgentKey(%q): %v; want ErrAgentKeyMismatch", fp, err)
	}
}

var wrongFingerprint = sealing.Fingerprint([]byte("not the bound key"))

// A headerless call must not hide a wrong-key attempt right after it:
// both rows are written, and the second names the presented key.
func TestAgentKeyMismatchAudit_MissingThenMismatchWritesBoth(t *testing.T) {
	svc, pool, _ := bootstrap(t)
	a := mintKeyedAgent(t, svc)

	wantKeyMismatch(t, svc, a, "")
	wantKeyMismatch(t, svc, a, wrongFingerprint)

	rows := keyMismatchRows(t, pool, a.ID)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v; want a missing row and a mismatch row", rows)
	}
	if rows[0].ErrorKind != "missing" || rows[0].Presented != "" {
		t.Errorf("first row = %+v; want error_kind missing, no presented fingerprint", rows[0])
	}
	if rows[1].ErrorKind != "mismatch" || rows[1].Presented != wrongFingerprint || rows[1].Bound != testAgentFingerprint {
		t.Errorf("second row = %+v; want error_kind mismatch naming %s", rows[1], wrongFingerprint)
	}
	for _, r := range rows {
		if r.Suppressed != nil {
			t.Errorf("first row of a slot carries suppressed_count: %+v", r)
		}
	}
}

// Repeated mismatches in one window are one row; the first row after
// the window says how many it folded.
func TestAgentKeyMismatchAudit_SuppressedCountOnNextRow(t *testing.T) {
	svc, pool, rdb := bootstrap(t)
	a := mintKeyedAgent(t, svc)

	for i := 0; i < 5; i++ {
		wantKeyMismatch(t, svc, a, wrongFingerprint)
	}
	if rows := keyMismatchRows(t, pool, a.ID); len(rows) != 1 || rows[0].Suppressed != nil {
		t.Fatalf("after 5 mismatches in one window: %+v; want one row without suppressed_count", rows)
	}

	endKeyMismatchWindow(t, rdb, a.ID, "mismatch")
	wantKeyMismatch(t, svc, a, wrongFingerprint)
	rows := keyMismatchRows(t, pool, a.ID)
	if len(rows) != 2 || rows[1].Suppressed == nil || *rows[1].Suppressed != 4 {
		t.Fatalf("row after the window: %+v; want suppressed_count 4", rows)
	}

	// The count was taken: the window after that starts from zero.
	endKeyMismatchWindow(t, rdb, a.ID, "mismatch")
	wantKeyMismatch(t, svc, a, wrongFingerprint)
	rows = keyMismatchRows(t, pool, a.ID)
	if len(rows) != 3 || rows[2].Suppressed != nil {
		t.Fatalf("third row: %+v; want no suppressed_count", rows)
	}
}

// The rollup still bounds the volume: a flood of every kind writes at
// most one row per kind per window, and each kind counts only its own
// folded events.
func TestAgentKeyMismatchAudit_BoundsVolume(t *testing.T) {
	svc, pool, rdb := bootstrap(t)
	a := mintKeyedAgent(t, svc)

	for i := 0; i < 30; i++ {
		wantKeyMismatch(t, svc, a, "")
		wantKeyMismatch(t, svc, a, "not-a-fingerprint")
		wantKeyMismatch(t, svc, a, wrongFingerprint)
	}
	rows := keyMismatchRows(t, pool, a.ID)
	if len(rows) != 3 {
		t.Fatalf("90 rejections over 3 kinds wrote %d rows; want 3: %+v", len(rows), rows)
	}
	kinds := map[string]bool{}
	for _, r := range rows {
		kinds[r.ErrorKind] = true
	}
	for _, k := range []string{"missing", "malformed", "mismatch"} {
		if !kinds[k] {
			t.Errorf("no %s row: %+v", k, rows)
		}
	}

	endKeyMismatchWindow(t, rdb, a.ID, "malformed")
	wantKeyMismatch(t, svc, a, "not-a-fingerprint")
	wantKeyMismatch(t, svc, a, wrongFingerprint) // still inside its window
	rows = keyMismatchRows(t, pool, a.ID)
	if len(rows) != 4 || rows[3].ErrorKind != "malformed" || rows[3].Suppressed == nil || *rows[3].Suppressed != 29 {
		t.Fatalf("after the malformed window: %+v; want a 4th malformed row with suppressed_count 29", rows)
	}

	// The right key still passes, and writes nothing.
	if err := svc.AuthenticateAgentKey(t.Context(), a.ID, a.AgentSecret, testAgentFingerprint); err != nil {
		t.Fatalf("bound key: %v", err)
	}
	if n := len(keyMismatchRows(t, pool, a.ID)); n != 4 {
		t.Fatalf("rows after an accepted call = %d; want 4", n)
	}
}
