package storage_test

import (
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secrets-bridge/api/pkg/storage"
)

// secrets-bridge/gateway#13: 0049 purges the stored Argo CD tokens (drops
// argocd_endpoints and gitops_app_mappings) with one audit row per
// endpoint, keeps gitops_observations readable as history, moves every
// control_plane environment to none and refuses control_plane after.
// Running it twice changes nothing more and writes no more audit rows.
func TestMigration0049_PurgesArgoCDTokens(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	read := func(name string) string {
		t.Helper()
		b, err := fs.ReadFile(storage.MigrationsFS(), "migrations/"+name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	up, down := read("0049_argocd_only_in_gateway.up.sql"), read("0049_argocd_only_in_gateway.down.sql")

	// Back to the schema before 0049, and back to head whatever happens.
	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("0049 down: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(t.Context(), up) })

	const (
		cipherCanary = "argocd-token-ciphertext-canary-0049"
		dekCanary    = "argocd-token-dek-canary-0049"
		nonceCanary  = "argocd-nonce-canary-0049"
		kmsCanary    = "kms-key-canary-0049"
	)
	var proj, cpEnv, gwEnv uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO projects (name) VALUES ('m49-'||gen_random_uuid()) RETURNING id`).Scan(&proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	for _, e := range []struct {
		dst  *uuid.UUID
		name string
		src  string
	}{{&cpEnv, "tenant-a-uat", "control_plane"}, {&gwEnv, "tenant-a-prod", "gateway"}} {
		if err := pool.QueryRow(ctx, `INSERT INTO environments (project_id, name, type, kind, observation_source)
			VALUES ($1, $2, 'uat', 'non_prod', $3) RETURNING id`, proj, e.name, e.src).Scan(e.dst); err != nil {
			t.Fatalf("environment %s: %v", e.name, err)
		}
	}
	var live, deleted uuid.UUID
	for _, ep := range []struct {
		dst     *uuid.UUID
		name    string
		env     *uuid.UUID
		deleted bool
	}{{&live, "argo-live", &cpEnv, false}, {&deleted, "argo-deleted", nil, true}} {
		if err := pool.QueryRow(ctx, `INSERT INTO argocd_endpoints
			(name, environment_id, base_url, token_ciphertext, token_data_key_ciphertext, token_nonce, token_kms_key_id, deleted_at)
			VALUES ($1, $2, 'https://argocd.example.com', $3, $4, $5, $6, CASE WHEN $7 THEN now() END) RETURNING id`,
			ep.name, ep.env, []byte(cipherCanary), []byte(dekCanary), []byte(nonceCanary), kmsCanary, ep.deleted).Scan(ep.dst); err != nil {
			t.Fatalf("endpoint %s: %v", ep.name, err)
		}
	}
	var reqID, obsID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO access_requests
		(requester_id, type, status, justification, target_provider_type, target_secret_ref, target_keys, workflow_id)
		VALUES ('alice', 'patch', 'executed', 'm49', 'vault', 'team-alpha/uat/db', '["K"]',
		        (SELECT id FROM workflow_definitions WHERE is_system ORDER BY created_at LIMIT 1)) RETURNING id`).Scan(&reqID); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO gitops_observations
		(request_id, argocd_endpoint_id, application_name, polling_state, observed_state)
		VALUES ($1, $2, 'payments-api', 'applied', '{"health_status":"Healthy","sync_status":"Synced"}') RETURNING id`,
		reqID, live).Scan(&obsID); err != nil {
		t.Fatalf("observation: %v", err)
	}

	// tokenHits scans every text, bytea and jsonb column of every table
	// for the token canaries.
	tokenHits := func() []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT table_name, column_name, data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND data_type IN ('bytea', 'text', 'jsonb', 'character varying')`)
		if err != nil {
			t.Fatal(err)
		}
		type col struct{ table, column, typ string }
		var cols []col
		for rows.Next() {
			var c col
			if err := rows.Scan(&c.table, &c.column, &c.typ); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		if len(cols) < 50 {
			t.Fatalf("only %d columns scanned; the scan looks broken", len(cols))
		}
		var hits []string
		for _, c := range cols {
			tbl, cl := pgx.Identifier{c.table}.Sanitize(), pgx.Identifier{c.column}.Sanitize()
			q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE strpos(%s::text, $1) > 0`, tbl, cl)
			if c.typ == "bytea" {
				q = fmt.Sprintf(`SELECT count(*) FROM %s WHERE position(convert_to($1, 'UTF8') IN %s) > 0`, tbl, cl)
			}
			for _, canary := range []string{cipherCanary, dekCanary, nonceCanary, kmsCanary} {
				var n int
				if err := pool.QueryRow(ctx, q, canary).Scan(&n); err != nil {
					t.Fatalf("scan %s.%s: %v", c.table, c.column, err)
				}
				if n != 0 {
					hits = append(hits, c.table+"."+c.column)
				}
			}
		}
		return hits
	}
	// The scan finds the envelope before the migration, so it is not
	// vacuous afterwards.
	if hits := tokenHits(); len(hits) != 4 {
		t.Fatalf("token canaries before 0049 found in %v; want the four argocd_endpoints token columns", hits)
	}

	for run := 1; run <= 2; run++ {
		if _, err := pool.Exec(ctx, up); err != nil {
			t.Fatalf("run %d of 0049: %v", run, err)
		}
	}

	// The token tables are gone.
	for _, tbl := range []string{"argocd_endpoints", "gitops_app_mappings"} {
		var reg *string
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, tbl).Scan(&reg); err != nil {
			t.Fatal(err)
		}
		if reg != nil {
			t.Fatalf("%s still exists after 0049", tbl)
		}
	}

	// No token material is left in any column of any table.
	if hits := tokenHits(); len(hits) != 0 {
		t.Fatalf("token material left after 0049 in %v", hits)
	}

	// One audit row per endpoint across both runs, ids only.
	type auditRow struct {
		actor, resource, status string
		meta                    map[string]any
	}
	auditFor := func(action string) []auditRow {
		t.Helper()
		rs, err := pool.Query(ctx, `SELECT actor, resource, status, metadata FROM audit_events WHERE action = $1 ORDER BY resource`, action)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		var out []auditRow
		for rs.Next() {
			var r auditRow
			if err := rs.Scan(&r.actor, &r.resource, &r.status, &r.meta); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	purged := auditFor("argocd_endpoint.token_purged")
	if len(purged) != 2 {
		t.Fatalf("token_purged audit rows = %d; want one per endpoint (2) across two runs", len(purged))
	}
	want := []string{"argocd_endpoint:" + live.String(), "argocd_endpoint:" + deleted.String()}
	for _, r := range purged {
		if r.actor != "system:migration" || r.status != "success" || !slices.Contains(want, r.resource) {
			t.Fatalf("token_purged row = %+v", r)
		}
		for k := range r.meta {
			if !slices.Contains([]string{"environment_id", "changed_keys", "reason"}, k) {
				t.Fatalf("token_purged metadata carries %q: %v", k, r.meta)
			}
		}
		if !metaOnAllowlist("argocd_endpoint.token_purged", r.meta) {
			t.Fatalf("token_purged metadata is not on the audit allowlist: %v", r.meta)
		}
		if r.resource == want[0] && r.meta["environment_id"] != cpEnv.String() {
			t.Fatalf("token_purged row for the live endpoint = %v; want its environment id", r.meta)
		}
	}

	// control_plane moved to none, audited once; gateway untouched.
	moved := auditFor("environment.observation_source.update")
	if len(moved) != 1 || moved[0].resource != "environment:"+cpEnv.String() ||
		moved[0].meta["observation_source_before"] != "control_plane" || moved[0].meta["observation_source_after"] != "none" ||
		!metaOnAllowlist("environment.observation_source.update", moved[0].meta) {
		t.Fatalf("observation source audit rows = %+v; want one for the control_plane environment", moved)
	}
	srcOf := func(id uuid.UUID) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx, `SELECT observation_source FROM environments WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if srcOf(cpEnv) != "none" || srcOf(gwEnv) != "gateway" {
		t.Fatalf("sources after 0049 = %s, %s; want none, gateway", srcOf(cpEnv), srcOf(gwEnv))
	}
	if _, err := pool.Exec(ctx, `UPDATE environments SET observation_source = 'control_plane' WHERE id = $1`, gwEnv); err == nil {
		t.Fatal("control_plane accepted after 0049")
	}
	var def string
	if err := pool.QueryRow(ctx, `INSERT INTO environments (project_id, name, type, kind) VALUES ($1, 'tenant-a-dev', 'dev', 'non_prod')
		RETURNING observation_source`, proj).Scan(&def); err != nil || def != "none" {
		t.Fatalf("default observation_source = %q, %v; want none", def, err)
	}

	// The history row is untouched and still readable.
	hist, err := storage.NewGitOpsObservations(pool).ListForRequest(ctx, reqID)
	if err != nil || len(hist) != 1 || hist[0].ID != obsID || hist[0].PollingState != storage.GitOpsStateApplied ||
		hist[0].ObservedState["health_status"] != "Healthy" {
		t.Fatalf("history after 0049 = %+v, %v", hist, err)
	}
	var endpointID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT argocd_endpoint_id FROM gitops_observations WHERE id = $1`, obsID).Scan(&endpointID); err != nil || endpointID != live {
		t.Fatalf("history row endpoint id = %s, %v; want %s kept as a bare id", endpointID, err, live)
	}
}

// metaOnAllowlist reports whether the audit sanitizer would keep meta
// unchanged: every key on the allowlist with a value of the right shape.
func metaOnAllowlist(action string, meta map[string]any) bool {
	return reflect.DeepEqual(storage.SanitizeAuditMetadata(action, meta), meta)
}
