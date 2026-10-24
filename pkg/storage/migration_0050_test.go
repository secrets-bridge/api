package storage_test

import (
	"io/fs"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// api#308 (ADR 0002 S4): 0050 adds the discovery storage. The down drops
// every table, column, constraint and the team_covers function it added,
// soft-deletes bindings to discovered targets (nothing could dispatch
// them safely after the rollback) and rewrites the two new verdict
// reasons. The up applies again cleanly after the down.
func TestMigration0050_UpDown(t *testing.T) {
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
	up, down := read("0050_gateway_discovery.up.sql"), read("0050_gateway_discovery.down.sql")
	t.Cleanup(func() {
		_, _ = pool.Exec(t.Context(), `DELETE FROM gateway_connector_bindings; DELETE FROM gateways;`)
	})

	exists := func(q string, args ...any) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, q, args...).Scan(&ok); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return ok
	}
	column := func(table, col string) bool {
		return exists(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2)`, table, col)
	}
	table := func(name string) bool { return exists(`SELECT to_regclass($1) IS NOT NULL`, name) }
	fn := func() bool { return exists(`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'team_covers')`) }

	// Head: the schema is there and its checks hold.
	for _, tb := range []string{"gateway_discovered_targets", "gateway_connector_project_teams", "gateway_discovery_snapshots"} {
		if !table(tb) {
			t.Fatalf("table %s missing at head", tb)
		}
	}
	for _, c := range [][2]string{
		{"gateway_connectors", "approved_scope_digest"}, {"gateway_connectors", "discovery_lease_id"},
		{"gateway_connectors", "status_reason"}, {"gateway_connectors", "last_discovery_at"},
		{"gateway_connector_bindings", "suspended_reason"}, {"gateway_connector_bindings", "target_source"},
		{"gateways", "discovery_max_entries"},
	} {
		if !column(c[0], c[1]) {
			t.Fatalf("column %s.%s missing at head", c[0], c[1])
		}
	}
	if !fn() {
		t.Fatal("team_covers missing at head")
	}

	var gw, conn, proj, env uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO gateways (name, boundary, created_by) VALUES ('m50-'||substr(gen_random_uuid()::text,1,8), 'tenant-a-uat', 'test') RETURNING id`).Scan(&gw); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO gateway_connectors (gateway_id, name, kind) VALUES ($1, 'argocd-main', 'argocd') RETURNING id`, gw).Scan(&conn); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (name) VALUES ('m50-'||gen_random_uuid()) RETURNING id`).Scan(&proj); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO environments (project_id, name, type, kind) VALUES ($1, 'uat', 'uat', 'non_prod') RETURNING id`, proj).Scan(&env); err != nil {
		t.Fatal(err)
	}
	// The target id is the derived digest, never a uid or a static id.
	insTarget := func(id string) error {
		_, err := pool.Exec(ctx, `INSERT INTO gateway_discovered_targets
			(connector_id, target_id, gateway_id, app_project, namespace, name, generation_first_seen, last_seen_generation, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, 'team-a-apps', 'argocd', 'payments-api', 1, 1, now(), now())`, conn, id, gw)
		return err
	}
	if err := insTarget("6f1c2c1e-0000-4000-8000-0000000000a1"); err == nil {
		t.Fatal("a raw uid was accepted as a discovered target id")
	}
	if err := insTarget("d-li3oyoq5xwjxe72ps7qqn5dikf"); err != nil {
		t.Fatalf("derived target id refused: %v", err)
	}
	// discovered_at keeps whole seconds only.
	if _, err := pool.Exec(ctx, `INSERT INTO gateway_discovery_snapshots (connector_id, generation, discovered_at, alg, nonce, ciphertext)
		VALUES ($1, 1, '2026-10-24T12:00:00.5Z', 'A256GCM+HKDF-SHA256/v1', 'oKGio6Slpqeoqaqr', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA')`, conn); err == nil {
		t.Fatal("a fractional discovered_at was stored")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO gateway_connector_bindings
		(gateway_id, environment_id, provider_connection_id, secret_ref, argocd_connector_id, argocd_target_id, target_source, created_by)
		VALUES ($1, $2, NULL, NULL, $3, 'd-li3oyoq5xwjxe72ps7qqn5dikf', 'discovered', 'test')`, gw, env, conn); err == nil {
		t.Fatal("binding without a secret scope accepted")
	}
	var secret uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO secrets (cluster_name, provider_type, secret_ref, status) VALUES ('tenant-a-uat', 'vault', 'team-alpha/uat/'||gen_random_uuid(), 'present') RETURNING id`).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	var discBinding, staticBinding uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO gateway_connector_bindings
		(gateway_id, environment_id, secret_id, argocd_connector_id, argocd_target_id, target_source, created_by)
		VALUES ($1, $2, $3, $4, 'd-li3oyoq5xwjxe72ps7qqn5dikf', 'discovered', 'test') RETURNING id`, gw, env, secret, conn).Scan(&discBinding); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO gateway_connector_bindings
		(gateway_id, environment_id, secret_id, argocd_connector_id, argocd_target_id, created_by)
		VALUES ($1, $2, $3, $4, 'payments-api', 'test') RETURNING id`, gw, env, secret, conn).Scan(&staticBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE gateway_connector_bindings SET suspended_reason = 'scope_changed' WHERE id = $1`, staticBinding); err == nil {
		t.Fatal("suspended_reason without suspended_at accepted")
	}

	// Down.
	if _, err := pool.Exec(ctx, down); err != nil {
		t.Fatalf("0050 down: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(t.Context(), up) })
	for _, tb := range []string{"gateway_discovered_targets", "gateway_connector_project_teams", "gateway_discovery_snapshots"} {
		if table(tb) {
			t.Fatalf("table %s left by the down", tb)
		}
	}
	for _, c := range [][2]string{
		{"gateway_connectors", "approved_scope_digest"}, {"gateway_connectors", "discovery_lease_id"},
		{"gateway_connectors", "status_reason"}, {"gateway_connector_bindings", "suspended_reason"},
		{"gateway_connector_bindings", "target_source"}, {"gateways", "discovery_max_entries"},
	} {
		if column(c[0], c[1]) {
			t.Fatalf("column %s.%s left by the down", c[0], c[1])
		}
	}
	if fn() {
		t.Fatal("team_covers left by the down")
	}
	var discDeleted, staticDeleted bool
	if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM gateway_connector_bindings WHERE id = $1`, discBinding).Scan(&discDeleted); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM gateway_connector_bindings WHERE id = $1`, staticBinding).Scan(&staticDeleted); err != nil {
		t.Fatal(err)
	}
	if !discDeleted || staticDeleted {
		t.Fatalf("after down: discovered binding deleted = %v, static deleted = %v; want true, false", discDeleted, staticDeleted)
	}

	// Up again, from the pre-0050 schema.
	if _, err := pool.Exec(ctx, up); err != nil {
		t.Fatalf("0050 up after down: %v", err)
	}
	if !table("gateway_discovered_targets") || !column("gateway_connectors", "approved_scope_digest") || !fn() {
		t.Fatal("0050 up after down did not restore the schema")
	}
	var src string
	if err := pool.QueryRow(ctx, `SELECT target_source FROM gateway_connector_bindings WHERE id = $1`, staticBinding).Scan(&src); err != nil || src != "static" {
		t.Fatalf("existing binding target_source = %q, %v; want static", src, err)
	}
}

// team_covers walks up from the team: the root itself and any descendant
// are covered, a sibling and the parent are not.
func TestTeamCovers(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	mk := func(parent *uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO teams (name, parent_team_id) VALUES ('tc-'||gen_random_uuid(), $1) RETURNING id`, parent).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	root := mk(nil)
	child := mk(&root)
	grand := mk(&child)
	sibling := mk(nil)
	for _, c := range []struct {
		root, team uuid.UUID
		want       bool
	}{
		{root, root, true}, {root, child, true}, {root, grand, true},
		{child, root, false}, {root, sibling, false}, {sibling, grand, false},
	} {
		var got bool
		if err := pool.QueryRow(ctx, `SELECT team_covers($1, $2)`, c.root, c.team).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("team_covers(%s, %s) = %v; want %v", c.root, c.team, got, c.want)
		}
	}
	var got bool
	if err := pool.QueryRow(ctx, `SELECT team_covers($1, NULL)`, root).Scan(&got); err != nil || got {
		t.Fatalf("team_covers(root, NULL) = %v, %v; want false", got, err)
	}
}
