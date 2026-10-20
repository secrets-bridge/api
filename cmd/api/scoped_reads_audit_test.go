package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// These tests drive the REAL router built by newApp (every route, guard
// and handler wiring from main.go) against real Postgres + Redis. They
// skip when TEST_DATABASE_URL / TEST_REDIS_URL are unset.
//
// They cover API-N-04 (project-scoped reads), API-N-05 (privilege and
// tenancy writes audited, provenance from the session), API-N-06
// (malformed grant scopes) and API-15 (real audit actor on job, agent
// and argocd actions).

type liveApp struct {
	app  *fiber.App
	pool *storage.Pool
	// logs holds everything the app logged, for canary checks.
	logs *hygLogBuffer
}

func newLiveApp(t *testing.T, opts ...func(*Config)) *liveApp {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dsn, MaxConns: 8, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)

	const wipe = `
		DELETE FROM gateway_connector_bindings;
		DELETE FROM gateways;
		DELETE FROM gitops_observations;
		DELETE FROM gitops_app_mappings;
		DELETE FROM argocd_endpoints;
		DELETE FROM reveal_sessions;
		DELETE FROM secret_wraps;
		DELETE FROM approvals;
		DELETE FROM sync_jobs;
		DELETE FROM access_requests;
		DELETE FROM project_secrets;
		DELETE FROM secrets;
		DELETE FROM project_provider_connections;
		DELETE FROM agent_enrollment_tokens;
		DELETE FROM agents;
		DELETE FROM provider_connections;
		DELETE FROM sso_providers;
		UPDATE sso_settings SET public_url = NULL, pending_cap = 50;
		DELETE FROM policy_rules WHERE is_system = false;
		DELETE FROM team_members;
		DELETE FROM teams;
		DELETE FROM user_roles;
		DELETE FROM roles WHERE is_system = false;
		DELETE FROM workflow_definitions WHERE is_system = false;
		DELETE FROM environments;
		DELETE FROM projects;
		DELETE FROM sessions;
		DELETE FROM user_mfa_factors;
		DELETE FROM local_users;`
	if _, err := pool.Exec(ctx, wipe); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL})
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	km, err := keymgmt.NewLocalKMS(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	authSvc := services.NewAuthService(
		storage.NewLocalUsers(pool), storage.NewRoles(pool), storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
	)

	// newApp flips the package-level header-identity switch from the
	// config; restore it so other tests keep the secure default.
	prev := middleware.AllowInsecureHeaderIdentity
	t.Cleanup(func() { middleware.AllowInsecureHeaderIdentity = prev })

	appCfg := Config{
		Env:                     ModeDev,
		GitOpsEnabled:           true,
		AllowInsecureHeaderAuth: true,
		AllowDirectAgentMint:    true,
		AllowInsecureVaultAddr:  true,
	}
	for _, o := range opts {
		o(&appCfg)
	}
	logs := &hygLogBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &liveApp{app: newApp(appCfg, logger, pool, rdb, km, authSvc), pool: pool, logs: logs}
}

// grantUser creates a fresh user holding a fresh role with perms at the
// given raw scope JSON (inserted verbatim, so malformed shapes can be
// seeded the way a legacy row would look).
func (l *liveApp) grantUser(t *testing.T, perms []string, scopeJSON string) string {
	t.Helper()
	uid := uuid.New().String()
	l.addGrant(t, uid, perms, scopeJSON)
	return uid
}

func (l *liveApp) addGrant(t *testing.T, uid string, perms []string, scopeJSON string) uuid.UUID {
	t.Helper()
	permsJSON, _ := json.Marshal(perms)
	roleID := uuid.New()
	if _, err := l.pool.Exec(t.Context(),
		`INSERT INTO roles (id, name, permissions, is_system) VALUES ($1, $2, $3::jsonb, false)`,
		roleID, "it-role-"+roleID.String()[:8], string(permsJSON)); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := l.pool.Exec(t.Context(),
		`INSERT INTO user_roles (user_id, role_id, scope) VALUES ($1, $2, $3::jsonb)`,
		uid, roleID, scopeJSON); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	return roleID
}

func (l *liveApp) call(t *testing.T, method, path, user string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.Header.Set("X-User-Id", user)
	}
	resp, err := l.app.Test(req, fiber.TestConfig{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

type auditRow struct {
	Actor         string
	Resource      string
	CorrelationID uuid.UUID
	Metadata      map[string]any
}

func (l *liveApp) auditRows(t *testing.T, action string) []auditRow {
	t.Helper()
	rows, err := l.pool.Query(t.Context(),
		`SELECT actor, resource, correlation_id, metadata FROM audit_events WHERE action = $1 ORDER BY occurred_at`, action)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var meta []byte
		if err := rows.Scan(&r.Actor, &r.Resource, &r.CorrelationID, &meta); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		_ = json.Unmarshal(meta, &r.Metadata)
		out = append(out, r)
	}
	return out
}

// requireOneAudit asserts exactly one audit row exists for action, that it
// names the session actor and carries a correlation id, and returns it.
func (l *liveApp) requireOneAudit(t *testing.T, action, actorUserID string) auditRow {
	t.Helper()
	rows := l.auditRows(t, action)
	if len(rows) != 1 {
		t.Fatalf("audit %q: got %d rows, want exactly 1", action, len(rows))
	}
	r := rows[0]
	if want := "user:" + actorUserID; r.Actor != want {
		t.Errorf("audit %q actor = %q, want %q", action, r.Actor, want)
	}
	if r.CorrelationID == uuid.Nil {
		t.Errorf("audit %q has no correlation id", action)
	}
	return r
}

func mustJSON(t *testing.T, raw []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode %s: %v", string(raw), err)
	}
}

// ---- API-N-04: project-scoped reads ---------------------------------

func TestLive_ProjectScopedReads_404OutOfScope(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	projA, projB := uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1,'tenant-a'),($2,'tenant-b')`, projA, projB); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	envs := storage.NewEnvironments(l.pool)
	envB := &storage.Environment{ProjectID: projB, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := envs.Create(ctx, envB); err != nil {
		t.Fatalf("seed env: %v", err)
	}

	// A secret bound to project B's uat env, with two named keys.
	sec := &storage.Secret{ClusterName: "tenant-b-uat", ProviderType: "vault", SecretRef: "team-alpha/uat/db", Status: "present"}
	if err := storage.NewSecrets(l.pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if err := storage.NewProjectSecrets(l.pool).Bind(ctx, &storage.ProjectSecret{
		ProjectID: projB, SecretID: sec.ID, EnvironmentID: &envB.ID,
		AllowedKeys: []string{"DB_USER", "DB_PASSWORD"}, AllowedOps: []string{storage.OpRead}, CreatedBy: "seed",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// A project-anchored policy rule on B.
	var defaultWF uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE is_default LIMIT 1`).Scan(&defaultWF); err != nil {
		t.Fatalf("default workflow: %v", err)
	}
	ruleID := uuid.New()
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO policy_rules (id, name, selector, workflow_id, priority, project_id)
		 VALUES ($1, 'b-uat-rule', '{"environment_kind":"non_prod"}'::jsonb, $2, 100, $3)`,
		ruleID, defaultWF, projB); err != nil {
		t.Fatalf("seed policy rule: %v", err)
	}

	// A provider connection bound to B's uat env.
	connID, bindingID := uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO provider_connections (id, name, type, auth_method, scope) VALUES ($1, 'vault-b', 'vault', 'token', '{"address":"https://vault.example.com"}'::jsonb)`,
		connID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO project_provider_connections (id, project_id, environment_id, provider_connection_id) VALUES ($1, $2, $3, $4)`,
		bindingID, projB, envB.ID, connID); err != nil {
		t.Fatalf("seed connection binding: %v", err)
	}

	nobody := uuid.New().String() // authenticated, zero grants
	aDev := l.grantUser(t, []string{"secret.list", "secret.request"}, `{"project_id":"`+projA.String()+`"}`)
	bReader := l.grantUser(t, []string{"secret.list"}, `{"project_id":"`+projB.String()+`"}`)
	bAuthor := l.grantUser(t, []string{"policy.author"}, `{"project_id":"`+projB.String()+`"}`)
	bBinder := l.grantUser(t, []string{"integration.bind"}, `{"project_id":"`+projB.String()+`"}`)

	envSecrets := "/api/v1/projects/" + projB.String() + "/environments/" + envB.ID.String() + "/secrets"
	rules := "/api/v1/projects/" + projB.String() + "/policy-rules"
	rule := rules + "/" + ruleID.String()
	history := rule + "/history"
	bindings := "/api/v1/projects/" + projB.String() + "/provider-connection-bindings"

	reads := []string{envSecrets, rules, rule, history, bindings}
	for _, p := range reads {
		if code, _ := l.call(t, http.MethodGet, p, "", nil); code != http.StatusUnauthorized {
			t.Errorf("guest GET %s = %d, want 401", p, code)
		}
	}
	for _, outsider := range []struct{ name, id string }{{"no-grants", nobody}, {"project-a-dev", aDev}} {
		for _, p := range reads {
			code, body := l.call(t, http.MethodGet, p, outsider.id, nil)
			if code != http.StatusNotFound {
				t.Errorf("%s GET %s = %d, want 404 (body %s)", outsider.name, p, code, body)
			}
			for _, leak := range []string{"team-alpha/uat/db", "DB_PASSWORD", sec.ID.String(), envB.ID.String(), ruleID.String(), bindingID.String()} {
				if strings.Contains(string(body), leak) {
					t.Errorf("%s GET %s leaked %q", outsider.name, p, leak)
				}
			}
		}
	}

	// A project-B reader sees the real data on every read.
	code, body := l.call(t, http.MethodGet, envSecrets, bReader, nil)
	if code != http.StatusOK || !strings.Contains(string(body), "DB_PASSWORD") {
		t.Errorf("B reader env secrets = %d %s, want 200 with key names", code, body)
	}
	code, body = l.call(t, http.MethodGet, rules, bReader, nil)
	if code != http.StatusOK || !strings.Contains(string(body), ruleID.String()) {
		t.Errorf("B reader policy-rules = %d %s, want 200 with the rule", code, body)
	}
	if code, body = l.call(t, http.MethodGet, rule, bReader, nil); code != http.StatusOK {
		t.Errorf("B reader policy-rule get = %d %s, want 200", code, body)
	}
	if code, body = l.call(t, http.MethodGet, history, bReader, nil); code != http.StatusOK {
		t.Errorf("B reader policy-rule history = %d %s, want 200", code, body)
	}
	code, body = l.call(t, http.MethodGet, bindings, bReader, nil)
	if code != http.StatusOK || !strings.Contains(string(body), bindingID.String()) {
		t.Errorf("B reader bindings = %d %s, want 200 with the binding", code, body)
	}

	// The people who author / bind on B keep reading what they manage.
	if code, body = l.call(t, http.MethodGet, rules, bAuthor, nil); code != http.StatusOK {
		t.Errorf("B policy author policy-rules = %d %s, want 200", code, body)
	}
	if code, body = l.call(t, http.MethodGet, bindings, bBinder, nil); code != http.StatusOK {
		t.Errorf("B binder bindings = %d %s, want 200", code, body)
	}
	// ...but a binder or author scope does not open the dev secret list.
	if code, _ = l.call(t, http.MethodGet, envSecrets, bBinder, nil); code != http.StatusNotFound {
		t.Errorf("B binder env secrets = %d, want 404", code)
	}
}

// ---- API-N-06: malformed grant scopes --------------------------------

func TestLive_MalformedGrantScope_RejectedAndFailsClosed(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	// Pre-existing malformed rows (inserted directly, as legacy data would
	// be). Each carries audit.read, which GET /audit-events requires at
	// GLOBAL scope. None of them may pass that gate.
	malformed := map[string]string{
		"empty project_id":   `{"project_id":""}`,
		"null project_id":    `{"project_id":null}`,
		"numeric team_id":    `{"team_id":123}`,
		"unknown key":        `{"tenant":"tenant-a"}`,
		"empty prefix + env": `{"secret_ref_prefix":"","environment":"uat"}`,
		"json null scope":    `null`,
	}
	for name, scope := range malformed {
		uid := l.grantUser(t, []string{"audit.read"}, scope)
		if code, _ := l.call(t, http.MethodGet, "/api/v1/audit-events", uid, nil); code != http.StatusForbidden {
			t.Errorf("legacy %s grant: GET /audit-events = %d, want 403 (must not act as global)", name, code)
		}
	}
	// Control: a real global grant still passes.
	global := l.grantUser(t, []string{"audit.read"}, `{}`)
	if code, _ := l.call(t, http.MethodGet, "/api/v1/audit-events", global, nil); code != http.StatusOK {
		t.Fatalf("global audit.read = %d, want 200", code)
	}

	// A PARTIAL collapse widens too: {"project_id":"","environment":"uat"}
	// used to evaluate as {"environment":"uat"}, i.e. every project's uat.
	// The scoped developer dropdown checks secret.request against
	// {project_id, environment}.
	proj := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1, 'tenant-b')`, proj); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	uat := &storage.Environment{ProjectID: proj, Name: "uat", Type: storage.EnvironmentTypeUAT, Kind: storage.EnvironmentKindNonProd}
	if err := storage.NewEnvironments(l.pool).Create(ctx, uat); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	partial := l.grantUser(t, []string{"secret.request"}, `{"project_id":"","environment":"uat"}`)
	dropdown := "/api/v1/provider-connections?project_id=" + proj.String() + "&environment_id=" + uat.ID.String()
	if code, body := l.call(t, http.MethodGet, dropdown, partial, nil); code != http.StatusForbidden {
		t.Errorf("legacy {project_id:\"\",environment:uat} grant: dropdown = %d %s, want 403", code, body)
	}
	scoped := l.grantUser(t, []string{"secret.request"}, `{"project_id":"`+proj.String()+`","environment":"uat"}`)
	if code, body := l.call(t, http.MethodGet, dropdown, scoped, nil); code != http.StatusOK {
		t.Errorf("well-formed scoped grant: dropdown = %d %s, want 200", code, body)
	}

	// The write side refuses the same shapes at POST /user-roles.
	admin := l.grantUser(t, []string{"user_role.edit"}, `{}`)
	var roleID uuid.UUID
	if err := l.pool.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'developer'`).Scan(&roleID); err != nil {
		t.Fatalf("developer role: %v", err)
	}
	target := uuid.New().String()
	bad := []map[string]any{
		{"project_id": ""},
		{"project_id": nil},
		{"team_id": 123},
		{"tenant": "tenant-a"},
		{"project_id": "not-a-uuid"},
		{"secret_ref_prefix": ""},
		{"environment": 7},
	}
	for _, scope := range bad {
		code, body := l.call(t, http.MethodPost, "/api/v1/user-roles", admin,
			map[string]any{"user_id": target, "role_id": roleID, "scope": scope})
		if code != http.StatusBadRequest {
			t.Errorf("POST /user-roles scope=%v = %d %s, want 400", scope, code, body)
		}
	}
	var stored int
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE user_id = $1`, target).Scan(&stored); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stored != 0 {
		t.Errorf("rejected grants left %d user_roles rows", stored)
	}

	// Valid shapes still work: global, project-scoped, team+env.
	team := uuid.New()
	for _, scope := range []map[string]any{
		nil,
		{"project_id": strings.ToUpper(uuid.NewString())},
		{"team_id": team.String(), "environment": "uat", "secret_ref_prefix": "team-alpha/uat/", "provider_type": "vault"},
	} {
		code, body := l.call(t, http.MethodPost, "/api/v1/user-roles", admin,
			map[string]any{"user_id": target, "role_id": roleID, "scope": scope})
		if code != http.StatusCreated {
			t.Errorf("POST /user-roles valid scope=%v = %d %s, want 201", scope, code, body)
		}
	}
}

// ---- API-N-05: privilege + tenancy writes audited --------------------

func TestLive_PrivilegeAndTenancyWrites_AuditedWithSessionActor(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	admin := l.grantUser(t, []string{
		"role.edit", "user_role.edit", "workflow.edit", "team.edit", "integration.bind", "secret.list",
	}, `{}`)

	// roles
	code, body := l.call(t, http.MethodPost, "/api/v1/roles", admin,
		map[string]any{"name": "it-auditor", "permissions": []string{"audit.read"}})
	if code != http.StatusCreated {
		t.Fatalf("create role = %d %s", code, body)
	}
	var role struct{ ID uuid.UUID }
	mustJSON(t, body, &role)
	l.requireOneAudit(t, "role.create", admin)
	if code, body = l.call(t, http.MethodPut, "/api/v1/roles/"+role.ID.String()+"/permissions", admin,
		map[string]any{"permissions": []string{"audit.read", "secret.list"}}); code != http.StatusNoContent {
		t.Fatalf("update role = %d %s", code, body)
	}
	upd := l.requireOneAudit(t, "role.permissions.update", admin)
	if added, _ := upd.Metadata["permissions_added"].([]any); len(added) != 1 || added[0] != "secret.list" {
		t.Errorf("role.permissions.update permissions_added = %v, want [secret.list]", upd.Metadata["permissions_added"])
	}

	// user-roles: body granted_by is ignored, the session actor is stored.
	target := uuid.New().String()
	code, body = l.call(t, http.MethodPost, "/api/v1/user-roles", admin, map[string]any{
		"user_id": target, "role_id": role.ID, "granted_by": "system:oidc",
		"scope": map[string]any{"project_id": uuid.NewString()},
	})
	if code != http.StatusCreated {
		t.Fatalf("grant = %d %s", code, body)
	}
	var grant struct {
		ID        uuid.UUID `json:"id"`
		GrantedBy string    `json:"granted_by"`
	}
	mustJSON(t, body, &grant)
	if grant.GrantedBy != "user:"+admin {
		t.Errorf("granted_by = %q, want session actor user:%s (body value must be ignored)", grant.GrantedBy, admin)
	}
	var storedBy string
	if err := l.pool.QueryRow(ctx, `SELECT COALESCE(granted_by,'') FROM user_roles WHERE id = $1`, grant.ID).Scan(&storedBy); err != nil {
		t.Fatalf("read granted_by: %v", err)
	}
	if storedBy == "system:oidc" || storedBy != "user:"+admin {
		t.Errorf("stored granted_by = %q, want user:%s", storedBy, admin)
	}
	g := l.requireOneAudit(t, "user_role.grant", admin)
	if g.Metadata["user_id"] != target || g.Metadata["role_id"] != role.ID.String() {
		t.Errorf("user_role.grant metadata = %v", g.Metadata)
	}
	if code, body = l.call(t, http.MethodDelete, "/api/v1/user-roles/"+grant.ID.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", code, body)
	}
	rv := l.requireOneAudit(t, "user_role.revoke", admin)
	if rv.Metadata["user_id"] != target || rv.Metadata["role_id"] != role.ID.String() {
		t.Errorf("user_role.revoke metadata = %v", rv.Metadata)
	}
	if code, body = l.call(t, http.MethodDelete, "/api/v1/roles/"+role.ID.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete role = %d %s", code, body)
	}
	l.requireOneAudit(t, "role.delete", admin)

	// workflows
	wfBody := map[string]any{
		"name": "it-wf", "min_approvers": 1, "enabled": true,
		"wrap_ttl_created_seconds": 3600, "wrap_ttl_approved_seconds": 3600,
		"wrap_ttl_claimed_seconds": 300, "request_ttl_seconds": 3600,
	}
	code, body = l.call(t, http.MethodPost, "/api/v1/workflows", admin, wfBody)
	if code != http.StatusCreated {
		t.Fatalf("create workflow = %d %s", code, body)
	}
	var wf struct{ ID uuid.UUID }
	mustJSON(t, body, &wf)
	l.requireOneAudit(t, "workflow.create", admin)
	wfBody["min_approvers"] = 0
	wfBody["require_justification"] = true
	if code, body = l.call(t, http.MethodPut, "/api/v1/workflows/"+wf.ID.String(), admin, wfBody); code != http.StatusNoContent {
		t.Fatalf("update workflow = %d %s", code, body)
	}
	wu := l.requireOneAudit(t, "workflow.update", admin)
	changed, _ := wu.Metadata["changed_keys"].([]any)
	if !containsAll(changed, "min_approvers", "require_justification") {
		t.Errorf("workflow.update changed_keys = %v, want min_approvers + require_justification", changed)
	}
	if code, body = l.call(t, http.MethodDelete, "/api/v1/workflows/"+wf.ID.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete workflow = %d %s", code, body)
	}
	l.requireOneAudit(t, "workflow.delete", admin)

	// projects
	code, body = l.call(t, http.MethodPost, "/api/v1/projects", admin, map[string]any{"name": "tenant-a"})
	if code != http.StatusCreated {
		t.Fatalf("create project = %d %s", code, body)
	}
	var proj struct{ ID uuid.UUID }
	mustJSON(t, body, &proj)
	l.requireOneAudit(t, "project.create", admin)
	if code, body = l.call(t, http.MethodPut, "/api/v1/projects/"+proj.ID.String()+"/status", admin,
		map[string]any{"status": "archived"}); code != http.StatusNoContent {
		t.Fatalf("project status = %d %s", code, body)
	}
	l.requireOneAudit(t, "project.status.update", admin)
	teamID := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO teams (id, name) VALUES ($1, 'team-alpha')`, teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if code, body = l.call(t, http.MethodPut, "/api/v1/projects/"+proj.ID.String()+"/team", admin,
		map[string]any{"team_id": teamID}); code != http.StatusNoContent {
		t.Fatalf("project team = %d %s", code, body)
	}
	pt := l.requireOneAudit(t, "project.team.update", admin)
	if pt.Metadata["team_id_after"] != teamID.String() || pt.Metadata["team_id_before"] != nil {
		t.Errorf("project.team.update metadata = %v", pt.Metadata)
	}

	// environments: the kind travels on create + delete, so a
	// delete-and-recreate kind change is visible in the audit chain.
	code, body = l.call(t, http.MethodPost, "/api/v1/environments", admin,
		map[string]any{"project_id": proj.ID, "name": "uat", "type": "uat", "kind": "non_prod"})
	if code != http.StatusCreated {
		t.Fatalf("create env = %d %s", code, body)
	}
	var env struct{ ID uuid.UUID }
	mustJSON(t, body, &env)
	ec := l.requireOneAudit(t, "environment.create", admin)
	if ec.Metadata["kind"] != "non_prod" || ec.Metadata["project_id"] != proj.ID.String() {
		t.Errorf("environment.create metadata = %v", ec.Metadata)
	}
	if code, body = l.call(t, http.MethodPut, "/api/v1/environments/"+env.ID.String(), admin,
		map[string]any{"risk_level": 3}); code != http.StatusOK {
		t.Fatalf("update env = %d %s", code, body)
	}
	eu := l.requireOneAudit(t, "environment.update", admin)
	if eu.Metadata["kind_before"] != "non_prod" || eu.Metadata["kind_after"] != "non_prod" {
		t.Errorf("environment.update kind before/after = %v", eu.Metadata)
	}

	// project-secret bindings: created_by comes from the session.
	sec := &storage.Secret{ClusterName: "tenant-a-uat", ProviderType: "vault", SecretRef: "team-alpha/uat/db", Status: "present"}
	if err := storage.NewSecrets(l.pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	bindPath := "/api/v1/projects/" + proj.ID.String() + "/secrets"
	code, body = l.call(t, http.MethodPost, bindPath, admin, map[string]any{
		"secret_id": sec.ID, "allowed_keys": []string{"DB_USER"}, "allowed_ops": []string{"read"},
		"environment_id": env.ID.String(), "created_by": "system:oidc",
	})
	if code != http.StatusCreated {
		t.Fatalf("bind = %d %s", code, body)
	}
	var createdBy string
	if err := l.pool.QueryRow(ctx, `SELECT COALESCE(created_by,'') FROM project_secrets WHERE project_id = $1 AND secret_id = $2`,
		proj.ID, sec.ID).Scan(&createdBy); err != nil {
		t.Fatalf("read created_by: %v", err)
	}
	if createdBy != admin {
		t.Errorf("project_secrets.created_by = %q, want session identity %s (body value ignored)", createdBy, admin)
	}
	pb := l.requireOneAudit(t, "project_secret.bind", admin)
	if pb.Metadata["secret_id"] != sec.ID.String() || pb.Metadata["environment_id"] != env.ID.String() {
		t.Errorf("project_secret.bind metadata = %v", pb.Metadata)
	}
	if code, body = l.call(t, http.MethodPut, bindPath+"/"+sec.ID.String(), admin, map[string]any{
		"allowed_keys": []string{"DB_USER", "DB_PASSWORD"}, "allowed_ops": []string{"read"},
	}); code != http.StatusOK {
		t.Fatalf("update binding = %d %s", code, body)
	}
	l.requireOneAudit(t, "project_secret.update", admin)
	if code, body = l.call(t, http.MethodDelete, bindPath+"/"+sec.ID.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("unbind = %d %s", code, body)
	}
	l.requireOneAudit(t, "project_secret.unbind", admin)

	if code, body = l.call(t, http.MethodDelete, "/api/v1/environments/"+env.ID.String(), admin, nil); code != http.StatusNoContent {
		t.Fatalf("delete env = %d %s", code, body)
	}
	ed := l.requireOneAudit(t, "environment.delete", admin)
	if ed.Metadata["kind"] != "non_prod" || ed.Metadata["environment_id"] != env.ID.String() {
		t.Errorf("environment.delete metadata = %v", ed.Metadata)
	}
	// Recreate it as prod WITHOUT sending kind: the audit must carry the
	// kind storage derived from type, so the non_prod -> prod flip shows.
	if code, body = l.call(t, http.MethodPost, "/api/v1/environments", admin,
		map[string]any{"project_id": proj.ID, "name": "uat", "type": "prod"}); code != http.StatusCreated {
		t.Fatalf("recreate env = %d %s", code, body)
	}
	if rows := l.auditRows(t, "environment.create"); len(rows) != 2 || rows[1].Metadata["kind"] != "prod" {
		t.Errorf("recreated environment.create rows = %+v, want a second row with kind=prod", rows)
	}

	// No audit row in this flow may carry a secret ref or key value text.
	var leaks int
	if err := l.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%team-alpha/uat/db%'`).Scan(&leaks); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
	if leaks != 0 {
		t.Errorf("%d audit rows carry the secret ref", leaks)
	}

	// A refused write (no permission) audits nothing.
	nobody := uuid.New().String()
	if code, _ := l.call(t, http.MethodPost, "/api/v1/roles", nobody, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Errorf("no-perm create role = %d, want 403", code)
	}
	if n := len(l.auditRows(t, "role.create")); n != 1 {
		t.Errorf("role.create rows after refused write = %d, want 1", n)
	}
}

func containsAll(have []any, want ...string) bool {
	set := map[string]bool{}
	for _, v := range have {
		if s, ok := v.(string); ok {
			set[s] = true
		}
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// ---- API-15: real actor on job, agent and argocd actions -------------

func TestLive_JobAgentArgoCDActions_RecordRealActor(t *testing.T) {
	l := newLiveApp(t)

	// A tiny ArgoCD stand-in for the read-only discovery call.
	argo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/api/v1/applications") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(argo.Close)

	op := l.grantUser(t, []string{"job.enqueue", "agent.mint", "integration.edit"}, `{}`)

	if code, body := l.call(t, http.MethodPost, "/api/v1/jobs", op,
		map[string]any{"job_type": "discover", "payload": map[string]any{}}); code != http.StatusCreated {
		t.Fatalf("enqueue = %d %s", code, body)
	}
	l.requireOneAudit(t, "job.enqueue", op)

	if code, body := l.call(t, http.MethodPost, "/api/v1/agents", op, map[string]any{"name": "tenant-a-uat-agent"}); code != http.StatusCreated {
		t.Fatalf("mint = %d %s", code, body)
	}
	l.requireOneAudit(t, "agent.mint", op)

	code, body := l.call(t, http.MethodPost, "/api/v1/argocd-endpoints", op, map[string]any{
		"name": "argo-a", "base_url": argo.URL, "token_b64": "ZmFrZS10b2tlbg==",
	})
	if code != http.StatusCreated {
		t.Fatalf("argocd create = %d %s", code, body)
	}
	var ep struct{ ID string }
	mustJSON(t, body, &ep)
	l.requireOneAudit(t, "argocd_endpoint.create", op)

	if code, body := l.call(t, http.MethodGet, "/api/v1/argocd-endpoints/"+ep.ID+"/discovered-apps", op, nil); code != http.StatusOK {
		t.Fatalf("discover = %d %s", code, body)
	}
	l.requireOneAudit(t, "argocd_endpoint.discover", op)

	if code, body := l.call(t, http.MethodPut, "/api/v1/argocd-endpoints/"+ep.ID+"/enabled", op, map[string]any{"enabled": false}); code != http.StatusNoContent {
		t.Fatalf("set enabled = %d %s", code, body)
	}
	l.requireOneAudit(t, "argocd_endpoint.set_enabled", op)

	if code, body := l.call(t, http.MethodDelete, "/api/v1/argocd-endpoints/"+ep.ID, op, nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", code, body)
	}
	l.requireOneAudit(t, "argocd_endpoint.delete", op)

	// Nothing on this flow is attributed to the old hard-coded "admin".
	var hardcoded int
	if err := l.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE actor = 'admin'`).Scan(&hardcoded); err != nil {
		t.Fatalf("count: %v", err)
	}
	if hardcoded != 0 {
		t.Errorf("%d audit rows still carry actor=admin", hardcoded)
	}
}
