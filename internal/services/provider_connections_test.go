package services_test

// Slice P2 — ProviderConnectionsService tests.
//
// The validation rules are pure (no DB) so they run in every test
// environment. The Create / Update / Delete / OnDiscoverJobCompleted
// integration paths bootstrap a real Postgres and SKIP when
// TEST_DATABASE_URL is unset.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- pure validation tests ----------------------------------------

func newPureSvc(t *testing.T) *services.ProviderConnectionsService {
	t.Helper()
	// Pure-validation paths never reach the repositories; nil is
	// safe because the validation routines exit before any repo call.
	return services.NewProviderConnections(nil, nil, nil)
}

func validVaultInput(name string) services.CreateInput {
	return services.CreateInput{
		Name:       name,
		Type:       storage.ProviderConnectionTypeVault,
		AuthMethod: "token",
		Scope: map[string]string{
			"address": "https://vault.example.com",
			"mount":   "secret",
		},
		ClusterName:             "",
		Description:             "",
		DiscoverEnabled:         false,
		DiscoverIntervalSeconds: 300,
	}
}

func validAWSInput(name string) services.CreateInput {
	return services.CreateInput{
		Name:       name,
		Type:       storage.ProviderConnectionTypeAWSSM,
		AuthMethod: "default",
		Scope: map[string]string{
			"region":  "us-east-1",
			"roleArn": "arn:aws:iam::123456789012:role/sb-agent",
		},
		DiscoverIntervalSeconds: 300,
	}
}

// TestCredentialRefusal — 14 banned keys × 3 casings = 42 cases.
// Match runs BEFORE shape validation.
func TestCredentialRefusal_TableDriven(t *testing.T) {
	svc := newPureSvc(t)
	banned := []string{
		"credentials", "secret", "secrets", "password", "passphrase",
		"awsAccessKeyID", "awsSecretAccessKey", "awsSessionToken",
		"accessKeyID", "secretAccessKey", "sessionToken",
		"token", "vaultToken", "approleSecretID",
		"serviceAccountKey", "clientSecret", "subscriptionKey",
	}
	casings := []func(string) string{
		func(s string) string { return s },                  // as-is
		strings.ToLower,
		strings.ToUpper,
	}
	for _, b := range banned {
		for _, cs := range casings {
			key := cs(b)
			t.Run(key, func(t *testing.T) {
				in := validVaultInput("v")
				in.Scope[key] = "x"
				err := svc.ValidateCreate(in)
				if !errors.Is(err, services.ErrCredentialShapedKey) {
					t.Fatalf("banned key %q: expected ErrCredentialShapedKey, got %v", key, err)
				}
				var d *services.ValidationDetail
				if !errors.As(err, &d) || d.BannedKey != key {
					t.Fatalf("missing banned_key in detail: %+v", d)
				}
			})
		}
	}
}

func TestCredentialRefusal_RunsBeforeShapeCheck(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["unknown_key"] = "x" // unknown
	in.Scope["awsAccessKeyID"] = "y" // banned
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrCredentialShapedKey) {
		t.Fatalf("expected credential refusal to fire BEFORE shape check; got %v", err)
	}
}

func TestSecretShapedValue_AKIA(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["kvPrefix"] = "AKIAIOSFODNN7EXAMPLE" // legitimate field, but value looks like an AWS access key
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrSecretShapedValue) {
		t.Fatalf("AKIA value: expected ErrSecretShapedValue, got %v", err)
	}
}

func TestSecretShapedValue_VaultToken(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["kvPrefix"] = "hvs." + strings.Repeat("X", 25)
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrSecretShapedValue) {
		t.Fatalf("hvs. value: expected ErrSecretShapedValue, got %v", err)
	}
}

func TestSecretShapedValue_JWT(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["kvPrefix"] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrSecretShapedValue) {
		t.Fatalf("JWT value: expected ErrSecretShapedValue, got %v", err)
	}
}

func TestSecretShapedValue_OAuth(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["kvPrefix"] = "ya29.a0AfH6SMBx_some-google-oauth-token"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrSecretShapedValue) {
		t.Fatalf("OAuth value: expected ErrSecretShapedValue, got %v", err)
	}
}

func TestSecretShapedValue_OptOut(t *testing.T) {
	svc := newPureSvc(t).WithRejectSecretValues(false)
	in := validVaultInput("v")
	in.Scope["kvPrefix"] = "AKIAIOSFODNN7EXAMPLE"
	if err := svc.ValidateCreate(in); err != nil {
		t.Fatalf("RejectSecretValues=false should pass validation; got %v", err)
	}
}

func TestScopeShape_MissingRequired(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	delete(in.Scope, "mount") // vault requires mount
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrInvalidScope) {
		t.Fatalf("missing mount: expected ErrInvalidScope, got %v", err)
	}
	var d *services.ValidationDetail
	if !errors.As(err, &d) {
		t.Fatal("missing ValidationDetail")
	}
	if !contains(d.MissingKeys, "mount") {
		t.Fatalf("missing_keys = %v want includes mount", d.MissingKeys)
	}
}

func TestScopeShape_UnknownKey(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["zoomZoom"] = "x"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrInvalidScope) {
		t.Fatalf("unknown key: expected ErrInvalidScope, got %v", err)
	}
	var d *services.ValidationDetail
	if !errors.As(err, &d) {
		t.Fatal("missing ValidationDetail")
	}
	if !contains(d.UnknownKeys, "zoomZoom") {
		t.Fatalf("unknown_keys = %v want includes zoomZoom", d.UnknownKeys)
	}
}

func TestVaultURL_HTTPSOk(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["address"] = "https://vault.example.com:8200"
	// Pure validation reaches the repo (nil); we just expect no
	// pre-repo validation error.
	err := svc.ValidateCreate(in)
	if isValidationErr(err) {
		t.Fatalf("https vault should pass validation; got %v", err)
	}
}

func TestVaultURL_HTTPRefused(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["address"] = "http://vault.example.com"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrInvalidProviderURL) {
		t.Fatalf("http vault: expected ErrInvalidProviderURL, got %v", err)
	}
}

func TestVaultURL_HTTPAllowedViaOverride(t *testing.T) {
	svc := newPureSvc(t).WithAllowInsecureVaultAddr(true)
	in := validVaultInput("v")
	in.Scope["address"] = "http://vault.example.com"
	err := svc.ValidateCreate(in)
	if isValidationErr(err) {
		t.Fatalf("http vault with override should pass validation; got %v", err)
	}
}

func TestVaultURL_UserInfoRefused(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["address"] = "https://user:pass@vault.example.com"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrInvalidProviderURL) {
		t.Fatalf("userinfo: expected ErrInvalidProviderURL, got %v", err)
	}
	var d *services.ValidationDetail
	if errors.As(err, &d) && d.Reason != "userinfo_present" {
		t.Fatalf("reason = %q want userinfo_present", d.Reason)
	}
}

func TestVaultURL_TokenQueryRefused(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.Scope["address"] = "https://vault.example.com?token=abc"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrInvalidProviderURL) {
		t.Fatalf("token query: expected ErrInvalidProviderURL, got %v", err)
	}
	var d *services.ValidationDetail
	if errors.As(err, &d) && d.Reason != "token_in_query" {
		t.Fatalf("reason = %q want token_in_query", d.Reason)
	}
}

func TestAWSRoleArn_ValidAndInvalid(t *testing.T) {
	svc := newPureSvc(t)

	good := validAWSInput("a")
	good.Scope["roleArn"] = "arn:aws:iam::123456789012:role/sb-agent"
	if err := svc.ValidateCreate(good); err != nil {
		t.Fatalf("valid ARN failed validation: %v", err)
	}

	bad := validAWSInput("a")
	bad.Scope["roleArn"] = "arn:aws:s3:::my-bucket"
	if err := svc.ValidateCreate(bad); !errors.Is(err, services.ErrInvalidRoleArn) {
		t.Fatalf("bad ARN: expected ErrInvalidRoleArn, got %v", err)
	}

	short := validAWSInput("a")
	short.Scope["roleArn"] = "arn:aws:iam::12345:role/r" // not 12 digits
	if err := svc.ValidateCreate(short); !errors.Is(err, services.ErrInvalidRoleArn) {
		t.Fatalf("short account: expected ErrInvalidRoleArn, got %v", err)
	}
}

func TestDescriptionLength_499_500_501(t *testing.T) {
	svc := newPureSvc(t)

	mk := func(n int) services.CreateInput {
		in := validVaultInput("v")
		in.Description = strings.Repeat("a", n)
		return in
	}
	cases := []struct {
		n         int
		shouldErr bool
	}{
		{499, false}, {500, false}, {501, true},
	}
	for _, c := range cases {
		err := svc.ValidateCreate(mk(c.n))
		if c.shouldErr {
			if !errors.Is(err, services.ErrDescriptionTooLong) {
				t.Errorf("n=%d: expected ErrDescriptionTooLong, got %v", c.n, err)
			}
		} else if errors.Is(err, services.ErrDescriptionTooLong) {
			t.Errorf("n=%d: should pass validation, got ErrDescriptionTooLong", c.n)
		}
	}
}

func TestDiscoverEnabled_RequiresClusterName(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.DiscoverEnabled = true
	in.ClusterName = "" // missing
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrDiscoverRequiresCluster) {
		t.Fatalf("expected ErrDiscoverRequiresCluster, got %v", err)
	}
}

func TestDiscoverInterval_Bounds(t *testing.T) {
	svc := newPureSvc(t)
	mk := func(n int) services.CreateInput {
		in := validVaultInput("v")
		in.DiscoverIntervalSeconds = n
		return in
	}
	cases := []struct {
		n         int
		shouldErr bool
	}{
		{59, true}, {60, false}, {86400, false}, {86401, true},
	}
	for _, c := range cases {
		err := svc.ValidateCreate(mk(c.n))
		if c.shouldErr && !errors.Is(err, services.ErrInvalidDiscoverInterval) {
			t.Errorf("n=%d: expected ErrInvalidDiscoverInterval, got %v", c.n, err)
		}
		if !c.shouldErr && errors.Is(err, services.ErrInvalidDiscoverInterval) {
			t.Errorf("n=%d: should pass, got ErrInvalidDiscoverInterval", c.n)
		}
	}
}

func TestAuthMethod_PerType(t *testing.T) {
	svc := newPureSvc(t)
	in := validVaultInput("v")
	in.AuthMethod = "invalid"
	err := svc.ValidateCreate(in)
	if !errors.Is(err, services.ErrInvalidAuthMethod) {
		t.Fatalf("expected ErrInvalidAuthMethod, got %v", err)
	}
}

func TestName_RegexRejectsBadShape(t *testing.T) {
	svc := newPureSvc(t)
	for _, bad := range []string{"", "Vault-Prod", "vault_prod", "vault prod"} {
		t.Run(fmt.Sprintf("name=%q", bad), func(t *testing.T) {
			in := validVaultInput(bad)
			err := svc.ValidateCreate(in)
			if !errors.Is(err, services.ErrInvalidName) {
				t.Fatalf("expected ErrInvalidName, got %v", err)
			}
		})
	}
}

// ---- DB-backed integration tests ----------------------------------

func setupPCSvc(t *testing.T) (*services.ProviderConnectionsService, *storage.Pool) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	const truncate = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	svc := services.NewProviderConnections(
		storage.NewProviderConnections(pool),
		storage.NewProjectProviderConnections(pool),
		storage.NewAuditEvents(pool),
	)
	return svc, pool
}

func TestCreate_AuditsWithoutScope(t *testing.T) {
	svc, pool := setupPCSvc(t)
	ctx := t.Context()
	created, err := svc.Create(ctx, validVaultInput("vault-audit"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Inspect the audit row for the canary "https://vault.example.com"
	// substring — it MUST NOT appear in metadata.
	var any int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'provider_connection.create'`,
	).Scan(&any); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if any != 1 {
		t.Fatalf("audit count = %d want 1", any)
	}
	var hit int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%vault.example.com%'`,
	).Scan(&hit); err != nil {
		t.Fatalf("scan metadata: %v", err)
	}
	if hit > 0 {
		t.Fatalf("scope leaked into audit metadata (%d hits)", hit)
	}
	_ = created
}

func TestUpdate_RenameOnlyEmitsChangedKeysName(t *testing.T) {
	svc, pool := setupPCSvc(t)
	ctx := t.Context()
	created, err := svc.Create(ctx, validVaultInput("vault-orig"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	in := services.UpdateInput{
		Name:                    "vault-renamed",
		AuthMethod:              created.AuthMethod,
		Scope:                   created.Scope,
		ClusterName:             created.ClusterName,
		Description:             created.Description,
		Status:                  created.Status,
		DiscoverEnabled:         created.DiscoverEnabled,
		DiscoverIntervalSeconds: created.DiscoverIntervalSeconds,
	}
	if _, err := svc.Update(ctx, created.ID, in); err != nil {
		t.Fatalf("Update: %v", err)
	}
	var metaText string
	if err := pool.QueryRow(ctx,
		`SELECT metadata::text FROM audit_events WHERE action = 'provider_connection.update'`,
	).Scan(&metaText); err != nil {
		t.Fatalf("scan audit: %v", err)
	}
	if !strings.Contains(metaText, `"name"`) {
		t.Fatalf("changed_keys missing 'name': %s", metaText)
	}
}

func TestDelete_BlockedByBindings(t *testing.T) {
	svc, pool := setupPCSvc(t)
	ctx := t.Context()
	created, err := svc.Create(ctx, validVaultInput("vault-blocked"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Insert a binding via direct SQL.
	var projectID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p-blocked') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO project_provider_connections
			(project_id, provider_connection_id, purpose) VALUES ($1, $2, 'destination')`,
		projectID, created.ID,
	); err != nil {
		t.Fatalf("insert binding: %v", err)
	}
	counts, err := svc.Delete(ctx, created.ID, "alice", uuid.New())
	if !errors.Is(err, storage.ErrConnectionInUse) {
		t.Fatalf("expected ErrConnectionInUse, got %v", err)
	}
	if counts.BindingsCount != 1 || counts.OpenRequestsCount != 0 {
		t.Fatalf("counts = %+v want bindings=1 open=0", counts)
	}
}

func TestMarkDiscoverFinished_SanitizesError(t *testing.T) {
	svc, pool := setupPCSvc(t)
	ctx := t.Context()
	in := validVaultInput("vault-sanitize")
	in.ClusterName = "c1"
	in.DiscoverEnabled = true
	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	canary := "AKIAIOSFODNN7EXAMPLE"
	rawErr := "vault: 403 forbidden — token " + canary + " rejected"
	if err := svc.MarkDiscoverFinished(ctx, created.ID, storage.DiscoverStatusFailure, rawErr, time.Now()); err != nil {
		t.Fatalf("MarkDiscoverFinished: %v", err)
	}
	var storedErr string
	if err := pool.QueryRow(ctx,
		`SELECT coalesce(last_discover_error, '') FROM provider_connections WHERE id = $1`,
		created.ID,
	).Scan(&storedErr); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if strings.Contains(storedErr, canary) {
		t.Fatalf("canary leaked into last_discover_error: %q", storedErr)
	}
	if !strings.Contains(storedErr, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] marker: %q", storedErr)
	}
}

func TestMarkDiscoverFinished_RejectsRunning(t *testing.T) {
	svc, _ := setupPCSvc(t)
	ctx := t.Context()
	in := validVaultInput("vault-running")
	in.ClusterName = "c1"
	in.DiscoverEnabled = true
	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = svc.MarkDiscoverFinished(ctx, created.ID, storage.DiscoverStatusRunning, "", time.Now())
	if !errors.Is(err, storage.ErrInvalidDiscoverStatus) {
		t.Fatalf("expected ErrInvalidDiscoverStatus, got %v", err)
	}
}

func TestOnDiscoverJobCompleted_FiltersByJobType(t *testing.T) {
	svc, pool := setupPCSvc(t)
	ctx := t.Context()
	in := validVaultInput("vault-hook")
	in.ClusterName = "c1"
	in.DiscoverEnabled = true
	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Non-discover job: hook should silently no-op.
	svc.OnDiscoverJobCompleted(ctx, &storage.SyncJob{
		JobType: storage.JobTypePatch,
		Status:  storage.JobStatusSucceeded,
		Payload: map[string]any{"connection_id": created.ID.String()},
	})
	// Verify provider_connections row was NOT touched.
	var status *string
	if err := pool.QueryRow(ctx,
		`SELECT last_discover_status FROM provider_connections WHERE id = $1`, created.ID,
	).Scan(&status); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status != nil {
		t.Fatalf("non-discover job mutated row: status=%q", *status)
	}
	// Discover succeeded job: hook should flip to success.
	svc.OnDiscoverJobCompleted(ctx, &storage.SyncJob{
		JobType: storage.JobTypeDiscover,
		Status:  storage.JobStatusSucceeded,
		Payload: map[string]any{"connection_id": created.ID.String()},
	})
	if err := pool.QueryRow(ctx,
		`SELECT last_discover_status FROM provider_connections WHERE id = $1`, created.ID,
	).Scan(&status); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if status == nil || *status != storage.DiscoverStatusSuccess {
		t.Fatalf("expected success, got %v", status)
	}
}

func TestBindUnbind_AuditEmitted(t *testing.T) {
	svc, pool := setupPCSvc(t)
	ctx := t.Context()
	created, err := svc.Create(ctx, validVaultInput("vault-bind"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var projectID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p-bind') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("project: %v", err)
	}
	b, err := svc.Bind(ctx, services.BindInput{
		ConnectionID: created.ID,
		ProjectID:    projectID,
		Purpose:      storage.ProjectProviderConnectionPurposeDestination,
		ActorID:      "alice",
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := svc.Unbind(ctx, b.ID, "alice"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	var bindAudits, unbindAudits int
	_ = pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'provider_connection.bind'`,
	).Scan(&bindAudits)
	_ = pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'provider_connection.unbind'`,
	).Scan(&unbindAudits)
	if bindAudits != 1 || unbindAudits != 1 {
		t.Fatalf("audit counts: bind=%d unbind=%d want 1 each", bindAudits, unbindAudits)
	}
}

// ---- helpers ------------------------------------------------------

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// isValidationErr returns true when err is a *ValidationDetail
// (i.e. a service-layer validation failure). Used by pure-validation
// tests to confirm a happy-path payload reaches the storage layer
// (which is nil in those tests — the call will return a different
// non-validation error from the nil pointer dereference at the repo
// boundary).
func isValidationErr(err error) bool {
	if err == nil {
		return false
	}
	var d *services.ValidationDetail
	return errors.As(err, &d)
}
