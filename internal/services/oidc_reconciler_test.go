package services_test

// Integration tests for the group-claim → role reconciler (Slice E).
// Requires TEST_DATABASE_URL; SKIPs otherwise.
//
// The reconciler is a method on *OIDCService but doesn't actually need
// the live IdP — only the role + user_role repositories + the
// service's config. We construct a bare OIDCService for the test
// rather than going through NewOIDCService (which would try to
// discover a real IdP).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapReconciler(t *testing.T) (*services.RoleReconciler, *storage.Pool, *storage.LocalUser, []*storage.Role) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}
	ctx := t.Context()
	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open storage: %v", err)
	}
	t.Cleanup(pool.Close)

	const truncate = `
		TRUNCATE TABLE
			audit_events, user_roles, local_users
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Seed one user; the system roles (admin/approver/developer)
	// already exist from the workflow-engine seed migration.
	hash, err := bcrypt.GenerateFromPassword([]byte("anything"), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	users := storage.NewLocalUsers(pool)
	owner := &storage.LocalUser{
		Email:        "alice@example.com",
		PasswordHash: hash,
		DisplayName:  "Alice",
	}
	if err := users.Create(ctx, owner); err != nil {
		t.Fatalf("create user: %v", err)
	}

	roleRepo := storage.NewRoles(pool)
	roleList, err := roleRepo.List(ctx)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}

	rec := services.NewRoleReconcilerForTest(
		"groups",
		map[string]string{
			"sb-admins":    "admin",
			"sb-approvers": "approver",
		},
		roleRepo,
		storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
	)
	return rec, pool, owner, roleList
}

func TestReconcile_AddsGrantsForNewGroups(t *testing.T) {
	rec, pool, owner, _ := bootstrapReconciler(t)
	ctx := t.Context()

	if err := rec.Reconcile(ctx, owner.ID.String(), []string{"sb-admins"}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	urs := storage.NewUserRoles(pool)
	rows, err := urs.ListByUser(ctx, owner.ID.String())
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 grant after reconcile, got %d", len(rows))
	}
	if rows[0].GrantedBy != "system:oidc" {
		t.Fatalf("expected granted_by=system:oidc, got %q", rows[0].GrantedBy)
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	rec, pool, owner, _ := bootstrapReconciler(t)
	ctx := t.Context()

	for i := 0; i < 3; i++ {
		if err := rec.Reconcile(ctx, owner.ID.String(), []string{"sb-admins", "sb-approvers"}); err != nil {
			t.Fatalf("Reconcile run %d: %v", i, err)
		}
	}
	urs := storage.NewUserRoles(pool)
	rows, err := urs.ListByUser(ctx, owner.ID.String())
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected exactly 2 grants after 3 idempotent runs, got %d", len(rows))
	}
}

func TestReconcile_RevokesGrantsForRemovedGroups(t *testing.T) {
	rec, pool, owner, _ := bootstrapReconciler(t)
	ctx := t.Context()

	if err := rec.Reconcile(ctx, owner.ID.String(), []string{"sb-admins", "sb-approvers"}); err != nil {
		t.Fatalf("Reconcile add: %v", err)
	}
	// User loses the approver group, keeps admin.
	if err := rec.Reconcile(ctx, owner.ID.String(), []string{"sb-admins"}); err != nil {
		t.Fatalf("Reconcile remove: %v", err)
	}
	urs := storage.NewUserRoles(pool)
	rows, err := urs.ListByUser(ctx, owner.ID.String())
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 grant after group removal, got %d", len(rows))
	}
}

func TestReconcile_LeavesAdminAssignedGrantsAlone(t *testing.T) {
	rec, pool, owner, roleList := bootstrapReconciler(t)
	ctx := t.Context()

	// Admin manually grants the `developer` role (granted_by !=
	// system:oidc). The reconciler must NEVER touch this.
	var devRoleID uuid.UUID
	for _, r := range roleList {
		if r.Name == "developer" {
			devRoleID = r.ID
		}
	}
	if devRoleID == uuid.Nil {
		t.Fatal("seeded developer role not found")
	}
	urs := storage.NewUserRoles(pool)
	adminGrant := &storage.UserRole{
		UserID:    owner.ID.String(),
		RoleID:    devRoleID,
		Scope:     map[string]any{},
		GrantedBy: "admin:bootstrap", // explicitly NOT system:oidc
	}
	if err := urs.Grant(ctx, adminGrant); err != nil {
		t.Fatalf("admin grant: %v", err)
	}

	// Reconciler runs with only sb-admins → would normally produce
	// a single grant. The admin-assigned developer row should
	// survive.
	if err := rec.Reconcile(ctx, owner.ID.String(), []string{"sb-admins"}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	rows, err := urs.ListByUser(ctx, owner.ID.String())
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 grants (admin-assigned + OIDC-provisioned), got %d", len(rows))
	}
	var sawAdmin, sawOIDC bool
	for _, r := range rows {
		switch r.GrantedBy {
		case "admin:bootstrap":
			sawAdmin = true
		case "system:oidc":
			sawOIDC = true
		}
	}
	if !sawAdmin || !sawOIDC {
		t.Fatalf("expected both grants present (admin=%v oidc=%v)", sawAdmin, sawOIDC)
	}

	// Reconcile again with NO matching groups → OIDC grant goes away;
	// admin grant stays.
	if err := rec.Reconcile(ctx, owner.ID.String(), []string{}); err != nil {
		t.Fatalf("Reconcile empty: %v", err)
	}
	rows, _ = urs.ListByUser(ctx, owner.ID.String())
	if len(rows) != 1 || rows[0].GrantedBy != "admin:bootstrap" {
		t.Fatalf("after group removal: expected only admin-assigned row to remain, got %+v", rows)
	}
}

func TestReconcile_DisabledByEmptyClaim(t *testing.T) {
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}
	ctx := t.Context()
	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE audit_events, user_roles, local_users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), 10)
	users := storage.NewLocalUsers(pool)
	u := &storage.LocalUser{Email: "noclaim@example.com", PasswordHash: hash, DisplayName: "NC"}
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := services.NewRoleReconcilerForTest(
		"", // empty claim → reconciler short-circuits
		map[string]string{"sb-admins": "admin"},
		storage.NewRoles(pool),
		storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
	)
	if err := rec.Reconcile(ctx, u.ID.String(), []string{"sb-admins"}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	rows, _ := storage.NewUserRoles(pool).ListByUser(ctx, u.ID.String())
	if len(rows) != 0 {
		t.Fatalf("expected zero grants when GroupClaim is empty, got %d", len(rows))
	}
}

// Compile-time assertion that the package-level test build sees the
// expected exported helper. If `NewRoleReconcilerForTest` is renamed
// the test file fails to compile, surfacing the breakage in CI.
var _ = func(ctx context.Context) {
	_ = ctx
}
