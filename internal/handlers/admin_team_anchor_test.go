// R-follow-up #3 (api#127) slice 1d tests — admin /admin/policies
// supports team-anchored rules, enforces selector safety server-side,
// fires the {policy.edit, team} counter cardinality, and emits
// normalized policy.create/update/delete audit events.

package handlers_test

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapAdminWithAudit(t *testing.T) (*fiber.App, *storage.Pool, uuid.UUID) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	// Reuse the existing bootstrap for fixtures + seed re-seeding, then
	// rebuild the handler with WithAudit wired.
	_, p, _ := bootstrapAdmin(t)

	// Seed a team for the team-anchored tests. Unique per test so
	// successive runs don't collide on the (parent_team_id, name)
	// unique index (bootstrapAdmin doesn't wipe teams).
	teamsRepo := storage.NewTeams(p)
	team := &storage.Team{Name: "team-anchor-" + uuid.New().String()[:8]}
	if err := teamsRepo.Create(t.Context(), team); err != nil {
		t.Fatalf("teams.Create: %v", err)
	}

	auditRepo := storage.NewAuditEvents(p)
	hWithAudit := handlers.NewAdmin(
		storage.NewRoles(p),
		storage.NewUserRoles(p),
		storage.NewWorkflows(p),
		storage.NewPolicies(p),
	).WithAudit(auditRepo)
	return mountAdmin(hWithAudit), p, team.ID
}

func seedStandardWorkflowID(t *testing.T, pool *storage.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(),
		`SELECT id FROM workflow_definitions WHERE name='standard'`,
	).Scan(&id); err != nil {
		t.Fatalf("seed workflow lookup: %v", err)
	}
	return id
}

// --- Anchor support -----------------------------------------------

func TestAdminCreatePolicy_TeamAnchored_HappyPath(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)

	resp, body := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "team-rule",
		"selector":    map[string]any{"environment_kind": "non_prod"},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var got handlers.PolicyBody
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.TeamID == nil || *got.TeamID != teamID {
		t.Errorf("team_id round-trip mismatch: got %v", got.TeamID)
	}
	if got.ProjectID != nil {
		t.Errorf("project_id must be nil for team rule")
	}

	// Audit row with scope=team + actor_permission_used=policy.edit.
	var scope, perm string
	if err := pool.QueryRow(t.Context(),
		`SELECT metadata->>'scope', metadata->>'actor_permission_used'
		   FROM audit_events WHERE action='policy.create'
		   ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&scope, &perm); err != nil {
		t.Fatal(err)
	}
	if scope != "team" {
		t.Errorf("scope=%q want team", scope)
	}
	if perm != "policy.edit" {
		t.Errorf("actor_permission_used=%q want policy.edit", perm)
	}
}

func TestAdminCreatePolicy_BothAnchorsRejected(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)
	projectID := uuid.New()
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO projects (id, name) VALUES ($1, $2)`,
		projectID, "p-admin-anchor-"+projectID.String()[:8],
	); err != nil {
		t.Fatal(err)
	}
	resp, _ := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "bad",
		"selector":    map[string]any{"environment_kind": "non_prod"},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
		"project_id":  projectID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for mixed anchor; got %d", resp.StatusCode)
	}
}

// --- §5 C5 team-anchored selector safety -------------------------

func TestAdminCreatePolicy_TeamAnchored_RejectsSelectorProjectID(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)
	resp, _ := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "bad",
		"selector":    map[string]any{"environment_kind": "non_prod", "project_id": uuid.New().String()},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", resp.StatusCode)
	}
}

func TestAdminCreatePolicy_TeamAnchored_RejectsSelectorEnvironmentID(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)
	resp, _ := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "bad",
		"selector":    map[string]any{"environment_kind": "non_prod", "environment_id": uuid.New().String()},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", resp.StatusCode)
	}
}

func TestAdminCreatePolicy_TeamAnchored_RejectsSelectorTeamID(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)
	resp, _ := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "bad",
		"selector":    map[string]any{"environment_kind": "non_prod", "team_id": teamID.String()},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", resp.StatusCode)
	}
}

func TestAdminCreatePolicy_TeamAnchored_RejectsMissingNonProdEnvKind(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)
	resp, _ := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "bad",
		"selector":    map[string]any{"environment_kind": "prod"},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", resp.StatusCode)
	}
}

// --- DELETE emits scope-aware audit ------------------------------

func TestAdminDeletePolicy_TeamAnchored_EmitsAudit(t *testing.T) {
	a, pool, teamID := bootstrapAdminWithAudit(t)
	wf := seedStandardWorkflowID(t, pool)
	// Create
	resp, body := doJSON(t, a, "POST", "/api/v1/policies", map[string]any{
		"name":        "to-delete",
		"selector":    map[string]any{"environment_kind": "non_prod"},
		"workflow_id": wf,
		"priority":    100,
		"enabled":     true,
		"team_id":     teamID,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", resp.StatusCode, body)
	}
	var got handlers.PolicyBody
	_ = json.Unmarshal(body, &got)
	if got.ID == uuid.Nil {
		t.Fatal("created rule missing id")
	}
	// Delete
	resp2, _ := doJSON(t, a, "DELETE", "/api/v1/policies/"+got.ID.String(), nil)
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", resp2.StatusCode)
	}
	// Verify audit
	var scope string
	if err := pool.QueryRow(t.Context(),
		`SELECT metadata->>'scope' FROM audit_events
		   WHERE action='policy.delete'
		   ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != "team" {
		t.Errorf("delete audit scope=%q want team", scope)
	}
}

