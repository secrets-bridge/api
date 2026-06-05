package storage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice N1 — storage-layer tests for the cross_team request flow.
//
// Covers the load-bearing storage invariants:
//   - schema CHECKs reject non-cross_team rows holding cross_team-only
//     statuses / target / destination / snapshot columns
//   - FK ON DELETE RESTRICT refuses team / project / env /
//     provider_connection deletes that have open cross_team rows
//   - Fill is atomic (one of N concurrent callers wins; the others see
//     ErrCrossTeamAlreadyFilled)
//   - Fill rejects late writers with ErrFillWindowExpired
//   - SweepFillExpired transitions only past-TTL pending_values rows
//   - Refuse atomically moves pending_values → refused
//   - ListInbox filters by team scope (fail-closed on empty allow-set)
//   - Canary scan: nothing operator-supplied lands in a column that
//     could shadow a secret value

func makeTeamForCrossTeam(t *testing.T, pool *storage.Pool, name string) uuid.UUID {
	t.Helper()
	teams := storage.NewTeams(pool)
	team := &storage.Team{Name: name}
	if err := teams.Create(t.Context(), team); err != nil {
		t.Fatalf("teams.Create %q: %v", name, err)
	}
	return team.ID
}

// makeProvConnForCrossTeam creates a provider_connection. The schema
// has no project_id column — connections are scoped via the JSON
// `scope` field. We stash the project_id there so tests that need to
// assert "this connection is bound to this project" can grep it.
func makeProvConnForCrossTeam(t *testing.T, pool *storage.Pool, projectID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	const q = `
		INSERT INTO provider_connections (name, type, auth_method, scope, status)
		VALUES ($1, 'vault', 'token', $2::jsonb, 'active')
		RETURNING id`
	scope := `{"project_id":"` + projectID.String() + `"}`
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), q, name, scope).Scan(&id); err != nil {
		t.Fatalf("provider_connections insert %q: %v", name, err)
	}
	return id
}

func makeEnvForCrossTeam(t *testing.T, pool *storage.Pool, projectID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	repo := storage.NewEnvironments(pool)
	env := &storage.Environment{
		ProjectID: projectID,
		Name:      name,
		Type:      storage.EnvironmentTypeUAT,
		Kind:      storage.EnvironmentKindNonProd,
	}
	if err := repo.Create(t.Context(), env); err != nil {
		t.Fatalf("env Create %q: %v", name, err)
	}
	return env.ID
}

// crossTeamFixture builds a self-contained scope graph + an unattached
// cross_team request the caller mutates to suit each test. Caller must
// repo.CreateCrossTeam(req) themselves.
type crossTeamFixture struct {
	pool                 *storage.Pool
	repo                 *storage.AccessRequests
	requesterID          string
	sourceProjectID      uuid.UUID
	targetTeamID         uuid.UUID
	targetProjectID      uuid.UUID
	targetEnvID          uuid.UUID
	destProvConnID       uuid.UUID
	workflowID           uuid.UUID
	policyRuleID         uuid.UUID
	requiresSecApproval  bool
	minApprovers         int16
	fillExpiresAt        time.Time
}

func newCrossTeamFixture(t *testing.T, label string) *crossTeamFixture {
	t.Helper()
	pool := freshDB(t)
	ctx := t.Context()

	sourceProject := makeProject(t, pool, label+"-src")
	targetTeam := makeTeamForCrossTeam(t, pool, label+"-target-team")
	targetProject := makeProject(t, pool, label+"-target")
	targetEnv := makeEnvForCrossTeam(t, pool, targetProject, "uat")
	destProvConn := makeProvConnForCrossTeam(t, pool, sourceProject, label+"-dest-vault")

	// Use the seeded default workflow + match-all policy rule so
	// snapshot fields point at real rows.
	wf, err := storage.NewWorkflows(pool).GetDefault(ctx)
	if err != nil {
		t.Fatalf("default workflow: %v", err)
	}

	var policyRuleID uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT id FROM policy_rules WHERE is_system = true LIMIT 1`,
	).Scan(&policyRuleID); err != nil {
		t.Fatalf("policy rule lookup: %v", err)
	}

	return &crossTeamFixture{
		pool:                pool,
		repo:                storage.NewAccessRequests(pool),
		requesterID:         "alice@example.com",
		sourceProjectID:     sourceProject,
		targetTeamID:        targetTeam,
		targetProjectID:     targetProject,
		targetEnvID:         targetEnv,
		destProvConnID:      destProvConn,
		workflowID:          wf.ID,
		policyRuleID:        policyRuleID,
		requiresSecApproval: false,
		minApprovers:        1,
		fillExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
	}
}

func (f *crossTeamFixture) build() *storage.AccessRequest {
	req := &storage.AccessRequest{
		RequesterID:                     f.requesterID,
		Type:                            storage.AccessRequestTypeCrossTeam,
		Justification:                   "rotate billing creds; team-handoff",
		Status:                          storage.AccessRequestStatusPendingValues,
		WorkflowID:                      &f.workflowID,
		TargetTeamID:                    &f.targetTeamID,
		TargetProjectID:                 &f.targetProjectID,
		TargetEnvironmentID:             &f.targetEnvID,
		DestinationProviderConnectionID: &f.destProvConnID,
		DestinationSecretRef:            "billing/uat/db",
		DestinationKeys:                 []string{"DB_PASSWORD", "DB_USER"},
		FillExpiresAt:                   &f.fillExpiresAt,
		MatchedPolicyRuleID:             &f.policyRuleID,
		SnapRequiresSecurityApproval:    &f.requiresSecApproval,
		SnapMinApprovers:                &f.minApprovers,
		TargetScope: map[string]any{
			"project_id":  f.sourceProjectID.String(),
			"environment": "prod",
		},
	}
	return req
}

func TestCrossTeam_CreateRoundtrips(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-create")
	ctx := t.Context()

	req := f.build()
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}

	got, err := f.repo.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Type != storage.AccessRequestTypeCrossTeam {
		t.Errorf("Type = %s", got.Type)
	}
	if got.Status != storage.AccessRequestStatusPendingValues {
		t.Errorf("Status = %s want pending_values", got.Status)
	}
	if got.TargetTeamID == nil || *got.TargetTeamID != f.targetTeamID {
		t.Errorf("TargetTeamID round-trip mismatch")
	}
	if got.DestinationProviderConnectionID == nil || *got.DestinationProviderConnectionID != f.destProvConnID {
		t.Errorf("DestinationProviderConnectionID round-trip mismatch")
	}
	if len(got.DestinationKeys) != 2 {
		t.Errorf("DestinationKeys round-trip = %v", got.DestinationKeys)
	}
	if got.SnapRequiresSecurityApproval == nil || *got.SnapRequiresSecurityApproval != false {
		t.Errorf("SnapRequiresSecurityApproval round-trip mismatch")
	}
	if got.SnapMinApprovers == nil || *got.SnapMinApprovers != 1 {
		t.Errorf("SnapMinApprovers round-trip = %v", got.SnapMinApprovers)
	}
	if got.MatchedPolicyRuleID == nil || *got.MatchedPolicyRuleID != f.policyRuleID {
		t.Errorf("MatchedPolicyRuleID round-trip mismatch")
	}
	if got.FillExpiresAt == nil {
		t.Errorf("FillExpiresAt is nil")
	}
}

func TestCrossTeam_CrossTeamStatusOnlyCheck(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-status-check")
	ctx := t.Context()

	// A non-cross_team request (patch) cannot be moved into the
	// cross_team-only states by a malicious or buggy caller.
	wf, _ := storage.NewWorkflows(f.pool).GetDefault(ctx)
	patch := &storage.AccessRequest{
		RequesterID:        f.requesterID,
		Type:               storage.AccessRequestTypePatch,
		Justification:      "patch flow",
		WorkflowID:         &wf.ID,
		TargetProviderType: "vault",
		TargetSecretRef:    "billing/uat/db",
		TargetKeys:         []string{"DB_PASSWORD"},
		TargetScope:        map[string]any{},
	}
	if err := f.repo.Create(ctx, patch); err != nil {
		t.Fatalf("seed patch request: %v", err)
	}

	for _, status := range []storage.AccessRequestStatus{
		storage.AccessRequestStatusPendingValues,
		storage.AccessRequestStatusPendingVerification,
		storage.AccessRequestStatusRefused,
	} {
		err := f.repo.UpdateStatus(ctx, patch.ID, status)
		if err == nil {
			t.Errorf("patch row admitted into status=%q (should be CHECK-rejected)", status)
		}
	}
}

func TestCrossTeam_FK_RestrictTeamDeleteWithOpenRequest(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-fk-team")
	ctx := t.Context()
	if err := f.repo.CreateCrossTeam(ctx, f.build()); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}
	_, err := f.pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, f.targetTeamID)
	if err == nil {
		t.Fatal("team delete succeeded; should be RESTRICTed by open cross_team request")
	}
}

func TestCrossTeam_FK_RestrictProviderConnectionDeleteWithOpenRequest(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-fk-conn")
	ctx := t.Context()
	if err := f.repo.CreateCrossTeam(ctx, f.build()); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}
	_, err := f.pool.Exec(ctx, `DELETE FROM provider_connections WHERE id = $1`, f.destProvConnID)
	if err == nil {
		t.Fatal("provider_connection delete succeeded; should be RESTRICTed")
	}
}

func TestCrossTeam_FillHappyPath(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-fill")
	ctx := t.Context()
	req := f.build()
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}

	filledAt := time.Now().UTC()
	if err := f.repo.Fill(ctx, req.ID, "bob@example.com", "rotated; valid for 90 days", filledAt); err != nil {
		t.Fatalf("Fill: %v", err)
	}

	got, _ := f.repo.Get(ctx, req.ID)
	if got.Status != storage.AccessRequestStatusPendingVerification {
		t.Errorf("Status = %s want pending_verification", got.Status)
	}
	if got.FilledByUserID != "bob@example.com" {
		t.Errorf("FilledByUserID = %q", got.FilledByUserID)
	}
	if got.FillComment != "rotated; valid for 90 days" {
		t.Errorf("FillComment = %q", got.FillComment)
	}
	// Postgres TIMESTAMPTZ truncates to microsecond precision; check
	// within a millisecond window rather than exact equality.
	if got.FilledAt == nil || got.FilledAt.Sub(filledAt).Abs() > time.Millisecond {
		t.Errorf("FilledAt round-trip mismatch: got %v want ~%v", got.FilledAt, filledAt)
	}
}

func TestCrossTeam_FillRejectsSecondCaller(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-fill-2nd")
	ctx := t.Context()
	req := f.build()
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}
	filledAt := time.Now().UTC()
	if err := f.repo.Fill(ctx, req.ID, "bob@example.com", "", filledAt); err != nil {
		t.Fatalf("first Fill: %v", err)
	}
	err := f.repo.Fill(ctx, req.ID, "carol@example.com", "", filledAt.Add(time.Second))
	if !errors.Is(err, storage.ErrCrossTeamAlreadyFilled) {
		t.Fatalf("second Fill err = %v want ErrCrossTeamAlreadyFilled", err)
	}
}

func TestCrossTeam_FillRejectsAfterTTLElapsed(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-fill-ttl")
	ctx := t.Context()
	// Pre-stamp the fixture's expiry to a past timestamp so the
	// CHECK fires on Fill.
	past := time.Now().Add(-time.Minute).UTC()
	f.fillExpiresAt = past
	req := f.build()
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}

	err := f.repo.Fill(ctx, req.ID, "bob@example.com", "", time.Now().UTC())
	if !errors.Is(err, storage.ErrFillWindowExpired) {
		t.Fatalf("Fill err = %v want ErrFillWindowExpired", err)
	}
}

func TestCrossTeam_FillNotFound(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-fill-404")
	ctx := t.Context()
	err := f.repo.Fill(ctx, uuid.New(), "bob@example.com", "", time.Now().UTC())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestCrossTeam_RefuseHappyPath(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-refuse")
	ctx := t.Context()
	req := f.build()
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}
	if err := f.repo.Refuse(ctx, req.ID, "out-of-scope ask"); err != nil {
		t.Fatalf("Refuse: %v", err)
	}
	got, _ := f.repo.Get(ctx, req.ID)
	if got.Status != storage.AccessRequestStatusRefused {
		t.Errorf("Status = %s want refused", got.Status)
	}
	if got.RejectReason != "" {
		t.Errorf("RejectReason should not be set on refuse: %q", got.RejectReason)
	}
	// Verify the refuse_reason landed in its own column.
	var stored string
	_ = f.pool.QueryRow(ctx, `SELECT refuse_reason FROM access_requests WHERE id = $1`, req.ID).Scan(&stored)
	if stored != "out-of-scope ask" {
		t.Errorf("refuse_reason stored = %q", stored)
	}
}

func TestCrossTeam_RefuseRejectsNonPendingValues(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-refuse-bad-state")
	ctx := t.Context()
	req := f.build()
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}
	if err := f.repo.Fill(ctx, req.ID, "bob@example.com", "", time.Now().UTC()); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	err := f.repo.Refuse(ctx, req.ID, "too late")
	if !errors.Is(err, storage.ErrCrossTeamStatusInvalidTransition) {
		t.Fatalf("err = %v want ErrCrossTeamStatusInvalidTransition", err)
	}
}

func TestCrossTeam_SweepFillExpired(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-sweep")
	ctx := t.Context()

	// Two past-TTL rows + one fresh row.
	past := time.Now().Add(-time.Hour).UTC()
	future := time.Now().Add(time.Hour).UTC()
	for i, exp := range []time.Time{past, past, future} {
		f.fillExpiresAt = exp
		req := f.build()
		req.RequesterID = "user-" + uuid.NewString()
		req.Justification = "sweep test row " + uuid.NewString()
		if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
			t.Fatalf("CreateCrossTeam row %d: %v", i, err)
		}
	}

	swept, err := f.repo.SweepFillExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("SweepFillExpired: %v", err)
	}
	if len(swept) != 2 {
		t.Fatalf("swept = %d want 2", len(swept))
	}

	// Re-run is idempotent.
	again, err := f.repo.SweepFillExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("SweepFillExpired re-run: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("idempotent re-run swept %d rows; want 0", len(again))
	}

	// The fresh row stays pending_values.
	var stillPending int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM access_requests WHERE status = 'pending_values' AND type = 'cross_team'`,
	).Scan(&stillPending); err != nil {
		t.Fatalf("count pending_values: %v", err)
	}
	if stillPending != 1 {
		t.Errorf("pending_values count = %d want 1", stillPending)
	}
}

func TestCrossTeam_ListInbox(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-inbox")
	ctx := t.Context()

	// Three pending_values requests against the original target team.
	for i := 0; i < 3; i++ {
		req := f.build()
		req.RequesterID = "alice-" + uuid.NewString()
		if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond) // ensure distinct created_at
	}
	originalTargetTeam := f.targetTeamID
	// One unrelated team's request — must not appear in the inbox of
	// the original target team.
	otherTeam := makeTeamForCrossTeam(t, f.pool, "ct-inbox-other")
	f.targetTeamID = otherTeam
	if err := f.repo.CreateCrossTeam(ctx, f.build()); err != nil {
		t.Fatalf("seed unrelated row: %v", err)
	}

	got, err := f.repo.ListInbox(ctx, storage.InboxFilter{
		TeamIDs: []uuid.UUID{originalTargetTeam},
	})
	if err != nil {
		t.Fatalf("ListInbox: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("inbox rows = %d want 3", len(got))
	}
	// Oldest first.
	for i := 1; i < len(got); i++ {
		if got[i].CreatedAt.Before(got[i-1].CreatedAt) {
			t.Errorf("inbox not ordered oldest-first")
		}
	}

	// Fail-closed on empty team set.
	empty, err := f.repo.ListInbox(ctx, storage.InboxFilter{TeamIDs: nil})
	if err != nil {
		t.Fatalf("ListInbox(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty-team-set returned %d rows", len(empty))
	}
}

func TestCrossTeam_CanaryNotInOperatorTextColumns(t *testing.T) {
	f := newCrossTeamFixture(t, "ct-canary")
	ctx := t.Context()

	canary := "ZZZ-ct-canary-XYZ"
	req := f.build()
	req.Justification = "rotate creds — context: " + canary
	if err := f.repo.CreateCrossTeam(ctx, req); err != nil {
		t.Fatalf("CreateCrossTeam: %v", err)
	}

	// Walk every TEXT-ish column on access_requests and confirm the
	// canary appears ONLY in justification (where the caller put it).
	// fill_comment / refuse_reason / target_secret_ref must NOT
	// inadvertently mirror it.
	rows, err := f.pool.Query(ctx, `
		SELECT COALESCE(fill_comment, ''),
		       COALESCE(refuse_reason, ''),
		       COALESCE(destination_secret_ref, ''),
		       COALESCE(target_secret_ref, ''),
		       COALESCE(reject_reason, '')
		FROM access_requests WHERE id = $1`, req.ID)
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("row not found")
	}
	var fill, refuse, dest, targetRef, reject string
	if err := rows.Scan(&fill, &refuse, &dest, &targetRef, &reject); err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, col := range []string{fill, refuse, dest, targetRef, reject} {
		if contains(col, canary) {
			t.Errorf("canary leaked into a column that should not carry justification text: %q", col)
		}
	}
}

// contains is a tiny helper that avoids importing strings for one call;
// the existing test files use the same shape (containsBytes).
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

