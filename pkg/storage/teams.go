package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Team mirrors a row in the teams table. The hierarchy is N-level via
// ParentTeamID; root teams have ParentTeamID == nil. Membership lives
// in a separate join table — Team itself only carries the structural
// metadata.
type Team struct {
	ID           uuid.UUID
	Name         string
	ParentTeamID *uuid.UUID // nil for root teams
	Status       TeamStatus
	Description  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TeamStatus is constrained by a CHECK in the schema.
type TeamStatus string

const (
	TeamStatusActive   TeamStatus = "active"
	TeamStatusArchived TeamStatus = "archived"
)

// TeamMember mirrors a row in the team_members join table.
type TeamMember struct {
	TeamID    uuid.UUID
	UserID    uuid.UUID
	CreatedAt time.Time
	CreatedBy *uuid.UUID
}

// Sentinel errors specific to the teams domain. ErrNotFound +
// ErrDuplicateName are shared with the rest of the storage package.
var (
	// ErrCyclicParent surfaces when the application-layer cycle check
	// detects an attempt to set parent_team_id to a team that lives
	// inside the moved team's own subtree. The schema can't express
	// this; the repository enforces it via DescendantIDs.
	ErrCyclicParent = errors.New("storage: parent_team_id would create a cycle")

	// ErrHasChildren surfaces when an attempt to delete a team fails
	// because Postgres's ON DELETE RESTRICT kicked in. Operators must
	// unparent or delete the children first.
	ErrHasChildren = errors.New("storage: team has children")

	// ErrAlreadyMember surfaces when adding a user that's already in
	// the team (the PRIMARY KEY on (team_id, user_id) raised 23505).
	ErrAlreadyMember = errors.New("storage: user already a member of this team")
)

// TeamRepository is the read/write surface for teams + team_members.
type TeamRepository interface {
	// Team CRUD.
	Create(ctx context.Context, t *Team) error
	Get(ctx context.Context, id uuid.UUID) (*Team, error)
	List(ctx context.Context) ([]*Team, error)
	Update(ctx context.Context, id uuid.UUID, name, description string, parent *uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status TeamStatus) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Hierarchy walk. DescendantIDs returns the team and ALL its
	// descendants, depth-first, deduped. Used by the access resolver to
	// expand a team-scoped grant into the full subtree.
	DescendantIDs(ctx context.Context, root uuid.UUID) ([]uuid.UUID, error)

	// AncestorIDs returns the team and ALL its ancestors up to the
	// root. Used to render breadcrumbs + to answer "is X under Y?" in
	// constant queries.
	AncestorIDs(ctx context.Context, leaf uuid.UUID) ([]uuid.UUID, error)

	// Membership.
	AddMember(ctx context.Context, teamID, userID uuid.UUID, createdBy *uuid.UUID) error
	RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error
	ListMembers(ctx context.Context, teamID uuid.UUID) ([]TeamMember, error)
	ListTeamsForUser(ctx context.Context, userID uuid.UUID) ([]*Team, error)
}

// Teams is the Postgres-backed implementation.
type Teams struct {
	pool *Pool
}

// NewTeams binds a Teams repository to the given pool.
func NewTeams(pool *Pool) *Teams { return &Teams{pool: pool} }

// Create inserts a new team. Sibling-name uniqueness is enforced by
// the partial unique indexes; a 23505 maps to ErrDuplicateName. A
// parent_team_id pointing at an unknown row raises a 23503 (foreign
// key violation) which surfaces as ErrNotFound for caller clarity.
func (r *Teams) Create(ctx context.Context, t *Team) error {
	if t.Name == "" {
		return errors.New("storage: team Name is required")
	}
	if t.Status == "" {
		t.Status = TeamStatusActive
	}

	const q = `
		INSERT INTO teams (name, parent_team_id, status, description)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		RETURNING id, created_at, updated_at`

	err := r.pool.QueryRow(ctx, q,
		t.Name, t.ParentTeamID, string(t.Status), t.Description,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return mapTeamErr(err)
	}
	return nil
}

// Get fetches a single team by ID.
func (r *Teams) Get(ctx context.Context, id uuid.UUID) (*Team, error) {
	const q = `
		SELECT id, name, parent_team_id, status, COALESCE(description, ''),
		       created_at, updated_at
		FROM teams
		WHERE id = $1`
	t := &Team{}
	var desc string
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&t.ID, &t.Name, &t.ParentTeamID, &t.Status, &desc,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("teams.Get: %w", err)
	}
	t.Description = desc
	return t, nil
}

// List returns every team, ordered by created_at ASC. Hierarchies are
// usually small enough to materialize fully; callers that need a tree
// view assemble it client-side from this flat list.
func (r *Teams) List(ctx context.Context) ([]*Team, error) {
	const q = `
		SELECT id, name, parent_team_id, status, COALESCE(description, ''),
		       created_at, updated_at
		FROM teams
		ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("teams.List: %w", err)
	}
	defer rows.Close()
	var out []*Team
	for rows.Next() {
		t := &Team{}
		var desc string
		if err := rows.Scan(
			&t.ID, &t.Name, &t.ParentTeamID, &t.Status, &desc,
			&t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("teams.List scan: %w", err)
		}
		t.Description = desc
		out = append(out, t)
	}
	return out, rows.Err()
}

// Update rewrites name, description, and parent_team_id atomically.
// parent == nil un-parents the team to the root; pointer-to-uuid.Nil
// is treated the same way. A parent pointing into the team's own
// subtree raises ErrCyclicParent.
func (r *Teams) Update(ctx context.Context, id uuid.UUID, name, description string, parent *uuid.UUID) error {
	if name == "" {
		return errors.New("storage: team Name is required")
	}
	// Cycle check: parent must not live inside id's subtree.
	if parent != nil && *parent != uuid.Nil {
		desc, err := r.DescendantIDs(ctx, id)
		if err != nil {
			return fmt.Errorf("teams.Update cycle check: %w", err)
		}
		for _, d := range desc {
			if d == *parent {
				return ErrCyclicParent
			}
		}
	}

	// Normalise pointer-to-Nil into a true SQL NULL.
	var parentArg interface{}
	if parent != nil && *parent != uuid.Nil {
		parentArg = *parent
	}

	const q = `
		UPDATE teams
		   SET name = $1,
		       description = NULLIF($2, ''),
		       parent_team_id = $3
		 WHERE id = $4`
	ct, err := r.pool.Exec(ctx, q, name, description, parentArg, id)
	if err != nil {
		return mapTeamErr(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateWithLineageAudit is the transactional sibling of Update used
// when an operator changes a team's parent_team_id. Per §2 C6 the
// lineage-change audit event MUST commit in the SAME transaction as
// the parent update — an audit append that fails must roll back the
// parent change, and a successful parent change MUST emit the audit.
//
// When the parent change is a no-op (old parent == new parent), no
// audit event is emitted (idempotent — matches the project-side
// audit's "changed_keys" preserve semantic).
//
// The lineage audit metadata mirrors the user-locked spec:
//
//	{
//	  team_id, old_parent_team_id, new_parent_team_id,
//	  team_policy_rule_count, affected_project_count
//	}
//
// Counts are computed inside the same transaction so the operator
// sees the blast radius captured against the pre-change topology.
func (r *Teams) UpdateWithLineageAudit(
	ctx context.Context,
	id uuid.UUID,
	name, description string,
	parent *uuid.UUID,
	actor string,
	audit *AuditEvents,
) error {
	if name == "" {
		return errors.New("storage: team Name is required")
	}
	if parent != nil && *parent != uuid.Nil {
		desc, err := r.DescendantIDs(ctx, id)
		if err != nil {
			return fmt.Errorf("teams.UpdateWithLineageAudit cycle check: %w", err)
		}
		for _, d := range desc {
			if d == *parent {
				return ErrCyclicParent
			}
		}
	}
	var parentArg interface{}
	if parent != nil && *parent != uuid.Nil {
		parentArg = *parent
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("teams.UpdateWithLineageAudit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Load existing parent FOR UPDATE so concurrent edits serialise.
	var oldParent *uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT parent_team_id FROM teams WHERE id = $1 FOR UPDATE`, id,
	).Scan(&oldParent); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("teams.UpdateWithLineageAudit: load: %w", err)
	}

	// Apply the UPDATE.
	if _, err := tx.Exec(ctx, `
		UPDATE teams
		   SET name = $1,
		       description = NULLIF($2, ''),
		       parent_team_id = $3
		 WHERE id = $4`, name, description, parentArg, id,
	); err != nil {
		return mapTeamErr(err)
	}

	// Determine whether parent actually changed.
	var newParent *uuid.UUID
	if parent != nil && *parent != uuid.Nil {
		v := *parent
		newParent = &v
	}
	parentChanged := !uuidPtrEqual(oldParent, newParent)

	if parentChanged && audit != nil {
		// Compute affected counts INSIDE the same transaction so the
		// audit sees the pre-change topology by SQL semantics — the
		// UPDATE above changed the team's parent, but `descendants`
		// here walks rows in the CURRENT (post-update) state. For
		// the §2 C6 spec, the operator wants the blast radius of
		// the new lineage. Both readings are useful; we pick the
		// new lineage because it answers "how many projects will
		// now see different resolution results."
		var ruleCount, projectCount int
		if err := tx.QueryRow(ctx, `
			WITH RECURSIVE descendants AS (
			    SELECT id FROM teams WHERE id = $1
			    UNION ALL
			    SELECT t.id FROM teams t JOIN descendants d ON t.parent_team_id = d.id
			)
			SELECT
			    (SELECT COUNT(*) FROM policy_rules WHERE team_id = $1),
			    (SELECT COUNT(*) FROM projects WHERE team_id IN (SELECT id FROM descendants))`,
			id,
		).Scan(&ruleCount, &projectCount); err != nil {
			return fmt.Errorf("teams.UpdateWithLineageAudit: counts: %w", err)
		}

		oldParentStr := ""
		if oldParent != nil {
			oldParentStr = oldParent.String()
		}
		newParentStr := ""
		if newParent != nil {
			newParentStr = newParent.String()
		}
		if err := audit.AppendTx(ctx, tx, &AuditEvent{
			Actor:    actorOrSystem(actor),
			Action:   "policy.team_lineage_changed",
			Resource: "team:" + id.String(),
			Status:   AuditStatusSuccess,
			Metadata: map[string]any{
				"team_id":                id.String(),
				"old_parent_team_id":     oldParentStr,
				"new_parent_team_id":     newParentStr,
				"team_policy_rule_count": ruleCount,
				"affected_project_count": projectCount,
			},
		}); err != nil {
			return fmt.Errorf("teams.UpdateWithLineageAudit: audit append: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// actorOrSystem returns "system" when actor is empty, mirroring the
// services package's actorOrAdmin helper. Avoids a "" actor that the
// audit_events CHECK constraint would reject.
func actorOrSystem(actor string) string {
	if actor == "" {
		return "system"
	}
	return actor
}

// UpdateStatus toggles active ↔ archived.
func (r *Teams) UpdateStatus(ctx context.Context, id uuid.UUID, status TeamStatus) error {
	if status != TeamStatusActive && status != TeamStatusArchived {
		return fmt.Errorf("storage: invalid team status %q", status)
	}
	ct, err := r.pool.Exec(ctx,
		`UPDATE teams SET status = $1 WHERE id = $2`,
		string(status), id,
	)
	if err != nil {
		return fmt.Errorf("teams.UpdateStatus: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a team. Postgres's ON DELETE RESTRICT on the
// parent_team_id self-reference raises 23503 when the team has
// children — surface as ErrHasChildren so the handler can return 409.
// team_members rows CASCADE-delete cleanly. mapTeamErr can't help here
// because the same constraint code carries opposite meanings depending
// on whether the FK was violated by an insert/update (referenced row
// missing → ErrNotFound) or a delete-restrict (referencing rows still
// exist → ErrHasChildren); this Delete sets the latter explicitly.
func (r *Teams) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrHasChildren
		}
		return mapTeamErr(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DescendantIDs returns root and every team in its subtree, depth-
// first ordered. Implemented as a recursive CTE so the entire walk
// is a single round-trip regardless of depth. Deduplicated by the
// CTE's natural set semantics (a team has exactly one parent).
func (r *Teams) DescendantIDs(ctx context.Context, root uuid.UUID) ([]uuid.UUID, error) {
	const q = `
		WITH RECURSIVE subtree AS (
			SELECT id FROM teams WHERE id = $1
			UNION ALL
			SELECT t.id
			  FROM teams t
			  JOIN subtree s ON t.parent_team_id = s.id
		)
		SELECT id FROM subtree`
	rows, err := r.pool.Query(ctx, q, root)
	if err != nil {
		return nil, fmt.Errorf("teams.DescendantIDs: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("teams.DescendantIDs scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AncestorIDs returns leaf and every team above it up to the root.
func (r *Teams) AncestorIDs(ctx context.Context, leaf uuid.UUID) ([]uuid.UUID, error) {
	const q = `
		WITH RECURSIVE ancestors AS (
			SELECT id, parent_team_id FROM teams WHERE id = $1
			UNION ALL
			SELECT t.id, t.parent_team_id
			  FROM teams t
			  JOIN ancestors a ON t.id = a.parent_team_id
		)
		SELECT id FROM ancestors`
	rows, err := r.pool.Query(ctx, q, leaf)
	if err != nil {
		return nil, fmt.Errorf("teams.AncestorIDs: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("teams.AncestorIDs scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AddMember inserts a (team_id, user_id) row. createdBy is optional;
// nil records the membership without an attribution audit field. A
// duplicate insert surfaces as ErrAlreadyMember (23505).
func (r *Teams) AddMember(ctx context.Context, teamID, userID uuid.UUID, createdBy *uuid.UUID) error {
	const q = `
		INSERT INTO team_members (team_id, user_id, created_by)
		VALUES ($1, $2, $3)`
	_, err := r.pool.Exec(ctx, q, teamID, userID, createdBy)
	if err != nil {
		return mapTeamErr(err)
	}
	return nil
}

// RemoveMember deletes a membership row. A missing row returns
// ErrNotFound so the handler can distinguish "already absent" from
// "deleted successfully" in audit events.
func (r *Teams) RemoveMember(ctx context.Context, teamID, userID uuid.UUID) error {
	ct, err := r.pool.Exec(ctx,
		`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`,
		teamID, userID,
	)
	if err != nil {
		return fmt.Errorf("teams.RemoveMember: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListMembers returns every membership row for the team, oldest first.
func (r *Teams) ListMembers(ctx context.Context, teamID uuid.UUID) ([]TeamMember, error) {
	const q = `
		SELECT team_id, user_id, created_at, created_by
		FROM team_members
		WHERE team_id = $1
		ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q, teamID)
	if err != nil {
		return nil, fmt.Errorf("teams.ListMembers: %w", err)
	}
	defer rows.Close()
	var out []TeamMember
	for rows.Next() {
		var m TeamMember
		if err := rows.Scan(&m.TeamID, &m.UserID, &m.CreatedAt, &m.CreatedBy); err != nil {
			return nil, fmt.Errorf("teams.ListMembers scan: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListTeamsForUser returns every team a user is directly a member of.
// Subtree expansion (a member of team T also belongs to T's ancestors
// for visibility purposes) is the resolver's job, not the repository's.
func (r *Teams) ListTeamsForUser(ctx context.Context, userID uuid.UUID) ([]*Team, error) {
	const q = `
		SELECT t.id, t.name, t.parent_team_id, t.status,
		       COALESCE(t.description, ''), t.created_at, t.updated_at
		  FROM teams t
		  JOIN team_members m ON m.team_id = t.id
		 WHERE m.user_id = $1
		 ORDER BY t.created_at ASC`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("teams.ListTeamsForUser: %w", err)
	}
	defer rows.Close()
	var out []*Team
	for rows.Next() {
		t := &Team{}
		var desc string
		if err := rows.Scan(
			&t.ID, &t.Name, &t.ParentTeamID, &t.Status, &desc,
			&t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("teams.ListTeamsForUser scan: %w", err)
		}
		t.Description = desc
		out = append(out, t)
	}
	return out, rows.Err()
}

// mapTeamErr translates Postgres SQLSTATEs into the sentinel set that
// callers branch on. Anything else flows through with wrapping for
// log-trace context.
func mapTeamErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			switch pgErr.ConstraintName {
			case "teams_name_per_parent_uniq", "teams_name_root_uniq":
				return ErrDuplicateName
			case "team_members_pkey":
				return ErrAlreadyMember
			}
		case "23503": // foreign_key_violation
			if pgErr.ConstraintName == "teams_parent_team_id_fkey" {
				return ErrNotFound
			}
		case "23P01", "23P00": // restrict_violation / foreign_key_violation w/ restrict
			return ErrHasChildren
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("teams: %w", err)
}
