package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PolicyRule maps a request scope to the workflow that should govern
// it. Resolution: PolicyEngine walks enabled rules in priority DESC
// order; the first whose selector fully matches the scope wins.
//
// Slice L2 fields carry the access DECISION (separate from the
// approval CEREMONY which stays on the workflow):
//
//   - DirectRevealAllowed: when true AND the matched environment is
//     non_prod, the API bypasses access_requests and issues a
//     single-shot wrap. The PolicyEngine ZEROES this whenever the
//     scope's environment.kind is 'prod', regardless of what the
//     operator wrote.
//   - RequiresMFA: when true, the API attaches RequireFreshMFA
//     middleware on the matched route.
//   - RevealTTLSeconds: server-enforced reveal-session/wrap TTL.
//     CHECK constraint pins to 10..300.
//
// EPIC R + R-follow-up #3 anchor model:
//
//	ProjectID NULL,  TeamID NULL    → platform-owned (admin policy.edit)
//	ProjectID set,   TeamID NULL    → project-scoped (EPIC R, api#108)
//	ProjectID NULL,  TeamID set     → team-scoped (R-follow-up #3, api#114)
//	ProjectID set,   TeamID set     → INVALID (CHECK constraint)
type PolicyRule struct {
	ID                  uuid.UUID
	Name                string
	Selector            map[string]any
	WorkflowID          uuid.UUID
	Priority            int
	Enabled             bool
	IsSystem            bool
	DirectRevealAllowed bool
	RequiresMFA         bool
	RevealTTLSeconds    int

	// EPIC R (api#108) — NULL means platform-owned (admin only via
	// policy.edit). Non-nil means scoped to a specific project; the
	// scoped service path (policy.author) gates writes; the resolver
	// gates matching so a project-A rule never resolves for a request
	// against project B.
	ProjectID *uuid.UUID

	// R-follow-up #3 (api#114) — NULL means platform OR project anchor.
	// Non-nil means team-scoped; the rule cascades down to every
	// descendant project of the team subtree at resolution time.
	// Mutually exclusive with ProjectID — the DB CHECK
	// policy_rules_one_anchor enforces.
	TeamID *uuid.UUID

	// WorkflowName is populated by ListForProject / ListForTeam /
	// ListForAdmin via a server-side JOIN on workflow_definitions.
	// Get / Create / Update leave it empty. Callers that need a
	// workflow name on a single-row response should do their own
	// lookup (or wait for the next slice that extends Get).
	WorkflowName string

	// TeamName is populated by ListForProject for team-inherited rows
	// (TeamID set) and by ListForTeam for ancestor-inherited rows. The
	// envelope projection at the handler layer surfaces it on the
	// `[team]` badge tooltip. Leave empty everywhere else.
	TeamName string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Anchor is the 3-anchor classification of a PolicyRule used for the
// resolver's tie-break specificity rank (project > team > platform).
type Anchor int

const (
	// AnchorPlatform — ProjectID NULL AND TeamID NULL.
	AnchorPlatform Anchor = iota
	// AnchorTeam — TeamID set; rule cascades to descendant projects.
	AnchorTeam
	// AnchorProject — ProjectID set; rule applies only to that project.
	AnchorProject
)

// Anchor returns the rule's anchor classification. Integer ordering
// (platform=0, team=1, project=2) matches the SQL specificity rank
// embedded in ListEnabledOrderedByPriority's ORDER BY.
func (r *PolicyRule) Anchor() Anchor {
	switch {
	case r.ProjectID != nil:
		return AnchorProject
	case r.TeamID != nil:
		return AnchorTeam
	default:
		return AnchorPlatform
	}
}

// ErrAnchorImmutable is returned by Update when a caller attempts to
// flip a rule's anchor (project ↔ team, or null ↔ non-null). Changing
// the anchor changes resolver semantics; force delete-and-recreate.
var ErrAnchorImmutable = errors.New("storage: policy rule anchor is immutable; delete and re-create with the new anchor")

// PolicyRepository is the read/write surface for policy_rules.
type PolicyRepository interface {
	Create(ctx context.Context, p *PolicyRule) error
	Get(ctx context.Context, id uuid.UUID) (*PolicyRule, error)
	List(ctx context.Context) ([]*PolicyRule, error)
	// ListEnabledOrderedByPriority returns enabled rules ordered for
	// resolution: deterministic 5-clause tie-break chain:
	//
	//   priority DESC
	//   anchor specificity DESC (project=2, team=1, platform=0)
	//   team distance ASC NULLS LAST (closer ancestor = smaller = wins)
	//   created_at ASC
	//   id ASC
	//
	// EPIC R + R-follow-up #3 applicability filter: when projectID is
	// the zero uuid, return platform-owned rules only. When projectID
	// is set, return platform + project-scoped + team-scoped rules
	// where the team is in the project's ancestor chain. Subtree-down
	// cascade is computed by walking projects.team_id up via
	// parent_team_id inside an inline recursive CTE.
	ListEnabledOrderedByPriority(ctx context.Context, projectID uuid.UUID) ([]*PolicyRule, error)
	Update(ctx context.Context, p *PolicyRule) error
	Delete(ctx context.Context, id uuid.UUID) error

	// ListForProject returns rows visible from a project's policies
	// page: own project-scoped rules (any enabled state) + platform
	// inherited (enabled only) + team inherited (enabled only). The
	// C4 filter on inherited rows belongs to the SQL layer so the
	// handler doesn't have to re-filter post-fetch. WorkflowName +
	// TeamName populated via JOIN.
	ListForProject(ctx context.Context, projectID uuid.UUID) ([]*PolicyRule, error)

	// ListForTeam returns rows visible from a team's policies page:
	// own team-scoped rules (any enabled state) + ancestor-team
	// inherited (enabled only) + platform inherited (enabled only).
	// NEVER includes project-scoped rules under the team subtree —
	// that's a different mental model. WorkflowName populated via JOIN.
	ListForTeam(ctx context.Context, teamID uuid.UUID) ([]*PolicyRule, error)
}

// Policies is the Postgres implementation.
type Policies struct {
	pool *Pool
}

// NewPolicies binds a Policies repository to the given pool.
func NewPolicies(pool *Pool) *Policies { return &Policies{pool: pool} }

func (r *Policies) Create(ctx context.Context, p *PolicyRule) error {
	if p.Name == "" {
		return errors.New("storage: policy Name is required")
	}
	if p.WorkflowID == uuid.Nil {
		return errors.New("storage: policy WorkflowID is required")
	}
	if p.Selector == nil {
		p.Selector = map[string]any{}
	}
	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return fmt.Errorf("storage: marshal policy selector: %w", err)
	}
	if p.RevealTTLSeconds == 0 {
		p.RevealTTLSeconds = 60
	}
	const q = `
		INSERT INTO policy_rules (
			name, selector, workflow_id, priority, enabled, is_system,
			direct_reveal_allowed, requires_mfa, reveal_ttl_seconds,
			project_id, team_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		p.Name, selector, p.WorkflowID, p.Priority, p.Enabled, p.IsSystem,
		p.DirectRevealAllowed, p.RequiresMFA, p.RevealTTLSeconds,
		p.ProjectID, p.TeamID,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (r *Policies) Get(ctx context.Context, id uuid.UUID) (*PolicyRule, error) {
	return scanPolicy(r.pool.QueryRow(ctx, policySelect+` WHERE id = $1`, id))
}

func (r *Policies) List(ctx context.Context) ([]*PolicyRule, error) {
	rows, err := r.pool.Query(ctx, policySelect+` ORDER BY priority DESC, created_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list policies: %w", err)
	}
	defer rows.Close()

	var out []*PolicyRule
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// resolverSelect carries the same column set policySelect does plus a
// computed `team_distance` from the team_chain CTE used by
// ListEnabledOrderedByPriority. The distance is hops UP from the
// project's owning team to the rule's team_id; smaller = closer
// ancestor = wins on tie. NULL for project + platform rows (kept out
// of the team-depth comparison via NULLS LAST in the ORDER BY).
const policyResolverColumns = `
	pr.id, pr.name, pr.selector, pr.workflow_id, pr.priority, pr.enabled, pr.is_system,
	pr.direct_reveal_allowed, pr.requires_mfa, pr.reveal_ttl_seconds,
	pr.project_id, pr.team_id,
	pr.created_at, pr.updated_at`

func (r *Policies) ListEnabledOrderedByPriority(ctx context.Context, projectID uuid.UUID) ([]*PolicyRule, error) {
	// Platform-only path stays simple — no project context means no
	// team_chain to walk. Cheaper than the CTE; identical to today's
	// behavior for callers that pass uuid.Nil.
	if projectID == uuid.Nil {
		const q = `
			SELECT id, name, selector, workflow_id, priority, enabled, is_system,
			       direct_reveal_allowed, requires_mfa, reveal_ttl_seconds,
			       project_id, team_id,
			       created_at, updated_at
			  FROM policy_rules
			 WHERE enabled = TRUE
			   AND project_id IS NULL
			   AND team_id IS NULL
			 ORDER BY priority DESC, created_at ASC, id ASC`
		rows, err := r.pool.Query(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("storage: list enabled platform policies: %w", err)
		}
		defer rows.Close()
		return collectPolicies(rows)
	}

	// Project context — single inline recursive CTE walks ancestor
	// teams of the project's owning team. Deterministic 5-clause
	// tie-break per §1 C2. The LEFT JOIN team_chain populates
	// team_distance for team rows; project + platform rows get NULL
	// (kept out of the team-depth tie-break via NULLS LAST).
	const q = `
		WITH RECURSIVE team_chain(id, distance) AS (
		    -- Distance 0 = the project's owning team. Projects with
		    -- team_id IS NULL (pre-0018 backfill, or unassigned) yield
		    -- an empty CTE; no team rules will match — graceful fallback
		    -- to project + platform only.
		    SELECT p.team_id, 0
		      FROM projects p
		     WHERE p.id = $1 AND p.team_id IS NOT NULL
		    UNION ALL
		    SELECT t.parent_team_id, tc.distance + 1
		      FROM teams t
		      JOIN team_chain tc ON t.id = tc.id
		     WHERE t.parent_team_id IS NOT NULL
		)
		SELECT ` + policyResolverColumns + `
		  FROM policy_rules pr
		  LEFT JOIN team_chain tc ON tc.id = pr.team_id
		 WHERE pr.enabled = TRUE
		   AND (
		        pr.project_id = $1                                  -- project rule
		        OR (pr.project_id IS NULL AND pr.team_id IS NULL)   -- platform rule
		        OR pr.team_id IN (SELECT id FROM team_chain)        -- team rule (cascading down)
		   )
		 ORDER BY
		    pr.priority DESC,
		    CASE
		        WHEN pr.project_id IS NOT NULL THEN 2
		        WHEN pr.team_id    IS NOT NULL THEN 1
		        ELSE 0
		    END DESC,
		    tc.distance ASC NULLS LAST,
		    pr.created_at ASC,
		    pr.id ASC`
	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("storage: list enabled policies for project: %w", err)
	}
	defer rows.Close()
	return collectPolicies(rows)
}

// ListForProject — own rows (any enabled state) + inherited
// platform (enabled only) + inherited team (enabled only). The C4
// filter on inherited rows lives in the WHERE clause so the handler
// doesn't re-filter. JOINs populate WorkflowName + TeamName.
func (r *Policies) ListForProject(ctx context.Context, projectID uuid.UUID) ([]*PolicyRule, error) {
	const q = `
		WITH RECURSIVE team_chain(id, distance) AS (
		    SELECT p.team_id, 0
		      FROM projects p
		     WHERE p.id = $1 AND p.team_id IS NOT NULL
		    UNION ALL
		    SELECT t.parent_team_id, tc.distance + 1
		      FROM teams t
		      JOIN team_chain tc ON t.id = tc.id
		     WHERE t.parent_team_id IS NOT NULL
		)
		SELECT pr.id, pr.name, pr.selector, pr.workflow_id, pr.priority, pr.enabled, pr.is_system,
		       pr.direct_reveal_allowed, pr.requires_mfa, pr.reveal_ttl_seconds,
		       pr.project_id, pr.team_id,
		       pr.created_at, pr.updated_at,
		       COALESCE(wd.name, '') AS workflow_name,
		       COALESCE(t.name, '')  AS team_name
		  FROM policy_rules pr
		  LEFT JOIN workflow_definitions wd ON wd.id = pr.workflow_id
		  LEFT JOIN teams t ON t.id = pr.team_id
		  LEFT JOIN team_chain tc ON tc.id = pr.team_id
		 WHERE (
		       pr.project_id = $1                                    -- own (any enabled state)
		       OR (
		           pr.enabled = TRUE                                  -- C4: inherited enabled-only
		           AND (
		               (pr.project_id IS NULL AND pr.team_id IS NULL) -- platform inherited
		               OR pr.team_id IN (SELECT id FROM team_chain)   -- team inherited (subtree-down)
		           )
		       )
		   )
		 ORDER BY pr.priority DESC,
		          CASE WHEN pr.project_id IS NOT NULL THEN 2
		               WHEN pr.team_id    IS NOT NULL THEN 1
		               ELSE 0 END DESC,
		          tc.distance ASC NULLS LAST,
		          pr.created_at ASC,
		          pr.id ASC`
	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("storage: list policies for project: %w", err)
	}
	defer rows.Close()
	return collectPoliciesWithNames(rows)
}

// ListForTeam — own team rows (any enabled state) + ancestor-team
// inherited (enabled only) + platform inherited (enabled only). Does
// NOT include project-scoped rules under the team subtree (per §1
// Q3 lock — team page is the team's authoring surface, not a
// project-aggregate report). JOIN populates WorkflowName; TeamName
// stays empty for own rows (URL teamID is implicit) and ancestor
// rows surface the ancestor team's name.
func (r *Policies) ListForTeam(ctx context.Context, teamID uuid.UUID) ([]*PolicyRule, error) {
	const q = `
		WITH RECURSIVE team_chain(id, distance) AS (
		    SELECT $1::uuid, 0
		    UNION ALL
		    SELECT t.parent_team_id, tc.distance + 1
		      FROM teams t
		      JOIN team_chain tc ON t.id = tc.id
		     WHERE t.parent_team_id IS NOT NULL
		)
		SELECT pr.id, pr.name, pr.selector, pr.workflow_id, pr.priority, pr.enabled, pr.is_system,
		       pr.direct_reveal_allowed, pr.requires_mfa, pr.reveal_ttl_seconds,
		       pr.project_id, pr.team_id,
		       pr.created_at, pr.updated_at,
		       COALESCE(wd.name, '') AS workflow_name,
		       COALESCE(t.name, '')  AS team_name
		  FROM policy_rules pr
		  LEFT JOIN workflow_definitions wd ON wd.id = pr.workflow_id
		  LEFT JOIN teams t ON t.id = pr.team_id
		  LEFT JOIN team_chain tc ON tc.id = pr.team_id
		 WHERE (
		       pr.team_id = $1                                        -- own (any enabled state)
		       OR (
		           pr.enabled = TRUE
		           AND (
		               (pr.project_id IS NULL AND pr.team_id IS NULL) -- platform inherited
		               OR pr.team_id IN (SELECT id FROM team_chain WHERE id <> $1)
		               -- ancestor-team inherited (excludes the URL team itself)
		           )
		       )
		   )
		 ORDER BY pr.priority DESC,
		          CASE WHEN pr.project_id IS NOT NULL THEN 2
		               WHEN pr.team_id    IS NOT NULL THEN 1
		               ELSE 0 END DESC,
		          tc.distance ASC NULLS LAST,
		          pr.created_at ASC,
		          pr.id ASC`
	rows, err := r.pool.Query(ctx, q, teamID)
	if err != nil {
		return nil, fmt.Errorf("storage: list policies for team: %w", err)
	}
	defer rows.Close()
	return collectPoliciesWithNames(rows)
}

func (r *Policies) Update(ctx context.Context, p *PolicyRule) error {
	if p.Selector == nil {
		p.Selector = map[string]any{}
	}
	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return fmt.Errorf("storage: marshal policy selector: %w", err)
	}
	if p.RevealTTLSeconds == 0 {
		p.RevealTTLSeconds = 60
	}
	// Anchor immutability — load the existing row to compare. A flip
	// of project_id ↔ team_id, or NULL ↔ set on either, is rejected.
	// Mirrors the pattern EPIC R established for project_id (which is
	// also de-facto immutable — the service-layer UpdateForScopedAuthor
	// path doesn't expose it). With the team_id addition the immutability
	// check has to be explicit since admin paths COULD attempt it.
	existing, getErr := r.Get(ctx, p.ID)
	if getErr != nil {
		return getErr
	}
	if !uuidPtrEqual(existing.ProjectID, p.ProjectID) || !uuidPtrEqual(existing.TeamID, p.TeamID) {
		return ErrAnchorImmutable
	}
	const q = `
		UPDATE policy_rules
		SET name = $2, selector = $3, workflow_id = $4, priority = $5, enabled = $6,
		    direct_reveal_allowed = $7, requires_mfa = $8, reveal_ttl_seconds = $9
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q,
		p.ID, p.Name, selector, p.WorkflowID, p.Priority, p.Enabled,
		p.DirectRevealAllowed, p.RequiresMFA, p.RevealTTLSeconds,
	)
	if err != nil {
		return fmt.Errorf("storage: update policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Policies) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM policy_rules WHERE id = $1 AND is_system = false`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("storage: delete policy: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	p, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if p.IsSystem {
		return ErrSystemRow
	}
	return ErrNotFound
}

const policySelect = `
	SELECT id, name, selector, workflow_id, priority, enabled, is_system,
	       direct_reveal_allowed, requires_mfa, reveal_ttl_seconds,
	       project_id, team_id,
	       created_at, updated_at
	FROM policy_rules`

func scanPolicy(row interface {
	Scan(dest ...any) error
}) (*PolicyRule, error) {
	var (
		p           PolicyRule
		selectorRaw []byte
	)
	err := row.Scan(
		&p.ID, &p.Name, &selectorRaw, &p.WorkflowID, &p.Priority, &p.Enabled, &p.IsSystem,
		&p.DirectRevealAllowed, &p.RequiresMFA, &p.RevealTTLSeconds,
		&p.ProjectID, &p.TeamID,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan policy: %w", err)
	}
	if len(selectorRaw) > 0 {
		if err := json.Unmarshal(selectorRaw, &p.Selector); err != nil {
			return nil, fmt.Errorf("storage: unmarshal policy selector: %w", err)
		}
	}
	return &p, nil
}

// scanPolicyWithNames extends scanPolicy with the trailing
// workflow_name + team_name columns from the envelope JOINs in
// ListForProject + ListForTeam.
func scanPolicyWithNames(row interface {
	Scan(dest ...any) error
}) (*PolicyRule, error) {
	var (
		p           PolicyRule
		selectorRaw []byte
	)
	err := row.Scan(
		&p.ID, &p.Name, &selectorRaw, &p.WorkflowID, &p.Priority, &p.Enabled, &p.IsSystem,
		&p.DirectRevealAllowed, &p.RequiresMFA, &p.RevealTTLSeconds,
		&p.ProjectID, &p.TeamID,
		&p.CreatedAt, &p.UpdatedAt,
		&p.WorkflowName, &p.TeamName,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan policy with names: %w", err)
	}
	if len(selectorRaw) > 0 {
		if err := json.Unmarshal(selectorRaw, &p.Selector); err != nil {
			return nil, fmt.Errorf("storage: unmarshal policy selector: %w", err)
		}
	}
	return &p, nil
}

func collectPolicies(rows pgx.Rows) ([]*PolicyRule, error) {
	var out []*PolicyRule
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func collectPoliciesWithNames(rows pgx.Rows) ([]*PolicyRule, error) {
	var out []*PolicyRule
	for rows.Next() {
		p, err := scanPolicyWithNames(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func uuidPtrEqual(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
