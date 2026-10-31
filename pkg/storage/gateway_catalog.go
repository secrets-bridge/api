package storage

// Console catalog read, AppProject to team mapping and the lookups the
// bind rules need (ADR 0002 S4, api#308; gateway
// docs/design/discovery-contract.md section 8).
//
// The catalog filter for a team-scoped caller is part of the query,
// before paging, so a page never has holes and nothing about another
// team's targets reaches the caller (C4).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Mapping errors.
var (
	ErrGatewayUnknownAppProject = errors.New("storage: AppProject is not in the latest discovery upload")
	ErrGatewayTeamNotFound      = errors.New("storage: team not found")
)

// CatalogFilter is a validated A1 query. Teams nil means a global
// caller; otherwise the caller sees discovered targets on approved
// connectors whose AppProject maps to one of Teams (the expanded
// subtrees), and team_ids lists only those teams.
type CatalogFilter struct {
	Teams         []uuid.UUID
	GatewayID     *uuid.UUID
	ConnectorUUID *uuid.UUID
	AppProject    string
	Namespace     string
	Q             string
	Source        string
	Status        string
	Bound         *bool
	New           *bool
	TeamID        *uuid.UUID
	// ProjectID keeps the targets this project can bind: every static
	// target, and a discovered target only when a team its AppProject maps
	// to covers the project's team (bind rule 5). It matches nothing for a
	// project outside a team-scoped caller's teams.
	ProjectID *uuid.UUID
	Limit     int
	// After is the keyset of the last item of the previous page.
	After *CatalogKey
	Now   time.Time
}

// CatalogKey is the sort key: Gateway, connector, AppProject, namespace,
// name, target id.
type CatalogKey struct {
	GatewayID   uuid.UUID `json:"g"`
	ConnectorID uuid.UUID `json:"c"`
	AppProject  string    `json:"p"`
	Namespace   string    `json:"n"`
	Name        string    `json:"a"`
	TargetID    string    `json:"t"`
}

// CatalogItem is one A1 item.
type CatalogItem struct {
	Key          CatalogKey
	ConnectorID  string // connector name, connector_id on the wire
	Source       string
	Status       string
	FirstSeenAt  time.Time
	LastSeenAt   *time.Time
	BindingCount int
	TeamIDs      []uuid.UUID
	LookAlike    bool
}

// catalogSQL is the catalog read. $1 global, $2 caller teams, then the
// filters, the keyset and the limit. Static targets come from the
// advertised_targets JSONB, global callers only, with an empty
// AppProject so they sort first. first_seen_at of a static target is
// its connector's creation time: the JSONB keeps no per-target time.
const catalogSQL = `
WITH visible AS (
	SELECT dt.gateway_id, c.id AS connector_uuid, c.name AS connector_name, dt.target_id, 'discovered' AS source,
	       dt.status, dt.app_project, dt.namespace, dt.name, dt.first_seen_at, dt.last_seen_at::timestamptz AS last_seen_at,
	       ARRAY(SELECT pt.team_id FROM gateway_connector_project_teams pt
	             WHERE pt.connector_id = c.id AND pt.app_project = dt.app_project
	               AND ($1::boolean OR pt.team_id = ANY($2::uuid[])) ORDER BY pt.team_id)::text[] AS team_ids
	FROM gateway_discovered_targets dt JOIN gateway_connectors c ON c.id = dt.connector_id
	WHERE $1::boolean OR (c.status = 'approved' AND EXISTS (
		SELECT 1 FROM gateway_connector_project_teams vt
		WHERE vt.connector_id = c.id AND vt.app_project = dt.app_project AND vt.team_id = ANY($2::uuid[])))
	UNION ALL
	SELECT c.gateway_id, c.id, c.name, t->>'target_id', 'static',
	       CASE WHEN t->>'identity_status' = 'identity_changed' THEN 'identity_changed'
	            WHEN (t->>'stale')::boolean THEN 'stale' ELSE 'present' END,
	       '', COALESCE(t->>'namespace', ''), COALESCE(t->>'name', ''), c.created_at, NULL::timestamptz, '{}'::text[]
	FROM gateway_connectors c, jsonb_array_elements(c.advertised_targets) t
	WHERE $1::boolean AND c.kind = 'argocd'
), names AS (
	SELECT gateway_id, name, count(DISTINCT app_project || '/' || namespace) AS places
	FROM visible WHERE name <> '' GROUP BY gateway_id, name
), items AS (
	SELECT v.*, COALESCE(n.places, 1) > 1 AS look_alike,
	       (SELECT count(*) FROM gateway_connector_bindings b
	        WHERE b.argocd_connector_id = v.connector_uuid AND b.argocd_target_id = v.target_id AND b.deleted_at IS NULL) AS binding_count
	FROM visible v LEFT JOIN names n ON n.gateway_id = v.gateway_id AND n.name = v.name
)
SELECT gateway_id, connector_uuid, connector_name, target_id, source, status, app_project, namespace, name,
       first_seen_at, last_seen_at, team_ids, look_alike, binding_count
FROM items
WHERE ($3::uuid IS NULL OR gateway_id = $3)
  AND ($4::uuid IS NULL OR connector_uuid = $4)
  AND ($5 = '' OR app_project = $5)
  AND ($6 = '' OR namespace = $6)
  AND ($7 = '' OR strpos(name, $7) > 0)
  AND ($8 = '' OR source = $8)
  AND ($9 = '' OR status = $9)
  AND ($10::boolean IS NULL OR (binding_count > 0) = $10)
  AND ($11::boolean IS NULL OR (first_seen_at > $12::timestamptz - interval '24 hours') = $11)
  AND ($13::text IS NULL OR $13::text = ANY(team_ids))
  AND ($22::uuid IS NULL OR EXISTS (
       SELECT 1 FROM projects p
       WHERE p.id = $22 AND ($1::boolean OR p.team_id = ANY($2::uuid[]))
         AND (source = 'static' OR EXISTS (
              SELECT 1 FROM gateway_connector_project_teams pt
              WHERE pt.connector_id = connector_uuid AND pt.app_project = items.app_project
                AND team_covers(pt.team_id, p.team_id)))))
  AND ($14::boolean IS NOT TRUE OR
       (gateway_id, connector_uuid, app_project COLLATE "C", namespace COLLATE "C", name COLLATE "C", target_id COLLATE "C")
       > ($15::uuid, $16::uuid, $17::text COLLATE "C", $18::text COLLATE "C", $19::text COLLATE "C", $20::text COLLATE "C"))
ORDER BY gateway_id, connector_uuid, app_project COLLATE "C", namespace COLLATE "C", name COLLATE "C", target_id COLLATE "C"
LIMIT $21`

// ListCatalog returns up to f.Limit+1 items (one more than a page, so
// the caller knows whether a next page exists).
func (r *Gateways) ListCatalog(ctx context.Context, f CatalogFilter) ([]CatalogItem, error) {
	global := f.Teams == nil
	teams := uuidStrings(f.Teams)
	after := f.After != nil
	var a CatalogKey
	if after {
		a = *f.After
	}
	rows, err := r.pool.Query(ctx, catalogSQL, global, teams,
		f.GatewayID, f.ConnectorUUID, f.AppProject, f.Namespace, f.Q, f.Source, f.Status, f.Bound, f.New, f.Now, f.TeamID,
		after, a.GatewayID, a.ConnectorID, a.AppProject, a.Namespace, a.Name, a.TargetID, f.Limit+1, f.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("storage: catalog read: %w", err)
	}
	defer rows.Close()
	var out []CatalogItem
	for rows.Next() {
		var it CatalogItem
		var teamIDs []string
		if err := rows.Scan(&it.Key.GatewayID, &it.Key.ConnectorID, &it.ConnectorID, &it.Key.TargetID, &it.Source, &it.Status,
			&it.Key.AppProject, &it.Key.Namespace, &it.Key.Name, &it.FirstSeenAt, &it.LastSeenAt, &teamIDs,
			&it.LookAlike, &it.BindingCount); err != nil {
			return nil, fmt.Errorf("storage: scan catalog item: %w", err)
		}
		if it.TeamIDs, err = parseUUIDs(teamIDs); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// BindingFilter is a validated bindings read. All is a global caller;
// otherwise the caller gets the discovered bindings of the projects of
// Teams (the expanded subtrees).
type BindingFilter struct {
	All       bool
	Teams     []uuid.UUID
	GatewayID *uuid.UUID
	ProjectID *uuid.UUID
	Suspended *bool
	Limit     int
	// After is the keyset of the last item of the previous page.
	After *BindingKey
}

// BindingKey is the sort key: newest first, then binding id.
type BindingKey struct {
	CreatedAt time.Time `json:"c"`
	ID        uuid.UUID `json:"i"`
}

// BindingItem is a binding with its target, as far as the caller can
// see the target. AppProject, Namespace and Name are empty when it
// can't: a binding stays listed for its project's team after a mapping
// change or a scope change hides the target, so the team finds out why
// it stopped. A team-scoped delete of such a binding answers 404.
type BindingItem struct {
	Binding    *GatewayBinding
	AppProject string
	Namespace  string
	Name       string
}

// bindingListSQL is the bindings read. $1 all, $2 caller teams, then
// the filters, the keyset and the limit. The target join applies the
// catalog's visibility rule (C4), so it never shows a team a target the
// catalog hides from it.
const bindingListSQL = `SELECT ` + gatewayBindingColumns + `,
	COALESCE(v.app_project, ''), COALESCE(v.namespace, ''), COALESCE(v.name, '')
FROM gateway_connector_bindings b
JOIN environments e ON e.id = b.environment_id
JOIN projects p ON p.id = e.project_id
LEFT JOIN LATERAL (
	SELECT dt.app_project, dt.namespace, dt.name
	FROM gateway_discovered_targets dt JOIN gateway_connectors c ON c.id = dt.connector_id
	WHERE dt.connector_id = b.argocd_connector_id AND dt.target_id = b.argocd_target_id
	  AND ($1::boolean OR (c.status = 'approved' AND EXISTS (
		SELECT 1 FROM gateway_connector_project_teams vt
		WHERE vt.connector_id = c.id AND vt.app_project = dt.app_project AND vt.team_id = ANY($2::uuid[]))))
) v ON true
WHERE b.deleted_at IS NULL
  AND ($1::boolean OR (b.target_source = 'discovered' AND p.team_id = ANY($2::uuid[])))
  AND ($3::uuid IS NULL OR b.gateway_id = $3)
  AND ($4::uuid IS NULL OR e.project_id = $4)
  AND ($5::boolean IS NULL OR (b.suspended_reason IS NOT NULL OR ` + bindingTargetIdentityChangedSQL + `) = $5)
  AND ($6::boolean IS NOT TRUE OR (b.created_at, b.id) < ($7::timestamptz, $8::uuid))
ORDER BY b.created_at DESC, b.id DESC
LIMIT $9`

// ListBindingItems returns up to f.Limit+1 bindings (one more than a
// page, so the caller knows whether a next page exists).
func (r *Gateways) ListBindingItems(ctx context.Context, f BindingFilter) ([]BindingItem, error) {
	after := f.After != nil
	var a BindingKey
	if after {
		a = *f.After
	}
	rows, err := r.pool.Query(ctx, bindingListSQL, f.All, uuidStrings(f.Teams),
		f.GatewayID, f.ProjectID, f.Suspended, after, a.CreatedAt, a.ID, f.Limit+1)
	if err != nil {
		return nil, fmt.Errorf("storage: list binding items: %w", err)
	}
	defer rows.Close()
	var out []BindingItem
	for rows.Next() {
		var it BindingItem
		if it.Binding, err = scanGatewayBinding(rows, &it.AppProject, &it.Namespace, &it.Name); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// DiscoveredTarget is one stored discovered target with the teams its
// AppProject maps to.
type DiscoveredTarget struct {
	ConnectorID uuid.UUID
	TargetID    string
	AppProject  string
	Namespace   string
	Name        string
	Status      string
	Teams       []uuid.UUID
}

// GetDiscoveredTarget returns a connector's discovered target, or
// ErrNotFound.
func (r *Gateways) GetDiscoveredTarget(ctx context.Context, connectorID uuid.UUID, targetID string) (*DiscoveredTarget, error) {
	return getDiscoveredTarget(ctx, r.pool, connectorID, targetID)
}

func getDiscoveredTarget(ctx context.Context, q querier, connectorID uuid.UUID, targetID string) (*DiscoveredTarget, error) {
	var t DiscoveredTarget
	var teams []string
	err := q.QueryRow(ctx, `
		SELECT dt.connector_id, dt.target_id, dt.app_project, dt.namespace, dt.name, dt.status,
		       ARRAY(SELECT pt.team_id FROM gateway_connector_project_teams pt
		             WHERE pt.connector_id = dt.connector_id AND pt.app_project = dt.app_project ORDER BY pt.team_id)::text[]
		FROM gateway_discovered_targets dt WHERE dt.connector_id = $1 AND dt.target_id = $2`, connectorID, targetID).
		Scan(&t.ConnectorID, &t.TargetID, &t.AppProject, &t.Namespace, &t.Name, &t.Status, &teams)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: discovered target: %w", err)
	}
	if t.Teams, err = parseUUIDs(teams); err != nil {
		return nil, err
	}
	return &t, nil
}

func parseUUIDs(ss []string) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0, len(ss))
	for _, s := range ss {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("storage: parse uuid: %w", err)
		}
		out = append(out, id)
	}
	return out, nil
}

// EnvironmentBindInfo is what the bind rules read about an environment.
type EnvironmentBindInfo struct {
	ProjectID     uuid.UUID
	ProjectTeamID *uuid.UUID
	Type          string
	Kind          string
}

// EnvironmentBindInfo returns an environment's project, the project's
// team, and the environment type and kind.
func (r *Gateways) EnvironmentBindInfo(ctx context.Context, envID uuid.UUID) (*EnvironmentBindInfo, error) {
	var e EnvironmentBindInfo
	err := r.pool.QueryRow(ctx, `
		SELECT e.project_id, p.team_id, e.type, e.kind FROM environments e JOIN projects p ON p.id = e.project_id
		WHERE e.id = $1`, envID).Scan(&e.ProjectID, &e.ProjectTeamID, &e.Type, &e.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: environment bind info: %w", err)
	}
	return &e, nil
}

// TeamCoveredByAny reports whether team is in the subtree of one of
// roots.
func (r *Gateways) TeamCoveredByAny(ctx context.Context, roots []uuid.UUID, team uuid.UUID) (bool, error) {
	var ok bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM unnest($1::uuid[]) root WHERE team_covers(root, $2))`,
		uuidStrings(roots), team).Scan(&ok); err != nil {
		return false, fmt.Errorf("storage: team coverage: %w", err)
	}
	return ok, nil
}

// GatewayProjectTeams is a connector's AppProject to team mapping.
type GatewayProjectTeams struct {
	Mappings        map[string][]uuid.UUID // AppProject to sorted team ids
	AllowedProjects []string               // from the latest upload, nil when none
	Complete        bool
}

// GetProjectTeams returns the mapping of a Gateway's connector.
func (r *Gateways) GetProjectTeams(ctx context.Context, gatewayID, connectorID uuid.UUID) (*GatewayProjectTeams, error) {
	return getProjectTeams(ctx, r.pool, gatewayID, connectorID)
}

func getProjectTeams(ctx context.Context, q querier, gatewayID, connectorID uuid.UUID) (*GatewayProjectTeams, error) {
	var allowed []byte
	err := q.QueryRow(ctx, `SELECT discovery_allowed_projects FROM gateway_connectors WHERE id = $1 AND gateway_id = $2 AND kind = 'argocd'`,
		connectorID, gatewayID).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: project teams connector: %w", err)
	}
	out := &GatewayProjectTeams{Mappings: map[string][]uuid.UUID{}}
	if allowed != nil {
		if err := json.Unmarshal(allowed, &out.AllowedProjects); err != nil {
			return nil, fmt.Errorf("storage: allowed projects: %w", err)
		}
	}
	rows, err := q.Query(ctx, `SELECT app_project, team_id FROM gateway_connector_project_teams
		WHERE connector_id = $1 ORDER BY app_project, team_id`, connectorID)
	if err != nil {
		return nil, fmt.Errorf("storage: project teams: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		var team uuid.UUID
		if err := rows.Scan(&p, &team); err != nil {
			return nil, fmt.Errorf("storage: scan project team: %w", err)
		}
		out.Mappings[p] = append(out.Mappings[p], team)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out.Complete = allowed != nil
	for _, p := range out.AllowedProjects {
		if len(out.Mappings[p]) == 0 {
			out.Complete = false
		}
	}
	return out, nil
}

// GatewayMappingOutcome is what PutProjectTeams changed.
type GatewayMappingOutcome struct {
	Before, After     *GatewayProjectTeams
	BindingsSuspended int
	Cancelled         []*ObservationTask
}

// PutProjectTeams replaces a connector's mapping (A2). Every AppProject
// must be in the latest upload (ErrGatewayUnknownAppProject) and every
// team must exist (ErrGatewayTeamNotFound). On an approved connector the
// result must map every allowed AppProject
// (ErrGatewayProjectMappingIncomplete). Bindings the new mapping no
// longer covers are suspended with mapping_removed and their open tasks
// cancelled with binding_suspended, in the same transaction.
func (r *Gateways) PutProjectTeams(ctx context.Context, gatewayID, connectorID uuid.UUID, mappings map[string][]uuid.UUID, by string, at time.Time) (*GatewayMappingOutcome, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin project teams: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `SELECT id FROM gateways WHERE id = $1 FOR UPDATE`, gatewayID).Scan(new(uuid.UUID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: lock gateway: %w", err)
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM gateway_connectors WHERE id = $1 AND gateway_id = $2 AND kind = 'argocd' FOR UPDATE`,
		connectorID, gatewayID).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: lock connector: %w", err)
	}
	before, err := getProjectTeams(ctx, tx, gatewayID, connectorID)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, p := range before.AllowedProjects {
		allowed[p] = true
	}
	var teams []string
	for p, ts := range mappings {
		if !allowed[p] {
			return nil, ErrGatewayUnknownAppProject
		}
		for _, t := range ts {
			teams = append(teams, t.String())
		}
	}
	if len(teams) > 0 {
		var found int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT id) FROM teams WHERE id = ANY($1::uuid[])`, teams).Scan(&found); err != nil {
			return nil, fmt.Errorf("storage: teams exist: %w", err)
		}
		distinct := map[string]bool{}
		for _, t := range teams {
			distinct[t] = true
		}
		if found != len(distinct) {
			return nil, ErrGatewayTeamNotFound
		}
	}
	if status == GatewayConnectorApproved {
		for _, p := range before.AllowedProjects {
			if len(mappings[p]) == 0 {
				return nil, ErrGatewayProjectMappingIncomplete
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM gateway_connector_project_teams WHERE connector_id = $1`, connectorID); err != nil {
		return nil, fmt.Errorf("storage: clear project teams: %w", err)
	}
	projects := make([]string, 0, len(mappings))
	for p := range mappings {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for _, p := range projects {
		for _, t := range mappings[p] {
			if _, err := tx.Exec(ctx, `INSERT INTO gateway_connector_project_teams (connector_id, app_project, team_id, approved_by, approved_at)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, connectorID, p, t, by, at); err != nil {
				return nil, fmt.Errorf("storage: insert project team: %w", err)
			}
		}
	}
	out := &GatewayMappingOutcome{Before: before}
	if out.BindingsSuspended, out.Cancelled, err = suspendUncoveredBindings(ctx, tx, connectorID, nil, at); err != nil {
		return nil, err
	}
	if out.After, err = getProjectTeams(ctx, tx, gatewayID, connectorID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit project teams: %w", err)
	}
	return out, nil
}

// TargetBound reports whether an Argo CD target has a binding that is
// not deleted.
func (r *Gateways) TargetBound(ctx context.Context, connectorID uuid.UUID, targetID string) (bool, error) {
	n, err := countTargetBindings(ctx, r.pool, connectorID, targetID)
	return n > 0, err
}
