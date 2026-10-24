package storage

// Argo CD discovery, heartbeat side (ADR 0002 S4, api#308; gateway
// docs/design/discovery-contract.md sections 2.4 to 2.6 and 8.3).
// Migration 0050.
//
// A contract 2 heartbeat reports a scope digest per Argo CD connector.
// In the heartbeat transaction, which already holds the Gateway row FOR
// UPDATE, each reported connector row is locked FOR UPDATE, so every
// decision below is single across api replicas:
//
//   - live replicas that report different digests: the connector carries
//     status_reason scope_mismatch_between_replicas, its leased tasks go
//     back to queued, and no lease is granted until they agree;
//   - an approved connector whose agreed digest differs from the approved
//     one (or that has none yet with discovery on) goes back to
//     advertised with status_reason scope_changed, its bindings are
//     suspended with scope_changed and its leased tasks go back to queued;
//   - an approved connector with no approved digest and discovery off
//     adopts the first digest, audited by the service;
//   - a discovery lease is granted to the calling replica when the
//     contract conditions hold (section 2.5).
//
// Digests are one-way SHA-256 values; nothing here is a URL or a name.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Connector status reasons (gateway_connectors.status_reason).
const (
	GatewayConnectorReasonScopeChanged  = "scope_changed"
	GatewayConnectorReasonScopeMismatch = "scope_mismatch_between_replicas"
	GatewayConnectorReasonSnapshotStale = "snapshot_stale"
	// GatewayConnectorReasonOverPrivileged latches a connector a replica
	// reported over_privileged (or that a replica reporting itself
	// over_privileged serves) until a platform admin re-approves it after
	// a passing probe (ADR 0002 C2 and section 6).
	GatewayConnectorReasonOverPrivileged = "over_privileged"
)

// Binding suspended reasons (gateway_connector_bindings.suspended_reason).
const (
	GatewayBindingSuspendedTargetMissing   = "target_missing"
	GatewayBindingSuspendedIdentityChanged = "identity_changed"
	GatewayBindingSuspendedMappingRemoved  = "mapping_removed"
	GatewayBindingSuspendedScopeChanged    = "scope_changed"
)

// Binding target sources (gateway_connector_bindings.target_source).
const (
	GatewayTargetSourceStatic     = "static"
	GatewayTargetSourceDiscovered = "discovered"
)

// Discovery lease bounds (contract sections 2.3 and 2.5, decision E-3).
const (
	// GatewayDiscoveryIntervalFloor is the C9 floor between two grants
	// for one connector, enforced on the control plane too.
	GatewayDiscoveryIntervalFloor = 60 * time.Second
	// GatewayDiscoveryLeaseTTLDefault, Min and Max bound the CP setting.
	GatewayDiscoveryLeaseTTLDefault = 300 * time.Second
	GatewayDiscoveryLeaseTTLMin     = 60 * time.Second
	GatewayDiscoveryLeaseTTLMax     = 900 * time.Second
)

// Discovery errors.
var (
	// ErrGatewayScopeDigestChanged: the approve body's digest is not the
	// one every live replica reports now (A3, 409 scope_digest_changed).
	ErrGatewayScopeDigestChanged = errors.New("storage: scope digest is not the one the replicas report")
	// ErrGatewayProjectMappingIncomplete: an allowed AppProject has no
	// team (A2, A3, 409 project_mapping_incomplete).
	ErrGatewayProjectMappingIncomplete = errors.New("storage: an allowed AppProject has no team")
	// ErrGatewayConnectorOverPrivileged: a live replica still reports the
	// connector, or itself, over_privileged (A3, 409
	// connector_over_privileged).
	ErrGatewayConnectorOverPrivileged = errors.New("storage: a live replica reports the connector over_privileged")
)

// GatewayDiscoveryLease is one lease granted by a heartbeat.
type GatewayDiscoveryLease struct {
	ConnectorID   uuid.UUID
	ConnectorName string
	LeaseID       uuid.UUID
	Generation    int64
	ExpiresAt     time.Time
}

// Scope events a heartbeat can produce.
const (
	GatewayScopeEventChanged  = "changed"
	GatewayScopeEventAdopted  = "adopted"
	GatewayScopeEventMismatch = "mismatch"
	// GatewayScopeEventOverPrivileged: an approved connector latched back
	// to advertised with status_reason over_privileged.
	GatewayScopeEventOverPrivileged = "over_privileged"
)

// GatewayScopeEvent is a scope state change one heartbeat caused. Old is
// "" when the connector had no approved digest.
type GatewayScopeEvent struct {
	ConnectorID       uuid.UUID
	Event             string
	Old, New          string
	BindingsSuspended int
	TasksRequeued     int
	// AppProjectsBefore is the AppProject count of the latest accepted
	// upload, nil when there is none.
	AppProjectsBefore *int
}

// GatewaySnapshotGeneration is a connector with a stored snapshot.
type GatewaySnapshotGeneration struct {
	ConnectorName string
	Generation    int64
}

// GatewayBoundTargets is the bound target list of one connector.
type GatewayBoundTargets struct {
	ConnectorName string   `json:"connector_id"`
	TargetIDs     []string `json:"target_ids"`
}

// GatewayDiscoveryHeartbeat is the contract 2 part of a heartbeat's
// outcome.
type GatewayDiscoveryHeartbeat struct {
	Leases              []GatewayDiscoveryLease
	ScopeEvents         []GatewayScopeEvent
	SnapshotGenerations []GatewaySnapshotGeneration
	BoundTargets        []GatewayBoundTargets
	BoundTargetsVersion string
}

// gatewayReplicaScopeSQL selects, for every live replica of Gateway $1
// seen after $2 that reports connector $3: its digest ("" when it sends
// none), discovery_enabled, and whether the replica or the connector on
// it is over_privileged.
const gatewayReplicaScopeSQL = `
	SELECT COALESCE(ch->>'scope_digest', ''), COALESCE((ch->>'discovery_enabled')::boolean, false),
	       rp.status = 'over_privileged' OR ch->>'status' = 'over_privileged'
	FROM gateway_replicas rp, jsonb_array_elements(rp.connector_health) ch
	WHERE rp.gateway_id = $1 AND rp.last_seen_at > $2 AND ch->>'connector_id' = $3`

// liveScope is what the live replicas report for one connector.
type liveScope struct {
	digests          []string // distinct, sorted, non-empty
	missing          int      // live replicas that report the connector with no digest
	discoveryEnabled bool     // any replica reports discovery on
	overPrivileged   bool     // any replica reports it, or itself, over_privileged
}

// agreed is the digest every live replica reports. A live replica that
// reports the connector without a digest (a contract 1 shaped
// heartbeat) is not in agreement (review on #317, item 1).
func (l liveScope) agreed() (string, bool) {
	if len(l.digests) == 1 && l.missing == 0 {
		return l.digests[0], true
	}
	return "", false
}

// single is the one digest the replicas that send one report, ignoring
// replicas that send none yet. Scope change detection and adoption use
// it: a replica restarting sends one contract 1 shaped heartbeat, and
// that must not flap the connector. Leases and approvals use agreed.
func (l liveScope) single() (string, bool) {
	if len(l.digests) == 1 {
		return l.digests[0], true
	}
	return "", false
}

func readLiveScope(ctx context.Context, q querier, gatewayID uuid.UUID, connector string, seenSince time.Time) (liveScope, error) {
	rows, err := q.Query(ctx, gatewayReplicaScopeSQL, gatewayID, seenSince, connector)
	if err != nil {
		return liveScope{}, fmt.Errorf("storage: read replica scope digests: %w", err)
	}
	defer rows.Close()
	var out liveScope
	seen := map[string]bool{}
	for rows.Next() {
		var d string
		var on, op bool
		if err := rows.Scan(&d, &on, &op); err != nil {
			return liveScope{}, fmt.Errorf("storage: scan replica scope digest: %w", err)
		}
		out.discoveryEnabled = out.discoveryEnabled || on
		out.overPrivileged = out.overPrivileged || op
		switch {
		case d == "":
			out.missing++
		case !seen[d]:
			seen[d] = true
			out.digests = append(out.digests, d)
		}
	}
	sort.Strings(out.digests)
	return out, rows.Err()
}

// latchOverPrivileged takes every approved Argo CD connector a heartbeat
// reports over_privileged (all of them when the replica itself is
// over_privileged) back to advertised with status_reason
// over_privileged, and moves its leased tasks back to queued. It runs
// for every heartbeat, contract 1 or 2. The pause no longer lifts on the
// replica's next healthy heartbeat: a platform admin re-approves.
func latchOverPrivileged(ctx context.Context, tx pgx.Tx, hb GatewayHeartbeat, at time.Time) ([]GatewayScopeEvent, error) {
	// names nil with a replica-level over_privileged means every Argo CD
	// connector of the Gateway.
	var names []string
	if hb.Status != "over_privileged" {
		for _, ch := range hb.Connectors {
			if ch.Kind == "argocd" && ch.Status == "over_privileged" {
				names = append(names, ch.ConnectorID)
			}
		}
		if len(names) == 0 {
			return nil, nil
		}
	}
	rows, err := tx.Query(ctx, `
		UPDATE gateway_connectors SET status = 'advertised', status_reason = 'over_privileged',
			approved_by = NULL, approved_at = NULL,
			discovery_lease_id = NULL, discovery_lease_replica_id = NULL, discovery_lease_generation = NULL,
			discovery_lease_expires_at = NULL
		WHERE gateway_id = $1 AND kind = 'argocd' AND status = 'approved'
		  AND ($2::text[] IS NULL OR name = ANY($2::text[]))
		RETURNING id`, hb.GatewayID, names)
	if err != nil {
		return nil, fmt.Errorf("storage: latch over_privileged: %w", err)
	}
	ids, err := collectIDs(rows)
	if err != nil {
		return nil, err
	}
	var out []GatewayScopeEvent
	for _, id := range ids {
		n, err := requeueLeasedForConnector(ctx, tx, id, at)
		if err != nil {
			return nil, err
		}
		out = append(out, GatewayScopeEvent{ConnectorID: id, Event: GatewayScopeEventOverPrivileged, TasksRequeued: n})
	}
	return out, nil
}

func collectIDs(rows pgx.Rows) ([]uuid.UUID, error) {
	defer rows.Close()
	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("storage: scan id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// requeueLeasedForConnector moves the leased tasks of every binding on
// an Argo CD connector back to queued, closing their attempts as
// cancelled, like requeueLeasedForGateway.
func requeueLeasedForConnector(ctx context.Context, tx pgx.Tx, connectorID uuid.UUID, at time.Time) (int, error) {
	const leased = `t.state = 'leased' AND t.binding_id IN (
		SELECT b.id FROM gateway_connector_bindings b WHERE b.argocd_connector_id = $1)`
	if _, err := tx.Exec(ctx, `
		UPDATE observation_task_attempts a SET outcome = 'cancelled', ended_at = $2
		FROM observation_tasks t
		WHERE `+leased+` AND a.attempt_id = t.current_attempt_id AND a.outcome IS NULL`, connectorID, at); err != nil {
		return 0, fmt.Errorf("storage: cancel leased attempts for connector: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE observation_tasks t SET state = 'queued', current_attempt_id = NULL, lease_expires_at = NULL,
			leased_replica_id = NULL, leased_at = NULL, not_before = $2
		WHERE `+leased, connectorID, at)
	if err != nil {
		return 0, fmt.Errorf("storage: requeue leased tasks for connector: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// suspendConnectorBindings suspends every live, not yet suspended
// binding on an Argo CD connector with reason.
func suspendConnectorBindings(ctx context.Context, tx pgx.Tx, connectorID uuid.UUID, reason string, at time.Time) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE gateway_connector_bindings SET suspended_reason = $2, suspended_at = $3
		WHERE argocd_connector_id = $1 AND deleted_at IS NULL AND suspended_reason IS NULL`, connectorID, reason, at)
	if err != nil {
		return 0, fmt.Errorf("storage: suspend connector bindings: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

type discoveryConnectorRow struct {
	id           uuid.UUID
	status       string
	approved     *string
	reason       *string
	leaseExpires *time.Time
	lastGrant    *time.Time
	granted      int64
	projects     *int
}

// connectorScopeHeartbeat applies one reported Argo CD connector of a
// contract 2 heartbeat. The connector row is locked FOR UPDATE. A
// connector the Gateway has not advertised through E3 yet is skipped.
//
// at is the api clock (suspension stamps); dbNow is the database clock,
// which every lease time uses, so api replicas with skewed clocks agree
// on expiry and on the interval floor.
func connectorScopeHeartbeat(ctx context.Context, tx pgx.Tx, hb GatewayHeartbeat, ch GatewayConnectorHealth, at, dbNow, seenSince time.Time, out *GatewayDiscoveryHeartbeat) error {
	var c discoveryConnectorRow
	err := tx.QueryRow(ctx, `
		SELECT id, status, approved_scope_digest, status_reason, discovery_lease_expires_at,
		       last_lease_granted_at, discovery_generation_granted, jsonb_array_length(discovery_allowed_projects)
		FROM gateway_connectors WHERE gateway_id = $1 AND name = $2 AND kind = 'argocd'
		FOR UPDATE`, hb.GatewayID, ch.ConnectorID).
		Scan(&c.id, &c.status, &c.approved, &c.reason, &c.leaseExpires, &c.lastGrant, &c.granted, &c.projects)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("storage: lock discovery connector: %w", err)
	}
	live, err := readLiveScope(ctx, tx, hb.GatewayID, ch.ConnectorID, seenSince)
	if err != nil {
		return err
	}
	digest, settled := live.single()
	_, agreed := live.agreed()
	reason := ""
	if c.reason != nil {
		reason = *c.reason
	}
	inactive := c.status == GatewayConnectorMissing || c.status == GatewayConnectorDisabled

	switch {
	case inactive || reason == GatewayConnectorReasonOverPrivileged:
		// A missing, disabled or over_privileged connector takes no scope
		// decision; the latter waits for a platform admin.
	case !settled:
		// Recorded unless a stronger reason holds the connector already
		// (scope_changed and over_privileged both need a re-approval).
		if reason == "" || reason == GatewayConnectorReasonSnapshotStale {
			if _, err := tx.Exec(ctx, `UPDATE gateway_connectors SET status_reason = $2 WHERE id = $1`,
				c.id, GatewayConnectorReasonScopeMismatch); err != nil {
				return fmt.Errorf("storage: mark scope mismatch: %w", err)
			}
			n, err := requeueLeasedForConnector(ctx, tx, c.id, at)
			if err != nil {
				return err
			}
			out.ScopeEvents = append(out.ScopeEvents, GatewayScopeEvent{ConnectorID: c.id, Event: GatewayScopeEventMismatch, TasksRequeued: n})
		}
	default:
		if reason == GatewayConnectorReasonScopeMismatch {
			if _, err := tx.Exec(ctx, `UPDATE gateway_connectors SET status_reason = NULL WHERE id = $1`, c.id); err != nil {
				return fmt.Errorf("storage: clear scope mismatch: %w", err)
			}
		}
		if c.status != GatewayConnectorApproved {
			break
		}
		switch {
		case c.approved == nil && !live.discoveryEnabled:
			// First digest of a connector approved before contract 2,
			// discovery off: adopted without re-approval (decision S-3).
			if _, err := tx.Exec(ctx, `UPDATE gateway_connectors SET approved_scope_digest = $2 WHERE id = $1`, c.id, digest); err != nil {
				return fmt.Errorf("storage: adopt scope digest: %w", err)
			}
			out.ScopeEvents = append(out.ScopeEvents, GatewayScopeEvent{ConnectorID: c.id, Event: GatewayScopeEventAdopted, New: digest})
		case c.approved == nil || *c.approved != digest:
			old := ""
			if c.approved != nil {
				old = *c.approved
			}
			if _, err := tx.Exec(ctx, `
				UPDATE gateway_connectors SET status = 'advertised', status_reason = $2, approved_by = NULL, approved_at = NULL
				WHERE id = $1`, c.id, GatewayConnectorReasonScopeChanged); err != nil {
				return fmt.Errorf("storage: reset changed scope: %w", err)
			}
			suspended, err := suspendConnectorBindings(ctx, tx, c.id, GatewayBindingSuspendedScopeChanged, at)
			if err != nil {
				return err
			}
			requeued, err := requeueLeasedForConnector(ctx, tx, c.id, at)
			if err != nil {
				return err
			}
			out.ScopeEvents = append(out.ScopeEvents, GatewayScopeEvent{
				ConnectorID: c.id, Event: GatewayScopeEventChanged, Old: old, New: digest,
				BindingsSuspended: suspended, TasksRequeued: requeued, AppProjectsBefore: c.projects,
			})
		}
	}

	// Lease grant (contract section 2.5). Approval is not a condition:
	// the first upload must arrive before approval.
	healthy := func(s string) bool { return s == "ok" || s == "degraded" }
	if inactive || !agreed || live.overPrivileged || reason == GatewayConnectorReasonOverPrivileged ||
		ch.DiscoveryEnabled == nil || !*ch.DiscoveryEnabled ||
		!healthy(hb.Status) || !healthy(ch.Status) || hb.LeaseTTL <= 0 {
		return nil
	}
	if c.leaseExpires != nil && c.leaseExpires.After(dbNow) {
		return nil
	}
	floor := max(GatewayDiscoveryIntervalFloor, time.Duration(ch.DiscoveryIntervalSeconds)*time.Second)
	if c.lastGrant != nil && dbNow.Sub(*c.lastGrant) < floor {
		return nil
	}
	lease := GatewayDiscoveryLease{
		ConnectorID: c.id, ConnectorName: ch.ConnectorID, LeaseID: uuid.New(),
		Generation: c.granted + 1, ExpiresAt: dbNow.Add(hb.LeaseTTL),
	}
	if _, err := tx.Exec(ctx, `
		UPDATE gateway_connectors SET discovery_lease_id = $2, discovery_lease_replica_id = $3,
			discovery_lease_generation = $4, discovery_lease_expires_at = $5,
			discovery_generation_granted = $4, last_lease_granted_at = $6
		WHERE id = $1`, c.id, lease.LeaseID, hb.ReplicaID, lease.Generation, lease.ExpiresAt, dbNow); err != nil {
		return fmt.Errorf("storage: grant discovery lease: %w", err)
	}
	out.Leases = append(out.Leases, lease)
	return nil
}

// recordDiscoveryHeartbeat is the contract 2 part of RecordHeartbeat,
// in its transaction, after the replica row is written.
func recordDiscoveryHeartbeat(ctx context.Context, tx pgx.Tx, hb GatewayHeartbeat, at, seenSince time.Time) (*GatewayDiscoveryHeartbeat, error) {
	out := &GatewayDiscoveryHeartbeat{}
	if hb.Contract2 {
		var dbNow time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&dbNow); err != nil {
			return nil, fmt.Errorf("storage: database clock: %w", err)
		}
		for _, ch := range hb.Connectors {
			if ch.Kind != "argocd" || ch.ScopeDigest == "" {
				continue
			}
			if err := connectorScopeHeartbeat(ctx, tx, hb, ch, at, dbNow, seenSince, out); err != nil {
				return nil, err
			}
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT c.name, s.generation FROM gateway_discovery_snapshots s
		JOIN gateway_connectors c ON c.id = s.connector_id
		WHERE c.gateway_id = $1 ORDER BY c.name`, hb.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: snapshot generations: %w", err)
	}
	for rows.Next() {
		var g GatewaySnapshotGeneration
		if err := rows.Scan(&g.ConnectorName, &g.Generation); err != nil {
			rows.Close()
			return nil, fmt.Errorf("storage: scan snapshot generation: %w", err)
		}
		out.SnapshotGenerations = append(out.SnapshotGenerations, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out.BoundTargets, err = listBoundTargets(ctx, tx, hb.GatewayID); err != nil {
		return nil, err
	}
	out.BoundTargetsVersion = BoundTargetsVersion(out.BoundTargets)
	return out, nil
}

// listBoundTargets returns every Argo CD target of the Gateway with at
// least one binding that is not deleted, suspended or not, by connector
// name then target id.
func listBoundTargets(ctx context.Context, q querier, gatewayID uuid.UUID) ([]GatewayBoundTargets, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT c.name, b.argocd_target_id
		FROM gateway_connector_bindings b JOIN gateway_connectors c ON c.id = b.argocd_connector_id
		WHERE b.gateway_id = $1 AND b.deleted_at IS NULL AND b.argocd_target_id IS NOT NULL
		ORDER BY c.name, b.argocd_target_id`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: list bound targets: %w", err)
	}
	defer rows.Close()
	var out []GatewayBoundTargets
	for rows.Next() {
		var conn, target string
		if err := rows.Scan(&conn, &target); err != nil {
			return nil, fmt.Errorf("storage: scan bound target: %w", err)
		}
		if n := len(out); n == 0 || out[n-1].ConnectorName != conn {
			out = append(out, GatewayBoundTargets{ConnectorName: conn})
		}
		out[len(out)-1].TargetIDs = append(out[len(out)-1].TargetIDs, target)
	}
	return out, rows.Err()
}

// BoundTargetsVersion is the opaque bound_targets_version: SHA-256 over
// the JSON of the sorted list, "" when there are no bindings.
func BoundTargetsVersion(groups []GatewayBoundTargets) string {
	if len(groups) == 0 {
		return ""
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CountBoundTargets returns the number of distinct Argo CD targets of a
// Gateway with a binding that is not deleted (the 4096 cap, E-4).
func (r *Gateways) CountBoundTargets(ctx context.Context, gatewayID uuid.UUID) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx, `
		SELECT count(*) FROM (SELECT DISTINCT argocd_connector_id, argocd_target_id
			FROM gateway_connector_bindings
			WHERE gateway_id = $1 AND deleted_at IS NULL AND argocd_target_id IS NOT NULL) bt`, gatewayID).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count bound targets: %w", err)
	}
	return n, nil
}

// GatewayConnectorScope is the scope view of one connector for the
// admin read and the approve check.
type GatewayConnectorScope struct {
	// ReportedDigest is the digest every live replica reports, "" when
	// none reports one or they disagree (Mismatch).
	ReportedDigest string
	// Mismatch is true while live replicas report different digests, or
	// some report one and some none.
	Mismatch         bool
	DiscoveryEnabled bool
	OverPrivileged   bool
}

// ConnectorScope returns what the live replicas report for a connector.
func (r *Gateways) ConnectorScope(ctx context.Context, gatewayID uuid.UUID, connectorName string, seenSince time.Time) (GatewayConnectorScope, error) {
	live, err := readLiveScope(ctx, r.pool, gatewayID, connectorName, seenSince)
	if err != nil {
		return GatewayConnectorScope{}, err
	}
	d, ok := live.agreed()
	return GatewayConnectorScope{
		ReportedDigest: d, Mismatch: len(live.digests) > 0 && !ok, DiscoveryEnabled: live.discoveryEnabled,
		OverPrivileged: live.overPrivileged,
	}, nil
}

// GatewayApproveOutcome is what ApproveConnectorScope changed.
type GatewayApproveOutcome struct {
	Connector       *GatewayConnector
	ScopeDigest     string
	BindingsResumed int
}

// ApproveConnectorScope approves an advertised connector of gatewayID
// for the scope digest the admin was shown (A3). digest is "" for a
// connector no live replica reports a digest for (a contract 1
// Gateway); otherwise it must equal the digest every live replica
// reports now (ErrGatewayScopeDigestChanged). With discovery on, every
// allowed AppProject of the latest upload must map to a team
// (ErrGatewayProjectMappingIncomplete), and an upload must exist. On
// success the digest is stored, status_reason is cleared and bindings
// suspended with scope_changed resume. The Gateway row is locked first,
// like a heartbeat, so the two serialise.
func (r *Gateways) ApproveConnectorScope(ctx context.Context, gatewayID, connectorID uuid.UUID, digest, by string, at, seenSince time.Time) (*GatewayApproveOutcome, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin approve: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `SELECT id FROM gateways WHERE id = $1 FOR UPDATE`, gatewayID).Scan(new(uuid.UUID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: lock gateway: %w", err)
	}
	c, err := scanGatewayConnector(tx.QueryRow(ctx, `SELECT `+gatewayConnectorColumns+`
		FROM gateway_connectors WHERE id = $1 AND gateway_id = $2 FOR UPDATE`, connectorID, gatewayID))
	if err != nil {
		return nil, err
	}
	if c.Status != GatewayConnectorAdvertised {
		return nil, ErrGatewayConnectorNotApprovable
	}
	live, err := readLiveScope(ctx, tx, gatewayID, c.Name, seenSince)
	if err != nil {
		return nil, err
	}
	reported, agreed := live.agreed()
	switch {
	case live.overPrivileged:
		// A passing probe first: no live replica may still report it.
		return nil, ErrGatewayConnectorOverPrivileged
	case len(live.digests) == 0 && digest != "":
		return nil, ErrGatewayScopeDigestChanged
	case len(live.digests) > 0 && (!agreed || digest != reported):
		return nil, ErrGatewayScopeDigestChanged
	case c.ApprovedScopeDigest != "" && digest == "":
		// Once a digest was approved, an approval must name one: an empty
		// body never writes NULL over it (review on #317, item 2).
		return nil, ErrGatewayScopeDigestChanged
	}
	if live.discoveryEnabled {
		complete, err := mappingComplete(ctx, tx, connectorID)
		if err != nil {
			return nil, err
		}
		if !complete {
			return nil, ErrGatewayProjectMappingIncomplete
		}
		// The AppProjects the console shows come from the latest upload:
		// it must be of the approved scope (review on #317, item 4).
		var uploaded string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(discovery_scope_digest, '') FROM gateway_connectors WHERE id = $1`, connectorID).Scan(&uploaded); err != nil {
			return nil, fmt.Errorf("storage: upload scope digest: %w", err)
		}
		if uploaded != digest {
			return nil, ErrGatewayScopeDigestChanged
		}
	}
	var stored any
	if digest != "" {
		stored = digest
	}
	c, err = scanGatewayConnector(tx.QueryRow(ctx, `
		UPDATE gateway_connectors SET status = 'approved', approved_by = $2, approved_at = $3,
			approved_scope_digest = COALESCE($4, approved_scope_digest), status_reason = NULL
		WHERE id = $1
		RETURNING `+gatewayConnectorColumns, connectorID, by, at, stored))
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE gateway_connector_bindings SET suspended_reason = NULL, suspended_at = NULL
		WHERE argocd_connector_id = $1 AND deleted_at IS NULL AND suspended_reason = $2`,
		connectorID, GatewayBindingSuspendedScopeChanged)
	if err != nil {
		return nil, fmt.Errorf("storage: resume scope bindings: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit approve: %w", err)
	}
	return &GatewayApproveOutcome{Connector: c, ScopeDigest: digest, BindingsResumed: int(tag.RowsAffected())}, nil
}

// mappingComplete reports whether a connector has an accepted upload and
// every AppProject in its allowed list maps to at least one team.
func mappingComplete(ctx context.Context, q querier, connectorID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT c.discovery_allowed_projects IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM jsonb_array_elements_text(c.discovery_allowed_projects) p(name)
			WHERE NOT EXISTS (SELECT 1 FROM gateway_connector_project_teams pt
				WHERE pt.connector_id = c.id AND pt.app_project = p.name))
		FROM gateway_connectors c WHERE c.id = $1`, connectorID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("storage: mapping completeness: %w", err)
	}
	return ok, nil
}
