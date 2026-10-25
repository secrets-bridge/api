package storage

// Argo CD discovery upload (E8) and snapshot fetch (E9) (ADR 0002 S4,
// api#308; gateway docs/design/discovery-contract.md sections 3 and 4).
//
// ReplaceDiscovery runs the contract's validation steps 4 to 13 in one
// transaction: the Gateway and then the connector row are locked (the
// heartbeat's order), so an upload, a lease grant and an approve never
// interleave. The service has already done steps 1 to 3 (parse, size,
// schema) and recomputed the scope digest.
//
// The sealed snapshot is stored as the exact strings the Gateway sent.
// Nothing here decodes or opens it, and nothing here holds a key.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GatewayMaxDiscoveredTargets is the per-Gateway cap on stored
// discovered targets after a replace (C9).
const GatewayMaxDiscoveredTargets = 10000

// Upload errors, one per contract code.
var (
	ErrDiscoveryGenerationStale = errors.New("storage: discovery generation is not newer than the last accepted one")
	ErrDiscoveryLeaseNotHeld    = errors.New("storage: discovery lease is not held")
	ErrDiscoveryScopeMismatch   = errors.New("storage: discovery scope digest mismatch")
	ErrDiscoveryCatalogTooLarge = errors.New("storage: discovery catalog over a cap")
)

// DiscoveredEntry is one validated names-mode entry of an upload.
type DiscoveredEntry struct {
	TargetID   string
	AppProject string
	Namespace  string
	Name       string
}

// SealedSnapshot is the opaque sealed blob, as uploaded.
type SealedSnapshot struct {
	Alg        string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// DiscoveryReplace is a validated upload.
type DiscoveryReplace struct {
	GatewayID       uuid.UUID
	ConnectorName   string
	ReplicaID       uuid.UUID
	LeaseID         uuid.UUID
	Generation      int64
	DiscoveredAt    time.Time
	ScopeDigest     string
	RecomputedScope string
	AllowedProjects []string
	Entries         []DiscoveredEntry // sorted by target id, unique
	Rejected        int
	Deferred        int
	Snapshot        SealedSnapshot
	BodySHA256      []byte
}

// DiscoveryResult is the E8 200 body.
type DiscoveryResult struct {
	Status         string `json:"status"`
	Generation     int64  `json:"generation"`
	TargetsPresent int    `json:"targets_present"`
	TargetsNew     int    `json:"targets_new"`
	TargetsMissing int    `json:"targets_missing"`
	TargetsRenamed int    `json:"targets_renamed"`
}

// DiscoveryOutcome is what ReplaceDiscovery changed, for the audit.
type DiscoveryOutcome struct {
	Result      DiscoveryResult
	Duplicate   bool
	ConnectorID uuid.UUID
	Renamed     []string // target ids whose name or namespace changed
	Moved       int      // targets whose AppProject changed
	Pruned      int      // unbound targets missing since an earlier upload, deleted
	// Bindings suspended and tasks cancelled by the lifecycle step.
	SuspendedMissing int
	SuspendedMapping int
	Cancelled        []*ObservationTask
}

type storedTarget struct {
	project, namespace, name, status string
	bound                            bool
}

// ReplaceDiscovery accepts one discovery upload (contract section 3.2,
// steps 4 to 13). A connector that is not an Argo CD connector of the
// Gateway's current catalog is ErrNotFound.
func (r *Gateways) ReplaceDiscovery(ctx context.Context, in DiscoveryReplace, at time.Time) (*DiscoveryOutcome, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin discovery: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status GatewayStatus
	var maxEntries int
	// dbNow is the database clock: lease expiry is judged on the same
	// clock the heartbeat granted it on.
	var dbNow time.Time
	err = tx.QueryRow(ctx, `SELECT status, discovery_max_entries, now() FROM gateways WHERE id = $1 FOR NO KEY UPDATE`, in.GatewayID).Scan(&status, &maxEntries, &dbNow)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGatewayNotLive
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock gateway: %w", err)
	}
	if !status.Live() {
		return nil, ErrGatewayNotLive
	}

	// Steps 4 and 5: the connector, locked.
	var c struct {
		id                       uuid.UUID
		generation               int64
		leaseID, leaseReplica    *uuid.UUID
		leaseGen                 *int64
		leaseExpires             *time.Time
		lastLease                *uuid.UUID
		lastSHA, lastResponseRaw []byte
		status string
		approvedDigest *string
	}
	err = tx.QueryRow(ctx, `
		SELECT id, discovery_generation, discovery_lease_id, discovery_lease_replica_id, discovery_lease_generation,
		       discovery_lease_expires_at, last_upload_lease_id, last_upload_sha256, last_upload_response,
		       status, approved_scope_digest
		FROM gateway_connectors
		WHERE gateway_id = $1 AND name = $2 AND kind = 'argocd' AND status <> 'missing'
		FOR UPDATE`, in.GatewayID, in.ConnectorName).
		Scan(&c.id, &c.generation, &c.leaseID, &c.leaseReplica, &c.leaseGen, &c.leaseExpires, &c.lastLease, &c.lastSHA, &c.lastResponseRaw, &c.status, &c.approvedDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock discovery connector: %w", err)
	}
	out := &DiscoveryOutcome{ConnectorID: c.id}

	// Step 6: a retry of the accepted upload.
	if c.lastLease != nil && *c.lastLease == in.LeaseID && c.generation == in.Generation && string(c.lastSHA) == string(in.BodySHA256) {
		if err := json.Unmarshal(c.lastResponseRaw, &out.Result); err != nil {
			return nil, fmt.Errorf("storage: stored discovery response: %w", err)
		}
		out.Result.Status = "duplicate"
		out.Duplicate = true
		return out, nil
	}
	// Step 7.
	if in.Generation <= c.generation {
		return nil, ErrDiscoveryGenerationStale
	}
	// Step 8.
	if c.leaseID == nil || *c.leaseID != in.LeaseID || !c.leaseExpires.After(dbNow) ||
		*c.leaseReplica != in.ReplicaID || *c.leaseGen != in.Generation {
		return nil, ErrDiscoveryLeaseNotHeld
	}
	// Step 9: the holder's last heartbeat digest, and the recomputed one.
	var holderDigest string
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(ch->>'scope_digest', '')
		FROM gateway_replicas rp, jsonb_array_elements(rp.connector_health) ch
		WHERE rp.gateway_id = $1 AND rp.replica_id = $2 AND ch->>'connector_id' = $3`,
		in.GatewayID, in.ReplicaID, in.ConnectorName).Scan(&holderDigest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("storage: holder scope digest: %w", err)
	}
	if holderDigest == "" || holderDigest != in.ScopeDigest || in.RecomputedScope != in.ScopeDigest {
		return nil, ErrDiscoveryScopeMismatch
	}

	// A holder may switch scopes after acquiring its lease. Refuse a new
	// snapshot until every currently-live replica agrees on the uploaded
	// digest, and an approved connector still approves exactly that digest.
	// This check is under the connector lock (see review on api#320).
	live, err := readLiveScope(ctx, tx, in.GatewayID, in.ConnectorName, dbNow.Add(-GatewayReplicaLiveWindow))
	if err != nil {
		return nil, err
	}
	agreed, ok := live.agreed()
	if !ok || agreed != in.ScopeDigest || live.overPrivileged ||
		(c.status == GatewayConnectorApproved && (c.approvedDigest == nil || *c.approvedDigest != in.ScopeDigest)) {
		return nil, ErrDiscoveryScopeMismatch
	}

	// Step 10: caps.
	if len(in.Entries) > maxEntries {
		return nil, ErrDiscoveryCatalogTooLarge
	}
	existing := map[string]storedTarget{}
	rows, err := tx.Query(ctx, `
		SELECT dt.target_id, dt.app_project, dt.namespace, dt.name, dt.status,
		       EXISTS (SELECT 1 FROM gateway_connector_bindings b
		               WHERE b.argocd_connector_id = dt.connector_id AND b.argocd_target_id = dt.target_id AND b.deleted_at IS NULL)
		FROM gateway_discovered_targets dt WHERE dt.connector_id = $1`, c.id)
	if err != nil {
		return nil, fmt.Errorf("storage: read discovered targets: %w", err)
	}
	for rows.Next() {
		var id string
		var t storedTarget
		if err := rows.Scan(&id, &t.project, &t.namespace, &t.name, &t.status, &t.bound); err != nil {
			rows.Close()
			return nil, fmt.Errorf("storage: scan discovered target: %w", err)
		}
		existing[id] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	incoming := make(map[string]bool, len(in.Entries))
	var ids, projects, namespaces, names, moved []string
	for _, e := range in.Entries {
		incoming[e.TargetID] = true
		ids, projects, namespaces, names = append(ids, e.TargetID), append(projects, e.AppProject), append(namespaces, e.Namespace), append(names, e.Name)
		prev, ok := existing[e.TargetID]
		switch {
		case !ok:
			out.Result.TargetsNew++
			continue
		case prev.name != e.Name || prev.namespace != e.Namespace:
			out.Renamed = append(out.Renamed, e.TargetID)
		}
		if prev.project != e.AppProject {
			moved = append(moved, e.TargetID)
		}
	}
	// Unbound targets that were already missing before this upload are
	// pruned, so missing rows cannot grow without bound; bound ones stay
	// (their bindings are suspended) until the binding is deleted.
	var prune, newlyMissing []string
	kept := 0
	for id, t := range existing {
		switch {
		case incoming[id]:
		case t.status == "missing" && !t.bound:
			prune = append(prune, id)
		case t.status == "present":
			newlyMissing = append(newlyMissing, id)
			kept++
		default:
			kept++
		}
	}
	var others int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM gateway_discovered_targets WHERE gateway_id = $1 AND connector_id <> $2`,
		in.GatewayID, c.id).Scan(&others); err != nil {
		return nil, fmt.Errorf("storage: count gateway discovered targets: %w", err)
	}
	// If this upload would cross the gateway-wide cap, reclaim unbound
	// targets that became missing in this same upload. Otherwise a full
	// Application UID churn can strand the connector over the cap forever.
	// Bound missing targets remain for their suspended bindings.
	missingCount := len(newlyMissing)
	if others+len(in.Entries)+kept > GatewayMaxDiscoveredTargets {
		remainingMissing := newlyMissing[:0]
		for _, id := range newlyMissing {
			if !existing[id].bound {
				prune = append(prune, id)
				kept--
			} else {
				remainingMissing = append(remainingMissing, id)
			}
		}
		newlyMissing = remainingMissing
	}
	if others+len(in.Entries)+kept > GatewayMaxDiscoveredTargets {
		return nil, ErrDiscoveryCatalogTooLarge
	}

	// Step 11: replace.
	if len(prune) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM gateway_discovered_targets WHERE connector_id = $1 AND target_id = ANY($2::text[])`, c.id, prune); err != nil {
			return nil, fmt.Errorf("storage: prune discovered targets: %w", err)
		}
		out.Pruned = len(prune)
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO gateway_discovered_targets
				(connector_id, target_id, gateway_id, app_project, namespace, name, status,
				 generation_first_seen, last_seen_generation, first_seen_at, last_seen_at)
			SELECT $1, u.t, $2, u.p, u.ns, u.n, 'present', $3, $3, $4, $4
			FROM unnest($5::text[], $6::text[], $7::text[], $8::text[]) AS u(t, p, ns, n)
			ON CONFLICT (connector_id, target_id) DO UPDATE SET
				app_project = EXCLUDED.app_project, namespace = EXCLUDED.namespace, name = EXCLUDED.name,
				status = 'present', last_seen_generation = EXCLUDED.last_seen_generation, last_seen_at = EXCLUDED.last_seen_at`,
			c.id, in.GatewayID, in.Generation, at, ids, projects, namespaces, names); err != nil {
			return nil, fmt.Errorf("storage: upsert discovered targets: %w", err)
		}
	}
	if len(newlyMissing) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE gateway_discovered_targets SET status = 'missing'
			WHERE connector_id = $1 AND target_id = ANY($2::text[])`, c.id, newlyMissing); err != nil {
			return nil, fmt.Errorf("storage: mark discovered targets missing: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO gateway_discovery_snapshots (connector_id, generation, discovered_at, alg, nonce, ciphertext, stored_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (connector_id) DO UPDATE SET generation = EXCLUDED.generation, discovered_at = EXCLUDED.discovered_at,
			alg = EXCLUDED.alg, nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext, stored_at = EXCLUDED.stored_at`,
		c.id, in.Generation, in.DiscoveredAt, in.Snapshot.Alg, in.Snapshot.Nonce, in.Snapshot.Ciphertext, at); err != nil {
		return nil, fmt.Errorf("storage: store snapshot: %w", err)
	}
	out.Result = DiscoveryResult{
		Status: "accepted", Generation: in.Generation, TargetsPresent: len(in.Entries), TargetsNew: out.Result.TargetsNew,
		TargetsMissing: missingCount, TargetsRenamed: len(out.Renamed),
	}
	out.Moved = len(moved)
	respRaw, err := json.Marshal(out.Result)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal discovery response: %w", err)
	}
	allowed, err := json.Marshal(in.AllowedProjects)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal allowed projects: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE gateway_connectors SET discovery_generation = $2, last_discovery_at = $3,
			discovery_lease_id = NULL, discovery_lease_replica_id = NULL, discovery_lease_generation = NULL,
			discovery_lease_expires_at = NULL, discovery_allowed_projects = $4, discovery_scope_digest = $8,
			last_upload_lease_id = $5, last_upload_sha256 = $6, last_upload_response = $7,
			status_reason = CASE WHEN status_reason = 'snapshot_stale' THEN NULL ELSE status_reason END
		WHERE id = $1`, c.id, in.Generation, at, allowed, in.LeaseID, in.BodySHA256, respRaw, in.ScopeDigest); err != nil {
		return nil, fmt.Errorf("storage: record discovery generation: %w", err)
	}

	// Step 12: lifecycle (ADR 0002 section 4.4).
	if len(newlyMissing) > 0 {
		suspended, err := suspendBindingsFor(ctx, tx, c.id, newlyMissing, GatewayBindingSuspendedTargetMissing, at)
		if err != nil {
			return nil, err
		}
		out.SuspendedMissing = len(suspended)
		cancelled, err := cancelOpenTasks(ctx, tx, `t.binding_id = ANY($1::uuid[])`, []any{uuidStrings(suspended)}, ObservationReasonTargetMissing, at)
		if err != nil {
			return nil, err
		}
		out.Cancelled = append(out.Cancelled, cancelled...)
	}
	if len(moved) > 0 {
		suspended, cancelled, err := suspendUncoveredBindings(ctx, tx, c.id, moved, at)
		if err != nil {
			return nil, err
		}
		out.SuspendedMapping = suspended
		out.Cancelled = append(out.Cancelled, cancelled...)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit discovery: %w", err)
	}
	return out, nil
}

// suspendBindingsFor suspends the live discovered bindings on targetIDs
// of a connector with reason target_missing. target_missing takes the
// place of any other reason: the target is gone, and a re-approval or a
// mapping change must not resume the binding. Returns the binding ids.
func suspendBindingsFor(ctx context.Context, tx pgx.Tx, connectorID uuid.UUID, targetIDs []string, reason string, at time.Time) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		UPDATE gateway_connector_bindings SET suspended_reason = $3, suspended_at = $4
		WHERE argocd_connector_id = $1 AND argocd_target_id = ANY($2::text[]) AND deleted_at IS NULL
		  AND target_source = 'discovered' AND suspended_reason IS DISTINCT FROM $3
		RETURNING id`, connectorID, targetIDs, reason, at)
	if err != nil {
		return nil, fmt.Errorf("storage: suspend bindings: %w", err)
	}
	return collectIDs(rows)
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// bindingTeamCoveredSQL is true when binding b's discovered target is in
// an AppProject mapped to a team whose subtree holds the team of the
// binding project (ADR 0002 C4). The claim query, task creation and the
// mapping lifecycle use the same expression.
const bindingTeamCoveredSQL = `EXISTS (
		SELECT 1 FROM gateway_discovered_targets cdt
		JOIN gateway_connector_project_teams cpt ON cpt.connector_id = cdt.connector_id AND cpt.app_project = cdt.app_project
		JOIN environments ce ON ce.id = b.environment_id
		JOIN projects cp ON cp.id = ce.project_id
		WHERE cdt.connector_id = b.argocd_connector_id AND cdt.target_id = b.argocd_target_id
		  AND team_covers(cpt.team_id, cp.team_id))`

// suspendUncoveredBindings suspends, with mapping_removed, every live
// discovered binding of a connector (on targetIDs, or all when nil)
// whose target's AppProject no longer maps to a team covering the
// binding project, and cancels their open tasks with binding_suspended.
// mapping_removed replaces scope_changed but never target_missing.
func suspendUncoveredBindings(ctx context.Context, tx pgx.Tx, connectorID uuid.UUID, targetIDs []string, at time.Time) (int, []*ObservationTask, error) {
	rows, err := tx.Query(ctx, `
		UPDATE gateway_connector_bindings b SET suspended_reason = 'mapping_removed', suspended_at = $3
		WHERE b.argocd_connector_id = $1 AND b.deleted_at IS NULL AND b.target_source = 'discovered'
		  AND ($2::text[] IS NULL OR b.argocd_target_id = ANY($2::text[]))
		  AND (b.suspended_reason IS NULL OR b.suspended_reason = 'scope_changed')
		  AND NOT `+bindingTeamCoveredSQL+`
		RETURNING b.id`, connectorID, targetIDs, at)
	if err != nil {
		return 0, nil, fmt.Errorf("storage: suspend uncovered bindings: %w", err)
	}
	ids, err := collectIDs(rows)
	if err != nil {
		return 0, nil, err
	}
	if len(ids) == 0 {
		return 0, nil, nil
	}
	cancelled, err := cancelOpenTasks(ctx, tx, `t.binding_id = ANY($1::uuid[])`, []any{uuidStrings(ids)}, ObservationReasonBindingSuspended, at)
	if err != nil {
		return 0, nil, err
	}
	return len(ids), cancelled, nil
}

// GatewaySnapshot is the stored sealed snapshot of a connector (E9).
type GatewaySnapshot struct {
	ConnectorName string
	Generation    int64
	DiscoveredAt  time.Time
	Snapshot      SealedSnapshot
}

// GetSnapshot returns the latest sealed snapshot of a Gateway's Argo CD
// connector, exactly as uploaded. ErrNotFound when there is none or the
// connector is not one of the Gateway's Argo CD connectors.
func (r *Gateways) GetSnapshot(ctx context.Context, gatewayID uuid.UUID, connectorName string) (*GatewaySnapshot, error) {
	var s GatewaySnapshot
	err := r.pool.QueryRow(ctx, `
		SELECT c.name, s.generation, s.discovered_at, s.alg, s.nonce, s.ciphertext
		FROM gateway_discovery_snapshots s JOIN gateway_connectors c ON c.id = s.connector_id
		WHERE c.gateway_id = $1 AND c.name = $2 AND c.kind = 'argocd' AND c.status <> 'missing'`, gatewayID, connectorName).
		Scan(&s.ConnectorName, &s.Generation, &s.DiscoveredAt, &s.Snapshot.Alg, &s.Snapshot.Nonce, &s.Snapshot.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get snapshot: %w", err)
	}
	return &s, nil
}

// SnapshotDiscoveredAt returns discovered_at of each stored snapshot of
// a Gateway, by connector row id (the snapshot_stale reason).
func (r *Gateways) SnapshotDiscoveredAt(ctx context.Context, gatewayID uuid.UUID) (map[uuid.UUID]time.Time, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT s.connector_id, s.discovered_at FROM gateway_discovery_snapshots s
		JOIN gateway_connectors c ON c.id = s.connector_id WHERE c.gateway_id = $1`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: snapshot ages: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]time.Time{}
	for rows.Next() {
		var id uuid.UUID
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("storage: scan snapshot age: %w", err)
		}
		out[id] = at
	}
	return out, rows.Err()
}

// deleteGatewaySnapshots drops every stored snapshot of a Gateway
// (revoke, decision E-6).
func deleteGatewaySnapshots(ctx context.Context, tx pgx.Tx, gatewayID uuid.UUID) (int, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM gateway_discovery_snapshots WHERE connector_id IN (
		SELECT id FROM gateway_connectors WHERE gateway_id = $1)`, gatewayID)
	if err != nil {
		return 0, fmt.Errorf("storage: delete snapshots: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
