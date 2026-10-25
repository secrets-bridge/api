package services

// E8 discovery upload and E9 snapshot fetch (ADR 0002 S4, api#308;
// gateway docs/design/discovery-contract.md sections 3 and 4).
//
// DecodeDiscoveryUpload is steps 1 and 3 of the contract's validation
// order (step 2, the 2 MiB size, is the route's body limit): a body that
// is not exactly one JSON object is ErrDiscoveryParse (400
// invalid_request); one that breaks gateway.discovery-catalog/v1 is
// ErrDiscoverySchema (422 schema_violation). Errors name nothing from
// the body.
//
// The sealed snapshot is checked for shape only and stored as uploaded.
// The control plane never decodes or opens it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Discovery wire errors.
var (
	ErrDiscoveryParse  = errors.New("services: discovery body is not one JSON object")
	ErrDiscoverySchema = errors.New("services: discovery body breaks its schema")
)

const (
	gatewayDiscoverySchemaVersion = "gateway.discovery-catalog/v1"
	gatewaySnapshotSchemaVersion  = "gateway.discovery-snapshot/v1"
	gatewaySnapshotAlg            = "A256GCM+HKDF-SHA256/v1"
	gatewayDiscoveryMaxEntries    = 10000
	gatewayDiscoveryMaxProjects   = 64
	gatewayDiscoveryMaxCounter    = 10000
	gatewaySnapshotMinCipher      = 24
	gatewaySnapshotMaxCipher      = 2000000
	gatewayMaxGeneration          = 9007199254740991
	// GatewayDiscoveryBodyLimit is the E8 body cap, answered 413
	// catalog_too_large.
	GatewayDiscoveryBodyLimit = 2 << 20
)

var (
	gatewayDiscoveredIDRe = regexp.MustCompile(`^d-[a-z2-7]{26}$`)
	// AppProject (gateway settings.go) and Application name
	// (validAppName): the Kubernetes subdomain pattern, at most 253.
	gatewayAppProjectRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	gatewayWholeSecondRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	gatewayNonceRe       = regexp.MustCompile(`^[A-Za-z0-9+/]{16}$`)
	gatewayCiphertextRe  = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

type discoverySealedWire struct {
	Alg        string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type discoveryEntryWire struct {
	TargetID     *string `json:"target_id"`
	AppProject   *string `json:"app_project"`
	Namespace    *string `json:"namespace"`
	Name         *string `json:"name"`
	ProjectAlias *string `json:"project_alias"`
	Label        *string `json:"label"`
}

type discoveryUploadWire struct {
	SchemaVersion   string                `json:"schema_version"`
	ReplicaID       string                `json:"replica_id"`
	LeaseID         string                `json:"lease_id"`
	Generation      *int64                `json:"generation"`
	DiscoveredAt    string                `json:"discovered_at"`
	ScopeDigest     string                `json:"scope_digest"`
	EndpointDigest  string                `json:"endpoint_digest"`
	IdentityMode    string                `json:"identity_mode"`
	AllowedProjects []string              `json:"allowed_projects"`
	ProjectAliases  []string              `json:"project_aliases"`
	Entries         *[]discoveryEntryWire `json:"entries"`
	EntriesRejected *int                  `json:"entries_rejected"`
	EntriesDeferred *int                  `json:"entries_deferred"`
	Snapshot        *discoverySealedWire  `json:"snapshot"`
}

// DiscoveryUpload is a decoded, schema-valid E8 body.
type DiscoveryUpload struct {
	ReplicaID       uuid.UUID
	LeaseID         uuid.UUID
	Generation      int64
	DiscoveredAt    time.Time
	ScopeDigest     string
	EndpointDigest  string
	AllowedProjects []string // sorted
	Entries         []storage.DiscoveredEntry
	Rejected        int
	Deferred        int
	Snapshot        storage.SealedSnapshot
}

func schemaViolation() error { return ErrDiscoverySchema }

// validAppName is the gateway's validAppName: the subdomain pattern, at
// most 253, and no "..".
func validAppName(s string) bool {
	return len(s) <= 253 && gatewayAppProjectRe.MatchString(s) && !strings.Contains(s, "..")
}

func validAppProject(s string) bool { return len(s) <= 253 && gatewayAppProjectRe.MatchString(s) }

func strictUUID(s string) (uuid.UUID, bool) {
	if !gatewayUUIDRe.MatchString(s) {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(s)
	return id, err == nil
}

// DecodeDiscoveryUpload decodes and checks an E8 body (contract steps 1
// and 3). Opaque mode is refused until it ships (decision E-8).
func DecodeDiscoveryUpload(body []byte) (*DiscoveryUpload, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return nil, ErrDiscoveryParse
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, ErrDiscoveryParse
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrDiscoveryParse
	}
	var w discoveryUploadWire
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&w); err != nil {
		return nil, schemaViolation()
	}
	return w.validate()
}

func (w *discoveryUploadWire) validate() (*DiscoveryUpload, error) {
	out := &DiscoveryUpload{ScopeDigest: w.ScopeDigest, EndpointDigest: w.EndpointDigest}
	var ok bool
	switch {
	case w.SchemaVersion != gatewayDiscoverySchemaVersion:
		return nil, schemaViolation()
	case w.Generation == nil || *w.Generation < 1 || *w.Generation > gatewayMaxGeneration:
		return nil, schemaViolation()
	case !gatewaySHA256Re.MatchString(w.ScopeDigest) || !gatewaySHA256Re.MatchString(w.EndpointDigest):
		return nil, schemaViolation()
	case w.IdentityMode != "names":
		// opaque is in the schema but refused until it ships (E-8).
		return nil, schemaViolation()
	case w.ProjectAliases != nil || w.AllowedProjects == nil:
		return nil, schemaViolation()
	case w.Entries == nil || len(*w.Entries) > gatewayDiscoveryMaxEntries:
		return nil, schemaViolation()
	case w.EntriesRejected == nil || *w.EntriesRejected < 0 || *w.EntriesRejected > gatewayDiscoveryMaxCounter:
		return nil, schemaViolation()
	case w.EntriesDeferred == nil || *w.EntriesDeferred < 0 || *w.EntriesDeferred > gatewayDiscoveryMaxCounter:
		return nil, schemaViolation()
	case w.Snapshot == nil:
		return nil, schemaViolation()
	}
	out.Generation, out.Rejected, out.Deferred = *w.Generation, *w.EntriesRejected, *w.EntriesDeferred
	if out.ReplicaID, ok = strictUUID(w.ReplicaID); !ok {
		return nil, schemaViolation()
	}
	if out.LeaseID, ok = strictUUID(w.LeaseID); !ok {
		return nil, schemaViolation()
	}
	if !gatewayWholeSecondRe.MatchString(w.DiscoveredAt) {
		return nil, schemaViolation()
	}
	at, err := time.Parse(time.RFC3339, w.DiscoveredAt)
	if err != nil || at.UTC().Format(time.RFC3339) != w.DiscoveredAt {
		return nil, schemaViolation()
	}
	out.DiscoveredAt = at.UTC()

	if len(w.AllowedProjects) < 1 || len(w.AllowedProjects) > gatewayDiscoveryMaxProjects {
		return nil, schemaViolation()
	}
	allowed := make(map[string]bool, len(w.AllowedProjects))
	for _, p := range w.AllowedProjects {
		if !validAppProject(p) || allowed[p] {
			return nil, schemaViolation()
		}
		allowed[p] = true
	}
	out.AllowedProjects = slices.Clone(w.AllowedProjects)
	slices.Sort(out.AllowedProjects)

	prev := ""
	out.Entries = make([]storage.DiscoveredEntry, 0, len(*w.Entries))
	for _, e := range *w.Entries {
		switch {
		case e.TargetID == nil || !gatewayDiscoveredIDRe.MatchString(*e.TargetID):
			return nil, schemaViolation()
		case *e.TargetID <= prev:
			// Sorted by target_id and unique.
			return nil, schemaViolation()
		case e.ProjectAlias != nil || e.Label != nil:
			return nil, schemaViolation()
		case e.AppProject == nil || !validAppProject(*e.AppProject) || !allowed[*e.AppProject]:
			return nil, schemaViolation()
		case e.Namespace == nil || !gatewayDNSLabelRe.MatchString(*e.Namespace):
			return nil, schemaViolation()
		case e.Name == nil || !validAppName(*e.Name):
			return nil, schemaViolation()
		}
		prev = *e.TargetID
		out.Entries = append(out.Entries, storage.DiscoveredEntry{
			TargetID: *e.TargetID, AppProject: *e.AppProject, Namespace: *e.Namespace, Name: *e.Name,
		})
	}

	s := w.Snapshot
	if s.Alg != gatewaySnapshotAlg || !gatewayNonceRe.MatchString(s.Nonce) ||
		len(s.Ciphertext) < gatewaySnapshotMinCipher || len(s.Ciphertext) > gatewaySnapshotMaxCipher ||
		!gatewayCiphertextRe.MatchString(s.Ciphertext) {
		return nil, schemaViolation()
	}
	out.Snapshot = storage.SealedSnapshot{Alg: s.Alg, Nonce: s.Nonce, Ciphertext: s.Ciphertext}
	return out, nil
}

// UploadDiscovery is E8 for an authenticated Gateway: decode (steps 1
// and 3), recompute the scope digest, then the transactional steps 4 to
// 13 in storage, then the audit. A retry of the accepted body answers
// the stored result with status duplicate.
func (s *GatewayService) UploadDiscovery(ctx context.Context, gatewayID uuid.UUID, connectorName string, body []byte) (*storage.DiscoveryResult, error) {
	up, err := DecodeDiscoveryUpload(body)
	if err != nil {
		return nil, err
	}
	if !ValidGatewayLocalID(connectorName) {
		return nil, storage.ErrNotFound
	}
	sum := sha256.Sum256(body)
	out, err := s.store.ReplaceDiscovery(ctx, storage.DiscoveryReplace{
		GatewayID: gatewayID, ConnectorName: connectorName, ReplicaID: up.ReplicaID, LeaseID: up.LeaseID,
		Generation: up.Generation, DiscoveredAt: up.DiscoveredAt, ScopeDigest: up.ScopeDigest,
		RecomputedScope: GatewayScopeDigest(up.EndpointDigest, up.AllowedProjects, true, "names"),
		AllowedProjects: up.AllowedProjects, Entries: up.Entries, Rejected: up.Rejected, Deferred: up.Deferred,
		Snapshot: up.Snapshot, BodySHA256: sum[:],
	}, s.now().UTC())
	if errors.Is(err, storage.ErrGatewayNotLive) {
		s.invalidateSecretHashCache(ctx, gatewayID)
		return nil, ErrGatewayRevoked
	}
	if err != nil {
		return nil, err
	}
	if out.Duplicate {
		return &out.Result, nil
	}
	actor := gatewayActor(gatewayID)
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: actor, Action: "gateway.discovery.catalog_replaced", Resource: actor, Status: storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"gateway_id": gatewayID.String(), "connector_id": out.ConnectorID.String(), "replica_id": up.ReplicaID.String(),
			"generation": up.Generation, "targets_present": out.Result.TargetsPresent, "targets_new": out.Result.TargetsNew,
			"targets_missing": out.Result.TargetsMissing, "targets_renamed": out.Result.TargetsRenamed,
			"targets_moved": out.Moved, "targets_pruned": out.Pruned,
			"entries_rejected": up.Rejected, "entries_deferred": up.Deferred, "app_project_count": len(up.AllowedProjects),
			"bindings_suspended": out.SuspendedMissing + out.SuspendedMapping, "tasks_cancelled": len(out.Cancelled),
		},
	})
	if len(out.Renamed) > 0 {
		ids := out.Renamed
		meta := map[string]any{
			"gateway_id": gatewayID.String(), "connector_id": out.ConnectorID.String(), "generation": up.Generation,
			"targets_renamed": len(ids),
		}
		// The audit list cap is 200 ids; the count is exact.
		if len(ids) > gatewayAuditMaxIDs {
			ids = ids[:gatewayAuditMaxIDs]
			meta["target_ids_truncated"] = true
		}
		meta["argocd_target_ids"] = ids
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "gateway.target.renamed", Resource: actor, Status: storage.AuditStatusSuccess, Metadata: meta,
		})
	}
	for _, t := range out.Cancelled {
		auditTaskClosed(ctx, s.audit, actor, "observation.task.cancelled", t)
	}
	return &out.Result, nil
}

// gatewayAuditMaxIDs is the audit allowlist's list cap.
const gatewayAuditMaxIDs = 200

// GetSnapshot is E9: the latest sealed snapshot of one of the Gateway's
// Argo CD connectors, exactly as uploaded. storage.ErrNotFound for every
// "no snapshot" case (decision E-9).
func (s *GatewayService) GetSnapshot(ctx context.Context, gatewayID uuid.UUID, connectorName string) (*storage.GatewaySnapshot, error) {
	if !ValidGatewayLocalID(connectorName) {
		return nil, storage.ErrNotFound
	}
	return s.store.GetSnapshot(ctx, gatewayID, connectorName)
}

// SnapshotSchemaVersion is the E9 body's schema_version.
func SnapshotSchemaVersion() string { return gatewaySnapshotSchemaVersion }

// gatewaySnapshotMaxAge is the largest snapshot_max_age a Gateway can
// set (1 hour). The CP learns nothing about the real value, so it shows
// a connector snapshot_stale past this age (contract section 7.2).
const gatewaySnapshotMaxAge = time.Hour

// StaleSnapshots returns the connectors of a Gateway whose stored
// snapshot is older than the largest snapshot_max_age, by row id.
func (s *GatewayService) StaleSnapshots(ctx context.Context, gatewayID uuid.UUID) (map[uuid.UUID]bool, error) {
	ages, err := s.store.SnapshotDiscoveredAt(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	out := map[uuid.UUID]bool{}
	for id, at := range ages {
		if now.Sub(at) > gatewaySnapshotMaxAge {
			out[id] = true
		}
	}
	return out, nil
}
