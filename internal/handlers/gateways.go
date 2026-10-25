package handlers

// Gateway registry HTTP layer (api#293). Two surfaces:
//
//   - machine routes under /api/v1/gateways/ for the Gateway process:
//     E1 enroll (enrollment token only), E2 heartbeat and E3 catalog
//     (X-Gateway-Secret through middleware.GatewayAuth). They match the
//     Gateway client on gateway main (internal/client): JSON bodies,
//     errors as {"error": "<code>"} from a closed list, and no error body
//     echoes request content.
//   - admin routes under /api/v1/admin/gateways and
//     /api/v1/admin/gateway-*, behind the session gate, each with a
//     gateway.* permission (and a fresh second factor for writes, wired
//     in cmd/api).
//
// No response carries a secret hash, and the enrollment token and the
// gateway secret appear in exactly one response each: the mint and the
// enroll.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Gateways serves the Gateway machine and admin routes.
type Gateways struct {
	svc          *services.GatewayService
	obs          *services.GatewayObservationService
	requireHTTPS bool
}

// NewGateways builds the handler. requireHTTPS refuses E1 over plain http
// (set outside SB_ENV=dev).
func NewGateways(svc *services.GatewayService, requireHTTPS bool) *Gateways {
	return &Gateways{svc: svc, requireHTTPS: requireHTTPS}
}

func gwError(c fiber.Ctx, status int, code string) error {
	return c.Status(status).JSON(fiber.Map{"error": code})
}

// decodeStrict decodes exactly one JSON value with no unknown fields.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func timePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func uuidPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

// ---- E1 enroll ---------------------------------------------------------

type gatewayEnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	ClusterName     string `json:"cluster_name,omitempty"`
}

type gatewayEnrollResponse struct {
	GatewayID                string `json:"gateway_id"`
	GatewaySecret            string `json:"gateway_secret"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ClaimPollSeconds         int    `json:"claim_poll_seconds"`
}

// secureTransport reports whether the request reached the api over TLS,
// directly or through a TLS-terminating proxy that set X-Forwarded-Proto.
func secureTransport(c fiber.Ctx) bool {
	if c.Scheme() == "https" {
		return true
	}
	proto, _, _ := strings.Cut(c.Get(fiber.HeaderXForwardedProto), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// Enroll handles POST /api/v1/gateways/enroll (E1). The one-time token is
// the only authentication; the route is session-exempt by design.
func (h *Gateways) Enroll(c fiber.Ctx) error {
	if h.svc == nil {
		return gwError(c, fiber.StatusServiceUnavailable, "enrollment_not_configured")
	}
	insecure := h.requireHTTPS && !secureTransport(c)
	var req gatewayEnrollRequest
	if !insecure {
		if err := decodeStrict(c.Body(), &req); err != nil {
			return gwError(c, fiber.StatusBadRequest, "invalid_request")
		}
	}
	res, err := h.svc.Enroll(c.Context(), services.GatewayEnrollInput{
		Token: req.EnrollmentToken, ClusterName: req.ClusterName, Insecure: insecure,
	})
	if err != nil {
		var status int
		var code string
		switch {
		case errors.Is(err, services.ErrGatewayInsecureTransport):
			status, code = fiber.StatusForbidden, "https_required"
		case errors.Is(err, services.ErrGatewayEnrollmentTokenInvalid):
			status, code = fiber.StatusUnauthorized, "enrollment_token_invalid"
		case errors.Is(err, services.ErrGatewayEnrollmentTokenExpired):
			status, code = fiber.StatusUnauthorized, "enrollment_token_expired"
		case errors.Is(err, services.ErrGatewayEnrollmentTokenConsumed):
			status, code = fiber.StatusConflict, "enrollment_token_already_consumed"
		case errors.Is(err, services.ErrGatewayAlreadyEnrolled):
			status, code = fiber.StatusConflict, "gateway_already_enrolled"
		case errors.Is(err, services.ErrGatewayEnrollmentTokenRevoked):
			status, code = fiber.StatusForbidden, "enrollment_token_revoked"
		case errors.Is(err, services.ErrGatewayClusterMismatch):
			status, code = fiber.StatusBadRequest, "cluster_name_mismatch"
		case errors.Is(err, services.ErrGatewayInvalidRequest):
			status, code = fiber.StatusBadRequest, "invalid_request"
		default:
			return err // logged, generic 500 body
		}
		return gwError(c, status, code)
	}
	return c.Status(fiber.StatusCreated).JSON(gatewayEnrollResponse{
		GatewayID: res.GatewayID.String(), GatewaySecret: res.Secret,
		HeartbeatIntervalSeconds: res.HeartbeatIntervalSeconds, ClaimPollSeconds: res.ClaimPollSeconds,
	})
}

// ---- E2 heartbeat ------------------------------------------------------

type gatewayHeartbeatRequest struct {
	ReplicaID        string   `json:"replica_id"`
	GatewayVersion   string   `json:"gateway_version"`
	ContractVersions []string `json:"contract_versions"`
	Status           string   `json:"status"`
	InFlight         int      `json:"in_flight"`
	CatalogVersion   string   `json:"catalog_version,omitempty"`
	// Contract 2 (api#308). The service refuses it unless the request
	// lists "2".
	BoundTargetsVersion *string `json:"bound_targets_version,omitempty"`
	Connectors          []struct {
		ConnectorID string `json:"connector_id"`
		Kind        string `json:"kind"`
		Status      string `json:"status"`
		// Contract 2, Argo CD only.
		ScopeDigest              *string `json:"scope_digest,omitempty"`
		DiscoveryEnabled         *bool   `json:"discovery_enabled,omitempty"`
		DiscoveryIntervalSeconds *int    `json:"discovery_interval_seconds,omitempty"`
	} `json:"connectors,omitempty"`
}

type gatewayHeartbeatResponse struct {
	Status               string `json:"status"`
	ServerTime           string `json:"server_time"`
	NextHeartbeatSeconds int    `json:"next_heartbeat_seconds"`
	ClaimPollSeconds     int    `json:"claim_poll_seconds"`
	ContractVersion      string `json:"contract_version"`
	CatalogVersion       string `json:"catalog_version"`
	// Contract 2 only (api#308, discovery-contract.md section 2.4). A
	// contract 1 answer never carries them.
	DiscoveryLeases     []gatewayDiscoveryLeaseView     `json:"discovery_leases,omitempty"`
	SnapshotGenerations []gatewaySnapshotGenerationView `json:"snapshot_generations,omitempty"`
	BoundTargetsVersion *string                         `json:"bound_targets_version,omitempty"`
	// BoundTargets is a pointer so an empty full replace is sent as [].
	BoundTargets *[]storage.GatewayBoundTargets `json:"bound_targets,omitempty"`
}

type gatewayDiscoveryLeaseView struct {
	ConnectorID string `json:"connector_id"`
	LeaseID     string `json:"lease_id"`
	Generation  int64  `json:"generation"`
	ExpiresAt   string `json:"expires_at"`
}

type gatewaySnapshotGenerationView struct {
	ConnectorID string `json:"connector_id"`
	Generation  int64  `json:"generation"`
}

// heartbeatResponse renders an E2 200 body. The contract 2 fields are
// set only when the service answered contract 2.
func heartbeatResponse(res *services.GatewayHeartbeatResult) gatewayHeartbeatResponse {
	out := gatewayHeartbeatResponse{
		Status: "ok", ServerTime: res.ServerTime.UTC().Format(time.RFC3339Nano),
		NextHeartbeatSeconds: res.NextHeartbeatSeconds, ClaimPollSeconds: res.ClaimPollSeconds,
		ContractVersion: res.ContractVersion, CatalogVersion: res.CatalogVersion,
	}
	d := res.Discovery
	if d == nil {
		return out
	}
	for _, l := range d.Leases {
		out.DiscoveryLeases = append(out.DiscoveryLeases, gatewayDiscoveryLeaseView{
			ConnectorID: l.ConnectorName, LeaseID: l.LeaseID.String(), Generation: l.Generation,
			ExpiresAt: l.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	for _, g := range d.SnapshotGenerations {
		out.SnapshotGenerations = append(out.SnapshotGenerations, gatewaySnapshotGenerationView{ConnectorID: g.ConnectorName, Generation: g.Generation})
	}
	version := d.BoundTargetsVersion
	out.BoundTargetsVersion = &version
	if res.SendBoundTargets {
		list := d.BoundTargets
		if list == nil {
			list = []storage.GatewayBoundTargets{}
		}
		out.BoundTargets = &list
	}
	return out
}

func authenticatedGateway(c fiber.Ctx) (uuid.UUID, error) {
	id, ok := middleware.GatewayIDFromContext(c.Context())
	if !ok {
		return uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
	}
	return id, nil
}

// Heartbeat handles POST /api/v1/gateways/:id/heartbeat (E2).
func (h *Gateways) Heartbeat(c fiber.Ctx) error {
	id, err := authenticatedGateway(c)
	if err != nil {
		return err
	}
	var req gatewayHeartbeatRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	}
	in := services.GatewayHeartbeatInput{
		ReplicaID: req.ReplicaID, GatewayVersion: req.GatewayVersion, ContractVersions: req.ContractVersions,
		Status: req.Status, InFlight: req.InFlight, CatalogVersion: req.CatalogVersion,
		BoundTargetsVersion: req.BoundTargetsVersion,
	}
	for _, ch := range req.Connectors {
		in.Connectors = append(in.Connectors, services.GatewayHeartbeatConnector{
			ConnectorID: ch.ConnectorID, Kind: ch.Kind, Status: ch.Status,
			ScopeDigest: ch.ScopeDigest, DiscoveryEnabled: ch.DiscoveryEnabled, DiscoveryIntervalSeconds: ch.DiscoveryIntervalSeconds,
		})
	}
	res, err := h.svc.Heartbeat(c.Context(), id, in)
	switch {
	case errors.Is(err, services.ErrGatewayInvalidRequest):
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	case errors.Is(err, services.ErrGatewayReplicaLimit):
		c.Set(fiber.HeaderRetryAfter, "60")
		return gwError(c, fiber.StatusTooManyRequests, "replica_limit")
	case errors.Is(err, services.ErrGatewayRevoked):
		return gwError(c, fiber.StatusUnauthorized, "unauthorized")
	case err != nil:
		return err
	}
	return c.JSON(heartbeatResponse(res))
}

// ---- E3 catalog --------------------------------------------------------

type gatewayCatalogRequest struct {
	Connectors []struct {
		ConnectorID string `json:"connector_id"`
		Kind        string `json:"kind"`
		Targets     []struct {
			TargetID                string  `json:"target_id"`
			Namespace               string  `json:"namespace,omitempty"`
			Name                    string  `json:"name,omitempty"`
			RefreshIntervalSeconds  *int    `json:"refresh_interval_seconds,omitempty"`
			ProgressDeadlineSeconds *int    `json:"progress_deadline_seconds,omitempty"`
			Identity                *string `json:"identity,omitempty"`
		} `json:"targets"`
	} `json:"connectors"`
}

type gatewayCatalogResponse struct {
	Accepted       int    `json:"accepted"`
	TargetsStale   int    `json:"targets_stale"`
	CatalogVersion string `json:"catalog_version"`
}

// Catalog handles PUT /api/v1/gateways/:id/catalog (E3). Full replace,
// idempotent. Advertising never approves or binds anything.
func (h *Gateways) Catalog(c fiber.Ctx) error {
	id, err := authenticatedGateway(c)
	if err != nil {
		return err
	}
	var req gatewayCatalogRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	}
	conns := make([]services.GatewayCatalogConnector, 0, len(req.Connectors))
	for _, rc := range req.Connectors {
		cc := services.GatewayCatalogConnector{ConnectorID: rc.ConnectorID, Kind: rc.Kind}
		for _, t := range rc.Targets {
			cc.Targets = append(cc.Targets, services.GatewayCatalogTarget{
				TargetID: t.TargetID, Namespace: t.Namespace, Name: t.Name,
				RefreshIntervalSeconds: t.RefreshIntervalSeconds, ProgressDeadlineSeconds: t.ProgressDeadlineSeconds,
				Identity: t.Identity,
			})
		}
		conns = append(conns, cc)
	}
	res, err := h.svc.PutCatalog(c.Context(), id, conns)
	switch {
	case errors.Is(err, services.ErrGatewayInvalidRequest):
		return gwError(c, fiber.StatusBadRequest, "invalid_request")
	case errors.Is(err, services.ErrGatewayRevoked):
		return gwError(c, fiber.StatusUnauthorized, "unauthorized")
	case err != nil:
		return err
	}
	return c.JSON(gatewayCatalogResponse{Accepted: res.Accepted, TargetsStale: res.TargetsStale, CatalogVersion: res.CatalogVersion})
}

// ---- admin views ---------------------------------------------------------

type gatewayView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Boundary         string   `json:"boundary"`
	EnvironmentID    *string  `json:"environment_id,omitempty"`
	Status           string   `json:"status"`
	GatewayVersion   string   `json:"gateway_version,omitempty"`
	ContractVersions []string `json:"contract_versions"`
	MaxReplicas      int      `json:"max_replicas"`
	MaxInflightTasks int      `json:"max_inflight_tasks"`
	CatalogVersion   string   `json:"catalog_version,omitempty"`
	CatalogUpdatedAt *string  `json:"catalog_updated_at,omitempty"`
	LastSeenAt       *string  `json:"last_seen_at,omitempty"`
	LastStatus       string   `json:"last_status,omitempty"`
	EnrolledAt       *string  `json:"enrolled_at,omitempty"`
	RevokedAt        *string  `json:"revoked_at,omitempty"`
	ReplicasSeen     int      `json:"replicas_seen"`
	// OverPrivileged is true while a replica seen in the replica window
	// last reported over_privileged; OverPrivilegedReportedAt is that
	// replica's latest heartbeat (api#298). The console alerts on this
	// flag instead of deriving it from last_status.
	OverPrivileged           bool    `json:"over_privileged"`
	OverPrivilegedReportedAt *string `json:"over_privileged_reported_at,omitempty"`
	CreatedBy                string  `json:"created_by"`
	CreatedAt                string  `json:"created_at"`
}

// gatewayConnectorSummaryView is a connector line of GET /admin/gateways:
// kind, status and target count, no target ids or names (api#298).
type gatewayConnectorSummaryView struct {
	ID          string `json:"id"`
	ConnectorID string `json:"connector_id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	TargetCount int    `json:"target_count"`
}

// gatewayListItem is one GET /admin/gateways item: the Gateway view plus
// its connector summary.
type gatewayListItem struct {
	gatewayView
	Connectors []gatewayConnectorSummaryView `json:"connectors"`
}

func toGatewayView(g *storage.Gateway) gatewayView {
	return gatewayView{
		ID: g.ID.String(), Name: g.Name, Boundary: g.Boundary, EnvironmentID: uuidPtr(g.EnvironmentID),
		Status: string(g.Status), GatewayVersion: g.GatewayVersion, ContractVersions: g.ContractVersions,
		MaxReplicas: g.MaxReplicas, MaxInflightTasks: g.MaxInflightTasks,
		CatalogVersion: g.CatalogVersion, CatalogUpdatedAt: timePtr(g.CatalogUpdatedAt),
		LastSeenAt: timePtr(g.LastSeenAt), LastStatus: g.LastStatus,
		EnrolledAt: timePtr(g.EnrolledAt), RevokedAt: timePtr(g.RevokedAt),
		ReplicasSeen: g.ReplicasSeen, OverPrivileged: g.OverPrivileged(), OverPrivilegedReportedAt: timePtr(g.OverPrivilegedAt),
		CreatedBy: g.CreatedBy, CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339),
	}
}

type gatewayReplicaView struct {
	ReplicaID      string                        `json:"replica_id"`
	GatewayVersion string                        `json:"gateway_version,omitempty"`
	Status         string                        `json:"status"`
	InFlight       int                           `json:"in_flight"`
	CatalogVersion string                        `json:"catalog_version,omitempty"`
	Connectors     []gatewayReplicaConnectorView `json:"connectors"`
	FirstSeenAt    string                        `json:"first_seen_at"`
	LastSeenAt     string                        `json:"last_seen_at"`
}

// gatewayReplicaConnectorView is a connector line of a replica: enums
// only, as before api#308. The scope digest is shown once per connector
// (gatewayConnectorView), not per replica.
type gatewayReplicaConnectorView struct {
	ConnectorID string `json:"connector_id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
}

type gatewayConnectorView struct {
	ID               string              `json:"id"`
	ConnectorID      string              `json:"connector_id"`
	Kind             string              `json:"kind"`
	Status           string              `json:"status"`
	Targets          []gatewayTargetView `json:"targets"`
	ApprovedBy       string              `json:"approved_by,omitempty"`
	ApprovedAt       *string             `json:"approved_at,omitempty"`
	LastAdvertisedAt *string             `json:"last_advertised_at,omitempty"`
	// Discovery (api#308). StatusReason is scope_changed,
	// scope_mismatch_between_replicas or snapshot_stale. ScopeDigest is
	// the digest every live replica reports now, the one an approve body
	// carries; ScopeMismatch is true while they disagree. Platform
	// admins only (gateway.list): the catalog read never carries them.
	StatusReason        string   `json:"status_reason,omitempty"`
	ScopeDigest         string   `json:"scope_digest,omitempty"`
	ScopeMismatch       bool     `json:"scope_mismatch,omitempty"`
	ApprovedScopeDigest string   `json:"approved_scope_digest,omitempty"`
	DiscoveryEnabled    bool     `json:"discovery_enabled,omitempty"`
	DiscoveryGeneration int64    `json:"discovery_generation,omitempty"`
	LastDiscoveryAt     *string  `json:"last_discovery_at,omitempty"`
	AllowedProjects     []string `json:"allowed_projects,omitempty"`
}

func replicaConnectors(hs []storage.GatewayConnectorHealth) []gatewayReplicaConnectorView {
	out := make([]gatewayReplicaConnectorView, 0, len(hs))
	for _, h := range hs {
		out = append(out, gatewayReplicaConnectorView{ConnectorID: h.ConnectorID, Kind: h.Kind, Status: h.Status})
	}
	return out
}

// withScope adds what the live replicas report to a connector view.
func (v gatewayConnectorView) withScope(sc storage.GatewayConnectorScope) gatewayConnectorView {
	v.ScopeDigest, v.ScopeMismatch, v.DiscoveryEnabled = sc.ReportedDigest, sc.Mismatch, sc.DiscoveryEnabled
	return v
}

// gatewayTargetView is an advertised target in the admin read. It
// carries identity_status (api#312) and never the identity digest
// itself: the console needs the state, not the value.
type gatewayTargetView struct {
	TargetID                string `json:"target_id"`
	Namespace               string `json:"namespace,omitempty"`
	Name                    string `json:"name,omitempty"`
	RefreshIntervalSeconds  *int   `json:"refresh_interval_seconds,omitempty"`
	ProgressDeadlineSeconds *int   `json:"progress_deadline_seconds,omitempty"`
	Stale                   bool   `json:"stale"`
	// IdentityStatus is unpinned (no identity advertised yet), pinned or
	// identity_changed (bindings suspended until re-confirmed).
	IdentityStatus string `json:"identity_status"`
	// IdentityChangeTrigger is set while identity_changed (api#314):
	// catalog (the Gateway advertised another identity) or
	// gateway_reported (the Gateway refused the object, the advertised
	// identity is still the pin). A re-confirm of a gateway_reported
	// change keeps the pin, so it flips back on the next such error until
	// the integrator fixes the settings uid.
	IdentityChangeTrigger string `json:"identity_change_trigger,omitempty"`
}

// Identity status of a target with no pin, as the admin read shows it.
const gatewayTargetUnpinned = "unpinned"

func toConnectorView(c *storage.GatewayConnector) gatewayConnectorView {
	targets := make([]gatewayTargetView, 0, len(c.Targets))
	for _, t := range c.Targets {
		status := t.IdentityStatus
		if status == "" {
			status = gatewayTargetUnpinned
		}
		targets = append(targets, gatewayTargetView{
			TargetID: t.TargetID, Namespace: t.Namespace, Name: t.Name,
			RefreshIntervalSeconds: t.RefreshIntervalSeconds, ProgressDeadlineSeconds: t.ProgressDeadlineSeconds,
			Stale: t.Stale, IdentityStatus: status, IdentityChangeTrigger: t.ChangeTrigger(),
		})
	}
	return gatewayConnectorView{
		ID: c.ID.String(), ConnectorID: c.Name, Kind: c.Kind, Status: c.Status, Targets: targets,
		ApprovedBy: c.ApprovedBy, ApprovedAt: timePtr(c.ApprovedAt), LastAdvertisedAt: timePtr(c.LastAdvertisedAt),
		StatusReason: c.StatusReason, ApprovedScopeDigest: c.ApprovedScopeDigest,
		DiscoveryGeneration: c.DiscoveryGeneration, LastDiscoveryAt: timePtr(c.LastDiscoveryAt),
		AllowedProjects: c.AllowedProjects,
	}
}

type gatewayBindingView struct {
	ID                   string   `json:"id"`
	GatewayID            string   `json:"gateway_id"`
	ProjectID            string   `json:"project_id"`
	EnvironmentID        string   `json:"environment_id"`
	SecretID             *string  `json:"secret_id,omitempty"`
	ProviderConnectionID *string  `json:"provider_connection_id,omitempty"`
	SecretRef            string   `json:"secret_ref,omitempty"`
	ExpectedStages       []string `json:"expected_stages"`
	ArgoCDConnectorID    *string  `json:"argocd_connector_id,omitempty"`
	ArgoCDTargetID       string   `json:"argocd_target_id,omitempty"`
	ObservationTimeoutS  int      `json:"observation_timeout_seconds"`
	Enabled              bool     `json:"enabled"`
	// SuspendedReason is identity_changed while the binding's target is
	// identity_changed: no dispatch and no evidence (api#312).
	SuspendedReason string `json:"suspended_reason,omitempty"`
	CreatedBy       string `json:"created_by"`
	CreatedAt       string `json:"created_at"`
}

func toBindingView(b *storage.GatewayBinding) gatewayBindingView {
	return gatewayBindingView{
		ID: b.ID.String(), GatewayID: b.GatewayID.String(), ProjectID: b.ProjectID.String(),
		EnvironmentID: b.EnvironmentID.String(), SecretID: uuidPtr(b.SecretID),
		ProviderConnectionID: uuidPtr(b.ProviderConnectionID), SecretRef: b.SecretRef,
		ExpectedStages: b.ExpectedStages, ArgoCDConnectorID: uuidPtr(b.ArgoCDConnectorID),
		ArgoCDTargetID: b.ArgoCDTargetID, ObservationTimeoutS: b.ObservationTimeoutS, Enabled: b.Enabled,
		SuspendedReason: b.SuspendedReason, CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt.UTC().Format(time.RFC3339),
	}
}

type gatewayTokenView struct {
	ID                  string  `json:"id"`
	ExpectedClusterName string  `json:"expected_cluster_name,omitempty"`
	ExpiresAt           string  `json:"expires_at"`
	ConsumedAt          *string `json:"consumed_at,omitempty"`
	RevokedAt           *string `json:"revoked_at,omitempty"`
	CreatedBy           string  `json:"created_by"`
	CreatedAt           string  `json:"created_at"`
}

// ---- admin routes --------------------------------------------------------

func adminActor(c fiber.Ctx) (string, error) {
	actor, ok := auth.IdentityFromContext(c.Context())
	if !ok || actor == "" {
		return "", fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	return actor, nil
}

func pathUUID(c fiber.Ctx, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Params(name))
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusBadRequest, "invalid_id")
	}
	return id, nil
}

type createGatewayRequest struct {
	Name             string     `json:"name"`
	Boundary         string     `json:"boundary"`
	EnvironmentID    *uuid.UUID `json:"environment_id,omitempty"`
	MaxReplicas      int        `json:"max_replicas,omitempty"`
	MaxInflightTasks int        `json:"max_inflight_tasks,omitempty"`
}

// AdminCreate handles POST /admin/gateways (gateway.mint, fresh MFA).
func (h *Gateways) AdminCreate(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	var req createGatewayRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
	}
	g, err := h.svc.CreateGateway(c.Context(), services.CreateGatewayInput{
		Name: req.Name, Boundary: req.Boundary, EnvironmentID: req.EnvironmentID,
		MaxReplicas: req.MaxReplicas, MaxInflightTasks: req.MaxInflightTasks, CreatedBy: actor,
	})
	switch {
	case errors.Is(err, services.ErrGatewayInvalidRequest):
		return fiber.NewError(fiber.StatusBadRequest, "invalid_"+strings.TrimPrefix(err.Error(), services.ErrGatewayInvalidRequest.Error()+": "))
	case errors.Is(err, storage.ErrGatewayNameTaken):
		return fiber.NewError(fiber.StatusConflict, "gateway_name_taken")
	case err != nil:
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(toGatewayView(g))
}

type mintGatewayTokenRequest struct {
	ExpiresInSeconds    int    `json:"expires_in_seconds,omitempty"`
	ExpectedClusterName string `json:"expected_cluster_name,omitempty"`
}

type mintGatewayTokenResponse struct {
	ID              string `json:"id"`
	GatewayID       string `json:"gateway_id"`
	EnrollmentToken string `json:"enrollment_token"`
	ExpiresAt       string `json:"expires_at"`
}

// AdminMintToken handles POST /admin/gateways/:id/enrollment-token
// (gateway.mint, fresh MFA). The token is in this response only.
func (h *Gateways) AdminMintToken(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	var req mintGatewayTokenRequest
	if len(bytes.TrimSpace(c.Body())) > 0 {
		if err := decodeStrict(c.Body(), &req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
		}
	}
	res, err := h.svc.MintEnrollmentToken(c.Context(), services.MintGatewayTokenInput{
		GatewayID: id, ExpiresInSeconds: req.ExpiresInSeconds, ExpectedClusterName: req.ExpectedClusterName, CreatedBy: actor,
	})
	switch {
	case errors.Is(err, services.ErrGatewayInvalidRequest):
		return fiber.NewError(fiber.StatusBadRequest, "invalid_expected_cluster_name")
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "gateway_not_found")
	case errors.Is(err, services.ErrGatewayAlreadyEnrolled):
		return fiber.NewError(fiber.StatusConflict, "gateway_not_pending")
	case err != nil:
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(mintGatewayTokenResponse{
		ID: res.ID.String(), GatewayID: res.GatewayID.String(), EnrollmentToken: res.Token,
		ExpiresAt: res.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// AdminRevokeToken handles POST /admin/gateway-enrollment-tokens/:id/revoke
// (gateway.mint, fresh MFA).
func (h *Gateways) AdminRevokeToken(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	if err := h.svc.RevokeEnrollmentToken(c.Context(), id, actor); err != nil {
		if errors.Is(err, storage.ErrGatewayEnrollmentTokenNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "enrollment_token_not_revocable")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

type revokeGatewayRequest struct {
	Reason string `json:"reason,omitempty"`
}

// cacheUnconfirmedMessages are the console texts for the 503 codes.
var cacheUnconfirmedMessages = map[string]string{
	"revoked_cache_unconfirmed": "Saved, but the credential cache could not be updated yet, so the credential may still be accepted for a moment. Repeat the request to confirm.",
	"enabled_cache_unconfirmed": "Saved, but the credential cache could not be updated yet, so the Gateway may still be refused for a moment. Repeat the request to confirm.",
}

// cacheUnconfirmed answers 503 for services.ErrCredentialCacheUnconfirmed:
// the change is saved, the auth cache isn't in line with it yet, and
// repeating the call is safe. It writes the body itself, in the stableErr
// shape plus the correlation id, because the app's error handler replaces
// every 5xx message with a generic one and the admin needs to know which
// way the cache may still be wrong.
func cacheUnconfirmed(c fiber.Ctx, code string) error {
	rid, _ := c.Locals(string(middleware.CtxKeyRequestID)).(string)
	c.Set(fiber.HeaderRetryAfter, "1")
	return stableErr(c, fiber.StatusServiceUnavailable, code, cacheUnconfirmedMessages[code], map[string]any{"correlation_id": rid})
}

// AdminRevoke handles POST /admin/gateways/:id/revoke (gateway.revoke,
// fresh MFA). The next heartbeat or catalog upload gets 401.
func (h *Gateways) AdminRevoke(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	var req revokeGatewayRequest
	if len(bytes.TrimSpace(c.Body())) > 0 {
		if err := decodeStrict(c.Body(), &req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
		}
	}
	if req.Reason != "" && !validReason(req.Reason) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_reason")
	}
	g, err := h.svc.Revoke(c.Context(), id, actor, req.Reason)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "gateway_not_found")
	case errors.Is(err, services.ErrCredentialCacheUnconfirmed):
		return cacheUnconfirmed(c, "revoked_cache_unconfirmed")
	case errors.Is(err, storage.ErrGatewayAlreadyRevoked):
		return fiber.NewError(fiber.StatusConflict, "gateway_already_revoked")
	case err != nil:
		return err
	}
	return c.JSON(toGatewayView(g))
}

// validReason bounds a revoke reason to a short code-like label.
func validReason(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// AdminList handles GET /admin/gateways (gateway.list). Each item carries
// a compact connector summary, so the console needs no detail call per
// Gateway.
func (h *Gateways) AdminList(c fiber.Ctx) error {
	gs, err := h.svc.List(c.Context())
	if err != nil {
		return err
	}
	conns, err := h.svc.ConnectorSummaries(c.Context())
	if err != nil {
		return err
	}
	items := make([]gatewayListItem, 0, len(gs))
	for _, g := range gs {
		it := gatewayListItem{gatewayView: toGatewayView(g), Connectors: []gatewayConnectorSummaryView{}}
		for _, cn := range conns[g.ID] {
			it.Connectors = append(it.Connectors, gatewayConnectorSummaryView{
				ID: cn.ID.String(), ConnectorID: cn.Name, Kind: cn.Kind, Status: cn.Status, TargetCount: cn.TargetCount,
			})
		}
		items = append(items, it)
	}
	return c.JSON(fiber.Map{"items": items})
}

// AdminGet handles GET /admin/gateways/:id (gateway.list).
func (h *Gateways) AdminGet(c fiber.Ctx) error {
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	d, err := h.svc.Get(c.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "gateway_not_found")
	}
	if err != nil {
		return err
	}
	replicas := make([]gatewayReplicaView, 0, len(d.Replicas))
	for _, r := range d.Replicas {
		replicas = append(replicas, gatewayReplicaView{
			ReplicaID: r.ReplicaID.String(), GatewayVersion: r.GatewayVersion, Status: r.Status, InFlight: r.InFlight,
			CatalogVersion: r.CatalogVersion, Connectors: replicaConnectors(r.ConnectorHealth),
			FirstSeenAt: r.FirstSeenAt.UTC().Format(time.RFC3339), LastSeenAt: r.LastSeenAt.UTC().Format(time.RFC3339),
		})
	}
	scopes, err := h.svc.ConnectorScopes(c.Context(), id, d.Connectors)
	if err != nil {
		return err
	}
	conns := make([]gatewayConnectorView, 0, len(d.Connectors))
	for _, cn := range d.Connectors {
		conns = append(conns, toConnectorView(cn).withScope(scopes[cn.ID]))
	}
	bindings := make([]gatewayBindingView, 0, len(d.Bindings))
	for _, b := range d.Bindings {
		bindings = append(bindings, toBindingView(b))
	}
	tokens := make([]gatewayTokenView, 0, len(d.Tokens))
	for _, t := range d.Tokens {
		tokens = append(tokens, gatewayTokenView{
			ID: t.ID.String(), ExpectedClusterName: t.ExpectedClusterName, ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339),
			ConsumedAt: timePtr(t.ConsumedAt), RevokedAt: timePtr(t.RevokedAt), CreatedBy: t.CreatedBy,
			CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return c.JSON(fiber.Map{
		"gateway": toGatewayView(d.Gateway), "replicas": replicas, "connectors": conns,
		"bindings": bindings, "enrollment_tokens": tokens,
	})
}

// AdminApproveConnector handles POST
// /admin/gateways/:id/connectors/:cid/approve (gateway.bind, fresh MFA).
func (h *Gateways) AdminApproveConnector(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	cid, err := pathUUID(c, "cid")
	if err != nil {
		return err
	}
	// api#308 (A3): the approved scope digest. An empty body stays valid
	// for a contract 1 Gateway.
	var req struct {
		ScopeDigest string `json:"scope_digest"`
	}
	if len(bytes.TrimSpace(c.Body())) > 0 {
		if err := decodeStrict(c.Body(), &req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
		}
	}
	cn, err := h.svc.ApproveConnector(c.Context(), id, cid, req.ScopeDigest, actor)
	switch {
	case errors.Is(err, services.ErrGatewayDiscoveryInvalid):
		return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "connector_not_found")
	case errors.Is(err, storage.ErrGatewayConnectorNotApprovable):
		return fiber.NewError(fiber.StatusConflict, "connector_not_advertised")
	case errors.Is(err, storage.ErrGatewayScopeDigestChanged):
		return fiber.NewError(fiber.StatusConflict, "scope_digest_changed")
	case errors.Is(err, storage.ErrGatewayProjectMappingIncomplete):
		return fiber.NewError(fiber.StatusConflict, "project_mapping_incomplete")
	case errors.Is(err, storage.ErrGatewayConnectorOverPrivileged):
		return fiber.NewError(fiber.StatusConflict, "connector_over_privileged")
	case err != nil:
		return err
	}
	return c.JSON(toConnectorView(cn))
}

// AdminConfirmTargetIdentity handles POST
// /admin/gateways/:id/connectors/:cid/targets/:tid/confirm-identity
// (gateway.bind, fresh MFA; api#312). It takes no body: the identity the
// Gateway now advertises becomes the pin, and the target's bindings
// resume. Answers the connector view.
func (h *Gateways) AdminConfirmTargetIdentity(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	cid, err := pathUUID(c, "cid")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(c.Body())) > 0 {
		var empty struct{}
		if err := decodeStrict(c.Body(), &empty); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
		}
	}
	cn, err := h.svc.ConfirmTargetIdentity(c.Context(), id, cid, c.Params("tid"), actor)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "connector_not_found")
	case errors.Is(err, storage.ErrGatewayTargetNotFound):
		return fiber.NewError(fiber.StatusNotFound, "target_not_found")
	case errors.Is(err, storage.ErrGatewayTargetIdentityNotChanged):
		return fiber.NewError(fiber.StatusConflict, "target_identity_not_changed")
	case errors.Is(err, storage.ErrGatewayTargetStale):
		return fiber.NewError(fiber.StatusConflict, "target_stale")
	case err != nil:
		return err
	}
	return c.JSON(toConnectorView(cn))
}

type createBindingRequest struct {
	GatewayID            uuid.UUID  `json:"gateway_id"`
	ProjectID            *uuid.UUID `json:"project_id,omitempty"`
	EnvironmentID        uuid.UUID  `json:"environment_id"`
	SecretID             *uuid.UUID `json:"secret_id,omitempty"`
	ProviderConnectionID *uuid.UUID `json:"provider_connection_id,omitempty"`
	SecretRef            string     `json:"secret_ref,omitempty"`
	ArgoCDConnectorID    uuid.UUID  `json:"argocd_connector_id"`
	ArgoCDTargetID       string     `json:"argocd_target_id"`
	ObservationTimeoutS  int        `json:"observation_timeout_seconds,omitempty"`
}

// AdminCreateBinding handles POST /admin/gateway-bindings (gateway.bind,
// fresh MFA). Release 1 binds an Argo CD target only; the strict decoder
// refuses eso or rollout fields rather than dropping them.
func (h *Gateways) AdminCreateBinding(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	var req createBindingRequest
	if err := decodeStrict(c.Body(), &req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
	}
	if req.GatewayID == uuid.Nil || req.EnvironmentID == uuid.Nil || req.ArgoCDConnectorID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid_request")
	}
	b, err := h.svc.CreateBinding(c.Context(), services.CreateBindingInput{
		GatewayID: req.GatewayID, EnvironmentID: req.EnvironmentID, ProjectID: req.ProjectID,
		SecretID: req.SecretID, ProviderConnectionID: req.ProviderConnectionID, SecretRef: req.SecretRef,
		ArgoCDConnectorID: req.ArgoCDConnectorID, ArgoCDTargetID: req.ArgoCDTargetID,
		ObservationTimeoutS: req.ObservationTimeoutS, CreatedBy: actor,
	})
	if code := services.BindingErrorCode(err); code != "" {
		status := fiber.StatusBadRequest
		switch code {
		case "binding_exists":
			status = fiber.StatusConflict
		case "gateway_not_found", "environment_not_found", "connector_not_found", "provider_connection_not_found", "reference_not_found":
			status = fiber.StatusNotFound
		case "connector_not_approved", "target_stale", "target_identity_changed", "gateway_revoked":
			status = fiber.StatusConflict
		}
		return fiber.NewError(status, code)
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(toBindingView(b))
}

// AdminListBindings handles GET /admin/gateway-bindings (gateway.list;
// binding writes stay on gateway.bind), optionally filtered by
// ?gateway_id=.
func (h *Gateways) AdminListBindings(c fiber.Ctx) error {
	var filter *uuid.UUID
	if raw := c.Query("gateway_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid_gateway_id")
		}
		filter = &id
	}
	bs, err := h.svc.ListBindings(c.Context(), filter)
	if err != nil {
		return err
	}
	items := make([]gatewayBindingView, 0, len(bs))
	for _, b := range bs {
		items = append(items, toBindingView(b))
	}
	return c.JSON(fiber.Map{"items": items})
}

// AdminDeleteBinding handles DELETE /admin/gateway-bindings/:id
// (gateway.bind, fresh MFA).
func (h *Gateways) AdminDeleteBinding(c fiber.Ctx) error {
	actor, err := adminActor(c)
	if err != nil {
		return err
	}
	id, err := pathUUID(c, "id")
	if err != nil {
		return err
	}
	if err := h.svc.DeleteBinding(c.Context(), id, actor); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "binding_not_found")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
