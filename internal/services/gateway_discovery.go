package services

// Argo CD discovery, service side (ADR 0002 S4, api#308; gateway
// docs/design/discovery-contract.md). This file holds the heartbeat
// audit and the scope-aware approve (A3).
//
// Audit metadata is ids, enums, one-way digests and counts. No
// AppProject, namespace or Application name, no URL and no uid.

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// ErrGatewayDiscoveryInvalid wraps an approve body that breaks its
// schema (400).
var ErrGatewayDiscoveryInvalid = errors.New("services: invalid discovery request")

// WithDiscoveryLeaseTTL sets the discovery lease TTL (decision E-3),
// clamped to 60 to 900 seconds. Zero keeps the 300 second default.
func (s *GatewayService) WithDiscoveryLeaseTTL(ttl time.Duration) *GatewayService {
	if ttl == 0 {
		return s
	}
	s.discoveryLeaseTTL = min(max(ttl, storage.GatewayDiscoveryLeaseTTLMin), storage.GatewayDiscoveryLeaseTTLMax)
	return s
}

// auditDiscoveryHeartbeat writes the audit rows for the scope events of
// one contract 2 heartbeat. A mismatch between replicas is a state, not
// a decision: it is visible as status_reason and not audited.
func (s *GatewayService) auditDiscoveryHeartbeat(ctx context.Context, gatewayID, replicaID uuid.UUID, d *storage.GatewayDiscoveryHeartbeat) {
	actor := gatewayActor(gatewayID)
	for _, ev := range d.ScopeEvents {
		if ev.Event == storage.GatewayScopeEventMismatch {
			// Replicas disagree: dispatch paused and leased tasks requeued.
			s.appendAudit(ctx, &storage.AuditEvent{
				Actor: actor, Action: "gateway.connector.scope_mismatch", Resource: actor, Status: storage.AuditStatusFailure,
				Metadata: map[string]any{
					"gateway_id": gatewayID.String(), "connector_id": ev.ConnectorID.String(), "replica_id": replicaID.String(),
					"tasks_requeued": ev.TasksRequeued,
				},
			})
			continue
		}
		meta := map[string]any{
			"gateway_id": gatewayID.String(), "connector_id": ev.ConnectorID.String(), "replica_id": replicaID.String(),
			"scope_digest_after": ev.New, "adopted": ev.Event == storage.GatewayScopeEventAdopted,
		}
		if ev.Old != "" {
			meta["scope_digest_before"] = ev.Old
		}
		status := storage.AuditStatusSuccess
		if ev.Event == storage.GatewayScopeEventChanged {
			status = storage.AuditStatusFailure
			meta["bindings_suspended"] = ev.BindingsSuspended
			meta["tasks_requeued"] = ev.TasksRequeued
			if ev.AppProjectsBefore != nil {
				meta["app_project_count_before"] = *ev.AppProjectsBefore
			}
		}
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "gateway.connector.scope_changed", Resource: actor, Status: status, Metadata: meta,
		})
	}
}

// auditOverPrivilegedLatch records each connector a heartbeat latched
// back to advertised for over_privileged.
func (s *GatewayService) auditOverPrivilegedLatch(ctx context.Context, gatewayID, replicaID uuid.UUID, evs []storage.GatewayScopeEvent) {
	actor := gatewayActor(gatewayID)
	for _, ev := range evs {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "gateway.connector.approval_reset", Resource: actor, Status: storage.AuditStatusFailure,
			Metadata: map[string]any{
				"gateway_id": gatewayID.String(), "connector_id": ev.ConnectorID.String(), "replica_id": replicaID.String(),
				"reason": storage.GatewayConnectorReasonOverPrivileged, "tasks_requeued": ev.TasksRequeued,
			},
		})
	}
}

// ApproveConnector approves an advertised connector of a Gateway (A3).
// scopeDigest is the digest the admin was shown: required when the live
// replicas report one, and it must equal what they report now
// (storage.ErrGatewayScopeDigestChanged). With discovery on, every
// allowed AppProject must map to a team first
// (storage.ErrGatewayProjectMappingIncomplete). Bindings suspended for
// scope_changed resume.
func (s *GatewayService) ApproveConnector(ctx context.Context, gatewayID, connectorID uuid.UUID, scopeDigest, by string) (*storage.GatewayConnector, error) {
	if scopeDigest != "" && !gatewaySHA256Re.MatchString(scopeDigest) {
		return nil, ErrGatewayDiscoveryInvalid
	}
	now := s.now().UTC()
	out, err := s.store.ApproveConnectorScope(ctx, gatewayID, connectorID, scopeDigest, by, now, now.Add(-GatewayReplicaWindow))
	if err != nil {
		return nil, err
	}
	meta := map[string]any{
		"gateway_id": gatewayID.String(), "connector_id": out.Connector.ID.String(), "kind": out.Connector.Kind,
		"bindings_resumed": out.BindingsResumed,
	}
	if out.ScopeDigest != "" {
		meta["scope_digest"] = out.ScopeDigest
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, by), Action: "gateway.connector.approved", Resource: gatewayActor(gatewayID),
		Status: storage.AuditStatusSuccess, Metadata: meta,
	})
	return out.Connector, nil
}

// ConnectorScopes returns what the live replicas report for each
// connector of a Gateway, keyed by connector row id, for the admin read.
func (s *GatewayService) ConnectorScopes(ctx context.Context, gatewayID uuid.UUID, conns []*storage.GatewayConnector) (map[uuid.UUID]storage.GatewayConnectorScope, error) {
	since := s.now().UTC().Add(-GatewayReplicaWindow)
	out := make(map[uuid.UUID]storage.GatewayConnectorScope, len(conns))
	for _, c := range conns {
		if c.Kind != GatewayKindArgoCD {
			continue
		}
		sc, err := s.store.ConnectorScope(ctx, gatewayID, c.Name, since)
		if err != nil {
			return nil, err
		}
		out[c.ID] = sc
	}
	return out, nil
}
