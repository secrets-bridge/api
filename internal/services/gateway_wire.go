package services

// Validation for the Gateway wire bodies (E1 to E3) and the admin
// inputs (api#293). Every string the Gateway sends is an id, an enum or a
// tightly patterned name, matching the patterns in the gateway repo's
// internal/contract and schemas/*.json, so a URL, a namespace/name pair,
// a message or a value has nowhere to go. Errors name the failing field,
// never its content.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// ErrGatewayInvalidRequest is a body that breaks the contract. The
// handler answers 400 invalid_request.
var ErrGatewayInvalidRequest = errors.New("services: invalid gateway request")

func gatewayInvalid(field string) error {
	return fmt.Errorf("%w: %s", ErrGatewayInvalidRequest, field)
}

var (
	// gatewayLocalIDRe is the schema localId: a DNS label. It cannot hold
	// a URL, a path or a namespace/name separator.
	gatewayLocalIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Kubernetes namespace (RFC 1123 label) and object name (RFC 1123
	// subdomain), display only.
	gatewayDNSLabelRe     = gatewayLocalIDRe
	gatewayDNSSubdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	gatewayVersionRe      = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]{1,32})?$`)
	gatewayContractRe     = regexp.MustCompile(`^[0-9]{1,4}$`)
	gatewayCatalogVerRe   = regexp.MustCompile(`^(sha256:[0-9a-f]{64})?$`)
	gatewayUUIDRe         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	gatewayNameRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	gatewayClusterNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Bounds. The 64 KiB body cap is the outer limit; these keep the stored
// JSON small and the loops bounded.
const (
	gatewayMaxConnectors        = 64
	gatewayMaxTargetsPerConn    = 256
	gatewayMaxTargetsTotal      = 1024
	gatewayMaxContractVersions  = 16
	gatewayMaxInFlight          = 100000
	gatewayMaxIntervalSeconds   = 1000000000
	gatewayMaxVersionLen        = 64
	gatewayMaxBoundaryLen       = 128
	gatewayMaxSecretRefLen      = 512
	gatewayContractVersion      = "1"
	gatewayHeartbeatIntervalSec = 30
	gatewayClaimPollSec         = 5
)

// Connector kinds a catalog may advertise. Release 1 binds argocd only
// (gateway#12); the others are recorded so the tables stay generic.
const (
	GatewayKindESO     = "eso"
	GatewayKindRollout = "rollout"
	GatewayKindArgoCD  = "argocd"
)

var (
	gatewayKinds          = map[string]bool{GatewayKindESO: true, GatewayKindRollout: true, GatewayKindArgoCD: true}
	gatewayReplicaStatus  = map[string]bool{"ok": true, "degraded": true, "not_ready": true, "over_privileged": true, "shutting_down": true}
	gatewayConnectorState = map[string]bool{"ok": true, "degraded": true, "unreachable": true, "unauthorized": true, "over_privileged": true}
)

// ValidGatewayLocalID reports whether s is a connector or target id.
func ValidGatewayLocalID(s string) bool { return gatewayLocalIDRe.MatchString(s) }

// GatewayHeartbeatInput is the E2 body.
type GatewayHeartbeatInput struct {
	ReplicaID        string
	GatewayVersion   string
	ContractVersions []string
	Status           string
	InFlight         int
	CatalogVersion   string
	Connectors       []storage.GatewayConnectorHealth
}

func (in GatewayHeartbeatInput) validate() (uuid.UUID, error) {
	if !gatewayUUIDRe.MatchString(in.ReplicaID) {
		return uuid.Nil, gatewayInvalid("replica_id")
	}
	replica, err := uuid.Parse(in.ReplicaID)
	if err != nil {
		return uuid.Nil, gatewayInvalid("replica_id")
	}
	if len(in.GatewayVersion) > gatewayMaxVersionLen || !gatewayVersionRe.MatchString(in.GatewayVersion) {
		return uuid.Nil, gatewayInvalid("gateway_version")
	}
	if len(in.ContractVersions) == 0 || len(in.ContractVersions) > gatewayMaxContractVersions {
		return uuid.Nil, gatewayInvalid("contract_versions")
	}
	seen := map[string]bool{}
	for _, v := range in.ContractVersions {
		if !gatewayContractRe.MatchString(v) || seen[v] {
			return uuid.Nil, gatewayInvalid("contract_versions")
		}
		seen[v] = true
	}
	if !gatewayReplicaStatus[in.Status] {
		return uuid.Nil, gatewayInvalid("status")
	}
	if in.InFlight < 0 || in.InFlight > gatewayMaxInFlight {
		return uuid.Nil, gatewayInvalid("in_flight")
	}
	if !gatewayCatalogVerRe.MatchString(in.CatalogVersion) {
		return uuid.Nil, gatewayInvalid("catalog_version")
	}
	if len(in.Connectors) > gatewayMaxConnectors {
		return uuid.Nil, gatewayInvalid("connectors")
	}
	ids := map[string]bool{}
	for _, c := range in.Connectors {
		if !ValidGatewayLocalID(c.ConnectorID) || ids[c.ConnectorID] {
			return uuid.Nil, gatewayInvalid("connectors.connector_id")
		}
		ids[c.ConnectorID] = true
		if !gatewayKinds[c.Kind] {
			return uuid.Nil, gatewayInvalid("connectors.kind")
		}
		if !gatewayConnectorState[c.Status] {
			return uuid.Nil, gatewayInvalid("connectors.status")
		}
	}
	return replica, nil
}

// GatewayCatalogTarget is one target in an E3 body.
type GatewayCatalogTarget struct {
	TargetID                string
	Namespace               string
	Name                    string
	RefreshIntervalSeconds  *int
	ProgressDeadlineSeconds *int
	// Identity is the optional scoped identity digest of an Argo CD
	// target (api#312), the same value as evidence
	// resource.identity_digest. Nil when the Gateway sent none.
	Identity *string
}

// GatewayCatalogConnector is one connector in an E3 body.
type GatewayCatalogConnector struct {
	ConnectorID string
	Kind        string
	Targets     []GatewayCatalogTarget
}

func validInterval(p *int) bool { return p == nil || (*p >= 0 && *p <= gatewayMaxIntervalSeconds) }

// normalizeCatalog validates an E3 body and returns it sorted by
// connector and target id, the form that is stored and digested.
func normalizeCatalog(conns []GatewayCatalogConnector) ([]storage.GatewayCatalogConnector, error) {
	if len(conns) > gatewayMaxConnectors {
		return nil, gatewayInvalid("connectors")
	}
	out := make([]storage.GatewayCatalogConnector, 0, len(conns))
	ids := map[string]bool{}
	total := 0
	for _, c := range conns {
		if !ValidGatewayLocalID(c.ConnectorID) || ids[c.ConnectorID] {
			return nil, gatewayInvalid("connectors.connector_id")
		}
		ids[c.ConnectorID] = true
		if !gatewayKinds[c.Kind] {
			return nil, gatewayInvalid("connectors.kind")
		}
		if len(c.Targets) > gatewayMaxTargetsPerConn {
			return nil, gatewayInvalid("connectors.targets")
		}
		total += len(c.Targets)
		if total > gatewayMaxTargetsTotal {
			return nil, gatewayInvalid("connectors.targets")
		}
		targets := make([]storage.GatewayTarget, 0, len(c.Targets))
		tids := map[string]bool{}
		for _, t := range c.Targets {
			if !ValidGatewayLocalID(t.TargetID) || tids[t.TargetID] {
				return nil, gatewayInvalid("connectors.targets.target_id")
			}
			tids[t.TargetID] = true
			if t.Namespace != "" && !gatewayDNSLabelRe.MatchString(t.Namespace) {
				return nil, gatewayInvalid("connectors.targets.namespace")
			}
			if t.Name != "" && !gatewayDNSSubdomainRe.MatchString(t.Name) {
				return nil, gatewayInvalid("connectors.targets.name")
			}
			if !validInterval(t.RefreshIntervalSeconds) {
				return nil, gatewayInvalid("connectors.targets.refresh_interval_seconds")
			}
			if !validInterval(t.ProgressDeadlineSeconds) {
				return nil, gatewayInvalid("connectors.targets.progress_deadline_seconds")
			}
			identity := ""
			if t.Identity != nil {
				// Argo CD targets only; a Kubernetes connector never
				// carries one. Present means well formed: "" is refused.
				if c.Kind != GatewayKindArgoCD || !obsIdentityDigestRe.MatchString(*t.Identity) {
					return nil, gatewayInvalid("connectors.targets.identity")
				}
				identity = *t.Identity
			}
			targets = append(targets, storage.GatewayTarget{
				TargetID: t.TargetID, Namespace: t.Namespace, Name: t.Name,
				RefreshIntervalSeconds: t.RefreshIntervalSeconds, ProgressDeadlineSeconds: t.ProgressDeadlineSeconds,
				IdentityAdvertised: identity,
			})
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })
		out = append(out, storage.GatewayCatalogConnector{ConnectorID: c.ConnectorID, Kind: c.Kind, Targets: targets})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectorID < out[j].ConnectorID })
	return out, nil
}

// catalogDigest is the opaque catalog_version: SHA-256 over the JSON of
// the normalized catalog. Metadata only; the catalog holds no value.
func catalogDigest(conns []storage.GatewayCatalogConnector) (string, error) {
	type t struct {
		TargetID string `json:"target_id"`
		NS       string `json:"namespace,omitempty"`
		Name     string `json:"name,omitempty"`
		Refresh  *int   `json:"refresh_interval_seconds,omitempty"`
		Deadline *int   `json:"progress_deadline_seconds,omitempty"`
		Identity string `json:"identity,omitempty"`
	}
	type c struct {
		ID      string `json:"connector_id"`
		Kind    string `json:"kind"`
		Targets []t    `json:"targets"`
	}
	doc := make([]c, 0, len(conns))
	for _, in := range conns {
		cc := c{ID: in.ConnectorID, Kind: in.Kind, Targets: make([]t, 0, len(in.Targets))}
		for _, tt := range in.Targets {
			cc.Targets = append(cc.Targets, t{tt.TargetID, tt.Namespace, tt.Name, tt.RefreshIntervalSeconds, tt.ProgressDeadlineSeconds, tt.IdentityAdvertised})
		}
		doc = append(doc, cc)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// validLabel is a bounded, printable admin label with no control
// characters.
func validLabel(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// validSecretRef bounds an admin-supplied provider secret reference: no
// control characters and no URL.
func validSecretRef(s string) bool {
	return validLabel(s, gatewayMaxSecretRefLen) && !strings.Contains(s, "://")
}
