package services

// Console catalog read (A1), AppProject to team mapping (A2) and the
// caller scope the bind rules use (ADR 0002 S4, api#308; gateway
// docs/design/discovery-contract.md section 8).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Catalog and mapping errors.
var (
	ErrCatalogInvalidQuery  = errors.New("services: invalid catalog query")
	ErrCatalogInvalidCursor = errors.New("services: invalid catalog cursor")
	ErrMappingInvalid       = errors.New("services: invalid project mapping")
)

// BindCaller is who calls a catalog or bind route: a platform admin
// (Global, global gateway.bind), a global reader (GlobalList, global
// gateway.list, catalog only), or a team-scoped gateway.bind holder
// whose reach is Teams (the expanded subtrees).
type BindCaller struct {
	Global     bool
	GlobalList bool
	Teams      []uuid.UUID
}

func (c BindCaller) readsAll() bool { return c.Global || c.GlobalList }

func (c BindCaller) hasTeam(id uuid.UUID) bool { return slices.Contains(c.Teams, id) }

func (c BindCaller) seesAnyOf(teams []uuid.UUID) bool {
	for _, t := range teams {
		if c.hasTeam(t) {
			return true
		}
	}
	return false
}

const (
	catalogDefaultLimit = 50
	catalogMaxLimit     = 200
	catalogMaxCursor    = 512
)

var (
	catalogQRe       = regexp.MustCompile(`^[a-z0-9.-]{1,63}$`)
	catalogCursorRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
	catalogQueryKeys = map[string]bool{
		"gateway_id": true, "connector_uuid": true, "app_project": true, "namespace": true, "q": true,
		"source": true, "status": true, "bound": true, "new": true, "team_id": true, "limit": true, "cursor": true,
	}
)

// CatalogPage is one A1 page.
type CatalogPage struct {
	Items      []storage.CatalogItem
	NextCursor string
}

type catalogCursor struct {
	K storage.CatalogKey `json:"k"`
	H string             `json:"h"`
}

// filterHash binds a cursor to the filters it was made with (limit
// excluded).
func filterHash(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "cursor" && k != "limit" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + params[k] + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func parseOptBool(s string) (*bool, bool) {
	switch s {
	case "":
		return nil, true
	case "true", "false":
		v := s == "true"
		return &v, true
	}
	return nil, false
}

func parseOptUUID(s string) (*uuid.UUID, bool) {
	if s == "" {
		return nil, true
	}
	id, ok := strictUUID(s)
	if !ok {
		return nil, false
	}
	return &id, true
}

// ListCatalog is A1 (section 8.1): the catalog filtered on the server
// by the caller's teams before paging. params is the raw query.
func (s *GatewayService) ListCatalog(ctx context.Context, caller BindCaller, params map[string]string) (*CatalogPage, error) {
	if !caller.readsAll() && len(caller.Teams) == 0 {
		return nil, ErrGatewayCatalogForbidden
	}
	for k, v := range params {
		if !catalogQueryKeys[k] || v == "" {
			return nil, ErrCatalogInvalidQuery
		}
	}
	f := storage.CatalogFilter{Limit: catalogDefaultLimit, Now: s.now().UTC()}
	if !caller.readsAll() {
		f.Teams = caller.Teams
	}
	var ok bool
	if f.GatewayID, ok = parseOptUUID(params["gateway_id"]); !ok {
		return nil, ErrCatalogInvalidQuery
	}
	if f.ConnectorUUID, ok = parseOptUUID(params["connector_uuid"]); !ok {
		return nil, ErrCatalogInvalidQuery
	}
	if f.TeamID, ok = parseOptUUID(params["team_id"]); !ok {
		return nil, ErrCatalogInvalidQuery
	}
	if f.Bound, ok = parseOptBool(params["bound"]); !ok {
		return nil, ErrCatalogInvalidQuery
	}
	if f.New, ok = parseOptBool(params["new"]); !ok {
		return nil, ErrCatalogInvalidQuery
	}
	f.AppProject, f.Namespace, f.Q, f.Source, f.Status = params["app_project"], params["namespace"], params["q"], params["source"], params["status"]
	switch {
	case f.AppProject != "" && !validAppProject(f.AppProject),
		f.Namespace != "" && !gatewayDNSLabelRe.MatchString(f.Namespace),
		f.Q != "" && !catalogQRe.MatchString(f.Q),
		f.Source != "" && f.Source != "discovered" && f.Source != "static",
		f.Status != "" && !slices.Contains([]string{"present", "missing", "stale", "identity_changed"}, f.Status):
		return nil, ErrCatalogInvalidQuery
	}
	if v := params["limit"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > catalogMaxLimit || strconv.Itoa(n) != v {
			return nil, ErrCatalogInvalidQuery
		}
		f.Limit = n
	}
	hash := filterHash(params)
	if v := params["cursor"]; v != "" {
		raw, err := base64.RawURLEncoding.DecodeString(v)
		var cur catalogCursor
		if len(v) > catalogMaxCursor || !catalogCursorRe.MatchString(v) || err != nil || json.Unmarshal(raw, &cur) != nil || cur.H != hash {
			return nil, ErrCatalogInvalidCursor
		}
		f.After = &cur.K
	}
	items, err := s.store.ListCatalog(ctx, f)
	if err != nil {
		return nil, err
	}
	page := &CatalogPage{Items: items}
	if len(items) > f.Limit {
		page.Items = items[:f.Limit]
		raw, err := json.Marshal(catalogCursor{K: page.Items[f.Limit-1].Key, H: hash})
		if err != nil {
			return nil, err
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

// ErrGatewayCatalogForbidden: the caller holds neither global
// gateway.list, global gateway.bind nor a team-scoped gateway.bind.
var ErrGatewayCatalogForbidden = errors.New("services: no catalog access")

// ProjectTeamsInput is the A2 PUT body.
type ProjectTeamsInput struct {
	AppProject string
	TeamIDs    []string
}

const (
	mappingMaxProjects = 64
	mappingMaxTeams    = 16
)

// GetProjectTeams is the A2 read.
func (s *GatewayService) GetProjectTeams(ctx context.Context, gatewayID, connectorID uuid.UUID) (*storage.GatewayProjectTeams, error) {
	return s.store.GetProjectTeams(ctx, gatewayID, connectorID)
}

// PutProjectTeams is the A2 write: a full replace of a connector's
// AppProject to team mapping. A change that leaves a binding uncovered
// suspends it (mapping_removed) and cancels its open tasks.
func (s *GatewayService) PutProjectTeams(ctx context.Context, gatewayID, connectorID uuid.UUID, in []ProjectTeamsInput, by string) (*storage.GatewayProjectTeams, error) {
	if len(in) > mappingMaxProjects {
		return nil, ErrMappingInvalid
	}
	mappings := map[string][]uuid.UUID{}
	for _, m := range in {
		if !validAppProject(m.AppProject) || mappings[m.AppProject] != nil || len(m.TeamIDs) < 1 || len(m.TeamIDs) > mappingMaxTeams {
			return nil, ErrMappingInvalid
		}
		ids := make([]uuid.UUID, 0, len(m.TeamIDs))
		for _, t := range m.TeamIDs {
			id, ok := strictUUID(t)
			if !ok || slices.Contains(ids, id) {
				return nil, ErrMappingInvalid
			}
			ids = append(ids, id)
		}
		mappings[m.AppProject] = ids
	}
	out, err := s.store.PutProjectTeams(ctx, gatewayID, connectorID, mappings, by, s.now().UTC())
	if err != nil {
		return nil, err
	}
	var teams []string
	seen := map[uuid.UUID]bool{}
	pairs := 0
	for _, ts := range out.After.Mappings {
		for _, t := range ts {
			pairs++
			if !seen[t] {
				seen[t] = true
				teams = append(teams, t.String())
			}
		}
	}
	sort.Strings(teams)
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, by), Action: "gateway.connector.project_mapping_changed", Resource: gatewayActor(gatewayID),
		Status: storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"gateway_id": gatewayID.String(), "connector_id": connectorID.String(), "team_ids": teams,
			"app_project_count": len(out.After.Mappings), "app_project_count_before": len(out.Before.Mappings),
			"mapping_count": pairs, "mapping_complete": out.After.Complete,
			"bindings_suspended": out.BindingsSuspended, "tasks_cancelled": len(out.Cancelled),
		},
	})
	for _, t := range out.Cancelled {
		auditTaskClosed(ctx, s.audit, auditActor(ctx, by), "observation.task.cancelled", t)
	}
	return out.After, nil
}
