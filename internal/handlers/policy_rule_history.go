// Policy rule history handlers — three URL families, one shared service.
//
// R-follow-up #5 slice 1c (api#135). Closes the EPIC #132 round-trip's
// api side. UI consumes this via the per-anchor Detail pages.
//
// URL family (§4 D1):
//
//	GET /api/v1/projects/:projectID/policy-rules/:ruleID/history    — scoped (project)
//	GET /api/v1/teams/:teamID/policy-rules/:ruleID/history          — scoped (team)
//	GET /api/v1/policies/:ruleID/history                            — admin (policy.edit)
//
// Anchor routing per §4 D3 / OQ4-1: silent 404 `policy_not_found` on
// URL/anchor mismatch (gate-order enumeration protection; NO denied
// audit event — same posture as the per-anchor Get handlers).
//
// Post-delete behavior per §4 C2 / C4 correction:
//   - Scoped paths: `policyRepo.Get(ruleID)` → if deleted → 404
//     `policy_not_found`. Scoped access is lost at delete time.
//   - Admin path: existence check via
//     `auditEvents.ListPolicyRuleHistory(ruleID, 1)` BEFORE the rule
//     lookup. If events exist, proceed even when rule is gone.
//     Forensic visibility stays admin-only.

package handlers

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ---- Prometheus counter (§4 / §6 lock) ---------------------------

var (
	policyRuleHistoryViewsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "policy_rule_history_views_total",
			Help: "Successful policy rule history reads, by anchor scope.",
		},
		// LOW-CARDINALITY LOCK: scope is {platform, project, team} —
		// 3 values total. NEVER carries actor_id / rule_id /
		// project_id / team_id labels. Per-rule reads live in the
		// audit log (action='audit.read.policy_history').
		[]string{"scope"},
	)
)

// ---- Wire envelope (§4 D2) ---------------------------------------

// historyEntryWire is the JSON shape for one rendered audit event.
// Mirrors services.HistoryEntry with explicit `json` tags so the
// service can stay encoding-agnostic.
type historyEntryWire struct {
	EventID             string             `json:"event_id"`
	OccurredAt          time.Time          `json:"occurred_at"`
	Actor               string             `json:"actor"`
	ActorDisplay        string             `json:"actor_display"`
	CorrelationID       string             `json:"correlation_id"`
	Action              string             `json:"action"`
	ActorPermissionUsed string             `json:"actor_permission_used,omitempty"`
	Scope               string             `json:"scope,omitempty"`
	Changes             []fieldChangeWire  `json:"changes"`
	SnapshotAfter       ruleSnapshotWire   `json:"snapshot_after"`
}

type fieldChangeWire struct {
	Key                string  `json:"key"`
	Before             any     `json:"before,omitempty"`
	After              any     `json:"after,omitempty"`
	BeforeWorkflowName *string `json:"before_workflow_name,omitempty"`
	AfterWorkflowName  *string `json:"after_workflow_name,omitempty"`
}

type ruleSnapshotWire struct {
	Name         *string  `json:"name,omitempty"`
	Enabled      *bool    `json:"enabled,omitempty"`
	Priority     int      `json:"priority"`
	WorkflowID   string   `json:"workflow_id"`
	WorkflowName *string  `json:"workflow_name,omitempty"`
	SelectorKeys []string `json:"selector_keys"`
}

type policyRuleHistoryResponse struct {
	RuleID  string             `json:"rule_id"`
	Scope   string             `json:"scope"`
	Entries []historyEntryWire `json:"entries"`
	HasMore bool               `json:"has_more"`
	Limit   int                `json:"limit"`
}

// ---- Limit parsing (§4 D5) ---------------------------------------

func parseHistoryLimit(c fiber.Ctx) (int, error) {
	raw := c.Query("limit")
	if raw == "" {
		return storage.DefaultPolicyHistoryLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, errors.New("limit must be a positive integer")
	}
	if n > storage.MaxPolicyHistoryLimit {
		n = storage.MaxPolicyHistoryLimit
	}
	return n, nil
}

// ---- Audit emission (§4 D6) --------------------------------------

// auditReadPolicyHistory emits one `audit.read.policy_history` event
// per successful history list. Fires from the handler so the URL
// family (scope) + actor context are captured at the request boundary.
func auditReadPolicyHistory(
	c fiber.Ctx,
	repo storage.AuditEventRepository,
	ruleID uuid.UUID,
	scope string,
	entryCount int,
) {
	if repo == nil {
		return
	}
	actor := identityFromCtx(c)
	if actor == "" {
		actor = "admin"
	}
	_ = repo.Append(c.Context(), &storage.AuditEvent{
		Actor:    actor,
		Action:   "audit.read.policy_history",
		Resource: "policy_rule:" + ruleID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"policy_rule_id": ruleID.String(),
			"scope":          scope,
			"entry_count":    entryCount,
		},
	})
}

// ---- Wire-shape conversion ---------------------------------------

func toHistoryEntryWires(entries []services.HistoryEntry) []historyEntryWire {
	out := make([]historyEntryWire, 0, len(entries))
	for _, e := range entries {
		w := historyEntryWire{
			EventID:             e.EventID.String(),
			OccurredAt:          e.OccurredAt,
			Actor:               e.Actor,
			ActorDisplay:        e.ActorDisplay,
			CorrelationID:       e.CorrelationID.String(),
			Action:              e.Action,
			ActorPermissionUsed: e.ActorPermissionUsed,
			Scope:               e.Scope,
			Changes:             toFieldChangeWires(e.Changes),
			SnapshotAfter:       toRuleSnapshotWire(e.SnapshotAfter),
		}
		out = append(out, w)
	}
	return out
}

func toFieldChangeWires(changes []services.FieldChange) []fieldChangeWire {
	if len(changes) == 0 {
		return []fieldChangeWire{}
	}
	out := make([]fieldChangeWire, 0, len(changes))
	for _, c := range changes {
		out = append(out, fieldChangeWire{
			Key:                c.Key,
			Before:             c.Before,
			After:              c.After,
			BeforeWorkflowName: c.BeforeWorkflowName,
			AfterWorkflowName:  c.AfterWorkflowName,
		})
	}
	return out
}

func toRuleSnapshotWire(s services.RuleSnapshot) ruleSnapshotWire {
	return ruleSnapshotWire{
		Name:         s.Name,
		Enabled:      s.Enabled,
		Priority:     s.Priority,
		WorkflowID:   s.WorkflowID,
		WorkflowName: s.WorkflowName,
		SelectorKeys: s.SelectorKeys,
	}
}

// scopeForRule derives the scope label from an in-storage rule for
// the admin handler's counter + envelope. Mirrors the §1 D1 anchor
// table from R-follow-up #3.
func scopeForRule(rule *storage.PolicyRule) string {
	switch {
	case rule.TeamID != nil:
		return "team"
	case rule.ProjectID != nil:
		return "project"
	}
	return "platform"
}

// _ = json.Marshal — keep `encoding/json` referenced in case the
// envelope grows custom marshaling without bumping imports later.
var _ = json.Marshal
