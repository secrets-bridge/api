// PolicyHistoryService is the compute-only service that walks an
// audit-event chain for a single policy_rules row and renders it as
// a structured timeline + per-event diff. Built for R-follow-up #5
// (api#132; slice 1a is api#133).
//
// Pure compute: no DB writes, no audit emission. Reads the audit log,
// the workflows repo (for name resolution), and the policies repo
// (only used by the handler layer to bridge admin post-delete
// forensic visibility; not used here directly).
//
// Hard rules (preserve EPIC R §6 lock):
//
//   - selector_keys diff is set-based (sorted) — NEVER carries values
//   - selector VALUES are NEVER exposed; the audit metadata doesn't
//     even include them
//   - changed_keys from metadata is IGNORED at render time; the
//     diff is the source of truth (§2 D4). `changed_keys` was author
//     intent, not ground-truth diff
//   - action-name compat at READ time (§3 D4): storage reads both
//     normalized AND legacy R-follow-up #3 names; service maps to
//     normalized before returning to the SPA
//   - chain head emits no `changes` regardless of action (§3 D3
//     step 3) — pre-cutover rules grandfathered in get the "Initial
//     snapshot observed" UX

package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services/actordisplay"
	"github.com/secrets-bridge/api/pkg/storage"
)

// HistoryEntry is one rendered audit event with its diff against the
// prior event in the chain.
type HistoryEntry struct {
	EventID             uuid.UUID
	OccurredAt          time.Time
	Actor               string
	ActorDisplay        string
	CorrelationID       uuid.UUID
	Action              string // ALWAYS normalized — `policy.create` / `policy.update` / `policy.delete`
	ActorPermissionUsed string // `policy.author` | `policy.edit` (when populated by emit site)
	Scope               string // `platform` | `project` | `team`
	Changes             []FieldChange
	SnapshotAfter       RuleSnapshot
	// Reconstructed marks an entry that was NOT derived from an audit
	// event — a response-time "initial snapshot" synthesized from the
	// live rule for rules that have zero audit history (migration-seeded
	// or pre-cutover; M6/api#143). The UI renders these as "initial
	// snapshot observed" rather than a real `policy.create` event (L7),
	// so genuine create events keep their normal "created" copy.
	Reconstructed bool
}

// FieldChange is one field's delta between consecutive snapshots.
// BeforeWorkflowName / AfterWorkflowName are populated for
// workflow_id changes only.
type FieldChange struct {
	Key                string
	Before             any
	After              any
	BeforeWorkflowName *string
	AfterWorkflowName  *string
}

// RuleSnapshot is the post-mutation snapshot from one event's
// metadata. Pointer fields signal "missing in legacy metadata" — the
// SPA renders `(unknown)` per the legacy-event caveat (§2 D3).
//
// SelectorKeys is set-based (sorted before return).
type RuleSnapshot struct {
	Name         *string
	Enabled      *bool
	Priority     int
	WorkflowID   string
	WorkflowName *string
	SelectorKeys []string
}

// PolicyHistoryService computes per-rule audit chains into rendered
// timelines. Pure compute over the audit + workflow repos + the
// shared actor-display resolver.
type PolicyHistoryService struct {
	audit     storage.AuditEventRepository
	workflows storage.WorkflowRepository
	resolver  *actordisplay.Resolver
}

// NewPolicyHistoryService binds the service to its dependencies. The
// resolver is created from the user + agent repos passed by the
// caller (mirrors the audit handler's wiring).
func NewPolicyHistoryService(
	audit storage.AuditEventRepository,
	workflows storage.WorkflowRepository,
	users storage.LocalUserRepository,
	agents storage.AgentRepository,
) *PolicyHistoryService {
	return &PolicyHistoryService{
		audit:     audit,
		workflows: workflows,
		resolver:  actordisplay.New(users, agents),
	}
}

// ListForRule returns the rendered timeline for one policy rule. The
// returned entries are ASC by occurred_at (chain order). HasMore is
// true when there's at least one older event past the limit.
//
// limit ≤ 0 → storage.DefaultPolicyHistoryLimit. Caller (handler) is
// expected to validate + cap before reaching this point.
// current is the live rule row (loaded by the handler for its scope
// check). When the rule has ZERO audit events — a migration-seeded or
// pre-cutover rule like the system `match-all` — and current is
// non-nil, the service synthesizes a single Reconstructed "initial
// snapshot" entry from it so the timeline isn't blank (M6/api#143). No
// migration, no audit write — pure compute. current may be nil on the
// admin post-delete forensic path (where events always exist, so the
// synthesis branch isn't reached anyway).
func (s *PolicyHistoryService) ListForRule(
	ctx context.Context,
	ruleID uuid.UUID,
	current *storage.PolicyRule,
	limit int,
) (entries []HistoryEntry, hasMore bool, err error) {
	if s.audit == nil {
		return nil, false, errors.New("services: PolicyHistoryService missing audit repo")
	}

	rawEvents, hasMore, err := s.audit.ListPolicyRuleHistory(ctx, ruleID, limit)
	if err != nil {
		return nil, false, fmt.Errorf("services: list policy rule history: %w", err)
	}
	if len(rawEvents) == 0 {
		if current == nil {
			return nil, false, nil
		}
		return []HistoryEntry{s.reconstructedSnapshot(ctx, current)}, false, nil
	}

	// Batch-resolve every distinct workflow_id surfacing in the chain.
	// Used by both the per-entry SnapshotAfter and the workflow_id
	// FieldChange's before/after names. One round-trip total.
	workflowNames, err := s.resolveWorkflowNames(ctx, rawEvents)
	if err != nil {
		return nil, false, err
	}

	// Per-request memoization cache for actor display lookups —
	// matches the audit handler's per-request pattern (every distinct
	// actor costs one repo call, not one per row).
	displayCache := make(map[string]string)

	entries = make([]HistoryEntry, 0, len(rawEvents))
	var prevSnapshot *RuleSnapshot

	for i, evt := range rawEvents {
		curr := snapshotFromMetadata(evt.Metadata, workflowNames)
		entry := HistoryEntry{
			EventID:             evt.ID,
			OccurredAt:          evt.OccurredAt,
			Actor:               evt.Actor,
			ActorDisplay:        s.resolver.Display(ctx, evt.Actor, displayCache),
			CorrelationID:       evt.CorrelationID,
			Action:              normalizeAction(evt.Action),
			ActorPermissionUsed: stringFromMeta(evt.Metadata, "actor_permission_used"),
			Scope:               stringFromMeta(evt.Metadata, "scope"),
			SnapshotAfter:       curr,
		}

		// §3 D3 step 3 / step 5:
		//   - Chain head (i == 0): no Changes regardless of action
		//   - policy.delete: no Changes; SnapshotAfter SHOULD be the
		//     prior event's snapshot since the delete-time metadata
		//     carries only the row state at delete which equals the
		//     last-known state — but emit it from the prior snapshot
		//     explicitly so legacy metadata gaps don't drop fields
		if i > 0 && entry.Action != "policy.delete" {
			entry.Changes = diffSnapshots(*prevSnapshot, curr, workflowNames)
		}
		if entry.Action == "policy.delete" && prevSnapshot != nil {
			entry.SnapshotAfter = *prevSnapshot
		}

		entries = append(entries, entry)
		snap := curr
		prevSnapshot = &snap
	}

	return entries, hasMore, nil
}

// resolveWorkflowNames walks the chain for every distinct workflow_id
// surfacing in metadata + does one batch ListByIDs call.
func (s *PolicyHistoryService) resolveWorkflowNames(
	ctx context.Context,
	events []*storage.AuditEvent,
) (map[string]string, error) {
	seen := make(map[uuid.UUID]struct{}, len(events))
	ids := make([]uuid.UUID, 0, len(events))
	for _, evt := range events {
		raw := stringFromMeta(evt.Metadata, "workflow_id")
		if raw == "" {
			continue
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	if len(ids) == 0 || s.workflows == nil {
		return map[string]string{}, nil
	}

	wfs, err := s.workflows.ListByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("services: batch workflow lookup: %w", err)
	}

	names := make(map[string]string, len(wfs))
	for _, w := range wfs {
		names[w.ID.String()] = w.Name
	}
	return names, nil
}

// reconstructedSnapshot builds the single synthetic "initial snapshot"
// entry for a rule with no audit history (M6). OccurredAt is the rule's
// created_at; the actor is "system" (no real event recorded who/when);
// Reconstructed=true drives the UI's "initial snapshot observed"
// treatment. No Changes — it's the baseline, not a delta.
func (s *PolicyHistoryService) reconstructedSnapshot(
	ctx context.Context,
	rule *storage.PolicyRule,
) HistoryEntry {
	scope := "platform"
	switch {
	case rule.TeamID != nil:
		scope = "team"
	case rule.ProjectID != nil:
		scope = "project"
	}
	return HistoryEntry{
		OccurredAt:    rule.CreatedAt,
		Actor:         "system",
		ActorDisplay:  "system",
		Action:        "policy.create",
		Scope:         scope,
		SnapshotAfter: s.snapshotFromRule(ctx, rule),
		Reconstructed: true,
	}
}

// snapshotFromRule renders a RuleSnapshot from the LIVE rule row (not an
// audit event), resolving the workflow name with a single lookup.
// Selector VALUES are never read — only the sorted key set, per the §6
// selector lock.
func (s *PolicyHistoryService) snapshotFromRule(
	ctx context.Context,
	rule *storage.PolicyRule,
) RuleSnapshot {
	name := rule.Name
	enabled := rule.Enabled
	snap := RuleSnapshot{
		Name:       &name,
		Enabled:    &enabled,
		Priority:   rule.Priority,
		WorkflowID: rule.WorkflowID.String(),
	}
	keys := make([]string, 0, len(rule.Selector))
	for k := range rule.Selector {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snap.SelectorKeys = keys

	if s.workflows != nil && rule.WorkflowID != uuid.Nil {
		if wfs, err := s.workflows.ListByIDs(ctx, []uuid.UUID{rule.WorkflowID}); err == nil {
			for _, w := range wfs {
				if w.ID == rule.WorkflowID {
					n := w.Name
					snap.WorkflowName = &n
				}
			}
		}
	}
	return snap
}

// snapshotFromMetadata builds a RuleSnapshot from one audit event's
// metadata. Missing fields produce nil pointers (legacy-event safe).
// workflowNames lookup populates SnapshotAfter.WorkflowName at render
// time (slice 1b adds the workflow_id field at emit time; this just
// resolves it).
func snapshotFromMetadata(
	meta map[string]any,
	workflowNames map[string]string,
) RuleSnapshot {
	snap := RuleSnapshot{
		WorkflowID: stringFromMeta(meta, "workflow_id"),
	}

	if v, ok := meta["name"].(string); ok {
		s := v
		snap.Name = &s
	}
	if v, ok := meta["enabled"].(bool); ok {
		b := v
		snap.Enabled = &b
	}
	if v, ok := meta["priority"]; ok {
		switch n := v.(type) {
		case float64: // JSON-unmarshal default
			snap.Priority = int(n)
		case int:
			snap.Priority = n
		case int64:
			snap.Priority = int(n)
		}
	}
	if name, ok := workflowNames[snap.WorkflowID]; ok && snap.WorkflowID != "" {
		s := name
		snap.WorkflowName = &s
	}

	if raw, ok := meta["selector_keys"].([]any); ok {
		keys := make([]string, 0, len(raw))
		for _, k := range raw {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
		}
		sort.Strings(keys)
		snap.SelectorKeys = keys
	}

	return snap
}

// diffSnapshots computes the fixed-key delta between two consecutive
// snapshots. Selector_keys is set-based (already sorted by
// snapshotFromMetadata); workflow_id change carries both names.
//
// Per §2 D4: this is the ground truth. `changed_keys` from metadata
// is intentionally NOT consulted.
func diffSnapshots(
	prev, curr RuleSnapshot,
	workflowNames map[string]string,
) []FieldChange {
	var changes []FieldChange

	if !pointerEqual(prev.Name, curr.Name) {
		changes = append(changes, FieldChange{
			Key:    "name",
			Before: derefStr(prev.Name),
			After:  derefStr(curr.Name),
		})
	}
	if !pointerEqual(prev.Enabled, curr.Enabled) {
		changes = append(changes, FieldChange{
			Key:    "enabled",
			Before: derefBool(prev.Enabled),
			After:  derefBool(curr.Enabled),
		})
	}
	if prev.Priority != curr.Priority {
		changes = append(changes, FieldChange{
			Key:    "priority",
			Before: prev.Priority,
			After:  curr.Priority,
		})
	}
	if prev.WorkflowID != curr.WorkflowID {
		change := FieldChange{
			Key:    "workflow_id",
			Before: prev.WorkflowID,
			After:  curr.WorkflowID,
		}
		if name, ok := workflowNames[prev.WorkflowID]; ok {
			s := name
			change.BeforeWorkflowName = &s
		}
		if name, ok := workflowNames[curr.WorkflowID]; ok {
			s := name
			change.AfterWorkflowName = &s
		}
		changes = append(changes, change)
	}
	if !stringSliceEqual(prev.SelectorKeys, curr.SelectorKeys) {
		changes = append(changes, FieldChange{
			Key:    "selector_keys",
			Before: prev.SelectorKeys,
			After:  curr.SelectorKeys,
		})
	}

	return changes
}

// normalizeAction maps the R-follow-up #3 pre-cutover names to the
// normalized post-§4 C2 names. §3 D4: SPA sees one stable enum.
func normalizeAction(raw string) string {
	switch raw {
	case "policy.created_for_scope":
		return "policy.create"
	case "policy.updated_for_scope":
		return "policy.update"
	case "policy.deleted_for_scope":
		return "policy.delete"
	}
	return raw
}

func stringFromMeta(meta map[string]any, key string) string {
	if v, ok := meta[key].(string); ok {
		return v
	}
	return ""
}

func pointerEqual[T comparable](a, b *T) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return *a == *b
}

func derefStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func derefBool(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
