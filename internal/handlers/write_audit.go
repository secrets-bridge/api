package handlers

import (
	"log/slog"
	"sort"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// sessionActor is the audit actor for the authenticated caller,
// "user:<id>". Provenance fields (granted_by, actor) come from here and
// never from a request body (API-N-05). Returns "" without an identity.
func sessionActor(c fiber.Ctx) string {
	if id, ok := auth.IdentityFromContext(c.Context()); ok {
		return "user:" + id
	}
	return ""
}

// auditWrite records one privilege or tenancy write: role, user-role,
// workflow, project, environment and project-secret binding changes
// (API-N-05). The actor is the session identity, every event gets its own
// correlation id, and meta must carry ids and shape only, never values.
//
// Best-effort like the other handler-emitted audits: the write has
// already committed, so an audit failure is logged rather than turned
// into a 500 the caller would retry. A nil repository is a no-op (legacy
// tests that don't wire audit).
func auditWrite(c fiber.Ctx, repo storage.AuditEventRepository, action, resource string, meta map[string]any) {
	if repo == nil {
		return
	}
	actor := sessionActor(c)
	if actor == "" {
		actor = "anonymous"
	}
	evt := &storage.AuditEvent{
		Actor:         actor,
		Action:        action,
		Resource:      resource,
		Status:        storage.AuditStatusSuccess,
		CorrelationID: uuid.New(),
		Metadata:      meta,
	}
	if err := repo.Append(c.Context(), evt); err != nil {
		slog.WarnContext(c.Context(), "audit append failed", "action", action, "resource", resource, "err", err)
	}
}

// sortedKeys returns m's keys in a stable order (scope shape metadata).
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stringSetDiff returns the members of after missing from before (added)
// and of before missing from after (removed), each sorted.
func stringSetDiff(before, after []string) (added, removed []string) {
	inBefore := make(map[string]bool, len(before))
	for _, s := range before {
		inBefore[s] = true
	}
	inAfter := make(map[string]bool, len(after))
	for _, s := range after {
		if inAfter[s] {
			continue
		}
		inAfter[s] = true
		if !inBefore[s] {
			added = append(added, s)
		}
	}
	seen := make(map[string]bool, len(before))
	for _, s := range before {
		if !inAfter[s] && !seen[s] {
			removed = append(removed, s)
		}
		seen[s] = true
	}
	sort.Strings(added)
	sort.Strings(removed)
	if added == nil {
		added = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	return added, removed
}

// nonNilStrings keeps a nil slice from reaching audit metadata as null.
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// uuidPtrMeta renders an optional id for audit metadata (nil stays null).
func uuidPtrMeta(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}
