// Package auth owns the platform's permission catalog and (when
// api#27 / P0-2 ships) the route-level enforcement middleware.
//
// Design notes (referencing ArgoCD's RBAC posture for inspiration):
//
//   - ArgoCD splits authz into resource × action × object
//     (`applications` + `create` + `myproj/*`). We collapse the first
//     two into a single `<resource>.<action>` string for v1 because
//     the catalog is small (~dozen entries) and operators read flat
//     strings more easily than triplets in a role's permission list.
//   - ArgoCD's policy.csv lives in a ConfigMap; ours is dynamic via
//     the `roles` + `user_roles` + `policy_rules` tables. Trade-off
//     accepted in BRD §17: GitOps-friendly editing is sacrificed for
//     in-platform admin ergonomics.
//   - ArgoCD ships built-in `role:admin` / `role:readonly` baselines;
//     we ship `admin` / `approver` / `developer` seeds (is_system).
//   - Object scoping (ArgoCD's `myproj/*`) is deferred: the
//     `user_roles.scope` jsonb column is reserved for narrowing
//     assignments to project/environment/etc. when multi-tenancy
//     becomes real. The permission string stays flat.
//   - Wildcards (e.g. `secret.*`) are NOT supported in v1. Adding a
//     future `secret.x.y` would silently grant it to wildcard holders;
//     wait until the catalog stabilizes (post-v1.0).
//   - The catalog is hand-curated in this file rather than
//     auto-derived from handler annotations. The catalog is small
//     enough that the maintenance cost is negligible, and reviewing
//     "what does this permission do?" works better as a curated table
//     than as scraped struct tags.
//
// The catalog endpoint (`GET /api/v1/permissions`) lets the UI render
// a discoverable picker from a stable source instead of guessing from
// observed role data. ArgoCD's `account/can-i/<r>/<a>/<o>` query is
// the natural next step once identity (api#26) lands — UI asks "can
// I do X?" instead of enumerating the user's permissions.
package auth

// Permission is the canonical string identifier of a single capability
// the platform exposes. Each constant below corresponds to one or
// more handlers that will gate on it once `auth.Require(perm)` middleware
// ships (api#27).
type Permission string

const (
	// RBAC admin --------------------------------------------------------
	PermRoleEdit     Permission = "role.edit"
	PermUserRoleEdit Permission = "user_role.edit"

	// Workflow / policy admin ------------------------------------------
	PermWorkflowEdit Permission = "workflow.edit"
	PermPolicyEdit   Permission = "policy.edit"

	// Agent admin -------------------------------------------------------
	PermAgentMint   Permission = "agent.mint"
	PermAgentRevoke Permission = "agent.revoke"
	PermAgentList   Permission = "agent.list"

	// Developer / approver ---------------------------------------------
	PermSecretRequest Permission = "secret.request"
	PermSecretApprove Permission = "secret.approve"

	// Read-only observability ------------------------------------------
	PermSecretList Permission = "secret.list"
	PermAuditRead  Permission = "audit.read"

	// Integrations (gated by SB_GITOPS_ENABLED) ------------------------
	PermIntegrationEdit Permission = "integration.edit"
)

// Descriptor is the JSON shape returned by GET /api/v1/permissions.
// Operators see this in the Roles drawer's permission picker; the
// `Group` field drives the resource-grouped layout there.
type Descriptor struct {
	Key         Permission `json:"key"`
	Group       string     `json:"group"`
	Description string     `json:"description"`
}

// Catalog is the canonical list of all permissions the platform
// recognizes. Order is presentation-stable so the UI doesn't reshuffle
// chips between releases. Adding a permission here is a one-line
// change; removing one is a breaking change that needs a migration to
// strip the value from existing role rows.
//
// HARD RULE: every permission string used in any seed migration's
// role JSON MUST appear in this catalog. The drift test in
// permissions_test.go enforces this — if you edit a migration to add
// a permission, you must add the constant here too.
var Catalog = []Descriptor{
	{PermRoleEdit, "RBAC", "Create, update, delete roles. Manage seeded role permission lists."},
	{PermUserRoleEdit, "RBAC", "Grant or revoke role assignments to users."},

	{PermWorkflowEdit, "Workflows", "Create, update, delete approval workflow definitions."},
	{PermPolicyEdit, "Workflows", "Create, update, delete policy rules that map request scope to a workflow."},

	{PermAgentMint, "Agents", "Mint a new agent identity and return its credentials."},
	{PermAgentRevoke, "Agents", "Revoke an agent — heartbeats stop being accepted."},
	{PermAgentList, "Agents", "List all registered agents and their status."},

	{PermSecretRequest, "Secrets", "Submit a patch or read request against a provider secret."},
	{PermSecretApprove, "Secrets", "Approve or reject pending secret requests."},

	{PermSecretList, "Observability", "List discovered secrets (metadata only, never values)."},
	{PermAuditRead, "Observability", "Read the immutable audit event log."},

	{PermIntegrationEdit, "Integrations", "Manage ArgoCD endpoints and gitops application mappings (when SB_GITOPS_ENABLED)."},
}

// Keys returns the set of every permission key in the catalog. Useful
// for set-membership tests (drift checks, etc.).
func Keys() map[Permission]struct{} {
	out := make(map[Permission]struct{}, len(Catalog))
	for _, d := range Catalog {
		out[d.Key] = struct{}{}
	}
	return out
}

// IsKnown reports whether the given string is a recognized catalog
// permission. Free-form strings outside the catalog are accepted by
// the api today (the Roles UI's custom-add path) but warned about;
// once auth.Require(perm) enforcement ships, unknown strings will not
// gate any handler.
func IsKnown(p string) bool {
	_, ok := Keys()[Permission(p)]
	return ok
}
