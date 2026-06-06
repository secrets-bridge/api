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

	// Tenancy admin -----------------------------------------------------
	PermTeamEdit Permission = "team.edit"

	// Workflow / policy admin ------------------------------------------
	PermWorkflowEdit Permission = "workflow.edit"
	PermPolicyEdit   Permission = "policy.edit"

	// EPIC R (api#108) — scoped project-level policy authoring. Granted
	// via the policy_author seed role (or any custom role carrying it).
	// Strictly NOT auto-covered by policy.edit server-side — the SPA's
	// capability helper unifies them in the UI but the api treats each
	// permission as distinct.
	PermPolicyAuthor Permission = "policy.author"

	// Agent admin -------------------------------------------------------
	PermAgentMint   Permission = "agent.mint"
	PermAgentRevoke Permission = "agent.revoke"
	PermAgentList   Permission = "agent.list"

	// Developer / approver ---------------------------------------------
	PermSecretRequest Permission = "secret.request"
	PermSecretApprove Permission = "secret.approve"
	// PermSecretRevealDirect (Slice L4) is an env-agnostic capability
	// to skip the approval workflow on a Tier-2 reveal. It is GATED in
	// EVERY callsite by: (a) the matched policy_rule must have
	// direct_reveal_allowed=true (Slice L2), AND (b) the matched
	// environment must have kind != 'prod' (Slice L1/L2 PROD invariant).
	// Without all three, the user is routed through the request flow
	// regardless of the permission. PROD direct-reveal is impossible
	// by construction.
	PermSecretRevealDirect Permission = "secret.reveal.direct"

	// PermSecretValueProvide (Slice N1) is the capability to fill or
	// refuse a cross-team integration request scoped to a team's
	// inbox. Scope-bearing: holders are typically granted with
	// scope={"team_id": "<uuid>"} so the fill / refuse / inbox
	// endpoints only allow access to that team's pending requests.
	// Operators who want a platform-wide "value-provider" grant the
	// role at global scope (scope IS NULL) — covers every team's
	// inbox.
	PermSecretValueProvide Permission = "secret.value.provide"

	// PermSecretSecurityApprove (Slice N1) is the third-vote
	// permission for cross_team requests in PROD environments. When
	// the matched workflow has requires_security_approval=true,
	// RequestService.Verify requires at least one approver holding
	// this permission to transition the request to 'approved'.
	// Strictly separate from secret.approve — operators must
	// explicitly assign both for a user to act as both regular and
	// security approver. Even when a user holds both, the same actor
	// cannot satisfy BOTH the source approval AND the security
	// approval on the same request (SoD enforced in Verify).
	// NOT scope-bearing in v1: security votes apply globally.
	PermSecretSecurityApprove Permission = "secret.security.approve"

	// Read-only observability ------------------------------------------
	PermSecretList Permission = "secret.list"
	PermAuditRead  Permission = "audit.read"

	// Integrations (gated by SB_GITOPS_ENABLED) ------------------------
	PermIntegrationEdit Permission = "integration.edit"

	// EPIC Q (api#99) — scoped self-service binding of platform-approved
	// provider connections to projects + environments the caller covers
	// via the team-aware resolver. Strictly NOT covered by
	// integration.edit server-side — the SPA's capability helper
	// unifies them in the UI; the api treats them as distinct.
	PermIntegrationBind Permission = "integration.bind"
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

	{PermTeamEdit, "Tenancy", "Create, update, archive teams and manage team memberships. Role grants scoped to a team_id implicitly cover that team's entire subtree."},

	{PermWorkflowEdit, "Workflows", "Create, update, delete approval workflow definitions."},
	{PermPolicyEdit, "Workflows", "Create, update, delete policy rules that map request scope to a workflow. Global scope — affects every project's rules. Does NOT auto-cover policy.author server-side (EPIC R, api#108)."},
	{PermPolicyAuthor, "Workflows", "Author project-scoped policy rules for non-prod environments (EPIC R, api#108). Scoped via the existing team-aware resolver. Refuses prod env selectors, priority >= 9000, and edits to platform global rules. Granted via the policy_author system seed role."},

	{PermAgentMint, "Agents", "Mint a new agent identity and return its credentials."},
	{PermAgentRevoke, "Agents", "Revoke an agent — heartbeats stop being accepted."},
	{PermAgentList, "Agents", "List all registered agents and their status."},

	{PermSecretRequest, "Secrets", "Submit a patch or read request against a provider secret."},
	{PermSecretApprove, "Secrets", "Approve or reject pending secret requests."},
	{PermSecretRevealDirect, "Secrets", "Skip the approval workflow on a Tier-2 reveal; gated by policy direct_reveal_allowed + env.kind != prod. PROD direct-reveal is impossible by construction."},
	{PermSecretValueProvide, "Secrets", "Fill or refuse an open cross-team integration request scoped to a team's inbox. Typically granted with a team_id scope."},
	{PermSecretSecurityApprove, "Secrets", "Cast the security-approval vote required for cross-team requests in PROD environments. Strict separation — does NOT include normal approve. Same actor cannot also cast the source vote on the same request."},

	{PermSecretList, "Observability", "List discovered secrets (metadata only, never values)."},
	{PermAuditRead, "Observability", "Read the immutable audit event log."},

	{PermIntegrationEdit, "Integrations", "Manage ArgoCD endpoints and gitops application mappings (when SB_GITOPS_ENABLED). Also gates provider connection lifecycle (create/update/delete/discover-now/bindings) per EPIC P."},
	{PermIntegrationBind, "Integrations", "Bind or unbind self-service-bindable provider connections on projects and environments you cover. NOT auto-covered by integration.edit server-side; grant explicitly (e.g. via the provider_connection_binder seed role)."},
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
