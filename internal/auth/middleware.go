package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Resolver loads the effective permissions an identity holds. The
// returned slice may contain duplicates (one row per user_role x
// permission pair); callers iterate-and-match instead of de-duping.
//
// Wired off the user_roles + roles repositories in main; tests inject
// a stub.
type Resolver interface {
	Resolve(ctx context.Context, userID string) ([]Grant, error)
}

// Grant is one effective (permission, scope) pair from a single
// user_role row. `Scope` is the assignment's scope verbatim; an empty
// map means global.
type Grant struct {
	Permission string
	Scope      map[string]string
}

// RepoResolver is the production Resolver. It loads every user_role
// for the identity, then fans out each role's permissions list. No
// caching today — the table is small.
type RepoResolver struct {
	userRoles storage.UserRoleRepository
	roles     storage.RoleRepository
}

// NewRepoResolver wires the production resolver.
func NewRepoResolver(ur storage.UserRoleRepository, r storage.RoleRepository) *RepoResolver {
	return &RepoResolver{userRoles: ur, roles: r}
}

// Resolve implements Resolver.
func (r *RepoResolver) Resolve(ctx context.Context, userID string) ([]Grant, error) {
	urs, err := r.userRoles.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list user_roles for %q: %w", userID, err)
	}
	out := make([]Grant, 0, len(urs)*2)
	for _, ur := range urs {
		role, err := r.roles.Get(ctx, ur.RoleID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue // stale assignment; skip
			}
			return nil, fmt.Errorf("auth: load role %s: %w", ur.RoleID, err)
		}
		scope := scopeAsStrings(ur.Scope)
		for _, p := range role.Permissions {
			out = append(out, Grant{Permission: p, Scope: scope})
		}
	}
	return out, nil
}

// scopeAsStrings narrows the storage layer's `map[string]any` to the
// string-typed scope keys the middleware actually understands. Non-
// string values are silently dropped (defensive — the schema should
// only ever store strings).
func scopeAsStrings(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok && s != "" {
			out[k] = s
		}
	}
	return out
}

// ScopeFn produces a request scope from the Fiber ctx. Common
// implementations (`ScopeFromQuery`, `ScopeFromJSONBody`) live below;
// handlers that need bespoke shapes can define their own.
type ScopeFn func(c fiber.Ctx) (map[string]string, error)

// Require returns a middleware that gates the next handler on the
// caller holding `perm` at GLOBAL scope (unscoped assignment).
//
// Use this for admin actions that aren't tenancy-scoped (e.g.
// role.edit, workflow.edit, integration.edit). For tenancy-scoped
// permissions (secret.request, secret.approve), use RequireScoped.
func Require(perm Permission, r Resolver) fiber.Handler {
	if r == nil {
		panic("auth: Require called with nil Resolver")
	}
	return func(c fiber.Ctx) error {
		userID, ok := IdentityFromContext(c.Context())
		if !ok {
			return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
		}
		grants, err := r.Resolve(c.Context(), userID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		for _, g := range grants {
			if g.Permission == string(perm) && len(g.Scope) == 0 {
				return c.Next()
			}
		}
		return fiber.NewError(fiber.StatusForbidden,
			fmt.Sprintf("missing permission %q (global scope)", perm))
	}
}

// RequireScoped returns a middleware that gates the next handler on
// the caller holding `perm` AT A SCOPE COVERING THE REQUEST.
//
// The handler-supplied `ScopeFn` extracts the request scope (from
// query, body, path params, etc.); the middleware finds a Grant whose
// scope `scopeCovers` the request.
//
// A Grant with an empty scope (unscoped assignment) covers every
// request — operators with global admin can do anything.
func RequireScoped(perm Permission, scope ScopeFn, r Resolver) fiber.Handler {
	if r == nil {
		panic("auth: RequireScoped called with nil Resolver")
	}
	if scope == nil {
		panic("auth: RequireScoped called with nil ScopeFn")
	}
	return func(c fiber.Ctx) error {
		userID, ok := IdentityFromContext(c.Context())
		if !ok {
			return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
		}
		reqScope, err := scope(c)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		grants, err := r.Resolve(c.Context(), userID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		for _, g := range grants {
			if g.Permission == string(perm) && scopeCovers(g.Scope, reqScope) {
				return c.Next()
			}
		}
		return fiber.NewError(fiber.StatusForbidden,
			fmt.Sprintf("missing permission %q for the requested scope", perm))
	}
}

// scopeCovers reports whether `user` is a superset-or-equal of
// `request`: every key present in `user` must match (or, for the
// special `secret_ref_prefix` key, prefix-match) the value in
// `request`. Keys absent from `user` are wildcards.
//
// An empty `user` map covers EVERY request (global admin).
//
// Mirrors the policy engine's selector semantics in services so
// scope semantics are consistent across the platform.
func scopeCovers(user, request map[string]string) bool {
	for k, want := range user {
		got := request[k]
		if k == "secret_ref_prefix" {
			if !strings.HasPrefix(got, want) {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

// IdentityFromContext returns the user_id stored on the context by
// the (real or stub) auth middleware. `ok` is false when no identity
// has been resolved (callers should treat that as 401).
//
// The middleware writes the identity into `middleware.CtxKeyActor`;
// the legacy stub wrote the literal string "anonymous" there, which
// IS a non-empty value — so callers that want STRONG identity should
// also reject `"anonymous"`. Today both the stub upgrade and the
// future OIDC swap will store a real opaque user_id.
func IdentityFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(middleware.CtxKeyActor).(string)
	if !ok || v == "" || v == "anonymous" {
		return "", false
	}
	return v, true
}

// --- common ScopeFn helpers -----------------------------------------

// ScopeFromQuery builds a request scope from query parameters. Pass
// the query keys you care about; absent keys are skipped (not added
// to the request scope, so they don't narrow the match).
func ScopeFromQuery(keys ...string) ScopeFn {
	return func(c fiber.Ctx) (map[string]string, error) {
		out := map[string]string{}
		for _, k := range keys {
			if v := c.Query(k); v != "" {
				out[k] = v
			}
		}
		return out, nil
	}
}

// ScopeFromJSONBody pulls scope fields from the request body. Useful
// for POST /requests where the request scope is in the body shape
// itself.
//
// NOTE: Fiber's body parser consumes the request body once. If a
// downstream handler also calls c.Bind().JSON(...), the body has
// already been read but Fiber's Bind buffers it, so reads are safe.
func ScopeFromJSONBody(keys ...string) ScopeFn {
	return func(c fiber.Ctx) (map[string]string, error) {
		var body map[string]any
		if err := c.Bind().JSON(&body); err != nil {
			return nil, fmt.Errorf("invalid JSON body")
		}
		out := map[string]string{}
		for _, k := range keys {
			if v, ok := body[k]; ok {
				switch t := v.(type) {
				case string:
					if t != "" {
						out[k] = t
					}
				case uuid.UUID:
					out[k] = t.String()
				}
			}
		}
		return out, nil
	}
}
