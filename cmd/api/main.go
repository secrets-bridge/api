// Command api is the Secrets Bridge Control Plane API.
//
// It owns the workflow / RBAC / audit / metadata domain backed by
// PostgreSQL and Redis. Agents and the dashboard SPA communicate with
// this service over HTTPS.
//
// Hard rules (from the project BRD):
//   - No secret values are ever stored, logged, or returned by this
//     service. Provider values live exclusively in the source provider
//     (Vault, AWS Secrets Manager, etc.) and are only touched by the
//     agent inside the target boundary.
//   - The service is stateless; durable state lives in PostgreSQL,
//     short-lived coordination lives in Redis.
//   - Every privileged action emits an audit event with a correlation
//     ID propagated from the originating request.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/observability"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/argocd"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

func main() {
	logger := observability.NewLogger(os.Getenv("LOG_LEVEL"))
	slog.SetDefault(logger)

	cfg := loadConfig()
	logger.Info("starting secrets-bridge api",
		"version", buildVersion,
		"addr", cfg.Addr,
		"shutdown_grace", cfg.ShutdownGrace,
	)

	// Storage wiring. The pool is required; the api refuses to start
	// without it because every meaningful endpoint depends on Postgres.
	// LOG_LEVEL=debug shows the migration tool's chatter; production
	// deploys are expected to stay at info or above.
	storageCfg, err := storage.LoadConfig()
	if err != nil {
		logger.Error("storage config", "error", err)
		os.Exit(1)
	}
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 60*time.Second)
	if err := storage.Migrate(bootCtx, storageCfg); err != nil {
		bootCancel()
		logger.Error("storage migrate", "error", err)
		os.Exit(1)
	}
	pool, err := storage.Open(bootCtx, storageCfg)
	if err != nil {
		bootCancel()
		logger.Error("storage open", "error", err)
		os.Exit(1)
	}
	// Runtime (Redis) wiring. Required like storage — every meaningful
	// CP operation relies on coordination primitives. Idempotency,
	// locks, rate limit, and pub/sub all live here.
	runtimeCfg, err := runtime.LoadConfig()
	if err != nil {
		bootCancel()
		logger.Error("runtime config", "error", err)
		os.Exit(1)
	}
	rdb, err := runtime.Open(bootCtx, runtimeCfg)
	if err != nil {
		bootCancel()
		logger.Error("runtime open", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = rdb.Close()
		pool.Close()
	}()

	// KMS bootstrap. Backend chosen via SB_KMS_BACKEND env var:
	//   - "local" (default): SB_WRAP_MASTER_KEY env var. Dev / single-node.
	//   - "vault-transit":   SB_KMS_VAULT_* env vars. OSS-first prod.
	// Same fail-fast posture as storage and runtime — the CP refuses to
	// start without a working KeyManager. Reuses bootCtx so the timeout
	// covers vault-transit's auth handshake too.
	km, err := keymgmt.FromEnv(bootCtx)
	bootCancel()
	if err != nil {
		logger.Error("keymgmt bootstrap", "error", err)
		os.Exit(1)
	}
	logger.Info("keymgmt backend ready", "key_id", km.CurrentKeyID())

	// Bootstrap admin assignment. Idempotent: if any user already
	// holds an admin grant, this is a no-op. v1 escape hatch so the
	// platform is usable before OIDC + a real login flow ship.
	if cfg.BootstrapAdminUserID != "" {
		if err := bootstrapAdminGrant(context.Background(), pool, cfg.BootstrapAdminUserID, logger); err != nil {
			logger.Error("bootstrap admin grant", "error", err)
			os.Exit(1)
		}
	}

	app := newApp(cfg, logger, pool, rdb, km)

	errCh := make(chan error, 1)
	go func() {
		if err := app.Listen(cfg.Addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	case err := <-errCh:
		logger.Error("listener exited", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

func newApp(cfg Config, logger *slog.Logger, pool *storage.Pool, rdb *runtime.Client, km keymgmt.KeyManager) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "secrets-bridge-api",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	})

	// Middleware order is intentional: request ID first so every other
	// middleware (including the logger) can read it from the context.
	app.Use(middleware.RequestID())
	app.Use(middleware.Logger(logger))
	app.Use(middleware.Recover(logger))

	// Probes and metrics are public; they must answer before auth so
	// kubelet and Prometheus can scrape without credentials. Readyz
	// gates on a fresh Postgres ping so kubelet removes the pod from
	// the Service when the database becomes unreachable.
	probes := handlers.NewProbes()
	probes.AddReadinessCheck("postgres", func(ctx context.Context) error {
		return pool.Ping(ctx)
	})
	probes.AddReadinessCheck("redis", func(ctx context.Context) error {
		return rdb.Ping(ctx)
	})
	app.Get("/healthz", probes.Healthz)
	app.Get("/readyz", probes.Readyz)
	app.Get("/metrics", handlers.Metrics)

	// Repositories + services + handlers wired off the pool/rdb so
	// concrete state lives in one place. Each new endpoint group adds
	// a handler + a Mount call below.
	agentRepo := storage.NewAgents(pool)
	auditRepo := storage.NewAuditEvents(pool)
	jobRepo := storage.NewSyncJobs(pool)
	roleRepo := storage.NewRoles(pool)
	userRoleRepo := storage.NewUserRoles(pool)
	workflowRepo := storage.NewWorkflows(pool)
	policyRepo := storage.NewPolicies(pool)
	wrapRepo := storage.NewSecretWraps(pool)
	requestRepo := storage.NewAccessRequests(pool)
	approvalRepo := storage.NewApprovals(pool)
	secretsRepo := storage.NewSecrets(pool)
	projectRepo := storage.NewProjects(pool)
	environmentRepo := storage.NewEnvironments(pool)

	agentSvc := services.NewAgentService(agentRepo, auditRepo, rdb)
	jobSvc := services.NewJobService(jobRepo, auditRepo)
	wrapSvc := services.NewWrapService(wrapRepo, auditRepo, km)
	policyEng := services.NewPolicyEngine(policyRepo, workflowRepo)
	requestSvc := services.NewRequestService(requestRepo, approvalRepo, wrapSvc, workflowRepo, policyEng, auditRepo, jobSvc)
	secretsSvc := services.NewSecretsService(secretsRepo, auditRepo)

	// GitOps observation integration (BRD §26) is OFF by default. The
	// flag is opt-in via `SB_GITOPS_ENABLED=true` (operators set this
	// via Helm values or a future UI integrations toggle). When the
	// flag is off, the request lifecycle behaves exactly as before
	// and the admin / user endpoints are not mounted.
	var gitopsH *handlers.GitOps
	if cfg.GitOpsEnabled {
		argoEndpointRepo := storage.NewArgoCDEndpoints(pool)
		gitopsMappingRepo := storage.NewGitOpsAppMappings(pool)
		gitopsObservationRepo := storage.NewGitOpsObservations(pool)
		gitopsSvc := services.NewGitOpsService(argoEndpointRepo, gitopsMappingRepo, gitopsObservationRepo, requestRepo, auditRepo, services.GitOpsConfig{})
		argoEndpointSvc := services.NewArgoCDEndpointService(argoEndpointRepo, km, auditRepo)
		requestSvc = requestSvc.WithGitOps(gitopsSvc)
		gitopsH = handlers.NewGitOps(argoEndpointSvc, gitopsMappingRepo, gitopsSvc, requestRepo, newArgoCDDiscoveryFactory())
		logger.Info("gitops visibility integration enabled (BRD §26)")
	} else {
		logger.Info("gitops visibility integration disabled (set SB_GITOPS_ENABLED=true to enable)")
	}

	// Wire the back-edge: when a patch job terminates, RequestService
	// transitions the owning access_request to executed/failed AND,
	// when GitOps is enabled, fans out observation rows for the
	// request's configured app mappings.
	jobSvc.OnCompleted(requestSvc.OnJobCompleted)

	agentsH := handlers.NewAgents(agentSvc)
	jobsH := handlers.NewJobs(jobSvc)
	adminH := handlers.NewAdmin(roleRepo, userRoleRepo, workflowRepo, policyRepo)
	requestsH := handlers.NewRequests(requestSvc)
	wrapsH := handlers.NewWraps(requestSvc, wrapSvc, agentRepo, km)
	secretsH := handlers.NewSecrets(secretsSvc)
	permissionsH := handlers.NewPermissions()
	tenancyH := handlers.NewTenancy(projectRepo, environmentRepo)

	// RBAC resolver for the `auth.Require(perm)` middleware. Loads each
	// caller's user_role assignments + the role catalog at request time.
	rbacResolver := auth.NewRepoResolver(userRoleRepo, roleRepo)

	// Authenticated API surface. Admin auth + RBAC + audit are stub
	// placeholders today; real implementations land with workflow
	// (issue #10).
	v1 := app.Group("/api/v1",
		middleware.Auth(),
		middleware.RBAC(),
		middleware.Audit(logger),
	)

	// Admin-side endpoints.
	//
	// Each WRITE endpoint is gated by `auth.Require(perm)`, which
	// resolves the caller's identity from `middleware.CtxKeyActor`
	// (set by the stub `middleware.Auth()` from the `X-User-Id`
	// header today; real OIDC lands with api#26) and checks against
	// the canonical catalog (`auth.Catalog`). READ endpoints stay
	// unauthenticated for v1 so the UI can hydrate without a session;
	// list-level RBAC lands as a follow-up.
	v1.Post("/agents", auth.Require(auth.PermAgentMint, rbacResolver), agentsH.Mint)
	v1.Get("/agents", agentsH.List)
	v1.Post("/jobs", jobsH.Enqueue)

	// Dynamic workflow + policy engine.
	v1.Post("/roles", auth.Require(auth.PermRoleEdit, rbacResolver), adminH.CreateRole)
	v1.Get("/roles", adminH.ListRoles)
	v1.Get("/roles/:id", adminH.GetRole)
	v1.Put("/roles/:id/permissions", auth.Require(auth.PermRoleEdit, rbacResolver), adminH.UpdateRolePermissions)
	v1.Delete("/roles/:id", auth.Require(auth.PermRoleEdit, rbacResolver), adminH.DeleteRole)

	v1.Post("/user-roles", auth.Require(auth.PermUserRoleEdit, rbacResolver), adminH.GrantUserRole)
	v1.Get("/user-roles", adminH.ListAllUserRoles)
	v1.Delete("/user-roles/:id", auth.Require(auth.PermUserRoleEdit, rbacResolver), adminH.RevokeUserRole)
	v1.Get("/users/:userID/roles", adminH.ListUserRoles)

	v1.Post("/workflows", auth.Require(auth.PermWorkflowEdit, rbacResolver), adminH.CreateWorkflow)
	v1.Get("/workflows", adminH.ListWorkflows)
	v1.Get("/workflows/:id", adminH.GetWorkflow)
	v1.Put("/workflows/:id", auth.Require(auth.PermWorkflowEdit, rbacResolver), adminH.UpdateWorkflow)
	v1.Delete("/workflows/:id", auth.Require(auth.PermWorkflowEdit, rbacResolver), adminH.DeleteWorkflow)

	v1.Post("/policies", auth.Require(auth.PermPolicyEdit, rbacResolver), adminH.CreatePolicy)
	v1.Get("/policies", adminH.ListPolicies)
	v1.Get("/policies/:id", adminH.GetPolicy)
	v1.Put("/policies/:id", auth.Require(auth.PermPolicyEdit, rbacResolver), adminH.UpdatePolicy)
	v1.Delete("/policies/:id", auth.Require(auth.PermPolicyEdit, rbacResolver), adminH.DeletePolicy)

	// Canonical permission catalog. Read by the Roles admin UI to
	// hydrate its permission picker, replacing the interim "union of
	// permissions across existing roles" client-side discovery
	// (ui#6). Cacheable for the api binary's lifetime — the catalog
	// is a compile-time package value (auth.Catalog).
	v1.Get("/permissions", permissionsH.List)

	// Audit log — read-only over the append-only audit_events table
	// (NFR-07). Gated by `audit.read` so platform operators with no
	// direct DB access can still see the chain of who-did-what to
	// every resource. Filters: actor / action / resource /
	// correlation_id / since / until / limit.
	auditH := handlers.NewAudit(auditRepo)
	v1.Get("/audit-events", auth.Require(auth.PermAuditRead, rbacResolver), auditH.List)

	// Tenancy admin — projects + environments. Pre-existed in the
	// schema (BRD §17, migration 0001) without an HTTP surface; this
	// wires admin CRUD so the UI can manage them. Projects use a
	// soft-delete (archive via status flip); environments hard-delete.
	v1.Post("/projects", tenancyH.CreateProject)
	v1.Get("/projects", tenancyH.ListProjects)
	v1.Get("/projects/:id", tenancyH.GetProject)
	v1.Put("/projects/:id/status", tenancyH.UpdateProjectStatus)
	v1.Get("/projects/:id/environments", tenancyH.ListEnvironmentsForProject)

	v1.Post("/environments", tenancyH.CreateEnvironment)
	v1.Get("/environments", tenancyH.ListEnvironments)
	v1.Get("/environments/:id", tenancyH.GetEnvironment)
	v1.Delete("/environments/:id", tenancyH.DeleteEnvironment)

	// Patch-request lifecycle. Plaintext values arrive only via
	// POST /requests, are envelope-encrypted by WrapService before
	// touching Postgres, and never appear in responses.
	v1.Post("/requests", requestsH.Submit)
	v1.Post("/requests/read", requestsH.SubmitRead)
	v1.Get("/requests", requestsH.List)
	v1.Get("/requests/:id", requestsH.Get)
	v1.Post("/requests/:id/approve", requestsH.Approve)
	v1.Post("/requests/:id/reject", requestsH.Reject)
	v1.Post("/requests/:id/cancel", requestsH.Cancel)
	// Value-free wrap summaries for the request detail page. Lets the
	// UI render the Wraps card (one row per key with a ready/consumed
	// pill) without ever fetching plaintext until the user clicks
	// Reveal. Same `user_id` stub-auth as the retrieval endpoint.
	v1.Get("/requests/:id/wraps", requestsH.ListWraps)

	// User-bound wrap retrieval for the read flow. Auth identity comes
	// from a `user_id` query param today; swaps to a middleware-stashed
	// identity once the auth design lands. Service-layer enforces
	// requester==userID + request.type=read.
	v1.Get("/requests/:id/wraps/:wrap_id", requestsH.RetrieveWrap)

	// GitOps observation panel + ArgoCD admin surface are mounted
	// ONLY when SB_GITOPS_ENABLED=true. The flag is opt-in via Helm
	// values or a future UI integrations toggle — disabled deployments
	// keep the existing wrap-only request shape unchanged.
	if gitopsH != nil {
		// User-bound observation panel (BRD §26). Same `user_id`
		// stub-auth as the wrap retrieval endpoint.
		v1.Get("/requests/:id/gitops", gitopsH.GetRequestObservations)

		// Admin: ArgoCD endpoint CRUD. Plaintext tokens arrive only
		// via POST, are envelope-encrypted via KeyManager before
		// touching Postgres, and never appear in responses.
		v1.Post("/argocd-endpoints", auth.Require(auth.PermIntegrationEdit, rbacResolver), gitopsH.CreateArgoCDEndpoint)
		v1.Get("/argocd-endpoints", gitopsH.ListArgoCDEndpoints)
		v1.Get("/argocd-endpoints/:id", gitopsH.GetArgoCDEndpoint)
		v1.Put("/argocd-endpoints/:id/enabled", auth.Require(auth.PermIntegrationEdit, rbacResolver), gitopsH.SetArgoCDEndpointEnabled)
		v1.Delete("/argocd-endpoints/:id", auth.Require(auth.PermIntegrationEdit, rbacResolver), gitopsH.DeleteArgoCDEndpoint)

		// Read-only ArgoCD discovery: drives the UI's bulk-create
		// mappings flow. Calls ArgoCD via the endpoint's KMS-wrapped
		// token, returns a trimmed list of applications. NEVER writes
		// to ArgoCD; the pkg/argocd readOnlyTransport enforces.
		v1.Get("/argocd-endpoints/:id/discovered-apps", gitopsH.GetDiscoveredApps)

		// Admin: secret_mapping (or provider_connection) → ArgoCD app(s).
		v1.Post("/gitops-app-mappings", auth.Require(auth.PermIntegrationEdit, rbacResolver), gitopsH.CreateGitOpsMapping)
		v1.Get("/gitops-app-mappings", gitopsH.ListGitOpsMappings)
		v1.Delete("/gitops-app-mappings/:id", auth.Require(auth.PermIntegrationEdit, rbacResolver), gitopsH.DeleteGitOpsMapping)
	}

	// Discovery surface. Admins search the cache via GET; the agent's
	// DiscoverExecutor upserts batches via the bulk endpoint (under
	// the AgentAuth group further down).
	v1.Get("/secrets", secretsH.List)
	v1.Get("/secrets/:id", secretsH.Get)

	// Agent-side endpoints. The `/agents/:id` sub-group is gated by
	// the AgentAuth middleware which validates X-Agent-Secret and
	// stashes the authenticated agent ID in the request context.
	// Handlers downstream simply read it via middleware.AgentIDFromContext.
	agentRoutes := v1.Group("/agents/:id", middleware.AgentAuth(agentSvc))
	agentRoutes.Post("/heartbeat", agentsH.Heartbeat)
	// Agent self-registers its X25519 public key after generating
	// the keypair at startup. Idempotent. Lets existing minted
	// agents opt into the sealed-wire path without an admin re-mint.
	agentRoutes.Put("/public-key", agentsH.SetPublicKey)
	agentRoutes.Post("/jobs/claim", jobsH.Claim)
	agentRoutes.Post("/jobs/:job/complete", jobsH.Complete)
	// Single-shot wrap retrieval. RetrieveWrap requires the owning
	// access_request to be in approved status; the wrap is consumed
	// on success (concurrent racers see ErrAlreadyConsumed → HTTP 410).
	agentRoutes.Get("/wraps/:wrap_id", wrapsH.Retrieve)
	// Agent-side wrap CREATION for the read flow: after the agent
	// fetches a value via core/providers.GetValue, it POSTs each key's
	// plaintext here so the CP envelope-encrypts and persists. The
	// requester later retrieves through the user-bound endpoint.
	// Accepts either base64 plaintext (legacy) or a wire-envelope
	// shape (Piece 8b) — the body shape itself selects the path.
	agentRoutes.Post("/wraps", wrapsH.Create)
	// Wire-envelope DEK issuance (Piece 8b). The agent calls this
	// FIRST when it has plaintext to send back to CP, uses the
	// returned plaintext key to AES-GCM-encrypt the value locally,
	// then POSTs the resulting ciphertext + the round-tripped
	// dek_ciphertext to /wraps. Plaintext never on the wire.
	agentRoutes.Post("/dek", wrapsH.IssueDEK)
	// Agent-side discovery upload. The agent's DiscoverExecutor calls
	// core/providers.ListMetadata against the configured provider and
	// POSTs the batch here; CP upserts into the secrets cache.
	agentRoutes.Post("/secrets/bulk", secretsH.BulkUpsert)

	return app
}

// newArgoCDDiscoveryFactory returns the factory wired into the GitOps
// handler so it can build a read-only ArgoCD client for the
// `discovered-apps` endpoint. The factory is a thin adapter:
// services.ArgoCDClientConfig → argocd.Config → *argocd.Client wrapped
// to satisfy services.AppLister (which returns the trimmed
// DiscoveredApp shape, not pkg/argocd's Application).
//
// pkg/argocd stays the canonical source for the wire shape; this
// adapter just trims to what the discovery flow needs.
func newArgoCDDiscoveryFactory() services.ArgoCDClientFactory {
	return func(in services.ArgoCDClientConfig) (services.AppLister, error) {
		c, err := argocd.New(argocd.Config{
			BaseURL:       in.BaseURL,
			Token:         in.Token,
			TLSCAPEM:      in.TLSCAPEM,
			TLSServerName: in.TLSServerName,
			Timeout:       15 * time.Second,
		})
		if err != nil {
			return nil, err
		}
		return &argoCDDiscoveryAdapter{c: c}, nil
	}
}

type argoCDDiscoveryAdapter struct{ c *argocd.Client }

func (a *argoCDDiscoveryAdapter) ListApplications(ctx context.Context, project string) ([]services.DiscoveredApp, error) {
	apps, err := a.c.ListApplications(ctx, project)
	if err != nil {
		return nil, err
	}
	out := make([]services.DiscoveredApp, 0, len(apps))
	for _, app := range apps {
		out = append(out, services.DiscoveredApp{
			Name:                 app.Name,
			Namespace:            app.Namespace,
			Project:              app.Project,
			DestinationServer:    app.DestinationServer,
			DestinationCluster:   app.DestinationCluster,
			DestinationNamespace: app.DestinationNamespace,
			HealthStatus:         app.HealthStatus,
			SyncStatus:           app.SyncStatus,
		})
	}
	return out, nil
}

// bootstrapAdminGrant idempotently ensures the configured
// `BootstrapAdminUserID` holds the seed `admin` role. Runs once at
// boot:
//
//   - If ANY admin grant already exists in user_roles, log + return.
//   - Else: insert one (user_id, admin_role_id, scope={}) row.
//
// Identity is opaque text (matches the future OIDC `sub` claim). No
// password material is involved — this is purely the assignment side.
// The login + password flow lands as slice 7.
func bootstrapAdminGrant(ctx context.Context, pool *storage.Pool, userID string, logger *slog.Logger) error {
	roles := storage.NewRoles(pool)
	userRoles := storage.NewUserRoles(pool)

	adminRole, err := roles.GetByName(ctx, "admin")
	if err != nil {
		return errors.New("bootstrap: seed `admin` role missing — was migration 0005 applied?")
	}

	existing, err := userRoles.ListByRole(ctx, adminRole.ID)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		logger.Info("bootstrap admin already assigned (idempotent skip)",
			"existing_count", len(existing))
		return nil
	}

	grant := &storage.UserRole{
		UserID: userID,
		RoleID: adminRole.ID,
		Scope:  map[string]any{}, // global
	}
	if err := userRoles.Grant(ctx, grant); err != nil {
		return err
	}
	logger.Info("bootstrap admin assignment created",
		"user_id", userID,
		"role", "admin",
		"scope", "global")
	return nil
}
