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

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/observability"
	"github.com/secrets-bridge/api/internal/services"
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
	bootCancel()
	defer func() {
		_ = rdb.Close()
		pool.Close()
	}()

	app := newApp(cfg, logger, pool, rdb)

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

func newApp(cfg Config, logger *slog.Logger, pool *storage.Pool, rdb *runtime.Client) *fiber.App {
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

	agentSvc := services.NewAgentService(agentRepo, auditRepo, rdb)
	jobSvc := services.NewJobService(jobRepo, auditRepo)

	agentsH := handlers.NewAgents(agentSvc)
	jobsH := handlers.NewJobs(jobSvc)
	adminH := handlers.NewAdmin(roleRepo, userRoleRepo, workflowRepo, policyRepo)

	// Authenticated API surface. Admin auth + RBAC + audit are stub
	// placeholders today; real implementations land with workflow
	// (issue #10).
	v1 := app.Group("/api/v1",
		middleware.Auth(),
		middleware.RBAC(),
		middleware.Audit(logger),
	)

	// Admin-side endpoints.
	v1.Post("/agents", agentsH.Mint)
	v1.Get("/agents", agentsH.List)
	v1.Post("/jobs", jobsH.Enqueue)

	// Dynamic workflow + policy engine — admin CRUD over the four
	// entities Piece 2 introduced. Real RBAC enforcement (checking
	// the caller has role.edit / workflow.edit / policy.edit
	// permissions) layers on top once the auth design lands.
	v1.Post("/roles", adminH.CreateRole)
	v1.Get("/roles", adminH.ListRoles)
	v1.Get("/roles/:id", adminH.GetRole)
	v1.Put("/roles/:id/permissions", adminH.UpdateRolePermissions)
	v1.Delete("/roles/:id", adminH.DeleteRole)

	v1.Post("/user-roles", adminH.GrantUserRole)
	v1.Delete("/user-roles/:id", adminH.RevokeUserRole)
	v1.Get("/users/:userID/roles", adminH.ListUserRoles)

	v1.Post("/workflows", adminH.CreateWorkflow)
	v1.Get("/workflows", adminH.ListWorkflows)
	v1.Get("/workflows/:id", adminH.GetWorkflow)
	v1.Put("/workflows/:id", adminH.UpdateWorkflow)
	v1.Delete("/workflows/:id", adminH.DeleteWorkflow)

	v1.Post("/policies", adminH.CreatePolicy)
	v1.Get("/policies", adminH.ListPolicies)
	v1.Get("/policies/:id", adminH.GetPolicy)
	v1.Put("/policies/:id", adminH.UpdatePolicy)
	v1.Delete("/policies/:id", adminH.DeletePolicy)

	// Agent-side endpoints. The `/agents/:id` sub-group is gated by
	// the AgentAuth middleware which validates X-Agent-Secret and
	// stashes the authenticated agent ID in the request context.
	// Handlers downstream simply read it via middleware.AgentIDFromContext.
	agentRoutes := v1.Group("/agents/:id", middleware.AgentAuth(agentSvc))
	agentRoutes.Post("/heartbeat", agentsH.Heartbeat)
	agentRoutes.Post("/jobs/claim", jobsH.Claim)
	agentRoutes.Post("/jobs/:job/complete", jobsH.Complete)

	return app
}
