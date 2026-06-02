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
	"strings"
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
	if err := cfg.ValidateEnv(); err != nil {
		logger.Error("config env", "error", err)
		os.Exit(1)
	}
	if err := cfg.ValidateMFADevFlag(); err != nil {
		logger.Error("config mfa-dev flag", "error", err)
		os.Exit(1)
	}
	logger.Info("starting secrets-bridge api",
		"version", buildVersion,
		"addr", cfg.Addr,
		"env", cfg.Env,
		"shutdown_grace", cfg.ShutdownGrace,
	)
	if cfg.Env == ModeDev {
		logger.Warn("SB_ENV=dev — LocalKMS allowed, dev seeder will run if local_users is empty. Do NOT use this in production.")
	}
	if cfg.MFADevAllowPwd {
		logger.Warn("SB_MFA_DEV_ALLOW_PWD=true — Tier 2 step-up is BYPASSED for all live sessions. Interim unblock only; remove before any production rollout.")
	}

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
	km, err := keymgmt.FromEnv(bootCtx, cfg.Env)
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

	// JWT secret is REQUIRED — the login endpoint can't function
	// without it.
	if err := cfg.ValidateJWTSecret(); err != nil {
		logger.Error("jwt secret missing", "error", err)
		os.Exit(1)
	}
	jwtSigner := auth.NewSigner(cfg.JWTSecret)

	// Local-admin bootstrap. Creates the seed admin user + role
	// assignment on first boot when local_users is empty. Idempotent
	// once any local user exists.
	localUsersRepo := storage.NewLocalUsers(pool)
	authSvc := services.NewAuthService(
		localUsersRepo,
		storage.NewRoles(pool),
		storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
		jwtSigner,
		cfg.JWTTokenTTL,
	)
	if cfg.BootstrapAdminEmail != "" && cfg.BootstrapAdminPassword != "" {
		bootCtx2, bootCancel2 := context.WithTimeout(context.Background(), 30*time.Second)
		id, err := authSvc.BootstrapLocalAdmin(bootCtx2, cfg.BootstrapAdminEmail, cfg.BootstrapAdminPassword)
		bootCancel2()
		if err != nil {
			logger.Error("bootstrap local admin", "error", err)
			os.Exit(1)
		}
		if id != "" {
			logger.Info("bootstrap local admin created", "user_id", id, "email", cfg.BootstrapAdminEmail)
		} else {
			logger.Info("bootstrap local admin skipped (users already exist)")
		}
	}

	// Dev seeder. Runs only when SB_ENV=dev AND local_users is
	// empty. Creates three users (admin / approver / requester) bound
	// to the matching system roles, then logs the credentials ONCE so
	// the operator can capture them from the boot output. The password
	// is either SB_DEV_SEED_PASSWORD (shared, useful for UAT) or
	// generated per user at random.
	if cfg.Env == ModeDev {
		bootCtx3, bootCancel3 := context.WithTimeout(context.Background(), 30*time.Second)
		seeded, err := authSvc.BootstrapDevUsers(bootCtx3, cfg.DevSeedPassword)
		bootCancel3()
		if err != nil {
			logger.Error("bootstrap dev users", "error", err)
			os.Exit(1)
		}
		if len(seeded) == 0 {
			logger.Info("bootstrap dev users skipped (users already exist)")
		} else {
			logger.Warn("================================================================")
			logger.Warn("DEV SEEDER — capture these credentials, they are logged ONCE")
			logger.Warn("================================================================")
			for _, u := range seeded {
				logger.Warn("dev user seeded",
					"email", u.Email,
					"role", u.Role,
					"password", u.Password,
				)
			}
			logger.Warn("================================================================")
		}
	}

	app := newApp(cfg, logger, pool, rdb, km, authSvc)

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

func newApp(cfg Config, logger *slog.Logger, pool *storage.Pool, rdb *runtime.Client, km keymgmt.KeyManager, authSvc *services.AuthService) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "secrets-bridge-api",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		// JSON error body shape — the SPA (and any other typed client)
		// expects `{"error":"<message>"}` so a parsed body has the field
		// the client extracts the message from. Fiber v3's default
		// handler emits plain text, which the SPA's `client.ts` then
		// shows as the literal `HTTP <status>` placeholder because
		// JSON.parse fails. Override the handler to JSON so the
		// step-up modal + every other error path can display the real
		// reason. Discovered during a Slice K pilot rollout where the
		// SPA surfaced "401: HTTP 401" instead of the step-up modal's
		// human message.
		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var fe *fiber.Error
			if errors.As(err, &fe) {
				code = fe.Code
			}
			// Preserve any headers the route handler set (e.g.
			// RequireFreshMFA's `WWW-Authenticate: step-up` challenge).
			c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
		},
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
	projectSecretsRepo := storage.NewProjectSecrets(pool)
	projectSecretsH := handlers.NewProjectSecrets(projectSecretsRepo, projectRepo, secretsRepo)
	teamRepo := storage.NewTeams(pool)
	teamsH := handlers.NewTeams(teamRepo)
	teamScopeResolver := auth.NewRepoTeamScopeResolver(teamRepo, projectRepo)
	// Reused by meH.WithIdentity to hydrate GET /users/me with the
	// caller's local_users row (email, display_name).
	localUsersRepoInApp := storage.NewLocalUsers(pool)

	// Slice H1 + H2: MFA factor storage + TOTP enrollment service.
	// The handler covers /users/me/mfa/factors + /users/me/mfa/totp/*;
	// WebAuthn (H3), challenge / verify (H4), and the mfa_enrolled
	// flag (H5) attach to the same `mfaH` in subsequent slices.
	mfaFactorRepo := storage.NewUserMFAFactors(pool)
	totpSvc := services.NewTOTPService(
		mfaFactorRepo,
		km,
		auditRepo,
		rdb,
		services.TOTPConfig{Issuer: cfg.MFATOTPIssuer},
	)
	mfaH := handlers.NewMFA(mfaFactorRepo, localUsersRepoInApp, totpSvc)

	// Slice H3: WebAuthn enrollment. The RP only constructs when the
	// operator sets BOTH RPID + RPOrigins — TOTP-only deployments
	// leave the WebAuthn knobs unset and the matching routes 503.
	var webauthnSvc *services.WebAuthnService
	if cfg.MFAWebAuthnRPID != "" && len(cfg.MFAWebAuthnRPOrigins) > 0 {
		built, err := services.NewWebAuthnService(
			mfaFactorRepo, localUsersRepoInApp, km, auditRepo, rdb,
			services.WebAuthnConfig{
				RPID:          cfg.MFAWebAuthnRPID,
				RPDisplayName: cfg.MFAWebAuthnRPDisplayName,
				RPOrigins:     cfg.MFAWebAuthnRPOrigins,
			},
		)
		if err != nil {
			logger.Error("webauthn: disabled", "err", err)
		} else {
			webauthnSvc = built
			mfaH = mfaH.WithWebAuthn(webauthnSvc)
		}
	}


	// RBAC resolver for the `auth.Require(perm)` middleware. Loads each
	// caller's user_role assignments + the role catalog at request time.
	rbacResolver := auth.NewRepoResolver(userRoleRepo, roleRepo)

	// Slice 3 of the team-hierarchy work: the approve / reject paths
	// now refuse with `out_of_scope_project` when the approver's
	// effective project access (PermSecretApprove, expanded through
	// the team subtree) doesn't cover the request's project_id.
	// WithApproverScope mutates the pointer in place, so the handler
	// built at the top of this block sees the change; no reassignment.
	requestSvc.WithApproverScope(rbacResolver, teamScopeResolver)

	// Project-scoped catalog (api#43 Slice B): GET /secrets restricts
	// results to the caller's project bindings unless they hold
	// secret.list at global scope. Team-scoped grants expand through
	// the descendant team subtree via teamScopeResolver.
	secretsH = secretsH.
		WithProjectScoping(projectSecretsRepo, rbacResolver).
		WithTeamScope(teamScopeResolver)

	// Submit-time tenancy gate (api#43 Slice C): POST /requests +
	// /requests/read refuse with 403 + error_kind when the caller's
	// scope doesn't cover the project / op / key set. Team-scoped
	// grants expand the same way as on the catalog read path.
	requestsH = requestsH.
		WithTenancyGate(projectSecretsRepo, secretsRepo, rbacResolver).
		WithTeamScope(teamScopeResolver)

	// "What are my projects?" projection (api#43 Slice D) — drives the
	// UI project switcher.
	meH := handlers.NewMe(projectRepo, rbacResolver).
		WithTeamScope(teamScopeResolver).
		WithIdentity(localUsersRepoInApp, teamRepo)

	// Session service (Slice A2). Owns the HttpOnly cookie auth path
	// that replaces JWT-in-sessionStorage. Postgres is the source of
	// truth — sessions revoke immediately on logout. A Redis cache
	// layer is a future performance follow-up only if profiling shows
	// the per-request validation lookup is a hot spot.
	sessionSvc := services.NewSessionService(
		storage.NewSessions(pool),
		storage.NewAuditEvents(pool),
	)
	if cfg.MFADevAllowPwd {
		p := sessionSvc.Policy()
		p.DevAllowPwd = true
		sessionSvc = sessionSvc.WithPolicy(p)
	}

	// Slice H4: /auth/mfa/{challenge,verify} verify orchestration.
	// Dispatches to TOTP / WebAuthn under the hood + stamps
	// `last_mfa_at` on the caller's session on success. This is the
	// ONLY path that stamps last_mfa_at post-H4 (OIDC callback's
	// amr-based stamping is gated behind SB_OIDC_TRUSTED_AMR_MFA).
	mfaVerifySvc := services.NewMFAVerifyService(
		mfaFactorRepo, totpSvc, webauthnSvc, sessionSvc, auditRepo, rdb,
		services.MFAVerifyConfig{},
	)
	authMFAH := handlers.NewAuthMFA(mfaVerifySvc)
	// Slice H5: /users/me carries `mfa_enrolled` so the SPA can route
	// brand-new users to /me/mfa instead of leaving them stuck on a
	// step-up modal with nothing to verify with. Single source of
	// truth — same `AnyEnrolled` check the step-up middleware uses.
	meH = meH.WithMFAEnrollment(mfaVerifySvc)

	// Authenticated API surface. Admin auth + RBAC + audit are stub
	// placeholders today; real implementations land with workflow
	// (issue #10). `AuthWith` adds the cookie path at the front of
	// the resolution chain (cookie -> Bearer JWT -> X-User-Id ->
	// anonymous).
	// Slice K — login-time MFA gate. When enabled, every authenticated
	// route requires the session to have been MFA-verified at least
	// once. The middleware has its own carve-out list for the routes
	// that MUST stay reachable to satisfy the gate (logout, /users/me,
	// /users/me/mfa/*, /auth/mfa/*). When the knob is off the
	// middleware is nil-passed and degrades to pass-through, so
	// existing step-up-only deployments are byte-for-byte unchanged.
	var requireStamped fiber.Handler
	if cfg.RequireMFAAtLogin {
		requireStamped = middleware.RequireMFAStamped(sessionSvc, mfaVerifySvc)
	}

	v1Middlewares := []any{
		middleware.AuthWith(authSvc, sessionSvc),
		middleware.RBAC(),
		middleware.Audit(logger),
	}
	if requireStamped != nil {
		v1Middlewares = append(v1Middlewares, requireStamped)
	}
	v1 := app.Group("/api/v1", v1Middlewares...)

	// Authentication — public route, no auth gating. The UI POSTs
	// email + password here and receives a signed JWT in return. The
	// rest of the platform reads identity from `middleware.CtxKeyActor`
	// which the upstream `middleware.Auth(authSvc)` populated from
	// either the Bearer JWT or the legacy X-User-Id header.
	//
	// Rate limit per architect Q7 + NAT-aware tuning (Slice A1):
	// 30 attempts / 60s per source IP. The architect's original
	// 5/60s assumed each user has their own public IP; many ISPs
	// (notably Iraqi CGNAT deployments) put dozens of legitimate
	// users behind one egress. The per-IP layer is an anti-scan
	// measure; per-account brute force is defended durably in
	// Postgres by `LockoutPolicy` (5 wrong → 15 min lock) which is
	// IP-independent and therefore NAT-safe.
	cookieMode := handlers.CookieModeProd
	if cfg.Env == ModeDev {
		// SB_ENV=dev allows http://localhost (Vite dev server) so
		// the Secure flag must come off; the SameSite=Strict +
		// HttpOnly attributes stay on regardless of mode.
		cookieMode = handlers.CookieModeDev
	}
	authH := handlers.NewAuth(authSvc).WithSessions(sessionSvc, cookieMode)
	v1.Post("/auth/login",
		middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
			Name: "auth:login", Bucket: middleware.ByIP(),
			Limit: 30, Window: 60 * time.Second,
		}),
		authH.Login,
	)
	// Logout is rate-limited at the same bucket as login — a malicious
	// page can otherwise trigger session-revoke spam.
	v1.Post("/auth/logout",
		middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
			Name: "auth:logout", Bucket: middleware.ByIP(),
			Limit: 30, Window: 60 * time.Second,
		}),
		authH.Logout,
	)

	// OIDC (Slice B). Mounted only when SB_OIDC_ISSUER is set so
	// existing local-admin-only deployments keep working unchanged.
	// All four endpoints are public — auth comes from the IdP / from
	// the cookie set by Callback / from the logout_token signature.
	if cfg.OIDCIssuer != "" {
		if err := cfg.ValidateOIDCGroupMap(); err != nil {
			logger.Error("oidc group map", "error", err)
			os.Exit(1)
		}
		oidcCtx, oidcCancel := context.WithTimeout(context.Background(), 30*time.Second)
		oidcSvc, err := services.NewOIDCService(oidcCtx, services.OIDCConfig{
			Issuer:         cfg.OIDCIssuer,
			ClientID:       cfg.OIDCClientID,
			ClientSecret:   cfg.OIDCClientSecret,
			RedirectURL:    cfg.OIDCRedirectURL,
			Scopes:         strings.Fields(cfg.OIDCScopes),
			PostLogoutURL:  cfg.OIDCPostLogout,
			GroupClaim:     cfg.OIDCGroupClaim,
			GroupMap:       cfg.OIDCGroupMap,
			TrustAMRForMFA: cfg.OIDCTrustAMRForMFA,
		}, localUsersRepoInApp, sessionSvc, auditRepo, rdb)
		oidcCancel()
		if err != nil {
			logger.Error("oidc bootstrap", "error", err)
			os.Exit(1)
		}
		// Slice E — attach the role reconciler. Without this the
		// reconciler short-circuits (JIT users have no grants). The
		// reconciler ONLY touches rows with `granted_by=system:oidc`
		// — admin assignments and the SB_BOOTSTRAP_ADMIN grant are
		// invisible to it.
		oidcSvc = oidcSvc.WithRoleReconciler(roleRepo, userRoleRepo)
		oidcH := handlers.NewOIDC(oidcSvc, sessionSvc, cookieMode)
		// /start gets the same NAT-aware per-IP cap as /auth/login —
		// it's the public surface that can spawn IdP redirects.
		v1.Get("/auth/oidc/start",
			middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
				Name: "auth:oidc:start", Bucket: middleware.ByIP(),
				Limit: 30, Window: 60 * time.Second,
			}),
			oidcH.Start,
		)
		// /callback gets the architect-pre-wired 60/60s — auth codes
		// are single-use so the cap is purely anti-scan.
		v1.Get("/auth/oidc/callback",
			middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
				Name: "auth:oidc:callback", Bucket: middleware.ByIP(),
				Limit: 60, Window: 60 * time.Second,
			}),
			oidcH.Callback,
		)
		v1.Post("/auth/oidc/logout",
			middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
				Name: "auth:oidc:logout", Bucket: middleware.ByIP(),
				Limit: 30, Window: 60 * time.Second,
			}),
			oidcH.Logout,
		)
		// Back-channel logout (RFC 8417). IdP-to-CP only; the cap is
		// per-IP so a malicious IdP can't flood us.
		v1.Post("/auth/oidc/backchannel",
			middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
				Name: "auth:oidc:backchannel", Bucket: middleware.ByIP(),
				Limit: 60, Window: 60 * time.Second,
			}),
			oidcH.BackchannelLogout,
		)
		logger.Info("oidc client mounted", "issuer", cfg.OIDCIssuer)
	} else {
		logger.Info("oidc disabled (set SB_OIDC_ISSUER to enable)")
	}
	// OIDC callback bucket lands here once Slice B mounts the real
	// route; pre-wiring the limiter keeps Slice A1 self-contained.
	// Architect Q7 + NAT-aware: 60/60s per-IP (the auth code is
	// single-use, so the cap is purely anti-scan).

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
	v1.Post("/agents/:id/revoke", auth.Require(auth.PermAgentRevoke, rbacResolver), agentsH.Revoke)
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
	auditH := handlers.NewAudit(auditRepo, localUsersRepoInApp, agentRepo)
	v1.Get("/audit-events", auth.Require(auth.PermAuditRead, rbacResolver), auditH.List)

	// Tenancy admin — projects + environments. Pre-existed in the
	// schema (BRD §17, migration 0001) without an HTTP surface; this
	// wires admin CRUD so the UI can manage them. Projects use a
	// soft-delete (archive via status flip); environments hard-delete.
	v1.Post("/projects", tenancyH.CreateProject)
	v1.Get("/projects", tenancyH.ListProjects)
	v1.Get("/projects/:id", tenancyH.GetProject)
	v1.Put("/projects/:id/status", tenancyH.UpdateProjectStatus)
	v1.Put("/projects/:id/team", auth.Require(auth.PermTeamEdit, rbacResolver), tenancyH.SetProjectTeam)
	v1.Get("/projects/:id/environments", tenancyH.ListEnvironmentsForProject)

	// Project ↔ secret bindings (multi-tenancy, api#43 Slice A).
	// Admin scope today; once OIDC + RBAC route gating land (P0-1/P0-2)
	// these will require a `projects.bind` permission.
	v1.Post("/projects/:id/secrets", projectSecretsH.Bind)
	v1.Get("/projects/:id/secrets", projectSecretsH.List)
	v1.Put("/projects/:id/secrets/:secret_id", projectSecretsH.Update)
	v1.Delete("/projects/:id/secrets/:secret_id", projectSecretsH.Unbind)

	// Slice D (api#43): caller-scoped projection used by the UI
	// project switcher.
	v1.Get("/users/me", meH.GetMe)
	v1.Get("/users/me/projects", meH.ListProjects)

	// Slice H2 (api#64): user-self MFA enrollment + management. No
	// RBAC gate — every authenticated user manages their OWN factors.
	// Handler derives the user id from the session, never from the
	// body, so cross-user paths are structurally impossible.
	v1.Get("/users/me/mfa/factors", mfaH.List)
	v1.Delete("/users/me/mfa/factors/:id", mfaH.Delete)
	v1.Post("/users/me/mfa/totp/enroll", mfaH.EnrollTOTP)
	v1.Post("/users/me/mfa/totp/confirm", mfaH.ConfirmTOTP)
	v1.Post("/users/me/mfa/webauthn/register/start", mfaH.EnrollWebAuthnStart)
	v1.Post("/users/me/mfa/webauthn/register/finish", mfaH.EnrollWebAuthnFinish)

	// Slice H4: step-up verification — the SOLE path post-H4 that
	// stamps `last_mfa_at` on a session. /auth/mfa/challenge mints
	// the per-kind nonce (TOTP ticket OR WebAuthn assertion options),
	// /auth/mfa/verify consumes the user's response and stamps on
	// success. Same cookie auth chain as /users/me/mfa/*.
	v1.Post("/auth/mfa/challenge", authMFAH.Challenge)
	v1.Post("/auth/mfa/verify", authMFAH.Verify)

	v1.Post("/environments", tenancyH.CreateEnvironment)
	v1.Get("/environments", tenancyH.ListEnvironments)
	v1.Get("/environments/:id", tenancyH.GetEnvironment)
	v1.Delete("/environments/:id", tenancyH.DeleteEnvironment)

	// Teams admin (api#43-followup). N-level hierarchy via
	// parent_team_id. Membership is structural-only; role grants on a
	// team_id scope expand to the subtree via auth.EffectiveTeamAccess
	// (lands in a follow-up PR).
	v1.Post("/teams", auth.Require(auth.PermTeamEdit, rbacResolver), teamsH.Create)
	v1.Get("/teams", teamsH.List)
	v1.Get("/teams/:id", teamsH.Get)
	v1.Put("/teams/:id", auth.Require(auth.PermTeamEdit, rbacResolver), teamsH.Update)
	v1.Put("/teams/:id/status", auth.Require(auth.PermTeamEdit, rbacResolver), teamsH.UpdateStatus)
	v1.Delete("/teams/:id", auth.Require(auth.PermTeamEdit, rbacResolver), teamsH.Delete)
	v1.Post("/teams/:id/members", auth.Require(auth.PermTeamEdit, rbacResolver), teamsH.AddMember)
	v1.Get("/teams/:id/members", teamsH.ListMembers)
	v1.Delete("/teams/:id/members/:user_id", auth.Require(auth.PermTeamEdit, rbacResolver), teamsH.RemoveMember)

	// Patch-request lifecycle. Plaintext values arrive only via
	// POST /requests, are envelope-encrypted by WrapService before
	// touching Postgres, and never appear in responses.
	// Slice D — Tier 2 step-up gate. Approve / reject / reveal-wrap
	// require an MFA-fresh session (architect Q6). The middleware
	// 401s with `WWW-Authenticate: step-up max_age=900 acr_values=mfa`
	// when `last_mfa_at` is older than the session policy's StepUpTTL.
	// Sessions without an MFA stamp at all (local-admin sign-in, IdP
	// without MFA) fail closed. Mounted as a route-level middleware
	// AFTER AuthWith so the session pointer is in context.
	// Slice H5: pass the enrollment checker so stale-session-with-zero-
	// factors returns 412 mfa_enrollment_required (SPA routes to
	// /me/mfa) instead of an unreachable 401 step_up_required.
	requireMFA := middleware.RequireFreshMFA(sessionSvc, mfaVerifySvc)

	v1.Post("/requests", requestsH.Submit)
	v1.Post("/requests/read", requestsH.SubmitRead)
	v1.Get("/requests", requestsH.List)
	v1.Get("/requests/:id", requestsH.Get)
	v1.Post("/requests/:id/approve", requireMFA, requestsH.Approve)
	v1.Post("/requests/:id/reject", requireMFA, requestsH.Reject)
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
	//
	// Rate limit per architect Q7 (Slice A1): 20 / 60s per user (or
	// per IP for anonymous probes). The wrap is single-shot at the
	// service layer; the rate limit blunts pre-approval probing and
	// keeps a leaked `user_id` from being used to brute-discover wrap
	// IDs against the 404/410/200 oracle.
	v1.Get("/requests/:id/wraps/:wrap_id",
		middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
			Name: "wrap:retrieve", Bucket: middleware.ByQueryUserID(),
			Limit: 20, Window: 60 * time.Second,
		}),
		// Slice D Tier 2: reveal requires fresh MFA. The wrap is
		// single-shot at the service layer; gating step-up here means
		// a stolen cookie can't burn a wrap unless it also carries
		// fresh MFA proof.
		requireMFA,
		requestsH.RetrieveWrap,
	)

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
	// Heartbeat rate limit per architect Q7: 6 / 60s per-agent. The
	// limiter sits AFTER AgentAuth so the bucket key is the agent
	// UUID (authenticated). Using the path id pre-auth would let an
	// unauthenticated spammer burn through the bucket on a single
	// agent — post-auth keeps the bucket tied to the authenticated
	// actor.
	agentRoutes.Post("/heartbeat",
		middleware.RateLimit(rdb, logger, middleware.RateLimitConfig{
			Name: "agent:heartbeat", Bucket: middleware.ByPathAgentID(),
			Limit: 6, Window: 60 * time.Second,
		}),
		agentsH.Heartbeat,
	)
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
