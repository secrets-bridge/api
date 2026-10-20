package services

// GatewayService owns the Gateway registry (api#293): admin create, token
// mint and revoke, enrollment (E1), authentication of X-Gateway-Secret,
// heartbeat (E2), catalog (E3), connector approval and bindings.
//
// The credential model copies the agent one (agents.go,
// agent_enrollment.go): a one-time enrollment token and a long-lived
// secret, each returned once and stored only as a SHA-256 hash, compared
// in constant time, with a short Redis hash cache that revoke deletes.
// It shares no table, no cache key and no header with agents, so an agent
// credential never authenticates a Gateway and the reverse.
//
// Audit metadata is ids, enums and counts only. The token, the secret and
// their hashes never reach a log, an audit row or a response after mint.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Gateway service errors. The handler maps each to a status and a closed
// error code.
var (
	ErrGatewayEnrollmentTokenInvalid  = errors.New("services: gateway enrollment token invalid")
	ErrGatewayEnrollmentTokenExpired  = errors.New("services: gateway enrollment token expired")
	ErrGatewayEnrollmentTokenConsumed = errors.New("services: gateway enrollment token already consumed")
	ErrGatewayEnrollmentTokenRevoked  = errors.New("services: gateway enrollment token revoked")
	ErrGatewayClusterMismatch         = errors.New("services: gateway cluster_name mismatch")
	ErrGatewayAlreadyEnrolled         = errors.New("services: gateway already enrolled")
	ErrGatewayInsecureTransport       = errors.New("services: gateway enrollment over plain http")
	ErrGatewayRevoked                 = errors.New("services: gateway revoked")
	ErrGatewayReplicaLimit            = errors.New("services: gateway replica limit")
	ErrGatewayBindingInvalid          = errors.New("services: gateway binding invalid")
)

// Tuning. TTL bounds copy agent enrollment (15m default, 1m to 24h).
const (
	gatewayTokenDefaultTTL = 15 * time.Minute
	gatewayTokenMinTTL     = time.Minute
	gatewayTokenMaxTTL     = 24 * time.Hour
	// GatewayReplicaWindow is how long a replica counts towards
	// max_replicas after its last heartbeat.
	GatewayReplicaWindow = 10 * time.Minute

	cacheKindGatewaySecretHash  = "gateway-hash"
	cacheKindGatewayAuthReject  = "gateway-auth-reject-audit"
	cacheKindGatewayEnrollRej   = "gateway-enroll-reject-audit"
	cacheKindGatewayReplicaLimt = "gateway-replica-limit-audit"
)

// GatewayStore is the storage surface the service needs.
type GatewayStore interface {
	Create(ctx context.Context, g *storage.Gateway) error
	Get(ctx context.Context, id uuid.UUID) (*storage.Gateway, error)
	GetAuth(ctx context.Context, id uuid.UUID) (storage.GatewayStatus, []byte, error)
	List(ctx context.Context, seenSince time.Time) ([]*storage.Gateway, error)
	GetView(ctx context.Context, id uuid.UUID, seenSince time.Time) (*storage.Gateway, error)
	ListConnectorSummaries(ctx context.Context) ([]*storage.GatewayConnectorSummary, error)
	CreateEnrollmentToken(ctx context.Context, t *storage.GatewayEnrollmentToken) error
	GetEnrollmentTokenByHash(ctx context.Context, hash []byte) (*storage.GatewayEnrollmentToken, error)
	GetEnrollmentToken(ctx context.Context, id uuid.UUID) (*storage.GatewayEnrollmentToken, error)
	ListEnrollmentTokens(ctx context.Context, gatewayID uuid.UUID) ([]*storage.GatewayEnrollmentToken, error)
	RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, by string, at time.Time) error
	ConsumeTokenAndEnroll(ctx context.Context, tokenID uuid.UUID, at time.Time, secretHash []byte) (uuid.UUID, error)
	Revoke(ctx context.Context, id uuid.UUID, by string, at time.Time) (*storage.GatewayRevokeOutcome, error)
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool, at time.Time) (bool, *storage.GatewayRevokeOutcome, error)
	RecordHeartbeat(ctx context.Context, hb storage.GatewayHeartbeat, at, seenSince time.Time) (*storage.GatewayHeartbeatOutcome, error)
	ListReplicas(ctx context.Context, gatewayID uuid.UUID) ([]*storage.GatewayReplica, error)
	ListConnectors(ctx context.Context, gatewayID uuid.UUID) ([]*storage.GatewayConnector, error)
	GetConnector(ctx context.Context, id uuid.UUID) (*storage.GatewayConnector, error)
	ReplaceCatalog(ctx context.Context, gatewayID uuid.UUID, conns []storage.GatewayCatalogConnector, digest string, at time.Time) (*storage.GatewayCatalogOutcome, error)
	ApproveConnector(ctx context.Context, gatewayID, connectorID uuid.UUID, by string, at time.Time) (*storage.GatewayConnector, error)
	CreateBinding(ctx context.Context, b *storage.GatewayBinding) error
	GetBinding(ctx context.Context, id uuid.UUID) (*storage.GatewayBinding, error)
	ListBindings(ctx context.Context, gatewayID *uuid.UUID) ([]*storage.GatewayBinding, error)
	DeleteBinding(ctx context.Context, id uuid.UUID, at time.Time) ([]*storage.ObservationTask, error)
	EnvironmentProject(ctx context.Context, envID uuid.UUID) (uuid.UUID, error)
	SecretBoundToProject(ctx context.Context, secretID, projectID uuid.UUID) (bool, error)
	ProviderConnectionExists(ctx context.Context, id uuid.UUID) (bool, error)
}

// GatewayService is the Gateway registry service.
type GatewayService struct {
	store GatewayStore
	audit storage.AuditEventRepository
	rdb   *runtime.Client
	now   func() time.Time

	secretHashCacheTTL time.Duration
}

// NewGatewayService builds the service. rdb may be nil (no cache, no
// audit rollup).
func NewGatewayService(store GatewayStore, audit storage.AuditEventRepository, rdb *runtime.Client) *GatewayService {
	return &GatewayService{store: store, audit: audit, rdb: rdb, now: time.Now, secretHashCacheTTL: 60 * time.Second}
}

func (s *GatewayService) appendAudit(ctx context.Context, e *storage.AuditEvent) {
	_ = s.audit.Append(ctx, e)
}

func gatewayActor(id uuid.UUID) string { return "gateway:" + id.String() }

// ---- admin: create, tokens, revoke -------------------------------------

// CreateGatewayInput is the admin create body.
type CreateGatewayInput struct {
	Name             string
	Boundary         string
	EnvironmentID    *uuid.UUID
	MaxReplicas      int
	MaxInflightTasks int
	CreatedBy        string
}

// CreateGateway creates a pending Gateway with no credential.
func (s *GatewayService) CreateGateway(ctx context.Context, in CreateGatewayInput) (*storage.Gateway, error) {
	if !gatewayNameRe.MatchString(in.Name) {
		return nil, gatewayInvalid("name")
	}
	if !validLabel(in.Boundary, gatewayMaxBoundaryLen) {
		return nil, gatewayInvalid("boundary")
	}
	if in.MaxReplicas == 0 {
		in.MaxReplicas = 200
	}
	if in.MaxInflightTasks == 0 {
		in.MaxInflightTasks = 20
	}
	if in.MaxReplicas < 1 || in.MaxReplicas > 1000 {
		return nil, gatewayInvalid("max_replicas")
	}
	if in.MaxInflightTasks < 1 || in.MaxInflightTasks > 1000 {
		return nil, gatewayInvalid("max_inflight_tasks")
	}
	if in.EnvironmentID != nil {
		if _, err := s.store.EnvironmentProject(ctx, *in.EnvironmentID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, gatewayInvalid("environment_id")
			}
			return nil, err
		}
	}
	g := &storage.Gateway{
		Name: in.Name, Boundary: in.Boundary, EnvironmentID: in.EnvironmentID,
		MaxReplicas: in.MaxReplicas, MaxInflightTasks: in.MaxInflightTasks, CreatedBy: in.CreatedBy,
	}
	if err := s.store.Create(ctx, g); err != nil {
		if errors.Is(err, storage.ErrGatewayBindingReferenceNotFound) {
			return nil, gatewayInvalid("environment_id")
		}
		return nil, err
	}
	meta := map[string]any{
		"gateway_id": g.ID.String(), "name": g.Name,
		"max_replicas": g.MaxReplicas, "max_inflight_tasks": g.MaxInflightTasks,
	}
	if g.EnvironmentID != nil {
		meta["environment_id"] = g.EnvironmentID.String()
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, in.CreatedBy), Action: "gateway.create",
		Resource: gatewayActor(g.ID), Status: storage.AuditStatusSuccess, Metadata: meta,
	})
	return g, nil
}

// MintGatewayTokenInput is the admin token body.
type MintGatewayTokenInput struct {
	GatewayID           uuid.UUID
	ExpiresInSeconds    int
	ExpectedClusterName string
	CreatedBy           string
}

// MintedGatewayToken holds the plaintext token, returned exactly once.
type MintedGatewayToken struct {
	ID        uuid.UUID
	GatewayID uuid.UUID
	Token     string
	ExpiresAt time.Time
}

// MintEnrollmentToken mints a one-time token for a pending Gateway and
// stores only its hash.
func (s *GatewayService) MintEnrollmentToken(ctx context.Context, in MintGatewayTokenInput) (*MintedGatewayToken, error) {
	if in.ExpectedClusterName != "" && !gatewayClusterNameRe.MatchString(in.ExpectedClusterName) {
		return nil, gatewayInvalid("expected_cluster_name")
	}
	ttl := time.Duration(in.ExpiresInSeconds) * time.Second
	if in.ExpiresInSeconds <= 0 {
		ttl = gatewayTokenDefaultTTL
	}
	ttl = min(max(ttl, gatewayTokenMinTTL), gatewayTokenMaxTTL)

	raw, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("gateways: random enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	expiresAt := s.now().UTC().Add(ttl)
	row := &storage.GatewayEnrollmentToken{
		GatewayID: in.GatewayID, TokenHash: hash[:], ExpectedClusterName: in.ExpectedClusterName,
		ExpiresAt: expiresAt, CreatedBy: in.CreatedBy,
	}
	if err := s.store.CreateEnrollmentToken(ctx, row); err != nil {
		if errors.Is(err, storage.ErrGatewayAlreadyEnrolled) {
			return nil, ErrGatewayAlreadyEnrolled
		}
		return nil, err
	}
	meta := map[string]any{
		"gateway_id": in.GatewayID.String(), "enrollment_token_id": row.ID.String(),
		"expires_at": expiresAt.Format(time.RFC3339),
	}
	if in.ExpectedClusterName != "" {
		meta["expected_cluster_name"] = in.ExpectedClusterName
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, in.CreatedBy), Action: "gateway.enrollment_token.create",
		Resource: gatewayActor(in.GatewayID), Status: storage.AuditStatusSuccess, Metadata: meta,
	})
	return &MintedGatewayToken{ID: row.ID, GatewayID: in.GatewayID, Token: token, ExpiresAt: expiresAt}, nil
}

// RevokeEnrollmentToken revokes an unused token.
func (s *GatewayService) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, by string) error {
	tok, err := s.store.GetEnrollmentToken(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.RevokeEnrollmentToken(ctx, id, by, s.now().UTC()); err != nil {
		return err
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, by), Action: "gateway.enrollment_token.revoke",
		Resource: gatewayActor(tok.GatewayID), Status: storage.AuditStatusSuccess,
		Metadata: map[string]any{"gateway_id": tok.GatewayID.String(), "enrollment_token_id": id.String()},
	})
	return nil
}

// Revoke revokes a Gateway and its unused tokens, moves its leased
// observation tasks back to queued (their attempts closed, so a late
// result is refused), then deletes the auth cache entry so the next call
// is refused.
func (s *GatewayService) Revoke(ctx context.Context, id uuid.UUID, by, reason string) (*storage.Gateway, error) {
	out, err := s.store.Revoke(ctx, id, by, s.now().UTC())
	if err != nil {
		return nil, err
	}
	s.invalidateSecretHashCache(ctx, id)
	meta := map[string]any{
		"gateway_id": id.String(), "enrollment_tokens_revoked": out.TokensRevoked,
		"tasks_requeued": out.TasksRequeued,
	}
	if reason != "" {
		meta["reason"] = reason
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, by), Action: "gateway.revoke",
		Resource: gatewayActor(id), Status: storage.AuditStatusSuccess, Metadata: meta,
	})
	return s.store.Get(ctx, id)
}

// SetEnabled disables or re-enables a Gateway (design section 9,
// gateway.revoke). Disabling refuses the Gateway's next call with 401,
// like revoke, and moves its leased observation tasks back to queued;
// unlike revoke it can be undone and keeps the credential. The auth
// cache entry is dropped either way.
func (s *GatewayService) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool, by string) (*storage.Gateway, error) {
	changed, out, err := s.store.SetEnabled(ctx, id, enabled, s.now().UTC())
	if err != nil {
		return nil, err
	}
	s.invalidateSecretHashCache(ctx, id)
	if changed {
		action := "gateway.enable"
		meta := map[string]any{"gateway_id": id.String()}
		if !enabled {
			action = "gateway.disable"
			meta["tasks_requeued"] = out.TasksRequeued
		}
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: auditActor(ctx, by), Action: action,
			Resource: gatewayActor(id), Status: storage.AuditStatusSuccess, Metadata: meta,
		})
	}
	return s.store.Get(ctx, id)
}

// ---- E1 enroll ---------------------------------------------------------

// GatewayEnrollInput is the E1 body plus what the handler knows about the
// transport.
type GatewayEnrollInput struct {
	Token       string
	ClusterName string
	// Insecure is true when the request arrived over plain http in a
	// production deployment. Enrollment is refused (ADR 0001 section 11).
	Insecure bool
}

// EnrolledGateway holds the gateway secret, returned exactly once.
type EnrolledGateway struct {
	GatewayID                uuid.UUID
	Secret                   string
	HeartbeatIntervalSeconds int
	ClaimPollSeconds         int
}

// Enroll exchanges a one-time token for the Gateway's secret. Scope comes
// from the pre-created gateways row, never from the body.
func (s *GatewayService) Enroll(ctx context.Context, in GatewayEnrollInput) (*EnrolledGateway, error) {
	res, tokenID, err := s.enroll(ctx, in)
	if err != nil {
		if reason, ok := gatewayEnrollRejectReason(err); ok && s.claimRejectSlot(ctx, cacheKindGatewayEnrollRej, "enroll", reason) {
			meta := map[string]any{"reason": reason, "rollup_window_seconds": int(rejectAuditWindow / time.Second)}
			if tokenID != uuid.Nil {
				meta["enrollment_token_id"] = tokenID.String()
			}
			s.appendAudit(ctx, &storage.AuditEvent{
				Actor: "gateway:enroll", Action: "gateway.enroll", Resource: "gateway_enrollment_token",
				Status: storage.AuditStatusDenied, Metadata: meta,
			})
		}
		return nil, err
	}
	meta := map[string]any{"gateway_id": res.GatewayID.String(), "enrollment_token_id": tokenID.String()}
	if in.ClusterName != "" && gatewayClusterNameRe.MatchString(in.ClusterName) {
		meta["cluster_name"] = in.ClusterName
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: gatewayActor(res.GatewayID), Action: "gateway.enroll",
		Resource: gatewayActor(res.GatewayID), Status: storage.AuditStatusSuccess, Metadata: meta,
	})
	return res, nil
}

func gatewayEnrollRejectReason(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrGatewayEnrollmentTokenInvalid):
		return "invalid", true
	case errors.Is(err, ErrGatewayEnrollmentTokenExpired):
		return "expired", true
	case errors.Is(err, ErrGatewayEnrollmentTokenConsumed):
		return "consumed", true
	case errors.Is(err, ErrGatewayEnrollmentTokenRevoked):
		return "revoked", true
	case errors.Is(err, ErrGatewayAlreadyEnrolled):
		return "already_enrolled", true
	case errors.Is(err, ErrGatewayClusterMismatch):
		return "cluster_name_mismatch", true
	case errors.Is(err, ErrGatewayInsecureTransport):
		return "insecure_transport", true
	}
	return "", false
}

func (s *GatewayService) enroll(ctx context.Context, in GatewayEnrollInput) (*EnrolledGateway, uuid.UUID, error) {
	if in.Insecure {
		return nil, uuid.Nil, ErrGatewayInsecureTransport
	}
	if in.Token == "" || len(in.Token) > 256 {
		return nil, uuid.Nil, ErrGatewayEnrollmentTokenInvalid
	}
	if in.ClusterName != "" && !gatewayClusterNameRe.MatchString(in.ClusterName) {
		return nil, uuid.Nil, gatewayInvalid("cluster_name")
	}
	hash := sha256.Sum256([]byte(in.Token))
	tok, err := s.store.GetEnrollmentTokenByHash(ctx, hash[:])
	if err != nil {
		if errors.Is(err, storage.ErrGatewayEnrollmentTokenNotFound) {
			return nil, uuid.Nil, ErrGatewayEnrollmentTokenInvalid
		}
		return nil, uuid.Nil, err
	}
	now := s.now().UTC()
	// Revoked and consumed are terminal and told apart from expiry, as
	// for agent tokens.
	switch {
	case tok.RevokedAt != nil:
		return nil, tok.ID, ErrGatewayEnrollmentTokenRevoked
	case tok.ConsumedAt != nil:
		return nil, tok.ID, ErrGatewayEnrollmentTokenConsumed
	case !tok.ExpiresAt.After(now):
		return nil, tok.ID, ErrGatewayEnrollmentTokenExpired
	}
	if tok.ExpectedClusterName != "" && tok.ExpectedClusterName != in.ClusterName {
		return nil, tok.ID, ErrGatewayClusterMismatch
	}

	raw, err := randomBytes(32)
	if err != nil {
		return nil, tok.ID, fmt.Errorf("gateways: random secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	secretHash := sha256.Sum256([]byte(secret))
	gatewayID, err := s.store.ConsumeTokenAndEnroll(ctx, tok.ID, now, secretHash[:])
	switch {
	case errors.Is(err, storage.ErrGatewayAlreadyEnrolled):
		return nil, tok.ID, ErrGatewayAlreadyEnrolled
	case errors.Is(err, storage.ErrGatewayEnrollmentTokenNotFound):
		return nil, tok.ID, s.unconsumableTokenErr(ctx, tok.ID, now)
	case err != nil:
		return nil, tok.ID, err
	}
	s.invalidateSecretHashCache(ctx, gatewayID)
	return &EnrolledGateway{
		GatewayID: gatewayID, Secret: secret,
		HeartbeatIntervalSeconds: gatewayHeartbeatIntervalSec, ClaimPollSeconds: gatewayClaimPollSec,
	}, tok.ID, nil
}

// unconsumableTokenErr names why the transactional consume matched no
// row after the pre-checks passed: a revoke or expiry that landed in
// between, or a lost race (consumed).
func (s *GatewayService) unconsumableTokenErr(ctx context.Context, id uuid.UUID, now time.Time) error {
	tok, err := s.store.GetEnrollmentToken(ctx, id)
	switch {
	case err != nil:
		return ErrGatewayEnrollmentTokenInvalid
	case tok.RevokedAt != nil:
		return ErrGatewayEnrollmentTokenRevoked
	case !tok.ExpiresAt.After(now) && tok.ConsumedAt == nil:
		return ErrGatewayEnrollmentTokenExpired
	default:
		return ErrGatewayEnrollmentTokenConsumed
	}
}

// ---- authentication ----------------------------------------------------

type cachedGatewayHash struct {
	Status string `json:"status"`
	Hash   []byte `json:"hash"`
}

// Authenticate checks X-Gateway-Secret for gateway id. Unknown Gateway,
// a Gateway that is not active or stale, and a wrong secret all fail;
// the caller answers a generic 401 and the reason goes to the audit log,
// rolled up per (id, reason).
func (s *GatewayService) Authenticate(ctx context.Context, id uuid.UUID, secret string) error {
	cached, ok := s.readSecretHashCache(ctx, id)
	if !ok {
		status, hash, err := s.store.GetAuth(ctx, id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				s.auditAuthRejected(ctx, id, "unknown_gateway")
			}
			return err
		}
		cached = cachedGatewayHash{Status: string(status), Hash: hash}
		s.fillSecretHashCache(ctx, id, cached)
	}
	if !storage.GatewayStatus(cached.Status).Live() {
		s.auditAuthRejected(ctx, id, "status_"+cached.Status)
		return storage.ErrUnauthorized
	}
	if len(cached.Hash) == 0 {
		s.auditAuthRejected(ctx, id, "no_credential")
		return storage.ErrUnauthorized
	}
	presented := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(presented[:], cached.Hash) != 1 {
		s.auditAuthRejected(ctx, id, "bad_secret")
		return storage.ErrUnauthorized
	}
	return nil
}

func (s *GatewayService) auditAuthRejected(ctx context.Context, id uuid.UUID, reason string) {
	subject := id.String()
	if reason == "unknown_gateway" {
		subject = "unknown" // caller-chosen ids share one bucket
	}
	if !s.claimRejectSlot(ctx, cacheKindGatewayAuthReject, subject, reason) {
		return
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: gatewayActor(id), Action: "gateway.auth.rejected", Resource: gatewayActor(id),
		Status:   storage.AuditStatusDenied,
		Metadata: map[string]any{"reason": reason, "rollup_window_seconds": int(rejectAuditWindow / time.Second)},
	})
}

// claimRejectSlot is the agent rollup (claimRejectAuditSlot) under the
// Gateway's own key kinds: true for the first (subject, reason) per
// window, and always true without Redis.
func (s *GatewayService) claimRejectSlot(ctx context.Context, kind, subject, reason string) bool {
	if s.rdb == nil {
		return true
	}
	ok, err := s.rdb.Raw().SetNX(ctx, s.rdb.Key(kind, subject+":"+reason), "1", rejectAuditWindow).Result()
	if err != nil {
		return true
	}
	return ok
}

func (s *GatewayService) readSecretHashCache(ctx context.Context, id uuid.UUID) (cachedGatewayHash, bool) {
	if s.rdb == nil {
		return cachedGatewayHash{}, false
	}
	raw, err := s.rdb.Raw().Get(ctx, s.rdb.Key(cacheKindGatewaySecretHash, id.String())).Bytes()
	if err != nil {
		return cachedGatewayHash{}, false
	}
	var c cachedGatewayHash
	if json.Unmarshal(raw, &c) != nil {
		return cachedGatewayHash{}, false
	}
	return c, true
}

// fillSecretHashCache writes the entry, then re-reads the row and drops
// the entry if it changed, so a revoke that committed between the read
// and the write never leaves a live entry behind (same as agents,
// API-S-21).
func (s *GatewayService) fillSecretHashCache(ctx context.Context, id uuid.UUID, c cachedGatewayHash) {
	if s.rdb == nil {
		return
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return
	}
	_, _ = s.rdb.Raw().Set(ctx, s.rdb.Key(cacheKindGatewaySecretHash, id.String()), raw, s.secretHashCacheTTL).Result()
	status, hash, err := s.store.GetAuth(ctx, id)
	if err != nil || string(status) != c.Status || !bytes.Equal(hash, c.Hash) {
		s.invalidateSecretHashCache(ctx, id)
	}
}

func (s *GatewayService) invalidateSecretHashCache(ctx context.Context, id uuid.UUID) {
	if s.rdb == nil {
		return
	}
	_, _ = s.rdb.Raw().Del(ctx, s.rdb.Key(cacheKindGatewaySecretHash, id.String())).Result()
}

// ---- E2 heartbeat ------------------------------------------------------

// GatewayHeartbeatResult is the E2 200 body.
type GatewayHeartbeatResult struct {
	ServerTime           time.Time
	NextHeartbeatSeconds int
	ClaimPollSeconds     int
	ContractVersion      string
	CatalogVersion       string
}

// Heartbeat records one replica's heartbeat for an authenticated Gateway.
func (s *GatewayService) Heartbeat(ctx context.Context, gatewayID uuid.UUID, in GatewayHeartbeatInput) (*GatewayHeartbeatResult, error) {
	replicaID, err := in.validate()
	if err != nil {
		return nil, err
	}
	connectors := in.Connectors
	if connectors == nil {
		connectors = []storage.GatewayConnectorHealth{}
	}
	now := s.now().UTC()
	out, err := s.store.RecordHeartbeat(ctx, storage.GatewayHeartbeat{
		GatewayID: gatewayID, ReplicaID: replicaID, GatewayVersion: in.GatewayVersion,
		ContractVersions: in.ContractVersions, Status: in.Status, InFlight: in.InFlight,
		CatalogVersion: in.CatalogVersion, Connectors: connectors,
	}, now, now.Add(-GatewayReplicaWindow))
	switch {
	case errors.Is(err, storage.ErrGatewayReplicaLimit):
		if s.claimRejectSlot(ctx, cacheKindGatewayReplicaLimt, gatewayID.String(), "replica_limit") {
			s.appendAudit(ctx, &storage.AuditEvent{
				Actor: gatewayActor(gatewayID), Action: "gateway.replica_limit", Resource: gatewayActor(gatewayID),
				Status: storage.AuditStatusDenied,
				Metadata: map[string]any{
					"gateway_id": gatewayID.String(), "replica_id": replicaID.String(),
					"max_replicas": out.MaxReplicas, "rollup_window_seconds": int(rejectAuditWindow / time.Second),
				},
			})
		}
		return nil, ErrGatewayReplicaLimit
	case errors.Is(err, storage.ErrGatewayNotLive):
		s.invalidateSecretHashCache(ctx, gatewayID)
		return nil, ErrGatewayRevoked
	case err != nil:
		return nil, err
	}
	if in.Status == "over_privileged" && out.PrevReplicaStatus != "over_privileged" {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: gatewayActor(gatewayID), Action: "gateway.over_privileged", Resource: gatewayActor(gatewayID),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{"gateway_id": gatewayID.String(), "replica_id": replicaID.String()},
		})
	}
	return &GatewayHeartbeatResult{
		ServerTime: now, NextHeartbeatSeconds: gatewayHeartbeatIntervalSec, ClaimPollSeconds: gatewayClaimPollSec,
		ContractVersion: gatewayContractVersion, CatalogVersion: out.CatalogVersion,
	}, nil
}

// ---- E3 catalog --------------------------------------------------------

// GatewayCatalogResult is the E3 200 body.
type GatewayCatalogResult struct {
	Accepted       int
	TargetsStale   int
	CatalogVersion string
}

// PutCatalog replaces the Gateway's advertised catalog. It never creates
// a binding or approves a connector.
func (s *GatewayService) PutCatalog(ctx context.Context, gatewayID uuid.UUID, conns []GatewayCatalogConnector) (*GatewayCatalogResult, error) {
	norm, err := normalizeCatalog(conns)
	if err != nil {
		return nil, err
	}
	digest, err := catalogDigest(norm)
	if err != nil {
		return nil, fmt.Errorf("gateways: catalog digest: %w", err)
	}
	out, err := s.store.ReplaceCatalog(ctx, gatewayID, norm, digest, s.now().UTC())
	if errors.Is(err, storage.ErrGatewayNotLive) {
		s.invalidateSecretHashCache(ctx, gatewayID)
		return nil, ErrGatewayRevoked
	}
	if err != nil {
		return nil, err
	}
	actor := gatewayActor(gatewayID)
	if out.Changed {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "gateway.catalog.updated", Resource: actor, Status: storage.AuditStatusSuccess,
			Metadata: map[string]any{
				"gateway_id": gatewayID.String(), "catalog_version": digest, "connector_count": out.Accepted,
				"target_count": out.Targets, "targets_stale": out.TargetsStale, "connectors_missing": len(out.Missing),
			},
		})
	}
	for _, c := range out.Missing {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "gateway.connector.missing", Resource: actor, Status: storage.AuditStatusSuccess,
			Metadata: map[string]any{"gateway_id": gatewayID.String(), "connector_id": c.ID.String(), "kind": c.Kind},
		})
	}
	for _, c := range out.Reset {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "gateway.connector.approval_reset", Resource: actor, Status: storage.AuditStatusSuccess,
			Metadata: map[string]any{"gateway_id": gatewayID.String(), "connector_id": c.ID.String(), "kind": c.Kind},
		})
	}
	return &GatewayCatalogResult{Accepted: out.Accepted, TargetsStale: out.TargetsStale, CatalogVersion: digest}, nil
}

// ---- admin reads -------------------------------------------------------

// GatewayDetail is one Gateway with its replicas, connectors, bindings
// and tokens (metadata only).
type GatewayDetail struct {
	Gateway    *storage.Gateway
	Replicas   []*storage.GatewayReplica
	Connectors []*storage.GatewayConnector
	Bindings   []*storage.GatewayBinding
	Tokens     []*storage.GatewayEnrollmentToken
}

// List returns every Gateway with the replicas seen in the window.
func (s *GatewayService) List(ctx context.Context) ([]*storage.Gateway, error) {
	return s.store.List(ctx, s.now().UTC().Add(-GatewayReplicaWindow))
}

// ConnectorSummaries returns every Gateway's connectors as kind, status
// and target count, keyed by Gateway id, for the list.
func (s *GatewayService) ConnectorSummaries(ctx context.Context) (map[uuid.UUID][]*storage.GatewayConnectorSummary, error) {
	cs, err := s.store.ListConnectorSummaries(ctx)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID][]*storage.GatewayConnectorSummary{}
	for _, c := range cs {
		out[c.GatewayID] = append(out[c.GatewayID], c)
	}
	return out, nil
}

// Get returns one Gateway's detail. The Gateway carries the same replica
// rollup (replicas_seen, over_privileged) as List.
func (s *GatewayService) Get(ctx context.Context, id uuid.UUID) (*GatewayDetail, error) {
	g, err := s.store.GetView(ctx, id, s.now().UTC().Add(-GatewayReplicaWindow))
	if err != nil {
		return nil, err
	}
	d := &GatewayDetail{Gateway: g}
	if d.Replicas, err = s.store.ListReplicas(ctx, id); err != nil {
		return nil, err
	}
	if d.Connectors, err = s.store.ListConnectors(ctx, id); err != nil {
		return nil, err
	}
	if d.Bindings, err = s.store.ListBindings(ctx, &id); err != nil {
		return nil, err
	}
	if d.Tokens, err = s.store.ListEnrollmentTokens(ctx, id); err != nil {
		return nil, err
	}
	return d, nil
}

// ---- connectors and bindings -------------------------------------------

// ApproveConnector approves an advertised connector of a Gateway.
func (s *GatewayService) ApproveConnector(ctx context.Context, gatewayID, connectorID uuid.UUID, by string) (*storage.GatewayConnector, error) {
	c, err := s.store.ApproveConnector(ctx, gatewayID, connectorID, by, s.now().UTC())
	if err != nil {
		return nil, err
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, by), Action: "gateway.connector.approved", Resource: gatewayActor(gatewayID),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"gateway_id": gatewayID.String(), "connector_id": c.ID.String(), "kind": c.Kind},
	})
	return c, nil
}

// CreateBindingInput is the admin bind body. Release 1 binds one Argo CD
// target (gateway#12).
type CreateBindingInput struct {
	GatewayID            uuid.UUID
	EnvironmentID        uuid.UUID
	ProjectID            *uuid.UUID
	SecretID             *uuid.UUID
	ProviderConnectionID *uuid.UUID
	SecretRef            string
	ArgoCDConnectorID    uuid.UUID
	ArgoCDTargetID       string
	ObservationTimeoutS  int
	CreatedBy            string
}

// bindingInvalid names the rule a bind broke, as a closed code.
func bindingInvalid(code string) error { return fmt.Errorf("%w: %s", ErrGatewayBindingInvalid, code) }

// BindingErrorCode returns the closed code of a binding error.
func BindingErrorCode(err error) string {
	if !errors.Is(err, ErrGatewayBindingInvalid) {
		return ""
	}
	msg := err.Error()
	const prefix = "services: gateway binding invalid: "
	if len(msg) > len(prefix) {
		return msg[len(prefix):]
	}
	return "invalid_binding"
}

// CreateBinding binds an advertised Argo CD target of a Gateway to a
// secret scope in an environment. The service checks what foreign keys
// cannot: same Gateway, approved, right kind, target advertised and not
// stale, environment in the project and in the Gateway's environment.
func (s *GatewayService) CreateBinding(ctx context.Context, in CreateBindingInput) (*storage.GatewayBinding, error) {
	if in.ObservationTimeoutS == 0 {
		in.ObservationTimeoutS = 1800
	}
	if in.ObservationTimeoutS < 60 || in.ObservationTimeoutS > 86400 {
		return nil, bindingInvalid("observation_timeout_out_of_range")
	}
	if !ValidGatewayLocalID(in.ArgoCDTargetID) {
		return nil, bindingInvalid("target_id_invalid")
	}
	scopeSecret := in.SecretID != nil
	scopeConn := in.ProviderConnectionID != nil || in.SecretRef != ""
	if scopeSecret == scopeConn {
		return nil, bindingInvalid("secret_scope_required")
	}
	if scopeConn && (in.ProviderConnectionID == nil || !validSecretRef(in.SecretRef)) {
		return nil, bindingInvalid("secret_scope_required")
	}

	g, err := s.store.Get(ctx, in.GatewayID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, bindingInvalid("gateway_not_found")
		}
		return nil, err
	}
	if g.Status == storage.GatewayStatusRevoked {
		return nil, bindingInvalid("gateway_revoked")
	}
	projectID, err := s.store.EnvironmentProject(ctx, in.EnvironmentID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, bindingInvalid("environment_not_found")
		}
		return nil, err
	}
	if in.ProjectID != nil && *in.ProjectID != projectID {
		return nil, bindingInvalid("environment_not_in_project")
	}
	if g.EnvironmentID != nil && *g.EnvironmentID != in.EnvironmentID {
		return nil, bindingInvalid("environment_outside_gateway")
	}
	if scopeSecret {
		ok, err := s.store.SecretBoundToProject(ctx, *in.SecretID, projectID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, bindingInvalid("secret_not_in_project")
		}
	} else {
		ok, err := s.store.ProviderConnectionExists(ctx, *in.ProviderConnectionID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, bindingInvalid("provider_connection_not_found")
		}
	}
	conn, err := s.store.GetConnector(ctx, in.ArgoCDConnectorID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, bindingInvalid("connector_not_found")
		}
		return nil, err
	}
	switch {
	case conn.GatewayID != in.GatewayID:
		return nil, bindingInvalid("connector_not_found")
	case conn.Kind != GatewayKindArgoCD:
		return nil, bindingInvalid("connector_kind_not_supported")
	case conn.Status != storage.GatewayConnectorApproved:
		return nil, bindingInvalid("connector_not_approved")
	}
	t, ok := conn.Target(in.ArgoCDTargetID)
	if !ok {
		return nil, bindingInvalid("target_not_advertised")
	}
	if t.Stale {
		return nil, bindingInvalid("target_stale")
	}

	connID := conn.ID
	b := &storage.GatewayBinding{
		GatewayID: in.GatewayID, EnvironmentID: in.EnvironmentID, ProjectID: projectID,
		SecretID: in.SecretID, ProviderConnectionID: in.ProviderConnectionID, SecretRef: in.SecretRef,
		ExpectedStages:    []string{"argocd_context"},
		ArgoCDConnectorID: &connID, ArgoCDTargetID: in.ArgoCDTargetID,
		ObservationTimeoutS: in.ObservationTimeoutS, CreatedBy: in.CreatedBy,
	}
	if err := s.store.CreateBinding(ctx, b); err != nil {
		switch {
		case errors.Is(err, storage.ErrGatewayBindingExists):
			return nil, bindingInvalid("binding_exists")
		case errors.Is(err, storage.ErrGatewayBindingReferenceNotFound):
			return nil, bindingInvalid("reference_not_found")
		}
		return nil, err
	}
	b.Enabled = true
	meta := map[string]any{
		"binding_id": b.ID.String(), "gateway_id": b.GatewayID.String(),
		"environment_id": b.EnvironmentID.String(), "project_id": projectID.String(),
		"argocd_connector_id": connID.String(), "argocd_target_id": b.ArgoCDTargetID,
		"expected_stages": b.ExpectedStages, "observation_timeout_seconds": b.ObservationTimeoutS,
	}
	if b.SecretID != nil {
		meta["secret_id"] = b.SecretID.String()
	} else {
		meta["provider_connection_id"] = b.ProviderConnectionID.String()
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, in.CreatedBy), Action: "gateway.binding.create", Resource: gatewayActor(b.GatewayID),
		Status: storage.AuditStatusSuccess, Metadata: meta,
	})
	return b, nil
}

// ListBindings returns live bindings, for one Gateway when set.
func (s *GatewayService) ListBindings(ctx context.Context, gatewayID *uuid.UUID) ([]*storage.GatewayBinding, error) {
	return s.store.ListBindings(ctx, gatewayID)
}

// DeleteBinding soft-deletes a binding and cancels its open
// observation tasks (reason binding_removed).
func (s *GatewayService) DeleteBinding(ctx context.Context, id uuid.UUID, by string) error {
	b, err := s.store.GetBinding(ctx, id)
	if err != nil {
		return err
	}
	cancelled, err := s.store.DeleteBinding(ctx, id, s.now().UTC())
	if err != nil {
		return err
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: auditActor(ctx, by), Action: "gateway.binding.delete", Resource: gatewayActor(b.GatewayID),
		Status: storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"binding_id": id.String(), "gateway_id": b.GatewayID.String(), "tasks_cancelled": len(cancelled),
		},
	})
	for _, t := range cancelled {
		auditTaskClosed(ctx, s.audit, auditActor(ctx, by), "observation.task.cancelled", t)
	}
	return nil
}
