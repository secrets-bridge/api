package services

// Agent Onboarding MVP (api#178) — enrollment-token generation + agent
// self-enrollment. Extends AgentService without touching the certified
// mint / heartbeat / AgentAuth paths. The persistent agent credential is
// still agents.secret_hash (returned once as agent_token).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Enrollment tuning.
const (
	enrollTokenDefaultTTLSeconds = 900   // 15m
	enrollTokenMinTTLSeconds     = 60    // 1m
	enrollTokenMaxTTLSeconds     = 86400 // 24h
	enrollHeartbeatIntervalSec   = 30
	enrollJobPollIntervalSec     = 5
)

// Enrollment sentinels — mapped to HTTP status in the handler layer.
var (
	ErrEnrollmentNotConfigured      = errors.New("services: enrollment not configured")
	ErrEnrollmentTokenInvalid       = errors.New("services: enrollment token invalid")
	ErrEnrollmentTokenExpired       = errors.New("services: enrollment token expired")
	ErrEnrollmentTokenConsumed      = errors.New("services: enrollment token already consumed")
	ErrEnrollmentTokenRevoked       = errors.New("services: enrollment token revoked")
	ErrEnrollmentProviderMismatch   = errors.New("services: provider_type mismatch")
	ErrEnrollmentClusterMismatch    = errors.New("services: cluster_name mismatch")
	ErrEnrollmentConnectionUnusable = errors.New("services: provider connection unavailable for enrollment")
)

// GenerateEnrollmentTokenInput is the admin request to mint a one-time
// enrollment token bound to a provider connection.
type GenerateEnrollmentTokenInput struct {
	ProviderConnectionID uuid.UUID
	Name                 string
	ExpiresInSeconds     int
	ExpectedClusterName  string
	ExpectedProviderType string
	CreatedBy            string // actor identity (session subject)
}

// GeneratedEnrollmentToken is returned by GenerateEnrollmentToken. Token is
// the plaintext, returned exactly ONCE — only its hash is persisted.
type GeneratedEnrollmentToken struct {
	Token                string
	ProviderConnectionID uuid.UUID
	ExpiresAt            time.Time
}

// GenerateEnrollmentToken validates the connection, mints a one-time token,
// stores only its SHA-256 hash, and returns the plaintext once.
func (s *AgentService) GenerateEnrollmentToken(ctx context.Context, in GenerateEnrollmentTokenInput) (*GeneratedEnrollmentToken, error) {
	if s.enrollTokens == nil || s.provConns == nil {
		return nil, ErrEnrollmentNotConfigured
	}
	if in.ProviderConnectionID == uuid.Nil {
		return nil, errors.New("agents: provider_connection_id is required")
	}
	if in.CreatedBy == "" {
		return nil, errors.New("agents: created_by is required")
	}

	conn, err := s.provConns.Get(ctx, in.ProviderConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return nil, storage.ErrConnectionNotFound
		}
		return nil, fmt.Errorf("agents: resolve provider connection: %w", err)
	}
	if conn.Status != storage.ProviderConnectionStatusActive {
		return nil, ErrEnrollmentConnectionUnusable
	}

	ttl := in.ExpiresInSeconds
	if ttl <= 0 {
		ttl = enrollTokenDefaultTTLSeconds
	}
	if ttl < enrollTokenMinTTLSeconds {
		ttl = enrollTokenMinTTLSeconds
	}
	if ttl > enrollTokenMaxTTLSeconds {
		ttl = enrollTokenMaxTTLSeconds
	}

	tokenBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))

	expiresAt := s.now().UTC().Add(time.Duration(ttl) * time.Second)
	row := &storage.AgentEnrollmentToken{
		ProviderConnectionID: in.ProviderConnectionID,
		Name:                 in.Name,
		TokenHash:            hash[:],
		ExpectedClusterName:  in.ExpectedClusterName,
		ExpectedProviderType: in.ExpectedProviderType,
		ExpiresAt:            expiresAt,
		CreatedBy:            in.CreatedBy,
	}
	if err := s.enrollTokens.Create(ctx, row); err != nil {
		return nil, fmt.Errorf("agents: create enrollment token: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + in.CreatedBy,
		Action:   "agent.enrollment_token.created",
		Resource: "provider_connection:" + in.ProviderConnectionID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"provider_connection_id": in.ProviderConnectionID.String(),
			"enrollment_token_id":    row.ID.String(),
			"expires_at":             expiresAt.Format(time.RFC3339),
			"expected_cluster_name":  in.ExpectedClusterName,
			"expected_provider_type": in.ExpectedProviderType,
		},
	})

	return &GeneratedEnrollmentToken{
		Token:                token,
		ProviderConnectionID: in.ProviderConnectionID,
		ExpiresAt:            expiresAt,
	}, nil
}

// EnrollInput is the agent's outbound self-enrollment request.
type EnrollInput struct {
	Token                string
	AgentName            string
	AgentVersion         string
	ClusterName          string
	ProviderType         string
	Region               string
	Capabilities         []string
	PublicKeyFingerprint string
}

// EnrolledAgent is returned by Enroll. AgentToken is the persistent agent
// credential — returned exactly ONCE, only its hash is stored.
type EnrolledAgent struct {
	AgentID                  uuid.UUID
	ProviderConnectionID     uuid.UUID
	AgentToken               string
	HeartbeatIntervalSeconds int
	JobPollIntervalSeconds   int
}

// Enroll validates a one-time token, creates a provider-connection-bound
// agent, consumes the token, and returns the persistent agent credential
// once. No provider credentials or secret values are ever returned.
func (s *AgentService) Enroll(ctx context.Context, in EnrollInput) (*EnrolledAgent, error) {
	if s.enrollTokens == nil || s.provConns == nil {
		return nil, ErrEnrollmentNotConfigured
	}
	if in.Token == "" {
		return nil, ErrEnrollmentTokenInvalid
	}
	if in.AgentName == "" {
		return nil, errors.New("agents: agent_name is required")
	}

	hash := sha256.Sum256([]byte(in.Token))
	tok, err := s.enrollTokens.GetByHash(ctx, hash[:])
	if err != nil {
		if errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
			return nil, ErrEnrollmentTokenInvalid
		}
		return nil, fmt.Errorf("agents: resolve enrollment token: %w", err)
	}

	now := s.now().UTC()
	// Order matters: revoked/consumed are terminal states distinct from
	// expiry so QA + the UI can tell them apart.
	if tok.RevokedAt != nil {
		return nil, ErrEnrollmentTokenRevoked
	}
	if tok.ConsumedAt != nil {
		return nil, ErrEnrollmentTokenConsumed
	}
	if !tok.ExpiresAt.After(now) {
		return nil, ErrEnrollmentTokenExpired
	}

	conn, err := s.provConns.Get(ctx, tok.ProviderConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return nil, ErrEnrollmentConnectionUnusable
		}
		return nil, fmt.Errorf("agents: resolve provider connection: %w", err)
	}
	if conn.Status != storage.ProviderConnectionStatusActive {
		return nil, ErrEnrollmentConnectionUnusable
	}

	// Provider type must agree with the bound connection (and the token's
	// expected value when configured). Empty agent-provided type defaults
	// to the connection's.
	connType := string(conn.Type)
	providerType := in.ProviderType
	if providerType == "" {
		providerType = connType
	}
	if providerType != connType {
		return nil, ErrEnrollmentProviderMismatch
	}
	if tok.ExpectedProviderType != "" && tok.ExpectedProviderType != providerType {
		return nil, ErrEnrollmentProviderMismatch
	}
	if tok.ExpectedClusterName != "" && tok.ExpectedClusterName != in.ClusterName {
		return nil, ErrEnrollmentClusterMismatch
	}

	secretBytes, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("agents: random agent secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	secretHash := sha256.Sum256([]byte(secret))

	connID := tok.ProviderConnectionID
	caps := in.Capabilities
	if caps == nil {
		caps = []string{}
	}
	agent := &storage.Agent{
		Name:                 in.AgentName,
		Status:               storage.AgentStatusEnrolled,
		SecretHash:           secretHash[:],
		ProviderConnectionID: &connID,
		ClusterName:          in.ClusterName,
		ProviderType:         providerType,
		Region:               in.Region,
		AgentVersion:         in.AgentVersion,
		PublicKeyFingerprint: in.PublicKeyFingerprint,
		Capabilities:         caps,
	}
	if err := s.agents.CreateEnrolled(ctx, agent); err != nil {
		return nil, fmt.Errorf("agents: create enrolled agent: %w", err)
	}

	// Single-use guard: burn the token atomically. A concurrent double
	// enrollment loses this race and is reported as already-consumed.
	if err := s.enrollTokens.MarkConsumed(ctx, tok.ID, agent.ID, now); err != nil {
		if errors.Is(err, storage.ErrEnrollmentTokenNotFound) {
			return nil, ErrEnrollmentTokenConsumed
		}
		return nil, fmt.Errorf("agents: consume enrollment token: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "agent:" + agent.ID.String(),
		Action:   "agent.enrolled",
		Resource: "agent:" + agent.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"agent_id":               agent.ID.String(),
			"provider_connection_id": connID.String(),
			"cluster_name":           in.ClusterName,
			"provider_type":          providerType,
			"agent_version":          in.AgentVersion,
			"capabilities":           caps,
		},
	})

	return &EnrolledAgent{
		AgentID:                  agent.ID,
		ProviderConnectionID:     connID,
		AgentToken:               secret,
		HeartbeatIntervalSeconds: enrollHeartbeatIntervalSec,
		JobPollIntervalSeconds:   enrollJobPollIntervalSec,
	}, nil
}
