// Package services — reveal_sessions.go: the bulk-reveal session
// orchestrator.
//
// Slice M2. A reveal session is the breadcrumb that pairs a SPA reveal
// window (the visible-plaintext window in React refs) with a
// server-side TTL row. The plaintext never lives in the session row —
// only wrap_ids + envelope timing — so even a DB exfil can't recover
// the values revealed during the window.
//
// Design: Open does NOT consume wraps. The SPA picks them up one at a
// time via the existing single-shot user-bound retrieval
// (GET /api/v1/requests/:id/wraps/:wrap_id), which is already
// rate-limited + MFA-gated. MarkExpired and the M3 sweeper advance the
// underlying wraps' TTL to "now" so any post-expiry retrieve gets a
// clean 410 — no double-window risk.
//
// State at rest (reveal_sessions row):
//
//	expired_at IS NULL                  → active
//	expired_at SET, reason='ttl'        → swept by worker (M3)
//	expired_at SET, reason='user_hide'  → user clicked Hide Now
//	expired_at SET, reason='unmount'    → SPA navigated away
//
// Hard rules:
//   - No secret values in reveal_sessions rows (schema enforces).
//   - No secret values in `reveal.session.opened` / `reveal.session.expired`
//     audit metadata — key_names[] only.
//   - Caller owns the session: Open binds user_id; MarkExpired refuses
//     non-owner; ListActiveForUser filters by user_id.
//   - TTL is policy-driven (PolicyDecision.RevealTTLSeconds, clamped to
//     schema range 10..300) — no caller-controlled TTL.
package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// RevealSessionService orchestrates the bulk-reveal session lifecycle.
type RevealSessionService struct {
	sessions  storage.RevealSessionRepository
	requests  storage.AccessRequestRepository
	wraps     *WrapService
	policy    *PolicyEngine
	envs      storage.EnvironmentRepository
	audit     storage.AuditEventRepository
	now       func() time.Time
}

// NewRevealSessionService wires a RevealSessionService to its deps.
// envs is optional — when nil, Open falls back to ttlDefault (60s) and
// skips the policy lookup; in production main.go always wires it.
func NewRevealSessionService(
	sessions storage.RevealSessionRepository,
	requests storage.AccessRequestRepository,
	wraps *WrapService,
	policy *PolicyEngine,
	audit storage.AuditEventRepository,
) *RevealSessionService {
	return &RevealSessionService{
		sessions: sessions,
		requests: requests,
		wraps:    wraps,
		policy:   policy,
		audit:    audit,
		now:      time.Now,
	}
}

// WithEnvironments attaches the env repository so Open can look up the
// kind for the PolicyEngine call. Returns the service for chaining.
func (s *RevealSessionService) WithEnvironments(envs storage.EnvironmentRepository) *RevealSessionService {
	s.envs = envs
	return s
}

// TTL clamp matches the reveal_sessions schema CHECK and the
// policy_rules schema CHECK (BETWEEN 10 AND 300).
const (
	revealTTLMinSeconds     = 10
	revealTTLMaxSeconds     = 300
	revealTTLDefaultSeconds = 60
)

// OpenInput carries the data Open needs from the handler.
type OpenInput struct {
	UserID    string
	RequestID uuid.UUID
}

// WrapHandle is the value-free per-wrap descriptor returned by Open.
// The SPA uses (WrapID, KeyName) to render rows + fetch each plaintext
// via the existing single-shot retrieval endpoint. NEVER carries
// ciphertext or plaintext.
type WrapHandle struct {
	WrapID  uuid.UUID
	KeyName string
}

// RevealSessionResponse is what Open returns.
type RevealSessionResponse struct {
	Session *storage.RevealSession
	Wraps   []WrapHandle
}

// Sentinel errors. Map to HTTP at the handler layer.
var (
	// ErrAllWrapsConsumed is returned by Open when every wrap tied to
	// the request has already been consumed (single-shot). Maps to 410.
	ErrAllWrapsConsumed = errors.New("services: all wraps already consumed")

	// ErrRevealSessionEnvMissing is returned by Open when the request
	// has no environment_id bound (L3 should have populated it; legacy
	// requests pre-L3 may not have it). Maps to 409 — request can't be
	// revealed until it carries an env binding.
	ErrRevealSessionEnvMissing = errors.New("services: request has no environment binding")

	// ErrNotSessionOwner is returned by MarkExpired when the caller is
	// not the user who opened the session. Maps to 403.
	ErrNotSessionOwner = errors.New("services: caller does not own this reveal session")
)

// Open creates a new reveal session for the caller bundling every
// unconsumed wrap of the given access_request. The wraps remain
// consumable through the existing /requests/:id/wraps/:wrap_id
// endpoint until either the SPA explicitly expires the session, the
// M3 sweeper fires TTL, or the per-wrap retrieve burns it.
func (s *RevealSessionService) Open(ctx context.Context, in OpenInput) (*RevealSessionResponse, error) {
	if in.UserID == "" {
		return nil, fmt.Errorf("%w: user_id required", ErrInvalidInput)
	}
	if in.RequestID == uuid.Nil {
		return nil, fmt.Errorf("%w: access_request_id required", ErrInvalidInput)
	}

	req, err := s.requests.Get(ctx, in.RequestID)
	if err != nil {
		return nil, err
	}
	if req.RequesterID != in.UserID {
		return nil, ErrNotRequestOwner
	}
	// Slice N3 — Open accepts type=read AND type=cross_team. Patch
	// requests are still refused (they're approver-side write flows;
	// the bulk reveal page is for issuer-side retrieval).
	if req.Type != storage.AccessRequestTypeRead && req.Type != storage.AccessRequestTypeCrossTeam {
		return nil, ErrWrongRequest
	}
	switch req.Status {
	case storage.AccessRequestStatusApproved, storage.AccessRequestStatusExecuted:
		// retrievable
	default:
		return nil, ErrRequestNotApproved
	}
	if req.EnvironmentID == nil {
		return nil, ErrRevealSessionEnvMissing
	}

	summaries, err := s.wraps.ListSummariesForRequest(ctx, in.RequestID)
	if err != nil {
		return nil, fmt.Errorf("services: list wrap summaries: %w", err)
	}
	fresh := make([]storage.WrapSummary, 0, len(summaries))
	for _, w := range summaries {
		if !w.Consumed {
			fresh = append(fresh, w)
		}
	}
	if len(fresh) == 0 {
		return nil, ErrAllWrapsConsumed
	}

	ttl := s.resolveTTL(ctx, req)

	wrapIDs := make([]uuid.UUID, len(fresh))
	for i, w := range fresh {
		wrapIDs[i] = w.ID
	}

	now := s.now().UTC()
	projectID, err := projectIDFromRequest(req)
	if err != nil {
		return nil, fmt.Errorf("services: project_id from request: %w", err)
	}
	session := &storage.RevealSession{
		UserID:          in.UserID,
		ProjectID:       projectID,
		EnvironmentID:   *req.EnvironmentID,
		AccessRequestID: &req.ID,
		TTLSeconds:      ttl,
		ExpiresAt:       now.Add(time.Duration(ttl) * time.Second),
		WrapIDs:         wrapIDs,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("services: create reveal session: %w", err)
	}

	keyNames := make([]string, len(fresh))
	handles := make([]WrapHandle, len(fresh))
	for i, w := range fresh {
		keyNames[i] = w.KeyName
		handles[i] = WrapHandle{WrapID: w.ID, KeyName: w.KeyName}
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.UserID,
		Action:        "reveal.session.opened",
		Resource:      "reveal_session:" + session.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata: map[string]any{
			"request_id":     req.ID.String(),
			"environment_id": req.EnvironmentID.String(),
			"ttl_seconds":    ttl,
			"wrap_count":     len(fresh),
			"key_names":      keyNames,
		},
	})

	return &RevealSessionResponse{Session: session, Wraps: handles}, nil
}

// MarkExpired transitions a reveal session from active to expired. The
// caller must own the session. After the row is flipped, the
// underlying wraps' expires_at is advanced to "now" so any post-expire
// retrieve returns a clean 410.
//
// Idempotent: a second MarkExpired (e.g. user double-taps Hide Now, or
// sweeper races a user-hide) returns nil instead of an error.
func (s *RevealSessionService) MarkExpired(
	ctx context.Context,
	id uuid.UUID,
	userID string,
	reason storage.RevealSessionExpiredReason,
) error {
	if userID == "" {
		return fmt.Errorf("%w: user_id required", ErrInvalidInput)
	}
	sess, err := s.sessions.Get(ctx, id)
	if err != nil {
		return err
	}
	if sess.UserID != userID {
		return ErrNotSessionOwner
	}

	now := s.now().UTC()
	if err := s.sessions.MarkExpired(ctx, id, now, reason); err != nil {
		if errors.Is(err, storage.ErrRevealSessionExpired) {
			// Idempotent — caller intent already satisfied.
			return nil
		}
		return err
	}

	// Advance wrap TTLs to "now" so any in-flight retrieve sees 410.
	// Failures are audited but not bubbled — the session is already
	// expired at the metadata layer; a stuck wrap will be caught by
	// the storage layer's expires_at filter on the next retrieve.
	var refreshErrs []string
	for _, wid := range sess.WrapIDs {
		if err := s.wraps.Expire(ctx, wid); err != nil {
			refreshErrs = append(refreshErrs, fmt.Sprintf("%s: %v", wid, err))
		}
	}

	meta := map[string]any{
		"reason":     string(reason),
		"wrap_count": len(sess.WrapIDs),
	}
	if len(refreshErrs) > 0 {
		meta["wrap_refresh_errors"] = refreshErrs
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID,
		Action:   "reveal.session.expired",
		Resource: "reveal_session:" + id.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: meta,
	})
	return nil
}

// ListActiveForUser returns every active reveal session for the
// caller. Used by the SPA on tab restore to detect orphan sessions
// left mid-window.
func (s *RevealSessionService) ListActiveForUser(ctx context.Context, userID string) ([]*storage.RevealSession, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id required", ErrInvalidInput)
	}
	return s.sessions.ListActiveForUser(ctx, userID)
}

// resolveTTL pulls the reveal TTL from the matched policy rule. When
// the policy lookup fails OR returns 0, falls back to the schema's
// default (60s). Clamps to [10, 300] so a misconfigured rule can't
// reach the schema CHECK and trip an insert.
func (s *RevealSessionService) resolveTTL(ctx context.Context, req *storage.AccessRequest) int {
	if s.policy == nil || s.envs == nil || req.EnvironmentID == nil {
		return revealTTLDefaultSeconds
	}
	env, err := s.envs.Get(ctx, *req.EnvironmentID)
	if err != nil {
		return revealTTLDefaultSeconds
	}
	projectIDStr, _ := req.TargetScope["project_id"].(string)
	dec, err := s.policy.Resolve(ctx, Scope{
		ProjectID:       projectIDStr,
		Environment:     env.Name,
		EnvironmentKind: env.Kind,
		ProviderType:    req.TargetProviderType,
		SecretRefPrefix: req.TargetSecretRef,
	})
	if err != nil || dec == nil {
		return revealTTLDefaultSeconds
	}
	ttl := dec.RevealTTLSeconds
	if ttl <= 0 {
		ttl = revealTTLDefaultSeconds
	}
	return clampRevealTTL(ttl)
}

func clampRevealTTL(ttl int) int {
	if ttl < revealTTLMinSeconds {
		return revealTTLMinSeconds
	}
	if ttl > revealTTLMaxSeconds {
		return revealTTLMaxSeconds
	}
	return ttl
}

// projectIDFromRequest pulls the project_id out of TargetScope. Open
// requires a valid project binding so the reveal_sessions row carries
// the same scope the original request used.
func projectIDFromRequest(req *storage.AccessRequest) (uuid.UUID, error) {
	raw, ok := req.TargetScope["project_id"].(string)
	if !ok || raw == "" {
		return uuid.Nil, errors.New("missing project_id in target_scope")
	}
	pid, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid project_id: %w", err)
	}
	return pid, nil
}
