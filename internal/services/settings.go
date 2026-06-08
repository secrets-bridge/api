// R-follow-up #2 (api#121) — admin-configurable platform settings.
//
// SettingsService caches whitelisted platform_settings values in memory
// and refreshes them on:
//
//   1. Boot (initial load from DB)
//   2. Redis pub/sub event on `settings:<key>:changed`
//      — the message is a signal ONLY; the receiver fetches fresh from
//        DB. We never trust the payload as the source of truth (§2 Q9).
//   3. TTL backstop refresh every 5 minutes (defense against missed
//      pub/sub messages)
//   4. On-demand: Get() with a cold cache fetches from DB
//
// Hardcode retirement (§3 Q15) — `DefaultPlatformReservedPriority` is
// kept as a Go constant for the seed migration value and test
// scaffolding ONLY. Runtime callers MUST go through SettingsService.
//
// Fail-closed (§3 correction 2) — if the cached read AND a fresh DB
// fetch both fail, GetInt returns ErrPlatformSettingUnavailable. The
// scoped policy gate chain surfaces this as 503; the SPA fails the
// author drawer closed with a banner.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secrets-bridge/api/pkg/storage"
)

// DefaultPlatformReservedPriority is the seed value for the
// platform_reserved_priority key. Used by migration 0036 + test
// scaffolding + fallback documentation ONLY. NOT a runtime source —
// runtime callers go through SettingsService.GetInt.
const DefaultPlatformReservedPriority = 9000

// KeyPlatformReservedPriority is the only whitelisted key in v1.
const KeyPlatformReservedPriority = "platform_reserved_priority"

// Whitelist is the v1 closed set of supported keys. Service-layer Get
// + Set reject anything outside this list.
var Whitelist = []string{KeyPlatformReservedPriority}

// PlatformReservedPriorityMin / Max are the §1 Q4 locked bounds.
const (
	PlatformReservedPriorityMin = 100
	PlatformReservedPriorityMax = 1000000
)

var (
	ErrUnknownPlatformSetting     = errors.New("services: unknown platform setting key")
	ErrInvalidPlatformSetting     = errors.New("services: platform setting value rejected")
	ErrPlatformSettingUnavailable = errors.New("services: platform setting unavailable")
)

// PlatformSettingValue carries the decoded value for a single setting
// plus its identity metadata. Returned by Get for the admin GET
// surface.
type PlatformSettingValue struct {
	Key       string
	Value     any
	UpdatedAt time.Time
	UpdatedBy *string
}

// AuditAppender is the slice of the audit repository SettingsService
// uses. Same shape pattern other services use to keep the audit edge
// narrow.
type AuditAppender interface {
	Append(ctx context.Context, e *storage.AuditEvent) error
}

// PoolTx is the slice of the pool needed for BEGIN. We accept this
// narrow interface so tests can inject a fake.
type PoolTx interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// PubSubPublisher is the slice of runtime.Client we use for cross-pod
// invalidation. Nil disables the publish (caller logs a WARN).
type PubSubPublisher interface {
	Publish(ctx context.Context, channel string, payload []byte) (int64, error)
}

// SettingsService combines the cache + the transactional Set + the
// audit emission.
type SettingsService struct {
	pool   PoolTx
	repo   storage.PlatformSettingRepository
	audit  AuditAppender
	rdb    PubSubPublisher
	logger *slog.Logger

	// Cache + refresh tracking.
	mu              sync.RWMutex
	cache           map[string]any
	lastRefreshedAt time.Time
	ttl             time.Duration

	// Allows tests to stub time.
	now func() time.Time
}

// NewSettingsService wires the service. rdb may be nil — the service
// still functions, just without cross-pod cache invalidation (every
// pod relies on its TTL backstop in that mode).
func NewSettingsService(
	pool PoolTx,
	repo storage.PlatformSettingRepository,
	audit AuditAppender,
	rdb PubSubPublisher,
	logger *slog.Logger,
) *SettingsService {
	if logger == nil {
		logger = slog.Default()
	}
	return &SettingsService{
		pool:   pool,
		repo:   repo,
		audit:  audit,
		rdb:    rdb,
		logger: logger,
		cache:  map[string]any{},
		ttl:    5 * time.Minute,
		now:    time.Now,
	}
}

// LoadCache populates the cache from the DB. Call at boot. Idempotent
// — subsequent calls re-read every whitelisted key.
func (s *SettingsService) LoadCache(ctx context.Context) error {
	rows, err := s.repo.List(ctx, Whitelist)
	if err != nil {
		return fmt.Errorf("services: load settings cache: %w", err)
	}
	next := make(map[string]any, len(rows))
	for _, r := range rows {
		var decoded map[string]any
		if err := json.Unmarshal(r.Value, &decoded); err != nil {
			return fmt.Errorf("services: decode setting %s: %w", r.Key, err)
		}
		next[r.Key] = decoded["value"]
	}
	s.mu.Lock()
	s.cache = next
	s.lastRefreshedAt = s.now()
	s.mu.Unlock()
	return nil
}

// GetInt returns the integer value of `key`. Fails closed when the
// cached read AND a fresh DB fetch both fail.
func (s *SettingsService) GetInt(ctx context.Context, key string) (int, error) {
	if !knownKey(key) {
		return 0, ErrUnknownPlatformSetting
	}
	if v, ok, ttlOk := s.cachedInt(key); ok && ttlOk {
		return v, nil
	}
	// Cache miss OR TTL expired — refresh from DB.
	if err := s.refreshKey(ctx, key); err != nil {
		// One more attempt at returning the (now stale) cached value
		// rather than fail-closed if anything is at all in cache. The
		// 503 surface is reserved for "we have no value at all."
		if v, ok, _ := s.cachedInt(key); ok {
			s.logger.Warn("services: settings DB refresh failed; using stale cache",
				"key", key, "err", err)
			return v, nil
		}
		return 0, fmt.Errorf("%w: %v", ErrPlatformSettingUnavailable, err)
	}
	v, ok, _ := s.cachedInt(key)
	if !ok {
		return 0, ErrPlatformSettingUnavailable
	}
	return v, nil
}

// Get returns the typed projection for the admin surface. Always
// reads through the repo (no cache) so admin sees authoritative state.
func (s *SettingsService) Get(ctx context.Context, key string) (*PlatformSettingValue, error) {
	if !knownKey(key) {
		return nil, ErrUnknownPlatformSetting
	}
	row, err := s.repo.Get(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrPlatformSettingNotFound) {
			return nil, ErrUnknownPlatformSetting
		}
		return nil, fmt.Errorf("services: get setting: %w", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(row.Value, &decoded); err != nil {
		return nil, fmt.Errorf("services: decode setting %s: %w", key, err)
	}
	return &PlatformSettingValue{
		Key:       row.Key,
		Value:     decoded["value"],
		UpdatedAt: row.UpdatedAt,
		UpdatedBy: row.UpdatedBy,
	}, nil
}

// List returns the whitelist via the admin GET. Pull-from-DB for
// authoritative state.
func (s *SettingsService) List(ctx context.Context) ([]*PlatformSettingValue, error) {
	rows, err := s.repo.List(ctx, Whitelist)
	if err != nil {
		return nil, err
	}
	out := make([]*PlatformSettingValue, 0, len(rows))
	for _, r := range rows {
		var decoded map[string]any
		if err := json.Unmarshal(r.Value, &decoded); err != nil {
			return nil, fmt.Errorf("services: decode setting %s: %w", r.Key, err)
		}
		out = append(out, &PlatformSettingValue{
			Key:       r.Key,
			Value:     decoded["value"],
			UpdatedAt: r.UpdatedAt,
			UpdatedBy: r.UpdatedBy,
		})
	}
	return out, nil
}

// SetInput carries the admin's set request.
type SetInput struct {
	Key           string
	Value         any
	ActorID       string
	CorrelationID string
}

// Set validates + persists + audits + publishes a cache-invalidation
// message. Transactional per §2 Q5 lock: settings UPDATE + audit
// INSERT are in the same transaction; pub/sub publish happens AFTER
// commit (§3 correction in §2).
//
// Returns the freshly-read row so the admin response can echo back
// the canonical state without a follow-up GET.
func (s *SettingsService) Set(ctx context.Context, in SetInput) (*PlatformSettingValue, error) {
	if !knownKey(in.Key) {
		return nil, ErrUnknownPlatformSetting
	}

	// Per-key validation. v1 ships only platform_reserved_priority.
	valueJSON, err := validateAndEncode(in.Key, in.Value)
	if err != nil {
		return nil, err
	}

	// Transactional update + audit. The DB-level CHECK is the last
	// line of defense against an out-of-bounds value the service
	// validation somehow missed.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("services: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// SELECT FOR UPDATE the existing row to capture old_value + lock
	// the row against concurrent edits.
	var oldRaw []byte
	if err := tx.QueryRow(ctx,
		`SELECT value FROM platform_settings WHERE key = $1 FOR UPDATE`, in.Key,
	).Scan(&oldRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUnknownPlatformSetting
		}
		return nil, fmt.Errorf("services: read old value: %w", err)
	}
	var oldDecoded map[string]any
	_ = json.Unmarshal(oldRaw, &oldDecoded)

	if err := s.repo.SetTx(ctx, tx, in.Key, valueJSON, in.ActorID); err != nil {
		if errors.Is(err, storage.ErrInvalidPlatformSetting) {
			return nil, ErrInvalidPlatformSetting
		}
		return nil, err
	}

	// Audit emission — in the same transaction so a rollback of either
	// side rolls back BOTH. audit_events table is append-only via a
	// trigger; INSERTs are fine within a tx.
	auditMeta := map[string]any{
		"key":                   in.Key,
		"new_value":             in.Value,
		"actor_permission_used": "policy.edit",
	}
	if v, ok := oldDecoded["value"]; ok {
		auditMeta["old_value"] = v
	}
	auditJSON, err := json.Marshal(auditMeta)
	if err != nil {
		return nil, fmt.Errorf("services: marshal audit metadata: %w", err)
	}
	corr := in.CorrelationID
	if corr == "" {
		corr = newCorrelationID()
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (actor, action, resource, status, metadata, correlation_id)
		 VALUES ($1, $2, $3, 'success', $4::jsonb, $5::uuid)`,
		in.ActorID,
		"platform_setting.update",
		"platform_setting:"+in.Key,
		auditJSON,
		corr,
	); err != nil {
		return nil, fmt.Errorf("services: insert audit row: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("services: commit settings update: %w", err)
	}

	// Pub/sub publish AFTER commit. Best-effort: a publish failure
	// doesn't roll back the persisted change — the cache backstop
	// (TTL refresh) eventually picks up the new value across pods.
	if s.rdb != nil {
		channel := fmt.Sprintf("settings:%s:changed", in.Key)
		if _, err := s.rdb.Publish(ctx, channel, []byte("changed")); err != nil {
			s.logger.Warn("services: settings pub/sub publish failed; pods will pick up via TTL backstop",
				"key", in.Key, "err", err)
		}
	} else {
		s.logger.Warn("services: pub/sub publisher not configured; cross-pod invalidation disabled")
	}

	// Local cache update.
	s.mu.Lock()
	s.cache[in.Key] = in.Value
	s.lastRefreshedAt = s.now()
	s.mu.Unlock()

	// Re-read for the response.
	return s.Get(ctx, in.Key)
}

// OnInvalidationMessage is the callback the api's pub/sub subscriber
// fires when a `settings:<key>:changed` message arrives. Per §2 Q9
// lock the receiver doesn't trust the message payload; it re-fetches
// from the DB.
func (s *SettingsService) OnInvalidationMessage(ctx context.Context, key string) {
	if !knownKey(key) {
		s.logger.Warn("services: settings invalidation for unknown key ignored", "key", key)
		return
	}
	if err := s.refreshKey(ctx, key); err != nil {
		s.logger.Error("services: refresh after pub/sub failed",
			"key", key, "err", err)
	}
}

// --- helpers ---------------------------------------------------------

func (s *SettingsService) cachedInt(key string) (val int, ok, ttlOk bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, present := s.cache[key]
	if !present {
		return 0, false, false
	}
	ttlOk = s.now().Sub(s.lastRefreshedAt) < s.ttl
	switch v := raw.(type) {
	case int:
		return v, true, ttlOk
	case int64:
		return int(v), true, ttlOk
	case float64:
		return int(v), true, ttlOk
	case json.Number:
		i64, err := v.Int64()
		if err != nil {
			return 0, false, false
		}
		return int(i64), true, ttlOk
	}
	return 0, false, false
}

// refreshKey re-fetches one key from the DB and updates the cache.
// Used by the pub/sub subscriber + the on-demand cold-cache path.
func (s *SettingsService) refreshKey(ctx context.Context, key string) error {
	row, err := s.repo.Get(ctx, key)
	if err != nil {
		return err
	}
	var decoded map[string]any
	if err := json.Unmarshal(row.Value, &decoded); err != nil {
		return err
	}
	s.mu.Lock()
	s.cache[key] = decoded["value"]
	s.lastRefreshedAt = s.now()
	s.mu.Unlock()
	return nil
}

func knownKey(key string) bool {
	for _, k := range Whitelist {
		if k == key {
			return true
		}
	}
	return false
}

// validateAndEncode runs the per-key shape + bounds checks, then JSON-
// encodes the value for the storage layer.
func validateAndEncode(key string, raw any) ([]byte, error) {
	switch key {
	case KeyPlatformReservedPriority:
		v, err := coerceInt(raw)
		if err != nil {
			return nil, ErrInvalidPlatformSetting
		}
		if v < PlatformReservedPriorityMin || v > PlatformReservedPriorityMax {
			return nil, ErrInvalidPlatformSetting
		}
		body, err := json.Marshal(map[string]int{"value": v})
		if err != nil {
			return nil, fmt.Errorf("services: encode value: %w", err)
		}
		return body, nil
	default:
		return nil, ErrUnknownPlatformSetting
	}
}

// coerceInt accepts only JSON integer numbers (Go float64 with no
// fractional part). Rejects strings, fractional values, nil, maps,
// arrays, booleans. Pinned by §2 Q11 lock.
func coerceInt(raw any) (int, error) {
	switch v := raw.(type) {
	case float64:
		// Reject fractional values (5000.5 → invalid).
		if v != float64(int(v)) {
			return 0, errors.New("not an integer")
		}
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case json.Number:
		i64, err := v.Int64()
		if err != nil {
			return 0, errors.New("not an integer")
		}
		return int(i64), nil
	case string:
		// Reject "5000" — the API contract requires JSON numbers.
		return 0, errors.New("not an integer (string given)")
	}
	return 0, errors.New("not an integer")
}

// newCorrelationID returns a fresh UUID for the audit chain. The
// SetInput's CorrelationID is preferred when present so callers (e.g.
// admin SPA mutations chained with downstream events) can stitch the
// trail; we generate one only when absent.
func newCorrelationID() string {
	return uuid.New().String()
}

// Channel is the public Redis pub/sub channel name for a key.
// Exported so the api/cmd boot wiring can subscribe.
func Channel(key string) string {
	return fmt.Sprintf("settings:%s:changed", key)
}

// CleanKey returns the key extracted from a `settings:<key>:changed`
// channel string. Used by the subscriber loop.
func CleanKey(channel string) string {
	const prefix = "settings:"
	const suffix = ":changed"
	if !strings.HasPrefix(channel, prefix) || !strings.HasSuffix(channel, suffix) {
		return ""
	}
	return channel[len(prefix) : len(channel)-len(suffix)]
}
