// R-follow-up #2 (api#121) — admin HTTP layer for platform_settings.
//
// Routes mounted by main on the admin route group:
//
//   GET    /api/v1/platform-settings           list whitelisted rows
//   GET    /api/v1/platform-settings/:key      single row, 404 unknown_platform_setting
//   PUT    /api/v1/platform-settings/:key      update; transactional with audit
//
// Auth: bearer + policy.edit on every route per §2 Q5 lock. Until a
// dedicated platform.settings.edit permission lands (when the broader
// settings surface lands), policy.edit gates the surface — the
// admin who governs the policy band IS the admin who edits the cap.

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/secrets-bridge/api/internal/services"
)

// platformSettingUpdatesTotal — handler-side counter per §2 Q10.
// LOW-CARDINALITY LOCK: `key` bounded by the v1 whitelist (1 value
// today); `result` ∈ {success, invalid, unknown, error}. NEVER
// actor_id / old_value / new_value / project_id / policy_rule_id
// labels.
//
// The companion `platform_setting_cache_reloads_total` lives in the
// services package because that's where reload events fire (boot,
// pub/sub event, TTL backstop, on-demand).
var platformSettingUpdatesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "platform_setting_updates_total",
		Help: "Platform settings update attempts, by key + result. Result set is fixed at {success, invalid, unknown, error}.",
	},
	[]string{"key", "result"},
)

// PlatformSettings is the admin handler over SettingsService.
type PlatformSettings struct {
	svc *services.SettingsService
}

// NewPlatformSettings constructs the handler.
func NewPlatformSettings(svc *services.SettingsService) *PlatformSettings {
	return &PlatformSettings{svc: svc}
}

// platformSettingProjection is the wire shape.
type platformSettingProjection struct {
	Key       string  `json:"key"`
	Value     any     `json:"value"`
	UpdatedAt string  `json:"updated_at"`
	UpdatedBy *string `json:"updated_by"`
}

func toPlatformSettingProjection(s *services.PlatformSettingValue) platformSettingProjection {
	return platformSettingProjection{
		Key:       s.Key,
		Value:     s.Value,
		UpdatedAt: s.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedBy: s.UpdatedBy,
	}
}

// List handles GET /api/v1/platform-settings.
func (h *PlatformSettings) List(c fiber.Ctx) error {
	rows, err := h.svc.List(c.Context())
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	out := make([]platformSettingProjection, 0, len(rows))
	for _, r := range rows {
		out = append(out, toPlatformSettingProjection(r))
	}
	return c.JSON(out)
}

// Get handles GET /api/v1/platform-settings/:key.
func (h *PlatformSettings) Get(c fiber.Ctx) error {
	key := c.Params("key")
	row, err := h.svc.Get(c.Context(), key)
	if err != nil {
		return mapPlatformSettingsErr(c, err, key)
	}
	return c.JSON(toPlatformSettingProjection(row))
}

// platformSettingPutBody is the wire shape for PUT.
//
// `key` MAY be present but is ignored — the URL is the source of truth
// per §2 Q7 lock (URL-vs-body confusion defense).
type platformSettingPutBody struct {
	Value any `json:"value"`
}

// Put handles PUT /api/v1/platform-settings/:key.
func (h *PlatformSettings) Put(c fiber.Ctx) error {
	key := c.Params("key")
	var body platformSettingPutBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		platformSettingUpdatesTotal.WithLabelValues(key, "invalid").Inc()
		return stableErr(c, fiber.StatusBadRequest, "bad_request",
			"request body is not valid JSON", nil)
	}
	row, err := h.svc.Set(c.Context(), services.SetInput{
		Key:           key,
		Value:         body.Value,
		ActorID:       identityFromCtx(c),
		CorrelationID: "",
	})
	if err != nil {
		return mapPlatformSettingsErr(c, err, key)
	}
	platformSettingUpdatesTotal.WithLabelValues(key, "success").Inc()
	return c.JSON(toPlatformSettingProjection(row))
}

// mapPlatformSettingsErr translates SettingsService sentinels into the
// stable envelope. Counter increments here so every failure path is
// observable per §2 Q10 lock.
func mapPlatformSettingsErr(c fiber.Ctx, err error, key string) error {
	switch {
	case errors.Is(err, services.ErrUnknownPlatformSetting):
		platformSettingUpdatesTotal.WithLabelValues(key, "unknown").Inc()
		return stableErr(c, fiber.StatusNotFound,
			"unknown_platform_setting",
			"platform setting not found", nil)
	case errors.Is(err, services.ErrInvalidPlatformSetting):
		platformSettingUpdatesTotal.WithLabelValues(key, "invalid").Inc()
		// Per-key bounds in the envelope. v1 only ships one key; the
		// envelope shape generalises with `min`/`max` extras for the
		// numeric case.
		extras := map[string]any{}
		if key == services.KeyPlatformReservedPriority {
			extras["min"] = services.PlatformReservedPriorityMin
			extras["max"] = services.PlatformReservedPriorityMax
		}
		return stableErr(c, fiber.StatusBadRequest,
			"invalid_platform_setting",
			"platform setting value is invalid", extras)
	case errors.Is(err, services.ErrPlatformSettingUnavailable):
		platformSettingUpdatesTotal.WithLabelValues(key, "error").Inc()
		return stableErr(c, fiber.StatusServiceUnavailable,
			"platform_setting_unavailable",
			"the platform setting is currently unavailable", nil)
	default:
		platformSettingUpdatesTotal.WithLabelValues(key, "error").Inc()
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}
