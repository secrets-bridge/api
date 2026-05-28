package handlers

import (
	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// Metrics exposes the Prometheus exposition endpoint over Fiber by
// gathering from the default registry and streaming the text exposition
// format directly to the response writer.
//
// The endpoint is public — Prometheus scrapes without credentials — but
// a Kubernetes NetworkPolicy in charts/api restricts who can reach
// :8080/metrics in production.
func Metrics(c fiber.Ctx) error {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).
			SendString("metrics gather failed: " + err.Error())
	}

	c.Set(fiber.HeaderContentType, string(expfmt.FmtText))
	enc := expfmt.NewEncoder(c.Response().BodyWriter(), expfmt.FmtText)
	for _, mf := range families {
		if err := enc.Encode(mf); err != nil {
			return err
		}
	}
	return nil
}
