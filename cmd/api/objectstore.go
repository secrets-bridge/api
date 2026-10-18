package main

// Object storage for media (secrets-bridge/api#253).
//
// Configured from SB_OBJECTSTORE_* (see pkg/objectstore). Three states:
//
//   - Not configured (no SB_OBJECTSTORE_* set): the api boots, logo
//     uploads and deletes answer 503 "logo storage is not configured",
//     and logos still stored inline in Postgres keep being served. Media
//     is never written to Postgres as a fallback.
//   - Misconfigured (a setting without a bucket, a bad value, or a bucket
//     the credentials can't reach): the api refuses to boot.
//   - Configured: logos are written to and read from the bucket, and the
//     one-time backfill of inline logos runs in the background.
//
// SB_OBJECTSTORE_LOGO_BACKFILL=false switches the backfill off, for the
// first step of a rolling upgrade from a version that stored logos in
// Postgres (see the 0040 migration and the PR for the rollout).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/objectstore"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

const (
	envLogoBackfill = "SB_OBJECTSTORE_LOGO_BACKFILL"
	// logoBackfillLock serialises the backfill across replicas.
	logoBackfillLock       = "objectstore:logo-backfill"
	logoBackfillLease      = 2 * time.Minute
	logoBackfillTimeout    = 30 * time.Minute
	objectStoreBootTimeout = 15 * time.Second
)

// openObjectStore loads the object-storage config and, when enabled,
// builds the S3 store and checks the bucket is reachable. A nil store
// with a nil error means object storage is not configured.
//
// Outside SB_ENV=dev a plain http:// endpoint refuses to boot, as the
// chart already does: the request signatures and the media would cross
// the network in clear text. The chart's check doesn't run when the
// SB_OBJECTSTORE_* variables come from secrets.existingSecret or from
// an install without the chart, so the api checks too.
func openObjectStore(ctx context.Context, env string) (objectstore.Store, objectstore.Config, error) {
	cfg, err := objectstore.LoadConfig()
	if err != nil || !cfg.Enabled() {
		return nil, cfg, err
	}
	if env != ModeDev && strings.HasPrefix(cfg.Endpoint, "http://") {
		return nil, cfg, fmt.Errorf("objectstore: %s is plain http://, which is refused with SB_ENV=%s; use an https:// endpoint", objectstore.EnvEndpoint, env)
	}
	store, err := objectstore.NewS3(ctx, cfg)
	if err != nil {
		return nil, cfg, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, objectStoreBootTimeout)
	defer cancel()
	if err := store.Check(checkCtx); err != nil {
		return nil, cfg, err
	}
	return store, cfg, nil
}

// startLogoBackfill moves inline logos to the object store in the
// background, under a Redis lock so one replica does it at a time. A
// replica that finds the lock held skips: the holder covers every row.
// Boot never waits for it; inline logos are served until they move.
func startLogoBackfill(logger *slog.Logger, rdb *runtime.Client, svc *services.LogoService) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), logoBackfillTimeout)
		defer cancel()
		lock, err := rdb.AcquireLock(ctx, logoBackfillLock, logoBackfillLease)
		if errors.Is(err, runtime.ErrLockHeld) {
			logger.Info("logo backfill: another replica holds the lock; skipping")
			return
		}
		if err != nil {
			logger.Warn("logo backfill: lock failed; will retry at next start", "err", err)
			return
		}
		stopRenew := lock.StartRenewal(ctx, cancel)
		defer func() {
			stopRenew()
			_ = lock.Release(context.Background())
		}()
		res, err := svc.BackfillObjects(ctx)
		attrs := []any{"moved", res.Moved, "skipped", res.Skipped, "failed", res.Failed}
		if err != nil {
			logger.Warn("logo backfill stopped early; will resume at next start", append(attrs, "err", err)...)
			return
		}
		if res.Moved+res.Skipped+res.Failed == 0 {
			logger.Debug("logo backfill: nothing to move")
			return
		}
		logger.Info("logo backfill done", attrs...)
	}()
}

// warnInlineLogos logs, when object storage is off, how many logos are
// still stored in Postgres, so an operator knows a backfill is pending.
func warnInlineLogos(ctx context.Context, logger *slog.Logger, logos storage.LogoRepository) {
	n, err := logos.CountInline(ctx)
	if err != nil {
		logger.Warn("logos: could not count inline logos", "err", err)
		return
	}
	if n > 0 {
		logger.Warn("object storage is not configured: logo uploads are disabled and logos still stored in Postgres wait for the backfill",
			"inline_logos", n)
	}
}
