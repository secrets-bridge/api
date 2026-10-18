// Package services, logos_backfill.go: the one-time move of logos
// stored in Postgres (project_logos.png, team_logos.png) to object
// storage (secrets-bridge/api#253).
//
// The api runs it at start, in the background, under a Redis lock so
// only one replica works at a time. It is idempotent: it only touches
// rows whose image is still inline, object keys are content addressed
// (a repeated write puts the same bytes at the same key), and each row
// is switched over with a conditional update. Running it again after it
// finished does nothing.
package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// logoBackfillPage is how many rows the backfill reads at once.
const logoBackfillPage = 100

// LogoBackfillResult counts what one backfill run did.
type LogoBackfillResult struct {
	// Moved: rows now pointing at an object, png cleared.
	Moved int
	// Skipped: rows left inline on purpose. Either the row changed while
	// the backfill ran, or the stored bytes don't match the recorded
	// sha256 (moving those would change the ETag and logo_version, so
	// an operator should look at them).
	Skipped int
	// Failed: rows left inline after an object store or database error.
	// A later run retries them.
	Failed int
}

// BackfillObjects copies every logo still stored inline to the object
// store and clears its png. It needs a configured store
// (ErrLogoStorageUnavailable otherwise) and stops early only when ctx
// ends. Audit is not written: the logo didn't change, only where its
// bytes live.
func (s *LogoService) BackfillObjects(ctx context.Context) (LogoBackfillResult, error) {
	var res LogoBackfillResult
	if s.store == nil {
		return res, ErrLogoStorageUnavailable
	}
	for _, kind := range []storage.LogoKind{storage.LogoKindProject, storage.LogoKindTeam} {
		after := uuid.Nil
		for {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			page, err := s.logos.ListInline(ctx, kind, after, logoBackfillPage)
			if err != nil {
				return res, err
			}
			for _, l := range page {
				switch s.backfillOne(ctx, kind, l) {
				case backfillMoved:
					res.Moved++
				case backfillSkipped:
					res.Skipped++
				default:
					res.Failed++
				}
				after = l.EntityID
			}
			if len(page) < logoBackfillPage {
				break
			}
		}
	}
	return res, nil
}

type backfillOutcome int

const (
	backfillMoved backfillOutcome = iota
	backfillSkipped
	backfillFailed
)

func (s *LogoService) backfillOne(ctx context.Context, kind storage.LogoKind, l *storage.Logo) backfillOutcome {
	log := slog.With("kind", kind, "entity_id", l.EntityID)
	digest := sha256.Sum256(l.PNG)
	if hex.EncodeToString(digest[:]) != l.SHA256 {
		log.WarnContext(ctx, "logo backfill: stored bytes do not match the recorded sha256; left inline")
		return backfillSkipped
	}
	key := s.ObjectKey(kind, l.EntityID, l.SHA256)
	if err := s.store.Put(ctx, key, bytes.NewReader(l.PNG), int64(len(l.PNG)), logoPNGType); err != nil {
		log.ErrorContext(ctx, "logo backfill: object write failed", "err", err)
		return backfillFailed
	}
	moved, previous, err := s.logos.MoveToObject(ctx, kind, l.EntityID, l.SHA256, key, len(l.PNG))
	if err != nil {
		// The row is unchanged and still inline. The object stays: it is
		// content addressed, so the next run writes the same key again.
		log.ErrorContext(ctx, "logo backfill: row update failed", "err", err)
		return backfillFailed
	}
	if !moved {
		// Replaced or removed since it was listed. The new upload owns
		// its own key; remove ours unless the row now points at it.
		if previous != key {
			s.removeObject(ctx, kind, l.EntityID, key, "backfill: row changed")
		}
		return backfillSkipped
	}
	// A replica on the old version may have written png over a row that
	// already had an object; that object is stale now.
	if previous != "" && previous != key {
		s.removeObject(ctx, kind, l.EntityID, previous, "backfill: stale object")
	}
	return backfillMoved
}
