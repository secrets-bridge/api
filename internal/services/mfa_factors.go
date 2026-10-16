// MFA factor removal (api#191 H3: audit every factor change).
//
// Enrollment already audits `mfa.totp.enroll` / `mfa.webauthn.enroll`.
// Deleting a factor used to go straight from the handler to the
// repository with no audit row, so a removed second factor left no
// trace. DeleteFactor is the audited path.

package services

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// DeleteFactor removes one of the user's own factors and audits it.
// The delete stays scoped to (factorID, userID), so another user's
// factor id surfaces as storage.ErrNotFound, same as a missing one.
// The audit row carries kind + label only, never factor material.
func (s *MFAVerifyService) DeleteFactor(ctx context.Context, userID, factorID uuid.UUID) error {
	// Read first so the audit row can say what was removed. A row of
	// another user is treated exactly like a missing one.
	f, err := s.factors.Get(ctx, factorID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if err != nil || f.UserID != userID {
		return storage.ErrNotFound
	}
	if err := s.factors.Delete(ctx, factorID, userID); err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:    "user:" + userID.String(),
				Action:   "mfa.factor.delete",
				Resource: "user_mfa_factor:" + factorID.String(),
				Status:   storage.AuditStatusFailure,
				Metadata: map[string]any{"kind": string(f.Kind), "error_kind": "delete_failed"},
			})
		}
		return err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + userID.String(),
		Action:   "mfa.factor.delete",
		Resource: "user_mfa_factor:" + factorID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"kind": string(f.Kind), "label": f.Label},
	})
	return nil
}
