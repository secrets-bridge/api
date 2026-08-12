package handlers

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// requestToBody must surface cross_team metadata — ids, refs, key
// NAMES, fill timestamps, and the frozen approval requirement — so the
// approver verify panel doesn't render blanks (ui#87). It must NEVER
// carry a value, and a patch/read row must not gain any cross_team
// field (omitempty stays empty).
func TestRequestToBody_IncludesCrossTeamMetadata(t *testing.T) {
	teamID, projID, envID, connID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	filledAt := time.Now().UTC()
	requiresSec := true
	minApprovers := int16(1)

	r := &storage.AccessRequest{
		ID:                              uuid.New(),
		RequesterID:                     "requester@example.com",
		Type:                            storage.AccessRequestTypeCrossTeam,
		Status:                          storage.AccessRequestStatusPendingVerification,
		TargetTeamID:                    &teamID,
		TargetProjectID:                 &projID,
		TargetEnvironmentID:             &envID,
		DestinationProviderConnectionID: &connID,
		DestinationSecretRef:            "team-b/uat/db",
		DestinationKeys:                 []string{"CT_KEY1", "CT_KEY2"},
		FilledByUserID:                  "provider@example.com",
		FilledAt:                        &filledAt,
		FillComment:                     "rotated per policy",
		SnapRequiresSecurityApproval:    &requiresSec,
		SnapMinApprovers:                &minApprovers,
	}

	body := requestToBody(r)

	if body.TargetTeamID != teamID.String() {
		t.Errorf("target_team_id = %q want %s", body.TargetTeamID, teamID)
	}
	if body.TargetProjectID != projID.String() {
		t.Errorf("target_project_id = %q", body.TargetProjectID)
	}
	if body.TargetEnvironmentID != envID.String() {
		t.Errorf("target_environment_id = %q", body.TargetEnvironmentID)
	}
	if body.DestinationProviderConnectionID != connID.String() {
		t.Errorf("destination_provider_connection_id = %q", body.DestinationProviderConnectionID)
	}
	if body.DestinationSecretRef != "team-b/uat/db" {
		t.Errorf("destination_secret_ref = %q", body.DestinationSecretRef)
	}
	if len(body.DestinationKeys) != 2 {
		t.Errorf("destination_keys = %v want 2", body.DestinationKeys)
	}
	if body.FilledByUserID != "provider@example.com" {
		t.Errorf("filled_by_user_id = %q", body.FilledByUserID)
	}
	if body.FilledAt == nil {
		t.Error("filled_at is nil; approver can't see when it was filled")
	}
	if body.FillComment != "rotated per policy" {
		t.Errorf("fill_comment = %q", body.FillComment)
	}
	if body.SnapRequiresSecurityApproval == nil || !*body.SnapRequiresSecurityApproval {
		t.Error("snap_requires_security_approval not surfaced")
	}

	// A patch row must NOT gain any cross_team field.
	patch := &storage.AccessRequest{
		ID: uuid.New(), RequesterID: "u", Type: storage.AccessRequestTypePatch,
		Status: storage.AccessRequestStatusPending,
		TargetSecretRef: "billing/prod/db", TargetKeys: []string{"X"},
	}
	pb := requestToBody(patch)
	if pb.TargetTeamID != "" || pb.DestinationSecretRef != "" || pb.FilledByUserID != "" {
		t.Errorf("patch row leaked cross_team fields: team=%q dest=%q filled=%q",
			pb.TargetTeamID, pb.DestinationSecretRef, pb.FilledByUserID)
	}
}
