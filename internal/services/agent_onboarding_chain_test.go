package services_test

// api#183 — prove the normal onboarding path end-to-end at the service
// layer: generate enrollment token → enroll → the returned persistent
// agent_token authenticates via the certified heartbeat. Wrong and
// cross-agent credentials are rejected. Reuses the DB-only enroll harness.

import (
	"errors"
	"testing"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func TestOnboarding_EnrollThenHeartbeatAuthenticates(t *testing.T) {
	h := bootstrapEnroll(t, "aws-sm", "active")
	ctx := t.Context()

	// enroll agent 1 via the token flow.
	tok1 := h.generate(t, services.GenerateEnrollmentTokenInput{})
	a1, err := h.svc.Enroll(ctx, services.EnrollInput{
		Token: tok1.Token, AgentName: "onboard-1", ProviderType: "aws-sm", ClusterName: "eks-x",
	})
	if err != nil {
		t.Fatalf("Enroll a1: %v", err)
	}

	// the persistent agent_token authenticates on the certified heartbeat.
	if err := h.svc.Heartbeat(ctx, a1.AgentID, a1.AgentToken); err != nil {
		t.Fatalf("heartbeat with enrolled agent_token: %v want success", err)
	}

	// a wrong secret is rejected.
	if err := h.svc.Heartbeat(ctx, a1.AgentID, "not-the-token"); !errors.Is(err, storage.ErrUnauthorized) {
		t.Errorf("wrong-secret heartbeat err = %v; want ErrUnauthorized", err)
	}

	// a second agent's credential cannot authenticate as the first.
	tok2 := h.generate(t, services.GenerateEnrollmentTokenInput{})
	a2, err := h.svc.Enroll(ctx, services.EnrollInput{
		Token: tok2.Token, AgentName: "onboard-2", ProviderType: "aws-sm", ClusterName: "eks-x",
	})
	if err != nil {
		t.Fatalf("Enroll a2: %v", err)
	}
	if err := h.svc.Heartbeat(ctx, a1.AgentID, a2.AgentToken); !errors.Is(err, storage.ErrUnauthorized) {
		t.Errorf("cross-agent heartbeat err = %v; want ErrUnauthorized", err)
	}
	// a2's own token still works.
	if err := h.svc.Heartbeat(ctx, a2.AgentID, a2.AgentToken); err != nil {
		t.Errorf("a2 heartbeat with own token: %v want success", err)
	}
}
