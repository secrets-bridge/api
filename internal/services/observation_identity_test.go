package services

import (
	"errors"
	"strings"
	"testing"
)

// Gateway target identity (gateway#21, ADR 0002 C3): an Argo CD stage
// carries a one-way identity_digest instead of the Application's raw
// uid, and a replaced Application arrives as the typed error
// target_identity_changed with no status.

const identityBody = `{"schema_version":"gateway.evidence-result/v1","task_id":"0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b",` +
	`"attempt_id":"c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f","gateway_id":"1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",` +
	`"replica_id":"7f3c9e2a-1b2c-4d5e-8f90-123456789abc","gateway_version":"0.1.0",` +
	`"started_at":"2026-10-18T10:00:01Z","finished_at":"2026-10-18T10:00:02Z","attempt_status":"completed",` +
	`"stages":[{"stage":"argocd_context","source":{"connector_id":"argocd-main","target_id":"payments-api","api":"argocd"},` +
	`"observed_at":"2026-10-18T10:00:02Z","resource":{"api_version":"argoproj.io/v1alpha1","kind":"Application","namespace":"argocd","name":"payments-api",` +
	`"identity_digest":"d-7qvuzdcaqndmfdcy3ypmjnz2rr"},` +
	`"outcome":"observed","confidence":"low","caveats":["argocd_health_not_proof"],"linkage":"none",` +
	`"facts":{"sync_status":"Synced","health_status":"Healthy"}}],"clock":{"cp_offset_ms":0}}`

const identityChangedBody = `{"schema_version":"gateway.evidence-result/v1","task_id":"0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b",` +
	`"attempt_id":"c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f","gateway_id":"1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9",` +
	`"replica_id":"7f3c9e2a-1b2c-4d5e-8f90-123456789abc","gateway_version":"0.1.0",` +
	`"started_at":"2026-10-18T10:00:01Z","finished_at":"2026-10-18T10:00:02Z","attempt_status":"completed",` +
	`"stages":[{"stage":"argocd_context","source":{"connector_id":"argocd-main","target_id":"payments-api","api":"argocd"},` +
	`"observed_at":"2026-10-18T10:00:02Z","outcome":"error","confidence":"none","caveats":["argocd_health_not_proof"],` +
	`"linkage":"none","error_code":"target_identity_changed"}],"clock":{"cp_offset_ms":0}}`

const identityTestUID = "6f1c2c1e-0000-4000-8000-0000000000a1"

func TestDecodeEvidenceResult_TargetIdentity(t *testing.T) {
	r, err := DecodeEvidenceResult([]byte(identityBody))
	if err != nil {
		t.Fatalf("argocd stage with identity_digest: %v", err)
	}
	st := (*r.Stages)[0]
	if st.Resource.IdentityDigest != "d-7qvuzdcaqndmfdcy3ypmjnz2rr" || st.Resource.UID != "" {
		t.Fatalf("resource = %+v", st.Resource)
	}
	// The stored body keeps the digest.
	body, err := st.stageBody()
	if err != nil || !strings.Contains(string(body), `"identity_digest":"d-7qvuzdcaqndmfdcy3ypmjnz2rr"`) {
		t.Fatalf("stage body = %s (%v)", body, err)
	}

	r, err = DecodeEvidenceResult([]byte(identityChangedBody))
	if err != nil {
		t.Fatalf("target_identity_changed: %v", err)
	}
	if st := (*r.Stages)[0]; st.ErrorCode != "target_identity_changed" || st.Resource != nil || st.argocd != nil {
		t.Fatalf("stage = %+v", st)
	}
}

func TestDecodeEvidenceResult_TargetIdentityRefusals(t *testing.T) {
	eso := `{"stage":"eso_sync","source":{"connector_id":"eso-main","target_id":"payments-api","api":"kubernetes"},` +
		`"observed_at":"2026-10-18T10:00:02Z","resource":{"api_version":"external-secrets.io/v1","kind":"ExternalSecret",` +
		`"namespace":"payments","name":"payments-env","identity_digest":"d-7qvuzdcaqndmfdcy3ypmjnz2rr"},` +
		`"outcome":"not_observed","confidence":"low","caveats":[],"linkage":"none","facts":{"ready_status":"True"}}`
	cases := []struct{ name, body string }{
		{"raw uid on an argocd resource", strings.Replace(identityBody,
			`"identity_digest":"d-7qvuzdcaqndmfdcy3ypmjnz2rr"`, `"uid":"`+identityTestUID+`"`, 1)},
		{"raw uid next to the digest", strings.Replace(identityBody,
			`"identity_digest":`, `"uid":"`+identityTestUID+`","identity_digest":`, 1)},
		{"digest is the uid", strings.Replace(identityBody, "d-7qvuzdcaqndmfdcy3ypmjnz2rr", identityTestUID, 1)},
		{"digest upper case", strings.Replace(identityBody, "d-7qvuzdcaqndmfdcy3ypmjnz2rr", "d-7QVUZDCAQNDMFDCY3YPMJNZ2RR", 1)},
		{"digest without prefix", strings.Replace(identityBody, "d-7qvuzdcaqndmfdcy3ypmjnz2rr", "7qvuzdcaqndmfdcy3ypmjnz2rr", 1)},
		{"digest on a kubernetes stage", strings.Replace(identityChangedBody,
			`"stages":[`, `"stages":[`+eso+`,`, 1)},
		{"identity error with the replacement's status", strings.Replace(identityChangedBody,
			`"error_code":"target_identity_changed"`, `"error_code":"target_identity_changed","facts":{"sync_status":"Synced","health_status":"Healthy"}`, 1)},
		{"identity error with confidence", strings.Replace(identityChangedBody, `"confidence":"none"`, `"confidence":"low"`, 1)},
		{"error code outside the closed set", strings.Replace(identityChangedBody, "target_identity_changed", "target_identity_changed_x", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == identityBody || tc.body == identityChangedBody {
				t.Fatal("the mutation did not apply")
			}
			_, err := DecodeEvidenceResult([]byte(tc.body))
			if !errors.Is(err, ErrObservationSchema) {
				t.Fatalf("err = %v, want a schema violation", err)
			}
			if strings.Contains(err.Error(), identityTestUID) || strings.Contains(err.Error(), "d-7q") {
				t.Fatalf("error echoes content: %v", err)
			}
		})
	}
}
