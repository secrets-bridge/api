package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// api#238: the token response carries the token's id, so it can be
// revoked, and an install hint that matches the agent chart and binary.
func TestLive_EnrollmentTokenResponse_IDAndInstallHint(t *testing.T) {
	l := newLiveApp(t)
	op := l.grantUser(t, []string{"agent.mint", "integration.edit"}, `{}`)

	code, body := l.call(t, http.MethodPost, "/api/v1/provider-connections", op, map[string]any{
		"name": "vault-hint", "type": "vault", "auth_method": "token",
		"scope":        map[string]string{"address": "https://vault.example.com", "mount": "kv-team-a"},
		"cluster_name": "tenant-a-uat", "discover_interval_seconds": 300,
	})
	if code != http.StatusCreated {
		t.Fatalf("create connection = %d %s", code, body)
	}
	var conn struct{ ID uuid.UUID }
	mustJSON(t, body, &conn)

	code, body = l.call(t, http.MethodPost, "/api/v1/provider-connections/"+conn.ID.String()+"/agent-enrollment-token", op,
		map[string]any{"expected_cluster_name": "tenant-a-uat-2"})
	if code != http.StatusCreated {
		t.Fatalf("enrollment token = %d %s", code, body)
	}
	var res struct {
		ID              string            `json:"id"`
		EnrollmentToken string            `json:"enrollment_token"`
		InstallHint     map[string]string `json:"install_hint"`
	}
	mustJSON(t, body, &res)

	var rowID string
	if err := l.pool.QueryRow(t.Context(),
		`SELECT id::text FROM agent_enrollment_tokens WHERE provider_connection_id = $1`, conn.ID).Scan(&rowID); err != nil {
		t.Fatalf("token row: %v", err)
	}
	if res.ID != rowID {
		t.Fatalf("response id %q, want the token row %q", res.ID, rowID)
	}

	helm := res.InstallHint["helm"]
	for _, want := range []string{
		"oci://ghcr.io/secrets-bridge/charts/secrets-bridge-agent",
		"--set cp.endpoint=<CONTROL_PLANE_URL>",
		"--set clusterName=tenant-a-uat-2", // the expected cluster wins over the connection's
		"--set agent.providerType=vault",
		"--set enrollment.enabled=true",
		"--set enrollment.tokenSecretName=secrets-bridge-agent-enroll",
		"--set identity.mode=file",
		"--set providers.vault.addr=https://vault.example.com",
		"--set providers.vault.kvMount=kv-team-a",
	} {
		if !strings.Contains(helm, want) {
			t.Errorf("helm hint lacks %q:\n%s", want, helm)
		}
	}
	// The chart reads the token from the Secret; as a chart value it
	// would be stored in the Helm release.
	for _, bad := range []string{res.EnrollmentToken, "controlPlane.url", "enrollment.token="} {
		if strings.Contains(helm, bad) {
			t.Errorf("helm hint contains %q", bad)
		}
	}
	if want := "--from-literal=enrollment_token=" + res.EnrollmentToken; !strings.Contains(res.InstallHint["kubectl"], want) {
		t.Errorf("kubectl hint lacks the Secret literal:\n%s", res.InstallHint["kubectl"])
	}
	cli := res.InstallHint["cli"]
	if !strings.Contains(cli, "SB_ENROLLMENT_TOKEN="+res.EnrollmentToken) || !strings.Contains(cli, "SB_ENROLLMENT_ENABLED=true") ||
		strings.Contains(cli, "agent enroll") {
		t.Errorf("cli hint does not match the agent binary:\n%s", cli)
	}

	// The id is what revoke takes.
	if code, body := l.call(t, http.MethodPost, "/api/v1/agent-enrollment-tokens/"+res.ID+"/revoke", op,
		map[string]any{"reason": "not needed"}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("revoke by response id = %d %s", code, body)
	}
}
