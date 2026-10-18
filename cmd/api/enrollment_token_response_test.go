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
	// ui#151: the token is on no line of the hint. Pasted into a shell,
	// a command line ends up in history and in the process arguments;
	// kubectl and cli read it at a silent prompt instead.
	for k, line := range res.InstallHint {
		if strings.Contains(line, res.EnrollmentToken) {
			t.Errorf("%s hint carries the enrollment token", k)
		}
	}
	kubectl := res.InstallHint["kubectl"]
	for _, want := range []string{"read -rs SB_ENROLL_TOKEN", "--from-file=enrollment_token=/dev/stdin", "unset SB_ENROLL_TOKEN"} {
		if !strings.Contains(kubectl, want) {
			t.Errorf("kubectl hint lacks %q:\n%s", want, kubectl)
		}
	}
	if strings.Contains(kubectl, "--from-literal") {
		t.Errorf("kubectl hint still passes the token as an argument:\n%s", kubectl)
	}
	cli := res.InstallHint["cli"]
	if !strings.Contains(cli, "read -rs SB_ENROLLMENT_TOKEN") || !strings.Contains(cli, "SB_ENROLLMENT_ENABLED=true") ||
		strings.Contains(cli, "SB_ENROLLMENT_TOKEN=") || strings.Contains(cli, "agent enroll") {
		t.Errorf("cli hint does not match the agent binary:\n%s", cli)
	}

	// The id is what revoke takes.
	if code, body := l.call(t, http.MethodPost, "/api/v1/agent-enrollment-tokens/"+res.ID+"/revoke", op,
		map[string]any{"reason": "not needed"}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("revoke by response id = %d %s", code, body)
	}
}

// Scope values are free text and the hint is pasted into a shell. A value
// that would add its own --set (helm splits on commas) or run a command
// becomes a placeholder; plain values still go in as typed.
func TestLive_EnrollmentInstallHint_UnsafeScopeValues(t *testing.T) {
	l := newLiveApp(t)
	op := l.grantUser(t, []string{"agent.mint", "integration.edit"}, `{}`)

	hint := func(t *testing.T, conn, expectedCluster map[string]any) map[string]string {
		t.Helper()
		code, body := l.call(t, http.MethodPost, "/api/v1/provider-connections", op, conn)
		if code != http.StatusCreated {
			t.Fatalf("create connection = %d %s", code, body)
		}
		var c struct{ ID uuid.UUID }
		mustJSON(t, body, &c)
		code, body = l.call(t, http.MethodPost, "/api/v1/provider-connections/"+c.ID.String()+"/agent-enrollment-token", op, expectedCluster)
		if code != http.StatusCreated {
			t.Fatalf("enrollment token = %d %s", code, body)
		}
		var res struct {
			InstallHint map[string]string `json:"install_hint"`
		}
		mustJSON(t, body, &res)
		return res.InstallHint
	}
	refuse := func(t *testing.T, h map[string]string, markers []string, wants []string) {
		t.Helper()
		for _, k := range []string{"helm", "cli", "kubectl"} {
			for _, m := range markers {
				if strings.Contains(h[k], m) {
					t.Errorf("%s hint carries %q:\n%s", k, m, h[k])
				}
			}
		}
		for _, w := range wants {
			if !strings.Contains(h["helm"], w) {
				t.Errorf("helm hint lacks %q:\n%s", w, h["helm"])
			}
		}
		if n := strings.Count(h["helm"], "--set cp.endpoint="); n != 1 {
			t.Errorf("helm hint sets cp.endpoint %d times:\n%s", n, h["helm"])
		}
	}

	t.Run("vault", func(t *testing.T) {
		h := hint(t, map[string]any{
			"name": "vault-unsafe", "type": "vault", "auth_method": "token",
			"scope": map[string]string{
				"address":   "https://vault.example.com/$(id)",
				"mount":     "kv,cp.endpoint=https://evil.example",
				"namespace": "team-a;id",
				"kvPrefix":  "apps,image.repository=evil.example/agent",
			},
			"cluster_name": "tenant-a-uat", "discover_interval_seconds": 300,
		}, map[string]any{"expected_cluster_name": "tenant-a-uat`id`"})
		refuse(t, h, []string{"evil.example", "$(id)", ";id", "`id`"}, []string{
			"--set clusterName=<cluster-name>",
			"--set providers.vault.addr=<vault-address>",
			"--set providers.vault.kvMount=<kv-mount>",
			"--set providers.vault.namespace=<vault-namespace>",
			"--set providers.vault.kvPrefix=<kv-prefix>",
		})
		if !strings.Contains(h["cli"], "SB_CLUSTER_NAME=<cluster-name>") {
			t.Errorf("cli hint keeps the unsafe cluster name:\n%s", h["cli"])
		}
	})

	t.Run("aws-sm", func(t *testing.T) {
		h := hint(t, map[string]any{
			"name": "aws-unsafe", "type": "aws-sm", "auth_method": "default",
			"scope": map[string]string{
				"region":   "us-east-1 $(id)",
				"endpoint": "https://sm.example.com/,cp.endpoint=https://evil.example",
			},
			"cluster_name": "tenant-a-uat", "discover_interval_seconds": 300,
		}, map[string]any{})
		refuse(t, h, []string{"evil.example", "$(id)"}, []string{
			"--set clusterName=tenant-a-uat",
			"--set providers.awsSecretsManager.region=<aws-region>",
			"--set providers.awsSecretsManager.endpoint=<aws-endpoint>",
		})
	})
}
