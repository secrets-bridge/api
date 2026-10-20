package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// TestRoutes_NoArgoCDOrGitOpsRoutes: after the Gateway R1 cutover
// (secrets-bridge/gateway#13) the api serves no Argo CD endpoint,
// discovery or app-mapping route, whatever the configuration. The one
// route left is the read-only history of the removed poller.
func TestRoutes_NoArgoCDOrGitOpsRoutes(t *testing.T) {
	fx := newHygFixture(t, Config{Env: ModeDev, AllowDirectAgentMint: true, AllowInsecureHeaderAuth: true}, nil)
	const history = http.MethodGet + " /api/v1/requests/:id/gitops"
	sawHistory := false
	for _, rt := range fx.app.GetRoutes(true) {
		key := rt.Method + " " + rt.Path
		p := strings.ToLower(rt.Path)
		if !strings.Contains(p, "gitops") && !strings.Contains(p, "argocd") && !strings.Contains(p, "argo-cd") {
			continue
		}
		if key == history {
			sawHistory = true
			continue
		}
		t.Errorf("route %s is registered; only the Gateway talks to Argo CD", key)
	}
	if !sawHistory {
		t.Errorf("history route %s is not registered; the request page reads it", history)
	}
}

// TestRetiredEnv_GitOpsIsNotASwitch: SB_GITOPS_ENABLED and
// SB_ALLOW_INSECURE_ARGOCD_ADDR are reported by name on their own line,
// never with their value. Config has no field they could set, so they
// switch nothing on.
func TestRetiredEnv_GitOpsIsNotASwitch(t *testing.T) {
	const canary = "retired-gitops-value-canary"
	t.Setenv("SB_JWT_SECRET", "")
	t.Setenv("SB_JWT_TOKEN_TTL", "")
	t.Setenv("SB_GITOPS_ENABLED", canary)
	t.Setenv("SB_ALLOW_INSECURE_ARGOCD_ADDR", canary)
	cfg := loadConfig()
	if !slices.Equal(cfg.RetiredEnvSet, []string{"SB_GITOPS_ENABLED", "SB_ALLOW_INSECURE_ARGOCD_ADDR"}) {
		t.Fatalf("RetiredEnvSet = %v", cfg.RetiredEnvSet)
	}
	var buf bytes.Buffer
	logRetiredEnv(slog.New(slog.NewTextHandler(&buf, nil)), cfg.RetiredEnvSet)
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "SB_GITOPS_ENABLED") ||
		!strings.Contains(out, "SB_ALLOW_INSECURE_ARGOCD_ADDR") || !strings.Contains(out, "Gateway") {
		t.Fatalf("log = %q; want one line naming both settings and the Gateway", out)
	}
	if strings.Contains(out, canary) {
		t.Fatalf("log leaks a retired value: %q", out)
	}
}
