package services

// Scope digest (ADR 0002 C6; gateway docs/design/discovery-contract.md
// section 2.2). The control plane recomputes it from the uploaded
// endpoint_digest, allowed_projects and identity mode to check an E8
// upload (section 3.2 step 9). It never sees the URL: endpoint_digest is
// the Gateway's salted SHA-256 of it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

const gatewayScopeDigestLabel = "sb-argocd-scope/v1"

// GatewayScopeDigest is "sha256:" + hex(SHA-256(canonical_json(...))) of
// the names-mode scope input. canonical_json is keys sorted by byte
// value, no insignificant whitespace and minimal escapes; every value is
// ASCII from a fixed pattern, so encoding/json over a map with HTML
// escaping off produces it.
func GatewayScopeDigest(endpointDigest string, allowedProjects []string, discoveryEnabled bool, identityMode string) string {
	projects := slices.Clone(allowedProjects)
	slices.Sort(projects)
	if projects == nil {
		projects = []string{}
	}
	doc := map[string]any{
		"v":                 gatewayScopeDigestLabel,
		"kind":              GatewayKindArgoCD,
		"endpoint_digest":   endpointDigest,
		"allowed_projects":  projects,
		"discovery_enabled": discoveryEnabled,
		"identity_mode":     identityMode,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return ""
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
