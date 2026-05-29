// Package argocd is a strict read-only HTTP client for ArgoCD's REST
// API. Surfaces just enough of the API for Secrets Bridge to observe
// application health, sync status, rollout progress, and pod
// readiness — see BRD §26.
//
// HARD INVARIANT (load-bearing for the integration's security model):
//
//	This client MUST NEVER issue a write request to ArgoCD. The
//	httpClient field is wired through a transport that rejects any
//	method other than GET — `assertReadOnly` is the gate, and the
//	SelfCheck function additionally verifies the configured token's
//	RBAC at boot to refuse any write-capable token.
//
// The integration MUST refuse to operate if the configured token
// happens to carry write verbs even if no API on this client uses
// them. The boot-time RBAC self-check is the trust anchor.
//
// All responses are mapped into the typed structs in client.go.
// Manifests are NEVER surfaced; only filtered status fields per
// BRD §26.4.
package argocd
