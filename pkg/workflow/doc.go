// Package workflow holds the access-request state machine for the
// Control Plane: which status each lifecycle action may start from and
// where it lands (transitions.go). Services read the allowed-from set
// here and pass it to the conditional writes in pkg/storage, so the
// table is the single source of truth for status changes.
//
// Per BRD §12.2 and §13 FR-01, FR-10, the request → approval →
// execution flow emits an audit event at every transition; separation
// of duties (requester ≠ approver) is enforced in the services layer.
package workflow
