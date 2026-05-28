// Package workflow will hold the approval state machine and request
// lifecycle for the Control Plane.
//
// Per BRD §12.2 and §13 FR-01, FR-10, this package will own the
// request → approval → execution flow with audit events emitted at
// every transition. Separation of duties (requester ≠ approver) is
// enforced here.
//
// Scaffold placeholder; concrete types land with secrets-bridge/api#6.
package workflow
