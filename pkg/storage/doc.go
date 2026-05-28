// Package storage will hold the Postgres-backed repositories and the
// migration tool that own the api's durable state.
//
// Per BRD §11 and §17, this package will own: projects, environments,
// provider_connections, agents, secret_mappings, access_requests,
// approvals, sync_jobs, sync_runs, and audit_events. Audit events are
// append-only.
//
// CRITICAL: no column in this schema may ever hold an actual secret
// value. Only references, version IDs, opaque content hashes, and
// statuses. This is the load-bearing invariant of the platform.
//
// Public surface of this package is importable by `worker` (per
// REFACTOR_PLAN §4 shared-code rule). `agent` and `controller` must
// never import it.
//
// Scaffold placeholder; concrete types land with secrets-bridge/api#2.
package storage
