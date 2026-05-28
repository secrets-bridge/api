// Package services holds the business-logic layer of the api: the
// glue between thin HTTP handlers and the lower-level pkg/storage and
// pkg/runtime layers.
//
// Handlers should be thin — parse, call a service, serialize the
// result. Database calls and Redis calls should not appear directly in
// handler code; they belong behind a service.
//
// Scaffold placeholder; concrete services land alongside their owning
// issues (storage in #2, runtime in #3, workflow in #6).
package services
