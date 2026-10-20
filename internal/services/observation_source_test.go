package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

type recAudit struct {
	storage.AuditEventRepository
	events []*storage.AuditEvent
}

func (r *recAudit) Append(_ context.Context, e *storage.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

type countGitOps struct{ n int }

func (g *countGitOps) Start(context.Context, *storage.AccessRequest) error { g.n++; return nil }

type fakeObserver struct {
	src    storage.ObservationSource
	err    error
	starts int
}

func (o *fakeObserver) Source(context.Context, *uuid.UUID) (storage.ObservationSource, error) {
	return o.src, o.err
}

func (o *fakeObserver) Start(context.Context, *storage.AccessRequest, *storage.SyncJob) error {
	o.starts++
	return nil
}

// TestStartObservation_OneObserverPerSource is the single decision point:
// each source starts exactly one observer (or none), and a source that
// cannot be read starts neither: never the control-plane poller by
// default (secrets-bridge/gateway#13).
func TestStartObservation_OneObserverPerSource(t *testing.T) {
	env := uuid.New()
	req := &storage.AccessRequest{ID: uuid.New(), EnvironmentID: &env}
	job := &storage.SyncJob{ID: uuid.New(), CorrelationID: uuid.New()}
	for _, tc := range []struct {
		name            string
		src             storage.ObservationSource
		err             error
		gitops, gateway int
		reason          string
	}{
		{"control_plane", storage.ObservationSourceControlPlane, nil, 1, 0, ""},
		{"gateway", storage.ObservationSourceGateway, nil, 0, 1, "source_gateway"},
		{"none", storage.ObservationSourceNone, nil, 0, 0, "source_none"},
		{"unreadable", "", errors.New("connection refused"), 0, 0, "source_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit, g, o := &recAudit{}, &countGitOps{}, &fakeObserver{src: tc.src, err: tc.err}
			s := &RequestService{audit: audit, gitops: g, observer: o}
			s.startObservation(context.Background(), req, job)
			if g.n != tc.gitops || o.starts != tc.gateway {
				t.Fatalf("gitops starts %d, gateway starts %d; want %d, %d", g.n, o.starts, tc.gitops, tc.gateway)
			}
			if tc.reason == "" {
				if len(audit.events) != 0 {
					t.Fatalf("audit = %+v; want none", audit.events)
				}
				return
			}
			if len(audit.events) != 1 || audit.events[0].Metadata["reason"] != tc.reason || audit.events[0].CorrelationID != job.CorrelationID {
				t.Fatalf("audit = %+v; want one row with reason %s", audit.events, tc.reason)
			}
		})
	}
}
