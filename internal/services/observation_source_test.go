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

// TestStartObservation_GatewayOrNothing is the single decision point:
// gateway starts the Gateway path, none starts nothing, and a source
// that cannot be read, or the retired control_plane, starts nothing.
// There is no control-plane observer to fall back to
// (secrets-bridge/gateway#13).
func TestStartObservation_GatewayOrNothing(t *testing.T) {
	env := uuid.New()
	withEnv := &storage.AccessRequest{ID: uuid.New(), EnvironmentID: &env}
	noEnv := &storage.AccessRequest{ID: uuid.New()}
	job := &storage.SyncJob{ID: uuid.New(), CorrelationID: uuid.New()}
	for _, tc := range []struct {
		name    string
		req     *storage.AccessRequest
		src     storage.ObservationSource
		err     error
		gateway int
		reason  string
	}{
		{"gateway", withEnv, storage.ObservationSourceGateway, nil, 1, ""},
		{"none", withEnv, storage.ObservationSourceNone, nil, 0, "source_none"},
		{"none without environment", noEnv, storage.ObservationSourceNone, nil, 0, ""},
		{"retired control_plane", withEnv, storage.ObservationSourceRetiredControlPlane, nil, 0, "source_unreadable"},
		{"unreadable", withEnv, "", errors.New("connection refused"), 0, "source_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit, o := &recAudit{}, &fakeObserver{src: tc.src, err: tc.err}
			s := &RequestService{audit: audit, observer: o}
			s.startObservation(context.Background(), tc.req, job)
			if o.starts != tc.gateway {
				t.Fatalf("gateway starts %d; want %d", o.starts, tc.gateway)
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

// TestObservationSource_ControlPlaneIsNotValid: the retired value is
// never a valid source, so no code path can store or start it.
func TestObservationSource_ControlPlaneIsNotValid(t *testing.T) {
	if storage.ObservationSourceRetiredControlPlane.Valid() {
		t.Fatal("control_plane is a valid observation source")
	}
	for _, s := range []storage.ObservationSource{storage.ObservationSourceGateway, storage.ObservationSourceNone} {
		if !s.Valid() {
			t.Fatalf("%s is not valid", s)
		}
	}
}
