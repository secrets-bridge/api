package workflow_test

import (
	"testing"

	"github.com/secrets-bridge/api/pkg/storage"
	"github.com/secrets-bridge/api/pkg/workflow"
)

// The transition table is what the conditional writes match on, so a
// wrong entry here re-opens the API-S-09 race. Pin it.
func TestTransitions_Table(t *testing.T) {
	const (
		pending      = storage.AccessRequestStatusPending
		pendValues   = storage.AccessRequestStatusPendingValues
		pendVerify   = storage.AccessRequestStatusPendingVerification
		approved     = storage.AccessRequestStatusApproved
		rejected     = storage.AccessRequestStatusRejected
		cancelled    = storage.AccessRequestStatusCancelled
		executed     = storage.AccessRequestStatusExecuted
		failed       = storage.AccessRequestStatusFailed
		expired      = storage.AccessRequestStatusExpired
		refused      = storage.AccessRequestStatusRefused
		allStatusLen = 10
	)
	all := []storage.AccessRequestStatus{pending, pendValues, pendVerify, approved, rejected, cancelled, executed, failed, expired, refused}
	if len(all) != allStatusLen {
		t.Fatalf("status list drifted")
	}

	cases := []struct {
		action workflow.Action
		from   []storage.AccessRequestStatus
		to     storage.AccessRequestStatus
	}{
		{workflow.ActionApprove, []storage.AccessRequestStatus{pending}, approved},
		{workflow.ActionReject, []storage.AccessRequestStatus{pending}, rejected},
		{workflow.ActionCancel, []storage.AccessRequestStatus{pending, pendValues, pendVerify}, cancelled},
		{workflow.ActionFill, []storage.AccessRequestStatus{pendValues}, pendVerify},
		{workflow.ActionRefuse, []storage.AccessRequestStatus{pendValues}, refused},
		{workflow.ActionVerifyApprove, []storage.AccessRequestStatus{pendVerify}, approved},
		{workflow.ActionVerifyReject, []storage.AccessRequestStatus{pendVerify}, rejected},
		{workflow.ActionExecute, []storage.AccessRequestStatus{approved}, executed},
		{workflow.ActionFail, []storage.AccessRequestStatus{approved}, failed},
		{workflow.ActionExpire, []storage.AccessRequestStatus{pending, pendValues, pendVerify}, expired},
	}
	for _, c := range cases {
		tr := workflow.For(c.action)
		if tr.To != c.to {
			t.Errorf("%s: to = %s want %s", c.action, tr.To, c.to)
		}
		for _, s := range all {
			want := false
			for _, f := range c.from {
				if f == s {
					want = true
				}
			}
			if got := tr.Allows(s); got != want {
				t.Errorf("%s: Allows(%s) = %v want %v", c.action, s, got, want)
			}
		}
	}
}

// No transition may start from a terminal status: once a request is
// decided, nothing moves it except the job outcome on approved.
func TestTransitions_TerminalStatusesAreFinal(t *testing.T) {
	terminal := []storage.AccessRequestStatus{
		storage.AccessRequestStatusRejected,
		storage.AccessRequestStatusCancelled,
		storage.AccessRequestStatusExecuted,
		storage.AccessRequestStatusFailed,
		storage.AccessRequestStatusExpired,
		storage.AccessRequestStatusRefused,
	}
	actions := []workflow.Action{
		workflow.ActionApprove, workflow.ActionReject, workflow.ActionCancel,
		workflow.ActionFill, workflow.ActionRefuse, workflow.ActionVerifyApprove,
		workflow.ActionVerifyReject, workflow.ActionExecute, workflow.ActionFail,
		workflow.ActionExpire,
	}
	for _, a := range actions {
		for _, s := range terminal {
			if workflow.For(a).Allows(s) {
				t.Errorf("%s may start from terminal status %s", a, s)
			}
		}
	}
}

// For hands out a copy, so a caller can't edit the shared table.
func TestTransitions_ForReturnsCopy(t *testing.T) {
	tr := workflow.For(workflow.ActionCancel)
	tr.From[0] = storage.AccessRequestStatusApproved
	if workflow.For(workflow.ActionCancel).Allows(storage.AccessRequestStatusApproved) {
		t.Fatal("mutating a returned Transition changed the table")
	}
}

func TestTransitions_UnknownActionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("For(unknown) did not panic")
		}
	}()
	workflow.For("not-an-action")
}
