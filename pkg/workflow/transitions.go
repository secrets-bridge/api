package workflow

import (
	"fmt"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Action names one lifecycle step that moves access_requests.status.
type Action string

const (
	// ActionApprove moves a pending patch/read request to approved once
	// the workflow's approval threshold is met.
	ActionApprove Action = "approve"
	// ActionReject closes a pending patch/read request.
	ActionReject Action = "reject"
	// ActionCancel lets the requester withdraw a request that is still
	// open (pending, or a cross_team request waiting on values or
	// verification).
	ActionCancel Action = "cancel"
	// ActionFill records Team B's values on a cross_team request.
	ActionFill Action = "fill"
	// ActionRefuse records Team B declining to provide values.
	ActionRefuse Action = "refuse"
	// ActionVerifyApprove moves a filled cross_team request to approved
	// once the source (and, when required, security) votes are in.
	ActionVerifyApprove Action = "verify_approve"
	// ActionVerifyReject closes a filled cross_team request.
	ActionVerifyReject Action = "verify_reject"
	// ActionExecute and ActionFail record the agent job outcome on an
	// approved request.
	ActionExecute Action = "execute"
	ActionFail    Action = "fail"
	// ActionExpire closes a request that was never approved within its
	// workflow's request_ttl.
	ActionExpire Action = "expire"
)

// Transition is the allowed-from set and the target status for an
// Action. Storage turns it into a conditional write
// (`UPDATE … WHERE id = $1 AND status = ANY(From)`), so a caller that
// read a stale status can never overwrite a decision someone else
// already made.
type Transition struct {
	From []storage.AccessRequestStatus
	To   storage.AccessRequestStatus
}

// openStatuses are the states in which a request has not been decided
// yet. Only these can be cancelled or expired.
var openStatuses = []storage.AccessRequestStatus{
	storage.AccessRequestStatusPending,
	storage.AccessRequestStatusPendingValues,
	storage.AccessRequestStatusPendingVerification,
}

var transitions = map[Action]Transition{
	ActionApprove: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusPending},
		To:   storage.AccessRequestStatusApproved,
	},
	ActionReject: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusPending},
		To:   storage.AccessRequestStatusRejected,
	},
	ActionCancel: {
		From: openStatuses,
		To:   storage.AccessRequestStatusCancelled,
	},
	ActionFill: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusPendingValues},
		To:   storage.AccessRequestStatusPendingVerification,
	},
	ActionRefuse: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusPendingValues},
		To:   storage.AccessRequestStatusRefused,
	},
	ActionVerifyApprove: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusPendingVerification},
		To:   storage.AccessRequestStatusApproved,
	},
	ActionVerifyReject: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusPendingVerification},
		To:   storage.AccessRequestStatusRejected,
	},
	ActionExecute: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusApproved},
		To:   storage.AccessRequestStatusExecuted,
	},
	ActionFail: {
		From: []storage.AccessRequestStatus{storage.AccessRequestStatusApproved},
		To:   storage.AccessRequestStatusFailed,
	},
	ActionExpire: {
		From: openStatuses,
		To:   storage.AccessRequestStatusExpired,
	},
}

// For returns the transition for an action. It panics on an unknown
// action: that is a programming error, and failing loudly beats
// silently allowing a write from any state.
func For(a Action) Transition {
	t, ok := transitions[a]
	if !ok {
		panic(fmt.Sprintf("workflow: unknown action %q", a))
	}
	from := make([]storage.AccessRequestStatus, len(t.From))
	copy(from, t.From)
	return Transition{From: from, To: t.To}
}

// Allows reports whether the transition may start from status s.
func (t Transition) Allows(s storage.AccessRequestStatus) bool {
	for _, f := range t.From {
		if f == s {
			return true
		}
	}
	return false
}
