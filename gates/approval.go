package gates

import (
	"context"

	"github.com/c1ayooo/capkit"
)

// ApproverFunc adapts a function to capkit.Approver.
type ApproverFunc func(ctx context.Context, req capkit.ApprovalRequest) error

func (f ApproverFunc) Require(ctx context.Context, req capkit.ApprovalRequest) error {
	return f(ctx, req)
}

// AutoApprove is an explicit test/dev opt-in. Never use it in production.
func AutoApprove() capkit.Approver {
	return ApproverFunc(func(context.Context, capkit.ApprovalRequest) error { return nil })
}

// DenyAll denies every approval request.
func DenyAll() capkit.Approver {
	return ApproverFunc(func(context.Context, capkit.ApprovalRequest) error {
		return capkit.NewError(capkit.CodeApprovalRequired, "approval is not configured")
	})
}
