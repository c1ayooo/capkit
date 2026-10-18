package gates

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/c1ayooo/capkit"
)

type countingLimiter struct {
	acquires int
	releases int
}

func (c *countingLimiter) Acquire(context.Context, string, capkit.RateLimitSpec) (func(), error) {
	c.acquires++
	return func() { c.releases++ }, nil
}

type memoryAudit struct{ events []capkit.AuditEvent }

func (m *memoryAudit) Record(_ context.Context, ev capkit.AuditEvent) {
	m.events = append(m.events, ev)
}

func testSpec() capkit.ToolSpec {
	return capkit.ToolSpec{
		Name: "probe", Description: "probe", Risk: capkit.RiskHigh,
		RateLimit: capkit.RateLimitSpec{PerSecond: 10, Burst: 2, Concurrency: 1},
		ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) {
			return []capkit.Target{{Kind: capkit.TargetURL, URL: "http://a.test", Host: "a.test"}}, nil
		},
	}
}

func TestChainScopeDenied(t *testing.T) {
	chain := &Chain{Scope: StaticScope("allowed.test"), Limiter: &countingLimiter{}, Audit: &memoryAudit{}}
	_, _, err := chain.Before(context.Background(), "cap", testSpec(), capkit.Call{Tool: "probe", Input: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("expected scope denial")
	}
	var ce *capkit.Error
	if !errors.As(err, &ce) || ce.Code != capkit.CodeScopeDenied {
		t.Fatalf("err = %v", err)
	}
}

func TestChainRequiresApproval(t *testing.T) {
	chain := &Chain{Scope: AllowAllScope(), Limiter: &countingLimiter{}, Audit: &memoryAudit{}, Approval: nil}
	_, _, err := chain.Before(context.Background(), "cap", testSpec(), capkit.Call{Tool: "probe", Input: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("expected approval error")
	}
	var ce *capkit.Error
	if !errors.As(err, &ce) || ce.Code != capkit.CodeApprovalRequired {
		t.Fatalf("err = %v", err)
	}
}

func TestChainAcquiresAndReleasesAndAudits(t *testing.T) {
	lim := &countingLimiter{}
	audit := &memoryAudit{}
	chain := &Chain{
		Scope: AllowAllScope(), Limiter: lim, Audit: audit,
		Approval: AutoApprove(), RequireApprovalAt: capkit.RiskHigh,
	}
	_, finish, err := chain.Before(context.Background(), "cap", testSpec(), capkit.Call{Tool: "probe", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if lim.acquires != 1 {
		t.Fatalf("acquires = %d", lim.acquires)
	}
	finish(capkit.TextResult("ok"), nil)
	if lim.releases != 1 {
		t.Fatalf("releases = %d", lim.releases)
	}
	if len(audit.events) != 2 {
		t.Fatalf("audit events = %d", len(audit.events))
	}
	if audit.events[0].Phase != "start" || audit.events[1].Phase != "finish" {
		t.Fatalf("phases = %q %q", audit.events[0].Phase, audit.events[1].Phase)
	}
	// finish is idempotent.
	finish(capkit.TextResult("ok"), nil)
	if lim.releases != 1 || len(audit.events) != 2 {
		t.Fatal("finish was not idempotent")
	}
}
