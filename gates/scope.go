package gates

import (
	"context"
	"strings"

	"github.com/c1ayooo/capkit"
)

// ScopeFunc adapts a function to capkit.ScopeChecker.
type ScopeFunc func(ctx context.Context, target capkit.Target) error

func (f ScopeFunc) Check(ctx context.Context, target capkit.Target) error {
	return f(ctx, target)
}

// AllowAllScope is an explicit test/dev opt-in. Never use it in production.
func AllowAllScope() capkit.ScopeChecker {
	return ScopeFunc(func(context.Context, capkit.Target) error { return nil })
}

// DenyAllScope fails closed.
func DenyAllScope() capkit.ScopeChecker {
	return ScopeFunc(func(context.Context, capkit.Target) error {
		return capkit.ScopeDenied("scope is not configured")
	})
}

// StaticScope allows exact hosts and their subdomains. IP/CIDR targets must
// match exactly. It is intentionally simple; real hosts should use their
// project-scope implementation.
func StaticScope(hosts ...string) capkit.ScopeChecker {
	allowed := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			allowed = append(allowed, h)
		}
	}
	return ScopeFunc(func(_ context.Context, target capkit.Target) error {
		key := target.Key()
		for _, h := range allowed {
			if key == h || strings.HasSuffix(key, "."+h) {
				return nil
			}
		}
		return capkit.ScopeDenied("target " + key + " is outside the authorized scope")
	})
}
