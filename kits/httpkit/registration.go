package httpkit

import "github.com/c1ayooo/capkit/core"

// NewCapability adapts New to the Registry constructor signature.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return New(deps), nil
}
