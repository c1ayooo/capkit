package httpkit

import "github.com/c1ayooo/capkit"

// NewCapability adapts New to the Registry constructor signature.
func NewCapability(deps capkit.Deps) (capkit.Capability, error) {
	return New(deps), nil
}
