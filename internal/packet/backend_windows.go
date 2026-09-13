//go:build windows

package packet

// DefaultBackend selects the in-box ETW adapter on Windows. It has no driver
// or packet-library installation step; Start reports token/OS limitations as
// a scoped capture status when ETW cannot be enabled.
func DefaultBackend() Backend {
	return NewETWBackend()
}
