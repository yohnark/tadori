//go:build !windows

package packet

// DefaultBackend is deliberately unsupported off Windows. Existing TCP/path
// probes continue to run and carry an explicit packet-capture availability
// fact rather than using a platform-specific raw socket or shell fallback.
func DefaultBackend() Backend {
	return NewUnsupportedBackend("no supported packet capture backend for this platform")
}
