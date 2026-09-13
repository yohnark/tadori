// Package dns implements resolver configuration and name-resolution probes.
//
// The probe deliberately accepts a small resolver interface. Production code
// uses the platform resolver adapter (including Windows DNS Client APIs),
// while tests can provide a deterministic fixture without depending on the
// host network or a public DNS service.
package dns
