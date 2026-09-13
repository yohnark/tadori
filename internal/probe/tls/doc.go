// Package tls implements the bounded TLS handshake and certificate probe.
//
// The probe owns the TCP connection it needs for a handshake. A failure while
// opening that connection is retained as a transport-phase observation and
// is never reported as a TLS handshake failure. Certificate verification is
// enabled by default and remains enabled for the normal probe path.
package tls
