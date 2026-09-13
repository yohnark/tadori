// Package http performs bounded HTTP and HTTPS request probes against an
// explicit model.Target.URL. It records safe response metadata and keeps
// client-side DNS, transport, TLS, timeout, redirect, and cancellation
// failures distinct from received HTTP status codes.
package http
