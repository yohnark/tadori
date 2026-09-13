// Package tcp implements bounded TCP connectivity probes.
//
// A probe performs one TCP connect to the host and port in a model.Target. It
// does not perform DNS resolution as a separate operation; when a hostname is
// supplied, the standard library resolver is used by the dial operation and
// the socket endpoint returned by the connection is recorded as evidence.
package tcp
