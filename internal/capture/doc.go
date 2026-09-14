// Package capture implements a bounded, browser-scoped explicit HTTP proxy.
//
// The proxy listens only on a literal loopback address, records destination
// metadata, and tunnels CONNECT traffic without inspecting or decrypting TLS.
// It is intentionally not a general packet capture or remote proxy service.
package capture
