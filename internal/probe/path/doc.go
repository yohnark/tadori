// Package path implements bounded, native path observation.
//
// The package records what each TTL actually yielded. A missing response is
// represented as an unobservable hop, never as packet loss. Native ICMP
// observation and TTL-limited TCP connects are used on Unix-like systems when
// the host permits them; callers can inject an Observer for deterministic
// tests and other platform adapters.
package path
