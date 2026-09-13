// Package packet owns the bounded packet-acquisition boundary and the pure
// correlation step that turns adapter observations into model.PacketFlowEvidence.
// Acquisition never exposes a general sniffing API: every backend receives a
// target, process, session, and probe scope, and callers retain only the
// structured observations needed by that diagnostic run.
package packet
