// Package diagnosis interprets the canonical report observation model without
// performing probe execution or network I/O. ProbeResult entry points remain
// compatibility adapters for callers that have not migrated yet.
//
// The package deliberately only consumes normalized interpretation fields.
// Raw evidence remains available to callers for inspection, but it is not a
// decision key here. Human-facing presentation belongs to internal/report.
package diagnosis
