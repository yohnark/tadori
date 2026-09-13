// Package diagnosis interprets collected model.ProbeResult values without
// performing probe execution or network I/O.
//
// The package deliberately only consumes normalized interpretation fields.
// Raw evidence remains available to callers for inspection, but it is not a
// decision key here. Human-facing presentation belongs to internal/report.
package diagnosis
