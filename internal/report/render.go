// Package report contains presentation-only projections of the canonical
// diagnostic model.  It deliberately does not run probes or interpret their
// observations.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

// MarshalJSON returns the canonical JSON representation of report.
//
// The model's JSON tags and field order are the canonical contract. Timestamp
// marshalers normalize report, probe, and evidence timestamps to UTC without
// changing the supplied report or inspecting Evidence.Raw.
func MarshalJSON(report model.DiagnosticReport) ([]byte, error) {
	return json.Marshal(report)
}

// RenderJSON is an explicit presentation-oriented alias for MarshalJSON.
// Callers that render more than one format can use the same vocabulary for
// both projections.
func RenderJSON(report model.DiagnosticReport) ([]byte, error) {
	return MarshalJSON(report)
}

// JSON is a short alias for RenderJSON for callers that select the output
// format at the call site.
func JSON(report model.DiagnosticReport) ([]byte, error) {
	return RenderJSON(report)
}

// WriteJSON writes the canonical JSON representation to w without appending a
// newline.  The absence of a newline keeps the returned document identical to
// MarshalJSON and leaves stream framing to the caller.
func WriteJSON(w io.Writer, report model.DiagnosticReport) error {
	if w == nil {
		return errors.New("report: nil JSON writer")
	}

	encoded, err := MarshalJSON(report)
	if err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}

// RenderHuman returns a concise, deterministic terminal projection of report.
// All interpretation and finding values are copied from the structured model;
// no meaning is inferred from raw evidence or from error text.  Slices are
// traversed in their supplied order so probe/evidence/finding ordering is
// retained.
func RenderHuman(report model.DiagnosticReport) string {
	var out strings.Builder

	fmt.Fprintf(&out, "Status: %s\n", report.Status)
	fmt.Fprintf(&out, "Target: %s\n", formatTarget(report.Target))
	if report.StartedAt != nil || report.CompletedAt != nil {
		out.WriteString("Report timing:")
		if report.StartedAt != nil {
			fmt.Fprintf(&out, " started_at=%s", strconv.Quote(formatTimestamp(*report.StartedAt)))
		}
		if report.CompletedAt != nil {
			fmt.Fprintf(&out, " completed_at=%s", strconv.Quote(formatTimestamp(*report.CompletedAt)))
		}
		out.WriteByte('\n')
	}

	out.WriteString("Probes:\n")
	if len(report.Probes) == 0 {
		out.WriteString("  (none)\n")
	} else {
		for i, probe := range report.Probes {
			fmt.Fprintf(&out, "  %d. %s: %s (%s)\n", i+1, probe.Name, probe.Status, formatTiming(probe.Timing))
			fmt.Fprintf(&out, "     interpretation: failure_reason=%s layer=%s fault_domain=%s\n",
				probe.Interpretation.FailureReason,
				probe.Interpretation.Layer,
				probe.Interpretation.FaultDomain,
			)
		}
	}

	out.WriteString("Evidence:\n")
	evidenceCount := 0
	for _, probe := range report.Probes {
		for _, evidence := range probe.Evidence {
			evidenceCount++
			fmt.Fprintf(&out, "  - %s: kind=%s", evidence.ID, evidence.Kind)
			if evidence.Source != "" {
				fmt.Fprintf(&out, " source=%s", evidence.Source)
			}
			if evidence.CapturedAt != nil {
				fmt.Fprintf(&out, " captured_at=%s", formatTimestamp(*evidence.CapturedAt))
			}
			// Raw is intentionally written as supplied.  It is evidence, not
			// an input to renderer policy.
			fmt.Fprintf(&out, " raw=%s\n", evidence.Raw)
		}
	}
	if evidenceCount == 0 {
		out.WriteString("  (none)\n")
	}

	out.WriteString("Path:\n")
	out.WriteString("  note: observed responders and inferred segments are not exact physical topology\n")
	pathCount := 0
	for _, probe := range report.Probes {
		for _, evidence := range probe.Evidence {
			if evidence.Kind != model.EvidenceKindPathObservation {
				continue
			}
			observation, err := model.DecodePathObservation(evidence)
			if err != nil {
				continue
			}
			pathCount++
			fmt.Fprintf(&out, "  - protocol=%s destination=%s port_aware=%t destination_reached=%t\n",
				observation.Protocol,
				formatPathDestination(observation.Destination, observation.DestinationPort),
				observation.PortAware,
				observation.DestinationReached,
			)
			for _, hop := range observation.Hops {
				fmt.Fprintf(&out, "    ttl=%d state=%s", hop.TTL, hop.State)
				if len(hop.Responders) > 0 {
					responders := make([]string, 0, len(hop.Responders))
					for _, responder := range hop.Responders {
						value := responder.Address
						if responder.Response != "" {
							value += ":" + responder.Response
						}
						responders = append(responders, value)
					}
					fmt.Fprintf(&out, " responders=%s", strings.Join(responders, ","))
				}
				out.WriteByte('\n')
			}
			for _, segment := range observation.Segments {
				fmt.Fprintf(&out, "    segment=%s ttl=%d-%d\n", segment.Kind, segment.FromTTL, segment.ToTTL)
			}
		}
	}
	if pathCount == 0 {
		out.WriteString("  (none)\n")
	}

	out.WriteString("Findings:\n")
	if len(report.Findings) == 0 {
		out.WriteString("  (none)\n")
	} else {
		for _, finding := range report.Findings {
			fmt.Fprintf(&out, "  - failure_reason=%s layer=%s fault_domain=%s",
				finding.FailureReason,
				finding.Layer,
				finding.FaultDomain,
			)
			if len(finding.ProbeNames) > 0 {
				fmt.Fprintf(&out, " probes=%s", strings.Join(finding.ProbeNames, ","))
			}
			if len(finding.EvidenceIDs) > 0 {
				fmt.Fprintf(&out, " evidence=%s", strings.Join(finding.EvidenceIDs, ","))
			}
			out.WriteByte('\n')
		}
	}

	return out.String()
}

// RenderTerminal is the terminal-rendering name retained for callers that
// distinguish terminal output from other human-readable projections.
func RenderTerminal(report model.DiagnosticReport) string {
	return RenderHuman(report)
}

// Human is a short alias for RenderHuman.
func Human(report model.DiagnosticReport) string {
	return RenderHuman(report)
}

// WriteHuman writes the terminal projection to w without changing it.  A
// newline is part of the human-readable document returned by RenderHuman.
func WriteHuman(w io.Writer, report model.DiagnosticReport) error {
	if w == nil {
		return errors.New("report: nil human-readable writer")
	}
	_, err := io.WriteString(w, RenderHuman(report))
	return err
}

// WriteTerminal is the writer form of RenderTerminal.
func WriteTerminal(w io.Writer, report model.DiagnosticReport) error {
	return WriteHuman(w, report)
}

func formatTarget(target model.Target) string {
	if target.URL != "" {
		return target.URL
	}

	var host string
	if target.Host != "" {
		host = target.Host
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
	}
	if target.Port != 0 {
		return fmt.Sprintf("%s:%d", host, target.Port)
	}
	if host != "" {
		return host
	}
	return "(unspecified)"
}

func formatPathDestination(host string, port uint16) string {
	if host == "" {
		return "(unspecified)"
	}
	if port == 0 {
		return host
	}
	return netJoinHostPort(host, port)
}

func netJoinHostPort(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func formatTiming(timing model.Timing) string {
	parts := []string{fmt.Sprintf("duration_ms=%d", timing.DurationMS)}
	if timing.StartedAt != nil {
		parts = append(parts, "started_at="+strconv.Quote(formatTimestamp(*timing.StartedAt)))
	}
	if timing.CompletedAt != nil {
		parts = append(parts, "completed_at="+strconv.Quote(formatTimestamp(*timing.CompletedAt)))
	}
	return strings.Join(parts, ", ")
}

// formatTimestamp is presentation-only. Human output uses one explicit zone
// for every timestamp in a report and does not alter the model value.
func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format(time.RFC3339Nano)
}
