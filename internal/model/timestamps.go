package model

import (
	"encoding/json"
	"time"
)

// canonicalTime returns a copy of timestamp in UTC. The input is never
// changed, which keeps presentation concerns separate from the canonical JSON
// projection.
func canonicalTime(timestamp *time.Time) *time.Time {
	if timestamp == nil {
		return nil
	}

	utc := timestamp.UTC()
	return &utc
}

// MarshalJSON emits timing timestamps in UTC while leaving DurationMS
// untouched. time.Time's JSON marshaler supplies RFC3339/RFC3339Nano output.
func (timing Timing) MarshalJSON() ([]byte, error) {
	type canonicalTiming struct {
		StartedAt   *time.Time `json:"started_at,omitempty"`
		CompletedAt *time.Time `json:"completed_at,omitempty"`
		DurationMS  int64      `json:"duration_ms"`
	}

	return json.Marshal(canonicalTiming{
		StartedAt:   canonicalTime(timing.StartedAt),
		CompletedAt: canonicalTime(timing.CompletedAt),
		DurationMS:  timing.DurationMS,
	})
}

// MarshalJSON emits evidence timestamps in UTC. Raw evidence is passed
// through unchanged.
func (evidence Evidence) MarshalJSON() ([]byte, error) {
	type canonicalEvidence struct {
		ID         string          `json:"id"`
		Kind       EvidenceKind    `json:"kind"`
		Source     string          `json:"source,omitempty"`
		CapturedAt *time.Time      `json:"captured_at,omitempty"`
		Raw        json.RawMessage `json:"raw"`
	}

	return json.Marshal(canonicalEvidence{
		ID:         evidence.ID,
		Kind:       evidence.Kind,
		Source:     evidence.Source,
		CapturedAt: canonicalTime(evidence.CapturedAt),
		Raw:        evidence.Raw,
	})
}

// MarshalJSON emits report timestamps in UTC. Probe timing and evidence use
// their own canonical marshalers, so all timestamp-bearing levels of a report
// share the same representation.
func (report DiagnosticReport) MarshalJSON() ([]byte, error) {
	type canonicalReport struct {
		SchemaVersion string              `json:"schema_version"`
		Target        Target              `json:"target"`
		Status        ReportStatus        `json:"status"`
		StartedAt     *time.Time          `json:"started_at,omitempty"`
		CompletedAt   *time.Time          `json:"completed_at,omitempty"`
		Probes        []ProbeResult       `json:"probes"`
		Findings      []DiagnosticFinding `json:"findings,omitempty"`
	}

	return json.Marshal(canonicalReport{
		SchemaVersion: report.SchemaVersion,
		Target:        report.Target,
		Status:        report.Status,
		StartedAt:     canonicalTime(report.StartedAt),
		CompletedAt:   canonicalTime(report.CompletedAt),
		Probes:        report.Probes,
		Findings:      report.Findings,
	})
}
