package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProbeResultJSONSeparatesRawEvidenceFromInterpretation(t *testing.T) {
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	completed := started.Add(12 * time.Millisecond)
	target, err := ParseTarget(TargetIntent{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	want := ProbeResult{
		Name:   "dns",
		Target: target,
		Status: ProbeStatusFailed,
		Timing: Timing{
			StartedAt:   &started,
			CompletedAt: &completed,
			DurationMS:  12,
		},
		Evidence: []Evidence{
			{
				ID:     "dns-1",
				Kind:   EvidenceKindDNSResolution,
				Source: "windows-resolver",
				Raw:    json.RawMessage(`{"rcode":"NXDOMAIN","answers":[]}`),
			},
		},
		Interpretation: ProbeInterpretation{
			FailureReason: FailureReasonDNSNXDomain,
			Layer:         LayerDNS,
			FaultDomain:   FaultDomainDNS,
		},
	}

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal probe result: %v", err)
	}

	gotJSON := string(encoded)
	for _, field := range []string{`"original_input":"https://example.com"`, `"requested_identity":"example.com"`, `"id":"https"`, `"port":443`} {
		if !strings.Contains(gotJSON, field) {
			t.Fatalf("canonical JSON missing %q: %s", field, gotJSON)
		}
	}

	var roundTrip ProbeResult
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal probe result: %v", err)
	}
	if !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("round trip changed contract\n got: %#v\nwant: %#v", roundTrip, want)
	}

	var document struct {
		Evidence []struct {
			Raw json.RawMessage `json:"raw"`
		} `json:"evidence"`
		Interpretation ProbeInterpretation `json:"interpretation"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("unmarshal separation check: %v", err)
	}
	if string(document.Evidence[0].Raw) != `{"rcode":"NXDOMAIN","answers":[]}` {
		t.Fatalf("raw evidence was rewritten: %s", document.Evidence[0].Raw)
	}
	if document.Interpretation.FailureReason != FailureReasonDNSNXDomain {
		t.Fatalf("interpretation was not serialized separately: %#v", document.Interpretation)
	}
}

func TestProbeResultJSONNormalizesTimestampOffsets(t *testing.T) {
	started := time.Date(2026, time.January, 2, 12, 4, 5, 123456789, time.FixedZone("ahead", 9*60*60))
	completed := time.Date(2026, time.January, 2, 4, 5, 6, 987654321, time.FixedZone("behind", -5*60*60))
	captured := time.Date(2026, time.January, 2, 20, 34, 5, 500000000, time.FixedZone("india", 5*60*60+30*60))
	duration := completed.Sub(started).Milliseconds()
	probe := ProbeResult{
		Name:   "offset-probe",
		Target: NewTarget("example.com", 443),
		Status: ProbeStatusPassed,
		Timing: Timing{
			StartedAt:   &started,
			CompletedAt: &completed,
			DurationMS:  duration,
		},
		Evidence: []Evidence{{
			ID:         "offset-evidence",
			Kind:       EvidenceKindHTTPResponse,
			CapturedAt: &captured,
			Raw:        json.RawMessage(`{"status":200}`),
		}},
		Interpretation: ProbeInterpretation{
			FailureReason: FailureReasonNone,
			Layer:         LayerHTTP,
			FaultDomain:   FaultDomainHTTP,
		},
	}

	encoded, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("marshal probe result: %v", err)
	}

	for _, want := range []string{
		`"started_at":"2026-01-02T03:04:05.123456789Z"`,
		`"completed_at":"2026-01-02T09:05:06.987654321Z"`,
		`"captured_at":"2026-01-02T15:04:05.5Z"`,
		`"duration_ms":21661864`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("canonical probe JSON missing %q: %s", want, encoded)
		}
	}
	for _, nonCanonical := range []string{"+09:00", "-05:00", "+05:30"} {
		if strings.Contains(string(encoded), nonCanonical) {
			t.Errorf("canonical probe JSON retained source offset %q: %s", nonCanonical, encoded)
		}
	}

	var decoded ProbeResult
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal normalized probe result: %v", err)
	}
	if !decoded.Timing.StartedAt.Equal(started) || !decoded.Timing.CompletedAt.Equal(completed) || !decoded.Evidence[0].CapturedAt.Equal(captured) {
		t.Fatalf("timestamp instant changed after canonicalization: %#v", decoded)
	}
	if decoded.Timing.DurationMS != duration {
		t.Fatalf("duration changed after canonicalization: got %d, want %d", decoded.Timing.DurationMS, duration)
	}
	if decoded.Timing.StartedAt.Location() != time.UTC || decoded.Timing.CompletedAt.Location() != time.UTC || decoded.Evidence[0].CapturedAt.Location() != time.UTC {
		t.Fatalf("decoded canonical timestamps are not UTC: %#v", decoded)
	}
}

func TestDiagnosticReportJSONCarriesFindingsWithoutPresentationText(t *testing.T) {
	report := DiagnosticReport{
		SchemaVersion: DiagnosticSchemaVersion,
		Target:        NewTarget("example.com", 443),
		Status:        ReportStatusComplete,
		Probes: []ProbeResult{
			{
				Name:   "icmp",
				Target: NewTarget("example.com", 443),
				Status: ProbeStatusFailed,
				Timing: Timing{DurationMS: 4},
				Interpretation: ProbeInterpretation{
					FailureReason: FailureReasonICMPFailure,
					Layer:         LayerICMP,
					FaultDomain:   FaultDomainICMP,
				},
			},
		},
		Findings: []DiagnosticFinding{
			{
				FailureReason: FailureReasonICMPFailure,
				Layer:         LayerICMP,
				FaultDomain:   FaultDomainICMP,
				ProbeNames:    []string{"icmp"},
			},
		},
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal diagnostic report: %v", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode diagnostic report: %v", err)
	}
	for _, presentationKey := range []string{"message", "summary", "text"} {
		if _, exists := document[presentationKey]; exists {
			t.Fatalf("presentation field %q unexpectedly present", presentationKey)
		}
	}

	var roundTrip DiagnosticReport
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal diagnostic report: %v", err)
	}
	if !reflect.DeepEqual(roundTrip, report) {
		t.Fatalf("round trip changed report contract\n got: %#v\nwant: %#v", roundTrip, report)
	}
	if roundTrip.Status != ReportStatusComplete {
		t.Fatalf("ICMP failure changed report execution status: %s", roundTrip.Status)
	}
	if roundTrip.Findings[0].FaultDomain == FaultDomainNetwork {
		t.Fatal("ICMP failure was promoted to a network fault domain")
	}
}
