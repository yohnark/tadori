package model

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestProbeResultJSONSeparatesRawEvidenceFromInterpretation(t *testing.T) {
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	completed := started.Add(12 * time.Millisecond)
	want := ProbeResult{
		Name: "dns",
		Target: Target{
			URL:    "https://example.com",
			Scheme: "https",
			Host:   "example.com",
			Port:   443,
		},
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
	wantJSON := `{"name":"dns","target":{"url":"https://example.com","scheme":"https","host":"example.com","port":443},"status":"failed","timing":{"started_at":"2026-01-02T03:04:05Z","completed_at":"2026-01-02T03:04:05.012Z","duration_ms":12},"evidence":[{"id":"dns-1","kind":"dns_resolution","source":"windows-resolver","raw":{"rcode":"NXDOMAIN","answers":[]}}],"interpretation":{"failure_reason":"dns_nxdomain","layer":"dns","fault_domain":"dns"}}`
	if gotJSON != wantJSON {
		t.Fatalf("unexpected canonical JSON\n got: %s\nwant: %s", gotJSON, wantJSON)
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

func TestDiagnosticReportJSONCarriesFindingsWithoutPresentationText(t *testing.T) {
	report := DiagnosticReport{
		SchemaVersion: DiagnosticSchemaVersion,
		Target: Target{
			Scheme: "https",
			Host:   "example.com",
			Port:   443,
		},
		Status: ReportStatusComplete,
		Probes: []ProbeResult{
			{
				Name:   "icmp",
				Target: Target{Host: "example.com", Port: 443},
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
