package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func TestMarshalJSONRoundTripsCanonicalReport(t *testing.T) {
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	completed := started.Add(12 * time.Millisecond)
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target: model.Target{
			URL:    "https://example.com/health",
			Scheme: "https",
			Host:   "example.com",
			Port:   443,
			Path:   "/health",
		},
		Status:      model.ReportStatusIncomplete,
		StartedAt:   &started,
		CompletedAt: &completed,
		Probes: []model.ProbeResult{
			{
				Name:   "dns",
				Target: model.Target{Host: "example.com", Port: 443},
				Status: model.ProbeStatusPassed,
				Timing: model.Timing{StartedAt: &started, CompletedAt: &completed, DurationMS: 12},
				Evidence: []model.Evidence{{
					ID:   "dns-1",
					Kind: model.EvidenceKindDNSResolution,
					Raw:  json.RawMessage(`{"answers":["192.0.2.1"]}`),
				}},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonNone,
					Layer:         model.LayerDNS,
					FaultDomain:   model.FaultDomainDNS,
				},
			},
			{
				Name:   "tcp",
				Target: model.Target{Host: "example.com", Port: 443},
				Status: model.ProbeStatusError,
				Timing: model.Timing{DurationMS: 34},
				Evidence: []model.Evidence{{
					ID:   "tcp-1",
					Kind: model.EvidenceKindTCPConnection,
					Raw:  json.RawMessage(`{"error":"connection refused"}`),
				}},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonTCPConnectionRefused,
					Layer:         model.LayerTCP,
					FaultDomain:   model.FaultDomainTransport,
				},
			},
		},
		Findings: []model.DiagnosticFinding{{
			FailureReason: model.FailureReasonTCPConnectionRefused,
			Layer:         model.LayerTCP,
			FaultDomain:   model.FaultDomainTransport,
			ProbeNames:    []string{"tcp"},
			EvidenceIDs:   []string{"tcp-1"},
		}},
	}

	encoded, err := MarshalJSON(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if !json.Valid(encoded) {
		t.Fatalf("renderer returned invalid JSON: %s", encoded)
	}

	var got model.DiagnosticReport
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !reflect.DeepEqual(got, report) {
		t.Fatalf("round trip changed canonical report\n got: %#v\nwant: %#v", got, report)
	}

	// Struct field order and compact encoding are part of this projection's
	// stable output.  Calling the alias must produce byte-identical JSON.
	alias, err := RenderJSON(report)
	if err != nil {
		t.Fatalf("render JSON alias: %v", err)
	}
	if !bytes.Equal(alias, encoded) {
		t.Fatalf("JSON aliases differ\n got: %s\nwant: %s", alias, encoded)
	}
}

func TestWriteJSONMatchesMarshalJSON(t *testing.T) {
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        model.Target{Host: "example.com", Port: 443},
		Status:        model.ReportStatusComplete,
		Probes:        []model.ProbeResult{},
	}
	want, err := MarshalJSON(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var got bytes.Buffer
	if err := WriteJSON(&got, report); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("written JSON differs\n got: %s\nwant: %s", got.Bytes(), want)
	}
}

func TestRenderHumanSuccessFixture(t *testing.T) {
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        model.Target{URL: "https://example.com"},
		Status:        model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name:   "dns",
			Status: model.ProbeStatusPassed,
			Timing: model.Timing{DurationMS: 7},
			Interpretation: model.ProbeInterpretation{
				FailureReason: model.FailureReasonNone,
				Layer:         model.LayerDNS,
				FaultDomain:   model.FaultDomainDNS,
			},
		}},
	}

	got := RenderHuman(report)
	for _, want := range []string{
		"Status: complete",
		"Target: https://example.com",
		"1. dns: passed (duration_ms=7)",
		"interpretation: failure_reason=none layer=dns fault_domain=dns",
		"Evidence:\n  (none)",
		"Findings:\n  (none)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("human output missing %q:\n%s", want, got)
		}
	}
}

func TestRenderHumanPartialFailureSeparatesEvidenceAndFinding(t *testing.T) {
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	report := model.DiagnosticReport{
		Target: model.Target{Host: "example.com", Port: 443},
		Status: model.ReportStatusIncomplete,
		Probes: []model.ProbeResult{
			{
				Name:   "dns",
				Status: model.ProbeStatusPassed,
				Timing: model.Timing{StartedAt: &started, DurationMS: 3},
				Evidence: []model.Evidence{{
					ID:     "dns-1",
					Kind:   model.EvidenceKindDNSResolution,
					Source: "resolver",
					Raw:    json.RawMessage(`{"rcode":"NOERROR","answers":["192.0.2.1"]}`),
				}},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonNone,
					Layer:         model.LayerDNS,
					FaultDomain:   model.FaultDomainDNS,
				},
			},
			{
				Name:   "tcp",
				Status: model.ProbeStatusFailed,
				Timing: model.Timing{DurationMS: 21},
				Evidence: []model.Evidence{{
					ID:   "tcp-1",
					Kind: model.EvidenceKindTCPConnection,
					Raw:  json.RawMessage(`{"error":"connection refused"}`),
				}},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonTCPConnectionRefused,
					Layer:         model.LayerTCP,
					FaultDomain:   model.FaultDomainTransport,
				},
			},
		},
		Findings: []model.DiagnosticFinding{{
			FailureReason: model.FailureReasonTCPConnectionRefused,
			Layer:         model.LayerTCP,
			FaultDomain:   model.FaultDomainTransport,
			ProbeNames:    []string{"tcp"},
			EvidenceIDs:   []string{"tcp-1"},
		}},
	}

	got := RenderHuman(report)
	for _, want := range []string{
		"Status: incomplete",
		"1. dns: passed (duration_ms=3, started_at=\"2026-01-02T03:04:05Z\")",
		"2. tcp: failed (duration_ms=21)",
		"dns-1: kind=dns_resolution source=resolver raw={\"rcode\":\"NOERROR\",\"answers\":[\"192.0.2.1\"]}",
		"tcp-1: kind=tcp_connection raw={\"error\":\"connection refused\"}",
		"failure_reason=tcp_connection_refused layer=tcp fault_domain=transport probes=tcp evidence=tcp-1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("human output missing %q:\n%s", want, got)
		}
	}

	evidenceAt := strings.Index(got, "Evidence:")
	findingAt := strings.Index(got, "Findings:")
	if evidenceAt < 0 || findingAt < 0 || evidenceAt >= findingAt {
		t.Fatalf("evidence and findings are not distinct ordered sections:\n%s", got)
	}
}

func TestRenderHumanMultiLayerFailurePreservesOrderAndDoesNotDiagnoseRawText(t *testing.T) {
	report := model.DiagnosticReport{
		Target: model.Target{Host: "2001:db8::1", Port: 443},
		Status: model.ReportStatusComplete,
		Probes: []model.ProbeResult{
			{
				Name:   "interface",
				Status: model.ProbeStatusPassed,
				Timing: model.Timing{DurationMS: 1},
				Evidence: []model.Evidence{{
					ID:   "if-1",
					Kind: model.EvidenceKindInterfaceState,
					Raw:  json.RawMessage(`{"error":"network unreachable"}`),
				}},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonNone,
					Layer:         model.LayerInterface,
					FaultDomain:   model.FaultDomainLocal,
				},
			},
			{
				Name:   "tls",
				Status: model.ProbeStatusPassed,
				Timing: model.Timing{DurationMS: 2},
				Evidence: []model.Evidence{{
					ID:   "tls-1",
					Kind: model.EvidenceKindTLSHandshake,
					Raw:  json.RawMessage(`{"error":"certificate expired"}`),
				}},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonNone,
					Layer:         model.LayerTLS,
					FaultDomain:   model.FaultDomainTLS,
				},
			},
		},
	}

	got := RenderHuman(report)
	if !strings.Contains(got, "Target: [2001:db8::1]:443") {
		t.Fatalf("IPv6 target was not rendered safely:\n%s", got)
	}
	if strings.Index(got, "1. interface") > strings.Index(got, "2. tls") {
		t.Fatalf("probe ordering changed:\n%s", got)
	}
	if strings.Index(got, "if-1:") > strings.Index(got, "tls-1:") {
		t.Fatalf("evidence ordering changed:\n%s", got)
	}
	if !strings.Contains(got, `if-1: kind=interface_state raw={"error":"network unreachable"}`) ||
		!strings.Contains(got, `tls-1: kind=tls_handshake raw={"error":"certificate expired"}`) {
		t.Fatalf("raw evidence was not projected verbatim:\n%s", got)
	}
	// The raw words above must not affect either report status or findings.
	if strings.Contains(got, "Findings:\n  -") {
		t.Fatalf("renderer derived a finding from raw evidence:\n%s", got)
	}
}

func TestWriteHumanAndTerminalAlias(t *testing.T) {
	report := model.DiagnosticReport{Status: model.ReportStatusError}
	want := RenderHuman(report)
	var human bytes.Buffer
	if err := WriteHuman(&human, report); err != nil {
		t.Fatalf("write human report: %v", err)
	}
	if human.String() != want {
		t.Fatalf("WriteHuman differs from RenderHuman\n got: %q\nwant: %q", human.String(), want)
	}
	if RenderTerminal(report) != want {
		t.Fatalf("RenderTerminal differs from RenderHuman")
	}
	var terminal bytes.Buffer
	if err := WriteTerminal(&terminal, report); err != nil {
		t.Fatalf("write terminal report: %v", err)
	}
	if terminal.String() != want {
		t.Fatalf("WriteTerminal differs from RenderHuman")
	}
}
