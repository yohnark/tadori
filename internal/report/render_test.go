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
	target, err := model.ParseTarget(model.TargetIntent{Input: "https://example.com/health"})
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusIncomplete,
		StartedAt:     &started,
		CompletedAt:   &completed,
		Probes: []model.ProbeResult{
			{
				Name:   "dns",
				Target: model.NewTarget("example.com", 443),
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
				Target: model.NewTarget("example.com", 443),
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
		Target:        model.NewTarget("example.com", 443),
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

func TestTimestampRenderingUsesUTCAcrossReportProbeAndEvidence(t *testing.T) {
	reportStarted := time.Date(2026, time.January, 2, 12, 4, 5, 123456789, time.FixedZone("ahead", 9*60*60))
	reportCompleted := time.Date(2026, time.January, 2, 4, 5, 6, 987654321, time.FixedZone("behind", -5*60*60))
	probeStarted := time.Date(2026, time.January, 2, 13, 0, 0, 0, time.FixedZone("india", 5*60*60+30*60))
	probeCompleted := time.Date(2026, time.January, 2, 2, 1, 0, 0, time.FixedZone("west", -7*60*60))
	evidenceCaptured := time.Date(2026, time.January, 2, 20, 34, 5, 500000000, time.FixedZone("india", 5*60*60+30*60))
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        model.NewTarget("example.com", 443),
		Status:        model.ReportStatusComplete,
		StartedAt:     &reportStarted,
		CompletedAt:   &reportCompleted,
		Probes: []model.ProbeResult{{
			Name:   "http",
			Status: model.ProbeStatusPassed,
			Timing: model.Timing{StartedAt: &probeStarted, CompletedAt: &probeCompleted, DurationMS: 91},
			Evidence: []model.Evidence{{
				ID:         "http-1",
				Kind:       model.EvidenceKindHTTPResponse,
				CapturedAt: &evidenceCaptured,
				Raw:        json.RawMessage(`{"status":200}`),
			}},
			Interpretation: model.ProbeInterpretation{
				FailureReason: model.FailureReasonNone,
				Layer:         model.LayerHTTP,
				FaultDomain:   model.FaultDomainHTTP,
			},
		}},
	}

	encoded, err := MarshalJSON(report)
	if err != nil {
		t.Fatalf("marshal report with offset timestamps: %v", err)
	}
	for _, want := range []string{
		`"started_at":"2026-01-02T03:04:05.123456789Z"`,
		`"completed_at":"2026-01-02T09:05:06.987654321Z"`,
		`"started_at":"2026-01-02T07:30:00Z"`,
		`"completed_at":"2026-01-02T09:01:00Z"`,
		`"captured_at":"2026-01-02T15:04:05.5Z"`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("canonical JSON missing %q: %s", want, encoded)
		}
	}
	for _, nonCanonical := range []string{"+09:00", "-05:00", "+05:30", "-07:00"} {
		if strings.Contains(string(encoded), nonCanonical) {
			t.Errorf("canonical JSON retained source offset %q: %s", nonCanonical, encoded)
		}
	}

	human := RenderHuman(report)
	for _, want := range []string{
		`started_at="2026-01-02T03:04:05.123456789Z"`,
		`completed_at="2026-01-02T09:05:06.987654321Z"`,
		`started_at="2026-01-02T07:30:00Z"`,
		`completed_at="2026-01-02T09:01:00Z"`,
		`captured_at=2026-01-02T15:04:05.5Z`,
	} {
		if !strings.Contains(human, want) {
			t.Errorf("human output missing %q:\n%s", want, human)
		}
	}
	for _, nonCanonical := range []string{"+09:00", "-05:00", "+05:30", "-07:00"} {
		if strings.Contains(human, nonCanonical) {
			t.Errorf("human output mixed source offset %q:\n%s", nonCanonical, human)
		}
	}

	// Rendering is a projection: it must not change the source locations held
	// by the structured report for a later, explicitly localized presentation.
	if report.StartedAt.Location() != reportStarted.Location() || report.Probes[0].Timing.StartedAt.Location() != probeStarted.Location() || report.Probes[0].Evidence[0].CapturedAt.Location() != evidenceCaptured.Location() {
		t.Fatal("timestamp rendering mutated the structured report")
	}
}

func TestRenderHumanSuccessFixture(t *testing.T) {
	target, err := model.ParseTarget(model.TargetIntent{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
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
		"Target: example.com",
		"Service: HTTPS",
		"Transport: tcp",
		"Port: 443",
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
		Target: model.NewTarget("example.com", 443),
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
		Target: model.NewTarget("2001:db8::1", 443),
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
	if !strings.Contains(got, "Target: 2001:db8::1") || !strings.Contains(got, "Port: 443") {
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

func TestRenderHumanPlacesNetworkContextBeforeRawRouteEvidence(t *testing.T) {
	target := model.NewTarget("10.0.10.25", 80)
	target.NetworkContext = &model.NetworkContext{
		RequestedIdentity:          "10.0.10.25",
		SelectedDestinationAddress: "10.0.10.25",
		SelectedSourceInterface:    "Ethernet",
		SelectedSourceAddress:      "10.0.10.10",
		EffectiveRoute:             model.RouteDispositionOnLink,
		RoutePrefix:                "10.0.10.0/24",
		NextHop:                    "on-link",
		NetworkScope:               model.NetworkScopeSameLink,
	}
	report := model.DiagnosticReport{
		Target: target,
		Status: model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name:   "target_route",
			Status: model.ProbeStatusPassed,
			Evidence: []model.Evidence{{
				ID:   "route-1",
				Kind: model.EvidenceKindRoute,
				Raw:  json.RawMessage(`{"route_type":"target","effective_route":"on_link"}`),
			}},
		}},
	}
	human := RenderHuman(report)
	contextAt := strings.Index(human, "Network Context:")
	evidenceAt := strings.Index(human, "Evidence:")
	if contextAt < 0 || evidenceAt < 0 || contextAt >= evidenceAt {
		t.Fatalf("network context was not rendered before raw evidence:\n%s", human)
	}
	for _, want := range []string{"Network scope: Local link", "Source interface: Ethernet", "Source address: 10.0.10.10", "Route: On-link", "Gateway: Not applicable"} {
		if !strings.Contains(human, want) {
			t.Fatalf("human network context missing %q:\n%s", want, human)
		}
	}
}

func TestRenderHumanIncludesStructuredPathObservation(t *testing.T) {
	raw, err := json.Marshal(model.PathObservation{
		Status:             model.PathObservationStatusObserved,
		Protocol:           model.PathProtocolTCP,
		Destination:        "2001:db8::10",
		DestinationPort:    8443,
		PortAware:          true,
		MaxTTL:             3,
		AttemptsPerTTL:     1,
		Hops:               []model.PathHop{{TTL: 1, State: model.PathHopStateUnobservable}, {TTL: 2, State: model.PathHopStateObserved, Responders: []model.PathResponder{{Address: "2001:db8::1", Response: "tcp_time_exceeded"}}}},
		Segments:           []model.PathSegment{{Kind: model.PathSegmentUnobservable, FromTTL: 1, ToTTL: 1}, {Kind: model.PathSegmentObservedResponder, FromTTL: 2, ToTTL: 2}},
		DestinationReached: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := RenderHuman(model.DiagnosticReport{Probes: []model.ProbeResult{{
		Name: "path",
		Evidence: []model.Evidence{{
			ID:   "path/tcp",
			Kind: model.EvidenceKindPathObservation,
			Raw:  raw,
		}},
	}}})
	for _, want := range []string{
		"Path:",
		"protocol=tcp destination=[2001:db8::10]:8443 port_aware=true destination_reached=false",
		"ttl=1 state=unobservable",
		"ttl=2 state=observed_responder responders=2001:db8::1:tcp_time_exceeded",
		"segment=unobservable ttl=1-1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("path output missing %q:\n%s", want, got)
		}
	}
}
