package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func TestRenderHTMLUsesCanonicalObservationsAndFindings(t *testing.T) {
	diagnosticReport := semanticHTMLFixture()
	first, err := RenderHTML(diagnosticReport)
	if err != nil {
		t.Fatalf("render HTML: %v", err)
	}
	second, err := RenderHTML(diagnosticReport)
	if err != nil {
		t.Fatalf("render HTML second time: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("HTML rendering is not deterministic")
	}

	document := string(first)
	for _, want := range []string{
		"Target and service",
		"Destination Status",
		"REACHABLE",
		"HTTP returned 200.",
		"canonical.example",
		"HTTPS",
		"Conclusion and diagnostic boundary",
		"DNS and name resolution",
		"Network context",
		"Transport",
		"TLS and security",
		"Application and service",
		"Observed path summary",
		"Enterprise policy and proxy observations",
		"Findings",
		"Limitations and conflicts",
		"Evidence and provenance",
		"tcp_timeout",
		"observed_responder",
		"inferred",
		"unsupported",
		"conflicting.example",
		"canonical JSON",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	semanticDocument := strings.SplitN(document, "<section class=\"section canonical\">", 2)[0]
	if strings.Contains(semanticDocument, "legacy.example") {
		t.Fatal("HTML derived target meaning from the compatibility Target field")
	}
	if statusAt, targetAt := strings.Index(document, "Destination Status"), strings.Index(document, "Target and service"); statusAt < 0 || targetAt < 0 || statusAt >= targetAt {
		t.Fatalf("destination status was not rendered near the top of the report: status=%d target=%d", statusAt, targetAt)
	}
	if !strings.Contains(document, `\u003craw-semantic-value\u003e`) {
		t.Fatal("canonical JSON evidence was not safely embedded as text")
	}
	if !strings.Contains(document, "Raw evidence references (secondary)") {
		t.Fatal("evidence provenance section missing")
	}
	if !strings.Contains(document, "not a physical topology claim") {
		t.Fatal("path boundary missing")
	}
	for _, forbidden := range []string{"<script", "<link", "<img", "src=\"http"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("self-contained HTML contains external or executable resource %q", forbidden)
		}
	}
}

func TestWriteHTMLMatchesRenderHTML(t *testing.T) {
	diagnosticReport := semanticHTMLFixture()
	want, err := RenderHTML(diagnosticReport)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := WriteHTML(&got, diagnosticReport); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("written HTML differs from rendered HTML")
	}
	if err := WriteHTML(nil, diagnosticReport); err == nil {
		t.Fatal("WriteHTML(nil, report) unexpectedly succeeded")
	}
}

func TestRenderHTMLDoesNotDecodeProbeEvidenceForSemantics(t *testing.T) {
	base := semanticHTMLFixture()
	base.Observations.Endpoint.RequestedIdentity = "canonical.example"
	base.Probes[0].Evidence[0].Raw = json.RawMessage(`{"requested_identity":"changed-by-raw","failure_reason":"tcp_timeout"}`)
	first, err := RenderHTML(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Probes[0].Evidence[0].Raw = json.RawMessage(`{"requested_identity":"another-raw-value","failure_reason":"none"}`)
	second, err := RenderHTML(base)
	if err != nil {
		t.Fatal(err)
	}
	firstSemantic := strings.SplitN(string(first), "<section class=\"section canonical\">", 2)[0]
	secondSemantic := strings.SplitN(string(second), "<section class=\"section canonical\">", 2)[0]
	if strings.Contains(firstSemantic, "changed-by-raw") || strings.Contains(secondSemantic, "another-raw-value") {
		t.Fatal("raw probe payload became a semantic HTML value")
	}
	if !strings.Contains(string(first), "canonical.example") || !strings.Contains(string(second), "canonical.example") {
		t.Fatal("canonical observation was not rendered")
	}
}

func semanticHTMLFixture() model.DiagnosticReport {
	legacyTarget, _ := model.ParseTarget(model.TargetIntent{Input: "https://legacy.example"})
	canonicalTarget, _ := model.ParseTarget(model.TargetIntent{Input: "https://canonical.example/health"})
	selected := model.Endpoint{Address: "192.0.2.10", Port: 443, Family: model.EndpointFamilyIPv4, SelectionReason: model.EndpointSelectionDeterministic, Certainty: model.ObservationCertaintyObserved}
	started := canonicalTargetPortTime()
	completed := started.Add(25 * 1e6)
	return model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        legacyTarget,
		Status:        model.ReportStatusComplete,
		StartedAt:     &started,
		CompletedAt:   &completed,
		Observations: model.Observations{
			Endpoint: model.EndpointObservation{
				OriginalInput:       "https://canonical.example/health",
				RequestedIdentity:   "canonical.example",
				Service:             canonicalTarget.Service,
				ApplicationProtocol: model.ApplicationProtocolHTTPS,
				TransportProtocol:   model.TransportTCP,
				Port:                443,
				Resource:            "/health",
				SelectedEndpoint:    &selected,
				TestedEndpoint:      &selected,
				Certainty:           model.ObservationCertaintyObserved,
				Provenance:          []string{"transport probe"},
				Limitations:         []string{"candidate selection is Tadori-local"},
				Conflicts: []model.ObservationConflict{{
					Field: "endpoint", Values: []string{"192.0.2.10", "192.0.2.11"}, Provenance: []string{"resolver", "transport"},
				}},
			},
			NameResolution: model.NameResolutionObservation{
				RequestedName: "canonical.example", A: []string{"192.0.2.10"}, SelectedAddress: "192.0.2.10",
				Certainty: model.ObservationCertaintyObserved, Provenance: []string{"native resolver"}, EvidenceIDs: []string{"dns-1"},
				EffectivePath: &model.NameResolutionPath{State: model.NameResolutionPathEffective, Mechanism: model.NameResolutionMechanismDNS, Certainty: model.NameResolutionCertaintyObserved, Resolver: "192.0.2.53"},
			},
			NetworkContext:   model.NetworkContext{RequestedIdentity: "canonical.example", SelectedDestinationAddress: "192.0.2.10", NetworkScope: model.NetworkScopeExternalRouted, EffectiveRoute: model.RouteDispositionRouted, Certainty: model.ObservationCertaintyObserved, EvidenceIDs: []string{"route-1"}},
			Transport:        model.TransportObservation{Applicability: model.ObservationApplicabilityApplicable, Connected: true, ConnectionOutcome: model.TransportConnectionOutcomeConnected, RemoteEndpoint: &selected, Timing: model.Timing{DurationMS: 12}, Certainty: model.ObservationCertaintyObserved, EvidenceIDs: []string{"tcp-1"}},
			Security:         model.SecurityObservation{Applicability: model.ObservationApplicabilityApplicable, Attempted: true, HandshakeComplete: true, NegotiatedProtocol: "h2", CipherSuite: "TLS_AES_128_GCM_SHA256", CertificateValidation: model.CertificateValidationValid, Certificates: []model.TLSCertificateObservation{{Subject: "CN=canonical.example", SHA256: "abc123"}}, Certainty: model.ObservationCertaintyObserved, EvidenceIDs: []string{"tls-1"}},
			Application:      model.ApplicationObservation{Applicability: model.ObservationApplicabilityApplicable, RequestAttempted: true, ResponseReceived: true, Protocol: model.ApplicationProtocolHTTPS, ProtocolResult: model.ApplicationProtocolResultSuccess, Result: model.HTTPResultSuccess, StatusCode: 200, Status: "success", RequestedResource: "/health", Certainty: model.ObservationCertaintyObserved, EvidenceIDs: []string{"http-1"}},
			Paths:            []model.PathObservation{{Status: model.PathObservationStatusObserved, Protocol: model.PathProtocolICMP, Destination: "192.0.2.10", DestinationPort: 443, Hops: []model.PathHop{{TTL: 1, State: model.PathHopStateObserved, Responders: []model.PathResponder{{Address: "198.51.100.1"}}}, {TTL: 2, State: model.PathHopStateUnobservable}}, Segments: []model.PathSegment{{Kind: model.PathSegmentObservedResponder, FromTTL: 1, ToTTL: 1}, {Kind: model.PathSegmentInferred, FromTTL: 1, ToTTL: 2}}, DestinationReached: true}},
			PathProvenance:   []model.ObservationProvenance{{ProbeName: "path", Source: "native path API", EvidenceIDs: []string{"path-1"}}},
			EnterprisePolicy: model.EnterprisePolicyObservation{RequestedIdentity: "canonical.example", State: model.EnterpriseObservationStatePartial, Unsupported: true, Certainty: model.ObservationCertaintyUnsupported, Limitations: []string{"enterprise policy lane unsupported"}},
			Conflicts:        []model.ObservationConflict{{Field: "security", Values: []string{"trusted", "unknown", "conflicting.example"}}},
		},
		Probes:   []model.ProbeResult{{Name: "tcp", Status: model.ProbeStatusPassed, Timing: model.Timing{StartedAt: &started, CompletedAt: &completed, DurationMS: 12}, Evidence: []model.Evidence{{ID: "tcp-1", Kind: model.EvidenceKindTCPConnection, Raw: json.RawMessage(`{"raw":"<raw-semantic-value>"}`)}}, Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonNone, Layer: model.LayerTCP, FaultDomain: model.FaultDomainTransport}}},
		Findings: []model.DiagnosticFinding{{FailureReason: model.FailureReasonTCPTimeout, Layer: model.LayerTCP, FaultDomain: model.FaultDomainTransport, ProbeNames: []string{"tcp"}, EvidenceIDs: []string{"tcp-1"}}},
	}
}

func canonicalTargetPortTime() (value time.Time) {
	return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
}
