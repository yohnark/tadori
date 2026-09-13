package web

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
	observationbuilder "github.com/yohnark/tadori/internal/observations"
)

func TestRepresentativeUIFixturesBuildDeterministicViews(t *testing.T) {
	fixtures := representativeUIFixtures()
	wantNames := []string{
		"complete-observable-path",
		"destination-reached-unobservable-intermediate",
		"icmp-unobservable-tcp-reaches",
		"tcp-port-comparison",
		"multiple-responders",
		"partial-unsupported-path",
		"failed-destination",
	}
	gotNames := make([]string, 0, len(fixtures))
	for name := range fixtures {
		gotNames = append(gotNames, name)
	}
	sort.Strings(gotNames)
	sort.Strings(wantNames)
	if fmt.Sprint(gotNames) != fmt.Sprint(wantNames) {
		t.Fatalf("fixture names = %v, want %v", gotNames, wantNames)
	}

	for _, name := range wantNames {
		fixture := fixtures[name]
		first, err := BuildDiagnosticView(fixture)
		if err != nil {
			t.Fatalf("BuildDiagnosticView(%s): %v", name, err)
		}
		second, err := BuildDiagnosticView(fixture)
		if err != nil {
			t.Fatalf("second BuildDiagnosticView(%s): %v", name, err)
		}
		firstJSON, _ := json.Marshal(first)
		secondJSON, _ := json.Marshal(second)
		if string(firstJSON) != string(secondJSON) {
			t.Fatalf("view for %s is not deterministic\nfirst: %s\nsecond: %s", name, firstJSON, secondJSON)
		}
		canonical, err := json.Marshal(fixture)
		if err != nil {
			t.Fatalf("marshal fixture %s: %v", name, err)
		}
		if first.CanonicalJSON != string(canonical) {
			t.Fatalf("canonical JSON for %s was not preserved", name)
		}
	}
}

func TestViewModelPreservesPathSemantics(t *testing.T) {
	fixtures := representativeUIFixtures()

	complete, _ := BuildDiagnosticView(fixtures["complete-observable-path"])
	if complete.Overall.Destination.State != "confirmed" {
		t.Fatalf("complete destination state = %q, want confirmed", complete.Overall.Destination.State)
	}
	if len(complete.Paths) != 2 || len(complete.Comparisons) != 1 {
		t.Fatalf("complete paths/comparisons = %d/%d, want 2/1", len(complete.Paths), len(complete.Comparisons))
	}

	longGap, _ := BuildDiagnosticView(fixtures["destination-reached-unobservable-intermediate"])
	if longGap.Overall.Destination.State != "confirmed" {
		t.Fatalf("destination with unobservable hops = %q, want confirmed", longGap.Overall.Destination.State)
	}
	for _, hop := range longGap.Paths[0].Hops {
		if hop.State == model.PathHopStateUnobservable && (hop.Tone == "negative" || hop.Detail == "") {
			t.Fatalf("unobservable hop was presented as failure: %#v", hop)
		}
	}
	var sawUnobservable, sawInferred bool
	for _, hop := range longGap.Paths[0].Hops {
		if hop.State == model.PathHopStateUnobservable {
			sawUnobservable = true
			if !containsText(hop.Detail, "not packet loss") {
				t.Fatalf("unobservable hop lacks semantic explanation: %#v", hop)
			}
		}
	}
	for _, segment := range longGap.Paths[0].Segments {
		if segment.Kind == model.PathSegmentInferred {
			sawInferred = true
		}
	}
	if !sawUnobservable || !sawInferred {
		t.Fatalf("long-gap fixture lost unobservable/inferred distinction: %#v", longGap.Paths[0])
	}

	protocols, _ := BuildDiagnosticView(fixtures["icmp-unobservable-tcp-reaches"])
	comparison := protocols.Comparisons[0]
	if !comparison.TCPDestinationConnected || comparison.ICMPDestinationReached {
		t.Fatalf("protocol comparison promoted the wrong signal: %#v", comparison)
	}
	if protocols.Overall.Destination.State != "confirmed" {
		t.Fatalf("TCP destination with ICMP gap = %q, want confirmed", protocols.Overall.Destination.State)
	}
	if !containsString(protocols.Overall.Destination.EvidenceIDs, "path/tcp") {
		t.Fatalf("confirmed destination lost TCP path evidence reference: %#v", protocols.Overall.Destination)
	}

	ports, _ := BuildDiagnosticView(fixtures["tcp-port-comparison"])
	if len(ports.Comparisons) != 2 {
		t.Fatalf("port comparison count = %d, want 2", len(ports.Comparisons))
	}
	if !ports.Comparisons[0].TCPDestinationConnected || ports.Comparisons[1].TCPDestinationConnected {
		t.Fatalf("TCP port comparison did not preserve success/failure: %#v", ports.Comparisons)
	}

	responders, _ := BuildDiagnosticView(fixtures["multiple-responders"])
	if len(responders.Paths[0].Hops[1].Responders) != 2 {
		t.Fatalf("multiple responders were collapsed: %#v", responders.Paths[0].Hops[1])
	}

	partial, _ := BuildDiagnosticView(fixtures["partial-unsupported-path"])
	if len(partial.Paths) != 2 || partial.Paths[0].ObservationStatus != model.PathObservationStatusUnsupported {
		t.Fatalf("partial/unsupported path state = %#v", partial.Paths)
	}
	partialEvidence := findEvidenceView(partial, "path/malformed")
	if partialEvidence.InspectorState != "available" || partialEvidence.Raw == nil {
		t.Fatalf("partial raw evidence was not retained: %#v", partialEvidence)
	}

	failed, _ := BuildDiagnosticView(fixtures["failed-destination"])
	if failed.Overall.Destination.State != "failed" {
		t.Fatalf("failed destination state = %q, want failed", failed.Overall.Destination.State)
	}
	if failed.Overall.DiagnosisState != "finding" {
		t.Fatalf("failed destination diagnosis state = %q, want finding", failed.Overall.DiagnosisState)
	}
	if failed.Paths[0].DestinationReached || failed.Paths[0].DestinationTCPConnected {
		t.Fatalf("failed path incorrectly confirmed destination: %#v", failed.Paths[0])
	}
}

func TestViewModelDoesNotInterpretUnknownEvidenceAsPath(t *testing.T) {
	target := fixtureTarget(443)
	fixture := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name:   "opaque",
			Target: target,
			Status: model.ProbeStatusPassed,
			Evidence: []model.Evidence{{
				ID:   "opaque-1",
				Kind: model.EvidenceKindUnknown,
				Raw:  json.RawMessage(`{"untrusted":"<b>not markup</b>"}`),
			}},
		}},
	}
	view, err := BuildDiagnosticView(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Paths) != 0 || len(view.Evidence) != 1 || !view.Evidence[0].Structured {
		t.Fatalf("opaque evidence was interpreted as path: %#v", view)
	}
}

func TestViewModelProjectsNameResolutionSeparatelyFromRawEvidence(t *testing.T) {
	target := fixtureTarget(445)
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name:   "dns",
			Target: target,
			Status: model.ProbeStatusPassed,
			// Probe-local name resolution is intentionally not the workbench source.
			// The canonical observation below is the only normal projection input.
			NameResolution: &model.NameResolutionObservation{RequestedName: "stale-probe-value", SelectedAddress: "192.0.2.99"},
			Evidence: []model.Evidence{{
				ID:   "dns/resolution",
				Kind: model.EvidenceKindDNSResolution,
				Raw:  json.RawMessage(`{"a":["10.30.14.22"]}`),
			}},
		}},
		Observations: model.Observations{NameResolution: model.NameResolutionObservation{
			RequestedName:       "fileserver.corp.example",
			CandidateNames:      []string{"fileserver", "fileserver.corp.example"},
			CandidateNamespaces: []string{"corp.example"},
			A:                   []string{"10.30.14.22"},
			SelectedAddress:     "10.30.14.22",
			Limitations:         []string{"resolver server was not exposed"},
			EffectivePath: &model.NameResolutionPath{
				State:       model.NameResolutionPathEffective,
				Mechanism:   model.NameResolutionMechanismDNS,
				Certainty:   model.NameResolutionCertaintyObserved,
				Provenance:  "native API",
				EvidenceIDs: []string{"dns/resolution"},
			},
			EvidenceIDs: []string{"dns/configuration", "dns/resolution"},
		}},
	}
	view, err := BuildDiagnosticView(report)
	if err != nil {
		t.Fatal(err)
	}
	if view.NameResolution == nil || view.NameResolution.RequestedName != "fileserver.corp.example" || view.NameResolution.SelectedAddress != "10.30.14.22" {
		t.Fatalf("name-resolution view = %#v", view.NameResolution)
	}
	if view.NameResolution.EffectivePath == nil || view.NameResolution.EffectivePath.Certainty != model.NameResolutionCertaintyObserved {
		t.Fatalf("effective path view = %#v", view.NameResolution.EffectivePath)
	}
	if len(view.Evidence) != 1 || string(view.Evidence[0].Raw) != `{"a":["10.30.14.22"]}` {
		t.Fatalf("raw evidence was not preserved: %#v", view.Evidence)
	}
}

func TestViewModelUsesCanonicalOperationalAndPathObservations(t *testing.T) {
	target := fixtureTarget(443)
	rawPath, err := json.Marshal(fixturePathObservation("raw", model.PathProtocolTCP, "198.51.100.9", 443, true, false, false))
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath := fixturePathObservation("canonical", model.PathProtocolTCP, "203.0.113.10", 443, true, true, true, fixtureHop(1, model.PathHopStateUnobservable))
	tested := model.Endpoint{Address: "203.0.113.10", Port: 443, Family: model.EndpointFamilyIPv4, Certainty: model.ObservationCertaintyObserved, EvidenceIDs: []string{"tcp/canonical"}}
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusComplete,
		Probes: []model.ProbeResult{{
			Name: "stale-path", Target: target, Status: model.ProbeStatusPassed,
			Evidence: []model.Evidence{{ID: "raw/path", Kind: model.EvidenceKindPathObservation, Raw: rawPath}},
		}},
		Observations: model.Observations{
			Endpoint: model.EndpointObservation{
				OriginalInput: target.OriginalInput, RequestedIdentity: target.RequestedIdentity,
				Service: target.Service, ApplicationProtocol: target.ApplicationProtocol,
				TransportProtocol: target.TransportProtocol, Port: target.Port,
				TestedEndpoint: &tested, Certainty: model.ObservationCertaintyObserved,
				EvidenceIDs: []string{"tcp/canonical"},
			},
			Transport: model.TransportObservation{
				Applicability: model.ObservationApplicabilityApplicable, Connected: true,
				ConnectionOutcome: model.TransportConnectionOutcomeConnected,
				ProbeNames:        []string{"tcp/canonical"}, EvidenceIDs: []string{"tcp/canonical"},
			},
			Security: model.SecurityObservation{
				Applicability: model.ObservationApplicabilityApplicable, HandshakeComplete: true,
				ProbeNames: []string{"tls/canonical"}, EvidenceIDs: []string{"tls/canonical"},
			},
			Application: model.ApplicationObservation{
				Applicability: model.ObservationApplicabilityApplicable, ResponseReceived: true,
				Result: model.HTTPResultSuccess, ProbeNames: []string{"http/canonical"}, EvidenceIDs: []string{"http/canonical"},
			},
			Paths:            []model.PathObservation{canonicalPath},
			PathProvenance:   []model.ObservationProvenance{{ProbeName: "canonical-path", Source: "normalized", EvidenceIDs: []string{"path/canonical"}}},
			PathCorrelations: []model.PathCorrelation{{Destination: "203.0.113.10", DestinationPort: 443, Observations: []model.PathObservation{canonicalPath}, TCPDestinationReached: true, TCPDestinationConnected: true}},
		},
	}

	view, err := BuildDiagnosticView(report)
	if err != nil {
		t.Fatal(err)
	}
	if view.Observations.Endpoint.TestedEndpoint == nil || view.Observations.Endpoint.TestedEndpoint.Address != "203.0.113.10" {
		t.Fatalf("canonical endpoint was not exposed: %#v", view.Observations.Endpoint)
	}
	if !view.Observations.Transport.Connected || !view.Observations.Security.HandshakeComplete || !view.Observations.Application.ResponseReceived {
		t.Fatalf("canonical operational observations were not retained: %#v", view.Observations)
	}
	if len(view.Paths) != 1 || view.Paths[0].Destination != "203.0.113.10" || !containsString(view.Paths[0].EvidenceIDs, "path/canonical") {
		t.Fatalf("path view was rebuilt from raw evidence: %#v", view.Paths)
	}
}

func TestViewModelProjectsNormalizedNetworkContext(t *testing.T) {
	target := fixtureTarget(443)
	context := model.NetworkContext{
		RequestedIdentity:          target.RequestedIdentity,
		SelectedDestinationAddress: "10.0.10.25",
		SelectedSourceInterface:    "Ethernet",
		SelectedSourceAddress:      "10.0.10.10",
		EffectiveRoute:             model.RouteDispositionOnLink,
		RoutePrefix:                "10.0.10.0/24",
		NextHop:                    "on-link",
		RouteMetric:                10,
		NetworkScope:               model.NetworkScopeSameLink,
		EvidenceIDs:                []string{"target-route-1", "interface-state-1"},
	}
	report := representativeReport(target, model.ReportStatusComplete)
	report.Observations.NetworkContext = context
	view, err := BuildDiagnosticView(report)
	if err != nil {
		t.Fatal(err)
	}
	if view.NetworkContext == nil || view.NetworkContext.NetworkScopeLabel != "Local link" || view.NetworkContext.EffectiveRouteLabel != "On-link" {
		t.Fatalf("network context view = %#v", view.NetworkContext)
	}
	if view.NetworkContext.SelectedSourceInterface != "Ethernet" || view.NetworkContext.RoutePrefix != "10.0.10.0/24" {
		t.Fatalf("network context fields were lost: %#v", view.NetworkContext)
	}
}

func TestViewModelUsesPacketEndpointConfirmationWithoutAddingPacketUI(t *testing.T) {
	target := fixtureTarget(443)
	flow := model.PacketFlowEvidence{
		SessionID: "session-1", ProbeID: "tcp", CorrelationID: "session-1/tcp", Target: target,
		CaptureStatus: model.PacketCaptureStatusAvailable, Outcome: model.PacketFlowOutcomeTCPSYNACK,
		Certainty: model.EvidenceCertaintyConfirmedEndpointResponse,
	}
	packetEvidence, err := model.PacketFlowEvidenceFor(flow)
	if err != nil {
		t.Fatalf("packet flow evidence: %v", err)
	}
	probe := fixtureProbeWithEvidence("tcp", target, model.ProbeStatusFailed, model.LayerTCP, model.FaultDomainTransport,
		model.Evidence{ID: "tcp-connection", Kind: model.EvidenceKindTCPConnection, Raw: json.RawMessage(`{"error":"timeout"}`)}, packetEvidence)
	report := representativeReport(target, model.ReportStatusComplete, probe)
	view, err := BuildDiagnosticView(report)
	if err != nil {
		t.Fatalf("BuildDiagnosticView: %v", err)
	}
	if view.Overall.Destination.State != "confirmed" {
		t.Fatalf("destination state = %q, want confirmed", view.Overall.Destination.State)
	}
	if findEvidenceView(view, packetEvidence.ID).Kind != model.EvidenceKindPacketFlow {
		t.Fatalf("packet flow was not retained in the evidence inspector: %#v", view.Evidence)
	}
	if len(view.Paths) != 0 {
		t.Fatalf("packet evidence created a packet/path UI: %#v", view.Paths)
	}
}

func findEvidenceView(view DiagnosticViewModel, id string) EvidenceView {
	for _, evidence := range view.Evidence {
		if evidence.ID == id {
			return evidence
		}
	}
	return EvidenceView{}
}

func containsText(value, want string) bool {
	return strings.Contains(value, want)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func representativeUIFixtures() map[string]model.DiagnosticReport {
	target := fixtureTarget(443)
	destination := "203.0.113.10"
	return map[string]model.DiagnosticReport{
		"complete-observable-path": representativeReport(target, model.ReportStatusComplete,
			fixturePathProbe("path", target,
				fixturePathObservation("path/icmp", model.PathProtocolICMP, destination, 443, false, true, true,
					fixtureHop(1, model.PathHopStateObserved, fixtureResponder("192.0.2.1", "icmp_time_exceeded")),
					fixtureHop(2, model.PathHopStateObserved, fixtureResponder("198.51.100.1", "icmp_time_exceeded")),
					fixtureHop(3, model.PathHopStateObserved, fixtureResponder(destination, "icmp_echo_reply"))),
				fixturePathObservation("path/tcp", model.PathProtocolTCP, destination, 443, true, true, true,
					fixtureHop(1, model.PathHopStateObserved, fixtureResponder("192.0.2.1", "tcp_syn_ack")),
					fixtureHop(2, model.PathHopStateObserved, fixtureResponder("198.51.100.1", "tcp_syn_ack")),
					fixtureHop(3, model.PathHopStateObserved, fixtureResponder(destination, "tcp_connected")))),
		),
		"destination-reached-unobservable-intermediate": representativeReport(target, model.ReportStatusComplete,
			fixturePathProbe("path", target,
				fixturePathObservation("path/tcp", model.PathProtocolTCP, destination, 443, true, true, true,
					fixtureHop(1, model.PathHopStateObserved, fixtureResponder("192.0.2.1", "tcp_time_exceeded")),
					fixtureHop(2, model.PathHopStateUnobservable),
					fixtureHop(3, model.PathHopStateUnobservable),
					fixtureHop(4, model.PathHopStateUnobservable),
					fixtureHop(5, model.PathHopStateObserved, fixtureResponder(destination, "tcp_connected")))),
		),
		"icmp-unobservable-tcp-reaches": representativeReport(target, model.ReportStatusComplete,
			fixturePathProbe("path", target,
				fixturePathObservation("path/icmp", model.PathProtocolICMP, destination, 443, false, false, true,
					fixtureHop(1, model.PathHopStateUnobservable),
					fixtureHop(2, model.PathHopStateUnobservable),
					fixtureHop(3, model.PathHopStateUnobservable)),
				fixturePathObservation("path/tcp", model.PathProtocolTCP, destination, 443, true, true, true,
					fixtureHop(1, model.PathHopStateUnobservable),
					fixtureHop(2, model.PathHopStateObserved, fixtureResponder(destination, "tcp_connected")))),
		),
		"tcp-port-comparison": representativeReport(target, model.ReportStatusComplete,
			fixturePathProbe("path-ports", target,
				fixturePathObservation("path/tcp-443", model.PathProtocolTCP, destination, 443, true, true, true,
					fixtureHop(1, model.PathHopStateUnobservable),
					fixtureHop(2, model.PathHopStateObserved, fixtureResponder(destination, "tcp_connected")))),
			fixturePathProbe("path-alt-port", fixtureTarget(8443),
				fixturePathObservation("path/tcp-8443", model.PathProtocolTCP, destination, 8443, true, true, false,
					fixtureHop(1, model.PathHopStateObserved, fixtureResponder("192.0.2.1", "tcp_time_exceeded")),
					fixtureHop(2, model.PathHopStateObserved, fixtureResponder(destination, "tcp_refused")))),
		),
		"multiple-responders": representativeReport(target, model.ReportStatusComplete,
			fixturePathProbe("path-ecmp", target,
				fixturePathObservation("path/icmp", model.PathProtocolICMP, destination, 443, false, true, true,
					fixtureHop(1, model.PathHopStateObserved, fixtureResponder("192.0.2.1", "icmp_time_exceeded")),
					fixtureHop(2, model.PathHopStateObserved,
						fixtureResponder("198.51.100.1", "icmp_time_exceeded"),
						fixtureResponder("198.51.100.2", "icmp_time_exceeded")),
					fixtureHop(3, model.PathHopStateObserved, fixtureResponder(destination, "icmp_echo_reply")))),
		),
		"partial-unsupported-path": representativeReport(target, model.ReportStatusIncomplete,
			fixturePathProbe("path-partial", target,
				fixturePathObservationWithStatus("path/icmp", model.PathProtocolICMP, destination, 443, false, false, model.PathObservationStatusUnsupported),
				fixturePathObservation("path/tcp", model.PathProtocolTCP, destination, 443, true, false, false,
					fixtureHop(1, model.PathHopStateUnobservable))),
			fixtureProbeWithEvidence("path-malformed", target, model.ProbeStatusPassed, model.LayerNetwork, model.FaultDomainNetwork,
				model.Evidence{ID: "path/malformed", Kind: model.EvidenceKindPathObservation, Raw: json.RawMessage(`"not-a-path"`)}),
		),
		"failed-destination": representativeFailedReport(target,
			fixturePathProbe("path-failed", target,
				fixturePathObservation("path/tcp", model.PathProtocolTCP, destination, 443, true, false, false,
					fixtureHop(1, model.PathHopStateUnobservable),
					fixtureHop(2, model.PathHopStateUnobservable))),
			fixtureProbeWithEvidence("tcp", target, model.ProbeStatusFailed, model.LayerTCP, model.FaultDomainTransport,
				model.Evidence{ID: "tcp-1", Kind: model.EvidenceKindTCPConnection, Raw: json.RawMessage(`{"error":"timeout"}`)}),
		),
	}
}

func fixtureTarget(port uint16) model.Target {
	target, err := model.ParseTarget(model.TargetIntent{Input: fmt.Sprintf("https://203.0.113.10:%d/health", port)})
	if err != nil {
		panic(err)
	}
	return target
}

func representativeReport(target model.Target, status model.ReportStatus, probes ...model.ProbeResult) model.DiagnosticReport {
	return model.DiagnosticReport{SchemaVersion: model.DiagnosticSchemaVersion, Target: target, Status: status, Probes: probes, Observations: observationbuilder.Build(target, probes)}
}

func representativeFailedReport(target model.Target, probes ...model.ProbeResult) model.DiagnosticReport {
	report := representativeReport(target, model.ReportStatusComplete, probes...)
	report.Findings = []model.DiagnosticFinding{{
		FailureReason: model.FailureReasonTCPTimeout,
		Layer:         model.LayerTCP,
		FaultDomain:   model.FaultDomainTransport,
		ProbeNames:    []string{"tcp"},
		EvidenceIDs:   []string{"tcp-1"},
	}}
	return report
}

func fixturePathProbe(name string, target model.Target, observations ...model.PathObservation) model.ProbeResult {
	evidence := make([]model.Evidence, 0, len(observations))
	for _, observation := range observations {
		raw, _ := json.Marshal(observation)
		evidence = append(evidence, model.Evidence{ID: fixtureEvidenceID(name, observation), Kind: model.EvidenceKindPathObservation, Source: "fixture-path-adapter", Raw: raw})
	}
	return fixtureProbe(name, target, model.ProbeStatusPassed, model.LayerTCP, model.FaultDomainNetwork, evidence...)
}

func fixtureProbeWithEvidence(name string, target model.Target, status model.ProbeStatus, layer model.Layer, domain model.FaultDomain, evidence ...model.Evidence) model.ProbeResult {
	return fixtureProbe(name, target, status, layer, domain, evidence...)
}

func fixtureProbe(name string, target model.Target, status model.ProbeStatus, layer model.Layer, domain model.FaultDomain, evidence ...model.Evidence) model.ProbeResult {
	reason := model.FailureReasonNone
	if status == model.ProbeStatusFailed {
		reason = model.FailureReasonTCPTimeout
	}
	return model.ProbeResult{Name: name, Target: target, Status: status, Evidence: evidence, Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain}}
}

func fixturePathObservation(id string, protocol model.PathProtocol, destination string, port uint16, portAware, reached, connected bool, hops ...model.PathHop) model.PathObservation {
	return fixturePathObservationWithStatusAndID(id, protocol, destination, port, portAware, reached, connected, model.PathObservationStatusObserved, hops...)
}

func fixturePathObservationWithStatus(id string, protocol model.PathProtocol, destination string, port uint16, portAware, reached bool, status model.PathObservationStatus) model.PathObservation {
	return fixturePathObservationWithStatusAndID(id, protocol, destination, port, portAware, reached, false, status)
}

func fixturePathObservationWithStatusAndID(_ string, protocol model.PathProtocol, destination string, port uint16, portAware, reached, connected bool, status model.PathObservationStatus, hops ...model.PathHop) model.PathObservation {
	segments := make([]model.PathSegment, 0, len(hops))
	for _, hop := range hops {
		kind := model.PathSegmentUnobservable
		if hop.State == model.PathHopStateObserved {
			kind = model.PathSegmentObservedResponder
		}
		segments = append(segments, model.PathSegment{Kind: kind, FromTTL: hop.TTL, ToTTL: hop.TTL, Responders: append([]model.PathResponder(nil), hop.Responders...)})
	}
	var previousObserved uint8
	for _, hop := range hops {
		if hop.State != model.PathHopStateObserved || len(hop.Responders) == 0 {
			continue
		}
		if previousObserved != 0 && hop.TTL-previousObserved > 1 {
			segments = append(segments, model.PathSegment{Kind: model.PathSegmentInferred, FromTTL: previousObserved, ToTTL: hop.TTL})
		}
		previousObserved = hop.TTL
	}
	sort.SliceStable(segments, func(i, j int) bool {
		if segments[i].FromTTL != segments[j].FromTTL {
			return segments[i].FromTTL < segments[j].FromTTL
		}
		if segments[i].ToTTL != segments[j].ToTTL {
			return segments[i].ToTTL < segments[j].ToTTL
		}
		return segments[i].Kind < segments[j].Kind
	})
	return model.PathObservation{Status: status, Protocol: protocol, Destination: destination, DestinationPort: port, PortAware: portAware, MaxTTL: uint8(len(hops)), AttemptsPerTTL: 1, Hops: hops, Segments: segments, DestinationReached: reached, DestinationTCPConnected: connected}
}

func fixtureEvidenceID(probeName string, observation model.PathObservation) string {
	if observation.Protocol == model.PathProtocolICMP {
		return "path/icmp"
	}
	if observation.DestinationPort == 8443 {
		return "path/tcp-8443"
	}
	if probeName == "path-ports" {
		return "path/tcp-443"
	}
	return "path/tcp"
}

func fixtureHop(ttl uint8, state model.PathHopState, responders ...model.PathResponder) model.PathHop {
	return model.PathHop{TTL: ttl, State: state, Attempts: 2, Responders: responders}
}

func fixtureResponder(address, response string) model.PathResponder {
	return model.PathResponder{Address: address, RTTMS: 4, Response: response}
}
