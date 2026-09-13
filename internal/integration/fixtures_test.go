package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/diagnosis"
	"github.com/yohnark/tadori/internal/model"
	observationbuilder "github.com/yohnark/tadori/internal/observations"
	"github.com/yohnark/tadori/internal/report"
	"github.com/yohnark/tadori/internal/web"
)

// These fixtures are deliberately process-local. They represent the complete
// report boundary after collection, so the regression suite can exercise
// diagnosis, canonical JSON, terminal rendering, and the UI projection on
// every supported runner without depending on a DNS server or public host.
var fixtureTime = time.Date(2026, time.September, 13, 1, 2, 3, 0, time.UTC)

type regressionFixture struct {
	name              string
	report            model.DiagnosticReport
	wantStatus        model.ReportStatus
	wantFinding       model.FailureReason
	wantService       model.ServiceProfileID
	wantDestination   string
	wantNetworkScope  model.NetworkScope
	wantResolution    bool
	wantPathEvidence  int
	wantUnsupported   bool
	wantCanonicalKeys []string
}

func regressionFixtures() []regressionFixture {
	return []regressionFixture{
		httpsSuccessFixture(),
		localPrivateOnLinkFixture(),
		splitDNSNRPTFixture(),
		unobservablePathFixture(),
		proxyPolicyPartialFixture(),
		serviceAwareSerializationFixture(),
	}
}

func TestRegressionFixturesAreCompleteDeterministicReports(t *testing.T) {
	fixtures := regressionFixtures()
	if len(fixtures) != 6 {
		t.Fatalf("fixture count = %d, want six acceptance scenarios", len(fixtures))
	}

	seen := make(map[string]bool, len(fixtures))
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			if seen[fixture.name] {
				t.Fatalf("fixture name %q is duplicated", fixture.name)
			}
			seen[fixture.name] = true
			if fixture.report.SchemaVersion != model.DiagnosticSchemaVersion {
				t.Fatalf("schema version = %q, want %q", fixture.report.SchemaVersion, model.DiagnosticSchemaVersion)
			}
			if fixture.report.SessionID == "" || fixture.report.StartedAt == nil || fixture.report.CompletedAt == nil {
				t.Fatal("complete fixture is missing session or report timing")
			}
			if fixture.report.Status != fixture.wantStatus {
				t.Fatalf("report status = %q, want %q", fixture.report.Status, fixture.wantStatus)
			}
			if fixture.wantService != "" && fixture.report.Target.Service.ID != fixture.wantService {
				t.Fatalf("service = %q, want %q", fixture.report.Target.Service.ID, fixture.wantService)
			}

			first := canonicalReport(t, fixture.report)
			second := canonicalReport(t, fixture.report)
			if !bytes.Equal(first, second) {
				t.Fatal("canonical report changed between identical serializations")
			}
			var decoded model.DiagnosticReport
			if err := json.Unmarshal(first, &decoded); err != nil {
				t.Fatalf("canonical report is not decodable: %v", err)
			}
			if roundTripped := canonicalReport(t, decoded); !bytes.Equal(roundTripped, first) {
				t.Fatalf("canonical report did not round-trip\n got: %s\nwant: %s", roundTripped, first)
			}

			view, err := web.BuildDiagnosticView(fixture.report)
			if err != nil {
				t.Fatalf("BuildDiagnosticView: %v", err)
			}
			if view.CanonicalJSON != string(first) {
				t.Fatal("UI projection did not retain the canonical report")
			}
			if view.Report.Status != fixture.wantStatus || len(view.Probes) != len(fixture.report.Probes) {
				t.Fatalf("view lost report contract: status=%q probes=%d", view.Report.Status, len(view.Probes))
			}
			if fixture.wantDestination != "" && view.Overall.Destination.State != fixture.wantDestination {
				t.Fatalf("destination state = %q, want %q", view.Overall.Destination.State, fixture.wantDestination)
			}
			if fixture.wantNetworkScope != "" {
				if view.NetworkContext == nil || view.NetworkContext.NetworkScope != fixture.wantNetworkScope {
					t.Fatalf("network scope = %#v, want %q", view.NetworkContext, fixture.wantNetworkScope)
				}
			}
			if fixture.wantResolution && view.NameResolution == nil {
				t.Fatal("name-resolution observation was lost in UI projection")
			}
			if len(view.Paths) != fixture.wantPathEvidence {
				t.Fatalf("path views = %d, want %d", len(view.Paths), fixture.wantPathEvidence)
			}
			if fixture.wantUnsupported && !hasUnsupportedProbe(fixture.report) {
				t.Fatal("fixture does not retain its unsupported lane")
			}
			for _, key := range fixture.wantCanonicalKeys {
				if !bytes.Contains(first, []byte(key)) {
					t.Fatalf("canonical report is missing %q", key)
				}
			}

			human := report.RenderHuman(fixture.report)
			for _, required := range []string{"Status:", "Target:", "Probes:", "Evidence:"} {
				if !strings.Contains(human, required) {
					t.Fatalf("human report is missing %q:\n%s", required, human)
				}
			}
		})
	}
}

func TestRegressionFixturesApplyDiagnosisAtTheReportBoundary(t *testing.T) {
	for _, fixture := range regressionFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			got := diagnosis.DiagnoseReport(fixture.report)
			if !reflect.DeepEqual(got.Target, fixture.report.Target) {
				t.Fatal("diagnosis changed the canonical target")
			}
			if !reflect.DeepEqual(got.Probes, fixture.report.Probes) {
				t.Fatal("diagnosis changed raw probe evidence")
			}
			if fixture.wantFinding == model.FailureReasonNone {
				if len(got.Findings) != 0 {
					t.Fatalf("findings = %#v, want none", got.Findings)
				}
				return
			}
			if len(got.Findings) == 0 || got.Findings[0].FailureReason != fixture.wantFinding {
				t.Fatalf("findings = %#v, want primary reason %q", got.Findings, fixture.wantFinding)
			}
		})
	}
}

func TestHTTPSuccessFixtureKeepsServiceAndEndpointEvidenceSeparate(t *testing.T) {
	fixture := httpsSuccessFixture()
	if fixture.report.Target.Service.ID != model.ServiceProfileHTTPS {
		t.Fatalf("service = %q, want HTTPS", fixture.report.Target.Service.ID)
	}
	if fixture.report.Target.SelectedEndpoint == nil || fixture.report.Target.TestedEndpoint == nil {
		t.Fatal("HTTPS fixture lost selected/tested endpoint lifecycle facts")
	}
	if fixture.report.Target.SelectedEndpoint.Address != "198.51.100.44" || fixture.report.Target.TestedEndpoint.Port != 443 {
		t.Fatalf("endpoint lifecycle = %#v/%#v", fixture.report.Target.SelectedEndpoint, fixture.report.Target.TestedEndpoint)
	}
	view, err := web.BuildDiagnosticView(fixture.report)
	if err != nil {
		t.Fatal(err)
	}
	if view.Overall.Destination.State != "confirmed" || view.Overall.DiagnosisState != "clear" {
		t.Fatalf("HTTPS view = %#v", view.Overall)
	}
	if !strings.Contains(report.RenderHuman(fixture.report), "Service: HTTPS") {
		t.Fatal("human report omitted the service-aware HTTPS label")
	}
}

func TestLocalPrivateOnLinkFixtureDoesNotInventGatewayFailure(t *testing.T) {
	fixture := localPrivateOnLinkFixture()
	if fixture.report.Target.NetworkContext == nil || fixture.report.Target.NetworkContext.EffectiveRoute != model.RouteDispositionOnLink {
		t.Fatalf("network context = %#v", fixture.report.Target.NetworkContext)
	}
	for _, finding := range fixture.report.Findings {
		if finding.FailureReason == model.FailureReasonGatewayUnreachable {
			t.Fatalf("on-link route produced gateway finding: %#v", fixture.report.Findings)
		}
	}
	view, err := web.BuildDiagnosticView(fixture.report)
	if err != nil {
		t.Fatal(err)
	}
	if view.NetworkContext.EffectiveRouteLabel != "On-link" || view.Overall.Destination.State != "confirmed" {
		t.Fatalf("on-link view = %#v / %#v", view.NetworkContext, view.Overall.Destination)
	}
}

func TestSplitDNSNRPTFixtureKeepsPolicyCandidateDistinctFromEffectivePath(t *testing.T) {
	fixture := splitDNSNRPTFixture()
	observation := fixture.report.Probes[0].NameResolution
	if observation == nil || observation.EffectivePath == nil {
		t.Fatal("split-DNS fixture has no effective path")
	}
	if observation.EffectivePath.Certainty != model.NameResolutionCertaintyObserved || observation.EffectivePath.Resolver != "" {
		t.Fatalf("effective path overclaims resolver provenance: %#v", observation.EffectivePath)
	}
	if len(model.NameResolutionPoliciesForNames(observation.CandidateNames, []model.NameResolutionPolicyRule{
		{Namespaces: []string{"corp.example.test"}, RuleID: "corp", Source: "NRPT"},
		{Namespaces: []string{"example.test"}, RuleID: "broad", Source: "NRPT"},
	})) != 2 {
		t.Fatal("NRPT candidate matching did not retain both applicable rules")
	}
	view, err := web.BuildDiagnosticView(fixture.report)
	if err != nil {
		t.Fatal(err)
	}
	if view.NameResolution.EffectivePath == nil || len(view.NameResolution.Paths) != 3 {
		t.Fatalf("name-resolution view = %#v", view.NameResolution)
	}
	if view.NameResolution.EffectivePath.Certainty != model.NameResolutionCertaintyObserved {
		t.Fatalf("effective path certainty = %q", view.NameResolution.EffectivePath.Certainty)
	}
}

func TestUnobservablePathFixtureConfirmsDestination(t *testing.T) {
	fixture := unobservablePathFixture()
	view, err := web.BuildDiagnosticView(fixture.report)
	if err != nil {
		t.Fatal(err)
	}
	if view.Overall.Destination.State != "confirmed" {
		t.Fatalf("destination = %#v, want confirmed", view.Overall.Destination)
	}
	if len(view.Paths) != 1 || view.Paths[0].Hops[1].State != model.PathHopStateUnobservable {
		t.Fatalf("path view did not preserve the unobservable segment: %#v", view.Paths)
	}
	if view.Paths[0].DestinationTCPConnected != true {
		t.Fatal("path view lost TCP endpoint confirmation")
	}
}

func TestProxyPolicyPartialFixtureRetainsUnsupportedEvidence(t *testing.T) {
	fixture := proxyPolicyPartialFixture()
	if fixture.report.Status != model.ReportStatusIncomplete || fixture.report.Findings[0].FailureReason != model.FailureReasonProxyConfigurationDivergence {
		t.Fatalf("proxy/policy report = %#v", fixture.report)
	}
	if !hasUnsupportedProbe(fixture.report) {
		t.Fatal("unsupported policy lane was not represented")
	}
	view, err := web.BuildDiagnosticView(fixture.report)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Findings) == 0 || view.Findings[0].FailureReason != model.FailureReasonProxyConfigurationDivergence {
		t.Fatalf("proxy finding view = %#v", view.Findings)
	}
	if len(view.Evidence) < 3 {
		t.Fatalf("proxy evidence count = %d, want configuration and policy evidence", len(view.Evidence))
	}
}

func TestServiceAwareTargetSerializationPreservesProfileAndPort(t *testing.T) {
	fixture := serviceAwareSerializationFixture()
	encoded := canonicalReport(t, fixture.report)
	var decoded model.DiagnosticReport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Target.Service.ID != model.ServiceProfileSMB || decoded.Target.Port != 1445 || decoded.Target.ApplicationProtocol != model.ApplicationProtocolSMB {
		t.Fatalf("decoded service target = %#v", decoded.Target)
	}
	if decoded.Target.OriginalInput != "fileserver01" {
		t.Fatalf("decoded original input = %q", decoded.Target.OriginalInput)
	}
	if !strings.Contains(report.RenderHuman(decoded), "Service: File sharing (SMB)") {
		t.Fatal("human serialization omitted service label")
	}
}

func httpsSuccessFixture() regressionFixture {
	target := targetFrom("https://service.example.test/health")
	target.ResolvedAddresses = []string{"198.51.100.44"}
	target.SelectedEndpoint = &model.Endpoint{Address: "198.51.100.44", Port: 443}
	target.TestedEndpoint = &model.Endpoint{Address: "198.51.100.44", Port: 443}
	resolution := model.NameResolutionObservation{
		RequestedName:   "service.example.test",
		CandidateNames:  []string{"service.example.test"},
		A:               []string{"198.51.100.44"},
		SelectedAddress: "198.51.100.44",
		SelectedFamily:  "ipv4",
		EffectivePath: &model.NameResolutionPath{
			State:       model.NameResolutionPathEffective,
			Mechanism:   model.NameResolutionMechanismDNS,
			A:           []string{"198.51.100.44"},
			Certainty:   model.NameResolutionCertaintyObserved,
			Provenance:  "deterministic resolver fixture",
			EvidenceIDs: []string{"https/dns-resolution"},
		},
		EvidenceIDs: []string{"https/dns-resolution"},
	}
	probes := []model.ProbeResult{
		passProbe("dns", target, model.LayerDNS, model.FaultDomainDNS, resolutionEvidence("https/dns-resolution", resolution), resolution),
		passProbe("tcp", target, model.LayerTCP, model.FaultDomainTransport, fixtureEvidence("https/tcp", model.EvidenceKindTCPConnection, map[string]any{"address": "198.51.100.44", "port": 443, "connected": true})),
		passProbe("tls", target, model.LayerTLS, model.FaultDomainTLS, fixtureEvidence("https/tls", model.EvidenceKindTLSHandshake, map[string]any{"version": "TLS1.3", "verified": true})),
		passProbe("http", target, model.LayerHTTP, model.FaultDomainHTTP, fixtureEvidence("https/http", model.EvidenceKindHTTPResponse, map[string]any{"status": 200, "resource": "/health"})),
	}
	return fixtureWithReport("https-success", target, model.ReportStatusComplete, probes, model.FailureReasonNone, model.ServiceProfileHTTPS, "confirmed", "", true, 0, false,
		[]string{`"id":"https"`, `"kind":"http_response"`})
}

func localPrivateOnLinkFixture() regressionFixture {
	target := targetFrom("https://10.20.30.40/health")
	target.ResolvedAddresses = []string{"10.20.30.40"}
	target.SelectedEndpoint = &model.Endpoint{Address: "10.20.30.40", Port: 443}
	target.TestedEndpoint = &model.Endpoint{Address: "10.20.30.40", Port: 443}
	target.NetworkContext = &model.NetworkContext{
		RequestedIdentity:          "10.20.30.40",
		SelectedDestinationAddress: "10.20.30.40",
		SelectedSourceInterface:    "Ethernet",
		SelectedSourceAddress:      "10.20.30.10",
		EffectiveRoute:             model.RouteDispositionOnLink,
		RoutePrefix:                "10.20.30.0/24",
		NextHop:                    "on-link",
		RouteMetric:                25,
		NetworkScope:               model.NetworkScopeSameLink,
		Neighbor: &model.NeighborEvidence{
			Observation: model.NeighborObservationObserved,
			Source:      "deterministic neighbor fixture",
			Entries:     []model.NeighborEntry{{Address: "10.20.30.40", Interface: "Ethernet", State: "reachable"}},
		},
		EvidenceIDs: []string{"local/route", "local/neighbor"},
	}
	probes := []model.ProbeResult{
		passProbe("interface_state", target, model.LayerInterface, model.FaultDomainLocal, fixtureEvidence("local/interface", model.EvidenceKindInterfaceState, map[string]any{"interface": "Ethernet", "operational": true})),
		passProbe("target_route", target, model.LayerRoute, model.FaultDomainRouting, fixtureEvidence("local/route", model.EvidenceKindRoute, map[string]any{"destination": "10.20.30.40", "route_prefix": "10.20.30.0/24", "effective_route": "on_link", "gateway_tested": false})),
		passProbe("neighbor", target, model.LayerNetwork, model.FaultDomainNetwork, fixtureEvidence("local/neighbor", model.EvidenceKindGatewayReachability, map[string]any{"observation": "observed", "address": "10.20.30.40"})),
		skippedProbe("gateway_reachability", target, model.LayerGateway, model.FaultDomainGateway),
		passProbe("tcp", target, model.LayerTCP, model.FaultDomainTransport, fixtureEvidence("local/tcp", model.EvidenceKindTCPConnection, map[string]any{"address": "10.20.30.40", "port": 443, "connected": true})),
	}
	return fixtureWithReport("local-private-on-link", target, model.ReportStatusComplete, probes, model.FailureReasonNone, model.ServiceProfileHTTPS, "confirmed", model.NetworkScopeSameLink, false, 0, true,
		[]string{`"effective_route":"on_link"`, `"network_scope":"same_link"`})
}

func splitDNSNRPTFixture() regressionFixture {
	target := targetFrom("https://printer.corp.example.test/health")
	target.ResolvedAddresses = []string{"10.44.5.18"}
	target.SelectedEndpoint = &model.Endpoint{Address: "10.44.5.18", Port: 443}
	target.TestedEndpoint = &model.Endpoint{Address: "10.44.5.18", Port: 443}
	effective := model.NameResolutionPath{
		State:       model.NameResolutionPathEffective,
		Mechanism:   model.NameResolutionMechanismDNS,
		Namespace:   "corp.example.test",
		A:           []string{"10.44.5.18"},
		Certainty:   model.NameResolutionCertaintyObserved,
		Provenance:  "Windows DNS client result",
		EvidenceIDs: []string{"split-dns/resolution"},
	}
	resolution := model.NameResolutionObservation{
		RequestedName:       "printer.corp.example.test",
		CandidateNames:      []string{"printer", "printer.corp.example.test"},
		CandidateSuffixes:   []string{"corp.example.test", "example.test"},
		CandidateNamespaces: []string{"corp.example.test"},
		Paths: []model.NameResolutionPath{
			{State: model.NameResolutionPathConfiguredCandidate, Mechanism: model.NameResolutionMechanismDNS, Resolver: "10.44.5.53", Namespace: "corp.example.test", PolicySource: "interface configuration", Certainty: model.NameResolutionCertaintyConfigured, Provenance: "configuration only", EvidenceIDs: []string{"split-dns/configuration"}},
			{State: model.NameResolutionPathPolicyCandidate, Mechanism: model.NameResolutionMechanismDNS, Namespaces: []string{"corp.example.test"}, PolicySource: "NRPT", PolicyRule: "corp-rule", Certainty: model.NameResolutionCertaintyConfigured, Provenance: "policy configuration", EvidenceIDs: []string{"split-dns/configuration"}},
			effective,
		},
		EffectivePath:   &effective,
		A:               []string{"10.44.5.18"},
		SelectedAddress: "10.44.5.18",
		SelectedFamily:  "ipv4",
		Limitations:     []string{"resolver identity is not exposed by the synchronous result"},
		EvidenceIDs:     []string{"split-dns/configuration", "split-dns/resolution"},
	}
	dnsProbe := passProbe("dns", target, model.LayerDNS, model.FaultDomainDNS,
		fixtureEvidence("split-dns/configuration", model.EvidenceKindDNSConfiguration, map[string]any{
			"search_suffixes": []string{"corp.example.test", "example.test"},
			"nrpt_rules":      []map[string]any{{"namespace": "corp.example.test", "rule_id": "corp-rule", "name_servers": []string{"10.44.5.53"}}, {"namespace": "example.test", "rule_id": "broad-rule"}},
		}), resolution)
	dnsProbe.Evidence = append(dnsProbe.Evidence, fixtureEvidence("split-dns/resolution", model.EvidenceKindDNSResolution, map[string]any{"name": "printer.corp.example.test", "a": []string{"10.44.5.18"}}))
	probes := []model.ProbeResult{
		dnsProbe,
		passProbe("tcp", target, model.LayerTCP, model.FaultDomainTransport, fixtureEvidence("split-dns/tcp", model.EvidenceKindTCPConnection, map[string]any{"address": "10.44.5.18", "port": 443, "connected": true})),
	}
	return fixtureWithReport("split-dns-nrpt", target, model.ReportStatusComplete, probes, model.FailureReasonNone, model.ServiceProfileHTTPS, "confirmed", "", true, 0, false,
		[]string{`"state":"policy_candidate"`, `"policy_source":"NRPT"`, `"selected_address":"10.44.5.18"`})
}

func unobservablePathFixture() regressionFixture {
	target := targetFrom("https://203.0.113.45:8443/health")
	target.ResolvedAddresses = []string{"203.0.113.45"}
	target.SelectedEndpoint = &model.Endpoint{Address: "203.0.113.45", Port: 8443}
	target.TestedEndpoint = &model.Endpoint{Address: "203.0.113.45", Port: 8443}
	observation := model.PathObservation{
		Status:          model.PathObservationStatusObserved,
		Protocol:        model.PathProtocolTCP,
		Destination:     "203.0.113.45",
		DestinationPort: 8443,
		PortAware:       true,
		MaxTTL:          5,
		AttemptsPerTTL:  2,
		Hops: []model.PathHop{
			{TTL: 1, State: model.PathHopStateObserved, Attempts: 2, Responders: []model.PathResponder{{Address: "192.0.2.1", RTTMS: 4, Response: "tcp_time_exceeded"}}},
			{TTL: 2, State: model.PathHopStateUnobservable, Attempts: 2},
			{TTL: 3, State: model.PathHopStateUnobservable, Attempts: 2},
			{TTL: 4, State: model.PathHopStateUnobservable, Attempts: 2},
			{TTL: 5, State: model.PathHopStateObserved, Attempts: 2, Responders: []model.PathResponder{{Address: "203.0.113.45", RTTMS: 18, Response: "tcp_connected", DestinationReached: true}}},
		},
		Segments: []model.PathSegment{
			{Kind: model.PathSegmentObservedResponder, FromTTL: 1, ToTTL: 1, Responders: []model.PathResponder{{Address: "192.0.2.1", RTTMS: 4, Response: "tcp_time_exceeded"}}},
			{Kind: model.PathSegmentUnobservable, FromTTL: 2, ToTTL: 4},
			{Kind: model.PathSegmentObservedResponder, FromTTL: 5, ToTTL: 5, Responders: []model.PathResponder{{Address: "203.0.113.45", RTTMS: 18, Response: "tcp_connected", DestinationReached: true}}},
		},
		DestinationReached:      true,
		DestinationTCPConnected: true,
	}
	rawPath, err := json.Marshal(observation)
	if err != nil {
		panic(err)
	}
	pathEvidence := model.Evidence{ID: "path/tcp-destination", Kind: model.EvidenceKindPathObservation, Source: "deterministic path fixture", CapturedAt: fixtureTimePointer(), Raw: rawPath}
	probes := []model.ProbeResult{
		failedProbe("tcp", target, model.LayerTCP, model.FaultDomainTransport, model.FailureReasonTCPTimeout, fixtureEvidence("path/tcp-timeout", model.EvidenceKindTCPConnection, map[string]any{"error": "bounded direct probe timeout"})),
		passProbe("path", target, model.LayerNetwork, model.FaultDomainNetwork, pathEvidence),
	}
	return fixtureWithReport("path-unobservable-destination-confirmed", target, model.ReportStatusComplete, probes, model.FailureReasonNone, model.ServiceProfileHTTPS, "confirmed", "", false, 1, false,
		[]string{`"kind":"path_observation"`, `"destination_tcp_connected":true`})
}

func proxyPolicyPartialFixture() regressionFixture {
	target := targetFrom("https://restricted.corp.example.test/health")
	resolution := model.NameResolutionObservation{RequestedName: "restricted.corp.example.test", CandidateNames: []string{"restricted.corp.example.test"}, A: []string{"10.50.8.20"}, SelectedAddress: "10.50.8.20", EvidenceIDs: []string{"proxy/dns"}}
	probes := []model.ProbeResult{
		passProbe("dns", target, model.LayerDNS, model.FaultDomainDNS, resolutionEvidence("proxy/dns", resolution), resolution),
		failedProbe("proxy_discovery", target, model.LayerProxy, model.FaultDomainProxy, model.FailureReasonProxyConfigurationDivergence,
			fixtureEvidence("proxy/configuration", model.EvidenceKindProxyConfiguration, map[string]any{
				"winhttp": map[string]any{"available": true, "mode": "proxy", "endpoint": "proxy.service.example.test:8080"},
				"wininet": map[string]any{"available": true, "mode": "proxy", "endpoint": "proxy.browser.example.test:8080"},
				"pac":     map[string]any{"configured": true, "executed": false, "reason": "bounded diagnostic does not execute PAC"},
			}),
			fixtureEvidence("proxy/policy-comparison", model.EvidenceKindRouteComparison, map[string]any{"application_path": "direct", "browser_path": "proxy", "comparison": "policy-dependent"})),
		skippedProbe("windows_enterprise", target, model.LayerNetwork, model.FaultDomainPolicy),
		failedProbe("http", target, model.LayerHTTP, model.FaultDomainHTTP, model.FailureReasonHTTPFailure, fixtureEvidence("proxy/http", model.EvidenceKindHTTPResponse, map[string]any{"attempted": false, "reason": "policy path unavailable"})),
	}
	return fixtureWithReport("proxy-policy-partial", target, model.ReportStatusIncomplete, probes, model.FailureReasonProxyConfigurationDivergence, model.ServiceProfileHTTPS, "unconfirmed", "", true, 0, true,
		[]string{`"failure_reason":"proxy_configuration_divergence"`, `"status":"skipped"`, `"kind":"proxy_configuration"`})
}

func serviceAwareSerializationFixture() regressionFixture {
	port := uint16(1445)
	target := targetFromIntent(model.TargetIntent{Input: "fileserver01", Service: model.ServiceProfileSMB, Port: &port})
	target.ResolvedAddresses = []string{"10.60.1.25"}
	target.SelectedEndpoint = &model.Endpoint{Address: "10.60.1.25", Port: 1445}
	target.TestedEndpoint = &model.Endpoint{Address: "10.60.1.25", Port: 1445}
	probes := []model.ProbeResult{
		passProbe("tcp", target, model.LayerTCP, model.FaultDomainTransport, fixtureEvidence("service/tcp", model.EvidenceKindTCPConnection, map[string]any{"address": "10.60.1.25", "port": 1445, "connected": true})),
		passProbe("service", target, model.LayerDestination, model.FaultDomainDestination, fixtureEvidence("service/intent", model.EvidenceKindUnknown, map[string]any{"service": "smb", "port": 1445, "intent": "smb_session"})),
	}
	return fixtureWithReport("service-aware-target", target, model.ReportStatusComplete, probes, model.FailureReasonNone, model.ServiceProfileSMB, "confirmed", "", false, 0, false,
		[]string{`"id":"smb"`, `"port":1445`, `"application_protocol":"smb"`})
}

func fixtureWithReport(name string, target model.Target, status model.ReportStatus, probes []model.ProbeResult, wantFinding model.FailureReason, service model.ServiceProfileID, destination string, scope model.NetworkScope, resolution bool, pathEvidence int, unsupported bool, keys []string) regressionFixture {
	started, completed := fixtureTimes()
	report := model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		SessionID:     "fixture/" + name,
		Status:        status,
		StartedAt:     started,
		CompletedAt:   completed,
		Probes:        probes,
	}
	report.Observations = observationbuilder.Build(target, probes)
	if target.NetworkContext != nil {
		report.Observations.NetworkContext = *target.NetworkContext
	}
	report.Findings = diagnosis.Diagnose(report.Probes)
	return regressionFixture{
		name:              name,
		report:            report,
		wantStatus:        status,
		wantFinding:       wantFinding,
		wantService:       service,
		wantDestination:   destination,
		wantNetworkScope:  scope,
		wantResolution:    resolution,
		wantPathEvidence:  pathEvidence,
		wantUnsupported:   unsupported,
		wantCanonicalKeys: keys,
	}
}

func passProbe(name string, target model.Target, layer model.Layer, domain model.FaultDomain, evidence model.Evidence, resolution ...model.NameResolutionObservation) model.ProbeResult {
	probe := baseProbe(name, target, model.ProbeStatusPassed, model.FailureReasonNone, layer, domain, evidence)
	if len(resolution) != 0 {
		value := model.NormalizeNameResolutionObservation(resolution[0])
		probe.NameResolution = &value
	}
	return probe
}

func failedProbe(name string, target model.Target, layer model.Layer, domain model.FaultDomain, reason model.FailureReason, evidence ...model.Evidence) model.ProbeResult {
	return baseProbe(name, target, model.ProbeStatusFailed, reason, layer, domain, evidence...)
}

func skippedProbe(name string, target model.Target, layer model.Layer, domain model.FaultDomain) model.ProbeResult {
	return baseProbe(name, target, model.ProbeStatusSkipped, model.FailureReasonUnsupported, layer, domain)
}

func baseProbe(name string, target model.Target, status model.ProbeStatus, reason model.FailureReason, layer model.Layer, domain model.FaultDomain, evidence ...model.Evidence) model.ProbeResult {
	return model.ProbeResult{
		Name:          name,
		Target:        target,
		SessionID:     "fixture/session",
		ProbeID:       name,
		CorrelationID: "fixture/session/" + name,
		Status:        status,
		Timing:        model.Timing{StartedAt: fixtureTimePointer(), CompletedAt: fixtureTimePointer(), DurationMS: 12},
		Evidence:      evidence,
		Interpretation: model.ProbeInterpretation{
			FailureReason: reason,
			Layer:         layer,
			FaultDomain:   domain,
		},
	}
}

func fixtureEvidence(id string, kind model.EvidenceKind, value any) model.Evidence {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("fixture evidence %s: %v", id, err))
	}
	return model.Evidence{ID: id, Kind: kind, Source: "deterministic regression fixture", CapturedAt: fixtureTimePointer(), Raw: raw}
}

func resolutionEvidence(id string, observation model.NameResolutionObservation) model.Evidence {
	return fixtureEvidence(id, model.EvidenceKindDNSResolution, observation)
}

func targetFrom(input string) model.Target {
	return targetFromIntent(model.TargetIntent{Input: input})
}

func targetFromIntent(intent model.TargetIntent) model.Target {
	target, err := model.ParseTarget(intent)
	if err != nil {
		panic(fmt.Sprintf("fixture target %q: %v", intent.Input, err))
	}
	return target
}

func canonicalReport(t *testing.T, value model.DiagnosticReport) []byte {
	t.Helper()
	encoded, err := report.MarshalJSON(value)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return encoded
}

func fixtureTimes() (*time.Time, *time.Time) {
	started := fixtureTime
	completed := fixtureTime.Add(750 * time.Millisecond)
	return &started, &completed
}

func fixtureTimePointer() *time.Time {
	value := fixtureTime
	return &value
}

func hasUnsupportedProbe(report model.DiagnosticReport) bool {
	for _, probe := range report.Probes {
		if probe.Status == model.ProbeStatusSkipped && probe.Interpretation.FailureReason == model.FailureReasonUnsupported {
			return true
		}
	}
	return false
}
