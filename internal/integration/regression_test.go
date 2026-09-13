package integration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/diagnosis"
	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/report"
	"github.com/yohnark/tadori/internal/web"
)

func TestRegressionFixtureInventoryMatchesIssueScenarios(t *testing.T) {
	want := map[string]struct {
		status       model.ReportStatus
		finding      model.FailureReason
		service      model.ServiceProfileID
		pathEvidence int
	}{
		"https-success":                           {status: model.ReportStatusComplete, finding: model.FailureReasonNone, service: model.ServiceProfileHTTPS},
		"local-private-on-link":                   {status: model.ReportStatusComplete, finding: model.FailureReasonNone, service: model.ServiceProfileHTTPS},
		"split-dns-nrpt":                          {status: model.ReportStatusComplete, finding: model.FailureReasonNone, service: model.ServiceProfileHTTPS},
		"path-unobservable-destination-confirmed": {status: model.ReportStatusComplete, finding: model.FailureReasonNone, service: model.ServiceProfileHTTPS, pathEvidence: 1},
		"proxy-policy-partial":                    {status: model.ReportStatusIncomplete, finding: model.FailureReasonProxyConfigurationDivergence, service: model.ServiceProfileHTTPS},
		"service-aware-target":                    {status: model.ReportStatusComplete, finding: model.FailureReasonNone, service: model.ServiceProfileSMB},
	}
	fixtures := regressionFixtures()
	if len(fixtures) != len(want) {
		t.Fatalf("fixture count = %d, want %d", len(fixtures), len(want))
	}
	for _, fixture := range fixtures {
		expectation, ok := want[fixture.name]
		if !ok {
			t.Fatalf("unexpected fixture %q", fixture.name)
		}
		if fixture.wantStatus != expectation.status || fixture.wantFinding != expectation.finding || fixture.wantService != expectation.service || fixture.wantPathEvidence != expectation.pathEvidence {
			t.Errorf("%s metadata = status %q, finding %q, service %q, paths %d", fixture.name, fixture.wantStatus, fixture.wantFinding, fixture.wantService, fixture.wantPathEvidence)
		}
	}
}

func TestRegressionFixturesHaveStableTimingAndEvidenceIdentity(t *testing.T) {
	for _, fixture := range regressionFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			if fixture.report.StartedAt == nil || fixture.report.CompletedAt == nil || fixture.report.CompletedAt.Sub(*fixture.report.StartedAt) != 750*time.Millisecond {
				t.Fatalf("report timing is not deterministic: %v - %v", fixture.report.StartedAt, fixture.report.CompletedAt)
			}
			seen := map[string]string{}
			for _, probe := range fixture.report.Probes {
				if probe.Timing.StartedAt == nil || probe.Timing.CompletedAt == nil || !probe.Timing.StartedAt.Equal(fixtureTime) || !probe.Timing.CompletedAt.Equal(fixtureTime) {
					t.Fatalf("probe %q has nondeterministic timing: %#v", probe.Name, probe.Timing)
				}
				if probe.ProbeID == "" || probe.CorrelationID == "" {
					t.Fatalf("probe %q lacks stable identity", probe.Name)
				}
				for _, evidence := range probe.Evidence {
					if evidence.ID == "" || evidence.Source == "" || evidence.CapturedAt == nil || !evidence.CapturedAt.Equal(fixtureTime) {
						t.Fatalf("probe %q has incomplete evidence identity: %#v", probe.Name, evidence)
					}
					if previous, exists := seen[evidence.ID]; exists {
						t.Fatalf("evidence ID %q is used by both %s and %s", evidence.ID, previous, probe.Name)
					}
					seen[evidence.ID] = probe.Name
					if !json.Valid(evidence.Raw) {
						t.Fatalf("evidence %q is not valid JSON: %s", evidence.ID, evidence.Raw)
					}
				}
			}
		})
	}
}

func TestRegressionFixturesPreserveRequestedIdentityAcrossEndpointFacts(t *testing.T) {
	for _, fixture := range regressionFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			target := fixture.report.Target
			if target.OriginalInput == "" || target.RequestedIdentity == "" {
				t.Fatal("fixture target lost its requested identity")
			}
			if len(target.ResolvedAddresses) != 0 && target.SelectedEndpoint == nil {
				t.Fatal("resolved address has no selected endpoint")
			}
			if target.SelectedEndpoint != nil && target.SelectedEndpoint.Port != target.Port {
				t.Fatalf("selected endpoint port = %d, want %d", target.SelectedEndpoint.Port, target.Port)
			}
			if target.TestedEndpoint != nil && target.TestedEndpoint.Port != target.Port {
				t.Fatalf("tested endpoint port = %d, want %d", target.TestedEndpoint.Port, target.Port)
			}
			if strings.Contains(target.RequestedIdentity, "://") {
				t.Fatalf("requested identity contains a URL scheme: %q", target.RequestedIdentity)
			}
		})
	}
}

func TestRegressionViewsDoNotMutateCanonicalReports(t *testing.T) {
	for _, fixture := range regressionFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			before := fixture.report
			beforeJSON := canonicalReport(t, before)
			if _, err := web.BuildDiagnosticView(fixture.report); err != nil {
				t.Fatalf("BuildDiagnosticView: %v", err)
			}
			afterJSON := canonicalReport(t, fixture.report)
			if !bytes.Equal(beforeJSON, afterJSON) || !reflect.DeepEqual(before, fixture.report) {
				t.Fatal("view projection mutated the canonical report")
			}
		})
	}
}

func TestPathFixtureUsesRequestedPortForDestinationCorrelation(t *testing.T) {
	fixture := unobservablePathFixture()
	pathIndex := -1
	for index, probe := range fixture.report.Probes {
		if probe.Name == "path" {
			pathIndex = index
			break
		}
	}
	if pathIndex < 0 || len(fixture.report.Probes[pathIndex].Evidence) != 1 {
		t.Fatal("path fixture is missing its single path observation")
	}
	pathProbe := fixture.report.Probes[pathIndex]
	observation, err := model.DecodePathObservation(pathProbe.Evidence[0])
	if err != nil {
		t.Fatalf("DecodePathObservation: %v", err)
	}
	observation.DestinationPort = fixture.report.Target.Port + 1
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	pathProbe.Evidence = []model.Evidence{{ID: "path/wrong-port", Kind: model.EvidenceKindPathObservation, Raw: raw}}
	got := diagnosis.Diagnose([]model.ProbeResult{fixture.report.Probes[0], pathProbe})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPTimeout {
		t.Fatalf("wrong-port path evidence changed diagnosis: %#v", got)
	}
}

func TestSplitDNSFixtureKeepsConfiguredAndObservedResolverClaimsSeparate(t *testing.T) {
	fixture := splitDNSNRPTFixture()
	var configured, policy, effective int
	for _, probe := range fixture.report.Probes {
		if probe.NameResolution == nil {
			continue
		}
		for _, path := range probe.NameResolution.Paths {
			switch path.State {
			case model.NameResolutionPathConfiguredCandidate:
				configured++
				if path.Certainty != model.NameResolutionCertaintyConfigured || path.Resolver == "" {
					t.Fatalf("configured path was not labeled as configured: %#v", path)
				}
			case model.NameResolutionPathPolicyCandidate:
				policy++
				if path.PolicySource != "NRPT" || path.Certainty != model.NameResolutionCertaintyConfigured {
					t.Fatalf("policy path overclaims certainty: %#v", path)
				}
			case model.NameResolutionPathEffective:
				effective++
				if path.Certainty != model.NameResolutionCertaintyObserved || path.Provenance == "" {
					t.Fatalf("effective path lacks observed provenance: %#v", path)
				}
			}
		}
	}
	if configured != 1 || policy != 1 || effective != 1 {
		t.Fatalf("split-DNS path states = configured:%d policy:%d effective:%d", configured, policy, effective)
	}
}

func TestProxyPartialFixtureRetainsOpaqueRawConfigurationInCanonicalJSON(t *testing.T) {
	fixture := proxyPolicyPartialFixture()
	encoded := canonicalReport(t, fixture.report)
	for _, value := range []string{"proxy.service.example.test:8080", "proxy.browser.example.test:8080", "bounded diagnostic does not execute PAC"} {
		if !bytes.Contains(encoded, []byte(value)) {
			t.Fatalf("canonical proxy fixture lost raw configuration value %q", value)
		}
	}
	if bytes.Contains(encoded, []byte("password")) || bytes.Contains(encoded, []byte("token=")) {
		t.Fatal("proxy fixture unexpectedly contains credential material")
	}
}

func TestServiceAwareFixtureUsesCanonicalWriterForAllConsumers(t *testing.T) {
	fixture := serviceAwareSerializationFixture()
	canonical := canonicalReport(t, fixture.report)
	var output bytes.Buffer
	if err := report.WriteJSON(&output, fixture.report); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), canonical) {
		t.Fatal("WriteJSON diverged from the canonical report writer")
	}
	view, err := web.BuildDiagnosticView(fixture.report)
	if err != nil {
		t.Fatal(err)
	}
	if view.Report.Target.Service.ID != model.ServiceProfileSMB || view.Report.Target.Port != 1445 {
		t.Fatalf("service-aware view lost target intent: %#v", view.Report.Target)
	}
}

func TestFixturesContainNoLiveNetworkDependency(t *testing.T) {
	for _, fixture := range regressionFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.HasSuffix(fixture.report.Target.RequestedIdentity, ".test") && fixture.report.Target.LiteralIP == "" && fixture.report.Target.RequestedIdentity != "fileserver01" {
				t.Fatalf("fixture target is not a documented/local endpoint: %#v", fixture.report.Target)
			}
			for _, probe := range fixture.report.Probes {
				for _, evidence := range probe.Evidence {
					if bytes.Contains(evidence.Raw, []byte("example.com")) || bytes.Contains(evidence.Raw, []byte("google.com")) {
						t.Fatalf("fixture %q contains a live public host in %s", fixture.name, evidence.ID)
					}
				}
			}
		})
	}
}
