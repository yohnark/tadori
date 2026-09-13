package observations

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	httpprobe "github.com/yohnark/tadori/internal/probe/http"
	tlsprobe "github.com/yohnark/tadori/internal/probe/tls"
)

type tcpEvidenceFixture struct {
	RequestedEndpoint string                  `json:"requested_endpoint"`
	LocalEndpoint     string                  `json:"local_endpoint,omitempty"`
	RemoteEndpoint    string                  `json:"remote_endpoint,omitempty"`
	SelectedEndpoint  string                  `json:"selected_endpoint,omitempty"`
	TestedEndpoint    string                  `json:"tested_endpoint,omitempty"`
	CandidateAttempts []model.EndpointAttempt `json:"candidate_attempts,omitempty"`
}

type httpResponseFixture struct {
	ResponseReceived bool                            `json:"response_received"`
	URL              string                          `json:"url,omitempty"`
	StatusCode       int                             `json:"status_code,omitempty"`
	Status           string                          `json:"status,omitempty"`
	Protocol         string                          `json:"protocol,omitempty"`
	Redirects        []model.HTTPRedirectObservation `json:"redirects,omitempty"`
}

type httpErrorFixture struct {
	ResponseReceived bool                            `json:"response_received"`
	URL              string                          `json:"url,omitempty"`
	ErrorKind        string                          `json:"error_kind"`
	Error            string                          `json:"error"`
	Redirects        []model.HTTPRedirectObservation `json:"redirects,omitempty"`
}

func fixedTiming() model.Timing {
	started := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("fixture", 9*60*60))
	completed := started.Add(23 * time.Millisecond)
	return model.Timing{StartedAt: &started, CompletedAt: &completed, DurationMS: 23}
}

func profileTarget(t *testing.T, input string, profileID model.ServiceProfileID) model.Target {
	t.Helper()
	target := mustTarget(t, input)
	profile, err := model.LookupServiceProfile(profileID)
	if err != nil {
		t.Fatal(err)
	}
	target.Service = profile
	target.ApplicationProtocol = profile.ApplicationProtocol
	target.TransportProtocol = profile.TransportProtocol
	return target
}

func fixtureTCPResult(t *testing.T, target model.Target, id, probeID, correlation string, status model.ProbeStatus, reason model.FailureReason, value tcpEvidenceFixture) model.ProbeResult {
	t.Helper()
	return model.ProbeResult{
		Name: "tcp", Target: target, ProbeID: probeID, CorrelationID: correlation,
		Status: status, Timing: fixedTiming(),
		Evidence:       []model.Evidence{fixtureEvidence(t, id, model.EvidenceKindTCPConnection, "fixture:tcp", value)},
		Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: model.LayerTCP, FaultDomain: model.FaultDomainTransport},
	}
}

func fixtureTLSResult(t *testing.T, target model.Target, id, probeID, correlation string, status model.ProbeStatus, reason model.FailureReason, handshake tlsprobe.HandshakeEvidence, certificates ...tlsprobe.CertificateMetadata) model.ProbeResult {
	t.Helper()
	evidence := []model.Evidence{fixtureEvidence(t, id, model.EvidenceKindTLSHandshake, "fixture:tls", handshake)}
	for index, certificate := range certificates {
		evidence = append(evidence, fixtureEvidence(t, id+"-cert-"+string(rune('a'+index)), model.EvidenceKindCertificate, "fixture:tls", certificate))
	}
	return model.ProbeResult{
		Name: "tls", Target: target, ProbeID: probeID, CorrelationID: correlation,
		Status: status, Timing: fixedTiming(), Evidence: evidence,
		Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTLS},
	}
}

func TestBuildTransportObservationsNormalizesConnectedRefusedResetAndTimeout(t *testing.T) {
	target := profileTarget(t, "service.example:443", model.ServiceProfileHTTPS)
	tests := []struct {
		name    string
		reason  model.FailureReason
		status  model.ProbeStatus
		outcome model.TransportConnectionOutcome
		remote  string
		tested  string
		wantOK  bool
	}{
		{name: "connected", reason: model.FailureReasonNone, status: model.ProbeStatusPassed, outcome: model.TransportConnectionOutcomeConnected, remote: "192.0.2.44:443", tested: "192.0.2.44:443", wantOK: true},
		{name: "refused", reason: model.FailureReasonTCPConnectionRefused, status: model.ProbeStatusFailed, outcome: model.TransportConnectionOutcomeRefused},
		{name: "reset", reason: model.FailureReasonTCPConnectionReset, status: model.ProbeStatusFailed, outcome: model.TransportConnectionOutcomeReset},
		{name: "timeout", reason: model.FailureReasonTCPTimeout, status: model.ProbeStatusFailed, outcome: model.TransportConnectionOutcomeTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := fixtureTCPResult(t, target, "tcp-"+test.name, "tcp-id-"+test.name, "corr-"+test.name, test.status, test.reason, tcpEvidenceFixture{
				RequestedEndpoint: "service.example:443", LocalEndpoint: "192.0.2.10:51000", RemoteEndpoint: test.remote, TestedEndpoint: test.tested,
			})
			got := Build(target, []model.ProbeResult{probe})
			if got.Transport.ConnectionOutcome != test.outcome || got.Transport.FailureReason != test.reason {
				t.Fatalf("transport = %#v, want outcome %q/reason %q", got.Transport, test.outcome, test.reason)
			}
			if got.Transport.Applicability != model.ObservationApplicabilityApplicable || got.Transport.Certainty != model.ObservationCertaintyObserved {
				t.Fatalf("transport state = %#v", got.Transport)
			}
			if test.wantOK {
				if !got.Transport.Connected || got.Transport.TestedEndpoint == nil || got.Transport.TestedEndpoint.Address != "192.0.2.44" {
					t.Fatalf("connected endpoint = %#v", got.Transport)
				}
				if got.Transport.LocalEndpoint != "192.0.2.10:51000" {
					t.Fatalf("local endpoint = %q", got.Transport.LocalEndpoint)
				}
			} else if got.Transport.Connected {
				t.Fatalf("failed transport marked connected: %#v", got.Transport)
			}
		})
	}
}

func TestBuildTransportRetainsCandidateAttemptsAndPacketFlowCorroboration(t *testing.T) {
	target := profileTarget(t, "dual.example:443", model.ServiceProfileHTTPS)
	probe := fixtureTCPResult(t, target, "tcp-connected", "tcp-54", "flow-54", model.ProbeStatusPassed, model.FailureReasonNone, tcpEvidenceFixture{
		RequestedEndpoint: "dual.example:443", SelectedEndpoint: "192.0.2.20:443", TestedEndpoint: "192.0.2.20:443", RemoteEndpoint: "192.0.2.20:443",
		CandidateAttempts: []model.EndpointAttempt{
			{Candidate: model.EndpointCandidate{Address: "192.0.2.10", Family: model.EndpointFamilyIPv4, Order: 1}, RequestedEndpoint: "192.0.2.10:443", Status: model.ProbeStatusFailed, FailureReason: model.FailureReasonTCPConnectionRefused, EvidenceIDs: []string{"tcp-connected"}},
			{Candidate: model.EndpointCandidate{Address: "192.0.2.20", Family: model.EndpointFamilyIPv4, Order: 2}, RequestedEndpoint: "192.0.2.20:443", Status: model.ProbeStatusPassed, EvidenceIDs: []string{"tcp-connected"}},
		},
	})
	flowEvidence, err := model.PacketFlowEvidenceFor(model.PacketFlowEvidence{
		CorrelationID: "flow-54", ProbeID: "tcp-54", Target: target,
		CaptureStatus: model.PacketCaptureStatusAvailable, Outcome: model.PacketFlowOutcomeTCPSYNACK,
		Certainty: model.EvidenceCertaintyConfirmedEndpointResponse,
	})
	if err != nil {
		t.Fatal(err)
	}
	probe.Evidence = append(probe.Evidence, flowEvidence)

	got := Build(target, []model.ProbeResult{probe})
	if got.Transport.TestedEndpoint == nil || got.Transport.TestedEndpoint.Address != "192.0.2.20" {
		t.Fatalf("tested endpoint = %#v", got.Transport.TestedEndpoint)
	}
	if len(got.Transport.CandidateAttempts) != 2 || len(got.Transport.PacketFlowEvidenceIDs) != 1 || got.Transport.PacketFlowEvidenceIDs[0] != flowEvidence.ID {
		t.Fatalf("transport corroboration = %#v", got.Transport)
	}
	if !contains(got.Transport.Provenance, "source:fixture:tcp") || !contains(got.Transport.EvidenceIDs, flowEvidence.ID) {
		t.Fatalf("transport provenance = %#v", got.Transport)
	}
}

func TestBuildSecurityProjectsHTTPSuccessAndCertificates(t *testing.T) {
	target := profileTarget(t, "secure.example:443", model.ServiceProfileHTTPS)
	target.TestedEndpoint = &model.Endpoint{Address: "192.0.2.44", Port: 443, Family: model.EndpointFamilyIPv4, SelectionReason: model.EndpointSelectionTransport, Provenance: "fixture tested endpoint"}
	probe := fixtureTLSResult(t, target, "tls-handshake", "tls-54", "corr-tls", model.ProbeStatusPassed, model.FailureReasonNone, tlsprobe.HandshakeEvidence{
		Phase: tlsprobe.PhaseComplete, Address: "192.0.2.44:443", ServerName: "secure.example", NegotiatedProtocol: "h2", NegotiatedProtocolID: "h2", TLSVersion: "TLS 1.3", TLSVersionID: 0x0304,
		CipherSuite: "TLS_AES_128_GCM_SHA256", CipherSuiteID: 0x1301, HandshakeComplete: true, PeerCertificateCount: 2,
	}, tlsprobe.CertificateMetadata{ChainIndex: 0, Subject: "CN=secure.example", Issuer: "CN=Example CA", DNSNames: []string{"secure.example"}, SHA256: "leaf-hash"}, tlsprobe.CertificateMetadata{ChainIndex: 1, Subject: "CN=Example CA", Issuer: "CN=Example Root", IsCA: true, SHA256: "ca-hash"})

	got := Build(target, []model.ProbeResult{probe})
	security := got.Security
	if security.Applicability != model.ObservationApplicabilityApplicable || !security.Attempted || !security.HandshakeComplete {
		t.Fatalf("TLS applicability/handshake = %#v", security)
	}
	if security.CertificateValidation != model.CertificateValidationValid || security.TLSVersion != "TLS 1.3" || security.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("TLS negotiation/validation = %#v", security)
	}
	if security.EndpointUsed == nil || security.EndpointUsed.Address != "192.0.2.44" || len(security.Certificates) != 2 {
		t.Fatalf("TLS endpoint/certificates = %#v", security)
	}
	if security.FailureReason != model.FailureReasonNone || security.Certainty != model.ObservationCertaintyObserved || security.Timing.DurationMS != 23 {
		t.Fatalf("TLS result metadata = %#v", security)
	}
}

func TestBuildSecurityProjectsTLSValidationFailureAndTrustInterceptionEvidence(t *testing.T) {
	target := profileTarget(t, "custom.example:8443", model.ServiceProfileCustomTLS)
	probe := fixtureTLSResult(t, target, "tls-invalid", "tls-invalid", "corr-invalid", model.ProbeStatusFailed, model.FailureReasonCertificateValidationFailure, tlsprobe.HandshakeEvidence{
		Phase: tlsprobe.PhaseHandshake, Address: "198.51.100.8:8443", ServerName: "custom.example", PeerCertificateCount: 1, Error: "x509: certificate signed by unknown authority",
	}, tlsprobe.CertificateMetadata{ChainIndex: 0, Subject: "CN=custom.example", Issuer: "CN=Intercepting CA", SHA256: "intercepted-leaf"})
	trust := fixtureEvidence(t, "tls-trust", model.EvidenceKindTLSTrust, "fixture:trust", struct {
		TrustStore   string `json:"trust_store"`
		Interception bool   `json:"interception"`
	}{TrustStore: "corporate interception store", Interception: true})
	probe.Evidence = append(probe.Evidence, trust)

	got := Build(target, []model.ProbeResult{probe})
	security := got.Security
	if security.CertificateValidation != model.CertificateValidationUntrusted || security.FailureReason != model.FailureReasonCertificateValidationFailure {
		t.Fatalf("TLS validation = %#v", security)
	}
	if len(security.TrustEvidenceIDs) != 1 || len(security.InterceptionEvidenceIDs) != 1 || security.InterceptionEvidenceIDs[0] != "tls-trust" {
		t.Fatalf("TLS trust/interception = %#v", security)
	}
	if len(security.Certificates) != 1 || security.Certificates[0].Issuer != "CN=Intercepting CA" {
		t.Fatalf("certificate facts = %#v", security.Certificates)
	}
}

func TestBuildApplicationProjectsHTTPSuccessAndHTTPStatusFailure(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		status     model.ProbeStatus
		reason     model.FailureReason
		result     model.HTTPResult
	}{
		{name: "success", statusCode: 204, status: model.ProbeStatusPassed, reason: model.FailureReasonNone, result: model.HTTPResultSuccess},
		{name: "status failure", statusCode: 503, status: model.ProbeStatusFailed, reason: model.FailureReasonHTTPStatusCode, result: model.HTTPResultStatusFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := profileTarget(t, "https://web.example/health", model.ServiceProfileHTTPS)
			target.Resource = "/health"
			target.TestedEndpoint = &model.Endpoint{Address: "192.0.2.55", Port: 443, Family: model.EndpointFamilyIPv4, SelectionReason: model.EndpointSelectionTransport}
			probe := model.ProbeResult{
				Name: "http", Target: target, ProbeID: "http-54", Status: test.status, Timing: fixedTiming(),
				Evidence: []model.Evidence{fixtureEvidence(t, "http-"+test.name, model.EvidenceKindHTTPResponse, "fixture:http", httpResponseFixture{
					ResponseReceived: true, URL: "https://web.example/health", StatusCode: test.statusCode, Status: "HTTP/1.1 " + string(rune('0'+test.statusCode/100)) + " response", Protocol: "HTTP/1.1",
					Redirects: []model.HTTPRedirectObservation{{URL: "https://web.example/", StatusCode: 301, Location: "/health", ToURL: "https://web.example/health"}},
				})},
				Interpretation: model.ProbeInterpretation{FailureReason: test.reason, Layer: model.LayerHTTP, FaultDomain: model.FaultDomainHTTP},
			}
			got := Build(target, []model.ProbeResult{probe})
			application := got.Application
			if application.Applicability != model.ObservationApplicabilityApplicable || !application.RequestAttempted || !application.ResponseReceived {
				t.Fatalf("HTTP state = %#v", application)
			}
			if application.Result != test.result || application.StatusCode != test.statusCode || application.HTTPVersion != "HTTP/1.1" || application.RequestedResource != "/health" {
				t.Fatalf("HTTP projection = %#v, want result %q/status %d", application, test.result, test.statusCode)
			}
			if application.FailureReason != test.reason || application.EndpointUsed == nil || application.EndpointUsed.Address != "192.0.2.55" || len(application.Redirects) != 1 {
				t.Fatalf("HTTP metadata = %#v", application)
			}
		})
	}
}

func TestBuildApplicationProjectsRequestFailureAndPreservesRedirectFacts(t *testing.T) {
	target := profileTarget(t, "http://web.example/start", model.ServiceProfileHTTP)
	target.Resource = "/start"
	probe := model.ProbeResult{
		Name: "http", Target: target, Status: model.ProbeStatusError, Timing: fixedTiming(),
		Evidence: []model.Evidence{fixtureEvidence(t, "http-error", httpprobe.EvidenceKindHTTPError, "fixture:http", httpErrorFixture{
			ResponseReceived: true, URL: "http://web.example/start", ErrorKind: "redirect_failure", Error: "stopped after redirect limit",
			Redirects: []model.HTTPRedirectObservation{{URL: "http://web.example/start", StatusCode: 302, Location: "/next", ToURL: "http://web.example/next"}},
		})},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonHTTPFailure, Layer: model.LayerHTTP, FaultDomain: model.FaultDomainHTTP},
	}
	got := Build(target, []model.ProbeResult{probe})
	if got.Application.Result != model.HTTPResultRequestFailure || !got.Application.RequestAttempted || !got.Application.ResponseReceived || len(got.Application.Redirects) != 1 {
		t.Fatalf("HTTP request failure = %#v", got.Application)
	}
}

func TestBuildMarksCustomTLSAndNonHTTPApplicationStatesExplicitly(t *testing.T) {
	customTLS := profileTarget(t, "secure.example:8443", model.ServiceProfileCustomTLS)
	tlsResult := fixtureTLSResult(t, customTLS, "tls-custom", "tls-custom", "corr-custom", model.ProbeStatusPassed, model.FailureReasonNone, tlsprobe.HandshakeEvidence{
		Phase: tlsprobe.PhaseComplete, Address: "192.0.2.99:8443", ServerName: "secure.example", TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", HandshakeComplete: true,
	})
	got := Build(customTLS, []model.ProbeResult{tlsResult})
	if got.Security.Applicability != model.ObservationApplicabilityApplicable || got.Application.Applicability != model.ObservationApplicabilityInapplicable || got.Application.Result != model.HTTPResultNotAttempted || got.Application.FailureReason != model.FailureReasonNone {
		t.Fatalf("custom TLS states = security %#v application %#v", got.Security, got.Application)
	}

	smb := profileTarget(t, "files.example:445", model.ServiceProfileSMB)
	smbGot := Build(smb, nil)
	if smbGot.Security.Applicability != model.ObservationApplicabilityInapplicable || smbGot.Application.Applicability != model.ObservationApplicabilityInapplicable {
		t.Fatalf("non-HTTP inapplicability = security %#v application %#v", smbGot.Security, smbGot.Application)
	}
	if smbGot.Security.FailureReason != model.FailureReasonNone || smbGot.Application.FailureReason != model.FailureReasonNone {
		t.Fatalf("inapplicable layers became failures = security %#v application %#v", smbGot.Security, smbGot.Application)
	}
}

func TestBuildRetainsConflictingPartialTransportEvidenceAndIsDeterministic(t *testing.T) {
	target := profileTarget(t, "conflict.example:443", model.ServiceProfileHTTPS)
	first := fixtureTCPResult(t, target, "tcp-a", "tcp-a", "corr-a", model.ProbeStatusPassed, model.FailureReasonNone, tcpEvidenceFixture{RequestedEndpoint: "conflict.example:443", TestedEndpoint: "192.0.2.10:443", RemoteEndpoint: "192.0.2.10:443"})
	second := fixtureTCPResult(t, target, "tcp-b", "tcp-b", "corr-b", model.ProbeStatusFailed, model.FailureReasonTCPConnectionRefused, tcpEvidenceFixture{RequestedEndpoint: "conflict.example:443", TestedEndpoint: "192.0.2.20:443"})
	partial := model.ProbeResult{
		Name: "tls", Target: target, Status: model.ProbeStatusFailed, Timing: fixedTiming(),
		Evidence:       []model.Evidence{{ID: "tls-malformed", Kind: model.EvidenceKindTLSHandshake, Source: "fixture:tls", Raw: json.RawMessage(`{"phase":`)}},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonTLSHandshakeFailure, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTLS},
	}
	left := Build(target, []model.ProbeResult{second, partial, first})
	right := Build(target, []model.ProbeResult{first, partial, second})
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("projection depends on probe order\nleft=%#v\nright=%#v", left, right)
	}
	if len(left.Transport.Conflicts) == 0 || left.Transport.Conflicts[0].Field != "transport.tested_endpoint" {
		t.Fatalf("transport conflict = %#v", left.Transport.Conflicts)
	}
	if len(left.Security.Limitations) == 0 || !contains(left.Security.EvidenceIDs, "tls-malformed") {
		t.Fatalf("partial TLS evidence = %#v", left.Security)
	}
	if !contains(left.Transport.Conflicts[0].EvidenceIDs, "tcp-a") || !contains(left.Transport.Conflicts[0].EvidenceIDs, "tcp-b") {
		t.Fatalf("conflict provenance = %#v", left.Transport.Conflicts[0])
	}
}

func TestNormalizeObservationsDetachesTransportTLSHTTPSlices(t *testing.T) {
	transport := model.TransportObservation{EvidenceIDs: []string{"tcp"}, PacketFlowEvidenceIDs: []string{"flow"}, CandidateAttempts: []model.EndpointAttempt{{Candidate: model.EndpointCandidate{EvidenceIDs: []string{"candidate"}}}}}
	security := model.SecurityObservation{EvidenceIDs: []string{"tls"}, Certificates: []model.TLSCertificateObservation{{DNSNames: []string{"example.test"}}}}
	application := model.ApplicationObservation{EvidenceIDs: []string{"http"}, Redirects: []model.HTTPRedirectObservation{{URL: "https://example.test"}}}
	observations := model.NormalizeObservations(model.Observations{Transport: transport, Security: security, Application: application})
	transport.EvidenceIDs[0] = "changed"
	transport.PacketFlowEvidenceIDs[0] = "changed"
	transport.CandidateAttempts[0].Candidate.EvidenceIDs[0] = "changed"
	security.EvidenceIDs[0] = "changed"
	security.Certificates[0].DNSNames[0] = "changed"
	application.EvidenceIDs[0] = "changed"
	application.Redirects[0].URL = "changed"
	if observations.Transport.EvidenceIDs[0] != "tcp" || observations.Transport.PacketFlowEvidenceIDs[0] != "flow" || observations.Transport.CandidateAttempts[0].Candidate.EvidenceIDs[0] != "candidate" || observations.Security.EvidenceIDs[0] != "tls" || observations.Security.Certificates[0].DNSNames[0] != "example.test" || observations.Application.EvidenceIDs[0] != "http" || observations.Application.Redirects[0].URL != "https://example.test" {
		t.Fatalf("normalized observations share input state: %#v", observations)
	}
}
