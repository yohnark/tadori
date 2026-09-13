package diagnosis

import (
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func canonicalObservationsTarget() model.Target {
	return model.NewTarget("service.example", 443)
}

func canonicalEnvelope() model.Observations {
	target := canonicalObservationsTarget()
	return model.Observations{Endpoint: model.EndpointObservation{
		RequestedIdentity:   target.RequestedIdentity,
		Port:                target.Port,
		Service:             target.Service,
		ApplicationProtocol: target.ApplicationProtocol,
		TransportProtocol:   target.TransportProtocol,
	}}
}

func TestDiagnoseObservationsPreservesBoundaryPrecedence(t *testing.T) {
	value := canonicalEnvelope()
	value.NetworkContext = model.NetworkContext{
		RequestedIdentity: value.Endpoint.RequestedIdentity,
		EffectiveRoute:    model.RouteDispositionUnknown,
		FailureReason:     model.FailureReasonNoRoute,
		FaultDomain:       model.FaultDomainRouting,
		ProbeNames:        []string{"target-route"},
		EvidenceIDs:       []string{"route-failure"},
	}
	value.Transport = model.TransportObservation{
		Applicability:     model.ObservationApplicabilityApplicable,
		ConnectionOutcome: model.TransportConnectionOutcomeTimeout,
		FailureReason:     model.FailureReasonTCPTimeout,
		FaultDomain:       model.FaultDomainTransport,
		ProbeNames:        []string{"tcp"},
		EvidenceIDs:       []string{"tcp-failure"},
	}
	got := DiagnoseObservations(value)
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonNoRoute || got[0].EvidenceIDs[0] != "route-failure" {
		t.Fatalf("canonical precedence = %#v", got)
	}
}

func TestDiagnoseObservationsDoesNotTreatConfigurationAsCausality(t *testing.T) {
	value := canonicalEnvelope()
	value.NameResolution = model.NameResolutionObservation{
		RequestedName: value.Endpoint.RequestedIdentity,
		Paths: []model.NameResolutionPath{{
			State:     model.NameResolutionPathPolicyCandidate,
			Mechanism: model.NameResolutionMechanismDNS,
			Namespace: ".corp.example",
			Certainty: model.NameResolutionCertaintyConfigured,
		}},
	}
	value.NetworkContext = model.NetworkContext{RequestedIdentity: value.Endpoint.RequestedIdentity, EffectiveRoute: model.RouteDispositionOnLink}
	value.EnterprisePolicy = model.EnterprisePolicyObservation{
		RequestedIdentity: value.Endpoint.RequestedIdentity,
		State:             model.EnterpriseObservationStateObserved,
		WinINET: model.EnterpriseProxySourceObservation{
			Configuration: model.EnterpriseProxyConfigurationObservation{
				StaticProxyConfigured: true,
				Certainty:             model.ObservationCertaintyConfigured,
			},
		},
	}
	if got := DiagnoseObservations(value); got != nil {
		t.Fatalf("configuration-only observations = %#v", got)
	}
}

func TestDiagnoseObservationsMixedEndpointCandidatesRequireAllFailure(t *testing.T) {
	value := canonicalEnvelope()
	value.Endpoint.CandidateAttempts = []model.EndpointAttempt{
		{Candidate: model.EndpointCandidate{Address: "192.0.2.10"}, Status: model.ProbeStatusFailed, FailureReason: model.FailureReasonTCPTimeout, EvidenceIDs: []string{"failed-candidate"}},
		{Candidate: model.EndpointCandidate{Address: "192.0.2.20"}, Status: model.ProbeStatusPassed, FailureReason: model.FailureReasonNone, EvidenceIDs: []string{"successful-candidate"}},
	}
	if got := DiagnoseObservations(value); got != nil {
		t.Fatalf("mixed candidate outcomes = %#v", got)
	}
}

func TestDiagnoseObservationsPacketFlowOverridesTimeout(t *testing.T) {
	target := canonicalObservationsTarget()
	value := canonicalEnvelope()
	value.Transport = model.TransportObservation{
		Applicability:     model.ObservationApplicabilityApplicable,
		RequestedEndpoint: "service.example:443",
		ConnectionOutcome: model.TransportConnectionOutcomeTimeout,
		FailureReason:     model.FailureReasonTCPTimeout,
		FaultDomain:       model.FaultDomainTransport,
		EvidenceIDs:       []string{"tcp-timeout"},
	}
	value.PacketFlows = []model.PacketFlowEvidence{{
		Target:        target,
		CaptureStatus: model.PacketCaptureStatusAvailable,
		Outcome:       model.PacketFlowOutcomeTCPSYNACK,
		Certainty:     model.EvidenceCertaintyConfirmedEndpointResponse,
	}}
	value.PacketFlowProvenance = []model.ObservationProvenance{{ProbeName: "packet-flow", EvidenceIDs: []string{"flow-synack"}}}
	if got := DiagnoseObservations(value); got != nil {
		t.Fatalf("SYN/ACK corroboration = %#v", got)
	}
}

func TestDiagnoseObservationsPathAndApplicationSuccessSemantics(t *testing.T) {
	value := canonicalEnvelope()
	value.Paths = []model.PathObservation{{
		Status:             model.PathObservationStatusError,
		Protocol:           model.PathProtocolTCP,
		Destination:        "192.0.2.20",
		DestinationPort:    443,
		PortAware:          true,
		DestinationReached: false,
		Error:              "bounded path error",
	}}
	value.PathProvenance = []model.ObservationProvenance{{ProbeName: "path", EvidenceIDs: []string{"path-error"}}}
	value.Transport = model.TransportObservation{
		Applicability:     model.ObservationApplicabilityApplicable,
		ConnectionOutcome: model.TransportConnectionOutcomeConnected,
		Connected:         true,
		FailureReason:     model.FailureReasonNone,
		ProbeNames:        []string{"tcp"},
		EvidenceIDs:       []string{"tcp-success"},
	}
	if got := DiagnoseObservations(value); got != nil {
		t.Fatalf("path error with transport success = %#v", got)
	}
}

func TestDiagnoseObservationsEnterpriseDirectProxyAndTLSFindings(t *testing.T) {
	t.Run("direct failure and proxy success", func(t *testing.T) {
		value := canonicalEnvelope()
		value.EnterprisePolicy = model.EnterprisePolicyObservation{
			RequestedIdentity: value.Endpoint.RequestedIdentity,
			State:             model.EnterpriseObservationStateObserved,
			DirectVsProxy: model.EnterprisePathComparisonObservation{
				State:            model.EnterprisePathComparisonDirectFailureProxyWorks,
				DirectWorksKnown: true,
				ProxyWorksKnown:  true,
				ProxyWorks:       true,
				PolicyPossible:   true,
				EvidenceIDs:      []string{"path-comparison"},
			},
		}
		got := DiagnoseObservations(value)
		if len(got) != 1 || got[0].FailureReason != model.FailureReasonDirectEgressRestricted {
			t.Fatalf("direct/proxy diagnosis = %#v", got)
		}
	})

	t.Run("bounded TLS suspicion", func(t *testing.T) {
		value := canonicalEnvelope()
		value.EnterprisePolicy = model.EnterprisePolicyObservation{
			RequestedIdentity: value.Endpoint.RequestedIdentity,
			State:             model.EnterpriseObservationStateObserved,
			TLS: model.EnterpriseTLSPolicyObservation{
				PossibleInterception:  true,
				InterceptionSuspicion: model.EnterpriseInterceptionSuspicionPossible,
				Certainty:             model.ObservationCertaintyInferred,
				EvidenceIDs:           []string{"tls-comparison"},
			},
		}
		got := DiagnoseObservations(value)
		if len(got) != 1 || got[0].FailureReason != model.FailureReasonTLSInterceptionSuspected {
			t.Fatalf("TLS suspicion diagnosis = %#v", got)
		}
	})
}

func TestDiagnoseReportUsesCanonicalObservationsOverProbeInterpretation(t *testing.T) {
	value := canonicalEnvelope()
	value.Transport = model.TransportObservation{
		Applicability:     model.ObservationApplicabilityApplicable,
		ConnectionOutcome: model.TransportConnectionOutcomeConnected,
		Connected:         true,
		FailureReason:     model.FailureReasonNone,
		ProbeNames:        []string{"canonical-tcp"},
		EvidenceIDs:       []string{"canonical-success"},
	}
	report := model.DiagnosticReport{
		Target:       valueToTarget(value),
		Observations: value,
		Probes: []model.ProbeResult{{
			Name:   "stale-tcp",
			Status: model.ProbeStatusFailed,
			Interpretation: model.ProbeInterpretation{
				FailureReason: model.FailureReasonTCPTimeout,
				Layer:         model.LayerTCP,
				FaultDomain:   model.FaultDomainTransport,
			},
		}},
	}
	if got := DiagnoseReport(report); got.Findings != nil {
		t.Fatalf("stale probe interpretation overrode canonical state = %#v", got.Findings)
	}
}

func valueToTarget(value model.Observations) model.Target {
	return model.NewTarget(value.Endpoint.RequestedIdentity, value.Endpoint.Port)
}

func canonicalApplicationEnvelope(protocol model.ApplicationProtocol) model.Observations {
	return model.Observations{Endpoint: model.EndpointObservation{
		RequestedIdentity:   "service.example",
		Port:                443,
		ApplicationProtocol: protocol,
		TransportProtocol:   model.TransportTCP,
	}}
}

func TestDiagnoseObservationsUsesProtocolAwareApplicationSemantics(t *testing.T) {
	tests := []struct {
		name   string
		value  model.Observations
		want   model.FailureReason
		layer  model.Layer
		result bool
	}{
		{
			name: "HTTP status",
			value: func() model.Observations {
				value := canonicalApplicationEnvelope(model.ApplicationProtocolHTTP)
				value.Application = model.ApplicationObservation{Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolHTTP, RequestAttempted: true, ResponseReceived: true, Result: model.HTTPResultStatusFailure, StatusCode: 503, EvidenceIDs: []string{"http-status"}}
				return value
			}(),
			want: model.FailureReasonHTTPStatusCode, layer: model.LayerHTTP,
		},
		{
			name:  "DNS refusal",
			value: dnsApplicationObservation("refused", "dns_service_refused"),
			want:  model.FailureReason("dns_service_refused"), layer: model.LayerDNS,
		},
		{
			name:  "DNS SERVFAIL",
			value: dnsApplicationObservation("servfail", "dns_service_servfail"),
			want:  model.FailureReason("dns_service_servfail"), layer: model.LayerDNS,
		},
		{
			name:  "DNS malformed",
			value: dnsApplicationObservation("malformed_response", "dns_service_malformed_response"),
			want:  model.FailureReason("dns_service_malformed_response"), layer: model.LayerDNS,
		},
		{
			name:  "DNS timeout",
			value: dnsApplicationObservation("timeout", "dns_service_timeout"),
			want:  model.FailureReason("dns_service_timeout"), layer: model.LayerDNS,
		},
		{
			name:  "SSH timeout",
			value: protocolApplicationObservation(model.ApplicationProtocolSSH, model.ApplicationProtocolResultTimeout),
			want:  model.FailureReasonSSHTimeout, layer: model.LayerSSH,
		},
		{
			name:  "RDP rejection",
			value: protocolApplicationObservation(model.ApplicationProtocolRDP, model.ApplicationProtocolResultRejected),
			want:  model.FailureReasonRDPNegotiationRejected, layer: model.LayerRDP,
		},
		{
			name:  "SMB rejection",
			value: smbApplicationObservation(model.SMBResultProtocolRejection, model.FailureReasonNone),
			want:  model.FailureReasonSMBProtocolRejection, layer: model.LayerSMB,
		},
		{
			name:  "SMB TCP refusal",
			value: smbApplicationObservation(model.SMBResultTCPFailure, model.FailureReasonTCPConnectionRefused),
			want:  model.FailureReasonTCPConnectionRefused, layer: model.LayerTCP,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := DiagnoseObservations(test.value)
			if len(got) != 1 || got[0].FailureReason != test.want || got[0].Layer != test.layer {
				t.Fatalf("diagnosis = %#v, want %q at %q", got, test.want, test.layer)
			}
		})
	}
}

func TestDiagnoseObservationsTreatsDNSLaneDivergenceAsSuccessBoundary(t *testing.T) {
	value := canonicalApplicationEnvelope(model.ApplicationProtocolDNS)
	value.Application = model.ApplicationObservation{
		Applicability:    model.ObservationApplicabilityApplicable,
		Protocol:         model.ApplicationProtocolDNS,
		RequestAttempted: true,
		ResponseReceived: true,
		EvidenceIDs:      []string{"dns-udp", "dns-tcp"},
		DNS: &model.DNSApplicationObservation{
			Result: model.DNSApplicationResultPartial, Divergence: true,
			UDP: model.DNSApplicationTransportObservation{Attempted: true, ResponseReceived: true, Outcome: "success"},
			TCP: model.DNSApplicationTransportObservation{Attempted: true, ResponseReceived: true, Outcome: "refused", FailureReason: model.FailureReason("dns_service_refused")},
		},
	}
	if got := DiagnoseObservations(value); got != nil {
		t.Fatalf("partial DNS divergence became a failure: %#v", got)
	}
}

func TestDiagnoseReportDoesNotReintroduceStaleBuiltInApplicationProbeFacts(t *testing.T) {
	value := canonicalApplicationEnvelope(model.ApplicationProtocolSSH)
	value.Application = model.ApplicationObservation{
		Applicability:      model.ObservationApplicabilityApplicable,
		Protocol:           model.ApplicationProtocolSSH,
		RequestAttempted:   true,
		ResponseReceived:   true,
		HandshakeAttempted: true,
		HandshakeComplete:  true,
		ProtocolResult:     model.ApplicationProtocolResultSuccess,
		EvidenceIDs:        []string{"ssh-success"},
	}
	report := model.DiagnosticReport{Target: valueToTarget(value), Observations: value, Probes: []model.ProbeResult{{
		Name: "stale-ssh", Status: model.ProbeStatusFailed,
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonSSHNonSSHResponse, Layer: model.LayerSSH, FaultDomain: model.FaultDomainSSH},
	}}}
	if got := DiagnoseReport(report); got.Findings != nil {
		t.Fatalf("stale SSH interpretation overrode canonical success: %#v", got.Findings)
	}
}

func TestDiagnoseObservationsDoesNotTreatCustomTLSOrTCPAsHTTP(t *testing.T) {
	for _, protocol := range []model.ApplicationProtocol{model.ApplicationProtocolTLS, model.ApplicationProtocolCustom} {
		value := canonicalApplicationEnvelope(protocol)
		value.Application = model.ApplicationObservation{Applicability: model.ObservationApplicabilityInapplicable, Protocol: protocol, RequestAttempted: true, Result: model.HTTPResultRequestFailure, FailureReason: model.FailureReasonHTTPFailure}
		if got := DiagnoseObservations(value); got != nil {
			t.Fatalf("%s application became HTTP diagnosis: %#v", protocol, got)
		}
	}
}

func dnsApplicationObservation(outcome, reason string) model.Observations {
	value := canonicalApplicationEnvelope(model.ApplicationProtocolDNS)
	value.Application = model.ApplicationObservation{
		Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolDNS,
		RequestAttempted: true, ResponseReceived: true, EvidenceIDs: []string{"dns-udp", "dns-tcp"},
		DNS: &model.DNSApplicationObservation{Result: model.DNSApplicationResultFailure, FailureReason: model.FailureReason(reason),
			UDP: model.DNSApplicationTransportObservation{Attempted: true, ResponseReceived: true, Outcome: outcome, FailureReason: model.FailureReason(reason)},
			TCP: model.DNSApplicationTransportObservation{Attempted: true, ResponseReceived: true, Outcome: outcome, FailureReason: model.FailureReason(reason)}},
	}
	return value
}

func protocolApplicationObservation(protocol model.ApplicationProtocol, result model.ApplicationProtocolResult) model.Observations {
	value := canonicalApplicationEnvelope(protocol)
	value.Application = model.ApplicationObservation{Applicability: model.ObservationApplicabilityApplicable, Protocol: protocol, RequestAttempted: true, HandshakeAttempted: true, ProtocolResult: result, EvidenceIDs: []string{"protocol"}}
	return value
}

func smbApplicationObservation(result model.SMBResult, reason model.FailureReason) model.Observations {
	value := canonicalApplicationEnvelope(model.ApplicationProtocolSMB)
	value.Application = model.ApplicationObservation{Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolSMB, RequestAttempted: true, FailureReason: reason, EvidenceIDs: []string{"smb"}, SMB: &model.SMBApplicationObservation{Result: result}}
	return value
}
