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
