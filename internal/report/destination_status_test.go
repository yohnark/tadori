package report

import (
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestDestinationStatusSemanticMatrix(t *testing.T) {
	tests := []struct {
		name         string
		observations model.Observations
		wantStatus   DestinationStatusState
		wantDetail   string
		wantReason   model.FailureReason
		wantProbe    string
		wantEvidence string
	}{
		{
			name: "HTTP success",
			observations: destinationObservations(model.ServiceProfileHTTPS, model.ApplicationObservation{
				Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolHTTPS,
				RequestAttempted: true, ResponseReceived: true, Result: model.HTTPResultSuccess, StatusCode: 200,
				ProbeNames: []string{"http"}, EvidenceIDs: []string{"http-success"}, Provenance: []string{"http response"},
			}),
			wantStatus: DestinationStatusReachable, wantDetail: "HTTP returned 200.", wantProbe: "http", wantEvidence: "http-success",
		},
		{
			name: "HTTP 503",
			observations: destinationObservations(model.ServiceProfileHTTPS, model.ApplicationObservation{
				Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolHTTPS,
				RequestAttempted: true, ResponseReceived: true, Result: model.HTTPResultStatusFailure, StatusCode: 503,
				FailureReason: model.FailureReasonHTTPStatusCode, ProbeNames: []string{"http"}, EvidenceIDs: []string{"http-503"},
			}),
			wantStatus: DestinationStatusDegraded, wantDetail: "HTTP returned 503.", wantReason: model.FailureReasonHTTPStatusCode,
		},
		{
			name: "HTTP redirect",
			observations: destinationObservations(model.ServiceProfileHTTP, model.ApplicationObservation{
				Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolHTTP,
				RequestAttempted: true, ResponseReceived: true, Result: model.HTTPResultSuccess, StatusCode: 302,
			}),
			wantStatus: DestinationStatusReachable, wantDetail: "HTTP returned 302.",
		},
		{
			name: "TCP refusal",
			observations: destinationObservationsWithTransport(model.ServiceProfileCustomTCP,
				model.TransportObservation{Applicability: model.ObservationApplicabilityApplicable, ConnectionOutcome: model.TransportConnectionOutcomeRefused, FailureReason: model.FailureReasonTCPConnectionRefused, ProbeNames: []string{"tcp"}, EvidenceIDs: []string{"tcp-refused"}}),
			wantStatus: DestinationStatusUnreachable, wantDetail: "TCP connection was refused.", wantReason: model.FailureReasonTCPConnectionRefused,
		},
		{
			name: "TLS failure after TCP success",
			observations: destinationObservationsWithTransportAndSecurity(model.ServiceProfileHTTPS,
				model.TransportObservation{Applicability: model.ObservationApplicabilityApplicable, Connected: true, ConnectionOutcome: model.TransportConnectionOutcomeConnected, ProbeNames: []string{"tcp"}, EvidenceIDs: []string{"tcp-connected"}},
				model.SecurityObservation{Applicability: model.ObservationApplicabilityApplicable, Attempted: true, FailureReason: model.FailureReasonTLSHandshakeFailure, ProbeNames: []string{"tls"}, EvidenceIDs: []string{"tls-failure"}}),
			wantStatus: DestinationStatusDegraded, wantDetail: "TLS handshake failed after transport connection.", wantReason: model.FailureReasonTLSHandshakeFailure,
		},
		{
			name: "DNS failure before transport",
			observations: model.Observations{
				Endpoint:       model.EndpointObservation{RequestedIdentity: "missing.example", Service: serviceProfile(model.ServiceProfileHTTPS)},
				NameResolution: model.NameResolutionObservation{RequestedName: "missing.example", Certainty: model.ObservationCertaintyObserved, FailureReason: model.FailureReasonDNSNXDomain, ProbeNames: []string{"dns"}, EvidenceIDs: []string{"dns-nxdomain"}},
			},
			wantStatus: DestinationStatusIndeterminate, wantDetail: "Name resolution did not establish a usable endpoint.", wantReason: model.FailureReasonDNSNXDomain,
		},
		{
			name: "SMB negotiated",
			observations: destinationObservations(model.ServiceProfileSMB, model.ApplicationObservation{
				Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolSMB,
				RequestAttempted: true, ResponseReceived: true, SMB: &model.SMBApplicationObservation{Result: model.SMBResultNegotiated, Negotiated: true},
				ProbeNames: []string{"smb"}, EvidenceIDs: []string{"smb-success"},
			}),
			wantStatus: DestinationStatusReachable,
		},
		{
			name: "SMB protocol rejection after TCP success",
			observations: destinationObservationsWithTransportAndApplication(model.ServiceProfileSMB,
				model.TransportObservation{Applicability: model.ObservationApplicabilityApplicable, Connected: true, ConnectionOutcome: model.TransportConnectionOutcomeConnected, EvidenceIDs: []string{"tcp-connected"}},
				model.ApplicationObservation{Applicability: model.ObservationApplicabilityApplicable, Protocol: model.ApplicationProtocolSMB, RequestAttempted: true, ResponseReceived: true, FailureReason: model.FailureReasonSMBProtocolRejection, SMB: &model.SMBApplicationObservation{Result: model.SMBResultProtocolRejection}, EvidenceIDs: []string{"smb-rejected"}}),
			wantStatus: DestinationStatusDegraded, wantDetail: "SMB protocol negotiation was rejected or failed.", wantReason: model.FailureReasonSMBProtocolRejection,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := DestinationStatusFromObservations(test.observations)
			if got.Status != test.wantStatus || got.Detail != test.wantDetail && test.wantDetail != "" {
				t.Fatalf("status = %#v, want %q/%q", got, test.wantStatus, test.wantDetail)
			}
			if test.wantReason != "" && got.FailureReason != test.wantReason {
				t.Fatalf("failure reason = %q, want %q", got.FailureReason, test.wantReason)
			}
			if test.wantProbe != "" && !containsDestinationString(got.ProbeNames, test.wantProbe) {
				t.Fatalf("probe refs = %#v, want %q", got.ProbeNames, test.wantProbe)
			}
			if test.wantEvidence != "" && !containsDestinationString(got.EvidenceIDs, test.wantEvidence) {
				t.Fatalf("evidence refs = %#v, want %q", got.EvidenceIDs, test.wantEvidence)
			}
		})
	}
}

func TestDestinationStatusProtocolAndEvidenceBoundaries(t *testing.T) {
	tests := []struct {
		name         string
		service      model.ServiceProfileID
		application  model.ApplicationObservation
		wantStatus   DestinationStatusState
		wantContains string
	}{
		{name: "SSH success", service: model.ServiceProfileSSH, application: model.ApplicationObservation{Protocol: model.ApplicationProtocolSSH, RequestAttempted: true, HandshakeAttempted: true, HandshakeComplete: true, ProtocolResult: model.ApplicationProtocolResultSuccess}, wantStatus: DestinationStatusReachable, wantContains: "SSH handshake succeeded."},
		{name: "SSH malformed after connection", service: model.ServiceProfileSSH, application: model.ApplicationObservation{Protocol: model.ApplicationProtocolSSH, RequestAttempted: true, HandshakeAttempted: true, ResponseReceived: true, TransportConnected: true, ProtocolResult: model.ApplicationProtocolResultMalformed, FailureReason: model.FailureReasonSSHBannerMalformed}, wantStatus: DestinationStatusDegraded, wantContains: "SSH protocol handshake was rejected or malformed."},
		{name: "RDP success", service: model.ServiceProfileRDP, application: model.ApplicationObservation{Protocol: model.ApplicationProtocolRDP, RequestAttempted: true, HandshakeAttempted: true, HandshakeComplete: true, ProtocolResult: model.ApplicationProtocolResultSuccess}, wantStatus: DestinationStatusReachable, wantContains: "RDP handshake succeeded."},
		{name: "RDP rejection after connection", service: model.ServiceProfileRDP, application: model.ApplicationObservation{Protocol: model.ApplicationProtocolRDP, RequestAttempted: true, HandshakeAttempted: true, ResponseReceived: true, TransportConnected: true, ProtocolResult: model.ApplicationProtocolResultRejected, FailureReason: model.FailureReasonRDPNegotiationRejected}, wantStatus: DestinationStatusDegraded, wantContains: "RDP protocol handshake was rejected or malformed."},
		{name: "unsupported", service: model.ServiceProfileHTTPS, application: model.ApplicationObservation{Applicability: model.ObservationApplicabilityUnsupported, Protocol: model.ApplicationProtocolHTTPS, Result: model.HTTPResultUnsupported, FailureReason: model.FailureReasonUnsupported}, wantStatus: DestinationStatusIndeterminate, wantContains: "unsupported"},
		{name: "no evidence", service: model.ServiceProfileHTTPS, application: model.ApplicationObservation{Applicability: model.ObservationApplicabilityNotAttempted, Protocol: model.ApplicationProtocolHTTPS, Result: model.HTTPResultNotAttempted}, wantStatus: DestinationStatusIndeterminate, wantContains: "not attempted"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := DestinationStatusFromObservations(destinationObservations(test.service, test.application))
			if got.Status != test.wantStatus || !strings.Contains(got.Detail, test.wantContains) {
				t.Fatalf("status = %#v, want %q containing %q", got, test.wantStatus, test.wantContains)
			}
		})
	}
}

func TestDestinationStatusForReportUsesObservationsAuthority(t *testing.T) {
	report := model.DiagnosticReport{
		Target: model.NewTarget("legacy.example", 443),
		Observations: destinationObservations(model.ServiceProfileHTTPS, model.ApplicationObservation{
			Protocol: model.ApplicationProtocolHTTPS, ResponseReceived: true, Result: model.HTTPResultSuccess, StatusCode: 204,
		}),
	}
	status := DestinationStatusForReport(report)
	if status.Status != DestinationStatusReachable || status.RequestedIdentity != "service.example" || status.RequestedService != "HTTPS" {
		t.Fatalf("destination status = %#v", status)
	}
}

func destinationObservations(service model.ServiceProfileID, application model.ApplicationObservation) model.Observations {
	profile := serviceProfile(service)
	endpoint := model.Endpoint{Address: "192.0.2.44", Port: profile.DefaultPort, Family: model.EndpointFamilyIPv4, EvidenceIDs: []string{"endpoint"}}
	return model.Observations{
		Endpoint:    model.EndpointObservation{RequestedIdentity: "service.example", Service: profile, ApplicationProtocol: profile.ApplicationProtocol, TransportProtocol: profile.TransportProtocol, Port: profile.DefaultPort, TestedEndpoint: &endpoint},
		Application: application,
	}
}

func destinationObservationsWithTransport(service model.ServiceProfileID, transport model.TransportObservation) model.Observations {
	observations := destinationObservations(service, model.ApplicationObservation{})
	observations.Transport = transport
	return observations
}

func destinationObservationsWithTransportAndSecurity(service model.ServiceProfileID, transport model.TransportObservation, security model.SecurityObservation) model.Observations {
	observations := destinationObservations(service, model.ApplicationObservation{})
	observations.Transport = transport
	observations.Security = security
	return observations
}

func destinationObservationsWithTransportAndApplication(service model.ServiceProfileID, transport model.TransportObservation, application model.ApplicationObservation) model.Observations {
	observations := destinationObservations(service, application)
	observations.Transport = transport
	return observations
}

func serviceProfile(id model.ServiceProfileID) model.ServiceProfile {
	profile, err := model.LookupServiceProfile(id)
	if err != nil {
		panic(err)
	}
	return profile
}

func containsDestinationString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
