package observations

import (
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func protocolTarget(t *testing.T, profileID model.ServiceProfileID, host string, port uint16) model.Target {
	t.Helper()
	profile, err := model.LookupServiceProfile(profileID)
	if err != nil {
		t.Fatal(err)
	}
	return model.Target{OriginalInput: host, RequestedIdentity: host, Service: profile, ApplicationProtocol: profile.ApplicationProtocol, TransportProtocol: profile.TransportProtocol, Port: port}
}

func TestBuildProjectsSSHHandshakeSeparatelyFromTCPSuccess(t *testing.T) {
	target := protocolTarget(t, model.ServiceProfileSSH, "ssh-fixture.test", 2222)
	tcpProbe := model.ProbeResult{
		Name: "tcp", Target: target, Status: model.ProbeStatusPassed,
		Evidence: []model.Evidence{fixtureEvidence(t, "tcp-success", model.EvidenceKindTCPConnection, "fixture", map[string]any{
			"requested_endpoint": "ssh-fixture.test:2222", "remote_endpoint": "192.0.2.22:2222", "tested_endpoint": "192.0.2.22:2222",
		})},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonNone, Layer: model.LayerTCP, FaultDomain: model.FaultDomainTransport},
	}
	sshProbe := model.ProbeResult{
		Name: "ssh", Target: target, Status: model.ProbeStatusFailed,
		Evidence: []model.Evidence{fixtureEvidence(t, "ssh-non-ssh", model.EvidenceKindSSHHandshake, "fixture", map[string]any{
			"transport_connected": true, "banner_received": true, "banner_valid": false, "response_class": "non_ssh",
		})},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonSSHNonSSHResponse, Layer: model.LayerSSH, FaultDomain: model.FaultDomainSSH},
	}

	got := Build(target, []model.ProbeResult{sshProbe, tcpProbe})
	if !got.Transport.Connected || got.Transport.ConnectionOutcome != model.TransportConnectionOutcomeConnected {
		t.Fatalf("transport = %#v", got.Transport)
	}
	if got.Application.Protocol != model.ApplicationProtocolSSH || !got.Application.TransportConnected || got.Application.HandshakeComplete || got.Application.ProtocolResult != model.ApplicationProtocolResultFailure {
		t.Fatalf("application = %#v", got.Application)
	}
	if got.Application.FailureReason != model.FailureReasonSSHNonSSHResponse || got.Application.FaultDomain != model.FaultDomainSSH {
		t.Fatalf("application failure = %#v", got.Application)
	}
}

func TestBuildProjectsSuccessfulRDPNegotiationFacts(t *testing.T) {
	target := protocolTarget(t, model.ServiceProfileRDP, "rdp-fixture.test", 3390)
	probe := model.ProbeResult{
		Name: "rdp", Target: target, Status: model.ProbeStatusPassed,
		Evidence: []model.Evidence{fixtureEvidence(t, "rdp-success", model.EvidenceKindRDPNegotiation, "fixture", map[string]any{
			"transport_connected": true, "negotiation_attempted": true, "negotiation_complete": true,
			"requested_protocols": []string{"tls", "credssp"}, "negotiated_protocol": "tls", "response_type": "success",
		})},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonNone, Layer: model.LayerRDP, FaultDomain: model.FaultDomainRDP},
	}

	got := Build(target, []model.ProbeResult{probe})
	if got.Application.Protocol != model.ApplicationProtocolRDP || !got.Application.HandshakeAttempted || !got.Application.HandshakeComplete || got.Application.ProtocolResult != model.ApplicationProtocolResultSuccess {
		t.Fatalf("application = %#v", got.Application)
	}
	if len(got.Application.RequestedSecurityProtocols) != 2 || got.Application.NegotiatedSecurityProtocol != "tls" {
		t.Fatalf("RDP security facts = %#v", got.Application)
	}
}
