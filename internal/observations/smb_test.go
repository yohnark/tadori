package observations

import (
	"encoding/json"
	"testing"

	"github.com/yohnark/tadori/internal/model"
	smbprobe "github.com/yohnark/tadori/internal/probe/smb"
)

func TestBuildProjectsSMBNegotiationIntoCanonicalApplicationObservation(t *testing.T) {
	target, err := model.ParseTarget(model.TargetIntent{Input: `\fileserver01\diagnostics`, Service: model.ServiceProfileSMB})
	if err != nil {
		t.Fatal(err)
	}
	if target.Resource != "/diagnostics" {
		t.Fatalf("parsed resource = %q", target.Resource)
	}
	port := uint16(1445)
	endpoint := &model.Endpoint{Address: "192.0.2.44", Port: port, Family: model.EndpointFamilyIPv4}
	target.SelectedEndpoint = endpoint
	target.TestedEndpoint = endpoint
	evidence := smbprobe.NegotiationEvidence{
		RequestedEndpoint: `fileserver01:1445`, TestedEndpoint: "192.0.2.44:1445",
		Connected: true, ResponseReceived: true, Negotiated: true,
		Dialect: "SMB 3.1.1", DialectRevision: 0x0311,
		Capabilities: []string{"DFS", "LARGE_MTU"}, ServerGUID: "00112233445566778899aabbccddeeff",
		SecurityMode: 1, MaxTransactSize: 0x200000, MaxReadSize: 0x100000, MaxWriteSize: 0x100000,
		ResponseBytes: 128, FailureReason: model.FailureReasonNone,
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	probe := model.ProbeResult{
		Name: "smb", Target: target, Status: model.ProbeStatusPassed,
		Evidence:       []model.Evidence{{ID: "smb-success", Kind: model.EvidenceKindSMBNegotiation, Source: "probe:smb", Raw: raw}},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonNone, Layer: model.LayerSMB, FaultDomain: model.FaultDomainSMB},
	}

	observations := Build(target, []model.ProbeResult{probe})
	application := observations.Application
	if application.Protocol != model.ApplicationProtocolSMB || application.Applicability != model.ObservationApplicabilityApplicable {
		t.Fatalf("application applicability = %#v", application)
	}
	if !application.RequestAttempted || !application.ResponseReceived || application.FailureReason != model.FailureReasonNone {
		t.Fatalf("application state = %#v", application)
	}
	if application.SMB == nil || application.SMB.Result != model.SMBResultNegotiated || !application.SMB.Negotiated {
		t.Fatalf("SMB application = %#v", application.SMB)
	}
	if application.SMB.Dialect != "SMB 3.1.1" || application.SMB.ServerGUID == "" || application.SMB.MaxReadSize != 0x100000 {
		t.Fatalf("SMB facts = %#v", application.SMB)
	}
	if observations.Endpoint.Resource != "/diagnostics" || observations.Endpoint.RequestedIdentity != "fileserver01" {
		t.Fatalf("endpoint resource identity = %#v", observations.Endpoint)
	}
	if len(application.EvidenceIDs) != 1 || application.EvidenceIDs[0] != "smb-success" {
		t.Fatalf("application evidence IDs = %#v", application.EvidenceIDs)
	}
}

func TestBuildKeepsSMBTCPFailureSeparateFromProtocolAvailability(t *testing.T) {
	target, err := model.ParseTarget(model.TargetIntent{Input: "192.0.2.44", Service: model.ServiceProfileSMB})
	if err != nil {
		t.Fatal(err)
	}
	evidence := smbprobe.NegotiationEvidence{
		RequestedEndpoint: "192.0.2.44:445", FailureReason: model.FailureReasonTCPConnectionRefused,
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	got := Build(target, []model.ProbeResult{{
		Name: "smb", Status: model.ProbeStatusFailed,
		Evidence:       []model.Evidence{{ID: "smb-refused", Kind: model.EvidenceKindSMBNegotiation, Source: "probe:smb", Raw: raw}},
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonTCPConnectionRefused, Layer: model.LayerTCP, FaultDomain: model.FaultDomainTransport},
	}}).Application
	if got.SMB == nil || got.SMB.Result != model.SMBResultTCPFailure {
		t.Fatalf("SMB result = %#v", got.SMB)
	}
	if got.ResponseReceived || got.FailureReason != model.FailureReasonTCPConnectionRefused || got.FaultDomain != model.FaultDomainTransport {
		t.Fatalf("TCP failure application = %#v", got)
	}
	if got.Applicability != model.ObservationApplicabilityApplicable || !got.RequestAttempted {
		t.Fatalf("TCP failure applicability = %#v", got)
	}
}
