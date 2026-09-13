package diagnosis

import (
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func TestPacketFlowEvidenceStrengthensTCPDiagnosis(t *testing.T) {
	target := model.Target{Host: "203.0.113.10", Port: 443}
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	completed := started.Add(time.Second)
	base := model.ProbeResult{
		Name: "tcp", Target: target, SessionID: "session-1", ProbeID: "tcp", CorrelationID: "session-1/tcp",
		Status: model.ProbeStatusFailed,
		Timing: model.Timing{StartedAt: &started, CompletedAt: &completed},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonTCPTimeout,
			Layer:         model.LayerTCP,
			FaultDomain:   model.FaultDomainTransport,
		},
	}

	for _, test := range []struct {
		name       string
		outcome    model.PacketFlowOutcome
		wantReason model.FailureReason
		wantLayer  model.Layer
		wantDomain model.FaultDomain
		wantEmpty  bool
	}{
		{name: "syn ack confirms endpoint", outcome: model.PacketFlowOutcomeTCPSYNACK, wantEmpty: true},
		{name: "handshake confirmation confirms endpoint", outcome: model.PacketFlowOutcomeTCPHandshakeConfirmed, wantEmpty: true},
		{name: "rst replaces timeout", outcome: model.PacketFlowOutcomeTCPRST, wantReason: model.FailureReasonTCPConnectionReset, wantLayer: model.LayerTCP, wantDomain: model.FaultDomainTransport},
		{name: "complete capture with no syn is local observation", outcome: model.PacketFlowOutcomeProbeNotEmitted, wantReason: model.FailureReasonTCPSYNNotObserved, wantLayer: model.LayerTCP, wantDomain: model.FaultDomainLocal},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := model.PacketFlowEvidence{
				SessionID: "session-1", ProbeID: "tcp", CorrelationID: "session-1/tcp", Target: target,
				CaptureStatus: model.PacketCaptureStatusAvailable, WindowStartedAt: started, WindowCompletedAt: completed,
				Outcome: test.outcome, Certainty: model.EvidenceCertaintyConfirmedEndpointResponse,
			}
			evidence, err := model.PacketFlowEvidenceFor(flow)
			if err != nil {
				t.Fatalf("packet flow evidence: %v", err)
			}
			result := base
			result.Evidence = []model.Evidence{evidence}
			got := Diagnose([]model.ProbeResult{result})
			if test.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("diagnosis = %#v, want packet confirmation to contradict timeout", got)
				}
				return
			}
			if len(got) == 0 || got[0].FailureReason != test.wantReason || got[0].Layer != test.wantLayer || got[0].FaultDomain != test.wantDomain {
				t.Fatalf("diagnosis = %#v", got)
			}
		})
	}
}

func TestUnavailablePacketCaptureDoesNotChangeTCPDiagnosis(t *testing.T) {
	target := model.Target{Host: "203.0.113.10", Port: 443}
	flow := model.PacketFlowEvidence{
		SessionID: "session-1", ProbeID: "tcp", CorrelationID: "session-1/tcp", Target: target,
		CaptureStatus: model.PacketCaptureStatusInsufficientPrivilege,
		Outcome:       model.PacketFlowOutcomeCaptureUnavailable, Certainty: model.EvidenceCertaintyUnobservableSegment,
	}
	evidence, err := model.PacketFlowEvidenceFor(flow)
	if err != nil {
		t.Fatalf("packet flow evidence: %v", err)
	}
	result := failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport)
	result.Target = target
	result.SessionID, result.ProbeID, result.CorrelationID = "session-1", "tcp", "session-1/tcp"
	result.Evidence = []model.Evidence{evidence}
	got := Diagnose([]model.ProbeResult{result})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPTimeout {
		t.Fatalf("diagnosis = %#v, want original timeout with unavailable capture", got)
	}
}
