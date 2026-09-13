package packet

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func TestCorrelateTCPSYNToSYNACK(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	start := scope.WindowStarted.Add(10 * time.Millisecond)
	ack := start.Add(4 * time.Millisecond)
	result := tcpResult(scope, "127.0.0.5:49152", "203.0.113.10:443")
	flow := Correlate(CorrelationInput{
		Scope:        scope,
		Result:       result,
		ProbeStarted: true,
		Capture: CaptureResult{Source: "fixture", Complete: true, Observations: []model.PacketObservation{
			tcpObservation(scope, "syn", model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, "127.0.0.5", 49152, "203.0.113.10", 443, start),
			tcpObservation(scope, "ack", model.PacketObservationInboundTCPSYNACK, model.PacketDirectionInbound, "203.0.113.10", 443, "127.0.0.5", 49152, ack),
		}},
	})
	if flow.ProbeEmission != model.PacketEmissionObserved || flow.Outcome != model.PacketFlowOutcomeTCPSYNACK {
		t.Fatalf("flow = %#v", flow)
	}
	if flow.Certainty != model.EvidenceCertaintyConfirmedEndpointResponse {
		t.Fatalf("certainty = %q, want endpoint response", flow.Certainty)
	}
	if !reflect.DeepEqual(flow.MatchedObservationIDs, []string{"ack", "syn"}) {
		t.Fatalf("matched IDs = %#v, want deterministic sorted IDs", flow.MatchedObservationIDs)
	}
}

func TestCorrelateTCPSYNToRST(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	result := tcpResult(scope, "127.0.0.5:49153", "203.0.113.10:443")
	flow := Correlate(CorrelationInput{
		Scope: scope, Result: result, ProbeStarted: true,
		Capture: CaptureResult{Source: "fixture", Complete: true, Observations: []model.PacketObservation{
			tcpObservation(scope, "syn", model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, "127.0.0.5", 49153, "203.0.113.10", 443, scope.WindowStarted.Add(time.Millisecond)),
			tcpObservation(scope, "rst", model.PacketObservationTCPRST, model.PacketDirectionInbound, "203.0.113.10", 443, "127.0.0.5", 49153, scope.WindowStarted.Add(2*time.Millisecond)),
		}},
	})
	if flow.Outcome != model.PacketFlowOutcomeTCPRST || flow.ProbeEmission != model.PacketEmissionObserved {
		t.Fatalf("flow = %#v", flow)
	}
}

func TestCorrelateICMPTimeExceededToPathTTL(t *testing.T) {
	scope := testScope(ProbeTypePath)
	when := scope.WindowStarted.Add(3 * time.Millisecond)
	emission := model.PacketObservation{
		ID: "echo", SessionID: scope.Identity.SessionID, ProbeID: scope.Identity.ProbeID, CorrelationID: scope.Identity.CorrelationID,
		Kind: model.PacketObservationOutboundICMPEcho, Protocol: model.PacketProtocolICMP, Direction: model.PacketDirectionOutbound,
		SourceAddress: "192.0.2.5", DestinationAddress: "203.0.113.10", ICMPIdentifier: 7, ICMPSequence: 0x0401,
		ProbeTTL: 4, ProbeAttempt: 1, ObservedAt: when,
	}
	response := model.PacketObservation{
		ID: "time", SessionID: scope.Identity.SessionID, ProbeID: scope.Identity.ProbeID, CorrelationID: scope.Identity.CorrelationID,
		Kind: model.PacketObservationICMPTimeExceeded, Protocol: model.PacketProtocolICMP, Direction: model.PacketDirectionInbound,
		SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.5", ICMPType: 11, ICMPCode: 0,
		QuotedDestinationAddress: "203.0.113.10", QuotedICMPIdentifier: 7, QuotedICMPSequence: 0x0401,
		ProbeTTL: 4, ProbeAttempt: 1, ObservedAt: when.Add(time.Millisecond),
	}
	flow := Correlate(CorrelationInput{Scope: scope, ProbeStarted: true, Capture: CaptureResult{
		Source: "fixture", Complete: true, Observations: []model.PacketObservation{emission, response},
	}})
	if flow.Outcome != model.PacketFlowOutcomeICMPTimeExceeded || flow.Certainty != model.EvidenceCertaintyObservedTTLResponder {
		t.Fatalf("flow = %#v", flow)
	}
	if flow.CorrelationMethod != "correlation_id_and_path_key" {
		t.Fatalf("correlation method = %q", flow.CorrelationMethod)
	}
}

func TestCorrelateICMPUnreachablePreservesExactTypeAndCode(t *testing.T) {
	scope := testScope(ProbeTypePath)
	when := scope.WindowStarted.Add(time.Millisecond)
	flow := Correlate(CorrelationInput{Scope: scope, ProbeStarted: true, Capture: CaptureResult{
		Source: "fixture", Complete: true, Observations: []model.PacketObservation{
			{ID: "echo", SessionID: "session-1", ProbeID: "path", CorrelationID: "session-1/path", Kind: model.PacketObservationOutboundICMPEcho, Protocol: model.PacketProtocolICMP, Direction: model.PacketDirectionOutbound, SourceAddress: "192.0.2.5", DestinationAddress: "203.0.113.10", ICMPIdentifier: 8, ICMPSequence: 3, ProbeTTL: 2, ObservedAt: when},
			{ID: "unreachable", SessionID: "session-1", ProbeID: "path", CorrelationID: "session-1/path", Kind: model.PacketObservationICMPUnreachable, Protocol: model.PacketProtocolICMP, Direction: model.PacketDirectionInbound, SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.5", ICMPType: 3, ICMPCode: 13, QuotedDestinationAddress: "203.0.113.10", QuotedICMPIdentifier: 8, QuotedICMPSequence: 3, ProbeTTL: 2, ObservedAt: when.Add(time.Millisecond)},
		},
	}})
	if flow.Outcome != model.PacketFlowOutcomeICMPUnreachable {
		t.Fatalf("outcome = %q", flow.Outcome)
	}
	var unreachable model.PacketObservation
	for _, observation := range flow.Observations {
		if observation.ID == "unreachable" {
			unreachable = observation
		}
	}
	if unreachable.ICMPType != 3 || unreachable.ICMPCode != 13 {
		t.Fatalf("ICMP evidence changed: %#v", unreachable)
	}
}

func TestCorrelatePathDoesNotUseProbeIdentityAloneAcrossTTLs(t *testing.T) {
	scope := testScope(ProbeTypePath)
	when := scope.WindowStarted.Add(time.Millisecond)
	emission := func(id string, ttl uint8) model.PacketObservation {
		return model.PacketObservation{
			ID: id, SessionID: scope.Identity.SessionID, ProbeID: scope.Identity.ProbeID, CorrelationID: scope.Identity.CorrelationID,
			Kind: model.PacketObservationOutboundICMPEcho, Protocol: model.PacketProtocolICMP, Direction: model.PacketDirectionOutbound,
			SourceAddress: "192.0.2.5", DestinationAddress: "203.0.113.10", ICMPIdentifier: 9, ICMPSequence: uint16(ttl), ProbeTTL: ttl, ObservedAt: when,
		}
	}
	response := model.PacketObservation{
		ID: "time", SessionID: scope.Identity.SessionID, ProbeID: scope.Identity.ProbeID, CorrelationID: scope.Identity.CorrelationID,
		Kind: model.PacketObservationICMPTimeExceeded, Protocol: model.PacketProtocolICMP, Direction: model.PacketDirectionInbound,
		SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.5", QuotedDestinationAddress: "203.0.113.10", ProbeTTL: 2, ObservedAt: when.Add(time.Millisecond),
	}
	flow := Correlate(CorrelationInput{Scope: scope, ProbeStarted: true, Capture: CaptureResult{
		Source: "fixture", Complete: true, Observations: []model.PacketObservation{emission("ttl-1", 1), emission("ttl-2", 2), response},
	}})
	if flow.Outcome != model.PacketFlowOutcomeICMPTimeExceeded || !reflect.DeepEqual(flow.MatchedObservationIDs, []string{"time", "ttl-2"}) {
		t.Fatalf("flow = %#v, want only the TTL-2 pair", flow)
	}
}

func TestCorrelateIgnoresUnrelatedTrafficAndIsolatesIdentityAndTuple(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	result := tcpResult(scope, "127.0.0.5:49154", "203.0.113.10:443")
	observations := []model.PacketObservation{
		tcpObservation(scope, "syn", model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, "127.0.0.5", 49154, "203.0.113.10", 443, scope.WindowStarted.Add(time.Millisecond)),
		tcpObservation(scope, "matching-rst", model.PacketObservationTCPRST, model.PacketDirectionInbound, "203.0.113.10", 443, "127.0.0.5", 49154, scope.WindowStarted.Add(2*time.Millisecond)),
		{ID: "wrong-session", SessionID: "other", ProbeID: "tcp", CorrelationID: "other/tcp", Kind: model.PacketObservationTCPRST, Protocol: model.PacketProtocolTCP, Direction: model.PacketDirectionInbound, SourceAddress: "203.0.113.10", SourcePort: 443, DestinationAddress: "127.0.0.5", DestinationPort: 49154, ObservedAt: scope.WindowStarted.Add(2 * time.Millisecond)},
		tcpObservation(scope, "wrong-port", model.PacketObservationTCPRST, model.PacketDirectionInbound, "203.0.113.10", 443, "127.0.0.5", 49155, scope.WindowStarted.Add(2*time.Millisecond)),
	}
	flow := Correlate(CorrelationInput{Scope: scope, Result: result, ProbeStarted: true, Capture: CaptureResult{Source: "fixture", Complete: true, Observations: observations}})
	if flow.Outcome != model.PacketFlowOutcomeTCPRST || len(flow.Observations) != 2 {
		t.Fatalf("isolated flow = %#v", flow)
	}
}

func TestCorrelateNoResponseAndCancellationSemantics(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	result := tcpResult(scope, "127.0.0.5:49156", "203.0.113.10:443")
	noResponse := Correlate(CorrelationInput{Scope: scope, Result: result, ProbeStarted: true, Capture: CaptureResult{
		Source: "fixture", Complete: true, Observations: []model.PacketObservation{
			tcpObservation(scope, "syn", model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, "127.0.0.5", 49156, "203.0.113.10", 443, scope.WindowStarted.Add(time.Millisecond)),
		},
	}})
	if noResponse.Outcome != model.PacketFlowOutcomeNoMatchingResponse || noResponse.ProbeEmission != model.PacketEmissionObserved {
		t.Fatalf("no response = %#v", noResponse)
	}
	cancelled := Correlate(CorrelationInput{Scope: scope, Result: result, ProbeStarted: true, Cancelled: true, Capture: CaptureResult{Cancelled: true}})
	if cancelled.CaptureStatus != model.PacketCaptureStatusCancelled || cancelled.Outcome != model.PacketFlowOutcomeCancelled {
		t.Fatalf("cancelled = %#v", cancelled)
	}
}

func TestPacketFlowCanonicalOutputContainsNoPayloadOrPacketBytes(t *testing.T) {
	scope := testScope(ProbeTypeTCP)
	flow := Correlate(CorrelationInput{Scope: scope, ProbeStarted: true, Capture: CaptureResult{Source: "fixture", Complete: true, Observations: []model.PacketObservation{
		tcpObservation(scope, "syn", model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, "127.0.0.5", 49157, "203.0.113.10", 443, scope.WindowStarted.Add(time.Millisecond)),
	}}})
	encoded, err := json.Marshal(flow)
	if err != nil {
		t.Fatalf("marshal flow: %v", err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"payload", "raw_packet", "packet_bytes", "super-secret-credential"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("canonical flow leaked %q: %s", forbidden, encoded)
		}
	}
	if flow.Observations[0].Certainty != model.EvidenceCertaintyDirectlyObservedLocalPacket {
		t.Fatalf("certainty = %q", flow.Observations[0].Certainty)
	}
}

func tcpResult(scope Scope, local, remote string) model.ProbeResult {
	raw, _ := json.Marshal(struct {
		LocalEndpoint  string `json:"local_endpoint"`
		RemoteEndpoint string `json:"remote_endpoint"`
	}{local, remote})
	return model.ProbeResult{
		Name: "tcp", Target: scope.Target, SessionID: scope.Identity.SessionID, ProbeID: scope.Identity.ProbeID, CorrelationID: scope.Identity.CorrelationID,
		Status: model.ProbeStatusFailed, Timing: model.Timing{StartedAt: timePtr(scope.WindowStarted), CompletedAt: timePtr(scope.Deadline)},
		Evidence: []model.Evidence{{ID: "tcp-connection", Kind: model.EvidenceKindTCPConnection, Raw: raw}},
	}
}

func tcpObservation(scope Scope, id string, kind model.PacketObservationKind, direction model.PacketDirection, source string, sourcePort uint16, destination string, destinationPort uint16, observedAt time.Time) model.PacketObservation {
	localPort := sourcePort
	if direction == model.PacketDirectionInbound {
		localPort = destinationPort
	}
	return model.PacketObservation{
		ID: id, SessionID: scope.Identity.SessionID, ProbeID: scope.Identity.ProbeID, CorrelationID: scope.Identity.CorrelationID,
		Kind: kind, Protocol: model.PacketProtocolTCP, Direction: direction,
		LocalAddress: "127.0.0.5", LocalPort: localPort, SourceAddress: source, SourcePort: sourcePort,
		DestinationAddress: destination, DestinationPort: destinationPort, ProcessID: scope.ProcessID, ObservedAt: observedAt,
	}
}

func timePtr(value time.Time) *time.Time { return &value }
