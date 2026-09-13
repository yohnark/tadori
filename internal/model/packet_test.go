package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPacketCertaintyClassification(t *testing.T) {
	tests := []struct {
		name      string
		kind      PacketObservationKind
		certainty EvidenceCertainty
	}{
		{name: "local SYN", kind: PacketObservationOutboundTCPSYN, certainty: EvidenceCertaintyDirectlyObservedLocalPacket},
		{name: "endpoint SYN ACK", kind: PacketObservationInboundTCPSYNACK, certainty: EvidenceCertaintyConfirmedEndpointResponse},
		{name: "endpoint RST", kind: PacketObservationTCPRST, certainty: EvidenceCertaintyConfirmedEndpointResponse},
		{name: "TTL responder", kind: PacketObservationICMPTimeExceeded, certainty: EvidenceCertaintyObservedTTLResponder},
		{name: "unreachable responder", kind: PacketObservationICMPUnreachable, certainty: EvidenceCertaintyObservedTTLResponder},
		{name: "inferred path", kind: PacketObservationKind("unknown"), certainty: EvidenceCertaintyUnobservableSegment},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := PacketObservation{Kind: test.kind}
			if test.kind == PacketObservationTCPRST {
				observation.Direction = PacketDirectionInbound
			}
			got := ClassifyPacketCertainty(observation)
			if got != test.certainty {
				t.Fatalf("certainty = %q, want %q", got, test.certainty)
			}
		})
	}
	if got := ClassifyPathCertainty(PathSegmentInferred); got != EvidenceCertaintyInferredTransitSegment {
		t.Fatalf("inferred path certainty = %q", got)
	}
	if got := ClassifyPathCertainty(PathSegmentUnobservable); got != EvidenceCertaintyUnobservableSegment {
		t.Fatalf("unobservable path certainty = %q", got)
	}
}

func TestPacketFlowEvidenceCanonicalizesWithoutPayloadFields(t *testing.T) {
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("test", 9*60*60))
	flow := PacketFlowEvidence{
		SessionID: "session-1", ProbeID: "tcp", CorrelationID: "session-1/tcp",
		Target: NewTarget("203.0.113.10", 443), CaptureStatus: PacketCaptureStatusAvailable,
		WindowStartedAt: when, WindowCompletedAt: when.Add(time.Second), ProbeEmission: PacketEmissionObserved,
		Outcome: PacketFlowOutcomeTCPRST, Certainty: EvidenceCertaintyConfirmedEndpointResponse,
		Observations: []PacketObservation{{
			ID: "rst", Kind: PacketObservationTCPRST, Direction: PacketDirectionInbound,
			SourceAddress: "203.0.113.10", SourcePort: 443, DestinationAddress: "[2001:db8::1]", DestinationPort: 49152,
			ObservedAt: when, Certainty: EvidenceCertaintyConfirmedEndpointResponse,
		}},
	}
	encoded, err := json.Marshal(flow)
	if err != nil {
		t.Fatalf("marshal flow: %v", err)
	}
	value := string(encoded)
	for _, forbidden := range []string{"payload", "raw_packet", "packet_bytes"} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("canonical flow contains %q: %s", forbidden, value)
		}
	}
	var decoded PacketFlowEvidence
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal flow: %v", err)
	}
	if decoded.Observations[0].DestinationAddress != "2001:db8::1" {
		t.Fatalf("address was not canonicalized after round trip: %#v", decoded.Observations[0])
	}
	if decoded.Observations[0].ObservedAt.Location() != time.UTC {
		t.Fatalf("observation timestamp is not UTC: %v", decoded.Observations[0].ObservedAt.Location())
	}
}
