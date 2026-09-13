package model

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ProbeIdentity is the explicit identity shared by an active probe and the
// packet observations collected while that probe is running. A correlation
// ID is scoped to one probe invocation and is never inferred from timing.
type ProbeIdentity struct {
	SessionID     string `json:"session_id,omitempty"`
	ProbeID       string `json:"probe_id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// PacketProtocol identifies the transport or control protocol represented by
// a packet observation.
type PacketProtocol string

const (
	PacketProtocolTCP  PacketProtocol = "tcp"
	PacketProtocolICMP PacketProtocol = "icmp"
)

// PacketDirection is relative to the diagnosed local host.
type PacketDirection string

const (
	PacketDirectionOutbound PacketDirection = "outbound"
	PacketDirectionInbound  PacketDirection = "inbound"
)

// PacketObservationKind names the small, payload-free set of packet facts
// useful to the diagnostic lane. The model intentionally does not have a raw
// packet or payload field.
type PacketObservationKind string

const (
	PacketObservationOutboundTCPSYN        PacketObservationKind = "outbound_tcp_syn"
	PacketObservationInboundTCPSYNACK      PacketObservationKind = "inbound_tcp_syn_ack"
	PacketObservationTCPRST                PacketObservationKind = "tcp_rst"
	PacketObservationICMPTimeExceeded      PacketObservationKind = "icmp_time_exceeded"
	PacketObservationICMPUnreachable       PacketObservationKind = "icmp_unreachable"
	PacketObservationOutboundICMPEcho      PacketObservationKind = "outbound_icmp_echo"
	PacketObservationInboundICMPEcho       PacketObservationKind = "inbound_icmp_echo"
	PacketObservationTCPHandshakeConfirmed PacketObservationKind = "tcp_handshake_confirmed"
)

// Short aliases make the packet vocabulary convenient at call sites while
// retaining the descriptive canonical constants above.
const (
	PacketKindOutboundTCPSYN   = PacketObservationOutboundTCPSYN
	PacketKindInboundTCPSYNACK = PacketObservationInboundTCPSYNACK
	PacketKindTCPRST           = PacketObservationTCPRST
	PacketKindICMPTimeExceeded = PacketObservationICMPTimeExceeded
	PacketKindICMPUnreachable  = PacketObservationICMPUnreachable
)

// EvidenceCertainty records what a fact establishes. It is deliberately
// orthogonal to packet kind: a directly observed packet from an intermediate
// host is not endpoint confirmation, and an unobservable segment is not a
// claim that a packet was dropped.
type EvidenceCertainty string

const (
	EvidenceCertaintyDirectlyObservedLocalPacket EvidenceCertainty = "directly_observed_local_packet"
	EvidenceCertaintyObservedTTLResponder        EvidenceCertainty = "observed_ttl_responder"
	EvidenceCertaintyConfirmedEndpointResponse   EvidenceCertainty = "confirmed_endpoint_response"
	EvidenceCertaintyInferredTransitSegment      EvidenceCertainty = "inferred_transit_segment"
	EvidenceCertaintyUnobservableSegment         EvidenceCertainty = "unobservable_segment"
)

// PacketObservation is one structured, payload-free observation from a
// bounded acquisition backend. Source and destination fields describe the
// observed packet. LocalAddress/LocalPort are retained explicitly so an
// inbound response can still be correlated with the local flow tuple.
//
// ProbeTTL is the TTL used by a path probe; TTL is the observed IP TTL or
// hop-limit when the backend exposes it. Keeping both prevents an observed
// responder's value from being confused with the probe's requested TTL.
type PacketObservation struct {
	ID                       string                `json:"id"`
	SessionID                string                `json:"session_id,omitempty"`
	ProbeID                  string                `json:"probe_id,omitempty"`
	CorrelationID            string                `json:"correlation_id,omitempty"`
	Kind                     PacketObservationKind `json:"kind"`
	Protocol                 PacketProtocol        `json:"protocol"`
	Direction                PacketDirection       `json:"direction"`
	Interface                string                `json:"interface,omitempty"`
	InterfaceIndex           uint32                `json:"interface_index,omitempty"`
	LocalAddress             string                `json:"local_address,omitempty"`
	LocalPort                uint16                `json:"local_port,omitempty"`
	SourceAddress            string                `json:"source_address,omitempty"`
	SourcePort               uint16                `json:"source_port,omitempty"`
	DestinationAddress       string                `json:"destination_address,omitempty"`
	DestinationPort          uint16                `json:"destination_port,omitempty"`
	TTL                      uint8                 `json:"ttl,omitempty"`
	HopLimit                 uint8                 `json:"hop_limit,omitempty"`
	ICMPType                 uint8                 `json:"icmp_type,omitempty"`
	ICMPCode                 uint8                 `json:"icmp_code,omitempty"`
	ICMPIdentifier           uint16                `json:"icmp_identifier,omitempty"`
	ICMPSequence             uint16                `json:"icmp_sequence,omitempty"`
	ProbeTTL                 uint8                 `json:"probe_ttl,omitempty"`
	ProbeAttempt             int                   `json:"probe_attempt,omitempty"`
	QuotedProtocol           PacketProtocol        `json:"quoted_protocol,omitempty"`
	QuotedSourceAddress      string                `json:"quoted_source_address,omitempty"`
	QuotedSourcePort         uint16                `json:"quoted_source_port,omitempty"`
	QuotedDestinationAddress string                `json:"quoted_destination_address,omitempty"`
	QuotedDestinationPort    uint16                `json:"quoted_destination_port,omitempty"`
	QuotedICMPIdentifier     uint16                `json:"quoted_icmp_identifier,omitempty"`
	QuotedICMPSequence       uint16                `json:"quoted_icmp_sequence,omitempty"`
	ProcessID                uint32                `json:"process_id,omitempty"`
	ConnectionID             string                `json:"connection_id,omitempty"`
	ObservedAt               time.Time             `json:"observed_at"`
	Certainty                EvidenceCertainty     `json:"certainty"`
}

// NormalizePacketObservation applies the same address normalization used by
// the rest of the canonical model and supplies the certainty implied by a
// known packet kind when an adapter did not set it.
func NormalizePacketObservation(observation PacketObservation) PacketObservation {
	for _, address := range []*string{
		&observation.LocalAddress,
		&observation.SourceAddress,
		&observation.DestinationAddress,
		&observation.QuotedSourceAddress,
		&observation.QuotedDestinationAddress,
	} {
		*address = normalizePacketAddress(*address)
	}
	if observation.Protocol == "" {
		switch observation.Kind {
		case PacketObservationOutboundTCPSYN, PacketObservationInboundTCPSYNACK, PacketObservationTCPRST, PacketObservationTCPHandshakeConfirmed:
			observation.Protocol = PacketProtocolTCP
		case PacketObservationICMPTimeExceeded, PacketObservationICMPUnreachable, PacketObservationOutboundICMPEcho, PacketObservationInboundICMPEcho:
			observation.Protocol = PacketProtocolICMP
		}
	}
	if observation.Certainty == "" {
		observation.Certainty = ClassifyPacketCertainty(observation)
	}
	if !observation.ObservedAt.IsZero() {
		observation.ObservedAt = observation.ObservedAt.UTC()
	}
	return observation
}

// ClassifyPacketCertainty maps a packet fact to the strongest claim it can
// support without inspecting a payload or making a transit-topology claim.
func ClassifyPacketCertainty(observation PacketObservation) EvidenceCertainty {
	switch observation.Kind {
	case PacketObservationInboundTCPSYNACK, PacketObservationInboundICMPEcho, PacketObservationTCPHandshakeConfirmed:
		return EvidenceCertaintyConfirmedEndpointResponse
	case PacketObservationTCPRST:
		if observation.Direction == PacketDirectionInbound {
			return EvidenceCertaintyConfirmedEndpointResponse
		}
		return EvidenceCertaintyDirectlyObservedLocalPacket
	case PacketObservationICMPTimeExceeded, PacketObservationICMPUnreachable:
		return EvidenceCertaintyObservedTTLResponder
	case PacketObservationOutboundTCPSYN, PacketObservationOutboundICMPEcho:
		return EvidenceCertaintyDirectlyObservedLocalPacket
	default:
		return EvidenceCertaintyUnobservableSegment
	}
}

// ClassifyPathCertainty preserves the certainty boundary already represented
// by the #31 path model.
func ClassifyPathCertainty(segment PathSegmentKind) EvidenceCertainty {
	switch segment {
	case PathSegmentObservedResponder:
		return EvidenceCertaintyObservedTTLResponder
	case PathSegmentInferred:
		return EvidenceCertaintyInferredTransitSegment
	case PathSegmentUnobservable:
		return EvidenceCertaintyUnobservableSegment
	default:
		return EvidenceCertaintyUnobservableSegment
	}
}

// PacketCaptureStatus describes acquisition availability without changing the
// outcome of unrelated probes.
type PacketCaptureStatus string

const (
	PacketCaptureStatusAvailable             PacketCaptureStatus = "available"
	PacketCaptureStatusUnsupported           PacketCaptureStatus = "unsupported"
	PacketCaptureStatusInsufficientPrivilege PacketCaptureStatus = "insufficient_privilege"
	PacketCaptureStatusPartial               PacketCaptureStatus = "partial"
	PacketCaptureStatusError                 PacketCaptureStatus = "error"
	PacketCaptureStatusCancelled             PacketCaptureStatus = "cancelled"
)

// PacketEmissionState avoids treating an unavailable capture backend as proof
// that a probe was not emitted.
type PacketEmissionState string

const (
	PacketEmissionObserved    PacketEmissionState = "observed"
	PacketEmissionNotObserved PacketEmissionState = "not_observed"
	PacketEmissionUnknown     PacketEmissionState = "unknown"
)

// PacketFlowOutcome is the deterministic result of correlating one active
// probe with the observations collected in its bounded window.
type PacketFlowOutcome string

const (
	PacketFlowOutcomeTCPHandshakeConfirmed PacketFlowOutcome = "tcp_handshake_confirmed"
	PacketFlowOutcomeTCPSYNACK             PacketFlowOutcome = "tcp_syn_ack_received"
	PacketFlowOutcomeTCPRST                PacketFlowOutcome = "tcp_rst_received"
	PacketFlowOutcomeICMPEchoReply         PacketFlowOutcome = "icmp_echo_reply_received"
	PacketFlowOutcomeICMPTimeExceeded      PacketFlowOutcome = "icmp_time_exceeded_received"
	PacketFlowOutcomeICMPUnreachable       PacketFlowOutcome = "icmp_unreachable_received"
	PacketFlowOutcomeNoMatchingResponse    PacketFlowOutcome = "no_matching_response_observed"
	PacketFlowOutcomeProbeNotEmitted       PacketFlowOutcome = "probe_not_observed"
	PacketFlowOutcomeCaptureUnavailable    PacketFlowOutcome = "capture_unavailable"
	PacketFlowOutcomeCancelled             PacketFlowOutcome = "cancelled"
)

// PacketFlowEvidence is the canonical flow-level supplement attached to the
// existing active probe result. It carries structured observations and their
// deterministic match IDs, never packet bytes or application payload.
type PacketFlowEvidence struct {
	SessionID             string              `json:"session_id"`
	ProbeID               string              `json:"probe_id"`
	CorrelationID         string              `json:"correlation_id"`
	Target                Target              `json:"target"`
	CaptureStatus         PacketCaptureStatus `json:"capture_status"`
	CaptureSource         string              `json:"capture_source,omitempty"`
	CaptureError          string              `json:"capture_error,omitempty"`
	EventsLost            uint64              `json:"events_lost,omitempty"`
	WindowStartedAt       time.Time           `json:"window_started_at"`
	WindowCompletedAt     time.Time           `json:"window_completed_at"`
	ProbeEmission         PacketEmissionState `json:"probe_emission"`
	Outcome               PacketFlowOutcome   `json:"outcome"`
	CorrelationMethod     string              `json:"correlation_method,omitempty"`
	MatchedObservationIDs []string            `json:"matched_observation_ids,omitempty"`
	Certainty             EvidenceCertainty   `json:"certainty"`
	LocalAddress          string              `json:"local_address,omitempty"`
	LocalPort             uint16              `json:"local_port,omitempty"`
	Observations          []PacketObservation `json:"observations,omitempty"`
}

// MarshalJSON normalizes all packet timestamps without mutating the flow.
func (flow PacketFlowEvidence) MarshalJSON() ([]byte, error) {
	type canonicalFlow PacketFlowEvidence
	copyFlow := canonicalFlow(flow)
	copyFlow.WindowStartedAt = flow.WindowStartedAt.UTC()
	copyFlow.WindowCompletedAt = flow.WindowCompletedAt.UTC()
	copyFlow.Observations = append([]PacketObservation(nil), flow.Observations...)
	for i := range copyFlow.Observations {
		copyFlow.Observations[i] = NormalizePacketObservation(copyFlow.Observations[i])
	}
	return json.Marshal(copyFlow)
}

// PacketFlowEvidenceFor returns a presentation-neutral Evidence item for a
// correlated flow. The raw value is only the structured PacketFlowEvidence
// JSON; no acquisition bytes are retained.
func PacketFlowEvidenceFor(flow PacketFlowEvidence) (Evidence, error) {
	raw, err := json.Marshal(flow)
	if err != nil {
		return Evidence{}, fmt.Errorf("marshal packet flow evidence: %w", err)
	}
	captured := flow.WindowCompletedAt.UTC()
	return Evidence{
		ID:         flow.CorrelationID + "/packet-flow",
		Kind:       EvidenceKindPacketFlow,
		Source:     flow.CaptureSource,
		CapturedAt: &captured,
		Raw:        raw,
	}, nil
}

// DecodePacketFlowEvidence decodes only the known structured packet-flow
// shape. It never attempts to parse or expose raw packet data.
func DecodePacketFlowEvidence(evidence Evidence) (PacketFlowEvidence, error) {
	if evidence.Kind != EvidenceKindPacketFlow {
		return PacketFlowEvidence{}, fmt.Errorf("evidence %q is not packet flow evidence", evidence.Kind)
	}
	var flow PacketFlowEvidence
	if err := json.Unmarshal(evidence.Raw, &flow); err != nil {
		return PacketFlowEvidence{}, fmt.Errorf("decode packet flow evidence: %w", err)
	}
	for i := range flow.Observations {
		flow.Observations[i] = NormalizePacketObservation(flow.Observations[i])
	}
	return flow, nil
}

func normalizePacketAddress(address string) string {
	address = strings.TrimSpace(strings.Trim(address, "[]"))
	if parsed, err := netip.ParseAddr(address); err == nil {
		return NormalizeAddr(parsed).String()
	}
	return address
}
