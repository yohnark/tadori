package model

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// PathProtocol identifies the packet family used to observe one path. The
// protocol is part of the observation because an ICMP path and a TCP path to
// the same endpoint do not prove the same thing.
type PathProtocol string

const (
	PathProtocolICMP PathProtocol = "icmp"
	PathProtocolTCP  PathProtocol = "tcp"
	// PathProtocolUDP reserves the canonical protocol value for a later
	// bounded UDP adapter; the current probe intentionally does not execute it.
	PathProtocolUDP PathProtocol = "udp"
)

const (
	PathProtocolICMPEcho       = PathProtocolICMP
	PathProtocolTCPDestination = PathProtocolTCP
)

// PathObservationStatus describes whether a path measurement was attempted.
// An observed measurement may contain entirely unobservable TTLs; that is a
// valid observation and is not packet-loss accounting.
type PathObservationStatus string

const (
	PathObservationStatusUnknown     PathObservationStatus = "unknown"
	PathObservationStatusObserved    PathObservationStatus = "observed"
	PathObservationStatusUnsupported PathObservationStatus = "unsupported"
	PathObservationStatusError       PathObservationStatus = "error"
)

// PathHopState records what was learned for a particular TTL. Unobservable
// means that no responder was received before the bounded per-TTL context
// ended. It deliberately does not mean that a packet was lost.
type PathHopState string

const (
	PathHopStateUnknown      PathHopState = "unknown"
	PathHopStateObserved     PathHopState = "observed_responder"
	PathHopStateUnobservable PathHopState = "unobservable"
)

const PathHopStateObservedResponder = PathHopStateObserved

// PathSegmentKind distinguishes direct observations from bounded inferences.
// None of these values claims that the observed path is the exact physical
// topology.
type PathSegmentKind string

const (
	PathSegmentObservedResponder PathSegmentKind = "observed_responder"
	PathSegmentInferred          PathSegmentKind = "inferred"
	PathSegmentUnobservable      PathSegmentKind = "unobservable"
)

const (
	PathSegmentKindObservedResponder = PathSegmentObservedResponder
	PathSegmentKindInferred          = PathSegmentInferred
	PathSegmentKindUnobservable      = PathSegmentUnobservable
)

// PathResponder is one response source associated with a TTL. Multiple
// responders at one TTL are retained because load balancing and asymmetric
// routing can produce more than one source across bounded attempts.
type PathResponder struct {
	Address            string `json:"address"`
	RTTMS              int64  `json:"rtt_ms,omitempty"`
	Response           string `json:"response,omitempty"`
	DestinationReached bool   `json:"destination_reached,omitempty"`
}

// PathHop is the complete observation for one TTL. Responders is intentionally
// a slice rather than a single address; an empty slice with an unobservable
// state is meaningful evidence.
type PathHop struct {
	TTL        uint8           `json:"ttl"`
	State      PathHopState    `json:"state"`
	Attempts   int             `json:"attempts,omitempty"`
	Responders []PathResponder `json:"responders,omitempty"`
}

// PathSegment is a presentation-neutral summary of path evidence. An
// observed-responder segment has one TTL and its responders. An unobservable
// segment covers one or more TTLs for which no responder was seen. An
// inferred segment only records the bounded progression between observed TTLs
// and must never be rendered as an exact physical link.
type PathSegment struct {
	Kind       PathSegmentKind `json:"kind"`
	FromTTL    uint8           `json:"from_ttl"`
	ToTTL      uint8           `json:"to_ttl"`
	Responders []PathResponder `json:"responders,omitempty"`
}

// PathObservation is the canonical structured observation for one protocol
// and endpoint. Hops preserve every probed TTL, including unobservable ones;
// Segments preserve the distinction between observed responders, bounded
// inferences, and unobservable portions. When carried in Evidence, the
// enclosing Evidence.Source and Evidence.CapturedAt provide its provenance.
//
// DestinationPort is retained for correlation across protocols. PortAware is
// true only when the observation actually used that destination port (TCP),
// and false for ICMP echo observations whose endpoint context still carries
// the requested port. DestinationReached can be true for a TCP refusal; the
// separate DestinationTCPConnected field is required to prove an open port.
type PathObservation struct {
	Status                  PathObservationStatus `json:"status"`
	Protocol                PathProtocol          `json:"protocol"`
	Destination             string                `json:"destination"`
	DestinationPort         uint16                `json:"destination_port,omitempty"`
	PortAware               bool                  `json:"port_aware"`
	MaxTTL                  uint8                 `json:"max_ttl"`
	AttemptsPerTTL          int                   `json:"attempts_per_ttl"`
	Hops                    []PathHop             `json:"hops"`
	Segments                []PathSegment         `json:"segments"`
	DestinationReached      bool                  `json:"destination_reached"`
	DestinationTCPConnected bool                  `json:"destination_tcp_connected"`
	Error                   string                `json:"error,omitempty"`
	ErrorType               string                `json:"error_type,omitempty"`
}

// PathCorrelation groups observations for the same destination and
// requested port. A TCP destination success is endpoint evidence; an ICMP
// result in the same correlation group remains ICMP evidence and is never
// promoted into application connectivity failure or success by itself.
type PathCorrelation struct {
	Destination             string            `json:"destination"`
	DestinationPort         uint16            `json:"destination_port"`
	Observations            []PathObservation `json:"observations"`
	TCPDestinationReached   bool              `json:"tcp_destination_reached"`
	TCPDestinationConnected bool              `json:"tcp_destination_connected"`
	ICMPDestinationReached  bool              `json:"icmp_destination_reached"`
}

// CorrelatePathObservations deterministically groups path observations by
// destination and destination port. It is useful to callers that collect
// separate protocol probes and is also the semantic key used by diagnosis.
func CorrelatePathObservations(observations ...PathObservation) []PathCorrelation {
	groups := make(map[string]*PathCorrelation)
	for _, observation := range observations {
		observation.Destination = canonicalPathDestination(observation.Destination)
		key := observation.Destination + "\x00" + strconv.Itoa(int(observation.DestinationPort))
		group := groups[key]
		if group == nil {
			group = &PathCorrelation{
				Destination:     observation.Destination,
				DestinationPort: observation.DestinationPort,
				Observations:    make([]PathObservation, 0, 1),
			}
			groups[key] = group
		}
		group.Observations = append(group.Observations, observation)
		if observation.Protocol == PathProtocolTCP && observation.PortAware && observation.DestinationReached {
			group.TCPDestinationReached = true
		}
		if observation.Protocol == PathProtocolTCP && observation.PortAware && observation.DestinationTCPConnected {
			group.TCPDestinationConnected = true
		}
		if observation.Protocol == PathProtocolICMP && observation.DestinationReached {
			group.ICMPDestinationReached = true
		}
	}

	result := make([]PathCorrelation, 0, len(groups))
	for _, group := range groups {
		sort.SliceStable(group.Observations, func(i, j int) bool {
			left, right := group.Observations[i], group.Observations[j]
			if left.Protocol != right.Protocol {
				return left.Protocol < right.Protocol
			}
			if left.Status != right.Status {
				return left.Status < right.Status
			}
			if left.DestinationReached != right.DestinationReached {
				return !left.DestinationReached
			}
			if left.MaxTTL != right.MaxTTL {
				return left.MaxTTL < right.MaxTTL
			}
			return left.AttemptsPerTTL < right.AttemptsPerTTL
		})
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Destination != result[j].Destination {
			return result[i].Destination < result[j].Destination
		}
		return result[i].DestinationPort < result[j].DestinationPort
	})
	return result
}

// Correlate is a concise alias for CorrelatePathObservations.
func Correlate(observations ...PathObservation) []PathCorrelation {
	return CorrelatePathObservations(observations...)
}

// DecodePathObservation decodes the known structured path evidence shape.
// Unknown evidence remains opaque to callers; only EvidenceKindPathObservation
// is accepted here.
func DecodePathObservation(evidence Evidence) (PathObservation, error) {
	if evidence.Kind != EvidenceKindPathObservation {
		return PathObservation{}, fmt.Errorf("evidence %q is not a path observation", evidence.Kind)
	}
	var observation PathObservation
	if err := json.Unmarshal(evidence.Raw, &observation); err != nil {
		return PathObservation{}, fmt.Errorf("decode path observation: %w", err)
	}
	return observation, nil
}

// MatchesTarget reports whether an observation belongs to the exact target
// endpoint, including its destination port. It is used before transport
// evidence is allowed to contradict another probe.
func (observation PathObservation) MatchesTarget(target Target) bool {
	return target.MatchesAddress(observation.Destination) && observation.DestinationPort == target.Port
}

// NormalizePathResponder canonicalizes an IP responder while leaving host
// names untouched. It is deliberately small so native and fixture observers
// share the same representation.
func NormalizePathResponder(responder PathResponder) PathResponder {
	address := strings.TrimSuffix(responder.Address, ".")
	if parsed, err := netip.ParseAddr(address); err == nil {
		responder.Address = NormalizeAddr(parsed).String()
	}
	return responder
}

func canonicalPathDestination(destination string) string {
	if parsed, err := netip.ParseAddr(destination); err == nil {
		return NormalizeAddr(parsed).String()
	}
	return destination
}
