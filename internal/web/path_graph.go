package web

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/yohnark/tadori/internal/model"
)

const (
	pathGraphNodeVantage              = "probe_vantage"
	pathGraphNodeResponder            = "responder"
	pathGraphNodeUnobservableRange    = "unobservable_range"
	pathGraphNodeUnknownRange         = "unknown_range"
	pathGraphNodeDestination          = "destination_confirmation"
	pathGraphGroupVantage             = "probe_vantage"
	pathGraphGroupHop                 = "ttl_hop"
	pathGraphGroupUnobservable        = "unobservable_range"
	pathGraphGroupUnknown             = "unknown_range"
	pathGraphGroupDestination         = "destination_confirmation"
	pathGraphEdgeObservationOrder     = "observation_order"
	pathGraphEdgeUnobservable         = "unobservable_visibility"
	pathGraphEdgeBoundedInference     = "bounded_inference"
	pathGraphEdgeDestinationConfirm   = "destination_confirmation"
	pathGraphRoleVantage              = "probe_vantage"
	pathGraphRoleIntermediate         = "intermediate_responder"
	pathGraphRoleDestinationResponder = "destination_responder"
	pathGraphRoleUnobservable         = "unobservable_range"
	pathGraphRoleUnknown              = "unknown_range"
	pathGraphRoleDestination          = "destination_confirmation"
)

// PathGraphView is the deterministic, presentation-ready projection of one
// canonical PathObservation. It describes the order and visibility of a
// bounded observation; it never claims that an edge is a physical link.
type PathGraphView struct {
	ID                      string                      `json:"id"`
	Supported               bool                        `json:"supported"`
	Protocol                model.PathProtocol          `json:"protocol"`
	ProtocolLabel           string                      `json:"protocol_label"`
	Destination             string                      `json:"destination"`
	DestinationPort         uint16                      `json:"destination_port"`
	PortAware               bool                        `json:"port_aware"`
	ObservationStatus       model.PathObservationStatus `json:"observation_status"`
	ObservationTone         string                      `json:"observation_tone"`
	ObservationLabel        string                      `json:"observation_label"`
	DestinationReached      bool                        `json:"destination_reached"`
	DestinationTCPConnected bool                        `json:"destination_tcp_connected"`
	Certainty               model.ObservationCertainty  `json:"certainty"`
	EvidenceIDs             []string                    `json:"evidence_ids,omitempty"`
	Provenance              []string                    `json:"provenance,omitempty"`
	Limitations             []string                    `json:"limitations,omitempty"`
	Nodes                   []PathGraphNodeView         `json:"nodes"`
	Edges                   []PathGraphEdgeView         `json:"edges"`
	Groups                  []PathGraphGroupView        `json:"groups"`
}

// PathGraphNodeView is an observation-oriented graph node. A responder node
// identifies a responder at a TTL, not a physical device. Range nodes retain
// missing visibility explicitly and intentionally contain no invented address.
type PathGraphNodeView struct {
	ID                      string                     `json:"id"`
	Kind                    string                     `json:"kind"`
	Role                    string                     `json:"role"`
	TTL                     uint8                      `json:"ttl,omitempty"`
	TTLFrom                 uint8                      `json:"ttl_from"`
	TTLTo                   uint8                      `json:"ttl_to"`
	State                   model.PathHopState         `json:"state"`
	Tone                    string                     `json:"tone"`
	Label                   string                     `json:"label"`
	Detail                  string                     `json:"detail"`
	Attempts                int                        `json:"attempts,omitempty"`
	Address                 string                     `json:"address,omitempty"`
	RTTMS                   int64                      `json:"rtt_ms,omitempty"`
	Response                string                     `json:"response,omitempty"`
	Protocol                model.PathProtocol         `json:"protocol"`
	Destination             string                     `json:"destination"`
	DestinationPort         uint16                     `json:"destination_port"`
	PortAware               bool                       `json:"port_aware"`
	Certainty               model.ObservationCertainty `json:"certainty"`
	DestinationConfirmed    bool                       `json:"destination_confirmed"`
	DestinationTCPConnected bool                       `json:"destination_tcp_connected"`
	EvidenceIDs             []string                   `json:"evidence_ids,omitempty"`
	Provenance              []string                   `json:"provenance,omitempty"`
	Limitations             []string                   `json:"limitations,omitempty"`
}

// PathGraphEdgeView connects observation stages. Its relation is deliberately
// semantic: ordered observation, bounded inference, or visibility through an
// unobservable interval. It is not a topology assertion.
type PathGraphEdgeView struct {
	ID           string                  `json:"id"`
	From         string                  `json:"from"`
	To           string                  `json:"to"`
	Kind         string                  `json:"kind"`
	Label        string                  `json:"label"`
	Detail       string                  `json:"detail"`
	FromTTL      uint8                   `json:"from_ttl"`
	ToTTL        uint8                   `json:"to_ttl"`
	SegmentKinds []model.PathSegmentKind `json:"segment_kinds,omitempty"`
	EvidenceIDs  []string                `json:"evidence_ids,omitempty"`
	Limitations  []string                `json:"limitations,omitempty"`
}

// PathGraphGroupView keeps one TTL stage (or an explicit contiguous range)
// together. A group with multiple node IDs is how ECMP/multiple responders
// remain visible at one TTL without collapsing their observations.
type PathGraphGroupView struct {
	ID           string                  `json:"id"`
	Kind         string                  `json:"kind"`
	FromTTL      uint8                   `json:"from_ttl"`
	ToTTL        uint8                   `json:"to_ttl"`
	State        model.PathHopState      `json:"state"`
	Label        string                  `json:"label"`
	Detail       string                  `json:"detail"`
	NodeIDs      []string                `json:"node_ids"`
	SegmentKinds []model.PathSegmentKind `json:"segment_kinds,omitempty"`
	EvidenceIDs  []string                `json:"evidence_ids,omitempty"`
	Limitations  []string                `json:"limitations,omitempty"`
}

type pathGraphLayer struct {
	kind    string
	role    string
	fromTTL uint8
	toTTL   uint8
	state   model.PathHopState
	nodeIDs []string
}

// buildPathGraphView is the only graph semantic projection. The browser
// consumes its nodes, edges, and groups; it does not derive graph meaning from
// raw evidence, table markup, or an independently maintained path model.
func buildPathGraphView(observation model.PathObservation, evidenceIDs, provenance, limitations []string) PathGraphView {
	graph := PathGraphView{
		ID:                      pathGraphID(observation, evidenceIDs),
		Supported:               observation.Status != model.PathObservationStatusUnsupported,
		Protocol:                observation.Protocol,
		ProtocolLabel:           labelForProtocol(observation.Protocol),
		Destination:             observation.Destination,
		DestinationPort:         observation.DestinationPort,
		PortAware:               observation.PortAware,
		ObservationStatus:       observation.Status,
		ObservationTone:         toneForPathStatus(observation.Status),
		ObservationLabel:        labelForPathStatus(observation.Status),
		DestinationReached:      observation.DestinationReached,
		DestinationTCPConnected: observation.DestinationTCPConnected,
		Certainty:               pathObservationCertainty(observation),
		EvidenceIDs:             append([]string(nil), evidenceIDs...),
		Provenance:              append([]string(nil), provenance...),
		Limitations:             append([]string(nil), limitations...),
		Nodes:                   make([]PathGraphNodeView, 0, len(observation.Hops)+2),
		Edges:                   make([]PathGraphEdgeView, 0, len(observation.Hops)+1),
		Groups:                  make([]PathGraphGroupView, 0, len(observation.Hops)+2),
	}

	sequence := make([]pathGraphLayer, 0, len(observation.Hops)+2)
	vantage := graphNode(
		graph, pathGraphNodeVantage, pathGraphRoleVantage, 0, 0, 0,
		model.PathHopStateUnknown, "Probe vantage", "Local diagnostic source for this observation lane.",
		"", 0, "", model.ObservationCertaintyConfigured, false, false,
	)
	graph.Nodes = append(graph.Nodes, vantage)
	vantageLayer := pathGraphLayer{
		kind: pathGraphGroupVantage, role: pathGraphRoleVantage, state: model.PathHopStateUnknown, nodeIDs: []string{vantage.ID},
	}
	graph.Groups = append(graph.Groups, graphGroup(graph, vantageLayer, observation.Segments, evidenceIDs, limitations))
	sequence = append(sequence, vantageLayer)

	hops := orderedPathHops(observation.Hops)
	for index := 0; index < len(hops); {
		hop := hops[index]
		kind := pathGraphHopKind(hop)
		if kind == pathGraphNodeResponder {
			responders := orderedPathResponders(hop.Responders)
			layer := pathGraphLayer{
				kind: pathGraphGroupHop, role: pathGraphRoleIntermediate,
				fromTTL: hop.TTL, toTTL: hop.TTL, state: hop.State,
				nodeIDs: make([]string, 0, len(responders)),
			}
			for responderIndex, responder := range responders {
				confirmed := responder.DestinationReached || (observation.DestinationReached && responder.Address == observation.Destination)
				role := pathGraphRoleIntermediate
				label := "Intermediate responder"
				detail := fmt.Sprintf("Responder observed at TTL %d; identity is scoped to this observation.", hop.TTL)
				if confirmed {
					role = pathGraphRoleDestinationResponder
					label = "Destination responder"
					detail = fmt.Sprintf("Destination responder observed at TTL %d.", hop.TTL)
				}
				node := graphNode(
					graph, pathGraphNodeResponder, role, hop.TTL, hop.TTL, hop.TTL,
					hop.State, label, detail, responder.Address, responder.RTTMS, responder.Response,
					model.ObservationCertaintyObserved, confirmed, observation.DestinationTCPConnected,
				)
				node.Attempts = hop.Attempts
				node.ID = uniqueGraphNodeID(node.ID, graph.Nodes)
				graph.Nodes = append(graph.Nodes, node)
				layer.nodeIDs = append(layer.nodeIDs, node.ID)
				_ = responderIndex
			}
			graph.Groups = append(graph.Groups, graphGroup(graph, layer, observation.Segments, evidenceIDs, limitations))
			sequence = append(sequence, layer)
			index++
			continue
		}

		end := index
		for end+1 < len(hops) && pathGraphHopKind(hops[end+1]) == kind && contiguousTTL(hops[end].TTL, hops[end+1].TTL) {
			end++
		}
		fromTTL, toTTL := hops[index].TTL, hops[end].TTL
		state := model.PathHopStateUnknown
		role := pathGraphRoleUnknown
		label := "Unknown TTL range"
		detail := fmt.Sprintf("The canonical observation does not identify a responder for TTL %d.", fromTTL)
		if kind == pathGraphNodeUnobservableRange {
			state = model.PathHopStateUnobservable
			role = pathGraphRoleUnobservable
			label = "Unobservable TTL range"
			detail = unobservableRangeDetail(fromTTL, toTTL)
		}
		node := graphNode(
			graph, kind, role, fromTTL, fromTTL, toTTL, state, label, detail, "", 0, "",
			model.ObservationCertaintyUnknown, false, observation.DestinationTCPConnected,
		)
		node.Attempts = hops[index].Attempts
		graph.Nodes = append(graph.Nodes, node)
		layer := pathGraphLayer{
			kind: graphGroupKindForNode(kind), role: role, fromTTL: fromTTL, toTTL: toTTL,
			state: state, nodeIDs: []string{node.ID},
		}
		graph.Groups = append(graph.Groups, graphGroup(graph, layer, observation.Segments, evidenceIDs, limitations))
		sequence = append(sequence, layer)
		index = end + 1
	}

	destinationConfirmed := observation.DestinationReached || observation.DestinationTCPConnected
	destinationDetail := "Destination confirmation was not observed in this lane."
	if destinationConfirmed {
		destinationDetail = "Destination confirmed; intermediate visibility may still be incomplete."
		if observation.DestinationTCPConnected {
			destinationDetail = "Destination confirmed and TCP connection established."
		}
	}
	destination := graphNode(
		graph, pathGraphNodeDestination, pathGraphRoleDestination, 0, 0, 0,
		pathDestinationNodeState(destinationConfirmed), "Destination confirmation", destinationDetail,
		observation.Destination, 0, "", pathDestinationNodeCertainty(destinationConfirmed, graph.Supported),
		destinationConfirmed, observation.DestinationTCPConnected,
	)
	graph.Nodes = append(graph.Nodes, destination)
	sequence = append(sequence, pathGraphLayer{
		kind: pathGraphGroupDestination, role: pathGraphRoleDestination, state: pathDestinationNodeState(destinationConfirmed), nodeIDs: []string{destination.ID},
	})
	graph.Groups = append(graph.Groups, graphGroup(graph, sequence[len(sequence)-1], observation.Segments, evidenceIDs, limitations))

	for index := 1; index < len(sequence); index++ {
		from, to := sequence[index-1], sequence[index]
		segmentKinds := graphSegmentKindsBetween(observation.Segments, from.toTTL, to.fromTTL)
		kind := pathGraphEdgeKind(from, to, segmentKinds, index == len(sequence)-1)
		for _, fromID := range from.nodeIDs {
			for _, toID := range to.nodeIDs {
				graph.Edges = append(graph.Edges, PathGraphEdgeView{
					ID: fmt.Sprintf("%s/edge-%d", graph.ID, len(graph.Edges)+1), From: fromID, To: toID,
					Kind: kind, Label: pathGraphEdgeLabel(kind), Detail: pathGraphEdgeDetail(kind),
					FromTTL: from.toTTL, ToTTL: to.fromTTL, SegmentKinds: append([]model.PathSegmentKind(nil), segmentKinds...),
					EvidenceIDs: append([]string(nil), evidenceIDs...), Limitations: append([]string(nil), limitations...),
				})
			}
		}
	}
	return graph
}

func graphNode(graph PathGraphView, kind, role string, ttl, fromTTL, toTTL uint8, state model.PathHopState, label, detail, address string, rttMS int64, response string, certainty model.ObservationCertainty, destinationConfirmed, tcpConnected bool) PathGraphNodeView {
	return PathGraphNodeView{
		ID:                      fmt.Sprintf("%s/node-%s-%d-%d-%s", graph.ID, kind, fromTTL, toTTL, graphToken(address)),
		Kind:                    kind,
		Role:                    role,
		TTL:                     ttl,
		TTLFrom:                 fromTTL,
		TTLTo:                   toTTL,
		State:                   state,
		Tone:                    graphNodeTone(kind, destinationConfirmed),
		Label:                   label,
		Detail:                  detail,
		Address:                 address,
		RTTMS:                   rttMS,
		Response:                response,
		Protocol:                graph.Protocol,
		Destination:             graph.Destination,
		DestinationPort:         graph.DestinationPort,
		PortAware:               graph.PortAware,
		Certainty:               certainty,
		DestinationConfirmed:    destinationConfirmed,
		DestinationTCPConnected: tcpConnected,
		EvidenceIDs:             append([]string(nil), graph.EvidenceIDs...),
		Provenance:              append([]string(nil), graph.Provenance...),
		Limitations:             append([]string(nil), graph.Limitations...),
	}
}

func graphGroup(graph PathGraphView, layer pathGraphLayer, segments []model.PathSegment, evidenceIDs, limitations []string) PathGraphGroupView {
	label, detail := pathGraphGroupCopy(layer)
	return PathGraphGroupView{
		ID:           fmt.Sprintf("%s/group-%d", graph.ID, len(graph.Groups)+1),
		Kind:         layer.kind,
		FromTTL:      layer.fromTTL,
		ToTTL:        layer.toTTL,
		State:        layer.state,
		Label:        label,
		Detail:       detail,
		NodeIDs:      append([]string(nil), layer.nodeIDs...),
		SegmentKinds: graphSegmentKindsForRange(segments, layer.fromTTL, layer.toTTL),
		EvidenceIDs:  append([]string(nil), evidenceIDs...),
		Limitations:  append([]string(nil), limitations...),
	}
}

func pathGraphGroupCopy(layer pathGraphLayer) (string, string) {
	switch layer.kind {
	case pathGraphGroupVantage:
		return "Probe vantage", "Local diagnostic source; this graph preserves observation order."
	case pathGraphGroupHop:
		if len(layer.nodeIDs) == 1 {
			return fmt.Sprintf("TTL %d responder", layer.fromTTL), "One responder observation retained at this TTL."
		}
		return fmt.Sprintf("TTL %d responders", layer.fromTTL), fmt.Sprintf("%d responder observations retained at this TTL; none are collapsed.", len(layer.nodeIDs))
	case pathGraphGroupUnobservable:
		return "Unobservable TTL range", unobservableRangeDetail(layer.fromTTL, layer.toTTL)
	case pathGraphGroupUnknown:
		return "Unknown TTL range", fmt.Sprintf("The canonical observation does not identify responders for TTL %s.", ttlRangeText(layer.fromTTL, layer.toTTL))
	case pathGraphGroupDestination:
		return "Destination confirmation", "Destination reachability and port state are shown separately from intermediate responders."
	default:
		return "Observed path stage", "Canonical observation stage."
	}
}

func pathGraphHopKind(hop model.PathHop) string {
	if len(hop.Responders) > 0 {
		return pathGraphNodeResponder
	}
	if hop.State == model.PathHopStateUnobservable || hop.State == model.PathHopStateObserved {
		return pathGraphNodeUnobservableRange
	}
	return pathGraphNodeUnknownRange
}

func graphGroupKindForNode(kind string) string {
	if kind == pathGraphNodeResponder {
		return pathGraphGroupHop
	}
	return kind
}

func contiguousTTL(left, right uint8) bool {
	return int(right) == int(left)+1
}

func unobservableRangeDetail(fromTTL, toTTL uint8) string {
	return fmt.Sprintf("No responder was observed for TTL %s; this is not packet loss.", ttlRangeText(fromTTL, toTTL))
}

func ttlRangeText(fromTTL, toTTL uint8) string {
	if fromTTL == toTTL {
		return strconv.Itoa(int(fromTTL))
	}
	return fmt.Sprintf("%d–%d", fromTTL, toTTL)
}

func pathDestinationNodeState(confirmed bool) model.PathHopState {
	if confirmed {
		return model.PathHopStateObserved
	}
	return model.PathHopStateUnknown
}

func pathDestinationNodeCertainty(confirmed, supported bool) model.ObservationCertainty {
	if !supported {
		return model.ObservationCertaintyUnsupported
	}
	if confirmed {
		return model.ObservationCertaintyObserved
	}
	return model.ObservationCertaintyUnknown
}

func graphNodeTone(kind string, destinationConfirmed bool) string {
	switch kind {
	case pathGraphNodeResponder:
		return "positive"
	case pathGraphNodeDestination:
		if destinationConfirmed {
			return "positive"
		}
		return "neutral"
	case pathGraphNodeUnobservableRange, pathGraphNodeUnknownRange:
		return "neutral"
	default:
		return "neutral"
	}
}

func graphSegmentKindsForRange(segments []model.PathSegment, fromTTL, toTTL uint8) []model.PathSegmentKind {
	if fromTTL == 0 && toTTL == 0 {
		return nil
	}
	result := make([]model.PathSegmentKind, 0, len(segments))
	for _, segment := range segments {
		if segment.ToTTL < fromTTL || segment.FromTTL > toTTL {
			continue
		}
		if !containsPathSegmentKind(result, segment.Kind) {
			result = append(result, segment.Kind)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func graphSegmentKindsBetween(segments []model.PathSegment, fromTTL, toTTL uint8) []model.PathSegmentKind {
	if fromTTL == 0 || toTTL == 0 {
		return nil
	}
	if fromTTL > toTTL {
		fromTTL, toTTL = toTTL, fromTTL
	}
	return graphSegmentKindsForRange(segments, fromTTL, toTTL)
}

func containsPathSegmentKind(values []model.PathSegmentKind, want model.PathSegmentKind) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func pathGraphEdgeKind(from, to pathGraphLayer, segmentKinds []model.PathSegmentKind, destination bool) string {
	if destination {
		return pathGraphEdgeDestinationConfirm
	}
	if containsPathSegmentKind(segmentKinds, model.PathSegmentUnobservable) || from.kind == pathGraphGroupUnobservable || to.kind == pathGraphGroupUnobservable {
		return pathGraphEdgeUnobservable
	}
	if containsPathSegmentKind(segmentKinds, model.PathSegmentInferred) || (from.toTTL != 0 && to.fromTTL != 0 && int(to.fromTTL) > int(from.toTTL)+1) {
		return pathGraphEdgeBoundedInference
	}
	return pathGraphEdgeObservationOrder
}

func pathGraphEdgeLabel(kind string) string {
	switch kind {
	case pathGraphEdgeUnobservable:
		return "Unobservable visibility"
	case pathGraphEdgeBoundedInference:
		return "Bounded inferred progression"
	case pathGraphEdgeDestinationConfirm:
		return "Destination confirmation"
	default:
		return "Observed order"
	}
}

func pathGraphEdgeDetail(kind string) string {
	switch kind {
	case pathGraphEdgeUnobservable:
		return "The sequence crosses a TTL range without a responder; this is not packet loss or an invented device."
	case pathGraphEdgeBoundedInference:
		return "The edge records bounded TTL progression between observations, not an exact physical link."
	case pathGraphEdgeDestinationConfirm:
		return "Destination confirmation is a separate reachability and port-state observation."
	default:
		return "The edge records canonical observation order, not physical topology."
	}
}

func pathObservationCertainty(observation model.PathObservation) model.ObservationCertainty {
	switch observation.Status {
	case model.PathObservationStatusObserved:
		return model.ObservationCertaintyObserved
	case model.PathObservationStatusUnsupported:
		return model.ObservationCertaintyUnsupported
	default:
		return model.ObservationCertaintyUnknown
	}
}

func pathObservationLimitations(observation model.PathObservation) []string {
	limitations := []string{
		"Graph nodes identify observed TTL responders, not physical devices; edges preserve bounded observation order.",
	}
	if observation.Protocol == model.PathProtocolICMP {
		limitations = append(limitations, "This ICMP path lane carries endpoint port context but does not prove destination-port connectivity.")
	} else if !observation.PortAware {
		limitations = append(limitations, "This path lane is not port-aware and does not prove destination-port connectivity.")
	}
	hasUnobservable := false
	for _, hop := range observation.Hops {
		if hop.State == model.PathHopStateUnobservable || (hop.State == model.PathHopStateObserved && len(hop.Responders) == 0) {
			hasUnobservable = true
			break
		}
	}
	if hasUnobservable {
		limitations = append(limitations, "Unobservable TTLs mean no responder was received before the bounded context ended; they are not packet loss.")
		if observation.DestinationReached || observation.DestinationTCPConnected {
			limitations = append(limitations, "Destination confirmation is independent of visibility at intermediate TTLs.")
		}
	}
	if observation.Status == model.PathObservationStatusUnsupported {
		limitations = append(limitations, "This protocol lane is unsupported; no reachability conclusion is drawn from the missing capability.")
	}
	if observation.Status == model.PathObservationStatusError {
		limitations = append(limitations, "The path adapter reported an error; partial TTL evidence remains scoped to what was observed.")
	}
	return uniqueStrings(limitations)
}

func orderedPathHops(hops []model.PathHop) []model.PathHop {
	result := append([]model.PathHop(nil), hops...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].TTL < result[j].TTL })
	return result
}

func orderedPathSegments(segments []model.PathSegment) []model.PathSegment {
	result := append([]model.PathSegment(nil), segments...)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].FromTTL != result[j].FromTTL {
			return result[i].FromTTL < result[j].FromTTL
		}
		if result[i].ToTTL != result[j].ToTTL {
			return result[i].ToTTL < result[j].ToTTL
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}

func orderedPathResponders(responders []model.PathResponder) []model.PathResponder {
	result := append([]model.PathResponder(nil), responders...)
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Response != right.Response {
			return left.Response < right.Response
		}
		if left.RTTMS != right.RTTMS {
			return left.RTTMS < right.RTTMS
		}
		return !left.DestinationReached && right.DestinationReached
	})
	return result
}

func pathGraphID(observation model.PathObservation, evidenceIDs []string) string {
	parts := []string{string(observation.Protocol), observation.Destination, strconv.Itoa(int(observation.DestinationPort))}
	if len(evidenceIDs) > 0 && evidenceIDs[0] != "" {
		parts = append(parts, evidenceIDs[0])
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, graphToken(part))
	}
	return "path-" + strings.Join(result, "-")
}

func graphToken(value string) string {
	if value == "" {
		return "none"
	}
	var builder strings.Builder
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '-' || char == '_' || char == '.' {
			builder.WriteRune(char)
			continue
		}
		builder.WriteByte('-')
	}
	return strings.Trim(builder.String(), "-")
}

func uniqueGraphNodeID(base string, nodes []PathGraphNodeView) string {
	if !graphNodeIDExists(base, nodes) {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s-%d", base, suffix)
		if !graphNodeIDExists(candidate, nodes) {
			return candidate
		}
	}
}

func graphNodeIDExists(id string, nodes []PathGraphNodeView) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}
