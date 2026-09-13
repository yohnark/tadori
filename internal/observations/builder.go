// Package observations owns the backend projection from probe-local results
// to the report-level normalized world model.  It has no presentation
// dependencies and deliberately retains source disagreement as data.
package observations

import (
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/dns"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	"github.com/yohnark/tadori/internal/probe/route"
)

// Build is the deterministic backend projector for report-level observations.
// It consumes only the target intent/execution snapshot and already-collected
// probe results.  It does not read host state, invoke probes, or mutate its
// inputs.
func Build(target model.Target, probes []model.ProbeResult) model.Observations {
	ordered := orderedProbes(probes)
	target = model.NormalizeTarget(target)

	endpoint := buildEndpointObservation(target, ordered)
	nameResolution := buildNameResolutionObservation(target, ordered)
	paths, packetFlows, pathProvenance, packetFlowProvenance, pathCorrelations, observationConflicts, observationDivergences := buildPathFlowObservations(ordered)

	// Route probes are intentionally given the execution view of the target:
	// this preserves #52's tested-endpoint hand-off while the report's Target
	// remains an intent object for new consumers.
	runtimeTarget := targetWithEndpointObservation(target, endpoint)
	networkContext := buildNetworkObservation(runtimeTarget, ordered)

	return model.NormalizeObservations(model.Observations{
		Endpoint:             endpoint,
		NameResolution:       nameResolution,
		NetworkContext:       networkContext,
		Paths:                paths,
		PacketFlows:          packetFlows,
		PathProvenance:       pathProvenance,
		PacketFlowProvenance: packetFlowProvenance,
		PathCorrelations:     pathCorrelations,
		Conflicts:            observationConflicts,
		Divergences:          observationDivergences,
	})
}

// BuildObservations is the descriptive API name used by report construction.
// Build remains available as the short projector name for backend callers.
func BuildObservations(target model.Target, probes []model.ProbeResult) model.Observations {
	return Build(target, probes)
}

func orderedProbes(probes []model.ProbeResult) []model.ProbeResult {
	ordered := append([]model.ProbeResult(nil), probes...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.ProbeID != right.ProbeID {
			return left.ProbeID < right.ProbeID
		}
		if left.CorrelationID != right.CorrelationID {
			return left.CorrelationID < right.CorrelationID
		}
		return probeOrderKey(left) < probeOrderKey(right)
	})
	for index := range ordered {
		ordered[index].Evidence = orderedEvidence(ordered[index].Evidence)
	}
	return ordered
}

func probeOrderKey(probe model.ProbeResult) string {
	selected := ""
	if probe.NameResolution != nil {
		selected = probe.NameResolution.SelectedAddress
	}
	evidenceKey := ""
	for _, evidence := range probe.Evidence {
		evidenceKey += "|" + evidence.ID + ":" + string(evidence.Kind)
	}
	return selected + evidenceKey
}

func orderedEvidence(evidence []model.Evidence) []model.Evidence {
	ordered := append([]model.Evidence(nil), evidence...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].ID != ordered[j].ID {
			return ordered[i].ID < ordered[j].ID
		}
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].Source < ordered[j].Source
	})
	return ordered
}

func buildEndpointObservation(target model.Target, probes []model.ProbeResult) model.EndpointObservation {
	observation := model.EndpointObservation{
		OriginalInput:       target.OriginalInput,
		RequestedIdentity:   target.RequestedIdentity,
		LiteralIP:           target.LiteralIP,
		Service:             target.Service,
		ApplicationProtocol: target.ApplicationProtocol,
		TransportProtocol:   target.TransportProtocol,
		Port:                target.Port,
		Resource:            target.Resource,
		Certainty:           model.ObservationCertaintyUnknown,
	}

	// The final target is authoritative for the #52 sets when orchestration
	// has already enriched it.  A standalone projector still accepts probe
	// results and reconstructs the same sets from DNS evidence.
	if len(target.ResolvedCandidates) != 0 {
		observation.ResolvedCandidates = cloneCandidatesWithMetadata(target.ResolvedCandidates, model.ObservationCertaintyDerived, "target runtime endpoint state", nil)
	}
	if len(target.ProbeCandidates) != 0 {
		observation.ProbeCandidates = cloneCandidatesWithMetadata(target.ProbeCandidates, model.ObservationCertaintyDerived, "target runtime endpoint state", nil)
	}
	if target.SelectedEndpoint != nil {
		selected := endpointWithMetadata(*target.SelectedEndpoint, model.ObservationCertaintyDerived, target.SelectedEndpoint.Provenance, nil)
		observation.SelectedEndpoint = &selected
		observation.Provenance = appendUnique(observation.Provenance, target.SelectedEndpoint.Provenance)
	}
	if target.TestedEndpoint != nil {
		tested := endpointWithMetadata(*target.TestedEndpoint, model.ObservationCertaintyObserved, target.TestedEndpoint.Provenance, nil)
		observation.TestedEndpoint = &tested
	}
	observation.CandidateAttempts = append(observation.CandidateAttempts, cloneAttempts(target.CandidateAttempts)...)

	var selectedValues []sourceValue
	var testedValues []sourceValue
	for _, probe := range probes {
		probeEvidenceIDs := evidenceIDs(probe.Evidence)
		observation.ProbeNames = appendUnique(observation.ProbeNames, probe.Name)
		for _, evidence := range probe.Evidence {
			if evidence.Kind == model.EvidenceKindDNSResolution {
				value, err := decodeDNSResolution(evidence)
				if err != nil {
					observation.Limitations = appendUnique(observation.Limitations, "DNS evidence decode: "+err.Error())
					continue
				}
				candidates := model.EndpointCandidatesFromAnswers(value.A, value.AAAA)
				if len(observation.ResolvedCandidates) == 0 {
					observation.ResolvedCandidates = append(observation.ResolvedCandidates, cloneCandidatesWithMetadata(candidates, model.ObservationCertaintyObserved, "DNS resolution evidence", []string{evidence.ID})...)
				} else {
					mergeCandidates(&observation.ResolvedCandidates, candidates, model.ObservationCertaintyObserved, "DNS resolution evidence", []string{evidence.ID})
				}
				addEndpointProvenance(&observation.Provenance, &observation.EvidenceIDs, probe, evidence)
			}
			if evidence.Kind != model.EvidenceKindTCPConnection {
				continue
			}
			var value tcpEndpointEvidence
			if err := json.Unmarshal(evidence.Raw, &value); err != nil {
				observation.Limitations = appendUnique(observation.Limitations, "TCP evidence decode: "+err.Error())
				continue
			}
			if len(value.CandidateAttempts) > 0 && len(observation.CandidateAttempts) == 0 {
				observation.CandidateAttempts = append(observation.CandidateAttempts, cloneAttempts(value.CandidateAttempts)...)
			}
			if value.TestedEndpoint != "" {
				if endpoint, ok := concreteEndpoint(value.TestedEndpoint, target.Port); ok {
					endpoint = endpointWithMetadata(endpoint, model.ObservationCertaintyObserved, "transport conn.RemoteAddr observation", []string{evidence.ID})
					testedValues = append(testedValues, sourceValue{value: endpoint.Address + ":" + strconv.Itoa(int(endpoint.Port)), probe: probe.Name, evidenceID: evidence.ID})
					if observation.TestedEndpoint == nil {
						observation.TestedEndpoint = &endpoint
					}
				}
			} else if value.RemoteEndpoint != "" && probe.Status == model.ProbeStatusPassed {
				if endpoint, ok := concreteEndpoint(value.RemoteEndpoint, target.Port); ok {
					endpoint = endpointWithMetadata(endpoint, model.ObservationCertaintyObserved, "transport conn.RemoteAddr observation", []string{evidence.ID})
					testedValues = append(testedValues, sourceValue{value: endpoint.Address + ":" + strconv.Itoa(int(endpoint.Port)), probe: probe.Name, evidenceID: evidence.ID})
					if observation.TestedEndpoint == nil {
						observation.TestedEndpoint = &endpoint
					}
				}
			}
			addEndpointProvenance(&observation.Provenance, &observation.EvidenceIDs, probe, evidence)
		}

		if probe.NameResolution != nil {
			if probe.NameResolution.SelectedAddress != "" {
				selectedValues = append(selectedValues, sourceValue{value: normalizeAddress(probe.NameResolution.SelectedAddress), probe: probe.Name, evidenceID: firstEvidenceID(probe.NameResolution.EvidenceIDs)})
			}
			candidates := model.EndpointCandidatesFromAnswers(probe.NameResolution.A, probe.NameResolution.AAAA)
			if len(observation.ResolvedCandidates) == 0 {
				observation.ResolvedCandidates = append(observation.ResolvedCandidates, cloneCandidatesWithMetadata(candidates, model.ObservationCertaintyObserved, "probe name-resolution observation", probe.NameResolution.EvidenceIDs)...)
			} else {
				mergeCandidates(&observation.ResolvedCandidates, candidates, model.ObservationCertaintyObserved, "probe name-resolution observation", probe.NameResolution.EvidenceIDs)
			}
			addNameResolutionProvenance(&observation.Provenance, &observation.EvidenceIDs, &observation.ProbeNames, probe, *probe.NameResolution)
		}

		mergeProbeTargetEndpoint(&observation, probe.Target, probe.Name, probeEvidenceIDs)
	}

	if len(observation.ResolvedCandidates) == 0 && target.LiteralIP != "" {
		if address, err := netip.ParseAddr(target.LiteralIP); err == nil {
			candidate := model.EndpointCandidate{Address: model.NormalizeAddr(address).String(), Family: endpointFamily(address), Order: 1}
			observation.ResolvedCandidates = []model.EndpointCandidate{candidateWithMetadata(candidate, model.ObservationCertaintyObserved, "canonical target literal; DNS was skipped", []string{"dns-resolution"})}
			observation.EvidenceIDs = appendUnique(observation.EvidenceIDs, "dns-resolution")
			observation.Provenance = appendUnique(observation.Provenance, "canonical target literal; DNS was skipped")
		}
	}
	if len(observation.ProbeCandidates) == 0 && len(observation.ResolvedCandidates) != 0 {
		observation.ProbeCandidates = cloneCandidatesWithMetadata(model.LimitEndpointCandidates(observation.ResolvedCandidates, model.MaxEndpointCandidates), model.ObservationCertaintyDerived, "bounded probe candidate selection", nil)
	}
	if observation.SelectedEndpoint == nil && len(observation.ProbeCandidates) != 0 {
		selected := model.Endpoint{Address: observation.ProbeCandidates[0].Address, Port: target.Port, Family: observation.ProbeCandidates[0].Family, SelectionReason: model.EndpointSelectionDeterministic, Provenance: "tadori bounded deterministic candidate selection", Certainty: model.ObservationCertaintyDerived}
		observation.SelectedEndpoint = &selected
	}
	for _, probe := range probes {
		if probe.Target.TestedEndpoint != nil {
			value := *probe.Target.TestedEndpoint
			testedValues = append(testedValues, sourceValue{value: normalizeAddress(value.Address) + ":" + strconv.Itoa(int(value.Port)), probe: probe.Name, evidenceID: firstEvidenceID(probeEvidenceIDs(probe))})
		}
	}
	if observation.TestedEndpoint != nil {
		observation.TestedEndpoint = endpointPointerWithMetadata(*observation.TestedEndpoint, model.ObservationCertaintyObserved, observation.TestedEndpoint.Provenance, observation.TestedEndpoint.EvidenceIDs)
	}
	detectSourceConflicts(&observation, selectedValues, testedValues)
	if observation.TestedEndpoint != nil || observation.SelectedEndpoint != nil || len(observation.ResolvedCandidates) != 0 {
		observation.Certainty = model.ObservationCertaintyDerived
	} else if target.RequestedIdentity != "" {
		observation.Certainty = model.ObservationCertaintyObserved
	}
	return observation
}

type sourceValue struct {
	value      string
	probe      string
	evidenceID string
}

type pathObservationRecord struct {
	value      model.PathObservation
	provenance model.ObservationProvenance
	evidenceID string
	probeName  string
}

type packetFlowRecord struct {
	value      model.PacketFlowEvidence
	provenance model.ObservationProvenance
	evidenceID string
	probeName  string
}

// buildPathFlowObservations projects the two bounded observation lanes into
// the report envelope.  The records are sorted before their parallel
// provenance slices are emitted, so the result cannot depend on probe or
// evidence arrival order.
func buildPathFlowObservations(probes []model.ProbeResult) (
	[]model.PathObservation,
	[]model.PacketFlowEvidence,
	[]model.ObservationProvenance,
	[]model.ObservationProvenance,
	[]model.PathCorrelation,
	[]model.ObservationConflict,
	[]model.ObservationDivergence,
) {
	paths := make([]pathObservationRecord, 0)
	flows := make([]packetFlowRecord, 0)
	for _, probe := range probes {
		for _, evidence := range probe.Evidence {
			source := evidence.Source
			if source == "" {
				source = probe.Name
			}
			provenance := model.ObservationProvenance{
				ProbeName:   probe.Name,
				ProbeID:     probe.ProbeID,
				Source:      source,
				EvidenceIDs: []string{evidence.ID},
			}
			switch evidence.Kind {
			case model.EvidenceKindPathObservation:
				observation, err := model.DecodePathObservation(evidence)
				if err != nil {
					continue
				}
				observation = normalizePathObservation(observation)
				paths = append(paths, pathObservationRecord{value: observation, provenance: provenance, evidenceID: evidence.ID, probeName: probe.Name})
			case model.EvidenceKindPacketFlow:
				flow, err := model.DecodePacketFlowEvidence(evidence)
				if err != nil {
					continue
				}
				flows = append(flows, packetFlowRecord{value: flow, provenance: provenance, evidenceID: evidence.ID, probeName: probe.Name})
			}
		}
	}

	sort.SliceStable(paths, func(i, j int) bool {
		left, right := paths[i], paths[j]
		leftKey, rightKey := pathObservationSortKey(left.value), pathObservationSortKey(right.value)
		if leftKey != rightKey {
			return leftKey < rightKey
		}
		return observationSourceKey(left.provenance, left.evidenceID) < observationSourceKey(right.provenance, right.evidenceID)
	})
	sort.SliceStable(flows, func(i, j int) bool {
		left, right := flows[i], flows[j]
		leftKey, rightKey := packetFlowSortKey(left.value), packetFlowSortKey(right.value)
		if leftKey != rightKey {
			return leftKey < rightKey
		}
		return observationSourceKey(left.provenance, left.evidenceID) < observationSourceKey(right.provenance, right.evidenceID)
	})

	pathValues := make([]model.PathObservation, 0, len(paths))
	pathProvenance := make([]model.ObservationProvenance, 0, len(paths))
	for _, record := range paths {
		pathValues = append(pathValues, record.value)
		pathProvenance = append(pathProvenance, record.provenance)
	}
	flowValues := make([]model.PacketFlowEvidence, 0, len(flows))
	flowProvenance := make([]model.ObservationProvenance, 0, len(flows))
	for _, record := range flows {
		flowValues = append(flowValues, record.value)
		flowProvenance = append(flowProvenance, record.provenance)
	}

	pathCorrelations := model.CorrelatePathObservations(pathValues...)
	conflicts := pathFlowConflicts(paths, flows)
	divergences := pathFlowDivergences(paths, flows)
	return pathValues, flowValues, pathProvenance, flowProvenance, pathCorrelations, conflicts, divergences
}

func normalizePathObservation(observation model.PathObservation) model.PathObservation {
	observation.Destination = normalizeAddress(observation.Destination)
	for hopIndex := range observation.Hops {
		for responderIndex := range observation.Hops[hopIndex].Responders {
			observation.Hops[hopIndex].Responders[responderIndex] = model.NormalizePathResponder(observation.Hops[hopIndex].Responders[responderIndex])
		}
	}
	for segmentIndex := range observation.Segments {
		for responderIndex := range observation.Segments[segmentIndex].Responders {
			observation.Segments[segmentIndex].Responders[responderIndex] = model.NormalizePathResponder(observation.Segments[segmentIndex].Responders[responderIndex])
		}
	}
	return observation
}

func pathObservationSortKey(observation model.PathObservation) string {
	raw, _ := json.Marshal(observation)
	return strings.Join([]string{normalizeAddress(observation.Destination), strconv.Itoa(int(observation.DestinationPort)), string(observation.Protocol), string(observation.Status), string(raw)}, "|")
}

func packetFlowSortKey(flow model.PacketFlowEvidence) string {
	destination := flow.Target.RequestedIdentity
	if flow.Target.SelectedEndpoint != nil {
		destination = flow.Target.SelectedEndpoint.Address
	} else if flow.Target.LiteralIP != "" {
		destination = flow.Target.LiteralIP
	}
	raw, _ := json.Marshal(flow)
	return strings.Join([]string{normalizeAddress(destination), strconv.Itoa(int(flow.Target.Port)), flow.CorrelationID, string(flow.CaptureStatus), string(flow.Outcome), string(raw)}, "|")
}

func observationSourceKey(provenance model.ObservationProvenance, evidenceID string) string {
	return strings.Join([]string{provenance.ProbeName, provenance.ProbeID, provenance.Source, evidenceID}, "|")
}

func pathFlowConflicts(paths []pathObservationRecord, flows []packetFlowRecord) []model.ObservationConflict {
	conflicts := make([]model.ObservationConflict, 0)
	pathGroups := make(map[string][]pathObservationRecord)
	for _, record := range paths {
		key := pathObservationKey(record.value)
		pathGroups[key] = append(pathGroups[key], record)
	}
	for _, key := range sortedKeys(pathGroups) {
		group := pathGroups[key]
		conflicts = appendPathFieldConflicts(conflicts, key, group, "status", func(value model.PathObservation) string { return string(value.Status) })
		conflicts = appendPathFieldConflicts(conflicts, key, group, "destination_reached", func(value model.PathObservation) string { return boolString(value.DestinationReached) })
		conflicts = appendPathFieldConflicts(conflicts, key, group, "destination_tcp_connected", func(value model.PathObservation) string { return boolString(value.DestinationTCPConnected) })
	}

	flowGroups := make(map[string][]packetFlowRecord)
	for _, record := range flows {
		key := packetFlowKey(record.value)
		flowGroups[key] = append(flowGroups[key], record)
	}
	for _, key := range sortedKeys(flowGroups) {
		group := flowGroups[key]
		conflicts = appendFlowFieldConflicts(conflicts, key, group, "outcome", func(value model.PacketFlowEvidence) string { return string(value.Outcome) })
		conflicts = appendFlowFieldConflicts(conflicts, key, group, "capture_status", func(value model.PacketFlowEvidence) string { return string(value.CaptureStatus) })
		conflicts = appendFlowFieldConflicts(conflicts, key, group, "probe_emission", func(value model.PacketFlowEvidence) string { return string(value.ProbeEmission) })
	}
	return conflicts
}

func appendPathFieldConflicts(destination []model.ObservationConflict, key string, group []pathObservationRecord, field string, value func(model.PathObservation) string) []model.ObservationConflict {
	values := make([]string, 0, len(group))
	provenance := make([]string, 0, len(group))
	evidenceIDs := make([]string, 0, len(group))
	for _, record := range group {
		values = appendUnique(values, value(record.value))
		provenance = appendUnique(provenance, observationProbeProvenance(record.provenance))
		evidenceIDs = appendUnique(evidenceIDs, record.evidenceID)
	}
	if len(values) < 2 {
		return destination
	}
	return append(destination, model.ObservationConflict{Field: "path[" + key + "]." + field, Values: values, Provenance: provenance, EvidenceIDs: evidenceIDs})
}

func appendFlowFieldConflicts(destination []model.ObservationConflict, key string, group []packetFlowRecord, field string, value func(model.PacketFlowEvidence) string) []model.ObservationConflict {
	values := make([]string, 0, len(group))
	provenance := make([]string, 0, len(group))
	evidenceIDs := make([]string, 0, len(group))
	for _, record := range group {
		values = appendUnique(values, value(record.value))
		provenance = appendUnique(provenance, observationProbeProvenance(record.provenance))
		evidenceIDs = appendUnique(evidenceIDs, record.evidenceID)
	}
	if len(values) < 2 {
		return destination
	}
	return append(destination, model.ObservationConflict{Field: "packet_flow[" + key + "]." + field, Values: values, Provenance: provenance, EvidenceIDs: evidenceIDs})
}

func pathFlowDivergences(paths []pathObservationRecord, flows []packetFlowRecord) []model.ObservationDivergence {
	type divergenceGroup struct {
		pathValues            []string
		packetFlowValues      []string
		pathProvenance        []string
		packetFlowProvenance  []string
		pathEvidenceIDs       []string
		packetFlowEvidenceIDs []string
	}
	groups := make(map[string]*divergenceGroup)
	for _, path := range paths {
		pathValue, pathExplicit := pathConfirmation(path.value)
		if !pathExplicit {
			continue
		}
		for _, flow := range flows {
			if !pathFlowKeysMatch(path.value, flow.value) {
				continue
			}
			flowValue, flowExplicit := packetFlowConfirmation(flow.value, path.value.Protocol)
			if !flowExplicit || pathValue == flowValue {
				continue
			}
			key := pathObservationKey(path.value)
			group := groups[key]
			if group == nil {
				group = &divergenceGroup{}
				groups[key] = group
			}
			group.pathValues = appendUnique(group.pathValues, pathValue)
			group.packetFlowValues = appendUnique(group.packetFlowValues, flowValue)
			group.pathProvenance = appendUnique(group.pathProvenance, observationProbeProvenance(path.provenance))
			group.packetFlowProvenance = appendUnique(group.packetFlowProvenance, observationProbeProvenance(flow.provenance))
			group.pathEvidenceIDs = appendUnique(group.pathEvidenceIDs, path.evidenceID)
			group.packetFlowEvidenceIDs = appendUnique(group.packetFlowEvidenceIDs, flow.evidenceID)
		}
	}

	result := make([]model.ObservationDivergence, 0, len(groups))
	for _, key := range sortedKeys(groups) {
		group := groups[key]
		result = append(result, model.ObservationDivergence{
			Field:                 "destination_confirmation[" + key + "]",
			PathValues:            group.pathValues,
			PacketFlowValues:      group.packetFlowValues,
			PathProvenance:        group.pathProvenance,
			PacketFlowProvenance:  group.packetFlowProvenance,
			PathEvidenceIDs:       group.pathEvidenceIDs,
			PacketFlowEvidenceIDs: group.packetFlowEvidenceIDs,
		})
	}
	return result
}

func pathObservationKey(observation model.PathObservation) string {
	return strings.Join([]string{normalizeAddress(observation.Destination), strconv.Itoa(int(observation.DestinationPort)), string(observation.Protocol)}, ":")
}

func packetFlowKey(flow model.PacketFlowEvidence) string {
	destination := flow.Target.RequestedIdentity
	if flow.Target.SelectedEndpoint != nil {
		destination = flow.Target.SelectedEndpoint.Address
	} else if flow.Target.LiteralIP != "" {
		destination = flow.Target.LiteralIP
	}
	return strings.Join([]string{normalizeAddress(destination), strconv.Itoa(int(flow.Target.Port)), string(flowProtocol(flow))}, ":")
}

func pathFlowKeysMatch(path model.PathObservation, flow model.PacketFlowEvidence) bool {
	if path.DestinationPort != flow.Target.Port || path.Protocol != flowProtocol(flow) {
		return false
	}
	if normalizeAddress(path.Destination) == normalizeAddress(flow.Target.LiteralIP) || normalizeAddress(path.Destination) == normalizeAddress(flow.Target.RequestedIdentity) {
		return true
	}
	return flow.Target.MatchesAddress(path.Destination)
}

func flowProtocol(flow model.PacketFlowEvidence) model.PathProtocol {
	var protocol model.PathProtocol
	for _, observation := range flow.Observations {
		var candidate model.PathProtocol
		switch observation.Protocol {
		case model.PacketProtocolTCP:
			candidate = model.PathProtocolTCP
		case model.PacketProtocolICMP:
			candidate = model.PathProtocolICMP
		}
		if candidate == "" {
			continue
		}
		if protocol == "" {
			protocol = candidate
		} else if protocol != candidate {
			return ""
		}
	}
	if protocol != "" {
		return protocol
	}
	switch flow.Outcome {
	case model.PacketFlowOutcomeTCPHandshakeConfirmed, model.PacketFlowOutcomeTCPSYNACK, model.PacketFlowOutcomeTCPRST:
		return model.PathProtocolTCP
	case model.PacketFlowOutcomeICMPEchoReply, model.PacketFlowOutcomeICMPTimeExceeded, model.PacketFlowOutcomeICMPUnreachable:
		return model.PathProtocolICMP
	default:
		return ""
	}
}

func pathConfirmation(observation model.PathObservation) (string, bool) {
	if observation.Status != model.PathObservationStatusObserved {
		return "", false
	}
	if observation.DestinationReached || observation.DestinationTCPConnected {
		return "confirmed", true
	}
	return "not_confirmed", true
}

func packetFlowConfirmation(flow model.PacketFlowEvidence, protocol model.PathProtocol) (string, bool) {
	if flowProtocol(flow) != protocol || flow.CaptureStatus != model.PacketCaptureStatusAvailable {
		return "", false
	}
	switch flow.Outcome {
	case model.PacketFlowOutcomeTCPHandshakeConfirmed, model.PacketFlowOutcomeTCPSYNACK, model.PacketFlowOutcomeTCPRST, model.PacketFlowOutcomeICMPEchoReply:
		return "confirmed", true
	case model.PacketFlowOutcomeICMPTimeExceeded, model.PacketFlowOutcomeICMPUnreachable, model.PacketFlowOutcomeNoMatchingResponse:
		return "not_confirmed", true
	default:
		return "", false
	}
}

func observationProbeProvenance(provenance model.ObservationProvenance) string {
	if provenance.ProbeName != "" {
		return "probe:" + provenance.ProbeName
	}
	return "source:" + provenance.Source
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func detectSourceConflicts(observation *model.EndpointObservation, selected, tested []sourceValue) {
	if values := distinctSourceValues(selected); len(values) > 1 {
		observation.Conflicts = append(observation.Conflicts, conflict("endpoint.resolved_address", values, selected))
	}
	if values := distinctSourceValues(tested); len(values) > 1 {
		observation.Conflicts = append(observation.Conflicts, conflict("endpoint.tested_endpoint", values, tested))
	}
}

func distinctSourceValues(values []sourceValue) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value.value == "" || contains(result, value.value) {
			continue
		}
		result = append(result, value.value)
	}
	return result
}

func conflict(field string, values []string, sources []sourceValue) model.ObservationConflict {
	result := model.ObservationConflict{Field: field, Values: append([]string(nil), values...)}
	for _, source := range sources {
		result.Provenance = appendUnique(result.Provenance, "probe:"+source.probe)
		result.EvidenceIDs = appendUnique(result.EvidenceIDs, source.evidenceID)
	}
	return result
}

func mergeProbeTargetEndpoint(observation *model.EndpointObservation, target model.Target, probeName string, evidenceIDs []string) {
	if len(target.ResolvedCandidates) != 0 {
		mergeCandidates(&observation.ResolvedCandidates, target.ResolvedCandidates, model.ObservationCertaintyDerived, "probe target endpoint state", evidenceIDs)
	}
	if len(target.ProbeCandidates) != 0 {
		if len(observation.ProbeCandidates) == 0 {
			observation.ProbeCandidates = cloneCandidatesWithMetadata(target.ProbeCandidates, model.ObservationCertaintyDerived, "probe target endpoint state", evidenceIDs)
		}
	}
	if target.SelectedEndpoint != nil && observation.SelectedEndpoint == nil {
		selected := endpointWithMetadata(*target.SelectedEndpoint, model.ObservationCertaintyDerived, target.SelectedEndpoint.Provenance, evidenceIDs)
		observation.SelectedEndpoint = &selected
	}
	if target.TestedEndpoint != nil && observation.TestedEndpoint == nil {
		tested := endpointWithMetadata(*target.TestedEndpoint, model.ObservationCertaintyObserved, target.TestedEndpoint.Provenance, evidenceIDs)
		observation.TestedEndpoint = &tested
	}
	if len(target.CandidateAttempts) != 0 && len(observation.CandidateAttempts) == 0 {
		observation.CandidateAttempts = cloneAttempts(target.CandidateAttempts)
	}
	if probeName != "" {
		observation.ProbeNames = appendUnique(observation.ProbeNames, probeName)
	}
}

func buildNameResolutionObservation(target model.Target, probes []model.ProbeResult) model.NameResolutionObservation {
	observation := model.NameResolutionObservation{
		RequestedName: target.RequestedIdentity,
		Certainty:     model.ObservationCertaintyUnknown,
	}
	for _, probe := range probes {
		if probe.NameResolution != nil {
			value := model.NormalizeNameResolutionObservation(*probe.NameResolution)
			mergeNameResolution(&observation, value, probe.Name)
		}
		for _, evidence := range probe.Evidence {
			switch evidence.Kind {
			case model.EvidenceKindDNSResolution:
				value, err := decodeDNSResolution(evidence)
				if err != nil {
					observation.Limitations = appendUnique(observation.Limitations, "DNS evidence decode: "+err.Error())
					continue
				}
				mergeNameResolution(&observation, resolutionFromEvidence(value, evidence, probe), probe.Name)
			case model.EvidenceKindDNSConfiguration:
				mergeNameResolution(&observation, configurationFromEvidence(evidence), probe.Name)
			}
		}
	}
	if target.LiteralIP != "" && observation.SelectedAddress == "" {
		if address, err := netip.ParseAddr(target.LiteralIP); err == nil {
			address = model.NormalizeAddr(address)
			if address.Is4() {
				observation.A = []string{address.String()}
				observation.SelectedFamily = string(model.EndpointFamilyIPv4)
			} else {
				observation.AAAA = []string{address.String()}
				observation.SelectedFamily = string(model.EndpointFamilyIPv6)
			}
			observation.SelectedAddress = address.String()
			observation.EffectivePath = &model.NameResolutionPath{State: model.NameResolutionPathEffective, Mechanism: model.NameResolutionMechanismLiteralIP, Certainty: model.NameResolutionCertaintyObserved, Provenance: "canonical target literal; DNS was skipped", EvidenceIDs: []string{"dns-resolution"}, A: append([]string(nil), observation.A...), AAAA: append([]string(nil), observation.AAAA...)}
			observation.EvidenceIDs = appendUnique(observation.EvidenceIDs, "dns-resolution")
			observation.Provenance = appendUnique(observation.Provenance, "canonical target literal; DNS was skipped")
		}
	}
	if observation.RequestedName == "" {
		observation.RequestedName = target.RequestedIdentity
	}
	if observation.RequestedName != "" && len(observation.CandidateNames) == 0 {
		observation.CandidateNames = candidateNames(observation.RequestedName, observation.CandidateSuffixes)
	}
	if len(observation.A) != 0 || len(observation.AAAA) != 0 || observation.EffectivePath != nil {
		if observation.Certainty == model.ObservationCertaintyUnknown {
			observation.Certainty = model.ObservationCertaintyObserved
		}
	} else if len(observation.Paths) != 0 {
		observation.Certainty = model.ObservationCertaintyInferred
	}
	for _, probe := range probes {
		if observation.Certainty != model.ObservationCertaintyObserved && probe.Interpretation.FailureReason == model.FailureReasonUnsupported {
			observation.Certainty = model.ObservationCertaintyUnsupported
			break
		}
	}
	if observation.SelectedAddress == "" {
		if address := firstAnswer(observation.A, observation.AAAA); address != "" {
			observation.SelectedAddress = normalizeAddress(address)
			if len(observation.A) != 0 {
				observation.SelectedFamily = string(model.EndpointFamilyIPv4)
			} else {
				observation.SelectedFamily = string(model.EndpointFamilyIPv6)
			}
		}
	}
	return model.NormalizeNameResolutionObservation(observation)
}

func mergeNameResolution(destination *model.NameResolutionObservation, source model.NameResolutionObservation, probeName string) {
	if source.RequestedName != "" && destination.RequestedName != "" && !strings.EqualFold(source.RequestedName, destination.RequestedName) {
		destination.Conflicts = append(destination.Conflicts, model.ObservationConflict{Field: "name_resolution.requested_name", Values: []string{destination.RequestedName, source.RequestedName}, Provenance: []string{"probe:" + probeName}})
	} else if destination.RequestedName == "" {
		destination.RequestedName = source.RequestedName
	}
	destination.CandidateNames = appendUniqueFold(destination.CandidateNames, source.CandidateNames...)
	destination.CandidateSuffixes = appendUniqueFold(destination.CandidateSuffixes, source.CandidateSuffixes...)
	destination.CandidateNamespaces = appendUniqueFold(destination.CandidateNamespaces, source.CandidateNamespaces...)
	destination.A = appendUnique(destination.A, source.A...)
	destination.AAAA = appendUnique(destination.AAAA, source.AAAA...)
	destination.Paths = append(destination.Paths, cloneNamePaths(source.Paths)...)
	for _, path := range source.Paths {
		destination.Provenance = appendUnique(destination.Provenance, path.Provenance)
		destination.EvidenceIDs = appendUnique(destination.EvidenceIDs, path.EvidenceIDs...)
	}
	if source.EffectivePath != nil {
		if destination.EffectivePath == nil {
			path := *source.EffectivePath
			destination.EffectivePath = &path
		} else if namePathKey(*destination.EffectivePath) != namePathKey(*source.EffectivePath) {
			destination.Paths = append(destination.Paths, *source.EffectivePath)
			destination.Conflicts = append(destination.Conflicts, model.ObservationConflict{Field: "name_resolution.effective_path", Values: []string{namePathKey(*destination.EffectivePath), namePathKey(*source.EffectivePath)}, Provenance: []string{"probe:" + probeName}, EvidenceIDs: append([]string(nil), source.EvidenceIDs...)})
		}
	}
	if source.SelectedAddress != "" && destination.SelectedAddress != "" && normalizeAddress(source.SelectedAddress) != normalizeAddress(destination.SelectedAddress) {
		destination.Conflicts = append(destination.Conflicts, model.ObservationConflict{Field: "name_resolution.selected_address", Values: []string{destination.SelectedAddress, source.SelectedAddress}, Provenance: []string{"probe:" + probeName}, EvidenceIDs: append([]string(nil), source.EvidenceIDs...)})
	} else if destination.SelectedAddress == "" {
		destination.SelectedAddress = source.SelectedAddress
		destination.SelectedFamily = source.SelectedFamily
	}
	destination.HostsFileEntries = appendHostEntries(destination.HostsFileEntries, source.HostsFileEntries...)
	destination.Limitations = appendUnique(destination.Limitations, source.Limitations...)
	destination.EvidenceIDs = appendUnique(destination.EvidenceIDs, source.EvidenceIDs...)
	destination.Provenance = appendUnique(destination.Provenance, source.Provenance...)
	destination.ProbeNames = appendUnique(destination.ProbeNames, source.ProbeNames...)
	destination.ProbeNames = appendUnique(destination.ProbeNames, probeName)
	destination.Conflicts = append(destination.Conflicts, source.Conflicts...)
	destination.Certainty = strongerCertainty(destination.Certainty, source.Certainty)
}

func resolutionFromEvidence(value dns.DNSResolutionEvidence, evidence model.Evidence, probe model.ProbeResult) model.NameResolutionObservation {
	observation := model.NameResolutionObservation{
		RequestedName: value.Host,
		A:             append([]string(nil), value.A...),
		AAAA:          append([]string(nil), value.AAAA...),
		EvidenceIDs:   []string{evidence.ID},
		Provenance:    []string{"source:" + evidence.Source},
		ProbeNames:    []string{probe.Name},
		Certainty:     model.ObservationCertaintyObserved,
	}
	if len(value.A) != 0 || len(value.AAAA) != 0 || len(value.Results) != 0 {
		path := model.NameResolutionPath{
			State:       model.NameResolutionPathEffective,
			Mechanism:   model.NameResolutionMechanismDNS,
			Certainty:   model.NameResolutionCertaintyObserved,
			Provenance:  "resolver result; server and interface provenance are unavailable",
			EvidenceIDs: []string{evidence.ID},
			A:           append([]string(nil), value.A...),
			AAAA:        append([]string(nil), value.AAAA...),
		}
		observation.EffectivePath = &path
	}
	return observation
}

func configurationFromEvidence(evidence model.Evidence) model.NameResolutionObservation {
	var value dns.DNSConfigurationEvidence
	if err := json.Unmarshal(evidence.Raw, &value); err != nil {
		return model.NameResolutionObservation{Limitations: []string{"DNS configuration evidence decode: " + err.Error()}, EvidenceIDs: []string{evidence.ID}, Provenance: []string{"source:" + evidence.Source}, Certainty: model.ObservationCertaintyUnknown}
	}
	observation := model.NameResolutionObservation{
		EvidenceIDs: []string{evidence.ID},
		Provenance:  []string{"source:" + evidence.Source},
		Certainty:   model.ObservationCertaintyInferred,
	}
	if value.Environment != nil {
		appendDNSEnvironment(&observation, *value.Environment, evidence.ID)
	}
	// interfacecfg's DNS probe predates dns.ResolutionEnvironment and emits
	// the same facts at the top level. Project both shapes into the same path
	// model so the envelope is independent of which configuration probe ran.
	var legacy interfaceDNSConfigurationEvidence
	if err := json.Unmarshal(evidence.Raw, &legacy); err == nil {
		appendLegacyDNSConfiguration(&observation, legacy, evidence.ID)
	}
	for _, resolver := range value.Resolvers {
		observation.Paths = append(observation.Paths, model.NameResolutionPath{State: model.NameResolutionPathConfiguredCandidate, Mechanism: model.NameResolutionMechanismDNS, Resolver: normalizeAddress(resolver), Certainty: model.NameResolutionCertaintyConfigured, Provenance: "configured resolver candidate; not proof of query selection", EvidenceIDs: []string{evidence.ID}})
	}
	if value.Error != "" {
		observation.Limitations = appendUnique(observation.Limitations, "resolver configuration: "+value.Error)
	}
	return observation
}

type interfaceDNSConfigurationEvidence struct {
	Servers          []netip.Addr                     `json:"servers"`
	Interfaces       []interfacecfg.InterfaceState    `json:"interfaces,omitempty"`
	Suffixes         []string                         `json:"suffixes,omitempty"`
	SearchList       []string                         `json:"search_list,omitempty"`
	NRPT             []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
	NRPTError        string                           `json:"nrpt_error,omitempty"`
	HostsFileEntries []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
	HostsFileError   string                           `json:"hosts_file_error,omitempty"`
	Source           string                           `json:"source,omitempty"`
	Error            string                           `json:"error,omitempty"`
}

func appendDNSEnvironment(observation *model.NameResolutionObservation, environment dns.ResolutionEnvironment, evidenceID string) {
	observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, environment.CandidateSuffixes...)
	observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, environment.SearchList...)
	for _, iface := range environment.Interfaces {
		observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, iface.DNSSuffix)
		observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, iface.DNSSearchList...)
		for _, server := range iface.DNSServers {
			observation.Paths = append(observation.Paths, model.NameResolutionPath{State: model.NameResolutionPathConfiguredCandidate, Mechanism: model.NameResolutionMechanismDNS, Resolver: normalizeAddress(server), Interface: iface.Name, InterfaceIndex: iface.Index, VirtualAdapter: iface.VirtualAdapter, VPN: iface.VPN, Namespaces: append([]string(nil), iface.DNSSearchList...), Certainty: model.NameResolutionCertaintyConfigured, Provenance: "interface-specific DNS configuration; not proof of query selection", EvidenceIDs: []string{evidenceID}})
		}
	}
	for _, rule := range environment.NRPT {
		appendPolicyPaths(observation, rule, evidenceID)
	}
	observation.HostsFileEntries = appendHostEntries(observation.HostsFileEntries, environment.HostsFileEntries...)
	if environment.Error != "" {
		observation.Limitations = appendUnique(observation.Limitations, "name-resolution environment: "+environment.Error)
	}
	if environment.ResolverError != "" {
		observation.Limitations = appendUnique(observation.Limitations, "configured resolver state: "+environment.ResolverError)
	}
	if environment.PolicyError != "" {
		observation.Limitations = appendUnique(observation.Limitations, "NRPT policy: "+environment.PolicyError)
	}
	if environment.HostsFileError != "" {
		observation.Limitations = appendUnique(observation.Limitations, "hosts file: "+environment.HostsFileError)
	}
}

func appendLegacyDNSConfiguration(observation *model.NameResolutionObservation, value interfaceDNSConfigurationEvidence, evidenceID string) {
	observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, value.Suffixes...)
	observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, value.SearchList...)
	for _, iface := range value.Interfaces {
		observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, iface.DNSSuffix)
		observation.CandidateSuffixes = appendUnique(observation.CandidateSuffixes, iface.DNSSearchList...)
		for _, server := range iface.DNSServers {
			observation.Paths = append(observation.Paths, model.NameResolutionPath{State: model.NameResolutionPathConfiguredCandidate, Mechanism: model.NameResolutionMechanismDNS, Resolver: normalizeAddress(server.String()), Interface: iface.Name, InterfaceIndex: iface.Index, Namespaces: append([]string(nil), iface.DNSSearchList...), Certainty: model.NameResolutionCertaintyConfigured, Provenance: "interface-specific DNS configuration; not proof of query selection", EvidenceIDs: []string{evidenceID}})
		}
	}
	for _, rule := range value.NRPT {
		appendPolicyPaths(observation, rule, evidenceID)
	}
	observation.HostsFileEntries = appendHostEntries(observation.HostsFileEntries, value.HostsFileEntries...)
	if value.NRPTError != "" {
		observation.Limitations = appendUnique(observation.Limitations, "NRPT policy: "+value.NRPTError)
	}
	if value.HostsFileError != "" {
		observation.Limitations = appendUnique(observation.Limitations, "hosts file: "+value.HostsFileError)
	}
}

func appendPolicyPaths(observation *model.NameResolutionObservation, rule model.NameResolutionPolicyRule, evidenceID string) {
	for _, namespace := range rule.Namespaces {
		observation.CandidateNamespaces = appendUnique(observation.CandidateNamespaces, namespace)
	}
	servers := append([]string(nil), rule.NameServers...)
	if len(servers) == 0 {
		servers = []string{""}
	}
	for _, server := range servers {
		observation.Paths = append(observation.Paths, model.NameResolutionPath{State: model.NameResolutionPathPolicyCandidate, Mechanism: model.NameResolutionMechanismDNS, Resolver: normalizeAddress(server), Namespace: firstNamespace(rule), Namespaces: append([]string(nil), rule.Namespaces...), PolicySource: rule.Source, PolicyRule: rule.RuleID, VPN: rule.VPNRequired, Certainty: model.NameResolutionCertaintyConfigured, Provenance: "matching NRPT namespace policy; not proof of query selection", EvidenceIDs: []string{evidenceID}})
	}
}

func buildNetworkObservation(target model.Target, probes []model.ProbeResult) model.NetworkContext {
	context, ok := route.NetworkContextFromProbeResults(target, probes)
	if !ok {
		context = model.NetworkContext{RequestedIdentity: target.RequestedIdentity, EffectiveRoute: model.RouteDispositionUnknown, NetworkScope: model.NetworkScopeUnknown, Certainty: model.ObservationCertaintyUnknown}
		for _, probe := range probes {
			if probe.Name != route.TargetRouteProbeName && probe.Name != route.DefaultRouteProbeName && probe.Name != route.GatewayProbeName {
				continue
			}
			if probe.Interpretation.FailureReason == model.FailureReasonUnsupported {
				context.Certainty = model.ObservationCertaintyUnsupported
			}
			context.ProbeNames = appendUnique(context.ProbeNames, probe.Name)
			context.EvidenceIDs = appendUnique(context.EvidenceIDs, evidenceIDs(probe.Evidence)...)
		}
	}
	for _, probe := range probes {
		relevant := false
		for _, evidence := range probe.Evidence {
			if evidence.Kind == model.EvidenceKindRoute || evidence.Kind == model.EvidenceKindInterfaceState {
				relevant = true
				context.EvidenceIDs = appendUnique(context.EvidenceIDs, evidence.ID)
				if evidence.Source != "" {
					context.Provenance = appendUnique(context.Provenance, evidence.Source)
				}
			}
		}
		if relevant {
			context.ProbeNames = appendUnique(context.ProbeNames, probe.Name)
		}
	}
	if context.EffectiveRoute != model.RouteDispositionUnknown || context.SelectedDestinationAddress != "" {
		context.Certainty = model.ObservationCertaintyDerived
	}
	if context.Certainty != model.ObservationCertaintyDerived {
		for _, probe := range probes {
			if (probe.Name == route.TargetRouteProbeName || probe.Name == route.DefaultRouteProbeName || probe.Name == route.GatewayProbeName) && probe.Interpretation.FailureReason == model.FailureReasonUnsupported {
				context.Certainty = model.ObservationCertaintyUnsupported
				break
			}
		}
	}
	detectRouteConflicts(&context, probes)
	return context
}

func detectRouteConflicts(context *model.NetworkContext, probes []model.ProbeResult) {
	var sources []sourceValue
	for _, probe := range probes {
		for _, evidence := range probe.Evidence {
			if evidence.Kind != model.EvidenceKindRoute {
				continue
			}
			value, err := route.DecodeRouteEvidence(evidence)
			if err != nil || value.RouteType != "target" {
				continue
			}
			key := strings.Join([]string{value.RoutePrefix, value.Gateway, value.Interface, value.SourceAddress, value.TargetIP}, "|")
			sources = append(sources, sourceValue{value: key, probe: probe.Name, evidenceID: evidence.ID})
		}
	}
	if values := distinctSourceValues(sources); len(values) > 1 {
		context.Conflicts = append(context.Conflicts, conflict("network_context.effective_route", values, sources))
	}
}

func targetWithEndpointObservation(target model.Target, endpoint model.EndpointObservation) model.Target {
	target.ResolvedCandidates = cloneCandidates(endpoint.ResolvedCandidates)
	target.ProbeCandidates = cloneCandidates(endpoint.ProbeCandidates)
	target.CandidateAttempts = cloneAttempts(endpoint.CandidateAttempts)
	if endpoint.SelectedEndpoint != nil {
		selected := *endpoint.SelectedEndpoint
		target.SelectedEndpoint = &selected
	}
	if endpoint.TestedEndpoint != nil {
		tested := *endpoint.TestedEndpoint
		target.TestedEndpoint = &tested
	}
	return target
}

type tcpEndpointEvidence struct {
	RemoteEndpoint    string                  `json:"remote_endpoint"`
	TestedEndpoint    string                  `json:"tested_endpoint"`
	CandidateAttempts []model.EndpointAttempt `json:"candidate_attempts"`
}

func decodeDNSResolution(evidence model.Evidence) (dns.DNSResolutionEvidence, error) {
	var value dns.DNSResolutionEvidence
	if err := json.Unmarshal(evidence.Raw, &value); err != nil {
		return dns.DNSResolutionEvidence{}, err
	}
	return value, nil
}

func concreteEndpoint(raw string, defaultPort uint16) (model.Endpoint, bool) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		host = strings.Trim(strings.TrimSpace(raw), "[]")
		portText = strconv.Itoa(int(defaultPort))
	}
	if host == "" {
		return model.Endpoint{}, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return model.Endpoint{}, false
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return model.Endpoint{}, false
	}
	address = model.NormalizeAddr(address)
	return model.Endpoint{Address: address.String(), Port: uint16(port), Family: endpointFamily(address), SelectionReason: model.EndpointSelectionTransport}, true
}

func endpointFamily(address netip.Addr) model.EndpointFamily {
	if address.Is4() || address.Is4In6() {
		return model.EndpointFamilyIPv4
	}
	return model.EndpointFamilyIPv6
}

func endpointWithMetadata(value model.Endpoint, certainty model.ObservationCertainty, provenance string, evidenceIDs []string) model.Endpoint {
	if value.Address != "" {
		if address, err := netip.ParseAddr(strings.Trim(value.Address, "[]")); err == nil {
			address = model.NormalizeAddr(address)
			value.Address = address.String()
			if value.Family == "" {
				value.Family = endpointFamily(address)
			}
		}
	}
	if value.Certainty == "" {
		value.Certainty = certainty
	}
	if value.Provenance == "" {
		value.Provenance = provenance
	}
	value.EvidenceIDs = appendUnique(value.EvidenceIDs, evidenceIDs...)
	return value
}

func endpointPointerWithMetadata(value model.Endpoint, certainty model.ObservationCertainty, provenance string, evidenceIDs []string) *model.Endpoint {
	value = endpointWithMetadata(value, certainty, provenance, evidenceIDs)
	return &value
}

func candidateWithMetadata(value model.EndpointCandidate, certainty model.ObservationCertainty, provenance string, evidenceIDs []string) model.EndpointCandidate {
	value.Address = normalizeAddress(value.Address)
	if value.Address != "" && value.Family == "" {
		if address, err := netip.ParseAddr(value.Address); err == nil {
			value.Family = endpointFamily(address)
		}
	}
	if value.Certainty == "" {
		value.Certainty = certainty
	}
	if value.Provenance == "" {
		value.Provenance = provenance
	}
	value.EvidenceIDs = appendUnique(value.EvidenceIDs, evidenceIDs...)
	return value
}

func cloneCandidates(values []model.EndpointCandidate) []model.EndpointCandidate {
	result := make([]model.EndpointCandidate, len(values))
	for index, value := range values {
		result[index] = value
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	}
	return result
}

func cloneCandidatesWithMetadata(values []model.EndpointCandidate, certainty model.ObservationCertainty, provenance string, evidenceIDs []string) []model.EndpointCandidate {
	result := make([]model.EndpointCandidate, 0, len(values))
	for index, value := range values {
		value = candidateWithMetadata(value, certainty, provenance, evidenceIDs)
		value.Order = index + 1
		result = append(result, value)
	}
	return result
}

func mergeCandidates(destination *[]model.EndpointCandidate, values []model.EndpointCandidate, certainty model.ObservationCertainty, provenance string, evidenceIDs []string) {
	for _, value := range values {
		value = candidateWithMetadata(value, certainty, provenance, evidenceIDs)
		found := false
		for index := range *destination {
			if (*destination)[index].Address != value.Address {
				continue
			}
			(*destination)[index].EvidenceIDs = appendUnique((*destination)[index].EvidenceIDs, value.EvidenceIDs...)
			if (*destination)[index].Provenance == "" {
				(*destination)[index].Provenance = value.Provenance
			}
			found = true
			break
		}
		if !found {
			value.Order = len(*destination) + 1
			*destination = append(*destination, value)
		}
	}
}

func cloneAttempts(values []model.EndpointAttempt) []model.EndpointAttempt {
	result := make([]model.EndpointAttempt, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Candidate = candidateWithMetadata(value.Candidate, model.ObservationCertaintyObserved, "transport candidate attempt", value.EvidenceIDs)
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
		if result[index].Certainty == "" {
			result[index].Certainty = model.ObservationCertaintyObserved
		}
	}
	return result
}

func cloneNamePaths(values []model.NameResolutionPath) []model.NameResolutionPath {
	result := make([]model.NameResolutionPath, len(values))
	for index, value := range values {
		result[index] = value
		result[index].A = append([]string(nil), value.A...)
		result[index].AAAA = append([]string(nil), value.AAAA...)
		result[index].Namespaces = append([]string(nil), value.Namespaces...)
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	}
	return result
}

func appendHostEntries(destination []model.NameResolutionHostEntry, values ...model.NameResolutionHostEntry) []model.NameResolutionHostEntry {
	for _, value := range values {
		duplicate := false
		for _, existing := range destination {
			if strings.EqualFold(existing.Name, value.Name) && strings.Join(existing.Addresses, ",") == strings.Join(value.Addresses, ",") && existing.Source == value.Source {
				duplicate = true
				break
			}
		}
		if !duplicate {
			destination = append(destination, value)
		}
	}
	return destination
}

func addEndpointProvenance(provenance *[]string, evidenceIDs *[]string, probe model.ProbeResult, evidence model.Evidence) {
	*provenance = appendUnique(*provenance, "probe:"+probe.Name)
	if evidence.Source != "" {
		*provenance = appendUnique(*provenance, "source:"+evidence.Source)
	}
	*evidenceIDs = appendUnique(*evidenceIDs, evidence.ID)
}

func addNameResolutionProvenance(provenance *[]string, evidenceIDs *[]string, probeNames *[]string, probe model.ProbeResult, observation model.NameResolutionObservation) {
	*provenance = appendUnique(*provenance, observation.Provenance...)
	*evidenceIDs = appendUnique(*evidenceIDs, observation.EvidenceIDs...)
	*probeNames = appendUnique(*probeNames, probe.Name)
}

func evidenceIDs(evidence []model.Evidence) []string {
	result := make([]string, 0, len(evidence))
	for _, value := range evidence {
		result = appendUnique(result, value.ID)
	}
	return result
}

func probeEvidenceIDs(probe model.ProbeResult) []string {
	return evidenceIDs(probe.Evidence)
}

func firstEvidenceID(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func firstAnswer(a, aaaa []string) string {
	for _, value := range append(append([]string(nil), a...), aaaa...) {
		if normalizeAddress(value) != "" {
			return value
		}
	}
	return ""
}

func candidateNames(name string, suffixes []string) []string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}
	result := []string{name}
	if strings.Contains(name, ".") {
		return result
	}
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
		if suffix != "" {
			result = appendUnique(result, name+"."+suffix)
		}
	}
	return result
}

func namePathKey(path model.NameResolutionPath) string {
	return strings.Join([]string{string(path.State), string(path.Mechanism), path.Resolver, path.Interface, path.PolicySource, path.PolicyRule}, "|")
}

func firstNamespace(rule model.NameResolutionPolicyRule) string {
	if len(rule.Namespaces) == 0 {
		return ""
	}
	return rule.Namespaces[0]
}

func strongerCertainty(left, right model.ObservationCertainty) model.ObservationCertainty {
	rank := func(value model.ObservationCertainty) int {
		switch value {
		case model.ObservationCertaintyObserved:
			return 5
		case model.ObservationCertaintyDerived:
			return 4
		case model.ObservationCertaintyInferred:
			return 3
		case model.ObservationCertaintyUnsupported:
			return 2
		case model.ObservationCertaintyUnknown:
			return 1
		default:
			return 0
		}
	}
	if rank(right) > rank(left) {
		return right
	}
	return left
}

func normalizeAddress(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if address, err := netip.ParseAddr(value); err == nil {
		return model.NormalizeAddr(address).String()
	}
	return value
}

func appendUnique(values []string, additions ...string) []string {
	for _, value := range additions {
		if value == "" || contains(values, value) {
			continue
		}
		values = append(values, value)
	}
	return values
}

func appendUniqueFold(values []string, additions ...string) []string {
	for _, value := range additions {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if value == "" {
			continue
		}
		found := false
		for _, existing := range values {
			if strings.EqualFold(existing, value) {
				found = true
				break
			}
		}
		if !found {
			values = append(values, value)
		}
	}
	return values
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}
