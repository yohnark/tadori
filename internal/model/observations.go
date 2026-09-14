package model

// ObservationCertainty describes the relationship between a normalized fact
// and the evidence that supports it.  It is intentionally independent from
// probe status: an otherwise successful probe may only provide configured or
// inferred context, while a failed probe may still provide observed facts.
type ObservationCertainty string

const (
	ObservationCertaintyObserved    ObservationCertainty = "observed"
	ObservationCertaintyConfigured  ObservationCertainty = "configured"
	ObservationCertaintyDerived     ObservationCertainty = "derived"
	ObservationCertaintyInferred    ObservationCertainty = "inferred"
	ObservationCertaintyUnknown     ObservationCertainty = "unknown"
	ObservationCertaintyUnsupported ObservationCertainty = "unsupported"
)

// ObservationProvenance is a compact reference to the probe and evidence
// that contributed to a normalized observation.  Source is the adapter or
// platform source label, not a human-facing explanation.
type ObservationProvenance struct {
	ProbeName   string   `json:"probe_name,omitempty"`
	ProbeID     string   `json:"probe_id,omitempty"`
	Source      string   `json:"source,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// ObservationConflict retains mutually inconsistent source facts.  Values
// are deliberately not reduced to a winner; consumers can use the
// provenance and evidence IDs to explain the disagreement.
type ObservationConflict struct {
	Field       string   `json:"field"`
	Values      []string `json:"values"`
	Provenance  []string `json:"provenance,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// ObservationDivergence records facts that are different because they were
// measured by distinct observation lanes.  A divergence is not a malformed
// observation and has no implicit winner: path responders describe the
// responder visibility of a bounded path probe, while packet-flow evidence
// describes packets observed at the local capture point.
type ObservationDivergence struct {
	Field                 string   `json:"field"`
	PathValues            []string `json:"path_values,omitempty"`
	PacketFlowValues      []string `json:"packet_flow_values,omitempty"`
	PathProvenance        []string `json:"path_provenance,omitempty"`
	PacketFlowProvenance  []string `json:"packet_flow_provenance,omitempty"`
	PathEvidenceIDs       []string `json:"path_evidence_ids,omitempty"`
	PacketFlowEvidenceIDs []string `json:"packet_flow_evidence_ids,omitempty"`
}

// EndpointObservation is the report-level normalized endpoint view.  The
// selected endpoint is Tadori's probe candidate; TestedEndpoint is concrete
// transport evidence.  They are intentionally separate from the requested
// identity and from the resolver's representative answer.
type EndpointObservation struct {
	OriginalInput       string                `json:"original_input"`
	RequestedIdentity   string                `json:"requested_identity"`
	LiteralIP           string                `json:"literal_ip,omitempty"`
	Service             ServiceProfile        `json:"service"`
	ApplicationProtocol ApplicationProtocol   `json:"application_protocol"`
	TransportProtocol   TransportProtocol     `json:"transport_protocol"`
	Port                uint16                `json:"port"`
	Resource            string                `json:"resource,omitempty"`
	ResolvedCandidates  []EndpointCandidate   `json:"resolved_candidates,omitempty"`
	ProbeCandidates     []EndpointCandidate   `json:"probe_candidates,omitempty"`
	SelectedEndpoint    *Endpoint             `json:"selected_endpoint,omitempty"`
	TestedEndpoint      *Endpoint             `json:"tested_endpoint,omitempty"`
	CandidateAttempts   []EndpointAttempt     `json:"candidate_attempts,omitempty"`
	Certainty           ObservationCertainty  `json:"certainty"`
	Provenance          []string              `json:"provenance,omitempty"`
	ProbeNames          []string              `json:"probe_names,omitempty"`
	EvidenceIDs         []string              `json:"evidence_ids,omitempty"`
	Limitations         []string              `json:"limitations,omitempty"`
	Conflicts           []ObservationConflict `json:"conflicts,omitempty"`
}

// Observations is the one report-level normalized world model.  Probes keep
// their raw evidence and local interpretations; new cross-probe consumers
// should read this envelope rather than reconstructing facts from Target or
// ProbeResult fields.
type Observations struct {
	Endpoint             EndpointObservation         `json:"endpoint"`
	NameResolution       NameResolutionObservation   `json:"name_resolution"`
	NetworkContext       NetworkContext              `json:"network_context"`
	EnterprisePolicy     EnterprisePolicyObservation `json:"enterprise_policy"`
	Transport            TransportObservation        `json:"transport"`
	Security             SecurityObservation         `json:"security"`
	Application          ApplicationObservation      `json:"application"`
	BrowserCapture       *BrowserCaptureObservation  `json:"browser_capture,omitempty"`
	Paths                []PathObservation           `json:"paths,omitempty"`
	PacketFlows          []PacketFlowEvidence        `json:"packet_flows,omitempty"`
	PathProvenance       []ObservationProvenance     `json:"path_provenance,omitempty"`
	PacketFlowProvenance []ObservationProvenance     `json:"packet_flow_provenance,omitempty"`
	PathCorrelations     []PathCorrelation           `json:"path_correlations,omitempty"`
	Conflicts            []ObservationConflict       `json:"conflicts,omitempty"`
	Divergences          []ObservationDivergence     `json:"divergences,omitempty"`
}

// NormalizeObservations returns a detached, stable copy of an observation
// envelope.  It does not select between contradictory facts.
func NormalizeObservations(observations Observations) Observations {
	endpoint := observations.Endpoint
	endpoint.Service = cloneServiceProfile(endpoint.Service)
	endpoint.ResolvedCandidates = cloneEndpointCandidates(endpoint.ResolvedCandidates)
	endpoint.ProbeCandidates = cloneEndpointCandidates(endpoint.ProbeCandidates)
	endpoint.CandidateAttempts = cloneEndpointAttempts(endpoint.CandidateAttempts)
	endpoint.Provenance = append([]string(nil), endpoint.Provenance...)
	endpoint.ProbeNames = append([]string(nil), endpoint.ProbeNames...)
	endpoint.EvidenceIDs = append([]string(nil), endpoint.EvidenceIDs...)
	endpoint.Limitations = append([]string(nil), endpoint.Limitations...)
	endpoint.Conflicts = cloneObservationConflicts(endpoint.Conflicts)
	if endpoint.SelectedEndpoint != nil {
		value := cloneEndpoint(*endpoint.SelectedEndpoint)
		endpoint.SelectedEndpoint = &value
	}
	if endpoint.TestedEndpoint != nil {
		value := cloneEndpoint(*endpoint.TestedEndpoint)
		endpoint.TestedEndpoint = &value
	}

	name := NormalizeNameResolutionObservation(observations.NameResolution)
	name.Provenance = append([]string(nil), name.Provenance...)
	name.ProbeNames = append([]string(nil), name.ProbeNames...)
	name.Conflicts = cloneObservationConflicts(name.Conflicts)

	network := cloneNetworkContext(observations.NetworkContext)
	enterprise := NormalizeEnterprisePolicyObservation(observations.EnterprisePolicy)
	paths := clonePathObservations(observations.Paths)
	packetFlows := clonePacketFlows(observations.PacketFlows)
	pathProvenance := cloneObservationProvenance(observations.PathProvenance)
	packetFlowProvenance := cloneObservationProvenance(observations.PacketFlowProvenance)
	pathCorrelations := clonePathCorrelations(observations.PathCorrelations)
	conflicts := cloneObservationConflicts(observations.Conflicts)
	divergences := cloneObservationDivergences(observations.Divergences)
	var browserCapture *BrowserCaptureObservation
	if observations.BrowserCapture != nil {
		value := *observations.BrowserCapture
		value.Destinations = cloneBrowserCaptureDestinations(value.Destinations)
		value.Limitations = append([]string(nil), value.Limitations...)
		browserCapture = &value
	}
	return Observations{
		Endpoint:             endpoint,
		NameResolution:       name,
		NetworkContext:       network,
		EnterprisePolicy:     enterprise,
		Transport:            NormalizeTransportObservation(observations.Transport),
		Security:             NormalizeSecurityObservation(observations.Security),
		Application:          NormalizeApplicationObservation(observations.Application),
		BrowserCapture:       browserCapture,
		Paths:                paths,
		PacketFlows:          packetFlows,
		PathProvenance:       pathProvenance,
		PacketFlowProvenance: packetFlowProvenance,
		PathCorrelations:     pathCorrelations,
		Conflicts:            conflicts,
		Divergences:          divergences,
	}
}

func cloneBrowserCaptureDestinations(values []BrowserCaptureDestination) []BrowserCaptureDestination {
	if values == nil {
		return nil
	}
	result := make([]BrowserCaptureDestination, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Mechanisms = append([]BrowserCaptureMechanism(nil), value.Mechanisms...)
		result[index].ResolvedAddressCandidates = append([]string(nil), value.ResolvedAddressCandidates...)
		result[index].ConnectedEndpoints = append([]string(nil), value.ConnectedEndpoints...)
		result[index].FailureReasons = append([]string(nil), value.FailureReasons...)
	}
	return result
}

func cloneObservationProvenance(values []ObservationProvenance) []ObservationProvenance {
	if values == nil {
		return nil
	}
	result := make([]ObservationProvenance, len(values))
	for index, value := range values {
		result[index] = value
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	}
	return result
}

func clonePathObservations(values []PathObservation) []PathObservation {
	if values == nil {
		return nil
	}
	result := make([]PathObservation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Hops = append([]PathHop(nil), value.Hops...)
		for hopIndex := range result[index].Hops {
			result[index].Hops[hopIndex].Responders = append([]PathResponder(nil), value.Hops[hopIndex].Responders...)
		}
		result[index].Segments = append([]PathSegment(nil), value.Segments...)
		for segmentIndex := range result[index].Segments {
			result[index].Segments[segmentIndex].Responders = append([]PathResponder(nil), value.Segments[segmentIndex].Responders...)
		}
	}
	return result
}

func clonePacketFlows(values []PacketFlowEvidence) []PacketFlowEvidence {
	if values == nil {
		return nil
	}
	result := make([]PacketFlowEvidence, len(values))
	for index, value := range values {
		result[index] = value
		result[index].MatchedObservationIDs = append([]string(nil), value.MatchedObservationIDs...)
		result[index].Observations = append([]PacketObservation(nil), value.Observations...)
	}
	return result
}

func clonePathCorrelations(values []PathCorrelation) []PathCorrelation {
	if values == nil {
		return nil
	}
	result := make([]PathCorrelation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Observations = clonePathObservations(value.Observations)
	}
	return result
}

func cloneObservationDivergences(values []ObservationDivergence) []ObservationDivergence {
	if values == nil {
		return nil
	}
	result := make([]ObservationDivergence, len(values))
	for index, value := range values {
		result[index] = value
		result[index].PathValues = append([]string(nil), value.PathValues...)
		result[index].PacketFlowValues = append([]string(nil), value.PacketFlowValues...)
		result[index].PathProvenance = append([]string(nil), value.PathProvenance...)
		result[index].PacketFlowProvenance = append([]string(nil), value.PacketFlowProvenance...)
		result[index].PathEvidenceIDs = append([]string(nil), value.PathEvidenceIDs...)
		result[index].PacketFlowEvidenceIDs = append([]string(nil), value.PacketFlowEvidenceIDs...)
	}
	return result
}

func cloneEndpoint(value Endpoint) Endpoint {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	return value
}

func cloneEndpointCandidates(values []EndpointCandidate) []EndpointCandidate {
	if values == nil {
		return nil
	}
	result := make([]EndpointCandidate, len(values))
	for index, value := range values {
		result[index] = value
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	}
	return result
}

func cloneEndpointAttempts(values []EndpointAttempt) []EndpointAttempt {
	if values == nil {
		return nil
	}
	result := make([]EndpointAttempt, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Candidate.EvidenceIDs = append([]string(nil), value.Candidate.EvidenceIDs...)
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	}
	return result
}

func cloneObservationConflicts(values []ObservationConflict) []ObservationConflict {
	if values == nil {
		return nil
	}
	result := make([]ObservationConflict, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Values = append([]string(nil), value.Values...)
		result[index].Provenance = append([]string(nil), value.Provenance...)
		result[index].EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	}
	return result
}

func cloneNetworkContext(value NetworkContext) NetworkContext {
	value.CompetingRoutes = append([]RouteCandidate(nil), value.CompetingRoutes...)
	value.Provenance = append([]string(nil), value.Provenance...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.ProbeNames = append([]string(nil), value.ProbeNames...)
	value.Limitations = append([]string(nil), value.Limitations...)
	value.Conflicts = cloneObservationConflicts(value.Conflicts)
	if value.Neighbor != nil {
		neighbor := *value.Neighbor
		neighbor.Entries = append([]NeighborEntry(nil), value.Neighbor.Entries...)
		value.Neighbor = &neighbor
	}
	return value
}
