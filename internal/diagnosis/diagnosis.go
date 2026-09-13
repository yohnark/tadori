package diagnosis

import (
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/yohnark/tadori/internal/model"
)

// Diagnose returns the deterministic interpretation of collected probe
// results. The returned slice is newly allocated and the input is never
// modified. At most one primary finding is returned, followed by an optional
// gateway finding when gateway failure is useful supporting evidence.
//
// A result's normalized FailureReason is authoritative. Status and Layer are
// used to recognize successful observations and to resolve contradictory
// observations. Path evidence is the one intentionally structured exception:
// its protocol/port fields are decoded so a TCP destination response can be
// correlated with the requested endpoint without promoting ICMP evidence.
func Diagnose(probes []model.ProbeResult) []model.DiagnosticFinding {
	observations := normalize(probes)
	if len(observations) == 0 {
		return nil
	}

	// Rules are ordered from the earliest decisive boundary to the latest.
	// Keeping this as a slice (rather than ranging over a map) makes both
	// precedence and output stable. We collect the first built-in match before
	// comparing it with extension reasons below, so an opaque lower-layer
	// reason cannot be hidden by a known higher-layer reason.
	var builtIn *builtInCandidate
	for _, rule := range rules {
		matches := matching(observations, rule.reason)
		if len(matches) == 0 {
			continue
		}
		viable := make([]observation, 0, len(matches))
		for _, match := range matches {
			if !contradicted(match, observations) {
				viable = append(viable, match)
			}
		}
		if len(viable) == 0 {
			continue
		}
		candidate := builtInCandidate{reason: rule.reason, matches: viable}
		builtIn = &candidate
		break
	}

	// Probe-specific reasons may be added to model.FailureReason without
	// changing this package. They are not interpreted by their text: the
	// canonical layer and fault domain supplied by the probe are retained.
	extension := genericFailure(observations)
	if extension != nil && (builtIn == nil || layerRank(extension.result.Interpretation.Layer) < builtInLayerRank(*builtIn)) {
		return withGatewaySupport(makeExtensionFinding(*extension, observations), observations)
	}
	if builtIn != nil {
		return withGatewaySupport(makeFinding(builtIn.reason, builtIn.matches), observations)
	}

	// A gateway result is supporting evidence and can still be useful when no
	// decisive layer produced a finding.
	if gateway := matchingApplicableGateways(observations); len(gateway) != 0 && !contradicted(gateway[0], observations) {
		return []model.DiagnosticFinding{makeFinding(model.FailureReasonGatewayUnreachable, gateway)}
	}

	return nil
}

func withGatewaySupport(finding model.DiagnosticFinding, observations []observation) []model.DiagnosticFinding {
	// Gateway reachability is supporting evidence rather than a claim that
	// the gateway is necessarily the root cause. Preserve it as a second
	// machine-readable finding when a decisive failure exists.
	gateway := matchingApplicableGateways(observations)
	if len(gateway) != 0 && !contradicted(gateway[0], observations) {
		return []model.DiagnosticFinding{finding, makeFinding(model.FailureReasonGatewayUnreachable, gateway)}
	}
	return []model.DiagnosticFinding{finding}
}

// Findings is an explicit alias for callers that prefer the output-oriented
// name. It has the same pure and deterministic behavior as Diagnose.
func Findings(probes []model.ProbeResult) []model.DiagnosticFinding {
	return Diagnose(probes)
}

// Analyze is an alias for Diagnose retained as a discoverable interpretation
// entry point.
func Analyze(probes []model.ProbeResult) []model.DiagnosticFinding {
	return Diagnose(probes)
}

// DiagnoseReport returns a copy of report with Findings replaced by the
// interpretation of report.Probes. It does not change report status or raw
// probe evidence.
func DiagnoseReport(report model.DiagnosticReport) model.DiagnosticReport {
	report.Findings = Diagnose(report.Probes)
	return report
}

// Apply is a concise alias for DiagnoseReport.
func Apply(report model.DiagnosticReport) model.DiagnosticReport {
	return DiagnoseReport(report)
}

type rule struct {
	reason model.FailureReason
}

type builtInCandidate struct {
	reason  model.FailureReason
	matches []observation
}

func builtInLayerRank(candidate builtInCandidate) int {
	layer, _ := semantics(candidate.reason)
	return layerRank(layer)
}

// This table is the diagnosis policy. Reasons in the same layer are ordered
// from more specific to less specific where the contract supplies that
// distinction (for example NXDOMAIN before resolver timeout).
var rules = []rule{
	{reason: model.FailureReasonInterfaceDown},
	{reason: model.FailureReasonNoIPAddress},
	{reason: model.FailureReasonNoRoute},
	{reason: model.FailureReasonInvalidRoute},
	{reason: model.FailureReasonEffectiveRouteDifference},
	{reason: model.FailureReasonDNSNXDomain},
	{reason: model.FailureReasonDNSNoAnswer},
	{reason: model.FailureReasonDNSTimeout},
	{reason: model.FailureReasonDNSResolverFailure},
	{reason: model.FailureReasonProxyAuthenticationRequired},
	{reason: model.FailureReasonProxyConnectDenied},
	{reason: model.FailureReasonDirectEgressRestricted},
	{reason: model.FailureReasonProxyConfigurationDivergence},
	{reason: model.FailureReasonProxyConfigurationFailure},
	{reason: model.FailureReasonProxyUnavailable},
	{reason: model.FailureReasonNetworkUnreachable},
	{reason: model.FailureReasonFirewallBlocked},
	{reason: model.FailureReasonTCPTimeout},
	{reason: model.FailureReasonTCPConnectionRefused},
	{reason: model.FailureReasonTCPConnectionReset},
	{reason: model.FailureReasonTCPSYNNotObserved},
	{reason: model.FailureReasonTLSInterceptionSuspected},
	{reason: model.FailureReasonTLSTrustStoreMismatch},
	{reason: model.FailureReasonTLSHandshakeFailure},
	{reason: model.FailureReasonCertificateValidationFailure},
	{reason: model.FailureReasonHTTPStatusCode},
	{reason: model.FailureReasonHTTPFailure},
	{reason: model.FailureReasonProbeExecution},
}

type observation struct {
	result model.ProbeResult
	reason model.FailureReason
}

func normalize(probes []model.ProbeResult) []observation {
	observations := make([]observation, 0, len(probes))
	for _, result := range probes {
		reason := result.Interpretation.FailureReason
		if reason == "" {
			// FailureReasonNone is the canonical success value, but accepting
			// the zero value for a passed fixture keeps interpretation tolerant
			// of callers that only populate the required status and layer.
			if result.Status == model.ProbeStatusPassed {
				reason = model.FailureReasonNone
			} else {
				reason = model.FailureReasonUnknown
			}
		}
		result, reason = applyPacketFlowEvidence(result, reason)
		observations = append(observations, observation{result: result, reason: reason})
		observations = append(observations, pathDestinationSuccesses(result)...)
	}
	return observations
}

// applyPacketFlowEvidence supplements, but does not replace, a probe's
// interpretation. Only a complete, identity-compatible flow can strengthen
// a TCP result. A missing response remains a bounded observation and is not
// converted into a network-drop claim.
func applyPacketFlowEvidence(result model.ProbeResult, reason model.FailureReason) (model.ProbeResult, model.FailureReason) {
	for _, evidence := range result.Evidence {
		flow, err := model.DecodePacketFlowEvidence(evidence)
		if err != nil || !packetFlowBelongsToResult(flow, result) || flow.CaptureStatus != model.PacketCaptureStatusAvailable {
			continue
		}
		switch flow.Outcome {
		case model.PacketFlowOutcomeTCPHandshakeConfirmed, model.PacketFlowOutcomeTCPSYNACK:
			if flow.Certainty == model.EvidenceCertaintyConfirmedEndpointResponse && (result.Status == model.ProbeStatusFailed || result.Status == model.ProbeStatusError) {
				return packetFlowSuccessResult(result, evidence), model.FailureReasonNone
			}
		case model.PacketFlowOutcomeTCPRST:
			if flow.Certainty == model.EvidenceCertaintyConfirmedEndpointResponse && (result.Status == model.ProbeStatusFailed || result.Status == model.ProbeStatusError) {
				switch reason {
				case model.FailureReasonTCPTimeout, model.FailureReasonProbeExecution, model.FailureReasonUnknown, model.FailureReasonNone:
					result.Interpretation.FailureReason = model.FailureReasonTCPConnectionReset
					return result, model.FailureReasonTCPConnectionReset
				}
			}
		case model.PacketFlowOutcomeProbeNotEmitted:
			if result.Status == model.ProbeStatusFailed || result.Status == model.ProbeStatusError {
				switch reason {
				case model.FailureReasonTCPTimeout, model.FailureReasonProbeExecution, model.FailureReasonUnknown, model.FailureReasonNone:
					result.Interpretation.FailureReason = model.FailureReasonTCPSYNNotObserved
					result.Interpretation.Layer = model.LayerTCP
					result.Interpretation.FaultDomain = model.FaultDomainLocal
					return result, model.FailureReasonTCPSYNNotObserved
				}
			}
		}
	}
	return result, reason
}

func packetFlowBelongsToResult(flow model.PacketFlowEvidence, result model.ProbeResult) bool {
	if flow.ProbeID != "" && result.ProbeID != "" && flow.ProbeID != result.ProbeID {
		return false
	}
	if flow.SessionID != "" && result.SessionID != "" && flow.SessionID != result.SessionID {
		return false
	}
	if flow.CorrelationID != "" && result.CorrelationID != "" && flow.CorrelationID != result.CorrelationID {
		return false
	}
	if result.Target.RequestedIdentity != "" && flow.Target.RequestedIdentity != "" && !targetsCorrelate(result.Target, flow.Target, model.LayerTCP) {
		return false
	}
	return true
}

func packetFlowSuccessResult(result model.ProbeResult, evidence model.Evidence) model.ProbeResult {
	synthetic := result
	synthetic.Name = result.Name + "/packet-flow"
	synthetic.Status = model.ProbeStatusPassed
	synthetic.Evidence = []model.Evidence{evidence}
	synthetic.Interpretation = model.ProbeInterpretation{
		FailureReason: model.FailureReasonNone,
		Layer:         model.LayerTCP,
		FaultDomain:   model.FaultDomainTransport,
	}
	return synthetic
}

func pathDestinationSuccesses(result model.ProbeResult) []observation {
	if result.Name == "" {
		return nil
	}
	derived := make([]observation, 0)
	for _, evidence := range result.Evidence {
		pathObservation, err := model.DecodePathObservation(evidence)
		if err != nil || pathObservation.Status != model.PathObservationStatusObserved || pathObservation.Protocol != model.PathProtocolTCP || !pathObservation.PortAware || !pathObservation.DestinationReached || !pathObservation.DestinationTCPConnected {
			continue
		}
		if result.Target.Port == 0 || !pathObservation.MatchesTarget(result.Target) {
			continue
		}
		// A TCP path response at the requested destination port is a
		// successful transport observation even when every earlier TTL is
		// unobservable. Keep the original path evidence as the reference.
		synthetic := result
		synthetic.Name = result.Name + "/tcp-destination"
		synthetic.Status = model.ProbeStatusPassed
		synthetic.Evidence = []model.Evidence{evidence}
		synthetic.Interpretation = model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         model.LayerTCP,
			FaultDomain:   model.FaultDomainTransport,
		}
		derived = append(derived, observation{result: synthetic, reason: model.FailureReasonNone})
	}
	return derived
}

func matching(observations []observation, reason model.FailureReason) []observation {
	matches := make([]observation, 0)
	for _, observation := range observations {
		if observation.reason == reason {
			matches = append(matches, observation)
		}
	}
	return matches
}

func matchingApplicableGateways(observations []observation) []observation {
	matches := matching(observations, model.FailureReasonGatewayUnreachable)
	applicable := make([]observation, 0, len(matches))
	for _, match := range matches {
		if gatewayCheckApplies(match.result) {
			applicable = append(applicable, match)
		}
	}
	return applicable
}

// gatewayCheckApplies prevents a stale or hand-built gateway failure from
// becoming a diagnosis when the selected route explicitly has no gateway.
// Evidence that predates the structured route shape remains applicable so
// older callers do not silently lose a real supporting observation.
func gatewayCheckApplies(result model.ProbeResult) bool {
	for _, evidence := range result.Evidence {
		if evidence.Kind != model.EvidenceKindRoute && evidence.Kind != model.EvidenceKindGatewayReachability {
			continue
		}
		var routeValue struct {
			Destination    string                 `json:"destination"`
			RoutePrefix    string                 `json:"route_prefix"`
			Gateway        string                 `json:"gateway"`
			EffectiveRoute model.RouteDisposition `json:"effective_route"`
			GatewayTested  *bool                  `json:"gateway_tested"`
		}
		if err := json.Unmarshal(evidence.Raw, &routeValue); err != nil {
			continue
		}
		if routeValue.GatewayTested != nil && !*routeValue.GatewayTested {
			return false
		}
		if routeValue.EffectiveRoute == model.RouteDispositionOnLink && (routeValue.Destination != "" || routeValue.RoutePrefix != "") {
			return false
		}
		if !gatewayPresent(routeValue.Gateway) && (routeValue.Destination != "" || routeValue.RoutePrefix != "") {
			return false
		}
	}
	return true
}

func gatewayPresent(value string) bool {
	if value == "" {
		return false
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		// Preserve the conservative behavior for legacy opaque values: a
		// non-empty, unparseable gateway is still evidence that a check may
		// have been applicable.
		return true
	}
	return !address.IsUnspecified()
}

func makeFinding(reason model.FailureReason, matches []observation) model.DiagnosticFinding {
	layer, domain := semantics(reason)
	probeNames := make([]string, 0, len(matches))
	evidenceIDs := make([]string, 0)
	for _, match := range matches {
		if match.result.Name != "" {
			probeNames = append(probeNames, match.result.Name)
		}
		for _, evidence := range match.result.Evidence {
			if evidence.ID != "" {
				evidenceIDs = append(evidenceIDs, evidence.ID)
			}
		}
	}
	sort.Strings(probeNames)
	sort.Strings(evidenceIDs)
	return model.DiagnosticFinding{
		FailureReason: reason,
		Layer:         layer,
		FaultDomain:   domain,
		ProbeNames:    unique(probeNames),
		EvidenceIDs:   unique(evidenceIDs),
	}
}

func makeExtensionFinding(candidate observation, observations []observation) model.DiagnosticFinding {
	layer := candidate.result.Interpretation.Layer
	if layer == "" {
		layer = model.LayerUnknown
	}
	domain := candidate.result.Interpretation.FaultDomain
	if domain == "" {
		domain = model.FaultDomainUnknown
	}
	matches := make([]observation, 0, 1)
	for _, other := range observations {
		if !isGenericFailure(other) {
			continue
		}
		if other.result.Interpretation.Layer == model.LayerICMP || other.result.Interpretation.FaultDomain == model.FaultDomainICMP || other.reason == model.FailureReasonICMPFailure {
			continue
		}
		if other.reason == candidate.reason && other.result.Interpretation.Layer == candidate.result.Interpretation.Layer && other.result.Interpretation.FaultDomain == candidate.result.Interpretation.FaultDomain && targetsCorrelate(candidate.result.Target, other.result.Target, candidate.result.Interpretation.Layer) {
			matches = append(matches, other)
		}
	}
	finding := makeFinding(candidate.reason, matches)
	finding.Layer = layer
	finding.FaultDomain = domain
	return finding
}

// genericFailure selects an extension reason without assigning semantics to
// its value. Layer order is fixed so a collector's input ordering cannot
// change the primary finding. Reason/name are only stable tie-breakers when
// two opaque extensions occupy the same layer.
func genericFailure(observations []observation) *observation {
	candidates := make([]observation, 0)
	for _, observation := range observations {
		if !isGenericFailure(observation) {
			continue
		}
		if observation.result.Interpretation.Layer == model.LayerICMP || observation.result.Interpretation.FaultDomain == model.FaultDomainICMP || observation.reason == model.FailureReasonICMPFailure {
			continue
		}
		candidates = append(candidates, observation)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if layerRank(left.result.Interpretation.Layer) != layerRank(right.result.Interpretation.Layer) {
			return layerRank(left.result.Interpretation.Layer) < layerRank(right.result.Interpretation.Layer)
		}
		if left.reason != right.reason {
			return left.reason < right.reason
		}
		if left.result.Interpretation.Layer != right.result.Interpretation.Layer {
			return left.result.Interpretation.Layer < right.result.Interpretation.Layer
		}
		if left.result.Interpretation.FaultDomain != right.result.Interpretation.FaultDomain {
			return left.result.Interpretation.FaultDomain < right.result.Interpretation.FaultDomain
		}
		return left.result.Name < right.result.Name
	})
	for _, candidate := range candidates {
		if !contradictedExtension(candidate, observations) {
			selected := candidate
			return &selected
		}
	}
	return nil
}

func isGenericFailure(observation observation) bool {
	if observation.result.Status != model.ProbeStatusFailed && observation.result.Status != model.ProbeStatusError {
		return false
	}
	switch observation.reason {
	case "", model.FailureReasonNone, model.FailureReasonUnknown,
		model.FailureReasonICMPFailure, model.FailureReasonUnsupported,
		model.FailureReasonPathObservation, model.FailureReasonPathCancellation:
		return false
	}
	for _, rule := range rules {
		if observation.reason == rule.reason {
			return false
		}
	}
	// Gateway is intentionally not in rules because it is supporting-only,
	// but it is not an extension reason and must not be duplicated here.
	return observation.reason != model.FailureReasonGatewayUnreachable
}

func layerRank(layer model.Layer) int {
	switch layer {
	case model.LayerInterface, model.LayerIPConfiguration:
		return 10
	case model.LayerRoute:
		return 20
	case model.LayerGateway:
		return 30
	case model.LayerDNS:
		return 40
	case model.LayerProxy:
		return 50
	case model.LayerNetwork:
		return 60
	case model.LayerTCP:
		return 70
	case model.LayerTLS:
		return 80
	case model.LayerHTTP:
		return 90
	case model.LayerSMB:
		return 90
	case model.LayerDestination:
		return 100
	case model.LayerUnknown, "":
		return 1000
	case model.LayerICMP:
		return 2000
	default:
		return 1100
	}
}

func contradictedExtension(candidate observation, observations []observation) bool {
	for _, observation := range observations {
		if observation.result.Status != model.ProbeStatusPassed || observation.reason != model.FailureReasonNone {
			continue
		}
		if !targetsCorrelate(candidate.result.Target, observation.result.Target, candidate.result.Interpretation.Layer) {
			continue
		}
		if successfulLayerContradicts(candidate.result.Interpretation.Layer, observation.result.Interpretation.Layer) {
			return true
		}
	}
	return false
}

func successfulLayerContradicts(failedLayer, successfulLayer model.Layer) bool {
	switch failedLayer {
	case model.LayerInterface, model.LayerIPConfiguration, model.LayerRoute,
		model.LayerGateway, model.LayerNetwork:
		return successfulLayer == model.LayerTCP || successfulLayer == model.LayerTLS || successfulLayer == model.LayerHTTP || successfulLayer == model.LayerSMB
	case model.LayerDNS, model.LayerProxy:
		return successfulLayer == failedLayer
	case model.LayerTCP:
		return successfulLayer == model.LayerTCP || successfulLayer == model.LayerTLS || successfulLayer == model.LayerHTTP || successfulLayer == model.LayerSMB
	case model.LayerTLS:
		return successfulLayer == model.LayerTLS || successfulLayer == model.LayerHTTP
	case model.LayerHTTP:
		return successfulLayer == model.LayerHTTP
	case model.LayerSMB:
		return successfulLayer == model.LayerSMB
	default:
		return false
	}
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

// semantics intentionally derives output boundaries from machine-readable
// FailureReason constants. It never examines probe names, raw errors, or
// presentation text.
func semantics(reason model.FailureReason) (model.Layer, model.FaultDomain) {
	switch reason {
	case model.FailureReasonInterfaceDown:
		return model.LayerInterface, model.FaultDomainLocal
	case model.FailureReasonNoIPAddress:
		return model.LayerIPConfiguration, model.FaultDomainLocal
	case model.FailureReasonNoRoute, model.FailureReasonInvalidRoute, model.FailureReasonEffectiveRouteDifference:
		return model.LayerRoute, model.FaultDomainRouting
	case model.FailureReasonGatewayUnreachable:
		return model.LayerGateway, model.FaultDomainGateway
	case model.FailureReasonDNSNXDomain, model.FailureReasonDNSNoAnswer,
		model.FailureReasonDNSTimeout, model.FailureReasonDNSResolverFailure:
		return model.LayerDNS, model.FaultDomainDNS
	case model.FailureReasonProxyConfigurationFailure,
		model.FailureReasonProxyConfigurationDivergence,
		model.FailureReasonProxyUnavailable,
		model.FailureReasonProxyConnectDenied,
		model.FailureReasonProxyAuthenticationRequired:
		return model.LayerProxy, model.FaultDomainProxy
	case model.FailureReasonDirectEgressRestricted:
		return model.LayerNetwork, model.FaultDomainPolicy
	case model.FailureReasonNetworkUnreachable:
		return model.LayerNetwork, model.FaultDomainNetwork
	case model.FailureReasonFirewallBlocked:
		return model.LayerNetwork, model.FaultDomainFirewall
	case model.FailureReasonTCPSYNNotObserved:
		return model.LayerTCP, model.FaultDomainLocal
	case model.FailureReasonTCPTimeout,
		model.FailureReasonTCPConnectionRefused,
		model.FailureReasonTCPConnectionReset:
		return model.LayerTCP, model.FaultDomainTransport
	case model.FailureReasonTLSHandshakeFailure,
		model.FailureReasonCertificateValidationFailure,
		model.FailureReasonTLSTrustStoreMismatch,
		model.FailureReasonTLSInterceptionSuspected:
		return model.LayerTLS, model.FaultDomainTLS
	case model.FailureReasonHTTPStatusCode, model.FailureReasonHTTPFailure:
		return model.LayerHTTP, model.FaultDomainHTTP
	case model.FailureReasonSMBTimeout,
		model.FailureReasonSMBProtocolRejection,
		model.FailureReasonSMBMalformedResponse:
		return model.LayerSMB, model.FaultDomainSMB
	case model.FailureReasonSMBConnectionRefused:
		return model.LayerTCP, model.FaultDomainTransport
	case model.FailureReasonProbeExecution:
		return model.LayerUnknown, model.FaultDomainUnknown
	default:
		return model.LayerUnknown, model.FaultDomainUnknown
	}
}

func contradicted(candidate observation, observations []observation) bool {
	reason := candidate.reason
	// A normalized success at the same or a later boundary is stronger than a
	// contradictory failed observation. DNS is intentionally treated as its
	// own branch: a successful TCP connection does not prove hostname lookup
	// succeeded, and vice versa.
	for _, observation := range observations {
		if observation.result.Status != model.ProbeStatusPassed || observation.reason != model.FailureReasonNone {
			continue
		}
		if !targetsCorrelate(candidate.result.Target, observation.result.Target, candidate.result.Interpretation.Layer) {
			continue
		}
		layer := observation.result.Interpretation.Layer
		switch reason {
		case model.FailureReasonInterfaceDown, model.FailureReasonNoIPAddress,
			model.FailureReasonNoRoute, model.FailureReasonInvalidRoute,
			model.FailureReasonGatewayUnreachable,
			model.FailureReasonNetworkUnreachable,
			model.FailureReasonFirewallBlocked:
			if layer == model.LayerTCP || layer == model.LayerTLS || layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonDNSNXDomain, model.FailureReasonDNSNoAnswer,
			model.FailureReasonDNSTimeout, model.FailureReasonDNSResolverFailure:
			if layer == model.LayerDNS {
				return true
			}
		case model.FailureReasonProxyUnavailable:
			// Configuration success is not proof that a particular URL's
			// endpoint, CONNECT policy, or authentication path succeeds. Keep
			// the legacy contradiction only for a generic endpoint-unavailable
			// result, and retain the more specific enterprise findings.
			if layer == model.LayerProxy {
				return true
			}
		case model.FailureReasonTCPTimeout, model.FailureReasonTCPConnectionRefused,
			model.FailureReasonTCPConnectionReset, model.FailureReasonTCPSYNNotObserved:
			if layer == model.LayerTCP || layer == model.LayerTLS || layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonTLSHandshakeFailure,
			model.FailureReasonCertificateValidationFailure:
			if layer == model.LayerTLS || layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonHTTPStatusCode, model.FailureReasonHTTPFailure:
			if layer == model.LayerHTTP {
				return true
			}
		case model.FailureReasonProbeExecution:
			// Generic execution errors are only useful when no normalized
			// success exists at all; do not let one stale error override proof
			// that the path works.
			if layer != model.LayerUnknown {
				return true
			}
		}
	}
	return false
}

func targetsCorrelate(left, right model.Target, layer model.Layer) bool {
	if left.RequestedIdentity != "" && right.RequestedIdentity != "" &&
		!left.MatchesAddress(right.RequestedIdentity) && !right.MatchesAddress(left.RequestedIdentity) {
		return false
	}
	if transportEndpointLayer(layer) && left.Port != 0 && right.Port != 0 && left.Port != right.Port {
		return false
	}
	return true
}

func transportEndpointLayer(layer model.Layer) bool {
	switch layer {
	case model.LayerTCP, model.LayerTLS, model.LayerHTTP, model.LayerDestination:
		return true
	default:
		return false
	}
}
