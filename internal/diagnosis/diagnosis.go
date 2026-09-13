package diagnosis

import (
	"sort"
	"strings"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/observations"
)

// DiagnoseObservations interprets the report-level observation envelope. The
// envelope is the authority for cross-probe meaning; raw probe evidence is
// deliberately not inspected here.
func DiagnoseObservations(value model.Observations) []model.DiagnosticFinding {
	return diagnoseObservationState(model.NormalizeObservations(value), nil, false)
}

// Diagnose is a compatibility entry point for callers that still have only
// probe results. Results are first projected into the canonical observation
// envelope. Probe interpretations are retained only for facts for which the
// current envelope has no normalized field, and for opaque extension reasons.
func Diagnose(probes []model.ProbeResult) []model.DiagnosticFinding {
	return diagnoseFromProbes(probes)
}

// Findings is an output-oriented compatibility alias for Diagnose.
func Findings(probes []model.ProbeResult) []model.DiagnosticFinding { return Diagnose(probes) }

// Analyze is an interpretation-oriented compatibility alias for Diagnose.
func Analyze(probes []model.ProbeResult) []model.DiagnosticFinding { return Diagnose(probes) }

// FindingsFromObservations is the output-oriented observation API.
func FindingsFromObservations(value model.Observations) []model.DiagnosticFinding {
	return DiagnoseObservations(value)
}

// AnalyzeObservations is the interpretation-oriented observation API.
func AnalyzeObservations(value model.Observations) []model.DiagnosticFinding {
	return DiagnoseObservations(value)
}

// DiagnoseReport applies diagnosis to the report's canonical observation
// envelope without changing status, target, probes, or raw evidence. A
// report produced before the observation envelope was populated is accepted
// through the compatibility projection for the transition period.
func DiagnoseReport(report model.DiagnosticReport) model.DiagnosticReport {
	value := model.NormalizeObservations(report.Observations)
	if !hasCanonicalObservations(value) && len(report.Probes) != 0 {
		target := report.Target
		if target.RequestedIdentity == "" {
			target = targetFromProbes(report.Probes)
		}
		value = observations.Build(compatibilityTargetSnapshot(target), compatibilityProbeSnapshot(report.Probes))
	}
	report.Findings = diagnoseObservationState(value, report.Probes, len(report.Probes) != 0)
	return report
}

// Apply is a concise alias for DiagnoseReport.
func Apply(report model.DiagnosticReport) model.DiagnosticReport { return DiagnoseReport(report) }

func diagnoseFromProbes(probes []model.ProbeResult) []model.DiagnosticFinding {
	target := targetFromProbes(probes)
	value := observations.Build(compatibilityTargetSnapshot(target), compatibilityProbeSnapshot(probes))
	return diagnoseObservationState(value, probes, true)
}

// Target.TestedEndpoint is deprecated execution state. A probe-only caller
// can carry a stale value from a different observation lane, so the
// compatibility projection lets actual TCP/path evidence repopulate the
// canonical endpoint view instead of manufacturing transport success.
func compatibilityTargetSnapshot(target model.Target) model.Target {
	target.TestedEndpoint = nil
	return target
}

func compatibilityProbeSnapshot(probes []model.ProbeResult) []model.ProbeResult {
	result := append([]model.ProbeResult(nil), probes...)
	for index := range result {
		result[index].Target = compatibilityTargetSnapshot(result[index].Target)
	}
	return result
}

type candidate struct {
	reason      model.FailureReason
	layer       model.Layer
	domain      model.FaultDomain
	target      model.Target
	probeNames  []string
	evidenceIDs []string
	comparative bool
	supporting  bool
}

type success struct {
	layer       model.Layer
	target      model.Target
	probeNames  []string
	evidenceIDs []string
}

type diagnosisState struct {
	value      model.Observations
	target     model.Target
	candidates []candidate
	successes  []success
}

type rule struct{ reason model.FailureReason }

// This table is the diagnosis policy. It is ordered from the earliest
// decisive boundary to the latest, with specific reasons preceding broader
// reasons within a boundary.
var rules = []rule{
	{model.FailureReasonInterfaceDown},
	{model.FailureReasonNoIPAddress},
	{model.FailureReasonNoRoute},
	{model.FailureReasonInvalidRoute},
	{model.FailureReasonEffectiveRouteDifference},
	{model.FailureReasonDNSNXDomain},
	{model.FailureReasonDNSNoAnswer},
	{model.FailureReasonDNSTimeout},
	{model.FailureReasonDNSResolverFailure},
	{model.FailureReasonProxyAuthenticationRequired},
	{model.FailureReasonProxyConnectDenied},
	{model.FailureReasonDirectEgressRestricted},
	{model.FailureReasonProxyConfigurationDivergence},
	{model.FailureReasonProxyConfigurationFailure},
	{model.FailureReasonProxyUnavailable},
	{model.FailureReasonNetworkUnreachable},
	{model.FailureReasonFirewallBlocked},
	{model.FailureReasonTCPTimeout},
	{model.FailureReasonTCPConnectionRefused},
	{model.FailureReasonTCPConnectionReset},
	{model.FailureReasonTCPSYNNotObserved},
	{model.FailureReasonTLSInterceptionSuspected},
	{model.FailureReasonTLSTrustStoreMismatch},
	{model.FailureReasonTLSHandshakeFailure},
	{model.FailureReasonCertificateValidationFailure},
	{model.FailureReasonHTTPStatusCode},
	{model.FailureReasonHTTPFailure},
	{model.FailureReasonProbeExecution},
}

func diagnoseObservationState(value model.Observations, probes []model.ProbeResult, compatibility bool) []model.DiagnosticFinding {
	state := diagnosisState{value: value, target: targetFromObservations(value)}
	collectCanonical(&state)
	if compatibility {
		collectCompatibility(&state, probes)
	}
	return selectFindings(state)
}

func collectCanonical(state *diagnosisState) {
	value, target := state.value, state.target
	collectEndpoint(state, value.Endpoint, target)
	collectNameResolution(state, value.NameResolution, target)
	collectNetwork(state, value.NetworkContext, target)
	collectTransport(state, value.Transport, target)
	collectPacketFlows(state, value, target)
	collectPaths(state, value, target)
	collectSecurity(state, value.Security, target)
	collectApplication(state, value.Application, target)
	collectEnterprise(state, value.EnterprisePolicy, target)
}

func collectEndpoint(state *diagnosisState, value model.EndpointObservation, target model.Target) {
	target = mergeTarget(target, model.Target{RequestedIdentity: value.RequestedIdentity, Port: value.Port})
	refs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	if value.TestedEndpoint != nil {
		state.successes = append(state.successes, success{layer: model.LayerTCP, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
	}
	attempts := value.CandidateAttempts
	if len(attempts) == 0 || endpointAttemptsSucceeded(attempts) {
		return
	}
	for _, attempt := range attempts {
		if !activeReason(attempt.FailureReason) {
			continue
		}
		layer, domain := semantics(attempt.FailureReason)
		ids := append(append([]string(nil), attempt.EvidenceIDs...), attempt.Candidate.EvidenceIDs...)
		state.candidates = append(state.candidates, candidate{reason: attempt.FailureReason, layer: layer, domain: domain, target: target, probeNames: value.ProbeNames, evidenceIDs: ids})
	}
}

func collectNameResolution(state *diagnosisState, value model.NameResolutionObservation, target model.Target) {
	target = mergeTarget(target, model.Target{RequestedIdentity: value.RequestedName})
	refs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	if activeReason(value.FailureReason) {
		addReasonCandidate(state, value.FailureReason, model.LayerDNS, model.FaultDomainDNS, target, refs, false)
	}
	for _, conflict := range value.Conflicts {
		if !strings.Contains(conflict.Field, "failure_reason") {
			continue
		}
		for _, reason := range conflict.Values {
			if model.FailureReason(reason) == value.FailureReason {
				continue
			}
			ids := append(append([]string(nil), value.EvidenceIDs...), conflict.EvidenceIDs...)
			addReasonCandidate(state, model.FailureReason(reason), model.LayerDNS, model.FaultDomainDNS, target, candidateRefs{probeNames: value.ProbeNames, evidenceIDs: ids}, false)
		}
	}
	// An effective resolver path with an empty answer set is an observed
	// no-answer result. Configured paths without an effective path remain
	// policy context and are intentionally not causal diagnosis.
	if !activeReason(value.FailureReason) && value.EffectivePath != nil && len(value.A) == 0 && len(value.AAAA) == 0 && value.Certainty == model.ObservationCertaintyObserved {
		addReasonCandidate(state, model.FailureReasonDNSNoAnswer, model.LayerDNS, model.FaultDomainDNS, target, refs, false)
	}
	if nameResolutionSucceeded(value) {
		state.successes = append(state.successes, success{layer: model.LayerDNS, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
	}
}

func collectNetwork(state *diagnosisState, value model.NetworkContext, target model.Target) {
	target = mergeTarget(target, model.Target{RequestedIdentity: value.RequestedIdentity})
	refs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	if activeReason(value.FailureReason) && !(value.EffectiveRoute != model.RouteDispositionUnknown && (value.FailureReason == model.FailureReasonNoRoute || value.FailureReason == model.FailureReasonInvalidRoute)) {
		addReasonCandidate(state, value.FailureReason, model.LayerRoute, value.FaultDomain, target, refs, false)
	}
	for _, conflict := range value.Conflicts {
		if !strings.Contains(conflict.Field, "failure_reason") {
			continue
		}
		for _, reason := range conflict.Values {
			if model.FailureReason(reason) == value.FailureReason {
				continue
			}
			addReasonCandidate(state, model.FailureReason(reason), model.LayerRoute, value.FaultDomain, target, candidateRefs{probeNames: value.ProbeNames, evidenceIDs: append(append([]string(nil), value.EvidenceIDs...), conflict.EvidenceIDs...)}, false)
		}
	}
	if value.EffectiveRoute != "" && value.EffectiveRoute != model.RouteDispositionUnknown {
		state.successes = append(state.successes, success{layer: model.LayerRoute, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
	}
}

func collectTransport(state *diagnosisState, value model.TransportObservation, target model.Target) {
	target = mergeTarget(target, targetFromEndpoint(value.ProbeEndpoint, value.TestedEndpoint, value.RequestedEndpoint))
	refs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	if transportSucceeded(value) {
		state.successes = append(state.successes, success{layer: model.LayerTCP, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
		return
	}
	reason := value.FailureReason
	if !activeReason(reason) {
		reason = transportReason(value.ConnectionOutcome)
	}
	if activeReason(reason) && !strongPacketFlow(state.value, reason, target) && value.Applicability != model.ObservationApplicabilityUnsupported && value.Applicability != model.ObservationApplicabilityInapplicable {
		addReasonCandidate(state, reason, model.LayerTCP, value.FaultDomain, target, refs, false)
	}
	for _, conflict := range value.Conflicts {
		if conflict.Field != "transport.connection_outcome" {
			continue
		}
		for _, outcome := range conflict.Values {
			if conflictReason := transportReason(model.TransportConnectionOutcome(outcome)); activeReason(conflictReason) {
				addReasonCandidate(state, conflictReason, model.LayerTCP, value.FaultDomain, target, candidateRefs{probeNames: value.ProbeNames, evidenceIDs: append(append([]string(nil), value.EvidenceIDs...), conflict.EvidenceIDs...)}, false)
			}
		}
	}
}

func collectPacketFlows(state *diagnosisState, value model.Observations, target model.Target) {
	for index, flow := range value.PacketFlows {
		flowTarget := mergeTarget(target, flow.Target)
		names, ids := provenanceAt(value.PacketFlowProvenance, index)
		if len(ids) == 0 {
			ids = append(ids, value.Transport.PacketFlowEvidenceIDs...)
		}
		refs := candidateRefs{probeNames: names, evidenceIDs: ids}
		if flow.CaptureStatus != model.PacketCaptureStatusAvailable || !flowCorrelates(flow.Target, flowTarget, model.LayerTCP) {
			continue
		}
		switch flow.Outcome {
		case model.PacketFlowOutcomeTCPHandshakeConfirmed, model.PacketFlowOutcomeTCPSYNACK:
			if flow.Certainty == model.EvidenceCertaintyConfirmedEndpointResponse {
				state.successes = append(state.successes, success{layer: model.LayerTCP, target: flowTarget, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
			}
		case model.PacketFlowOutcomeTCPRST:
			if flow.Certainty == model.EvidenceCertaintyConfirmedEndpointResponse && packetFlowCanStrengthen(value.Transport.FailureReason, value.Transport.ConnectionOutcome, model.FailureReasonTCPConnectionReset) {
				addReasonCandidate(state, model.FailureReasonTCPConnectionReset, model.LayerTCP, model.FaultDomainTransport, flowTarget, refs, false)
			}
		case model.PacketFlowOutcomeProbeNotEmitted:
			if packetFlowCanStrengthen(value.Transport.FailureReason, value.Transport.ConnectionOutcome, model.FailureReasonTCPSYNNotObserved) {
				addReasonCandidate(state, model.FailureReasonTCPSYNNotObserved, model.LayerTCP, model.FaultDomainLocal, flowTarget, refs, false)
			}
		}
	}
}

func collectPaths(state *diagnosisState, value model.Observations, target model.Target) {
	for index, path := range value.Paths {
		pathTarget := targetForDestination(target, path.Destination, path.DestinationPort)
		names, ids := provenanceAt(value.PathProvenance, index)
		refs := candidateRefs{probeNames: names, evidenceIDs: ids}
		if path.Status != model.PathObservationStatusObserved || !path.PortAware || path.Protocol != model.PathProtocolTCP || !path.DestinationReached {
			continue
		}
		if path.DestinationTCPConnected {
			state.successes = append(state.successes, success{layer: model.LayerTCP, target: pathTarget, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
		}
	}
	for _, correlation := range value.PathCorrelations {
		if correlation.TCPDestinationConnected {
			pathTarget := targetForDestination(target, correlation.Destination, correlation.DestinationPort)
			state.successes = append(state.successes, success{layer: model.LayerTCP, target: pathTarget})
		}
	}
}

func collectSecurity(state *diagnosisState, value model.SecurityObservation, target model.Target) {
	target = mergeTarget(target, targetFromEndpoint(value.EndpointUsed, nil, ""))
	refs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	if value.HandshakeComplete {
		state.successes = append(state.successes, success{layer: model.LayerTLS, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
		return
	}
	reason := value.FailureReason
	if !activeReason(reason) {
		switch value.CertificateValidation {
		case model.CertificateValidationInvalid, model.CertificateValidationExpired, model.CertificateValidationHostnameMismatch, model.CertificateValidationUntrusted, model.CertificateValidationIncomplete:
			reason = model.FailureReasonCertificateValidationFailure
		}
	}
	if activeReason(reason) && value.Applicability != model.ObservationApplicabilityUnsupported {
		addReasonCandidate(state, reason, model.LayerTLS, value.FaultDomain, target, refs, false)
	}
}

func collectApplication(state *diagnosisState, value model.ApplicationObservation, target model.Target) {
	target = mergeTarget(target, targetFromEndpoint(value.EndpointUsed, nil, ""))
	refs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	if value.ResponseReceived && value.Result == model.HTTPResultSuccess && value.StatusCode < 400 {
		state.successes = append(state.successes, success{layer: model.LayerHTTP, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
		return
	}
	reason := value.FailureReason
	if !activeReason(reason) {
		switch value.Result {
		case model.HTTPResultStatusFailure:
			reason = model.FailureReasonHTTPStatusCode
		case model.HTTPResultRequestFailure:
			reason = model.FailureReasonHTTPFailure
		}
	}
	if activeReason(reason) && value.Applicability != model.ObservationApplicabilityUnsupported {
		addReasonCandidate(state, reason, model.LayerHTTP, value.FaultDomain, target, refs, false)
	}
}

func collectEnterprise(state *diagnosisState, value model.EnterprisePolicyObservation, target model.Target) {
	enterpriseTarget := mergeTarget(target, model.Target{RequestedIdentity: value.RequestedIdentity})
	enterpriseRefs := candidateRefs{probeNames: value.ProbeNames, evidenceIDs: value.EvidenceIDs}
	comparison := value.DirectVsProxy
	if comparison.State == model.EnterprisePathComparisonDirectFailureProxyWorks && comparison.DirectWorksKnown && comparison.ProxyWorksKnown && comparison.PolicyPossible {
		ids := append(append([]string(nil), enterpriseRefs.evidenceIDs...), comparison.EvidenceIDs...)
		addReasonCandidate(state, model.FailureReasonDirectEgressRestricted, model.LayerNetwork, model.FaultDomainPolicy, enterpriseTarget, candidateRefs{probeNames: enterpriseRefs.probeNames, evidenceIDs: ids}, true)
	}
	if value.ProxyConfigurationKnown && value.ProxyConfigurationDiverges && comparison.State != model.EnterprisePathComparisonUnknown {
		ids := append(append([]string(nil), enterpriseRefs.evidenceIDs...), enterpriseConflictEvidenceIDs(value)...)
		addReasonCandidate(state, model.FailureReasonProxyConfigurationDivergence, model.LayerProxy, model.FaultDomainProxy, enterpriseTarget, candidateRefs{probeNames: enterpriseRefs.probeNames, evidenceIDs: ids}, false)
	}
	if value.Network.RouteDifferenceKnown && value.Network.RouteDifference {
		ids := append(append([]string(nil), enterpriseRefs.evidenceIDs...), value.Network.EvidenceIDs...)
		addReasonCandidate(state, model.FailureReasonEffectiveRouteDifference, model.LayerRoute, model.FaultDomainRouting, enterpriseTarget, candidateRefs{probeNames: enterpriseRefs.probeNames, evidenceIDs: ids}, true)
	}
	if value.TLS.PossibleInterception && value.TLS.InterceptionSuspicion == model.EnterpriseInterceptionSuspicionPossible && value.TLS.Certainty != model.ObservationCertaintyUnsupported {
		ids := append(append([]string(nil), enterpriseRefs.evidenceIDs...), value.TLS.EvidenceIDs...)
		addReasonCandidate(state, model.FailureReasonTLSInterceptionSuspected, model.LayerTLS, model.FaultDomainTLS, enterpriseTarget, candidateRefs{probeNames: enterpriseRefs.probeNames, evidenceIDs: ids}, true)
	}
	if value.TLS.TrustMismatchKnown && value.TLS.TrustMismatch && value.TLS.Certainty != model.ObservationCertaintyUnsupported {
		ids := append(append([]string(nil), enterpriseRefs.evidenceIDs...), value.TLS.EvidenceIDs...)
		addReasonCandidate(state, model.FailureReasonTLSTrustStoreMismatch, model.LayerTLS, model.FaultDomainTLS, enterpriseTarget, candidateRefs{probeNames: enterpriseRefs.probeNames, evidenceIDs: ids}, true)
	}
	for _, path := range value.Paths {
		pathTarget := mergeTarget(enterpriseTarget, model.Target{RequestedIdentity: value.RequestedIdentity})
		refs := candidateRefs{probeNames: provenanceProbeNames(path.Provenance), evidenceIDs: path.EvidenceIDs}
		if activeReason(path.FailureReason) {
			layer, domain := semantics(path.FailureReason)
			if layer == model.LayerUnknown {
				layer, domain = enterprisePathLayer(path)
			}
			addReasonCandidate(state, path.FailureReason, layer, domain, pathTarget, refs, false)
		}
		if pathWorks(path) {
			addEnterprisePathSuccesses(state, path, pathTarget, refs)
		}
	}
	collectEnterpriseProxySource(state, value.WinHTTP, enterpriseTarget)
	collectEnterpriseProxySource(state, value.WinINET, enterpriseTarget)
}

func collectEnterpriseProxySource(state *diagnosisState, value model.EnterpriseProxySourceObservation, target model.Target) {
	refs := candidateRefs{evidenceIDs: append(append([]string(nil), value.EvidenceIDs...), value.Configuration.EvidenceIDs...)}
	if value.Configuration.Error != "" {
		addReasonCandidate(state, model.FailureReasonProxyConfigurationFailure, model.LayerProxy, model.FaultDomainProxy, target, refs, false)
	}
	if value.Effective.Observed && !value.Effective.ResolutionOK && value.Effective.Error != "" {
		ids := append(append([]string(nil), refs.evidenceIDs...), value.Effective.EvidenceIDs...)
		addReasonCandidate(state, model.FailureReasonProxyConfigurationFailure, model.LayerProxy, model.FaultDomainProxy, target, candidateRefs{probeNames: provenanceProbeNames(value.Effective.Provenance), evidenceIDs: ids}, false)
	}
	for _, endpoint := range value.EndpointReachability {
		ids := append(append([]string(nil), refs.evidenceIDs...), endpoint.EvidenceIDs...)
		if endpoint.Reachability == model.EnterpriseEndpointUnavailable || endpoint.Reachability == model.EnterpriseEndpointTimeout {
			addReasonCandidate(state, model.FailureReasonProxyUnavailable, model.LayerProxy, model.FaultDomainProxy, target, candidateRefs{evidenceIDs: ids}, false)
		}
	}
}

func addEnterprisePathSuccesses(state *diagnosisState, path model.EnterprisePathObservation, target model.Target, refs candidateRefs) {
	if path.TCPConnected || path.HTTPResponse || path.TLSHandshake {
		state.successes = append(state.successes, success{layer: model.LayerTCP, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
	}
	if path.TLSHandshake && path.CertificateTrusted && path.HostnameVerified {
		state.successes = append(state.successes, success{layer: model.LayerTLS, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
	}
	if path.HTTPResponse && path.HTTPStatusCode >= 200 && path.HTTPStatusCode < 400 {
		state.successes = append(state.successes, success{layer: model.LayerHTTP, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs})
	}
}

func collectCompatibility(state *diagnosisState, probes []model.ProbeResult) {
	for _, probe := range probes {
		reason := probe.Interpretation.FailureReason
		if activeReason(reason) {
			if reason == model.FailureReasonICMPFailure || reason == model.FailureReasonPathObservation || reason == model.FailureReasonPathCancellation || probe.Interpretation.Layer == model.LayerICMP || probe.Interpretation.FaultDomain == model.FaultDomainICMP || !compatibilityReasonAllowed(reason, state.value) {
				continue
			}
			layer, domain := semantics(reason)
			if layer == model.LayerUnknown {
				layer, domain = probe.Interpretation.Layer, probe.Interpretation.FaultDomain
			}
			state.candidates = append(state.candidates, candidate{reason: reason, layer: layer, domain: domain, target: compatibilityTarget(state.target, probe.Target), probeNames: []string{probe.Name}, evidenceIDs: evidenceIDs(probe.Evidence), supporting: reason == model.FailureReasonGatewayUnreachable})
			continue
		}
		if probe.Status == model.ProbeStatusPassed && probe.Interpretation.FailureReason == model.FailureReasonNone {
			layer := probe.Interpretation.Layer
			if layer != model.LayerProxy && (!canonicalLayerPresent(state.value, layer) || compatibilitySuccessCanFillGap(state.value, layer)) {
				state.successes = append(state.successes, success{layer: layer, target: compatibilityTarget(state.target, probe.Target), probeNames: []string{probe.Name}, evidenceIDs: evidenceIDs(probe.Evidence)})
			}
		}
	}
}

func selectFindings(state diagnosisState) []model.DiagnosticFinding {
	var builtIn *candidate
	for _, policy := range rules {
		matches := candidatesForReason(state.candidates, policy.reason)
		viable := make([]candidate, 0, len(matches))
		for _, match := range matches {
			if !candidateContradicted(match, state.successes) {
				viable = append(viable, match)
			}
		}
		if len(viable) != 0 {
			value := mergeCandidates(viable)
			builtIn = &value
			break
		}
	}
	extension := genericFailure(state.candidates, state.successes)
	if extension != nil && (builtIn == nil || layerRank(extension.layer) < layerRank(builtIn.layer)) {
		return withGatewaySupport(makeFinding(*extension), state)
	}
	if builtIn != nil {
		return withGatewaySupport(makeFinding(*builtIn), state)
	}
	if gateway := gatewayCandidates(state); len(gateway) != 0 {
		return []model.DiagnosticFinding{makeFinding(mergeCandidates(gateway))}
	}
	return nil
}

func withGatewaySupport(finding model.DiagnosticFinding, state diagnosisState) []model.DiagnosticFinding {
	result := []model.DiagnosticFinding{finding}
	if gateway := gatewayCandidates(state); len(gateway) != 0 {
		result = append(result, makeFinding(mergeCandidates(gateway)))
	}
	return result
}

func gatewayCandidates(state diagnosisState) []candidate {
	if state.value.NetworkContext.EffectiveRoute == model.RouteDispositionOnLink {
		return nil
	}
	result := make([]candidate, 0)
	for _, value := range state.candidates {
		if value.reason != model.FailureReasonGatewayUnreachable {
			continue
		}
		if state.value.NetworkContext.EffectiveRoute == model.RouteDispositionRouted && state.value.NetworkContext.Gateway == "" {
			continue
		}
		if !candidateContradicted(value, state.successes) {
			result = append(result, value)
		}
	}
	return result
}

func candidatesForReason(values []candidate, reason model.FailureReason) []candidate {
	result := make([]candidate, 0)
	for _, value := range values {
		if value.reason == reason && !value.supporting {
			result = append(result, value)
		}
	}
	return result
}

func genericFailure(values []candidate, successes []success) *candidate {
	ordered := make([]candidate, 0)
	for _, value := range values {
		if isGenericReason(value.reason) && !value.supporting && !candidateContradicted(value, successes) {
			ordered = append(ordered, value)
		}
	}
	if len(ordered) == 0 {
		return nil
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if layerRank(left.layer) != layerRank(right.layer) {
			return layerRank(left.layer) < layerRank(right.layer)
		}
		if left.reason != right.reason {
			return left.reason < right.reason
		}
		if left.domain != right.domain {
			return left.domain < right.domain
		}
		return strings.Join(sortedUnique(left.probeNames), "\x00") < strings.Join(sortedUnique(right.probeNames), "\x00")
	})
	first := ordered[0]
	selected := []candidate{first}
	for _, value := range ordered[1:] {
		if value.reason == first.reason && value.layer == first.layer && value.domain == first.domain {
			selected = append(selected, value)
		}
	}
	merged := mergeCandidates(selected)
	return &merged
}

func candidateContradicted(value candidate, successes []success) bool {
	if value.comparative {
		return false
	}
	for _, success := range successes {
		if !targetsCorrelate(value.target, success.target, value.layer) {
			continue
		}
		if successfulLayerContradicts(value.reason, value.layer, success.layer) {
			return true
		}
	}
	return false
}

func successfulLayerContradicts(reason model.FailureReason, failedLayer, successfulLayer model.Layer) bool {
	// Comparative observations describe distinct lanes. Their policy finding
	// remains useful even when one endpoint lane succeeds.
	switch reason {
	case model.FailureReasonDirectEgressRestricted, model.FailureReasonEffectiveRouteDifference, model.FailureReasonTLSInterceptionSuspected, model.FailureReasonTLSTrustStoreMismatch, model.FailureReasonProxyConfigurationDivergence:
		return false
	}
	switch failedLayer {
	case model.LayerInterface, model.LayerIPConfiguration, model.LayerRoute, model.LayerGateway, model.LayerNetwork:
		return successfulLayer == model.LayerTCP || successfulLayer == model.LayerTLS || successfulLayer == model.LayerHTTP
	case model.LayerDNS, model.LayerProxy:
		return successfulLayer == failedLayer
	case model.LayerTCP:
		return successfulLayer == model.LayerTCP || successfulLayer == model.LayerTLS || successfulLayer == model.LayerHTTP
	case model.LayerTLS:
		return successfulLayer == model.LayerTLS || successfulLayer == model.LayerHTTP
	case model.LayerHTTP:
		return successfulLayer == model.LayerHTTP
	default:
		return false
	}
}

func makeFinding(value candidate) model.DiagnosticFinding {
	layer, domain := semantics(value.reason)
	if layer == model.LayerUnknown {
		layer, domain = value.layer, value.domain
	}
	return model.DiagnosticFinding{FailureReason: value.reason, Layer: layer, FaultDomain: domain, ProbeNames: sortedUnique(value.probeNames), EvidenceIDs: sortedUnique(value.evidenceIDs)}
}

func mergeCandidates(values []candidate) candidate {
	if len(values) == 0 {
		return candidate{}
	}
	result := values[0]
	for _, value := range values[1:] {
		result.probeNames = append(result.probeNames, value.probeNames...)
		result.evidenceIDs = append(result.evidenceIDs, value.evidenceIDs...)
		result.comparative = result.comparative || value.comparative
	}
	result.probeNames = sortedUnique(result.probeNames)
	result.evidenceIDs = sortedUnique(result.evidenceIDs)
	return result
}

type candidateRefs struct {
	probeNames  []string
	evidenceIDs []string
}

func addReasonCandidate(state *diagnosisState, reason model.FailureReason, fallbackLayer model.Layer, fallbackDomain model.FaultDomain, target model.Target, refs candidateRefs, comparative bool) {
	if !activeReason(reason) {
		return
	}
	layer, domain := semantics(reason)
	if layer == model.LayerUnknown {
		layer, domain = fallbackLayer, fallbackDomain
	}
	if domain == "" {
		domain = model.FaultDomainUnknown
	}
	state.candidates = append(state.candidates, candidate{reason: reason, layer: layer, domain: domain, target: target, probeNames: refs.probeNames, evidenceIDs: refs.evidenceIDs, comparative: comparative, supporting: reason == model.FailureReasonGatewayUnreachable})
}

func activeReason(reason model.FailureReason) bool {
	switch reason {
	case "", model.FailureReasonNone, model.FailureReasonUnknown, model.FailureReasonUnsupported, model.FailureReasonICMPFailure, model.FailureReasonPathObservation, model.FailureReasonPathCancellation:
		return false
	default:
		return true
	}
}

func isGenericReason(reason model.FailureReason) bool {
	if !activeReason(reason) || reason == model.FailureReasonGatewayUnreachable {
		return false
	}
	for _, value := range rules {
		if value.reason == reason {
			return false
		}
	}
	return true
}

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
	case model.FailureReasonDNSNXDomain, model.FailureReasonDNSNoAnswer, model.FailureReasonDNSTimeout, model.FailureReasonDNSResolverFailure:
		return model.LayerDNS, model.FaultDomainDNS
	case model.FailureReasonProxyConfigurationFailure, model.FailureReasonProxyConfigurationDivergence, model.FailureReasonProxyUnavailable, model.FailureReasonProxyConnectDenied, model.FailureReasonProxyAuthenticationRequired:
		return model.LayerProxy, model.FaultDomainProxy
	case model.FailureReasonDirectEgressRestricted:
		return model.LayerNetwork, model.FaultDomainPolicy
	case model.FailureReasonNetworkUnreachable:
		return model.LayerNetwork, model.FaultDomainNetwork
	case model.FailureReasonFirewallBlocked:
		return model.LayerNetwork, model.FaultDomainFirewall
	case model.FailureReasonTCPSYNNotObserved:
		return model.LayerTCP, model.FaultDomainLocal
	case model.FailureReasonTCPTimeout, model.FailureReasonTCPConnectionRefused, model.FailureReasonTCPConnectionReset:
		return model.LayerTCP, model.FaultDomainTransport
	case model.FailureReasonTLSHandshakeFailure, model.FailureReasonCertificateValidationFailure, model.FailureReasonTLSTrustStoreMismatch, model.FailureReasonTLSInterceptionSuspected:
		return model.LayerTLS, model.FaultDomainTLS
	case model.FailureReasonHTTPStatusCode, model.FailureReasonHTTPFailure:
		return model.LayerHTTP, model.FaultDomainHTTP
	case model.FailureReasonProbeExecution:
		return model.LayerUnknown, model.FaultDomainUnknown
	default:
		return model.LayerUnknown, model.FaultDomainUnknown
	}
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

func targetFromObservations(value model.Observations) model.Target {
	target := model.Target{RequestedIdentity: value.Endpoint.RequestedIdentity, LiteralIP: value.Endpoint.LiteralIP, Service: value.Endpoint.Service, ApplicationProtocol: value.Endpoint.ApplicationProtocol, TransportProtocol: value.Endpoint.TransportProtocol, Port: value.Endpoint.Port, Resource: value.Endpoint.Resource}
	if target.RequestedIdentity == "" {
		target.RequestedIdentity = value.NameResolution.RequestedName
	}
	if value.Endpoint.SelectedEndpoint != nil {
		endpoint := *value.Endpoint.SelectedEndpoint
		target.SelectedEndpoint = &endpoint
	}
	if value.Endpoint.TestedEndpoint != nil {
		endpoint := *value.Endpoint.TestedEndpoint
		target.TestedEndpoint = &endpoint
	}
	return target
}

func targetFromProbes(probes []model.ProbeResult) model.Target {
	var target model.Target
	for _, probe := range probes {
		candidate := probe.Target
		if candidate.RequestedIdentity == "" && candidate.Port == 0 && candidate.OriginalInput == "" {
			continue
		}
		if target.RequestedIdentity == "" || target.Port == 0 {
			target = candidate
		}
	}
	return target
}

func mergeTarget(left, right model.Target) model.Target {
	result := left
	if result.RequestedIdentity == "" {
		result.RequestedIdentity = right.RequestedIdentity
	}
	if result.Port == 0 {
		result.Port = right.Port
	}
	if result.LiteralIP == "" {
		result.LiteralIP = right.LiteralIP
	}
	if result.SelectedEndpoint == nil && right.SelectedEndpoint != nil {
		endpoint := *right.SelectedEndpoint
		result.SelectedEndpoint = &endpoint
	}
	if result.TestedEndpoint == nil && right.TestedEndpoint != nil {
		endpoint := *right.TestedEndpoint
		result.TestedEndpoint = &endpoint
	}
	return result
}

func compatibilityTarget(base, probe model.Target) model.Target {
	if probe.RequestedIdentity != "" || probe.Port != 0 || probe.OriginalInput != "" {
		return probe
	}
	return base
}

func targetForDestination(base model.Target, destination string, port uint16) model.Target {
	result := base
	if destination != "" {
		result.RequestedIdentity = destination
	}
	if port != 0 {
		result.Port = port
	}
	return result
}

func targetFromEndpoint(probe, tested *model.Endpoint, requested string) model.Target {
	target := model.Target{RequestedIdentity: requested}
	if tested != nil {
		target.Port = tested.Port
		target.TestedEndpoint = tested
	} else if probe != nil {
		target.Port = probe.Port
		target.SelectedEndpoint = probe
	}
	return target
}

func endpointAttemptsSucceeded(values []model.EndpointAttempt) bool {
	for _, value := range values {
		if value.Status == model.ProbeStatusPassed || value.FailureReason == model.FailureReasonNone {
			return true
		}
	}
	return false
}

func transportSucceeded(value model.TransportObservation) bool {
	return value.Connected || value.ConnectionOutcome == model.TransportConnectionOutcomeConnected || value.TestedEndpoint != nil || endpointAttemptsSucceeded(value.CandidateAttempts)
}

func transportReason(outcome model.TransportConnectionOutcome) model.FailureReason {
	switch outcome {
	case model.TransportConnectionOutcomeTimeout:
		return model.FailureReasonTCPTimeout
	case model.TransportConnectionOutcomeRefused:
		return model.FailureReasonTCPConnectionRefused
	case model.TransportConnectionOutcomeReset:
		return model.FailureReasonTCPConnectionReset
	case model.TransportConnectionOutcomeUnreachable:
		return model.FailureReasonNetworkUnreachable
	default:
		return model.FailureReasonNone
	}
}

func packetFlowCanStrengthen(reason model.FailureReason, outcome model.TransportConnectionOutcome, strengthened model.FailureReason) bool {
	if strengthened == model.FailureReasonTCPConnectionReset || strengthened == model.FailureReasonTCPSYNNotObserved {
		return reason == model.FailureReasonTCPTimeout || reason == model.FailureReasonProbeExecution || reason == model.FailureReasonUnknown || reason == model.FailureReasonNone || outcome == model.TransportConnectionOutcomeTimeout
	}
	return false
}

func nameResolutionSucceeded(value model.NameResolutionObservation) bool {
	return value.SelectedAddress != "" || len(value.A) != 0 || len(value.AAAA) != 0 || value.EffectivePath != nil && value.EffectivePath.Mechanism == model.NameResolutionMechanismLiteralIP
}

func pathWorks(value model.EnterprisePathObservation) bool {
	if activeReason(value.FailureReason) {
		return false
	}
	return value.HTTPResponse && value.HTTPStatusCode >= 200 && value.HTTPStatusCode < 400 || value.TLSHandshake && value.CertificateTrusted && value.HostnameVerified
}

func enterprisePathLayer(value model.EnterprisePathObservation) (model.Layer, model.FaultDomain) {
	if strings.Contains(strings.ToLower(value.Mode), "proxy") || strings.Contains(strings.ToLower(value.Source), "proxy") {
		return model.LayerProxy, model.FaultDomainProxy
	}
	return model.LayerUnknown, model.FaultDomainUnknown
}

func targetsCorrelate(left, right model.Target, layer model.Layer) bool {
	leftIdentity, rightIdentity := targetIdentity(left), targetIdentity(right)
	if leftIdentity != "" && rightIdentity != "" && !strings.EqualFold(leftIdentity, rightIdentity) && !targetAddressesCorrelate(left, right) {
		return false
	}
	if transportEndpointLayer(layer) && left.Port != 0 && right.Port != 0 && left.Port != right.Port {
		return false
	}
	return true
}

func targetAddressesCorrelate(left, right model.Target) bool {
	leftValues := targetAddresses(left)
	rightValues := targetAddresses(right)
	for _, leftValue := range leftValues {
		for _, rightValue := range rightValues {
			if strings.EqualFold(leftValue, rightValue) || left.MatchesAddress(rightValue) || right.MatchesAddress(leftValue) {
				return true
			}
		}
	}
	return false
}

func targetAddresses(value model.Target) []string {
	result := []string{}
	if value.LiteralIP != "" {
		result = append(result, value.LiteralIP)
	}
	if value.SelectedEndpoint != nil {
		result = append(result, value.SelectedEndpoint.Address)
	}
	if value.TestedEndpoint != nil {
		result = append(result, value.TestedEndpoint.Address)
	}
	return result
}

func flowCorrelates(flow, target model.Target, layer model.Layer) bool {
	return targetsCorrelate(flow, target, layer)
}

func targetIdentity(value model.Target) string {
	if value.RequestedIdentity != "" {
		return value.RequestedIdentity
	}
	if value.TestedEndpoint != nil {
		return value.TestedEndpoint.Address
	}
	if value.SelectedEndpoint != nil {
		return value.SelectedEndpoint.Address
	}
	return value.LiteralIP
}

func transportEndpointLayer(layer model.Layer) bool {
	switch layer {
	case model.LayerTCP, model.LayerTLS, model.LayerHTTP, model.LayerDestination:
		return true
	default:
		return false
	}
}

func provenanceAt(values []model.ObservationProvenance, index int) ([]string, []string) {
	if index < 0 || index >= len(values) {
		return nil, nil
	}
	value := values[index]
	names := []string{}
	if value.ProbeName != "" {
		names = append(names, value.ProbeName)
	}
	return names, append([]string(nil), value.EvidenceIDs...)
}

func provenanceProbeNames(values []string) []string {
	result := make([]string, 0)
	for _, value := range values {
		if strings.HasPrefix(value, "probe:") && len(value) > len("probe:") {
			result = append(result, strings.TrimPrefix(value, "probe:"))
		}
	}
	return sortedUnique(result)
}

func evidenceIDs(values []model.Evidence) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value.ID != "" {
			result = append(result, value.ID)
		}
	}
	return sortedUnique(result)
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 1
	for _, value := range result[1:] {
		if value != result[write-1] {
			result[write] = value
			write++
		}
	}
	return result[:write]
}

func compatibilityReasonAllowed(reason model.FailureReason, value model.Observations) bool {
	switch reason {
	case model.FailureReasonInterfaceDown, model.FailureReasonNoIPAddress:
		return !activeReason(value.NetworkContext.FailureReason)
	case model.FailureReasonNoRoute, model.FailureReasonInvalidRoute:
		return value.NetworkContext.EffectiveRoute == model.RouteDispositionUnknown && !activeReason(value.NetworkContext.FailureReason)
	case model.FailureReasonEffectiveRouteDifference:
		return !value.EnterprisePolicy.Network.RouteDifferenceKnown
	case model.FailureReasonDNSNXDomain, model.FailureReasonDNSNoAnswer, model.FailureReasonDNSTimeout, model.FailureReasonDNSResolverFailure:
		return !activeReason(value.NameResolution.FailureReason)
	case model.FailureReasonTCPTimeout, model.FailureReasonTCPConnectionRefused, model.FailureReasonTCPConnectionReset, model.FailureReasonTCPSYNNotObserved, model.FailureReasonNetworkUnreachable:
		return !transportHasObservation(value.Transport) && !strongPacketFlow(value, reason, targetFromObservations(value))
	case model.FailureReasonTLSHandshakeFailure, model.FailureReasonCertificateValidationFailure, model.FailureReasonTLSTrustStoreMismatch, model.FailureReasonTLSInterceptionSuspected:
		return !securityHasObservation(value.Security) && !value.EnterprisePolicy.TLS.PossibleInterception
	case model.FailureReasonHTTPStatusCode, model.FailureReasonHTTPFailure:
		return !applicationHasObservation(value.Application)
	default:
		return true
	}
}

func transportHasObservation(value model.TransportObservation) bool {
	directEvidence := len(value.EvidenceIDs) != 0 && len(value.PacketFlowEvidenceIDs) != len(value.EvidenceIDs)
	return activeReason(value.FailureReason) || value.ConnectionOutcome != "" && value.ConnectionOutcome != model.TransportConnectionOutcomeNotAttempted && value.ConnectionOutcome != model.TransportConnectionOutcomeUnknown || directEvidence || len(value.CandidateAttempts) != 0 || value.TestedEndpoint != nil
}

func strongPacketFlow(value model.Observations, reason model.FailureReason, target model.Target) bool {
	if reason != model.FailureReasonTCPTimeout && reason != model.FailureReasonProbeExecution && reason != model.FailureReasonUnknown && reason != model.FailureReasonNone {
		return false
	}
	for _, flow := range value.PacketFlows {
		if flow.CaptureStatus != model.PacketCaptureStatusAvailable || !flowCorrelates(flow.Target, target, model.LayerTCP) {
			continue
		}
		switch flow.Outcome {
		case model.PacketFlowOutcomeTCPHandshakeConfirmed, model.PacketFlowOutcomeTCPSYNACK:
			return flow.Certainty == model.EvidenceCertaintyConfirmedEndpointResponse
		case model.PacketFlowOutcomeTCPRST, model.PacketFlowOutcomeProbeNotEmitted:
			return true
		}
	}
	return false
}

func securityHasObservation(value model.SecurityObservation) bool {
	return value.HandshakeComplete || activeReason(value.FailureReason) || len(value.EvidenceIDs) != 0
}

func applicationHasObservation(value model.ApplicationObservation) bool {
	return value.RequestAttempted || value.ResponseReceived || activeReason(value.FailureReason) || len(value.EvidenceIDs) != 0
}

func canonicalLayerPresent(value model.Observations, layer model.Layer) bool {
	switch layer {
	case model.LayerDNS:
		return value.NameResolution.RequestedName != "" || value.NameResolution.FailureReason != "" || len(value.NameResolution.EvidenceIDs) != 0 || nameResolutionSucceeded(value.NameResolution)
	case model.LayerRoute, model.LayerInterface, model.LayerIPConfiguration:
		return value.NetworkContext.RequestedIdentity != "" || value.NetworkContext.EffectiveRoute != "" && value.NetworkContext.EffectiveRoute != model.RouteDispositionUnknown || value.NetworkContext.FailureReason != "" || len(value.NetworkContext.EvidenceIDs) != 0
	case model.LayerTCP:
		return transportHasObservation(value.Transport) || len(value.PacketFlows) != 0 || len(value.Paths) != 0 || value.Endpoint.TestedEndpoint != nil || len(value.Endpoint.CandidateAttempts) != 0
	case model.LayerTLS:
		return securityHasObservation(value.Security) || value.EnterprisePolicy.TLS.PossibleInterception
	case model.LayerHTTP:
		return applicationHasObservation(value.Application)
	default:
		return false
	}
}

func compatibilitySuccessCanFillGap(value model.Observations, layer model.Layer) bool {
	if layer != model.LayerDNS {
		return false
	}
	return len(value.NameResolution.EvidenceIDs) == 0 && !nameResolutionSucceeded(value.NameResolution)
}

func hasCanonicalObservations(value model.Observations) bool {
	return value.Endpoint.RequestedIdentity != "" || value.Endpoint.Port != 0 || len(value.Endpoint.ResolvedCandidates) != 0 || len(value.Endpoint.CandidateAttempts) != 0 || value.NameResolution.RequestedName != "" || len(value.NameResolution.EvidenceIDs) != 0 || value.NetworkContext.RequestedIdentity != "" || value.NetworkContext.EffectiveRoute != "" && value.NetworkContext.EffectiveRoute != model.RouteDispositionUnknown || len(value.NetworkContext.EvidenceIDs) != 0 || activeReason(value.Transport.FailureReason) || value.Transport.ConnectionOutcome != "" && value.Transport.ConnectionOutcome != model.TransportConnectionOutcomeUnknown || value.Security.FailureReason != "" || value.Security.Attempted || value.Application.FailureReason != "" || value.Application.RequestAttempted || value.EnterprisePolicy.State != "" && value.EnterprisePolicy.State != model.EnterpriseObservationStateUnknown || len(value.Paths) != 0 || len(value.PacketFlows) != 0
}

func enterpriseConflictEvidenceIDs(value model.EnterprisePolicyObservation) []string {
	result := make([]string, 0)
	for _, conflict := range value.Conflicts {
		result = append(result, conflict.EvidenceIDs...)
	}
	return sortedUnique(result)
}
