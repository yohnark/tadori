package report

import (
	"fmt"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// DestinationStatusState is the semantic answer to whether the requested
// service boundary was reached. It is intentionally separate from report
// execution status and from individual probe status.
type DestinationStatusState string

const (
	DestinationStatusReachable     DestinationStatusState = "reachable"
	DestinationStatusUnreachable   DestinationStatusState = "unreachable"
	DestinationStatusDegraded      DestinationStatusState = "degraded"
	DestinationStatusIndeterminate DestinationStatusState = "indeterminate"
)

// DestinationStatus is the backend-owned summary shared by the workbench and
// exported report. Its conclusion is based only on normalized observations;
// raw probe evidence is never decoded here.
type DestinationStatus struct {
	Status            DestinationStatusState `json:"status"`
	Label             string                 `json:"label"`
	Detail            string                 `json:"detail"`
	RequestedIdentity string                 `json:"requested_identity,omitempty"`
	RequestedService  string                 `json:"requested_service,omitempty"`
	EffectiveEndpoint *model.Endpoint        `json:"effective_endpoint,omitempty"`
	FailureReason     model.FailureReason    `json:"failure_reason,omitempty"`
	ProbeNames        []string               `json:"probe_names,omitempty"`
	EvidenceIDs       []string               `json:"evidence_ids,omitempty"`
	Provenance        []string               `json:"provenance,omitempty"`
}

// DestinationStatusForReport projects one report-level semantic destination
// status. Observations are the authority; the compatibility Target and raw
// probe evidence are deliberately not consulted for the conclusion.
func DestinationStatusForReport(diagnosticReport model.DiagnosticReport) DestinationStatus {
	return DestinationStatusFromObservations(diagnosticReport.Observations)
}

// DestinationStatusFromObservations projects normalized canonical
// observations into the four-state destination status vocabulary.
func DestinationStatusFromObservations(value model.Observations) DestinationStatus {
	observations := model.NormalizeObservations(value)
	status := baseDestinationStatus(observations)

	// Application observations have precedence over lower layers. A service
	// response can be degraded even when TCP and TLS were both successful.
	if result, ok := applicationDestinationStatus(&status, observations); ok {
		return result
	}
	if result, ok := securityDestinationStatus(&status, observations); ok {
		return result
	}
	pathResult, pathObserved := pathDestinationStatus(&status, observations)
	if pathObserved && pathResult.Status == DestinationStatusReachable {
		return pathResult
	}
	if result, ok := transportDestinationStatus(&status, observations); ok {
		return result
	}
	if pathObserved {
		return pathResult
	}

	addNameResolutionRefs(&status, observations.NameResolution)
	if observations.NameResolution.FailureReason != "" && observations.NameResolution.FailureReason != model.FailureReasonNone && observations.NameResolution.FailureReason != model.FailureReasonUnknown ||
		(observations.NameResolution.Certainty == model.ObservationCertaintyObserved &&
			len(observations.NameResolution.A) == 0 && len(observations.NameResolution.AAAA) == 0) {
		return finishDestinationStatus(status, DestinationStatusIndeterminate,
			"Name resolution did not establish a usable endpoint.", observations.NameResolution.FailureReason)
	}
	return finishDestinationStatus(status, DestinationStatusIndeterminate,
		"Reachability could not be established from the available evidence.", model.FailureReasonNone)
}

func baseDestinationStatus(observations model.Observations) DestinationStatus {
	service := serviceLabel(observations.Endpoint.Service)
	if service == "" && observations.Application.Protocol != "" {
		service = strings.ToUpper(string(observations.Application.Protocol))
	}
	status := DestinationStatus{
		Status:            DestinationStatusIndeterminate,
		Label:             "Indeterminate",
		Detail:            "Reachability could not be established from the available evidence.",
		RequestedIdentity: firstNonEmpty(observations.Endpoint.RequestedIdentity, observations.NameResolution.RequestedName),
		RequestedService:  service,
		EffectiveEndpoint: effectiveDestinationEndpoint(observations),
		FailureReason:     model.FailureReasonNone,
	}
	if status.EffectiveEndpoint != nil {
		status.EvidenceIDs = appendUniqueDestination(status.EvidenceIDs, status.EffectiveEndpoint.EvidenceIDs...)
		if status.EffectiveEndpoint.Provenance != "" {
			status.Provenance = appendUniqueDestination(status.Provenance, status.EffectiveEndpoint.Provenance)
		}
	}
	return status
}

func applicationDestinationStatus(status *DestinationStatus, observations model.Observations) (DestinationStatus, bool) {
	application := observations.Application
	protocol := application.Protocol
	if protocol == "" && application.SMB == nil && !applicationAttempted(application) {
		return DestinationStatus{}, false
	}
	if application.Applicability == model.ObservationApplicabilityUnsupported ||
		application.Result == model.HTTPResultUnsupported || application.ProtocolResult == model.ApplicationProtocolResultUnsupported {
		addObservationRefs(status, application.Provenance, application.ProbeNames, application.EvidenceIDs...)
		return finishDestinationStatus(*status, DestinationStatusIndeterminate, "The requested application protocol is unsupported.", model.FailureReasonUnsupported), true
	}
	if requiresApplicationBoundary(protocol) && !applicationAttempted(application) {
		// HTTPS and custom TLS can establish their requested boundary at the
		// TLS layer when no HTTP/application request was attempted. Let the
		// security projection classify that evidence instead.
		if (protocol == model.ApplicationProtocolHTTPS || protocol == model.ApplicationProtocolTLS) &&
			(observations.Security.Attempted || observations.Security.HandshakeComplete) {
			return DestinationStatus{}, false
		}
		addObservationRefs(status, application.Provenance, application.ProbeNames, application.EvidenceIDs...)
		pathResult, pathObserved := pathDestinationStatus(status, observations)
		if pathObserved && pathResult.Status != DestinationStatusReachable {
			return pathResult, true
		}
		if !pathObserved {
			if result, ok := transportDestinationStatus(status, observations); ok && result.Status == DestinationStatusUnreachable {
				return result, true
			}
		}
		addPathObservationRefs(status, observations)
		return finishDestinationStatus(*status, DestinationStatusIndeterminate, "The requested application service was not attempted.", model.FailureReasonNone), true
	}

	if application.SMB != nil || protocol == model.ApplicationProtocolSMB {
		addObservationRefs(status, application.Provenance, application.ProbeNames, application.EvidenceIDs...)
		if application.SMB != nil && (application.SMB.Negotiated || application.SMB.Result == model.SMBResultNegotiated) {
			return finishDestinationStatus(*status, DestinationStatusReachable, "SMB negotiation succeeded.", model.FailureReasonNone), true
		}
		if application.SMB != nil && application.SMB.Result == model.SMBResultTCPFailure {
			if result, ok := transportDestinationStatus(status, observations); ok {
				return result, true
			}
			return finishDestinationStatus(*status, DestinationStatusIndeterminate, "SMB transport evidence is insufficient.", application.FailureReason), true
		}
		if applicationAttempted(application) || (application.SMB != nil && application.SMB.Result != model.SMBResultUnknown && application.SMB.Result != model.SMBResultNotAttempted) {
			if application.ResponseReceived || application.TransportConnected || observations.Transport.Connected {
				return finishDestinationStatus(*status, DestinationStatusDegraded, "SMB protocol negotiation was rejected or failed.", application.FailureReason), true
			}
		}
		return DestinationStatus{}, false
	}

	if protocol == model.ApplicationProtocolHTTP || protocol == model.ApplicationProtocolHTTPS ||
		application.StatusCode != 0 || application.Result == model.HTTPResultSuccess ||
		application.Result == model.HTTPResultStatusFailure || application.Result == model.HTTPResultRequestFailure {
		addObservationRefs(status, application.Provenance, application.ProbeNames, application.EvidenceIDs...)
		if application.ResponseReceived {
			if application.StatusCode >= 400 || application.Result == model.HTTPResultStatusFailure {
				reason := application.FailureReason
				if reason == model.FailureReasonNone || reason == model.FailureReasonUnknown {
					reason = model.FailureReasonHTTPStatusCode
				}
				return finishDestinationStatus(*status, DestinationStatusDegraded,
					fmt.Sprintf("HTTP returned %d.", application.StatusCode), reason), true
			}
			if application.Result == model.HTTPResultSuccess || (application.StatusCode >= 200 && application.StatusCode < 400) {
				return finishDestinationStatus(*status, DestinationStatusReachable,
					httpSuccessDetail(application.StatusCode), model.FailureReasonNone), true
			}
		}
		if applicationAttempted(application) || application.Result == model.HTTPResultRequestFailure {
			if application.TransportConnected || observations.Transport.Connected {
				return finishDestinationStatus(*status, DestinationStatusDegraded, "HTTP request failed after transport connection.", application.FailureReason), true
			}
			if result, ok := transportDestinationStatus(status, observations); ok {
				return result, true
			}
		}
		return DestinationStatus{}, false
	}

	if protocol == model.ApplicationProtocolSSH || protocol == model.ApplicationProtocolRDP {
		addObservationRefs(status, application.Provenance, application.ProbeNames, application.EvidenceIDs...)
		if application.HandshakeComplete || application.ProtocolResult == model.ApplicationProtocolResultSuccess {
			return finishDestinationStatus(*status, DestinationStatusReachable,
				strings.ToUpper(string(protocol))+" handshake succeeded.", model.FailureReasonNone), true
		}
		if applicationAttempted(application) {
			if application.TransportConnected || application.ResponseReceived || application.EndpointUsed != nil || observations.Transport.Connected {
				return finishDestinationStatus(*status, DestinationStatusDegraded,
					strings.ToUpper(string(protocol))+" protocol handshake was rejected or malformed.", application.FailureReason), true
			}
			if result, ok := transportDestinationStatus(status, observations); ok {
				return result, true
			}
		}
		return DestinationStatus{}, false
	}

	if application.RequestAttempted || application.ResponseReceived || application.HandshakeAttempted {
		addObservationRefs(status, application.Provenance, application.ProbeNames, application.EvidenceIDs...)
		if application.ResponseReceived || application.TransportConnected || observations.Transport.Connected {
			return finishDestinationStatus(*status, DestinationStatusDegraded, "The requested application service did not complete successfully.", application.FailureReason), true
		}
	}
	return DestinationStatus{}, false
}

func applicationAttempted(application model.ApplicationObservation) bool {
	return application.RequestAttempted || application.ResponseReceived || application.HandshakeAttempted ||
		(application.ProtocolResult != "" && application.ProtocolResult != model.ApplicationProtocolResultNotAttempted) ||
		(application.Result != "" && application.Result != model.HTTPResultNotAttempted)
}

func requiresApplicationBoundary(protocol model.ApplicationProtocol) bool {
	switch protocol {
	case model.ApplicationProtocolHTTP, model.ApplicationProtocolHTTPS,
		model.ApplicationProtocolSMB, model.ApplicationProtocolSSH,
		model.ApplicationProtocolRDP, model.ApplicationProtocolDNS,
		model.ApplicationProtocolTLS:
		return true
	default:
		return false
	}
}

func securityDestinationStatus(status *DestinationStatus, observations model.Observations) (DestinationStatus, bool) {
	security := observations.Security
	if !security.Attempted && !security.HandshakeComplete && security.Applicability != model.ObservationApplicabilityApplicable {
		return DestinationStatus{}, false
	}
	addObservationRefs(status, security.Provenance, security.ProbeNames, security.EvidenceIDs...)
	if security.HandshakeComplete {
		return finishDestinationStatus(*status, DestinationStatusReachable, "TLS handshake succeeded.", model.FailureReasonNone), true
	}
	if security.Attempted || security.HandshakeComplete {
		if observations.Transport.Connected || security.EndpointUsed != nil {
			return finishDestinationStatus(*status, DestinationStatusDegraded, "TLS handshake failed after transport connection.", security.FailureReason), true
		}
		if result, ok := transportDestinationStatus(status, observations); ok {
			return result, true
		}
	}
	return DestinationStatus{}, false
}

func transportDestinationStatus(status *DestinationStatus, observations model.Observations) (DestinationStatus, bool) {
	transport := observations.Transport
	addObservationRefs(status, transport.Provenance, transport.ProbeNames, transport.EvidenceIDs...)
	if transport.Connected || transport.ConnectionOutcome == model.TransportConnectionOutcomeConnected {
		return finishDestinationStatus(*status, DestinationStatusReachable, "Transport connection established.", model.FailureReasonNone), true
	}
	if isConcreteTransportFailure(transport) {
		return finishDestinationStatus(*status, DestinationStatusUnreachable,
			transportFailureDetail(transport), transportFailureReason(transport)), true
	}
	return DestinationStatus{}, false
}

func pathDestinationStatus(status *DestinationStatus, observations model.Observations) (DestinationStatus, bool) {
	for index, path := range observations.Paths {
		if path.Protocol != model.PathProtocolTCP || !path.PortAware {
			continue
		}
		addObservationRefs(status, nil, []string{observationProvenanceAt(observations.PathProvenance, index).ProbeName},
			observationEvidenceIDsAt(observations.PathProvenance, index)...)
		if path.DestinationTCPConnected {
			return finishDestinationStatus(*status, DestinationStatusReachable, "TCP destination connection established.", model.FailureReasonNone), true
		}
		if path.DestinationReached {
			return finishDestinationStatus(*status, DestinationStatusUnreachable,
				"TCP destination responded without establishing a connection.", model.FailureReasonTCPConnectionRefused), true
		}
	}
	for index, flow := range observations.PacketFlows {
		if flow.CaptureStatus != model.PacketCaptureStatusAvailable || flow.Certainty != model.EvidenceCertaintyConfirmedEndpointResponse {
			continue
		}
		addObservationRefs(status, nil, []string{observationProvenanceAt(observations.PacketFlowProvenance, index).ProbeName},
			observationEvidenceIDsAt(observations.PacketFlowProvenance, index)...)
		switch flow.Outcome {
		case model.PacketFlowOutcomeTCPHandshakeConfirmed, model.PacketFlowOutcomeTCPSYNACK:
			return finishDestinationStatus(*status, DestinationStatusReachable, "TCP destination connection established.", model.FailureReasonNone), true
		case model.PacketFlowOutcomeTCPRST:
			return finishDestinationStatus(*status, DestinationStatusUnreachable,
				"TCP destination reset the connection.", model.FailureReasonTCPConnectionReset), true
		}
	}
	return DestinationStatus{}, false
}

func finishDestinationStatus(status DestinationStatus, state DestinationStatusState, detail string, reason model.FailureReason) DestinationStatus {
	status.Status = state
	status.Label = destinationStatusLabel(state)
	status.Detail = detail
	if reason == "" || reason == model.FailureReasonUnknown {
		reason = model.FailureReasonNone
	}
	status.FailureReason = reason
	status.ProbeNames = uniqueDestination(status.ProbeNames)
	status.EvidenceIDs = uniqueDestination(status.EvidenceIDs)
	status.Provenance = uniqueDestination(status.Provenance)
	return status
}

func destinationStatusLabel(state DestinationStatusState) string {
	switch state {
	case DestinationStatusReachable:
		return "Reachable"
	case DestinationStatusUnreachable:
		return "Unreachable"
	case DestinationStatusDegraded:
		return "Degraded"
	default:
		return "Indeterminate"
	}
}

func effectiveDestinationEndpoint(observations model.Observations) *model.Endpoint {
	for _, endpoint := range []*model.Endpoint{
		observations.Application.EndpointUsed,
		observations.Security.EndpointUsed,
		observations.Transport.TestedEndpoint,
		observations.Endpoint.TestedEndpoint,
		observations.Endpoint.SelectedEndpoint,
	} {
		if endpoint == nil {
			continue
		}
		value := *endpoint
		value.EvidenceIDs = append([]string(nil), endpoint.EvidenceIDs...)
		return &value
	}
	return nil
}

func addObservationRefs(status *DestinationStatus, provenance []string, probeNames []string, evidenceIDs ...string) {
	status.Provenance = appendUniqueDestination(status.Provenance, provenance...)
	status.ProbeNames = appendUniqueDestination(status.ProbeNames, probeNames...)
	status.EvidenceIDs = appendUniqueDestination(status.EvidenceIDs, evidenceIDs...)
}

func addNameResolutionRefs(status *DestinationStatus, observation model.NameResolutionObservation) {
	addObservationRefs(status, observation.Provenance, observation.ProbeNames, observation.EvidenceIDs...)
}

func addPathObservationRefs(status *DestinationStatus, observations model.Observations) {
	for index := range observations.Paths {
		provenance := observationProvenanceAt(observations.PathProvenance, index)
		addObservationRefs(status, nil, []string{provenance.ProbeName}, provenance.EvidenceIDs...)
	}
	for index := range observations.PacketFlows {
		provenance := observationProvenanceAt(observations.PacketFlowProvenance, index)
		addObservationRefs(status, nil, []string{provenance.ProbeName}, provenance.EvidenceIDs...)
	}
}

func appendUniqueDestination(values []string, additions ...string) []string {
	for _, value := range additions {
		if value == "" {
			continue
		}
		seen := false
		for _, existing := range values {
			if existing == value {
				seen = true
				break
			}
		}
		if !seen {
			values = append(values, value)
		}
	}
	return values
}

func uniqueDestination(values []string) []string {
	return appendUniqueDestination(nil, values...)
}

func isConcreteTransportFailure(observation model.TransportObservation) bool {
	switch observation.ConnectionOutcome {
	case model.TransportConnectionOutcomeRefused,
		model.TransportConnectionOutcomeReset,
		model.TransportConnectionOutcomeTimeout,
		model.TransportConnectionOutcomeUnreachable,
		model.TransportConnectionOutcomeFailed:
		return true
	}
	switch observation.FailureReason {
	case model.FailureReasonTCPConnectionRefused,
		model.FailureReasonTCPConnectionReset,
		model.FailureReasonTCPTimeout,
		model.FailureReasonNetworkUnreachable:
		return true
	default:
		return false
	}
}

func transportFailureReason(observation model.TransportObservation) model.FailureReason {
	if observation.FailureReason != model.FailureReasonNone && observation.FailureReason != model.FailureReasonUnknown {
		return observation.FailureReason
	}
	switch observation.ConnectionOutcome {
	case model.TransportConnectionOutcomeRefused:
		return model.FailureReasonTCPConnectionRefused
	case model.TransportConnectionOutcomeReset:
		return model.FailureReasonTCPConnectionReset
	case model.TransportConnectionOutcomeTimeout:
		return model.FailureReasonTCPTimeout
	case model.TransportConnectionOutcomeUnreachable:
		return model.FailureReasonNetworkUnreachable
	default:
		return model.FailureReasonUnknown
	}
}

func transportFailureDetail(observation model.TransportObservation) string {
	switch transportFailureReason(observation) {
	case model.FailureReasonTCPConnectionRefused:
		return "TCP connection was refused."
	case model.FailureReasonTCPConnectionReset:
		return "TCP connection was reset."
	case model.FailureReasonNetworkUnreachable:
		return "The network reported the destination as unreachable."
	case model.FailureReasonTCPTimeout:
		return "TCP connection timed out."
	default:
		return "Transport connection failed."
	}
}

func httpSuccessDetail(statusCode int) string {
	if statusCode != 0 {
		return fmt.Sprintf("HTTP returned %d.", statusCode)
	}
	return "HTTP service responded successfully."
}

func observationProvenanceAt(values []model.ObservationProvenance, index int) model.ObservationProvenance {
	if index < 0 || index >= len(values) {
		return model.ObservationProvenance{}
	}
	return values[index]
}

func observationEvidenceIDsAt(values []model.ObservationProvenance, index int) []string {
	return append([]string(nil), observationProvenanceAt(values, index).EvidenceIDs...)
}
