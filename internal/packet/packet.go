package packet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

var (
	// ErrUnsupported is returned when the current platform has no safe packet
	// acquisition implementation.
	ErrUnsupported = errors.New("packet capture is unsupported")
	// ErrInsufficientPrivilege distinguishes a backend that exists from one
	// that cannot be enabled by the current process token.
	ErrInsufficientPrivilege = errors.New("packet capture requires additional privilege")
	// ErrInvalidScope prevents this package from becoming an unrestricted
	// packet-sniffing surface.
	ErrInvalidScope = errors.New("invalid packet capture scope")
)

// ProbeType identifies which active probe owns a bounded capture.
type ProbeType string

const (
	ProbeTypeTCP  ProbeType = "tcp"
	ProbeTypePath ProbeType = "path"
)

// Scope is the mandatory acquisition boundary. Backends must reject a scope
// without an explicit identity and endpoint rather than silently widening it.
type Scope struct {
	Identity      model.ProbeIdentity
	Target        model.Target
	ProbeType     ProbeType
	ProcessID     uint32
	WindowStarted time.Time
	Deadline      time.Time
}

func (scope Scope) validate() error {
	if scope.Identity.SessionID == "" || scope.Identity.ProbeID == "" || scope.Identity.CorrelationID == "" {
		return fmt.Errorf("%w: session, probe, and correlation identity are required", ErrInvalidScope)
	}
	if strings.TrimSpace(scope.Target.RequestedIdentity) == "" || scope.Target.Port == 0 {
		return fmt.Errorf("%w: target identity and port are required", ErrInvalidScope)
	}
	if scope.ProbeType != ProbeTypeTCP && scope.ProbeType != ProbeTypePath {
		return fmt.Errorf("%w: unsupported probe type %q", ErrInvalidScope, scope.ProbeType)
	}
	return nil
}

// Backend starts one bounded, scoped observation session. It is intentionally
// narrower than a packet-sniffer API and has no operation for arbitrary
// interfaces, filters, or persistent capture files.
type Backend interface {
	Start(ctx context.Context, scope Scope) (Capture, error)
}

// Capture stops one bounded observation session and returns structured events.
// Implementations must make Stop idempotent and must not retain packet bytes.
type Capture interface {
	Stop() (CaptureResult, error)
}

// CaptureResult is the finite output of a Capture. Complete is false when a
// cancellation, event loss, or backend failure prevents a negative
// observation from being treated as a bounded no-response result.
type CaptureResult struct {
	Source       string
	Observations []model.PacketObservation
	Complete     bool
	EventsLost   uint64
	Cancelled    bool
	Error        string
}

// CorrelationInput keeps the pure correlation lane independent from packet
// acquisition. StartError and StopError are retained as availability facts;
// they never become an unrelated probe failure.
type CorrelationInput struct {
	Scope        Scope
	Result       model.ProbeResult
	ProbeStarted bool
	Capture      CaptureResult
	StartError   error
	StopError    error
	Cancelled    bool
}

// Correlate applies explicit identity and tuple/path-key matching. Timing is
// used only as the already-bounded capture window; it is never the sole match
// key when a tuple, connection ID, ICMP quote, or correlation ID is present.
func Correlate(input CorrelationInput) model.PacketFlowEvidence {
	scope := input.Scope
	identity := scope.Identity
	if identity.SessionID == "" {
		identity.SessionID = input.Result.SessionID
	}
	if identity.ProbeID == "" {
		identity.ProbeID = input.Result.ProbeID
	}
	if identity.CorrelationID == "" {
		identity.CorrelationID = input.Result.CorrelationID
	}
	scope.Identity = identity
	if scope.Target.OriginalInput == "" && scope.Target.RequestedIdentity == "" && scope.Target.Port == 0 {
		scope.Target = input.Result.Target
	}
	scope.Target = model.NormalizeTarget(scope.Target)

	flow := model.PacketFlowEvidence{
		SessionID:         identity.SessionID,
		ProbeID:           identity.ProbeID,
		CorrelationID:     identity.CorrelationID,
		Target:            scope.Target,
		CaptureStatus:     captureStatus(input),
		CaptureSource:     input.Capture.Source,
		WindowStartedAt:   windowStart(scope, input.Result),
		WindowCompletedAt: windowEnd(scope, input.Result),
		ProbeEmission:     model.PacketEmissionUnknown,
		Outcome:           model.PacketFlowOutcomeCaptureUnavailable,
		Certainty:         model.EvidenceCertaintyUnobservableSegment,
	}
	if flow.CaptureSource == "" {
		flow.CaptureSource = "scoped-packet-backend"
	}
	if input.StartError != nil {
		flow.CaptureError = input.StartError.Error()
	}
	if input.StopError != nil {
		flow.CaptureError = input.StopError.Error()
	}
	if input.Capture.Error != "" && flow.CaptureError == "" {
		flow.CaptureError = input.Capture.Error
	}
	flow.EventsLost = input.Capture.EventsLost

	if flow.CaptureStatus == model.PacketCaptureStatusCancelled || input.Cancelled || input.Capture.Cancelled {
		flow.Outcome = model.PacketFlowOutcomeCancelled
		return flow
	}
	if flow.CaptureStatus != model.PacketCaptureStatusAvailable {
		return flow
	}

	tuple := tcpTupleFromResult(input.Result)
	if tuple.LocalAddress != "" {
		flow.LocalAddress = tuple.LocalAddress
		flow.LocalPort = tuple.LocalPort
	}
	observations := relevantObservations(input.Capture.Observations, scope, tuple, flow.WindowStartedAt, flow.WindowCompletedAt)
	flow.Observations = observations

	if scope.ProbeType == ProbeTypePath {
		correlatePath(&flow, observations, scope)
	} else {
		correlateTCP(&flow, observations, tuple, scope)
	}
	if flow.ProbeEmission == model.PacketEmissionUnknown && input.ProbeStarted && input.Capture.Complete && canClassifyProbeNotEmitted(scope, tuple, input.Result) {
		flow.ProbeEmission = model.PacketEmissionNotObserved
		flow.Outcome = model.PacketFlowOutcomeProbeNotEmitted
	}
	return flow
}

func canClassifyProbeNotEmitted(scope Scope, tuple tcpTuple, result model.ProbeResult) bool {
	if scope.ProbeType == ProbeTypePath {
		// A path adapter can be unsupported before it sends anything. A
		// completed path observation, including one with unobservable hops,
		// is the bounded case in which absence of an emitted echo is useful.
		return result.Status == model.ProbeStatusPassed
	}
	if tuple.RemoteAddress != "" {
		return true
	}
	// With a hostname and no resolved endpoint tuple, the capture cannot
	// separate this dial from another same-process flow. Keep emission
	// unknown rather than promoting an incomplete match to a local finding.
	_, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(scope.Target.LiteralIP), "[]"))
	return err == nil
}

func captureStatus(input CorrelationInput) model.PacketCaptureStatus {
	if input.Cancelled || input.Capture.Cancelled {
		return model.PacketCaptureStatusCancelled
	}
	if input.StartError != nil {
		if errors.Is(input.StartError, ErrInsufficientPrivilege) {
			return model.PacketCaptureStatusInsufficientPrivilege
		}
		if errors.Is(input.StartError, ErrUnsupported) {
			return model.PacketCaptureStatusUnsupported
		}
		return model.PacketCaptureStatusError
	}
	if input.StopError != nil {
		if errors.Is(input.StopError, ErrInsufficientPrivilege) {
			return model.PacketCaptureStatusInsufficientPrivilege
		}
		return model.PacketCaptureStatusError
	}
	if input.Capture.Error != "" {
		return model.PacketCaptureStatusError
	}
	if input.Capture.EventsLost != 0 {
		return model.PacketCaptureStatusPartial
	}
	if !input.Capture.Complete {
		return model.PacketCaptureStatusError
	}
	return model.PacketCaptureStatusAvailable
}

func windowStart(scope Scope, result model.ProbeResult) time.Time {
	if !scope.WindowStarted.IsZero() {
		return scope.WindowStarted.UTC()
	}
	if result.Timing.StartedAt != nil {
		return result.Timing.StartedAt.UTC()
	}
	return time.Time{}
}

func windowEnd(scope Scope, result model.ProbeResult) time.Time {
	if !scope.Deadline.IsZero() {
		return scope.Deadline.UTC()
	}
	if result.Timing.CompletedAt != nil {
		return result.Timing.CompletedAt.UTC()
	}
	return time.Time{}
}

type tcpTuple struct {
	LocalAddress  string
	LocalPort     uint16
	RemoteAddress string
	RemotePort    uint16
}

func tcpTupleFromResult(result model.ProbeResult) tcpTuple {
	for _, evidence := range result.Evidence {
		if evidence.Kind != model.EvidenceKindTCPConnection {
			continue
		}
		var value struct {
			LocalEndpoint  string `json:"local_endpoint"`
			RemoteEndpoint string `json:"remote_endpoint"`
		}
		if json.Unmarshal(evidence.Raw, &value) != nil {
			continue
		}
		localAddress, localPort := splitEndpoint(value.LocalEndpoint)
		remoteAddress, remotePort := splitEndpoint(value.RemoteEndpoint)
		if localAddress != "" || remoteAddress != "" {
			return tcpTuple{LocalAddress: localAddress, LocalPort: localPort, RemoteAddress: remoteAddress, RemotePort: remotePort}
		}
	}
	return tcpTuple{}
}

func splitEndpoint(value string) (string, uint16) {
	if value == "" {
		return "", 0
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return normalizeAddress(value), 0
	}
	var parsed uint64
	for _, character := range port {
		if character < '0' || character > '9' {
			return normalizeAddress(host), 0
		}
		parsed = parsed*10 + uint64(character-'0')
		if parsed > 65535 {
			return normalizeAddress(host), 0
		}
	}
	return normalizeAddress(host), uint16(parsed)
}

func relevantObservations(input []model.PacketObservation, scope Scope, tuple tcpTuple, start, end time.Time) []model.PacketObservation {
	result := make([]model.PacketObservation, 0, len(input))
	for _, raw := range input {
		observation := model.NormalizePacketObservation(raw)
		if !identityMatches(observation, scope.Identity) || !processMatches(observation, scope.ProcessID) || !withinWindow(observation.ObservedAt, start, end) {
			continue
		}
		if scope.ProbeType == ProbeTypeTCP {
			if !tcpTargetMatches(observation, scope.Target, tuple) {
				continue
			}
		} else if !pathTargetMatches(observation, scope.Target) {
			continue
		}
		result = append(result, observation)
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if !left.ObservedAt.Equal(right.ObservedAt) {
			if left.ObservedAt.IsZero() {
				return false
			}
			if right.ObservedAt.IsZero() {
				return true
			}
			return left.ObservedAt.Before(right.ObservedAt)
		}
		return left.ID < right.ID
	})
	for index := range result {
		if result[index].ID == "" {
			result[index].ID = fmt.Sprintf("%s/observation-%03d", scope.Identity.CorrelationID, index+1)
		}
	}
	return result
}

func identityMatches(observation model.PacketObservation, identity model.ProbeIdentity) bool {
	if observation.SessionID != "" && identity.SessionID != "" && observation.SessionID != identity.SessionID {
		return false
	}
	if observation.ProbeID != "" && identity.ProbeID != "" && observation.ProbeID != identity.ProbeID {
		return false
	}
	if observation.CorrelationID != "" && identity.CorrelationID != "" && observation.CorrelationID != identity.CorrelationID {
		return false
	}
	return true
}

func processMatches(observation model.PacketObservation, processID uint32) bool {
	return processID == 0 || observation.ProcessID == 0 || observation.ProcessID == processID
}

func withinWindow(observed, start, end time.Time) bool {
	if observed.IsZero() {
		return true
	}
	if !start.IsZero() && observed.Before(start) {
		return false
	}
	if !end.IsZero() && observed.After(end) {
		return false
	}
	return true
}

func tcpTargetMatches(observation model.PacketObservation, target model.Target, tuple tcpTuple) bool {
	observation = model.NormalizePacketObservation(observation)
	remote := tuple.RemoteAddress
	if remote == "" {
		if target.SelectedEndpoint != nil {
			remote = normalizeAddress(target.SelectedEndpoint.Address)
		} else {
			remote = normalizeAddress(target.LiteralIP)
		}
	}
	if tuple.LocalPort != 0 {
		localPort := observation.LocalPort
		if localPort == 0 {
			if observation.Direction == model.PacketDirectionInbound {
				localPort = observation.DestinationPort
			} else {
				localPort = observation.SourcePort
			}
		}
		if localPort != tuple.LocalPort {
			return false
		}
	}
	if tuple.LocalAddress != "" {
		localAddress := observation.LocalAddress
		if localAddress == "" {
			if observation.Direction == model.PacketDirectionInbound {
				localAddress = observation.DestinationAddress
			} else {
				localAddress = observation.SourceAddress
			}
		}
		if normalizeAddress(localAddress) != normalizeAddress(tuple.LocalAddress) {
			return false
		}
	}
	if target.Port != 0 && observation.Kind != model.PacketObservationOutboundICMPEcho {
		if observation.Kind == model.PacketObservationOutboundTCPSYN || observation.Direction == model.PacketDirectionOutbound {
			if observation.DestinationPort != target.Port {
				return false
			}
		} else if observation.SourcePort != target.Port && observation.DestinationPort != target.Port {
			return false
		}
	}
	if remote == "" {
		return true
	}
	addresses := []string{observation.SourceAddress, observation.DestinationAddress}
	for _, address := range addresses {
		if normalizeAddress(address) == remote || target.MatchesAddress(address) {
			return true
		}
	}
	return false
}

func pathTargetMatches(observation model.PacketObservation, target model.Target) bool {
	expected := normalizeAddress(target.LiteralIP)
	if expected == "" && target.SelectedEndpoint != nil {
		expected = normalizeAddress(target.SelectedEndpoint.Address)
	}
	if expected == "" && target.LiteralIP == "" {
		// A hostname can still be matched by the identity-aware helper below;
		// packet correlation remains conservative when no concrete address is
		// available.
		expected = normalizeAddress(target.RequestedIdentity)
	}
	if expected == "" {
		return false
	}
	for _, address := range []string{
		observation.SourceAddress,
		observation.DestinationAddress,
		observation.QuotedSourceAddress,
		observation.QuotedDestinationAddress,
	} {
		if normalizeAddress(address) == expected || target.MatchesAddress(address) {
			return true
		}
	}
	return false
}

func correlateTCP(flow *model.PacketFlowEvidence, observations []model.PacketObservation, tuple tcpTuple, scope Scope) {
	emissions := filterKind(observations, model.PacketObservationOutboundTCPSYN)
	if tuple.LocalPort != 0 {
		emissions = filterPort(emissions, tuple.LocalPort)
	}
	if len(emissions) == 0 {
		return
	}
	flow.ProbeEmission = model.PacketEmissionObserved
	responses := make([]model.PacketObservation, 0)
	for _, observation := range observations {
		if !isTCPResponse(observation) || observation.Direction != model.PacketDirectionInbound {
			continue
		}
		for _, emission := range emissions {
			if tcpPair(emission, observation) {
				responses = append(responses, observation)
				flow.MatchedObservationIDs = append(flow.MatchedObservationIDs, emission.ID, observation.ID)
				break
			}
		}
	}
	if len(responses) == 0 {
		flow.Outcome = model.PacketFlowOutcomeNoMatchingResponse
		flow.Certainty = model.EvidenceCertaintyUnobservableSegment
		if correlationIDIsExplicit(emissions) {
			flow.CorrelationMethod = "correlation_id_and_tcp_tuple"
		} else if identityIsExplicit(emissions) {
			flow.CorrelationMethod = "probe_identity_and_tcp_tuple"
		} else {
			flow.CorrelationMethod = "process_and_tcp_tuple"
		}
		return
	}
	selected := responses[0]
	switch selected.Kind {
	case model.PacketObservationInboundTCPSYNACK:
		flow.Outcome = model.PacketFlowOutcomeTCPSYNACK
		flow.Certainty = model.EvidenceCertaintyConfirmedEndpointResponse
	case model.PacketObservationTCPHandshakeConfirmed:
		flow.Outcome = model.PacketFlowOutcomeTCPHandshakeConfirmed
		flow.Certainty = model.EvidenceCertaintyConfirmedEndpointResponse
	default:
		flow.Outcome = model.PacketFlowOutcomeTCPRST
		flow.Certainty = model.EvidenceCertaintyConfirmedEndpointResponse
	}
	if correlationIDIsExplicit(emissions) {
		flow.CorrelationMethod = "correlation_id_and_tcp_tuple"
	} else if identityIsExplicit(emissions) {
		flow.CorrelationMethod = "probe_identity_and_tcp_tuple"
	} else {
		flow.CorrelationMethod = "process_and_tcp_tuple"
	}
	flow.MatchedObservationIDs = uniqueSorted(flow.MatchedObservationIDs)
	_ = scope
}

func correlatePath(flow *model.PacketFlowEvidence, observations []model.PacketObservation, scope Scope) {
	emissions := make([]model.PacketObservation, 0)
	for _, observation := range observations {
		if observation.Kind == model.PacketObservationOutboundICMPEcho {
			emissions = append(emissions, observation)
		}
	}
	if len(emissions) == 0 {
		return
	}
	flow.ProbeEmission = model.PacketEmissionObserved
	responses := make([]model.PacketObservation, 0)
	for _, observation := range observations {
		if observation.Kind != model.PacketObservationInboundICMPEcho && observation.Kind != model.PacketObservationICMPTimeExceeded && observation.Kind != model.PacketObservationICMPUnreachable {
			continue
		}
		for _, emission := range emissions {
			if pathPair(emission, observation, len(emissions), observations) {
				responses = append(responses, observation)
				flow.MatchedObservationIDs = append(flow.MatchedObservationIDs, emission.ID, observation.ID)
				break
			}
		}
	}
	if len(responses) == 0 {
		flow.Outcome = model.PacketFlowOutcomeNoMatchingResponse
		flow.Certainty = model.EvidenceCertaintyUnobservableSegment
		return
	}
	selected := responses[0]
	if selected.Kind == model.PacketObservationInboundICMPEcho {
		flow.Outcome = model.PacketFlowOutcomeICMPEchoReply
	} else if selected.Kind == model.PacketObservationICMPTimeExceeded {
		flow.Outcome = model.PacketFlowOutcomeICMPTimeExceeded
	} else {
		flow.Outcome = model.PacketFlowOutcomeICMPUnreachable
	}
	flow.Certainty = model.EvidenceCertaintyObservedTTLResponder
	if selected.Kind == model.PacketObservationInboundICMPEcho {
		flow.Certainty = model.EvidenceCertaintyConfirmedEndpointResponse
	}
	if selected.ICMPSequence != 0 || selected.ICMPIdentifier != 0 || selected.ProbeTTL != 0 || selected.QuotedICMPSequence != 0 || selected.QuotedICMPIdentifier != 0 {
		if correlationIDIsExplicit(emissions) {
			flow.CorrelationMethod = "correlation_id_and_path_key"
		} else if identityIsExplicit(emissions) {
			flow.CorrelationMethod = "probe_identity_and_path_key"
		} else {
			flow.CorrelationMethod = "path_key"
		}
	} else if len(emissions) == 1 && len(responses) == 1 {
		if correlationIDIsExplicit(emissions) {
			flow.CorrelationMethod = "correlation_id_and_unique_path_tuple"
		} else if identityIsExplicit(emissions) {
			flow.CorrelationMethod = "probe_identity_and_unique_path_tuple"
		} else {
			flow.CorrelationMethod = "unique_path_tuple"
		}
	} else {
		flow.Outcome = model.PacketFlowOutcomeNoMatchingResponse
		flow.MatchedObservationIDs = nil
		flow.Certainty = model.EvidenceCertaintyUnobservableSegment
		return
	}
	flow.MatchedObservationIDs = uniqueSorted(flow.MatchedObservationIDs)
	_ = scope
}

func filterKind(observations []model.PacketObservation, kind model.PacketObservationKind) []model.PacketObservation {
	result := make([]model.PacketObservation, 0)
	for _, observation := range observations {
		if observation.Kind == kind {
			result = append(result, observation)
		}
	}
	return result
}

func filterPort(observations []model.PacketObservation, port uint16) []model.PacketObservation {
	result := make([]model.PacketObservation, 0, len(observations))
	for _, observation := range observations {
		if observation.SourcePort == port || observation.LocalPort == port {
			result = append(result, observation)
		}
	}
	return result
}

func isTCPResponse(observation model.PacketObservation) bool {
	return observation.Kind == model.PacketObservationInboundTCPSYNACK ||
		observation.Kind == model.PacketObservationTCPRST ||
		observation.Kind == model.PacketObservationTCPHandshakeConfirmed
}

func tcpPair(emission, response model.PacketObservation) bool {
	if emission.ConnectionID != "" && response.ConnectionID != "" {
		if emission.ConnectionID != response.ConnectionID {
			return false
		}
	}
	if emission.SourcePort != 0 && response.DestinationPort != 0 && emission.SourcePort != response.DestinationPort {
		return false
	}
	if emission.DestinationPort != 0 && response.SourcePort != 0 && emission.DestinationPort != response.SourcePort {
		return false
	}
	if emission.SourceAddress != "" && response.DestinationAddress != "" && normalizeAddress(emission.SourceAddress) != normalizeAddress(response.DestinationAddress) {
		return false
	}
	if emission.DestinationAddress != "" && response.SourceAddress != "" && normalizeAddress(emission.DestinationAddress) != normalizeAddress(response.SourceAddress) {
		return false
	}
	return true
}

func pathPair(emission, response model.PacketObservation, emissionCount int, observations []model.PacketObservation) bool {
	correlationMatches := response.CorrelationID != "" && emission.CorrelationID != "" && response.CorrelationID == emission.CorrelationID
	if response.CorrelationID != "" && emission.CorrelationID != "" {
		if !correlationMatches {
			return false
		}
	}
	strongKey := false
	if response.ICMPIdentifier != 0 && emission.ICMPIdentifier != 0 && response.ICMPIdentifier != emission.ICMPIdentifier {
		return false
	}
	if response.ICMPIdentifier != 0 && emission.ICMPIdentifier != 0 {
		strongKey = true
	}
	if response.ICMPSequence != 0 && emission.ICMPSequence != 0 && response.ICMPSequence != emission.ICMPSequence {
		return false
	}
	if response.ICMPSequence != 0 && emission.ICMPSequence != 0 {
		strongKey = true
	}
	if response.QuotedICMPIdentifier != 0 && emission.ICMPIdentifier != 0 && response.QuotedICMPIdentifier != emission.ICMPIdentifier {
		return false
	}
	if response.QuotedICMPIdentifier != 0 && emission.ICMPIdentifier != 0 {
		strongKey = true
	}
	if response.QuotedICMPSequence != 0 && emission.ICMPSequence != 0 && response.QuotedICMPSequence != emission.ICMPSequence {
		return false
	}
	if response.QuotedICMPSequence != 0 && emission.ICMPSequence != 0 {
		strongKey = true
	}
	if response.ProbeTTL != 0 && emission.ProbeTTL != 0 && response.ProbeTTL != emission.ProbeTTL {
		return false
	}
	if response.ProbeTTL != 0 && emission.ProbeTTL != 0 {
		strongKey = true
	}
	if response.ProbeAttempt != 0 && emission.ProbeAttempt != 0 && response.ProbeAttempt != emission.ProbeAttempt {
		return false
	}
	if response.ProbeAttempt != 0 && emission.ProbeAttempt != 0 {
		strongKey = true
	}
	if response.QuotedDestinationAddress != "" && emission.DestinationAddress != "" && normalizeAddress(response.QuotedDestinationAddress) != normalizeAddress(emission.DestinationAddress) {
		return false
	}
	if response.QuotedDestinationPort != 0 && emission.DestinationPort != 0 && response.QuotedDestinationPort != emission.DestinationPort {
		return false
	}
	if strongKey {
		return true
	}
	if correlationMatches {
		matchingCorrelationEmissions := 0
		for _, candidate := range observations {
			if candidate.Kind == model.PacketObservationOutboundICMPEcho && candidate.CorrelationID == response.CorrelationID {
				matchingCorrelationEmissions++
			}
		}
		if matchingCorrelationEmissions == 1 {
			return true
		}
	}
	// A target/protocol match is acceptable only for a unique bounded path
	// request. It is not used to choose among multiple TTL attempts.
	return emissionCount == 1 && len(observations) <= 2
}

func identityIsExplicit(observations []model.PacketObservation) bool {
	for _, observation := range observations {
		if observation.ProbeID != "" || observation.SessionID != "" {
			return true
		}
	}
	return false
}

func correlationIDIsExplicit(observations []model.PacketObservation) bool {
	for _, observation := range observations {
		if observation.CorrelationID != "" {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func normalizeAddress(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if address, err := netip.ParseAddr(value); err == nil {
		return model.NormalizeAddr(address).String()
	}
	return strings.ToLower(value)
}
