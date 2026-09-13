package path

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	// PathProbeName is the stable report name for the combined path lane.
	PathProbeName = "path"
	// DefaultTimeout bounds the complete path lane, including all protocol
	// attempts and TTLs.
	DefaultTimeout = 5 * time.Second
	// DefaultMaxTTL keeps an accidental path invocation bounded while still
	// covering normal small and medium-sized routes.
	DefaultMaxTTL uint8 = 16
	// DefaultAttempts is enough to retain common load-balanced responders
	// without turning path observation into an unbounded scan.
	DefaultAttempts       = 2
	maxConfiguredTTL      = 64
	maxConfiguredAttempts = 8
)

const (
	FailureReasonPathObservation  = model.FailureReasonPathObservation
	FailureReasonPathCancellation = model.FailureReasonPathCancellation
)

// Protocol aliases keep protocol selection discoverable from the path
// package while the canonical values remain owned by model.
const (
	ProtocolICMP = model.PathProtocolICMP
	ProtocolTCP  = model.PathProtocolTCP
)

// ErrUnsupported indicates that the selected native path method is not
// available, commonly because raw sockets are unavailable to the process.
var ErrUnsupported = errors.New("native path observation is unsupported")

// Request describes one bounded observation at one TTL. Attempt is zero
// based and exists to let native and fixture observers correlate probes.
type Request struct {
	Target        model.Target
	Protocol      model.PathProtocol
	TTL           uint8
	Attempt       int
	Timeout       time.Duration
	SessionID     string
	ProbeID       string
	CorrelationID string
}

// Observation is the result of one TTL attempt. An empty observation is a
// valid no-response result and is intentionally different from an error.
type Observation struct {
	Responders         []model.PathResponder
	DestinationReached bool
}

// TTLObservation is a descriptive alias for Observation.
type TTLObservation = Observation

// ObservationRequest is a descriptive alias for Request.
type ObservationRequest = Request

// Observer supplies one protocol/TTL observation. It is the seam for native
// platform adapters and deterministic offline tests.
type Observer interface {
	Observe(context.Context, Request) (Observation, error)
}

// ObserverFunc adapts a function into Observer.
type ObserverFunc func(context.Context, Request) (Observation, error)

// Observe implements Observer.
func (f ObserverFunc) Observe(ctx context.Context, request Request) (Observation, error) {
	return f(ctx, request)
}

// Config controls a Probe. A zero value selects bounded defaults. Protocols
// are attempted in the supplied order, then rendered in deterministic order.
type Config struct {
	Timeout   time.Duration
	MaxTTL    uint8
	Attempts  int
	Protocols []model.PathProtocol
	Observer  Observer
	Now       func() time.Time
}

// Probe performs one combined ICMP/TCP path observation.
type Probe struct {
	Timeout   time.Duration
	MaxTTL    uint8
	Attempts  int
	Protocols []model.PathProtocol
	Observer  Observer
	Now       func() time.Time
}

var _ probe.Probe = (*Probe)(nil)

// New constructs a path probe. A supplied config is copied, including the
// protocol slice, so later caller mutation cannot alter the probe.
func New(config ...Config) *Probe {
	p := &Probe{}
	if len(config) != 0 {
		p.Timeout = config[0].Timeout
		p.MaxTTL = config[0].MaxTTL
		p.Attempts = config[0].Attempts
		p.Protocols = append([]model.PathProtocol(nil), config[0].Protocols...)
		p.Observer = config[0].Observer
		p.Now = config[0].Now
	}
	p.normalize()
	return p
}

// NewProbe is a descriptive constructor alias.
func NewProbe(config ...Config) *Probe { return New(config...) }

// NewWithConfig constructs a path probe from config.
func NewWithConfig(config Config) *Probe { return New(config) }

// NewWithObserver constructs a path probe with an injected observer.
func NewWithObserver(observer Observer, config ...Config) *Probe {
	if len(config) == 0 {
		return New(Config{Observer: observer})
	}
	config[0].Observer = observer
	return New(config[0])
}

// RunTarget is a convenience one-shot operation for callers that do not need
// to retain a Probe value.
func RunTarget(ctx context.Context, target model.Target, config ...Config) model.ProbeResult {
	return New(config...).Run(ctx, probe.ExecutionContext{Target: target})
}

// Name implements probe.Probe.
func (*Probe) Name() string { return PathProbeName }

// Run performs a bounded path observation for each configured protocol. A
// valid measurement with unobservable TTLs is a passed probe result: it is
// evidence about observability, not a packet-loss counter.
func (p *Probe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	if p == nil {
		p = New()
	}
	p.normalize()
	if ctx == nil {
		ctx = context.Background()
	}

	started := p.clockNow().UTC()
	result := model.ProbeResult{
		Name:          PathProbeName,
		Target:        model.NormalizeTarget(execution.Target),
		SessionID:     execution.SessionID,
		ProbeID:       execution.ProbeID,
		CorrelationID: execution.CorrelationID,
		Status:        model.ProbeStatusError,
		Timing:        model.Timing{StartedAt: &started},
		Interpretation: model.ProbeInterpretation{
			FailureReason: FailureReasonPathObservation,
			Layer:         model.LayerNetwork,
			FaultDomain:   model.FaultDomainNetwork,
		},
	}

	if err := validateTarget(result.Target); err != nil {
		return p.finish(result, started, err)
	}
	if err := ctx.Err(); err != nil {
		return p.finish(result, started, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	observer := p.Observer
	if observer == nil {
		observer = nativeObserver{}
	}

	observations := make([]model.PathObservation, 0, len(p.Protocols))
	protocolResults := make(chan protocolResult, len(p.Protocols))
	var wg sync.WaitGroup
	wg.Add(len(p.Protocols))
	for index, protocol := range p.Protocols {
		index, protocol := index, protocol
		go func() {
			defer wg.Done()
			observation, err := p.observeProtocol(runCtx, observer, execution, result.Target, protocol)
			protocolResults <- protocolResult{index: index, observation: observation, err: err}
		}()
	}
	wg.Wait()
	close(protocolResults)
	orderedResults := make([]protocolResult, len(p.Protocols))
	for value := range protocolResults {
		orderedResults[value.index] = value
	}
	for _, value := range orderedResults {
		observations = append(observations, value.observation)
	}
	sort.SliceStable(observations, func(i, j int) bool {
		return observations[i].Protocol < observations[j].Protocol
	})
	validCount := 0
	unsupportedCount := 0
	var firstErr error
	for _, observation := range observations {
		if observation.Status == model.PathObservationStatusObserved {
			validCount++
		}
		if observation.Status == model.PathObservationStatusUnsupported {
			unsupportedCount++
		}
	}
	for _, value := range orderedResults {
		if value.err != nil && firstErr == nil {
			firstErr = value.err
		}
	}

	for _, observation := range observations {
		result.Evidence = append(result.Evidence, pathEvidence(observation, p.clockNow()))
	}

	if validCount > 0 {
		result.Status = model.ProbeStatusPassed
		result.Interpretation = model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         pathLayer(observations),
			FaultDomain:   pathDomain(observations),
		}
	} else if unsupportedCount == len(observations) && len(observations) > 0 {
		result.Interpretation = model.ProbeInterpretation{
			FailureReason: model.FailureReasonUnsupported,
			Layer:         pathLayer(observations),
			FaultDomain:   pathDomain(observations),
		}
	} else if err := runCtx.Err(); err != nil {
		result.Interpretation = model.ProbeInterpretation{
			FailureReason: FailureReasonPathCancellation,
			Layer:         model.LayerNetwork,
			FaultDomain:   model.FaultDomainNetwork,
		}
	} else if firstErr != nil {
		result.Interpretation = failedPathInterpretation(observations)
	}

	completed := p.clockNow().UTC()
	result.Timing.CompletedAt = &completed
	result.Timing.DurationMS = nonNegativeDuration(completed.Sub(started)).Milliseconds()
	return result
}

type protocolResult struct {
	index       int
	observation model.PathObservation
	err         error
}

func failedPathInterpretation(observations []model.PathObservation) model.ProbeInterpretation {
	if len(observations) != 0 {
		allICMP := true
		anyError := false
		for _, observation := range observations {
			allICMP = allICMP && observation.Protocol == model.PathProtocolICMP
			anyError = anyError || observation.Status == model.PathObservationStatusError
		}
		if allICMP && anyError {
			// ICMP operational failure is evidence about ICMP observability
			// only. It must not become an application or generic network
			// connectivity conclusion.
			return model.ProbeInterpretation{
				FailureReason: model.FailureReasonICMPFailure,
				Layer:         model.LayerICMP,
				FaultDomain:   model.FaultDomainICMP,
			}
		}
	}
	return model.ProbeInterpretation{
		FailureReason: FailureReasonPathObservation,
		Layer:         model.LayerNetwork,
		FaultDomain:   model.FaultDomainNetwork,
	}
}

func (p *Probe) observeProtocol(ctx context.Context, observer Observer, execution probe.ExecutionContext, target model.Target, protocol model.PathProtocol) (model.PathObservation, error) {
	destination, _, _ := normalizeDestinationAddress(target.RequestedIdentity)
	observation := model.PathObservation{
		Status:          model.PathObservationStatusObserved,
		Protocol:        protocol,
		Destination:     destination,
		DestinationPort: target.Port,
		PortAware:       protocol == model.PathProtocolTCP,
		MaxTTL:          p.MaxTTL,
		AttemptsPerTTL:  p.Attempts,
		Hops:            make([]model.PathHop, 0, p.MaxTTL),
		Segments:        []model.PathSegment{},
	}
	if protocol != model.PathProtocolICMP && protocol != model.PathProtocolTCP {
		observation.Status = model.PathObservationStatusError
		observation.Error = fmt.Sprintf("unsupported path protocol %q", protocol)
		return observation, errors.New(observation.Error)
	}

	for ttlNumber := 1; ttlNumber <= int(p.MaxTTL); ttlNumber++ {
		ttl := uint8(ttlNumber)
		hop := model.PathHop{TTL: ttl, State: model.PathHopStateUnobservable, Attempts: p.Attempts}
		for attempt := 0; attempt < p.Attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				observation.Status = model.PathObservationStatusError
				observation.Error = err.Error()
				observation.ErrorType = fmt.Sprintf("%T", err)
				observation.Hops = append(observation.Hops, hop)
				observation.Segments = buildSegments(observation.Hops)
				return observation, err
			}
			attemptCtx, cancel := attemptContext(ctx, p.remainingAttempts(ttl, attempt))
			response, err := observeAttemptBounded(attemptCtx, observer, Request{
				Target: target, Protocol: protocol, TTL: ttl, Attempt: attempt, Timeout: contextTimeout(attemptCtx),
				SessionID: execution.SessionID, ProbeID: execution.ProbeID, CorrelationID: execution.CorrelationID,
			})
			cancel()
			if err != nil {
				if errors.Is(err, ErrUnsupported) || isUnsupportedError(err) {
					observation.Status = model.PathObservationStatusUnsupported
					observation.Error = err.Error()
					observation.ErrorType = fmt.Sprintf("%T", err)
					return observation, err
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					if ctx.Err() != nil {
						observation.Status = model.PathObservationStatusError
						observation.Error = ctx.Err().Error()
						observation.ErrorType = fmt.Sprintf("%T", ctx.Err())
						observation.Hops = append(observation.Hops, hop)
						observation.Segments = buildSegments(observation.Hops)
						return observation, ctx.Err()
					}
					// A bounded attempt with no response is an unobservable hop.
					continue
				}
				observation.Status = model.PathObservationStatusError
				observation.Error = err.Error()
				observation.ErrorType = fmt.Sprintf("%T", err)
				observation.Hops = append(observation.Hops, hop)
				observation.Segments = buildSegments(observation.Hops)
				return observation, err
			}

			for _, responder := range response.Responders {
				responder = model.NormalizePathResponder(responder)
				if responder.Address == "" {
					continue
				}
				if response.DestinationReached {
					responder.DestinationReached = true
				}
				hop.Responders = mergeResponder(hop.Responders, responder)
			}
			if response.DestinationReached {
				if protocol == model.PathProtocolTCP && tcpConnected(response) {
					observation.DestinationTCPConnected = true
				}
				if len(hop.Responders) == 0 {
					hop.Responders = append(hop.Responders, model.PathResponder{
						Address: destination, DestinationReached: true,
					})
				}
				observation.DestinationReached = true
			}
		}
		if len(hop.Responders) > 0 {
			hop.State = model.PathHopStateObserved
			sort.SliceStable(hop.Responders, func(i, j int) bool { return hop.Responders[i].Address < hop.Responders[j].Address })
		}
		observation.Hops = append(observation.Hops, hop)
		if observation.DestinationReached {
			break
		}
	}
	observation.Segments = buildSegments(observation.Hops)
	return observation, nil
}

// observeAttemptBounded protects the path lane from a platform adapter that
// fails to return promptly after cancellation. The result channel is buffered
// so a late adapter return cannot strand its goroutine on the reporting path.
func observeAttemptBounded(ctx context.Context, observer Observer, request Request) (Observation, error) {
	type outcome struct {
		observation Observation
		err         error
	}
	result := make(chan outcome, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				result <- outcome{err: fmt.Errorf("path observer panic: %v", recovered)}
			}
		}()
		observation, err := observer.Observe(ctx, request)
		result <- outcome{observation: observation, err: err}
	}()
	select {
	case value := <-result:
		return value.observation, value.err
	case <-ctx.Done():
		return Observation{}, ctx.Err()
	}
}

func tcpConnected(response Observation) bool {
	if !response.DestinationReached {
		return false
	}
	if len(response.Responders) == 0 {
		return true
	}
	for _, responder := range response.Responders {
		if responder.Response != "tcp_refused" && responder.Response != "tcp_reset" {
			return true
		}
	}
	return false
}

func (p *Probe) remainingAttempts(ttl uint8, attempt int) int {
	remainingTTL := int(p.MaxTTL) - int(ttl) + 1
	remaining := remainingTTL*p.Attempts - attempt
	if remaining < 1 {
		return 1
	}
	return remaining
}

func attemptContext(parent context.Context, remaining int) (context.Context, context.CancelFunc) {
	if deadline, ok := parent.Deadline(); ok {
		remainingDuration := time.Until(deadline)
		if remainingDuration <= 0 {
			return context.WithTimeout(parent, time.Nanosecond)
		}
		perAttempt := remainingDuration / time.Duration(remaining)
		if perAttempt <= 0 {
			perAttempt = time.Nanosecond
		}
		return context.WithTimeout(parent, perAttempt)
	}
	return context.WithTimeout(parent, DefaultTimeout/time.Duration(remaining))
}

func contextTimeout(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return remaining
		}
	}
	return time.Nanosecond
}

func buildSegments(hops []model.PathHop) []model.PathSegment {
	segments := make([]model.PathSegment, 0, len(hops))
	for index := 0; index < len(hops); {
		hop := hops[index]
		if hop.State == model.PathHopStateObserved && len(hop.Responders) > 0 {
			segments = append(segments, model.PathSegment{
				Kind: model.PathSegmentObservedResponder, FromTTL: hop.TTL, ToTTL: hop.TTL,
				Responders: append([]model.PathResponder(nil), hop.Responders...),
			})
			index++
			continue
		}
		start := hop.TTL
		end := hop.TTL
		for index+1 < len(hops) && (hops[index+1].State != model.PathHopStateObserved || len(hops[index+1].Responders) == 0) {
			index++
			end = hops[index].TTL
		}
		segments = append(segments, model.PathSegment{Kind: model.PathSegmentUnobservable, FromTTL: start, ToTTL: end})
		index++
	}

	// An inferred segment is a bounded statement about the observed TTL
	// progression. It is deliberately separate from unobservable TTL ranges,
	// and does not name a physical hop or link.
	observed := make([]model.PathHop, 0)
	for _, hop := range hops {
		if hop.State == model.PathHopStateObserved && len(hop.Responders) > 0 {
			observed = append(observed, hop)
		}
	}
	for index := 1; index < len(observed); index++ {
		if observed[index].TTL-observed[index-1].TTL <= 1 {
			continue
		}
		segments = append(segments, model.PathSegment{
			Kind:    model.PathSegmentInferred,
			FromTTL: observed[index-1].TTL,
			ToTTL:   observed[index].TTL,
		})
	}
	sort.SliceStable(segments, func(i, j int) bool {
		if segments[i].FromTTL != segments[j].FromTTL {
			return segments[i].FromTTL < segments[j].FromTTL
		}
		if segments[i].ToTTL != segments[j].ToTTL {
			return segments[i].ToTTL < segments[j].ToTTL
		}
		return segments[i].Kind < segments[j].Kind
	})
	return segments
}

func mergeResponder(responders []model.PathResponder, candidate model.PathResponder) []model.PathResponder {
	for index := range responders {
		if responders[index].Address != candidate.Address {
			continue
		}
		if responders[index].RTTMS == 0 || (candidate.RTTMS != 0 && candidate.RTTMS < responders[index].RTTMS) {
			responders[index].RTTMS = candidate.RTTMS
		}
		if responders[index].Response == "" {
			responders[index].Response = candidate.Response
		}
		responders[index].DestinationReached = responders[index].DestinationReached || candidate.DestinationReached
		return responders
	}
	return append(responders, candidate)
}

func pathEvidence(observation model.PathObservation, capturedAt time.Time) model.Evidence {
	raw, err := json.Marshal(observation)
	if err != nil {
		raw = json.RawMessage(`{"status":"error","protocol":"unknown","destination":"","hops":[],"segments":[],"destination_reached":false,"error":"unable to encode path observation"}`)
	}
	protocol := string(observation.Protocol)
	if protocol == "" {
		protocol = "unknown"
	}
	return model.Evidence{
		ID:         PathProbeName + "/" + protocol,
		Kind:       model.EvidenceKindPathObservation,
		Source:     "native-path-observer",
		CapturedAt: timePtr(capturedAt.UTC()),
		Raw:        raw,
	}
}

func (p *Probe) finish(result model.ProbeResult, started time.Time, cause error) model.ProbeResult {
	if cause != nil {
		if errors.Is(cause, context.Canceled) {
			result.Interpretation.FailureReason = FailureReasonPathCancellation
		} else if errors.Is(cause, context.DeadlineExceeded) {
			result.Interpretation.FailureReason = FailureReasonPathCancellation
		}
	}
	completed := p.clockNow().UTC()
	result.Timing.CompletedAt = &completed
	result.Timing.DurationMS = nonNegativeDuration(completed.Sub(started)).Milliseconds()
	return result
}

func (p *Probe) normalize() {
	if p.Timeout <= 0 {
		p.Timeout = DefaultTimeout
	}
	if p.MaxTTL == 0 {
		p.MaxTTL = DefaultMaxTTL
	} else if int(p.MaxTTL) > maxConfiguredTTL {
		p.MaxTTL = maxConfiguredTTL
	}
	if p.Attempts <= 0 {
		p.Attempts = DefaultAttempts
	} else if p.Attempts > maxConfiguredAttempts {
		p.Attempts = maxConfiguredAttempts
	}
	if len(p.Protocols) == 0 {
		p.Protocols = []model.PathProtocol{model.PathProtocolICMP, model.PathProtocolTCP}
	}
	if p.Now == nil {
		p.Now = time.Now
	}
}

func (p *Probe) clockNow() time.Time {
	if p == nil || p.Now == nil {
		return time.Now()
	}
	return p.Now()
}

func validateTarget(target model.Target) error {
	if strings.TrimSpace(target.RequestedIdentity) == "" {
		return errors.New("path target identity is empty")
	}
	if target.Port == 0 {
		return errors.New("path target port must be between 1 and 65535")
	}
	if strings.ContainsAny(target.RequestedIdentity, "\x00 \t\r\n") {
		return errors.New("path target identity is malformed")
	}
	return nil
}

func pathLayer(observations []model.PathObservation) model.Layer {
	for _, observation := range observations {
		if observation.Status == model.PathObservationStatusObserved && observation.Protocol == model.PathProtocolTCP && observation.PortAware && observation.DestinationReached && observation.DestinationTCPConnected {
			return model.LayerTCP
		}
	}
	for _, observation := range observations {
		if observation.Status == model.PathObservationStatusObserved && observation.Protocol == model.PathProtocolICMP && observation.DestinationReached {
			return model.LayerICMP
		}
	}
	for _, observation := range observations {
		if observation.Status == model.PathObservationStatusUnsupported && observation.Protocol == model.PathProtocolICMP {
			return model.LayerICMP
		}
	}
	return model.LayerNetwork
}

func pathDomain(observations []model.PathObservation) model.FaultDomain {
	if pathLayer(observations) == model.LayerICMP {
		return model.FaultDomainICMP
	}
	return model.FaultDomainNetwork
}

func isUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "operation not permitted") ||
		strings.Contains(message, "permission denied") ||
		strings.Contains(message, "protocol not supported") ||
		strings.Contains(message, "socket type not supported") ||
		strings.Contains(message, "raw socket")
}

func nonNegativeDuration(duration time.Duration) time.Duration {
	if duration < 0 {
		return 0
	}
	return duration
}

func timePtr(value time.Time) *time.Time { return &value }

// normalizeDestinationAddress is shared by native adapters and keeps IP
// literals in evidence canonical without resolving names.
func normalizeDestinationAddress(host string) (string, netip.Addr, error) {
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if address, err := netip.ParseAddr(host); err == nil {
		return model.NormalizeAddr(address).String(), model.NormalizeAddr(address), nil
	}
	return host, netip.Addr{}, nil
}

func endpointHost(address net.Addr) string {
	if address == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(address.String()); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(address.String(), "[]")
}
