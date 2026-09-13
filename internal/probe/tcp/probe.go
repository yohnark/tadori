package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

// DefaultTimeout is used when a Probe has no positive timeout. A timeout is
// always applied, including when callers pass context.Background().
const DefaultTimeout = 5 * time.Second

// These reasons are package-owned extensions to the frozen #2 model contract.
// The bootstrap contract does not yet define values for host-unreachable,
// invalid-address, or cancellation. Keeping the values here avoids changing
// the shared model while retaining a machine-readable interpretation.
const (
	FailureReasonTCPHostUnreachable model.FailureReason = "tcp_host_unreachable"
	FailureReasonTCPInvalidAddress  model.FailureReason = "tcp_invalid_address"
	FailureReasonTCPCancellation    model.FailureReason = "tcp_cancellation"

	// Aliases make the names useful to callers that describe the parser or
	// context outcome without changing the canonical values above.
	FailureReasonHostUnreachable model.FailureReason = FailureReasonTCPHostUnreachable
	FailureReasonInvalidAddress  model.FailureReason = FailureReasonTCPInvalidAddress
	FailureReasonInvalidPort     model.FailureReason = FailureReasonTCPInvalidAddress
	FailureReasonCancellation    model.FailureReason = FailureReasonTCPCancellation
)

// ContextDialer is the portion of net.Dialer used by Probe. It is injectable
// so callers and tests can supply deterministic local fixtures without making
// an Internet request.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContextFunc adapts a function into a ContextDialer.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialContext implements ContextDialer.
func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Config controls a Probe. Timeout is normalized to DefaultTimeout when it is
// zero or negative. Dialer defaults to net.Dialer when nil.
type Config struct {
	Timeout time.Duration
	Dialer  ContextDialer
}

// Probe performs a single TCP connect. The exported fields allow a caller to
// configure a probe directly; New and NewWithConfig are provided for the
// common cases.
type Probe struct {
	Timeout time.Duration
	Dialer  ContextDialer
}

var _ probecontract.Probe = Probe{}
var _ probecontract.Probe = (*Probe)(nil)

// New creates a TCP probe with timeout. A non-positive timeout selects
// DefaultTimeout. Omitting timeout also selects the default.
func New(timeout ...time.Duration) *Probe {
	var configured time.Duration
	if len(timeout) > 0 {
		configured = timeout[0]
	}
	return NewWithConfig(Config{Timeout: configured})
}

// NewProbe is an explicit constructor alias for New.
func NewProbe(timeout ...time.Duration) *Probe {
	return New(timeout...)
}

// NewWithConfig creates a TCP probe using config.
func NewWithConfig(config Config) *Probe {
	return &Probe{
		Timeout: boundedTimeout(config.Timeout),
		Dialer:  config.Dialer,
	}
}

// NewWithDialer creates a TCP probe with an injected dialer. It is useful for
// deterministic fixtures and for applications that need to configure the
// underlying network dial operation.
func NewWithDialer(timeout time.Duration, dialer ContextDialer) *Probe {
	return NewWithConfig(Config{Timeout: timeout, Dialer: dialer})
}

// Name returns the stable machine-readable probe name.
func (Probe) Name() string { return "tcp" }

// Run connects to execution.Target's canonical identity/endpoint and port. The
// returned result always contains timing and one TCP evidence item, including
// the original dial error when the connection fails. Context cancellation and
// deadlines are preserved as normalized outcomes.
func (p Probe) Run(ctx context.Context, execution probecontract.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}

	start := time.Now()
	target := execution.Target
	address, addressErr := targetAddress(target)
	if addressErr != nil {
		completed := time.Now()
		observation := tcpObservation{
			RequestedEndpoint: address,
			Error:             addressErr.Error(),
			ErrorType:         fmt.Sprintf("%T", addressErr),
		}
		return p.result(execution, start, completed, model.ProbeStatusError, FailureReasonTCPInvalidAddress, model.FaultDomainLocal, observation)
	}

	// Check before constructing the child context so an already-cancelled
	// caller is reported as cancellation, even if target validation succeeded.
	if err := ctx.Err(); err != nil {
		completed := time.Now()
		observation := tcpObservation{
			RequestedEndpoint: address,
			Error:             err.Error(),
			ErrorType:         fmt.Sprintf("%T", err),
		}
		reason := FailureReasonTCPCancellation
		if errors.Is(err, context.DeadlineExceeded) {
			reason = model.FailureReasonTCPTimeout
		}
		return p.result(execution, start, completed, model.ProbeStatusError, reason, faultDomainFor(reason), observation)
	}

	timeout := boundedTimeout(p.Timeout)
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	dialContext, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dialer.DialContext(dialContext, "tcp", address)
	dialContextErr := dialContext.Err()
	cancel()
	completed := time.Now()

	if err == nil {
		observation := tcpObservation{RequestedEndpoint: address}
		if conn != nil {
			observation.LocalEndpoint = endpointString(conn.LocalAddr())
			observation.RemoteEndpoint = endpointString(conn.RemoteAddr())
			observation.ResolvedEndpoint = observation.RemoteEndpoint
			_ = conn.Close()
		} else {
			// A nil connection with nil error violates the net dialer contract;
			// retain it as an execution error rather than reporting false success.
			err = errors.New("dialer returned a nil connection without an error")
		}
		if err == nil {
			return p.result(execution, start, completed, model.ProbeStatusPassed, model.FailureReasonNone, model.FaultDomainTransport, observation)
		}
	}

	// A custom dialer may return a context error without updating the parent
	// context. Check both contexts so cancellation remains observable.
	reason, status := normalizeError(err, ctx.Err(), dialContextErr)
	observation := tcpObservation{
		RequestedEndpoint: address,
		Error:             err.Error(),
		ErrorType:         fmt.Sprintf("%T", err),
	}
	addErrorDetails(&observation, err)
	return p.result(execution, start, completed, status, reason, faultDomainFor(reason), observation)
}

// RunTarget is a convenience one-shot operation for callers that do not need
// to retain a Probe value.
func RunTarget(ctx context.Context, target model.Target, timeout time.Duration) model.ProbeResult {
	return New(timeout).Run(ctx, probecontract.ExecutionContext{Target: target})
}

type tcpObservation struct {
	RequestedEndpoint string `json:"requested_endpoint"`
	LocalEndpoint     string `json:"local_endpoint,omitempty"`
	RemoteEndpoint    string `json:"remote_endpoint,omitempty"`
	ResolvedEndpoint  string `json:"resolved_endpoint,omitempty"`
	ElapsedNS         int64  `json:"elapsed_ns"`
	ElapsedMS         int64  `json:"elapsed_ms"`
	Error             string `json:"error,omitempty"`
	ErrorType         string `json:"error_type,omitempty"`
	ErrorCode         int64  `json:"error_code,omitempty"`
	Operation         string `json:"operation,omitempty"`
	Network           string `json:"network,omitempty"`
}

func (Probe) result(execution probecontract.ExecutionContext, start, completed time.Time, status model.ProbeStatus, reason model.FailureReason, domain model.FaultDomain, observation tcpObservation) model.ProbeResult {
	target := execution.Target
	elapsed := completed.Sub(start)
	if elapsed < 0 {
		elapsed = 0
	}
	observation.ElapsedNS = elapsed.Nanoseconds()
	observation.ElapsedMS = elapsed.Milliseconds()
	raw, err := json.Marshal(observation)
	if err != nil {
		// tcpObservation contains only primitive fields, so this is defensive;
		// valid JSON is still required by the model contract if that changes.
		raw = json.RawMessage(`{"error":"unable to encode TCP observation"}`)
	}
	startedAt := start.UTC()
	completedAt := completed.UTC()
	return model.ProbeResult{
		Name:          "tcp",
		Target:        target,
		SessionID:     execution.SessionID,
		ProbeID:       execution.ProbeID,
		CorrelationID: execution.CorrelationID,
		Status:        status,
		Timing: model.Timing{
			StartedAt:   &startedAt,
			CompletedAt: &completedAt,
			DurationMS:  elapsed.Milliseconds(),
		},
		Evidence: []model.Evidence{{
			ID:         "tcp-connection",
			Kind:       model.EvidenceKindTCPConnection,
			Source:     "go-net.Dialer",
			CapturedAt: &completedAt,
			Raw:        raw,
		}},
		Interpretation: model.ProbeInterpretation{
			FailureReason: reason,
			Layer:         model.LayerTCP,
			FaultDomain:   domain,
		},
	}
}

func targetAddress(target model.Target) (string, error) {
	address, err := model.NormalizeTarget(target).EndpointAddress()
	if err != nil {
		return "", fmt.Errorf("TCP target endpoint: %w", err)
	}
	return address, nil
}

func boundedTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultTimeout
	}
	return timeout
}

func endpointString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func addErrorDetails(observation *tcpObservation, err error) {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		observation.Operation = opErr.Op
		observation.Network = opErr.Net
		if opErr.Addr != nil {
			observation.RemoteEndpoint = opErr.Addr.String()
			observation.ResolvedEndpoint = observation.RemoteEndpoint
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		observation.ErrorCode = int64(errno)
	}
}

func normalizeError(err, parentErr, dialErr error) (model.FailureReason, model.ProbeStatus) {
	if errors.Is(parentErr, context.Canceled) || errors.Is(dialErr, context.Canceled) || errors.Is(err, context.Canceled) {
		return FailureReasonTCPCancellation, model.ProbeStatusError
	}
	if errors.Is(parentErr, context.DeadlineExceeded) || errors.Is(dialErr, context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return model.FailureReasonTCPTimeout, model.ProbeStatusFailed
	}
	if isTimeout(err) {
		return model.FailureReasonTCPTimeout, model.ProbeStatusFailed
	}
	if errors.Is(err, syscall.ECONNREFUSED) || containsErrorText(err, "connection refused", "actively refused") {
		return model.FailureReasonTCPConnectionRefused, model.ProbeStatusFailed
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || containsErrorText(err, "connection reset", "forcibly closed", "connection aborted") {
		return model.FailureReasonTCPConnectionReset, model.ProbeStatusFailed
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN) || containsErrorText(err, "network is unreachable", "network unreachable") {
		return model.FailureReasonNetworkUnreachable, model.ProbeStatusFailed
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EHOSTDOWN) || containsErrorText(err, "host is unreachable", "host unreachable") {
		return FailureReasonTCPHostUnreachable, model.ProbeStatusFailed
	}
	if containsErrorText(err, "no route to host", "no route") {
		return model.FailureReasonNoRoute, model.ProbeStatusFailed
	}
	return model.FailureReasonUnknown, model.ProbeStatusFailed
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func containsErrorText(err error, phrases ...string) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, phrase := range phrases {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

func faultDomainFor(reason model.FailureReason) model.FaultDomain {
	switch reason {
	case model.FailureReasonNone:
		return model.FaultDomainTransport
	case model.FailureReasonTCPConnectionRefused, model.FailureReasonTCPConnectionReset:
		return model.FaultDomainDestination
	case model.FailureReasonNetworkUnreachable, FailureReasonTCPHostUnreachable, model.FailureReasonNoRoute:
		return model.FaultDomainNetwork
	case model.FailureReasonTCPTimeout:
		return model.FaultDomainTransport
	case FailureReasonTCPInvalidAddress, FailureReasonTCPCancellation:
		return model.FaultDomainLocal
	default:
		return model.FaultDomainUnknown
	}
}
