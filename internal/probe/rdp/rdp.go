// Package rdp performs the bounded X.224 connection and RDP negotiation
// exchange. It does not attempt NLA, credentials, authentication, or a user
// session.
package rdp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

const (
	// DefaultTimeout bounds dialing, writing, and the complete response read.
	DefaultTimeout = 5 * time.Second
	MaxTPKTLength  = 4096
	MinTPKTLength  = 11
	// Security protocol identifiers from the RDP Negotiation Request/Response.
	ProtocolStandard uint32 = 0
	ProtocolTLS      uint32 = 1
	ProtocolCredSSP  uint32 = 2
	ProtocolRDSTLS   uint32 = 4
)

// EvidenceKind identifies the raw X.224/RDP negotiation observation.
const EvidenceKind = model.EvidenceKindRDPNegotiation

// ContextDialer is the small dialer surface used by Probe and local fixtures.
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// DialContextFunc adapts a function to ContextDialer.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Config controls one bounded RDP negotiation probe.
type Config struct {
	Timeout            time.Duration
	Dialer             ContextDialer
	MaxCandidates      int
	RequestedProtocols uint32
}

// Probe performs the unauthenticated X.224/RDP negotiation.
type Probe struct {
	Timeout            time.Duration
	Dialer             ContextDialer
	MaxCandidates      int
	RequestedProtocols uint32
}

var _ probecontract.Probe = Probe{}
var _ probecontract.Probe = (*Probe)(nil)

// New creates a probe with the default timeout and the standard TLS/CredSSP
// request. The request only advertises protocols; it does not authenticate.
func New(config ...Config) *Probe {
	value := Config{}
	if len(config) > 0 {
		value = config[0]
	}
	if value.Timeout <= 0 {
		value.Timeout = DefaultTimeout
	}
	if value.MaxCandidates <= 0 || value.MaxCandidates > model.MaxEndpointCandidates {
		value.MaxCandidates = model.MaxEndpointCandidates
	}
	if value.RequestedProtocols == 0 {
		value.RequestedProtocols = ProtocolTLS | ProtocolCredSSP
	}
	return &Probe{Timeout: value.Timeout, Dialer: value.Dialer, MaxCandidates: value.MaxCandidates, RequestedProtocols: value.RequestedProtocols}
}

// NewWithConfig is an explicit constructor alias.
func NewWithConfig(config Config) *Probe { return New(config) }

// NewWithDialer creates a fixture-friendly probe.
func NewWithDialer(timeout time.Duration, dialer ContextDialer) *Probe {
	return New(Config{Timeout: timeout, Dialer: dialer})
}

// Name returns the stable probe name.
func (Probe) Name() string { return "rdp" }

// RDPNegotiationEvidence is the bounded raw protocol observation.
type RDPNegotiationEvidence struct {
	RequestedEndpoint     string             `json:"requested_endpoint"`
	LocalEndpoint         string             `json:"local_endpoint,omitempty"`
	RemoteEndpoint        string             `json:"remote_endpoint,omitempty"`
	TransportConnected    bool               `json:"transport_connected"`
	NegotiationAttempted  bool               `json:"negotiation_attempted"`
	NegotiationComplete   bool               `json:"negotiation_complete"`
	RequestedProtocols    []string           `json:"requested_protocols,omitempty"`
	RequestedProtocolBits uint32             `json:"requested_protocol_bits,omitempty"`
	NegotiatedProtocol    string             `json:"negotiated_protocol,omitempty"`
	NegotiatedProtocolID  uint32             `json:"negotiated_protocol_id,omitempty"`
	ResponseType          string             `json:"response_type"`
	FailureCode           uint32             `json:"failure_code,omitempty"`
	TPKTLength            uint16             `json:"tpkt_length,omitempty"`
	BytesRead             int                `json:"bytes_read"`
	ElapsedMS             int64              `json:"elapsed_ms"`
	Error                 string             `json:"error,omitempty"`
	ErrorType             string             `json:"error_type,omitempty"`
	CandidateAttempts     []CandidateAttempt `json:"candidate_attempts,omitempty"`
}

// CandidateAttempt retains bounded endpoint outcomes without merging them
// into the canonical TCP observation.
type CandidateAttempt struct {
	RequestedEndpoint  string `json:"requested_endpoint"`
	TransportConnected bool   `json:"transport_connected"`
	ResponseType       string `json:"response_type"`
	Error              string `json:"error,omitempty"`
}

// RunTarget performs one RDP probe for target.
func RunTarget(ctx context.Context, target model.Target, timeout time.Duration) model.ProbeResult {
	return New(Config{Timeout: timeout}).Run(ctx, probecontract.ExecutionContext{Target: target})
}

// NegotiationRequest returns the bounded X.224/RDP request packet. It is
// exported for deterministic fixtures and contains no credentials.
func NegotiationRequest(protocols uint32) []byte {
	if protocols == 0 {
		protocols = ProtocolTLS | ProtocolCredSSP
	}
	// This is the minimal X.224 CR PDU plus RDP Negotiation Request. The
	// protocol bit field is the final little-endian uint32.
	packet := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(packet[len(packet)-4:], protocols)
	return packet
}

// Run performs the bounded exchange and never proceeds past negotiation.
func (p Probe) Run(ctx context.Context, execution probecontract.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	target := model.NormalizeTarget(execution.Target)
	execution.Target = target
	requested, err := target.EndpointAddress()
	if err != nil {
		return p.result(execution, started, time.Now(), model.ProbeStatusError, model.FailureReasonRDPNegotiationFailure, model.LayerRDP, model.FaultDomainRDP, RDPNegotiationEvidence{ResponseType: "invalid_target", Error: err.Error(), ErrorType: fmt.Sprintf("%T", err)})
	}
	if err := ctx.Err(); err != nil {
		reason := model.FailureReasonRDPTimeout
		if !errors.Is(err, context.DeadlineExceeded) {
			reason = model.FailureReasonRDPNegotiationFailure
		}
		return p.result(execution, started, time.Now(), model.ProbeStatusError, reason, model.LayerRDP, model.FaultDomainRDP, RDPNegotiationEvidence{RequestedEndpoint: requested, ResponseType: "canceled", Error: err.Error(), ErrorType: fmt.Sprintf("%T", err)})
	}

	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	candidates := target.ProbeEndpointCandidates()
	if len(candidates) == 0 {
		candidates = []model.EndpointCandidate{{Address: target.RequestedIdentity, Order: 1}}
	}
	limit := p.MaxCandidates
	if limit <= 0 || limit > model.MaxEndpointCandidates {
		limit = model.MaxEndpointCandidates
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	timeout := boundedTimeout(p.Timeout)
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	attemptBudget := timeout / time.Duration(len(candidates))
	if attemptBudget <= 0 {
		attemptBudget = time.Nanosecond
	}
	protocols := p.RequestedProtocols
	if protocols == 0 {
		protocols = ProtocolTLS | ProtocolCredSSP
	}
	var attempts []CandidateAttempt
	var last model.ProbeResult
	for _, candidate := range candidates {
		address := net.JoinHostPort(strings.Trim(candidate.Address, "[]"), strconv.Itoa(int(target.Port)))
		attemptContext, attemptCancel := context.WithTimeout(runContext, attemptBudget)
		conn, dialErr := dialer.DialContext(attemptContext, "tcp", address)
		contextErr := attemptContext.Err()
		attemptCancel()
		if dialErr != nil || conn == nil {
			if dialErr == nil {
				dialErr = errors.New("dialer returned a nil connection without an error")
			}
			reason, status := transportOutcome(dialErr, ctx.Err(), contextErr)
			attempt := CandidateAttempt{RequestedEndpoint: address, ResponseType: "transport_failure", Error: dialErr.Error()}
			attempts = append(attempts, attempt)
			last = p.result(execution, started, time.Now(), status, reason, model.LayerTCP, model.FaultDomainTransport, RDPNegotiationEvidence{RequestedEndpoint: address, RequestedProtocolBits: protocols, RequestedProtocols: protocolNames(protocols), ResponseType: "transport_failure", Error: dialErr.Error(), ErrorType: fmt.Sprintf("%T", dialErr), CandidateAttempts: attempts})
			if ctx.Err() != nil {
				return last
			}
			continue
		}

		value := RDPNegotiationEvidence{RequestedEndpoint: address, LocalEndpoint: endpointString(conn.LocalAddr()), RemoteEndpoint: endpointString(conn.RemoteAddr()), TransportConnected: true, NegotiationAttempted: true, RequestedProtocolBits: protocols, RequestedProtocols: protocolNames(protocols), ResponseType: "malformed"}
		_ = setConnectionDeadline(conn, attemptContext)
		request := NegotiationRequest(protocols)
		if err := writeAll(conn, request); err != nil {
			value.ResponseType = "negotiation_failure"
			value.Error = err.Error()
			value.ErrorType = fmt.Sprintf("%T", err)
			attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseType: value.ResponseType, Error: err.Error()})
			last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, rdpIOReason(err), model.LayerRDP, model.FaultDomainRDP, withAttempts(value, attempts))
			_ = conn.Close()
			if ctx.Err() != nil {
				return last
			}
			continue
		}
		packet, readErr := readTPKT(conn)
		_ = conn.Close()
		value.BytesRead = len(packet)
		if readErr != nil {
			value.ResponseType = "timeout"
			if !isTimeout(readErr) {
				value.ResponseType = "malformed"
			}
			value.Error = readErr.Error()
			value.ErrorType = fmt.Sprintf("%T", readErr)
			attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseType: value.ResponseType, Error: readErr.Error()})
			reason := model.FailureReasonRDPNegotiationMalformed
			if value.ResponseType == "timeout" {
				reason = model.FailureReasonRDPTimeout
			}
			last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, reason, model.LayerRDP, model.FaultDomainRDP, withAttempts(value, attempts))
			if ctx.Err() != nil {
				return last
			}
			continue
		}
		value.TPKTLength = binary.BigEndian.Uint16(packet[2:4])
		value = withAttempts(value, attempts)
		parsed := parseNegotiation(packet[4:])
		value.ResponseType = parsed.ResponseType
		value.FailureCode = parsed.FailureCode
		value.NegotiatedProtocolID = parsed.ProtocolID
		value.NegotiatedProtocol = protocolName(parsed.ProtocolID)
		value.NegotiationComplete = parsed.ResponseType == "success"
		attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseType: parsed.ResponseType})
		value.CandidateAttempts = append([]CandidateAttempt(nil), attempts...)
		if parsed.ResponseType == "success" {
			return p.result(execution, started, time.Now(), model.ProbeStatusPassed, model.FailureReasonNone, model.LayerRDP, model.FaultDomainRDP, value)
		}
		reason := model.FailureReasonRDPNegotiationMalformed
		if parsed.ResponseType == "rejected" {
			reason = model.FailureReasonRDPNegotiationRejected
		}
		last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, reason, model.LayerRDP, model.FaultDomainRDP, value)
	}
	if last.Name == "" {
		return p.result(execution, started, time.Now(), model.ProbeStatusError, model.FailureReasonRDPNegotiationFailure, model.LayerRDP, model.FaultDomainRDP, RDPNegotiationEvidence{RequestedEndpoint: requested, ResponseType: "no_candidate"})
	}
	return last
}

type negotiation struct {
	ResponseType string
	ProtocolID   uint32
	FailureCode  uint32
}

func parseNegotiation(body []byte) negotiation {
	if len(body) < 8 || body[0] < 6 || int(body[0])+1 > len(body) || body[1] != 0xd0 {
		return negotiation{ResponseType: "malformed"}
	}
	for index := 7; index+8 <= len(body); index++ {
		switch body[index] {
		case 0x02:
			return negotiation{ResponseType: "success", ProtocolID: binary.LittleEndian.Uint32(body[index+4 : index+8])}
		case 0x03:
			return negotiation{ResponseType: "rejected", FailureCode: binary.LittleEndian.Uint32(body[index+4 : index+8])}
		}
	}
	return negotiation{ResponseType: "malformed"}
}

func readTPKT(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return header, err
	}
	if header[0] != 0x03 || header[1] != 0x00 {
		return header, errors.New("RDP response is not a TPKT header")
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < MinTPKTLength || length > MaxTPKTLength {
		return header, errors.New("RDP TPKT length is outside bounded range")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return append(header, body...), err
	}
	return append(header, body...), nil
}

func (p Probe) result(execution probecontract.ExecutionContext, started, completed time.Time, status model.ProbeStatus, reason model.FailureReason, layer model.Layer, domain model.FaultDomain, value RDPNegotiationEvidence) model.ProbeResult {
	if completed.Before(started) {
		completed = started
	}
	value.ElapsedMS = completed.Sub(started).Milliseconds()
	raw, err := json.Marshal(value)
	if err != nil {
		raw = json.RawMessage(`{"response_type":"evidence_encoding_failure"}`)
	}
	completedUTC := completed.UTC()
	return model.ProbeResult{Name: "rdp", Target: execution.Target, SessionID: execution.SessionID, ProbeID: execution.ProbeID, CorrelationID: execution.CorrelationID, Status: status,
		Timing:         model.Timing{StartedAt: timePtr(started.UTC()), CompletedAt: &completedUTC, DurationMS: value.ElapsedMS},
		Evidence:       []model.Evidence{{ID: "rdp-negotiation", Kind: EvidenceKind, Source: "go-net.x224-rdp", CapturedAt: &completedUTC, Raw: raw}},
		Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain}}
}

func withAttempts(value RDPNegotiationEvidence, attempts []CandidateAttempt) RDPNegotiationEvidence {
	value.CandidateAttempts = append([]CandidateAttempt(nil), attempts...)
	return value
}

func protocolNames(bits uint32) []string {
	result := make([]string, 0, 4)
	for _, item := range []struct {
		bit  uint32
		name string
	}{{ProtocolTLS, "tls"}, {ProtocolCredSSP, "credssp"}, {ProtocolRDSTLS, "rdstls"}} {
		if bits&item.bit != 0 {
			result = append(result, item.name)
		}
	}
	if bits == ProtocolStandard {
		result = append(result, "standard_rdp")
	}
	return result
}

func protocolName(value uint32) string {
	switch value {
	case ProtocolStandard:
		return "standard_rdp"
	case ProtocolTLS:
		return "tls"
	case ProtocolCredSSP:
		return "credssp"
	case ProtocolRDSTLS:
		return "rdstls"
	case ProtocolTLS | ProtocolCredSSP:
		return "tls+credssp"
	default:
		return fmt.Sprintf("0x%08x", value)
	}
}

func transportOutcome(err, parentErr, attemptErr error) (model.FailureReason, model.ProbeStatus) {
	if errors.Is(parentErr, context.Canceled) || errors.Is(attemptErr, context.Canceled) {
		return model.FailureReasonRDPNegotiationFailure, model.ProbeStatusError
	}
	if errors.Is(parentErr, context.DeadlineExceeded) || errors.Is(attemptErr, context.DeadlineExceeded) || isTimeout(err) {
		return model.FailureReasonTCPTimeout, model.ProbeStatusFailed
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return model.FailureReasonTCPConnectionRefused, model.ProbeStatusFailed
	}
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "connection reset") {
		return model.FailureReasonTCPConnectionReset, model.ProbeStatusFailed
	}
	return model.FailureReasonRDPNegotiationFailure, model.ProbeStatusFailed
}

func rdpIOReason(err error) model.FailureReason {
	if isTimeout(err) {
		return model.FailureReasonRDPTimeout
	}
	return model.FailureReasonRDPNegotiationFailure
}

func writeAll(conn net.Conn, value []byte) error {
	for len(value) > 0 {
		written, err := conn.Write(value)
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func setConnectionDeadline(conn net.Conn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetDeadline(deadline)
	}
	return conn.SetDeadline(time.Now().Add(DefaultTimeout))
}

func endpointString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func boundedTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return DefaultTimeout
	}
	return value
}

func timePtr(value time.Time) *time.Time { return &value }
