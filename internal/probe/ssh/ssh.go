// Package ssh performs the bounded, unauthenticated SSH identification
// exchange. It deliberately stops after the server identification string;
// authentication, channels, and key exchange are outside this probe.
package ssh

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

const (
	// DefaultTimeout bounds dialing and the complete identification exchange.
	DefaultTimeout = 5 * time.Second
	// MaxBannerBytes is the RFC identification-line limit including the line
	// terminator. The probe never retains a larger server banner.
	MaxBannerBytes = 255
	// MaxPreludeLines and MaxPreludeBytes bound optional pre-identification
	// text permitted by the SSH transport protocol.
	MaxPreludeLines      = 50
	MaxPreludeBytes      = 2048
	clientIdentification = "SSH-2.0-tadori\r\n"
)

// EvidenceKind identifies the raw SSH identification exchange.
const EvidenceKind = model.EvidenceKindSSHHandshake

// ContextDialer is the small dialer surface used by Probe and deterministic
// local fixtures.
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// DialContextFunc adapts a function to ContextDialer.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Config controls one bounded SSH identification probe.
type Config struct {
	Timeout       time.Duration
	Dialer        ContextDialer
	MaxCandidates int
}

// Probe performs one unauthenticated SSH identification exchange per bounded
// endpoint candidate. A successful TCP connection is not a successful Probe:
// the server identification must also be valid.
type Probe struct {
	Timeout       time.Duration
	Dialer        ContextDialer
	MaxCandidates int
}

var _ probecontract.Probe = Probe{}
var _ probecontract.Probe = (*Probe)(nil)

// New creates a probe with the default timeout unless timeout is positive.
func New(timeout ...time.Duration) *Probe {
	var configured time.Duration
	if len(timeout) > 0 {
		configured = timeout[0]
	}
	return NewWithConfig(Config{Timeout: configured})
}

// NewWithConfig creates a probe with injectable transport and bounds.
func NewWithConfig(config Config) *Probe {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxCandidates := config.MaxCandidates
	if maxCandidates <= 0 || maxCandidates > model.MaxEndpointCandidates {
		maxCandidates = model.MaxEndpointCandidates
	}
	return &Probe{Timeout: timeout, Dialer: config.Dialer, MaxCandidates: maxCandidates}
}

// NewWithDialer is a fixture-friendly constructor.
func NewWithDialer(timeout time.Duration, dialer ContextDialer) *Probe {
	return NewWithConfig(Config{Timeout: timeout, Dialer: dialer})
}

// Name returns the stable probe name.
func (Probe) Name() string { return "ssh" }

// SSHHandshakeEvidence is the bounded raw observation emitted by the probe.
// The banner is the standard server identification string; no authentication
// or credential material is collected.
type SSHHandshakeEvidence struct {
	RequestedEndpoint    string             `json:"requested_endpoint"`
	LocalEndpoint        string             `json:"local_endpoint,omitempty"`
	RemoteEndpoint       string             `json:"remote_endpoint,omitempty"`
	TransportConnected   bool               `json:"transport_connected"`
	BannerReceived       bool               `json:"banner_received"`
	BannerValid          bool               `json:"banner_valid"`
	ServerProtocol       string             `json:"server_protocol,omitempty"`
	ServerSoftware       string             `json:"server_software,omitempty"`
	ServerIdentification string             `json:"server_identification,omitempty"`
	ResponseClass        string             `json:"response_class"`
	Error                string             `json:"error,omitempty"`
	ErrorType            string             `json:"error_type,omitempty"`
	BytesRead            int                `json:"bytes_read"`
	ElapsedMS            int64              `json:"elapsed_ms"`
	CandidateAttempts    []CandidateAttempt `json:"candidate_attempts,omitempty"`
}

// CandidateAttempt retains deterministic per-address transport/application
// outcomes without changing the canonical transport observation.
type CandidateAttempt struct {
	RequestedEndpoint  string `json:"requested_endpoint"`
	TransportConnected bool   `json:"transport_connected"`
	ResponseClass      string `json:"response_class"`
	Error              string `json:"error,omitempty"`
}

// RunTarget performs one SSH probe for target.
func RunTarget(ctx context.Context, target model.Target, timeout time.Duration) model.ProbeResult {
	return New(timeout).Run(ctx, probecontract.ExecutionContext{Target: target})
}

// Run performs the bounded exchange.
func (p Probe) Run(ctx context.Context, execution probecontract.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	target := model.NormalizeTarget(execution.Target)
	execution.Target = target
	requested, err := target.EndpointAddress()
	if err != nil {
		return p.result(execution, started, time.Now(), model.ProbeStatusError, model.FailureReasonSSHHandshakeFailure, model.LayerSSH, model.FaultDomainSSH, SSHHandshakeEvidence{ResponseClass: "invalid_target", Error: err.Error(), ErrorType: fmt.Sprintf("%T", err)})
	}
	if err := ctx.Err(); err != nil {
		reason := model.FailureReasonSSHTimeout
		if !errors.Is(err, context.DeadlineExceeded) {
			reason = model.FailureReasonSSHHandshakeFailure
		}
		return p.result(execution, started, time.Now(), model.ProbeStatusError, reason, model.LayerSSH, model.FaultDomainSSH, SSHHandshakeEvidence{RequestedEndpoint: requested, ResponseClass: "canceled", Error: err.Error(), ErrorType: fmt.Sprintf("%T", err)})
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
	runContext, cancel := context.WithTimeout(ctx, boundedTimeout(p.Timeout))
	defer cancel()
	attemptBudget := boundedTimeout(p.Timeout) / time.Duration(len(candidates))
	if attemptBudget <= 0 {
		attemptBudget = time.Nanosecond
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
			reason, status, domain := transportOutcome(dialErr, ctx.Err(), contextErr)
			attempt := CandidateAttempt{RequestedEndpoint: address, ResponseClass: "transport_failure", Error: dialErr.Error()}
			attempts = append(attempts, attempt)
			last = p.result(execution, started, time.Now(), status, reason, model.LayerTCP, domain, SSHHandshakeEvidence{RequestedEndpoint: address, ResponseClass: "transport_failure", Error: dialErr.Error(), ErrorType: fmt.Sprintf("%T", dialErr), CandidateAttempts: attempts})
			if ctx.Err() != nil {
				return last
			}
			continue
		}

		observation := SSHHandshakeEvidence{RequestedEndpoint: address, TransportConnected: true, ResponseClass: "malformed"}
		observation.LocalEndpoint = endpointString(conn.LocalAddr())
		observation.RemoteEndpoint = endpointString(conn.RemoteAddr())
		_ = setConnectionDeadline(conn, attemptContext)
		writeErr := writeIdentification(conn)
		if writeErr != nil {
			observation.Error = writeErr.Error()
			observation.ErrorType = fmt.Sprintf("%T", writeErr)
			observation.ResponseClass = "handshake_failure"
			attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseClass: observation.ResponseClass, Error: writeErr.Error()})
			last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, sshIOReason(writeErr), model.LayerSSH, model.FaultDomainSSH, withAttempts(observation, attempts))
			_ = conn.Close()
			if ctx.Err() != nil {
				return last
			}
			continue
		}
		banner, readErr := readIdentification(bufio.NewReader(conn))
		_ = conn.Close()
		observation.BytesRead = len(banner)
		if readErr != nil {
			observation.Error = readErr.Error()
			observation.ErrorType = fmt.Sprintf("%T", readErr)
			if errors.Is(readErr, context.DeadlineExceeded) || isTimeout(readErr) {
				observation.ResponseClass = "timeout"
				attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseClass: observation.ResponseClass, Error: readErr.Error()})
				last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, model.FailureReasonSSHTimeout, model.LayerSSH, model.FaultDomainSSH, withAttempts(observation, attempts))
			} else if errors.Is(readErr, errNonSSH) {
				observation.ResponseClass = "non_ssh"
				attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseClass: observation.ResponseClass, Error: readErr.Error()})
				last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, model.FailureReasonSSHNonSSHResponse, model.LayerSSH, model.FaultDomainSSH, withAttempts(observation, attempts))
			} else {
				observation.ResponseClass = "malformed"
				attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseClass: observation.ResponseClass, Error: readErr.Error()})
				last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, model.FailureReasonSSHBannerMalformed, model.LayerSSH, model.FaultDomainSSH, withAttempts(observation, attempts))
			}
			if ctx.Err() != nil {
				return last
			}
			continue
		}

		parsed := parseIdentification(banner)
		observation.BannerReceived = true
		observation.BannerValid = parsed.Valid
		observation.ServerIdentification = parsed.Identification
		observation.ServerProtocol = parsed.Protocol
		observation.ServerSoftware = parsed.Software
		observation.ResponseClass = "valid"
		attempts = append(attempts, CandidateAttempt{RequestedEndpoint: address, TransportConnected: true, ResponseClass: observation.ResponseClass})
		if !parsed.Valid {
			observation.ResponseClass = parsed.Class
			last = p.result(execution, started, time.Now(), model.ProbeStatusFailed, parsed.Reason, model.LayerSSH, model.FaultDomainSSH, withAttempts(observation, attempts))
			continue
		}
		return p.result(execution, started, time.Now(), model.ProbeStatusPassed, model.FailureReasonNone, model.LayerSSH, model.FaultDomainSSH, withAttempts(observation, attempts))
	}
	if last.Name == "" {
		return p.result(execution, started, time.Now(), model.ProbeStatusError, model.FailureReasonSSHHandshakeFailure, model.LayerSSH, model.FaultDomainSSH, SSHHandshakeEvidence{RequestedEndpoint: requested, ResponseClass: "no_candidate"})
	}
	return last
}

func withAttempts(value SSHHandshakeEvidence, attempts []CandidateAttempt) SSHHandshakeEvidence {
	value.CandidateAttempts = append([]CandidateAttempt(nil), attempts...)
	return value
}

func (p Probe) result(execution probecontract.ExecutionContext, started, completed time.Time, status model.ProbeStatus, reason model.FailureReason, layer model.Layer, domain model.FaultDomain, value SSHHandshakeEvidence) model.ProbeResult {
	value.ElapsedMS = maxDuration(completed.Sub(started)).Milliseconds()
	if value.RequestedEndpoint == "" {
		if endpoint, err := execution.Target.EndpointAddress(); err == nil {
			value.RequestedEndpoint = endpoint
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		raw = json.RawMessage(`{"response_class":"evidence_encoding_failure"}`)
	}
	completedUTC := completed.UTC()
	return model.ProbeResult{
		Name: "ssh", Target: execution.Target, SessionID: execution.SessionID, ProbeID: execution.ProbeID, CorrelationID: execution.CorrelationID,
		Status:         status,
		Timing:         model.Timing{StartedAt: timePtr(started.UTC()), CompletedAt: &completedUTC, DurationMS: maxDuration(completed.Sub(started)).Milliseconds()},
		Evidence:       []model.Evidence{{ID: "ssh-handshake", Kind: EvidenceKind, Source: "go-net.ssh-identification", CapturedAt: &completedUTC, Raw: raw}},
		Interpretation: model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain},
	}
}

type identification struct {
	Valid          bool
	Class          string
	Reason         model.FailureReason
	Identification string
	Protocol       string
	Software       string
}

var errNonSSH = errors.New("response does not begin with SSH identification")

func parseIdentification(line []byte) identification {
	value := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	if !strings.HasPrefix(value, "SSH-") {
		return identification{Class: "non_ssh", Reason: model.FailureReasonSSHNonSSHResponse}
	}
	parts := strings.SplitN(value, "-", 3)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" || strings.ContainsRune(parts[2], '\x00') || !utf8.ValidString(value) {
		return identification{Class: "malformed", Reason: model.FailureReasonSSHBannerMalformed}
	}
	if parts[1] != "2.0" && parts[1] != "1.99" {
		return identification{Class: "unsupported_version", Reason: model.FailureReasonSSHBannerMalformed}
	}
	return identification{Valid: true, Class: "valid", Reason: model.FailureReasonNone, Identification: value, Protocol: parts[1], Software: parts[2]}
}

func readIdentification(reader *bufio.Reader) ([]byte, error) {
	preludeBytes := 0
	for lineNumber := 0; lineNumber <= MaxPreludeLines; lineNumber++ {
		line, err := readBoundedLine(reader, MaxBannerBytes)
		if err != nil {
			return line, err
		}
		preludeBytes += len(line)
		if preludeBytes > MaxPreludeBytes {
			return line, errors.New("SSH pre-identification text exceeded bounded size")
		}
		if bytesHasPrefix(line, "SSH-") {
			parsed := parseIdentification(line)
			if parsed.Valid {
				return line, nil
			}
			if parsed.Class == "non_ssh" {
				return line, errNonSSH
			}
			return line, errors.New("malformed SSH identification")
		}
		if lineNumber == 0 && looksLikeNonSSH(line) {
			return line, errNonSSH
		}
	}
	return nil, errors.New("SSH identification was not received within bounded prelude")
}

func readBoundedLine(reader *bufio.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, limit)
	for len(line) < limit {
		value, err := reader.ReadByte()
		if err != nil {
			return line, err
		}
		line = append(line, value)
		if value == '\n' {
			return line, nil
		}
	}
	return line, errors.New("SSH identification line exceeded bounded size")
}

func writeIdentification(conn net.Conn) error {
	written := 0
	for written < len(clientIdentification) {
		n, err := conn.Write([]byte(clientIdentification)[written:])
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func looksLikeNonSSH(line []byte) bool {
	value := strings.ToLower(strings.TrimSpace(string(line)))
	return value != "" && (strings.HasPrefix(value, "http/") || strings.HasPrefix(value, "rdp") || strings.HasPrefix(value, "smtp") || strings.HasPrefix(value, "not ssh"))
}

func setConnectionDeadline(conn net.Conn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetDeadline(deadline)
	}
	return conn.SetDeadline(time.Now().Add(DefaultTimeout))
}

func transportOutcome(err, parentErr, attemptErr error) (model.FailureReason, model.ProbeStatus, model.FaultDomain) {
	if errors.Is(parentErr, context.Canceled) || errors.Is(attemptErr, context.Canceled) {
		return model.FailureReasonSSHHandshakeFailure, model.ProbeStatusError, model.FaultDomainTransport
	}
	if errors.Is(parentErr, context.DeadlineExceeded) || errors.Is(attemptErr, context.DeadlineExceeded) || isTimeout(err) {
		return model.FailureReasonTCPTimeout, model.ProbeStatusFailed, model.FaultDomainTransport
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return model.FailureReasonTCPConnectionRefused, model.ProbeStatusFailed, model.FaultDomainTransport
	}
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "connection reset") {
		return model.FailureReasonTCPConnectionReset, model.ProbeStatusFailed, model.FaultDomainTransport
	}
	return model.FailureReasonSSHHandshakeFailure, model.ProbeStatusFailed, model.FaultDomainTransport
}

func sshIOReason(err error) model.FailureReason {
	if isTimeout(err) {
		return model.FailureReasonSSHTimeout
	}
	return model.FailureReasonSSHHandshakeFailure
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func endpointString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

func bytesHasPrefix(value []byte, prefix string) bool {
	return strings.HasPrefix(string(value), prefix)
}

func boundedTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return DefaultTimeout
	}
	return value
}

func maxDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}

func timePtr(value time.Time) *time.Time { return &value }
