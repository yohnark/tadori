package smb

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	Name             = "smb"
	defaultTimeout   = 5 * time.Second
	defaultMaxBytes  = 4096
	maxNegotiateBody = 1024
)

// Config controls the bounded SMB probe. MaxReadBytes includes the SMB
// response body and is deliberately capped even when a caller supplies a
// larger value. MaxWriteBytes bounds the request envelope.
type Config struct {
	Timeout       time.Duration
	MaxReadBytes  int
	MaxWriteBytes int
}

type Probe struct {
	timeout       time.Duration
	maxReadBytes  int
	maxWriteBytes int
}

func (*Probe) Name() string { return Name }

func New(config Config) *Probe {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	maxReadBytes := config.MaxReadBytes
	if maxReadBytes <= 0 || maxReadBytes > defaultMaxBytes {
		maxReadBytes = defaultMaxBytes
	}
	maxWriteBytes := config.MaxWriteBytes
	if maxWriteBytes <= 0 || maxWriteBytes > maxNegotiateBody {
		maxWriteBytes = maxNegotiateBody
	}
	return &Probe{timeout: timeout, maxReadBytes: maxReadBytes, maxWriteBytes: maxWriteBytes}
}

// RunTarget is the direct package API used by focused callers and fixtures.
func RunTarget(ctx context.Context, target model.Target, timeout time.Duration) model.ProbeResult {
	return New(Config{Timeout: timeout}).Run(ctx, probe.ExecutionContext{Target: target})
}

// Run performs a default-bounded negotiation for callers that do not need a
// custom probe timeout.
func Run(ctx context.Context, target model.Target) model.ProbeResult {
	return New(Config{}).Run(ctx, probe.ExecutionContext{Target: target})
}

// NegotiationEvidence is the raw bounded payload retained by the probe. It
// contains protocol facts only; the canonical application projection is built
// later by internal/observations.
type NegotiationEvidence struct {
	RequestedEndpoint string              `json:"requested_endpoint"`
	TestedEndpoint    string              `json:"tested_endpoint,omitempty"`
	Connected         bool                `json:"connected"`
	ResponseReceived  bool                `json:"response_received"`
	Negotiated        bool                `json:"negotiated"`
	Dialect           string              `json:"dialect,omitempty"`
	DialectRevision   uint16              `json:"dialect_revision,omitempty"`
	Capabilities      []string            `json:"capabilities,omitempty"`
	ServerGUID        string              `json:"server_guid,omitempty"`
	SecurityMode      uint16              `json:"security_mode,omitempty"`
	MaxTransactSize   uint32              `json:"max_transact_size,omitempty"`
	MaxReadSize       uint32              `json:"max_read_size,omitempty"`
	MaxWriteSize      uint32              `json:"max_write_size,omitempty"`
	ResponseBytes     int                 `json:"response_bytes,omitempty"`
	NetBIOSLength     int                 `json:"netbios_length,omitempty"`
	Protocol          string              `json:"protocol,omitempty"`
	FailureReason     model.FailureReason `json:"failure_reason"`
	Phase             string              `json:"phase,omitempty"`
	Error             string              `json:"error,omitempty"`
}

func (p *Probe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if p == nil {
		p = New(Config{})
	} else if p.timeout <= 0 || p.maxReadBytes <= 0 || p.maxWriteBytes <= 0 {
		p = New(Config{Timeout: p.timeout, MaxReadBytes: p.maxReadBytes, MaxWriteBytes: p.maxWriteBytes})
	}
	started := time.Now()
	target := model.NormalizeTarget(execution.Target)
	requested, address := endpointForTarget(target)
	result := model.ProbeResult{
		Name:   Name,
		Target: target,
		Status: model.ProbeStatusError,
		Timing: model.Timing{StartedAt: &started},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonUnknown,
			Layer:         model.LayerSMB,
			FaultDomain:   model.FaultDomainSMB,
		},
	}
	evidence := NegotiationEvidence{RequestedEndpoint: requested, Phase: "connect", FailureReason: model.FailureReasonUnknown}
	finish := func(status model.ProbeStatus, reason model.FailureReason, layer model.Layer, domain model.FaultDomain) model.ProbeResult {
		completed := time.Now()
		result.Status = status
		result.Timing.CompletedAt = &completed
		result.Timing.DurationMS = completed.Sub(started).Milliseconds()
		result.Interpretation.FailureReason = reason
		result.Interpretation.Layer = layer
		result.Interpretation.FaultDomain = domain
		raw, err := json.Marshal(evidence)
		if err != nil {
			result.Status = model.ProbeStatusError
			result.Interpretation.FailureReason = model.FailureReasonUnknown
		} else {
			captured := completed
			result.Evidence = []model.Evidence{{
				ID:         Name + "-negotiation",
				Kind:       model.EvidenceKindSMBNegotiation,
				Source:     "probe:smb",
				CapturedAt: &captured,
				Raw:        raw,
			}}
		}
		return result
	}

	if address == "" {
		evidence.Phase = "target"
		evidence.FailureReason = model.FailureReasonSMBConnectionRefused
		evidence.Error = "target has no probe endpoint"
		return finish(model.ProbeStatusFailed, model.FailureReasonSMBConnectionRefused, model.LayerTCP, model.FaultDomainTransport)
	}

	dialer := net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		evidence.Phase = "connect"
		evidence.Error = boundedError(err)
		reason := classifyDialError(ctx, err)
		evidence.FailureReason = reason
		return finish(model.ProbeStatusFailed, reason, model.LayerTCP, model.FaultDomainTransport)
	}
	defer conn.Close()
	evidence.Connected = true
	evidence.TestedEndpoint = conn.RemoteAddr().String()

	deadline := time.Now().Add(p.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		evidence.Phase = "deadline"
		evidence.Error = boundedError(err)
		evidence.FailureReason = model.FailureReasonSMBTimeout
		return finish(model.ProbeStatusFailed, model.FailureReasonSMBTimeout, model.LayerSMB, model.FaultDomainSMB)
	}
	request := negotiateRequest()
	if len(request) > p.maxWriteBytes {
		evidence.Phase = "request"
		evidence.Error = "negotiate request exceeds configured write bound"
		evidence.FailureReason = model.FailureReasonSMBMalformedResponse
		return finish(model.ProbeStatusError, model.FailureReasonSMBMalformedResponse, model.LayerSMB, model.FaultDomainSMB)
	}
	if _, err := conn.Write(request); err != nil {
		evidence.Phase = "write"
		evidence.Error = boundedError(err)
		evidence.FailureReason = classifyIOError(err)
		return finish(model.ProbeStatusFailed, evidence.FailureReason, model.LayerSMB, model.FaultDomainSMB)
	}

	response, err := readResponse(conn, p.maxReadBytes)
	if err != nil {
		evidence.Phase = "read"
		evidence.Error = boundedError(err)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			evidence.FailureReason = model.FailureReasonSMBTimeout
			return finish(model.ProbeStatusFailed, model.FailureReasonSMBTimeout, model.LayerSMB, model.FaultDomainSMB)
		}
		if errors.Is(err, errNonSMBResponse) {
			evidence.FailureReason = model.FailureReasonSMBProtocolRejection
			return finish(model.ProbeStatusFailed, model.FailureReasonSMBProtocolRejection, model.LayerSMB, model.FaultDomainSMB)
		}
		if errors.Is(err, errMalformedResponse) {
			evidence.FailureReason = model.FailureReasonSMBMalformedResponse
			return finish(model.ProbeStatusFailed, model.FailureReasonSMBMalformedResponse, model.LayerSMB, model.FaultDomainSMB)
		}
		evidence.FailureReason = model.FailureReasonSMBTimeout
		if !isTimeout(err) {
			evidence.FailureReason = model.FailureReasonSMBProtocolRejection
		}
		return finish(model.ProbeStatusFailed, evidence.FailureReason, model.LayerSMB, model.FaultDomainSMB)
	}

	evidence.ResponseReceived = true
	evidence.ResponseBytes = len(response)
	parsed, err := parseResponse(response)
	if err != nil {
		evidence.Phase = "parse"
		evidence.Error = boundedError(err)
		if errors.Is(err, errNonSMBResponse) {
			evidence.FailureReason = model.FailureReasonSMBProtocolRejection
			return finish(model.ProbeStatusFailed, model.FailureReasonSMBProtocolRejection, model.LayerSMB, model.FaultDomainSMB)
		}
		if errors.Is(err, errProtocolRejected) {
			evidence.FailureReason = model.FailureReasonSMBProtocolRejection
			return finish(model.ProbeStatusFailed, model.FailureReasonSMBProtocolRejection, model.LayerSMB, model.FaultDomainSMB)
		}
		evidence.FailureReason = model.FailureReasonSMBMalformedResponse
		return finish(model.ProbeStatusFailed, model.FailureReasonSMBMalformedResponse, model.LayerSMB, model.FaultDomainSMB)
	}
	evidence.Phase = "negotiate"
	evidence.Protocol = "SMB2/3"
	evidence.Negotiated = true
	evidence.Dialect = parsed.Dialect
	evidence.DialectRevision = parsed.DialectRevision
	evidence.Capabilities = parsed.Capabilities
	evidence.ServerGUID = parsed.ServerGUID
	evidence.SecurityMode = parsed.SecurityMode
	evidence.MaxTransactSize = parsed.MaxTransactSize
	evidence.MaxReadSize = parsed.MaxReadSize
	evidence.MaxWriteSize = parsed.MaxWriteSize
	evidence.FailureReason = model.FailureReasonNone
	return finish(model.ProbeStatusPassed, model.FailureReasonNone, model.LayerSMB, model.FaultDomainSMB)
}

type parsedResponse struct {
	Dialect         string
	DialectRevision uint16
	Capabilities    []string
	ServerGUID      string
	SecurityMode    uint16
	MaxTransactSize uint32
	MaxReadSize     uint32
	MaxWriteSize    uint32
}

var (
	errNonSMBResponse    = errors.New("response is not SMB")
	errMalformedResponse = errors.New("malformed SMB response")
	errProtocolRejected  = errors.New("SMB negotiate rejected")
)

func endpointForTarget(target model.Target) (string, string) {
	requested := requestedEndpoint(target)
	if target.TestedEndpoint != nil && target.TestedEndpoint.Address != "" {
		address := concreteAddress(target.TestedEndpoint.Address, target.TestedEndpoint.Port, target.Port)
		return requested, address
	}
	if target.SelectedEndpoint != nil && target.SelectedEndpoint.Address != "" {
		address := concreteAddress(target.SelectedEndpoint.Address, target.SelectedEndpoint.Port, target.Port)
		return requested, address
	}
	host := target.LiteralIP
	if host == "" {
		host = target.RequestedIdentity
	}
	if host == "" || target.Port == 0 {
		return "", ""
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(target.Port)))
	return requested, address
}

func requestedEndpoint(target model.Target) string {
	host := strings.Trim(strings.TrimSpace(target.RequestedIdentity), "[]")
	if target.LiteralIP != "" {
		host = strings.Trim(strings.TrimSpace(target.LiteralIP), "[]")
	}
	if host == "" {
		return ""
	}
	if target.Port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(target.Port)))
}

func concreteAddress(host string, endpointPort, defaultPort uint16) string {
	port := endpointPort
	if port == 0 {
		port = defaultPort
	}
	if port == 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func negotiateRequest() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	body := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	// Security mode requests signing when required but does not authenticate.
	binary.LittleEndian.PutUint16(body[4:6], 1)
	binary.LittleEndian.PutUint32(body[8:12], 0x00000007)
	// A deterministic zero GUID is valid for a negotiate request and avoids
	// collecting host identity data in a diagnostic packet.
	for index, dialect := range dialects {
		binary.LittleEndian.PutUint16(body[36+index*2:], dialect)
	}
	envelope := make([]byte, 4+64+len(body))
	envelope[0] = 0
	length := len(envelope) - 4
	envelope[1] = byte(length >> 16)
	envelope[2] = byte(length >> 8)
	envelope[3] = byte(length)
	header := envelope[4:]
	copy(header[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], 0)
	binary.LittleEndian.PutUint16(header[14:16], 1)
	binary.LittleEndian.PutUint64(header[24:32], 0)
	copy(header[64:], body)
	return envelope
}

func readResponse(reader io.Reader, maxBytes int) ([]byte, error) {
	var envelope [4]byte
	if _, err := io.ReadFull(reader, envelope[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errMalformedResponse
		}
		return nil, err
	}
	if envelope[0] != 0 {
		return nil, errNonSMBResponse
	}
	length := int(envelope[1])<<16 | int(envelope[2])<<8 | int(envelope[3])
	if length < 64 || length > maxBytes {
		return nil, errMalformedResponse
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errMalformedResponse
		}
		return nil, err
	}
	return body, nil
}

func parseResponse(body []byte) (parsedResponse, error) {
	if len(body) < 4 || string(body[:4]) != "\xfeSMB" {
		return parsedResponse{}, errNonSMBResponse
	}
	if len(body) < 64+64 {
		return parsedResponse{}, errMalformedResponse
	}
	if binary.LittleEndian.Uint16(body[4:6]) != 64 || binary.LittleEndian.Uint16(body[12:14]) != 0 {
		return parsedResponse{}, errMalformedResponse
	}
	status := binary.LittleEndian.Uint32(body[8:12])
	if status != 0 {
		return parsedResponse{}, fmt.Errorf("%w with status 0x%08x", errProtocolRejected, status)
	}
	if binary.LittleEndian.Uint16(body[64:66]) != 65 {
		return parsedResponse{}, errMalformedResponse
	}
	dialectRevision := binary.LittleEndian.Uint16(body[68:70])
	dialect := dialectName(dialectRevision)
	if dialect == "" {
		return parsedResponse{}, fmt.Errorf("%w: unsupported dialect 0x%04x", errProtocolRejected, dialectRevision)
	}
	capabilities := smbCapabilities(binary.LittleEndian.Uint32(body[88:92]))
	return parsedResponse{
		Dialect: dialect, DialectRevision: dialectRevision, Capabilities: capabilities,
		ServerGUID: hex.EncodeToString(body[72:88]), SecurityMode: binary.LittleEndian.Uint16(body[66:68]),
		MaxTransactSize: binary.LittleEndian.Uint32(body[92:96]),
		MaxReadSize:     binary.LittleEndian.Uint32(body[96:100]),
		MaxWriteSize:    binary.LittleEndian.Uint32(body[100:104]),
	}, nil
}

func dialectName(value uint16) string {
	switch value {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		return ""
	}
}

func smbCapabilities(value uint32) []string {
	capabilities := make([]string, 0, 5)
	for _, capability := range []struct {
		mask uint32
		name string
	}{{0x00000001, "DFS"}, {0x00000002, "LEASING"}, {0x00000004, "LARGE_MTU"}, {0x00000008, "MULTI_CHANNEL"}, {0x00000010, "PERSISTENT_HANDLES"}} {
		if value&capability.mask != 0 {
			capabilities = append(capabilities, capability.name)
		}
	}
	return capabilities
}

func classifyDialError(ctx context.Context, err error) model.FailureReason {
	if isTimeout(err) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return model.FailureReasonTCPTimeout
	}
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return model.FailureReasonTCPConnectionRefused
	}
	return model.FailureReasonSMBConnectionRefused
}

func classifyIOError(err error) model.FailureReason {
	if isTimeout(err) {
		return model.FailureReasonSMBTimeout
	}
	return model.FailureReasonSMBProtocolRejection
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
