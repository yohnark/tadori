package tls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

// DefaultTimeout bounds the complete operation, including TCP setup and the
// TLS handshake. It is deliberately finite so a probe cannot hang on a
// half-open endpoint.
const DefaultTimeout = 10 * time.Second

// Failure reasons which are specific to the TLS lane. They use the canonical
// model type while remaining package-owned because the bootstrap contract is
// frozen and intentionally has no TLS-specific sub-classifications.
const (
	FailureReasonTransportFailure            model.FailureReason = "tls_transport_failure"
	FailureReasonTLSTimeout                  model.FailureReason = "tls_timeout"
	FailureReasonCertificateExpired          model.FailureReason = "certificate_expired"
	FailureReasonCertificateHostnameMismatch model.FailureReason = "certificate_hostname_mismatch"
	FailureReasonUnknownAuthority            model.FailureReason = "certificate_unknown_authority"
	FailureReasonCancellation                model.FailureReason = "cancellation"

	// Friendly aliases make the phase distinction explicit to callers without
	// introducing another result type.
	FailureReasonTLSTransportFailure         = FailureReasonTransportFailure
	FailureReasonCertificateUnknownAuthority = FailureReasonUnknownAuthority
)

// Phase identifies the stage represented by HandshakeEvidence.
type Phase string

const (
	PhaseTransport   Phase = "transport"
	PhaseHandshake   Phase = "handshake"
	PhaseCertificate Phase = "certificate"
	PhaseComplete    Phase = "complete"
)

// Config controls one TLS probe. A zero Config is valid and uses the system
// certificate roots and DefaultTimeout. TLSConfig is cloned before use; the
// probe always sets ServerName from the target and never enables
// InsecureSkipVerify.
type Config struct {
	Timeout time.Duration
	Dialer  *net.Dialer
	// DialContext is primarily useful for deterministic callers/tests that
	// already own a transport. When nil, Dialer (or net.Dialer) is used.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	TLSConfig   *tls.Config
}

// Probe performs a TLS handshake against the target supplied to Run.
type Probe struct {
	Config Config
}

// TLSProbe is an alias useful when several probe implementations are imported
// together. Probe remains the primary name and implements probe.Probe.
type TLSProbe = Probe

var _ probe.Probe = Probe{}

// New returns a TLS probe configured with cfg.
func New(cfg Config) *Probe { return &Probe{Config: cfg} }

// NewProbe returns a TLS probe. With no argument it uses default settings.
func NewProbe(cfg ...Config) *Probe {
	if len(cfg) == 0 {
		return New(Config{})
	}
	return New(cfg[0])
}

// NewWithTimeout returns a TLS probe with a complete-operation timeout.
func NewWithTimeout(timeout time.Duration) *Probe {
	return New(Config{Timeout: timeout})
}

// Run is a convenience function for callers that do not need a reusable
// configured probe.
func Run(ctx context.Context, target model.Target) model.ProbeResult {
	return New(Config{}).Run(ctx, probe.ExecutionContext{Target: target})
}

// Name implements probe.Probe.
func (p Probe) Name() string { return "tls" }

// HandshakeEvidence is the safe, JSON-serializable observation for the TLS
// and transport phases. It contains negotiated metadata but no key material
// or raw certificate bytes.
type HandshakeEvidence struct {
	Phase                Phase  `json:"phase"`
	Address              string `json:"address"`
	ServerName           string `json:"server_name,omitempty"`
	NegotiatedProtocol   string `json:"negotiated_protocol,omitempty"`
	NegotiatedProtocolID string `json:"negotiated_protocol_id,omitempty"`
	CipherSuite          string `json:"cipher_suite,omitempty"`
	CipherSuiteID        uint16 `json:"cipher_suite_id,omitempty"`
	TLSVersion           string `json:"tls_version,omitempty"`
	TLSVersionID         uint16 `json:"tls_version_id,omitempty"`
	HandshakeComplete    bool   `json:"handshake_complete"`
	PeerCertificateCount int    `json:"peer_certificate_count"`
	ErrorType            string `json:"error_type,omitempty"`
	Error                string `json:"error,omitempty"`
}

// CertificateMetadata is the safe metadata retained for one peer
// certificate. Raw DER/PEM and public-key bytes are intentionally omitted.
type CertificateMetadata struct {
	ChainIndex         int      `json:"chain_index"`
	Subject            string   `json:"subject,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	Version            int      `json:"version,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	IsCA               bool     `json:"is_ca"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	SHA256             string   `json:"sha256,omitempty"`
}

// Run executes a bounded TCP setup followed by a verified TLS handshake.
// Expected endpoint failures are returned as Failed results with structured
// evidence; malformed input or an unusable configuration is returned as an
// Error result.
func (p Probe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	started := time.Now()
	target := execution.Target
	result := model.ProbeResult{
		Name:   p.Name(),
		Target: target,
		Status: model.ProbeStatusError,
		Timing: model.Timing{StartedAt: &started},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonProbeExecution,
			Layer:         model.LayerTLS,
			FaultDomain:   model.FaultDomainTLS,
		},
	}
	host, address, err := targetAddress(target)
	if err != nil {
		return finishResult(result, started, nil, errReason(model.FailureReasonProbeExecution, err))
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return finishResult(result, started, handshakeObservation(PhaseTransport, address, host, err), interpretationFor(err, PhaseTransport))
	}

	timeout := p.Config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialContext := p.Config.DialContext
	if dialContext == nil {
		dialer := net.Dialer{}
		if p.Config.Dialer != nil {
			dialer = *p.Config.Dialer
		}
		dialContext = dialer.DialContext
	}
	conn, err := dialContext(runCtx, "tcp", address)
	if err != nil {
		return finishResult(result, started, handshakeObservation(PhaseTransport, address, host, err), interpretationForDialError(runCtx, err))
	}

	// Closing the raw connection also unblocks any operation if the context
	// expires while the TLS implementation is waiting for a record.
	defer conn.Close()
	deadline, hasDeadline := runCtx.Deadline()
	if hasDeadline {
		_ = conn.SetDeadline(deadline)
	}

	config := p.tlsConfig(host)
	tlsConn := tls.Client(conn, config)
	handshakeErr := tlsConn.HandshakeContext(runCtx)
	state := tlsConn.ConnectionState()
	chain := state.PeerCertificates
	if len(chain) == 0 {
		if verificationErr := new(tls.CertificateVerificationError); errors.As(handshakeErr, &verificationErr) {
			chain = verificationErr.UnverifiedCertificates
		}
	}
	if handshakeErr != nil {
		observation := handshakeObservation(PhaseHandshake, address, host, handshakeErr)
		observation.NegotiatedProtocol = state.NegotiatedProtocol
		observation.NegotiatedProtocolID = state.NegotiatedProtocol
		observation.CipherSuiteID = state.CipherSuite
		observation.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		observation.TLSVersionID = state.Version
		observation.TLSVersion = tlsVersionName(state.Version)
		observation.HandshakeComplete = state.HandshakeComplete
		observation.PeerCertificateCount = len(chain)
		result.Evidence = append(result.Evidence, evidence("tls-handshake", model.EvidenceKindTLSHandshake, observation))
		result.Evidence = appendCertificates(result.Evidence, chain)
		return finishResult(result, started, nil, interpretationForHandshake(runCtx, handshakeErr))
	}

	// Keep the connection bounded even after a successful handshake while we
	// read its state, then remove the deadline before closing it.
	_ = tlsConn.SetDeadline(time.Time{})
	observation := &HandshakeEvidence{
		Phase:                PhaseComplete,
		Address:              address,
		ServerName:           host,
		NegotiatedProtocol:   state.NegotiatedProtocol,
		NegotiatedProtocolID: state.NegotiatedProtocol,
		CipherSuite:          tls.CipherSuiteName(state.CipherSuite),
		CipherSuiteID:        state.CipherSuite,
		TLSVersion:           tlsVersionName(state.Version),
		TLSVersionID:         state.Version,
		HandshakeComplete:    state.HandshakeComplete,
		PeerCertificateCount: len(state.PeerCertificates),
	}
	result.Evidence = append(result.Evidence, evidence("tls-handshake", model.EvidenceKindTLSHandshake, observation))
	result.Evidence = appendCertificates(result.Evidence, state.PeerCertificates)
	result.Status = model.ProbeStatusPassed
	result.Interpretation = model.ProbeInterpretation{
		FailureReason: model.FailureReasonNone,
		Layer:         model.LayerTLS,
		FaultDomain:   model.FaultDomainTLS,
	}
	return finishResult(result, started, nil, result.Interpretation)
}

func (p Probe) tlsConfig(host string) *tls.Config {
	config := &tls.Config{}
	if p.Config.TLSConfig != nil {
		config = p.Config.TLSConfig.Clone()
	}
	config.ServerName = host
	// A caller-supplied insecure setting must not silently turn the normal
	// diagnostic probe into an unauthenticated TLS check.
	config.InsecureSkipVerify = false
	return config
}

func targetAddress(target model.Target) (string, string, error) {
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return "", "", errors.New("target host is required")
	}
	if target.Port == 0 {
		return "", "", errors.New("target port is required")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return host, net.JoinHostPort(host, strconv.Itoa(int(target.Port))), nil
}

func handshakeObservation(phase Phase, address, host string, err error) *HandshakeEvidence {
	observation := &HandshakeEvidence{
		Phase:      phase,
		Address:    address,
		ServerName: host,
	}
	if err != nil {
		observation.ErrorType = fmt.Sprintf("%T", err)
		observation.Error = err.Error()
	}
	return observation
}

func evidence(id string, kind model.EvidenceKind, value any) model.Evidence {
	raw, err := json.Marshal(value)
	if err != nil {
		// All values passed here are local structs. Keep the contract valid even
		// if that ever changes and a marshal error is introduced.
		raw = json.RawMessage(`{"error":"unable to encode TLS evidence"}`)
	}
	return model.Evidence{ID: id, Kind: kind, Source: "crypto/tls", Raw: raw}
}

func appendCertificates(evidenceList []model.Evidence, chain []*x509.Certificate) []model.Evidence {
	for i, cert := range chain {
		if cert == nil {
			continue
		}
		metadata := certificateMetadata(i, cert)
		evidenceList = append(evidenceList, evidence(fmt.Sprintf("tls-certificate-%d", i+1), model.EvidenceKindCertificate, metadata))
	}
	return evidenceList
}

func certificateMetadata(index int, cert *x509.Certificate) CertificateMetadata {
	digest := sha256.Sum256(cert.Raw)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return CertificateMetadata{
		ChainIndex:         index,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		Version:            cert.Version,
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:           append([]string(nil), cert.DNSNames...),
		IPAddresses:        ips,
		EmailAddresses:     append([]string(nil), cert.EmailAddresses...),
		IsCA:               cert.IsCA,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SHA256:             hex.EncodeToString(digest[:]),
	}
}

func finishResult(result model.ProbeResult, started time.Time, observation *HandshakeEvidence, interpretation model.ProbeInterpretation) model.ProbeResult {
	if observation != nil {
		result.Evidence = append(result.Evidence, evidence("tls-handshake", model.EvidenceKindTLSHandshake, observation))
	}
	completed := time.Now()
	result.Timing.StartedAt = &started
	result.Timing.CompletedAt = &completed
	result.Timing.DurationMS = completed.Sub(started).Milliseconds()
	result.Interpretation = interpretation
	if interpretation.FailureReason == model.FailureReasonNone {
		result.Status = model.ProbeStatusPassed
	} else if result.Status == model.ProbeStatusError && observation != nil {
		result.Status = model.ProbeStatusFailed
	}
	return result
}

func errReason(reason model.FailureReason, _ error) model.ProbeInterpretation {
	return model.ProbeInterpretation{FailureReason: reason, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTLS}
}

func interpretationFor(err error, phase Phase) model.ProbeInterpretation {
	if errors.Is(err, context.Canceled) {
		return model.ProbeInterpretation{FailureReason: FailureReasonCancellation, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTLS}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if phase == PhaseHandshake {
			return model.ProbeInterpretation{FailureReason: FailureReasonTLSTimeout, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTLS}
		}
		return model.ProbeInterpretation{FailureReason: FailureReasonTransportFailure, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTransport}
	}
	return model.ProbeInterpretation{FailureReason: FailureReasonTransportFailure, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTransport}
}

func interpretationForDialError(ctx context.Context, err error) model.ProbeInterpretation {
	if ctx.Err() != nil {
		return interpretationFor(ctx.Err(), PhaseTransport)
	}
	return interpretationFor(err, PhaseTransport)
}

func interpretationForHandshake(ctx context.Context, err error) model.ProbeInterpretation {
	if ctx.Err() != nil {
		return interpretationFor(ctx.Err(), PhaseHandshake)
	}
	if errors.Is(err, context.Canceled) {
		return interpretationFor(context.Canceled, PhaseHandshake)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return interpretationFor(context.DeadlineExceeded, PhaseHandshake)
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		if certInvalid.Reason == x509.Expired {
			return tlsInterpretation(FailureReasonCertificateExpired)
		}
		return tlsInterpretation(model.FailureReasonCertificateValidationFailure)
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return tlsInterpretation(FailureReasonCertificateHostnameMismatch)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return tlsInterpretation(FailureReasonUnknownAuthority)
	}
	var timeoutErr net.Error
	if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
		return tlsInterpretation(FailureReasonTLSTimeout)
	}
	return tlsInterpretation(model.FailureReasonTLSHandshakeFailure)
}

func tlsInterpretation(reason model.FailureReason) model.ProbeInterpretation {
	return model.ProbeInterpretation{FailureReason: reason, Layer: model.LayerTLS, FaultDomain: model.FaultDomainTLS}
}

func tlsVersionName(version uint16) string {
	if version == 0 {
		return ""
	}
	return tls.VersionName(version)
}
