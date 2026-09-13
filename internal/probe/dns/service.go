package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	// DiagnosticQueryName and DiagnosticQueryType identify the one bounded
	// application query. Recursion is not requested, so the query is useful
	// with deterministic authoritative or fixture servers and does not depend
	// on a public recursive resolver.
	DiagnosticQueryName     = "tadori.diagnostic."
	DiagnosticQueryType     = "A"
	DiagnosticQueryTypeCode = uint16(1)

	diagnosticQueryClassCode = uint16(1)
	defaultServiceTimeout    = 2 * time.Second
	defaultServiceRetries    = 1
	maxServiceRetries        = 2
	maxServiceMessageSize    = 4096
	maxServiceErrorLength    = 256
	serviceProbeName         = "dns_service"
)

// ServiceProbeName is the stable name of the DNS application lane.
const ServiceProbeName = serviceProbeName

// MaxDNSServiceMessageSize is the maximum DNS message retained in memory by
// the service probe. Only wire metadata is emitted as evidence.
const MaxDNSServiceMessageSize = maxServiceMessageSize

// DNS service failures are deliberately package-owned extensions. They keep
// target name-resolution failures separate from failures observed while the
// target itself is queried as a DNS server.
const (
	FailureReasonDNSServiceTransportFailure  model.FailureReason = "dns_service_transport_failure"
	FailureReasonDNSServiceProtocolFailure   model.FailureReason = "dns_service_protocol_failure"
	FailureReasonDNSServiceRefused           model.FailureReason = "dns_service_refused"
	FailureReasonDNSServiceServfail          model.FailureReason = "dns_service_servfail"
	FailureReasonDNSServiceTimeout           model.FailureReason = "dns_service_timeout"
	FailureReasonDNSServiceMalformedResponse model.FailureReason = "dns_service_malformed_response"
	FailureReasonDNSServiceTruncatedResponse model.FailureReason = "dns_service_truncated_response"
	FailureReasonDNSServiceNoEndpoint        model.FailureReason = "dns_service_no_resolved_endpoint"
	FailureReasonDNSServiceCancellation      model.FailureReason = "dns_service_cancellation"
)

// DNSServiceOutcome is the wire-level classification of one transport lane.
type DNSServiceOutcome string

const (
	DNSServiceOutcomeUnknown            DNSServiceOutcome = "unknown"
	DNSServiceOutcomeSuccess            DNSServiceOutcome = "success"
	DNSServiceOutcomeNegativeResponse   DNSServiceOutcome = "negative_response"
	DNSServiceOutcomeRefused            DNSServiceOutcome = "refused"
	DNSServiceOutcomeServfail           DNSServiceOutcome = "servfail"
	DNSServiceOutcomeProtocolFailure    DNSServiceOutcome = "protocol_failure"
	DNSServiceOutcomeMalformedResponse  DNSServiceOutcome = "malformed_response"
	DNSServiceOutcomeTruncatedResponse  DNSServiceOutcome = "truncated_response"
	DNSServiceOutcomeTimeout            DNSServiceOutcome = "timeout"
	DNSServiceOutcomeTransportFailure   DNSServiceOutcome = "transport_failure"
	DNSServiceOutcomeNotAttempted       DNSServiceOutcome = "not_attempted"
	DNSServiceOutcomeCancellation       DNSServiceOutcome = "cancellation"
	DNSServiceOutcomeNoResolvedEndpoint DNSServiceOutcome = "no_resolved_endpoint"
)

// ServiceDialer is the small network boundary used by DNSServiceProbe. It
// permits deterministic connection fixtures without changing the production
// wire implementation.
type ServiceDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ServiceDialerFunc adapts a function into a ServiceDialer.
type ServiceDialerFunc func(context.Context, string, string) (net.Conn, error)

// DialContext implements ServiceDialer.
func (f ServiceDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// DNSServiceOption configures a DNS service probe.
type DNSServiceOption func(*DNSServiceProbe)

// DNSServiceProbe performs one deterministic DNS application query over UDP
// and one over TCP. It expects target resolution to have already been
// observed by the separate dns probe when the target is a hostname.
type DNSServiceProbe struct {
	timeout time.Duration
	retries int
	dialer  ServiceDialer
	now     func() time.Time
}

// NewService constructs a bounded DNS service probe.
func NewService(opts ...DNSServiceOption) *DNSServiceProbe {
	p := &DNSServiceProbe{
		timeout: defaultServiceTimeout,
		retries: defaultServiceRetries,
		dialer:  &net.Dialer{},
		now:     time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	if p.timeout <= 0 {
		p.timeout = defaultServiceTimeout
	}
	if p.retries < 0 {
		p.retries = 0
	}
	if p.retries > maxServiceRetries {
		p.retries = maxServiceRetries
	}
	if p.dialer == nil {
		p.dialer = &net.Dialer{}
	}
	if p.now == nil {
		p.now = time.Now
	}
	return p
}

// NewDNSServiceProbe is the explicit constructor name for callers that want
// to distinguish this application probe from the resolver probe.
func NewDNSServiceProbe(opts ...DNSServiceOption) *DNSServiceProbe { return NewService(opts...) }

// NewServiceProbe is a compatibility-oriented constructor alias.
func NewServiceProbe(opts ...DNSServiceOption) *DNSServiceProbe { return NewService(opts...) }

// WithServiceTimeout bounds the complete UDP/TCP service check.
func WithServiceTimeout(timeout time.Duration) DNSServiceOption {
	return func(p *DNSServiceProbe) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// WithServiceRetries sets the bounded number of retries after the first
// attempt for each candidate and transport.
func WithServiceRetries(retries int) DNSServiceOption {
	return func(p *DNSServiceProbe) { p.retries = retries }
}

// WithServiceDialer injects the transport used by the service probe.
func WithServiceDialer(dialer ServiceDialer) DNSServiceOption {
	return func(p *DNSServiceProbe) { p.dialer = dialer }
}

// WithServiceNow injects the clock used for deterministic timing fixtures.
func WithServiceNow(now func() time.Time) DNSServiceOption {
	return func(p *DNSServiceProbe) {
		if now != nil {
			p.now = now
		}
	}
}

// Name implements probe.Probe.
func (*DNSServiceProbe) Name() string { return serviceProbeName }

var _ probe.Probe = (*DNSServiceProbe)(nil)

var serviceTransactionID atomic.Uint32

// DNSServiceAttempt is bounded per-attempt metadata. It never carries the
// DNS payload, answer names, or arbitrary server data.
type DNSServiceAttempt struct {
	Candidate             string            `json:"candidate"`
	RequestedEndpoint     string            `json:"requested_endpoint"`
	Attempt               int               `json:"attempt"`
	ResponseReceived      bool              `json:"response_received"`
	ResponseBytes         int               `json:"response_bytes,omitempty"`
	QuestionCount         int               `json:"question_count,omitempty"`
	AnswerCount           int               `json:"answer_count,omitempty"`
	AuthorityCount        int               `json:"authority_count,omitempty"`
	AdditionalCount       int               `json:"additional_count,omitempty"`
	TransactionID         uint16            `json:"transaction_id,omitempty"`
	ResponseTransactionID uint16            `json:"response_transaction_id,omitempty"`
	RCode                 int               `json:"rcode,omitempty"`
	RCodeName             string            `json:"rcode_name,omitempty"`
	Truncated             bool              `json:"truncated,omitempty"`
	Outcome               DNSServiceOutcome `json:"outcome"`
	Success               bool              `json:"success"`
	ErrorKind             string            `json:"error_kind,omitempty"`
	Error                 string            `json:"error,omitempty"`
	ErrorType             string            `json:"error_type,omitempty"`
	Endpoint              string            `json:"endpoint,omitempty"`
}

// DNSServiceEvidence is one metadata-only observation for either UDP or TCP.
// Keeping one record per transport preserves divergence for the canonical
// application projector and for diagnosis consumers.
type DNSServiceEvidence struct {
	Transport             string              `json:"transport"`
	RequestedEndpoint     string              `json:"requested_endpoint"`
	ResolvedAddress       string              `json:"resolved_address,omitempty"`
	Endpoint              string              `json:"endpoint,omitempty"`
	Port                  uint16              `json:"port"`
	QueryName             string              `json:"query_name"`
	QueryType             string              `json:"query_type"`
	TransactionID         uint16              `json:"transaction_id,omitempty"`
	ResponseTransactionID uint16              `json:"response_transaction_id,omitempty"`
	QueryBytes            int                 `json:"query_bytes,omitempty"`
	ResponseReceived      bool                `json:"response_received"`
	ResponseBytes         int                 `json:"response_bytes,omitempty"`
	QuestionCount         int                 `json:"question_count,omitempty"`
	AnswerCount           int                 `json:"answer_count,omitempty"`
	AuthorityCount        int                 `json:"authority_count,omitempty"`
	AdditionalCount       int                 `json:"additional_count,omitempty"`
	RCode                 int                 `json:"rcode,omitempty"`
	RCodeName             string              `json:"rcode_name,omitempty"`
	Truncated             bool                `json:"truncated,omitempty"`
	Outcome               DNSServiceOutcome   `json:"outcome"`
	Success               bool                `json:"success"`
	Attempts              int                 `json:"attempts"`
	CandidateAttempts     []DNSServiceAttempt `json:"candidate_attempts,omitempty"`
	Fallback              bool                `json:"fallback,omitempty"`
	FallbackReason        string              `json:"fallback_reason,omitempty"`
	ErrorKind             string              `json:"error_kind,omitempty"`
	Error                 string              `json:"error,omitempty"`
	ErrorType             string              `json:"error_type,omitempty"`
	DurationMS            int64               `json:"duration_ms"`
}

// DNSServiceObservation is a descriptive alias for the raw service evidence
// contract used by callers that prefer observation terminology.
type DNSServiceObservation = DNSServiceEvidence

// Run performs the two independent service queries. A successful response on
// either transport keeps the overall service result from claiming that the
// destination is unavailable; the per-transport evidence remains explicit.
func (p *DNSServiceProbe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	started := p.clockNow()
	target := model.NormalizeTarget(execution.Target)
	result := model.ProbeResult{
		Name:   serviceProbeName,
		Target: target,
		Status: model.ProbeStatusError,
		Interpretation: model.ProbeInterpretation{
			FailureReason: FailureReasonDNSServiceNoEndpoint,
			Layer:         model.LayerDNS,
			FaultDomain:   model.FaultDomainDNS,
		},
	}
	finish := func() model.ProbeResult {
		completed := p.clockNow()
		result.Timing.StartedAt = &started
		result.Timing.CompletedAt = &completed
		result.Timing.DurationMS = completed.Sub(started).Milliseconds()
		if result.Timing.DurationMS < 0 {
			result.Timing.DurationMS = 0
		}
		return result
	}

	requestedEndpoint := requestedServiceEndpoint(target)
	queryID := nextTransactionID()
	query, queryErr := buildDiagnosticQuery(queryID)
	if queryErr != nil {
		result.Interpretation.FailureReason = FailureReasonDNSServiceProtocolFailure
		result.Evidence = serviceFailureEvidence(target, requestedEndpoint, queryID, queryErr)
		return finish()
	}

	candidates := target.ProbeEndpointCandidates()
	if len(candidates) > model.MaxEndpointCandidates {
		candidates = candidates[:model.MaxEndpointCandidates]
	}
	if len(candidates) == 0 {
		result.Evidence = []model.Evidence{
			serviceNotAttemptedEvidence("udp", target, requestedEndpoint, queryID, len(query), FailureReasonDNSServiceNoEndpoint, DNSServiceOutcomeNoResolvedEndpoint),
			serviceNotAttemptedEvidence("tcp", target, requestedEndpoint, queryID, len(query), FailureReasonDNSServiceNoEndpoint, DNSServiceOutcomeNoResolvedEndpoint),
		}
		return finish()
	}

	if err := ctx.Err(); err != nil {
		reason := FailureReasonDNSServiceCancellation
		outcome := DNSServiceOutcomeCancellation
		if errors.Is(err, context.DeadlineExceeded) {
			reason = FailureReasonDNSServiceTimeout
			outcome = DNSServiceOutcomeTimeout
		}
		result.Interpretation.FailureReason = reason
		result.Evidence = []model.Evidence{
			serviceNotAttemptedEvidence("udp", target, requestedEndpoint, queryID, len(query), reason, outcome),
			serviceNotAttemptedEvidence("tcp", target, requestedEndpoint, queryID, len(query), reason, outcome),
		}
		return finish()
	}

	serviceCtx, cancel := context.WithTimeout(ctx, boundedServiceTimeout(p.timeout))
	defer cancel()
	laneBudget := boundedServiceTimeout(p.timeout) / 2
	if laneBudget <= 0 {
		laneBudget = time.Nanosecond
	}
	udp := p.runTransport(serviceCtx, target, candidates, "udp", query, queryID, laneBudget, false, "")
	fallback := udp.ResponseReceived && !udp.Success
	fallbackReason := ""
	if fallback {
		fallbackReason = "udp_" + string(udp.Outcome)
	}
	tcp := p.runTransport(serviceCtx, target, candidates, "tcp", query, queryID, laneBudget, fallback, fallbackReason)
	result.Evidence = []model.Evidence{
		{ID: "dns-service/udp", Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustJSON(udp)},
		{ID: "dns-service/tcp", Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustJSON(tcp)},
	}
	if udp.Success || tcp.Success {
		result.Status = model.ProbeStatusPassed
		result.Interpretation.FailureReason = model.FailureReasonNone
	} else {
		result.Status = model.ProbeStatusFailed
		result.Interpretation.FailureReason = serviceFailureReason(udp, tcp)
		if udp.Outcome == DNSServiceOutcomeCancellation && tcp.Outcome == DNSServiceOutcomeCancellation {
			result.Status = model.ProbeStatusError
		}
	}
	if endpoint := successfulServiceEndpoint(udp, tcp, target.Port); endpoint != nil {
		target.TestedEndpoint = endpoint
		result.Target = target
	}
	return finish()
}

func (p *DNSServiceProbe) runTransport(ctx context.Context, target model.Target, candidates []model.EndpointCandidate, transport string, query []byte, queryID uint16, budget time.Duration, fallback bool, fallbackReason string) DNSServiceEvidence {
	started := p.clockNow()
	evidence := DNSServiceEvidence{
		Transport:         transport,
		RequestedEndpoint: requestedServiceEndpoint(target),
		Port:              target.Port,
		QueryName:         DiagnosticQueryName,
		QueryType:         DiagnosticQueryType,
		QueryBytes:        len(query),
		Outcome:           DNSServiceOutcomeUnknown,
		Fallback:          fallback,
		FallbackReason:    fallbackReason,
	}
	if err := ctx.Err(); err != nil {
		evidence.Outcome = DNSServiceOutcomeCancellation
		evidence.ErrorKind = serviceErrorKind(err)
		evidence.Error = boundedServiceError(err)
		evidence.ErrorType = fmt.Sprintf("%T", err)
		evidence.DurationMS = p.durationMS(started)
		return evidence
	}

	maxAttempts := p.retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	attemptBudget := budget / time.Duration(len(candidates)*maxAttempts)
	if attemptBudget <= 0 {
		attemptBudget = time.Nanosecond
	}
	transportCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var best DNSServiceAttempt
	bestSet := false
	bestRank := -1
	for candidateIndex, candidate := range candidates {
		candidate = normalizeServiceCandidate(candidate, candidateIndex+1)
		if candidate.Address == "" {
			continue
		}
		if address, err := netip.ParseAddr(candidate.Address); err != nil {
			requested := net.JoinHostPort(candidate.Address, fmt.Sprintf("%d", target.Port))
			attempt := failedServiceAttempt(candidate.Address, requested, 1, errors.New("endpoint candidate is not a resolved IP address"), "unresolved_endpoint", DNSServiceOutcomeTransportFailure)
			evidence.CandidateAttempts = append(evidence.CandidateAttempts, attempt)
			evidence.Attempts++
			if !bestSet || serviceAttemptRank(attempt.Outcome) > bestRank {
				best, bestSet, bestRank = attempt, true, serviceAttemptRank(attempt.Outcome)
			}
			continue
		} else {
			candidate.Address = model.NormalizeAddr(address).String()
		}
		requested := net.JoinHostPort(candidate.Address, fmt.Sprintf("%d", target.Port))
		for retry := 0; retry < maxAttempts; retry++ {
			if err := transportCtx.Err(); err != nil {
				attempt := failedServiceAttempt(candidate.Address, requested, retry+1, err, serviceErrorKind(err), serviceOutcomeForError(err))
				evidence.CandidateAttempts = append(evidence.CandidateAttempts, attempt)
				evidence.Attempts++
				if !bestSet || serviceAttemptRank(attempt.Outcome) > bestRank {
					best, bestSet, bestRank = attempt, true, serviceAttemptRank(attempt.Outcome)
				}
				break
			}
			attemptCtx, attemptCancel := context.WithTimeout(transportCtx, attemptBudget)
			attempt := p.queryTransport(attemptCtx, transport, requested, candidate.Address, query, queryID, retry+1)
			attemptCancel()
			evidence.CandidateAttempts = append(evidence.CandidateAttempts, attempt)
			evidence.Attempts++
			if attempt.Success {
				p.copyAttemptToEvidence(&evidence, attempt)
				evidence.Success = true
				evidence.Outcome = attempt.Outcome
				evidence.DurationMS = p.durationMS(started)
				return evidence
			}
			if !bestSet || serviceAttemptRank(attempt.Outcome) > bestRank {
				best, bestSet, bestRank = attempt, true, serviceAttemptRank(attempt.Outcome)
			}
		}
	}
	if bestSet {
		p.copyAttemptToEvidence(&evidence, best)
	} else {
		evidence.Outcome = DNSServiceOutcomeTransportFailure
		evidence.ErrorKind = "invalid_endpoint"
		evidence.Error = "no usable endpoint candidate"
	}
	evidence.DurationMS = p.durationMS(started)
	return evidence
}

func (p *DNSServiceProbe) queryTransport(ctx context.Context, transport, requested, candidate string, query []byte, queryID uint16, attemptNumber int) DNSServiceAttempt {
	attempt := DNSServiceAttempt{
		Candidate:         candidate,
		RequestedEndpoint: requested,
		Attempt:           attemptNumber,
		TransactionID:     queryID,
		Outcome:           DNSServiceOutcomeUnknown,
	}
	conn, err := p.dialer.DialContext(ctx, transport, requested)
	if err != nil {
		attempt.ErrorKind = serviceErrorKind(err)
		attempt.Error = boundedServiceError(err)
		attempt.ErrorType = fmt.Sprintf("%T", err)
		attempt.Outcome = serviceOutcomeForError(err)
		return attempt
	}
	if conn == nil {
		err = errors.New("dialer returned nil connection")
		attempt.ErrorKind = "transport_failure"
		attempt.Error = err.Error()
		attempt.ErrorType = fmt.Sprintf("%T", err)
		attempt.Outcome = DNSServiceOutcomeTransportFailure
		return attempt
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	attempt.Endpoint = endpointString(conn.RemoteAddr())
	if err := writeServiceMessage(conn, transport, query); err != nil {
		attempt.ErrorKind = serviceErrorKind(err)
		attempt.Error = boundedServiceError(err)
		attempt.ErrorType = fmt.Sprintf("%T", err)
		attempt.Outcome = serviceOutcomeForError(err)
		return attempt
	}
	var response []byte
	if transport == "udp" {
		response = make([]byte, maxServiceMessageSize)
		n, readErr := conn.Read(response)
		if readErr != nil {
			attempt.ErrorKind = serviceErrorKind(readErr)
			attempt.Error = boundedServiceError(readErr)
			attempt.ErrorType = fmt.Sprintf("%T", readErr)
			attempt.Outcome = serviceOutcomeForError(readErr)
			return attempt
		}
		response = response[:n]
	} else {
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			attempt.ErrorKind = serviceErrorKind(err)
			attempt.Error = boundedServiceError(err)
			attempt.ErrorType = fmt.Sprintf("%T", err)
			attempt.Outcome = serviceOutcomeForError(err)
			return attempt
		}
		responseLength := int(binary.BigEndian.Uint16(length[:]))
		if responseLength == 0 || responseLength > maxServiceMessageSize {
			attempt.ResponseReceived = true
			attempt.ResponseBytes = responseLength
			attempt.ErrorKind = "message_size"
			attempt.Error = "DNS TCP response length is outside the bounded packet size"
			attempt.Outcome = DNSServiceOutcomeMalformedResponse
			return attempt
		}
		response = make([]byte, responseLength)
		if _, err := io.ReadFull(conn, response); err != nil {
			attempt.ResponseReceived = true
			attempt.ResponseBytes = len(response)
			attempt.ErrorKind = "malformed_response"
			attempt.Error = boundedServiceError(err)
			attempt.ErrorType = fmt.Sprintf("%T", err)
			attempt.Outcome = DNSServiceOutcomeMalformedResponse
			return attempt
		}
	}
	attempt.ResponseReceived = true
	attempt.ResponseBytes = len(response)
	if len(response) >= 12 {
		attempt.ResponseTransactionID = binary.BigEndian.Uint16(response[0:2])
		attempt.RCode = int(binary.BigEndian.Uint16(response[2:4]) & 0x000f)
		attempt.RCodeName = rcodeName(attempt.RCode)
		attempt.QuestionCount = int(binary.BigEndian.Uint16(response[4:6]))
		attempt.AnswerCount = int(binary.BigEndian.Uint16(response[6:8]))
		attempt.AuthorityCount = int(binary.BigEndian.Uint16(response[8:10]))
		attempt.AdditionalCount = int(binary.BigEndian.Uint16(response[10:12]))
		attempt.Truncated = binary.BigEndian.Uint16(response[2:4])&0x0200 != 0
	}
	parsed, parseErr := parseDiagnosticResponse(response, queryID)
	if parseErr != nil {
		attempt.ErrorKind = diagnosticResponseErrorKind(parseErr)
		attempt.Error = boundedServiceError(parseErr)
		attempt.ErrorType = fmt.Sprintf("%T", parseErr)
		attempt.Outcome = diagnosticResponseOutcome(parseErr)
		return attempt
	}
	attempt.QuestionCount = parsed.QuestionCount
	attempt.AnswerCount = parsed.AnswerCount
	attempt.AuthorityCount = parsed.AuthorityCount
	attempt.AdditionalCount = parsed.AdditionalCount
	attempt.RCode = parsed.RCode
	attempt.RCodeName = parsed.RCodeName
	attempt.Truncated = parsed.Truncated
	attempt.Outcome = parsed.Outcome
	attempt.Success = parsed.Success
	return attempt
}

func writeServiceMessage(conn net.Conn, transport string, query []byte) error {
	if transport == "tcp" {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(query)))
		if err := writeAll(conn, length[:]); err != nil {
			return err
		}
	}
	return writeAll(conn, query)
}

func writeAll(conn net.Conn, value []byte) error {
	for len(value) > 0 {
		n, err := conn.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}

func (p *DNSServiceProbe) copyAttemptToEvidence(evidence *DNSServiceEvidence, attempt DNSServiceAttempt) {
	evidence.ResolvedAddress = attempt.Candidate
	evidence.Endpoint = attempt.Endpoint
	evidence.TransactionID = attempt.TransactionID
	evidence.ResponseTransactionID = attempt.ResponseTransactionID
	evidence.ResponseReceived = attempt.ResponseReceived
	evidence.ResponseBytes = attempt.ResponseBytes
	evidence.QuestionCount = attempt.QuestionCount
	evidence.AnswerCount = attempt.AnswerCount
	evidence.AuthorityCount = attempt.AuthorityCount
	evidence.AdditionalCount = attempt.AdditionalCount
	evidence.RCode = attempt.RCode
	evidence.RCodeName = attempt.RCodeName
	evidence.Truncated = attempt.Truncated
	evidence.Outcome = attempt.Outcome
	evidence.ErrorKind = attempt.ErrorKind
	evidence.Error = attempt.Error
	evidence.ErrorType = attempt.ErrorType
}

func successfulServiceEndpoint(udp, tcp DNSServiceEvidence, port uint16) *model.Endpoint {
	for _, evidence := range []DNSServiceEvidence{udp, tcp} {
		if !evidence.Success || evidence.ResolvedAddress == "" {
			continue
		}
		address, err := netip.ParseAddr(evidence.ResolvedAddress)
		if err != nil {
			continue
		}
		family := model.EndpointFamilyIPv6
		if address.Is4() {
			family = model.EndpointFamilyIPv4
		}
		return &model.Endpoint{Address: model.NormalizeAddr(address).String(), Port: port, Family: family, SelectionReason: model.EndpointSelectionTransport, Provenance: "DNS service response endpoint", Certainty: model.ObservationCertaintyObserved}
	}
	return nil
}

func serviceFailureReason(udp, tcp DNSServiceEvidence) model.FailureReason {
	for _, evidence := range []DNSServiceEvidence{udp, tcp} {
		if reason := serviceEvidenceFailureReason(evidence); reason != model.FailureReasonUnknown {
			return reason
		}
	}
	return FailureReasonDNSServiceTransportFailure
}

func serviceEvidenceFailureReason(evidence DNSServiceEvidence) model.FailureReason {
	switch evidence.Outcome {
	case DNSServiceOutcomeRefused:
		return FailureReasonDNSServiceRefused
	case DNSServiceOutcomeServfail:
		return FailureReasonDNSServiceServfail
	case DNSServiceOutcomeProtocolFailure:
		return FailureReasonDNSServiceProtocolFailure
	case DNSServiceOutcomeMalformedResponse:
		return FailureReasonDNSServiceMalformedResponse
	case DNSServiceOutcomeTruncatedResponse:
		return FailureReasonDNSServiceTruncatedResponse
	case DNSServiceOutcomeTimeout:
		return FailureReasonDNSServiceTimeout
	case DNSServiceOutcomeCancellation:
		return FailureReasonDNSServiceCancellation
	case DNSServiceOutcomeNoResolvedEndpoint:
		return FailureReasonDNSServiceNoEndpoint
	case DNSServiceOutcomeTransportFailure:
		return FailureReasonDNSServiceTransportFailure
	default:
		return model.FailureReasonUnknown
	}
}

func failedServiceAttempt(candidate, requested string, number int, err error, kind string, outcome DNSServiceOutcome) DNSServiceAttempt {
	return DNSServiceAttempt{Candidate: candidate, RequestedEndpoint: requested, Attempt: number, Outcome: outcome, ErrorKind: kind, Error: boundedServiceError(err), ErrorType: fmt.Sprintf("%T", err)}
}

func serviceAttemptRank(outcome DNSServiceOutcome) int {
	switch outcome {
	case DNSServiceOutcomeRefused, DNSServiceOutcomeServfail, DNSServiceOutcomeProtocolFailure:
		return 5
	case DNSServiceOutcomeMalformedResponse, DNSServiceOutcomeTruncatedResponse:
		return 4
	case DNSServiceOutcomeTimeout:
		return 3
	case DNSServiceOutcomeTransportFailure:
		return 2
	case DNSServiceOutcomeCancellation:
		return 1
	default:
		return 0
	}
}

func requestedServiceEndpoint(target model.Target) string {
	if target.Port == 0 || target.RequestedIdentity == "" {
		return target.RequestedIdentity
	}
	return net.JoinHostPort(target.RequestedIdentity, fmt.Sprintf("%d", target.Port))
}

func normalizeServiceCandidate(candidate model.EndpointCandidate, order int) model.EndpointCandidate {
	candidate.Address = strings.Trim(strings.TrimSpace(candidate.Address), "[]")
	if address, err := netip.ParseAddr(candidate.Address); err == nil {
		candidate.Address = model.NormalizeAddr(address).String()
	}
	if candidate.Order <= 0 {
		candidate.Order = order
	}
	return candidate
}

func serviceNotAttemptedEvidence(transport string, target model.Target, requested string, queryID uint16, queryBytes int, reason model.FailureReason, outcome DNSServiceOutcome) model.Evidence {
	return model.Evidence{ID: "dns-service/" + transport, Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustJSON(DNSServiceEvidence{
		Transport: transport, RequestedEndpoint: requested, Port: target.Port, QueryName: DiagnosticQueryName, QueryType: DiagnosticQueryType, TransactionID: queryID, QueryBytes: queryBytes,
		Outcome: outcome, ErrorKind: string(reason), Error: "target endpoint was not queried", DurationMS: 0,
	})}
}

func serviceFailureEvidence(target model.Target, requested string, queryID uint16, err error) []model.Evidence {
	value := DNSServiceEvidence{Transport: "both", RequestedEndpoint: requested, Port: target.Port, QueryName: DiagnosticQueryName, QueryType: DiagnosticQueryType, TransactionID: queryID, Outcome: DNSServiceOutcomeProtocolFailure, ErrorKind: "query_build_failure", Error: boundedServiceError(err)}
	return []model.Evidence{{ID: "dns-service/error", Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustJSON(value)}}
}

func nextTransactionID() uint16 {
	value := serviceTransactionID.Add(1)
	id := uint16(value)
	if id == 0 {
		id = 1
	}
	return id
}

func boundedServiceTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return defaultServiceTimeout
	}
	return value
}

func (p *DNSServiceProbe) clockNow() time.Time {
	if p == nil || p.now == nil {
		return time.Now()
	}
	return p.now()
}

func (p *DNSServiceProbe) durationMS(started time.Time) int64 {
	duration := p.clockNow().Sub(started).Milliseconds()
	if duration < 0 {
		return 0
	}
	return duration
}

func boundedServiceError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > maxServiceErrorLength {
		return value[:maxServiceErrorLength]
	}
	return value
}

func serviceErrorKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return "transport_failure"
}

func serviceOutcomeForError(err error) DNSServiceOutcome {
	if errors.Is(err, context.DeadlineExceeded) {
		return DNSServiceOutcomeTimeout
	}
	if errors.Is(err, context.Canceled) {
		return DNSServiceOutcomeCancellation
	}
	if serviceErrorKind(err) == "timeout" {
		return DNSServiceOutcomeTimeout
	}
	return DNSServiceOutcomeTransportFailure
}

type diagnosticResponse struct {
	TransactionID   uint16
	QuestionCount   int
	AnswerCount     int
	AuthorityCount  int
	AdditionalCount int
	RCode           int
	RCodeName       string
	Truncated       bool
	Outcome         DNSServiceOutcome
	Success         bool
}

type diagnosticResponseError struct {
	kind    string
	outcome DNSServiceOutcome
	message string
}

func (e *diagnosticResponseError) Error() string { return e.message }

func diagnosticResponseErrorKind(err error) string {
	var responseErr *diagnosticResponseError
	if errors.As(err, &responseErr) {
		return responseErr.kind
	}
	return "malformed_response"
}

func diagnosticResponseOutcome(err error) DNSServiceOutcome {
	var responseErr *diagnosticResponseError
	if errors.As(err, &responseErr) {
		return responseErr.outcome
	}
	return DNSServiceOutcomeMalformedResponse
}

func parseDiagnosticResponse(data []byte, expectedID uint16) (diagnosticResponse, error) {
	if len(data) < 12 {
		return diagnosticResponse{}, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS response is shorter than its header")
	}
	response := diagnosticResponse{
		TransactionID:   binary.BigEndian.Uint16(data[0:2]),
		QuestionCount:   int(binary.BigEndian.Uint16(data[4:6])),
		AnswerCount:     int(binary.BigEndian.Uint16(data[6:8])),
		AuthorityCount:  int(binary.BigEndian.Uint16(data[8:10])),
		AdditionalCount: int(binary.BigEndian.Uint16(data[10:12])),
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	response.RCode = int(flags & 0x000f)
	response.RCodeName = rcodeName(response.RCode)
	if response.TransactionID != expectedID {
		return response, diagnosticError("transaction_mismatch", DNSServiceOutcomeProtocolFailure, "DNS response transaction ID does not match the query")
	}
	if flags&0x8000 == 0 {
		return response, diagnosticError("not_response", DNSServiceOutcomeProtocolFailure, "DNS packet is not marked as a response")
	}
	if flags&0x7800 != 0 {
		return response, diagnosticError("unsupported_opcode", DNSServiceOutcomeProtocolFailure, "DNS response opcode does not match a standard query")
	}
	if response.QuestionCount != 1 {
		return response, diagnosticError("question_count", DNSServiceOutcomeProtocolFailure, "DNS response does not contain exactly one question")
	}
	offset := 12
	name, next, err := readDiagnosticName(data, offset)
	if err != nil {
		return response, err
	}
	offset = next
	if offset+4 > len(data) {
		return response, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS question is truncated")
	}
	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4
	if normalizeDiagnosticName(name) != normalizeDiagnosticName(DiagnosticQueryName) || qtype != DiagnosticQueryTypeCode || qclass != diagnosticQueryClassCode {
		return response, diagnosticError("question_mismatch", DNSServiceOutcomeProtocolFailure, "DNS response question does not match the diagnostic query")
	}
	response.Truncated = flags&0x0200 != 0
	if response.Truncated {
		response.Outcome = DNSServiceOutcomeTruncatedResponse
		return response, nil
	}
	for count := 0; count < response.AnswerCount+response.AuthorityCount+response.AdditionalCount; count++ {
		var recordErr error
		offset, recordErr = skipDiagnosticRecord(data, offset)
		if recordErr != nil {
			return response, recordErr
		}
	}
	if offset != len(data) {
		return response, diagnosticError("trailing_data", DNSServiceOutcomeMalformedResponse, "DNS response contains trailing bytes")
	}
	switch response.RCode {
	case 0:
		response.Outcome = DNSServiceOutcomeSuccess
		response.Success = true
	case 2:
		response.Outcome = DNSServiceOutcomeServfail
	case 3:
		response.Outcome = DNSServiceOutcomeNegativeResponse
		response.Success = true
	case 5:
		response.Outcome = DNSServiceOutcomeRefused
	default:
		response.Outcome = DNSServiceOutcomeProtocolFailure
	}
	return response, nil
}

func diagnosticError(kind string, outcome DNSServiceOutcome, message string) error {
	return &diagnosticResponseError{kind: kind, outcome: outcome, message: message}
}

func readDiagnosticName(data []byte, start int) (string, int, error) {
	if start < 0 || start >= len(data) {
		return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name starts outside the response")
	}
	labels := make([]string, 0, 4)
	position := start
	consumed := start
	jumped := false
	visited := make(map[int]struct{})
	for steps := 0; steps < 128; steps++ {
		if position >= len(data) {
			return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name is truncated")
		}
		length := int(data[position])
		switch {
		case length == 0:
			if !jumped {
				consumed = position + 1
			}
			return strings.Join(labels, "."), consumed, nil
		case length&0xc0 == 0xc0:
			if position+1 >= len(data) {
				return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name pointer is truncated")
			}
			pointer := ((length & 0x3f) << 8) | int(data[position+1])
			if pointer >= len(data) {
				return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name pointer is outside the response")
			}
			if _, exists := visited[pointer]; exists {
				return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name pointer loop")
			}
			visited[pointer] = struct{}{}
			if !jumped {
				consumed = position + 2
				jumped = true
			}
			position = pointer
		case length&0xc0 != 0:
			return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name label has an invalid length")
		default:
			if length > 63 || position+1+length > len(data) {
				return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name label is truncated")
			}
			labels = append(labels, string(data[position+1:position+1+length]))
			position += 1 + length
		}
	}
	return "", start, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS name pointer depth exceeded")
}

func skipDiagnosticRecord(data []byte, offset int) (int, error) {
	_, offset, err := readDiagnosticName(data, offset)
	if err != nil {
		return offset, err
	}
	if offset+10 > len(data) {
		return offset, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS record header is truncated")
	}
	length := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
	offset += 10
	if length > maxServiceMessageSize || offset+length > len(data) {
		return offset, diagnosticError("malformed_response", DNSServiceOutcomeMalformedResponse, "DNS record payload is outside the response")
	}
	return offset + length, nil
}

func normalizeDiagnosticName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func rcodeName(value int) string {
	switch value {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	default:
		return fmt.Sprintf("RCODE_%d", value)
	}
}

func buildDiagnosticQuery(id uint16) ([]byte, error) {
	labels := strings.Split(strings.TrimSuffix(DiagnosticQueryName, "."), ".")
	query := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(query[0:2], id)
	// RD is deliberately zero: this is a service protocol check, not a
	// request for a public recursive lookup.
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return nil, errors.New("diagnostic DNS name contains an invalid label")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, byte(DiagnosticQueryTypeCode), 0, byte(diagnosticQueryClassCode))
	if len(query) > maxServiceMessageSize {
		return nil, errors.New("diagnostic DNS query exceeds the bounded packet size")
	}
	return query, nil
}

func endpointString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}
