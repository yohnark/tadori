// Package http implements the HTTP-layer connectivity probe.
//
// The probe accepts an HTTP-family service profile in model.Target and records
// an HTTP response (including non-success status codes) separately from
// failures that happen while the HTTP client is resolving, connecting, or
// negotiating TLS.
// Response bodies are not read unless a positive limit is configured.
package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

const (
	// HTTPProbeName is the stable machine-readable probe name.
	HTTPProbeName = "http"
	// EvidenceKindHTTPError identifies a client-side failure for which no
	// final HTTP response was received. The raw payload still uses the shared
	// Evidence contract and carries the lower-layer error classification.
	EvidenceKindHTTPError model.EvidenceKind = "http_error"

	// DefaultTimeout bounds a request made by a Probe with no configured
	// timeout. The caller's context can impose a shorter deadline.
	DefaultTimeout = 10 * time.Second

	// DefaultMaxRedirects prevents a redirecting endpoint from making an
	// unbounded number of requests.
	DefaultMaxRedirects = 10

	// maxHeaderValueBytes prevents unusually large response metadata from
	// becoming an unbounded evidence payload.
	maxHeaderValueBytes = 4096
)

// These HTTP-specific reasons extend the frozen #2 contract without changing
// its shape. Lower-layer errors use the corresponding model constants (for
// example model.FailureReasonDNSResolverFailure and
// model.FailureReasonTLSHandshakeFailure).
const (
	FailureReasonMalformedURL    model.FailureReason = "malformed_url"
	FailureReasonRequestTimeout  model.FailureReason = "request_timeout"
	FailureReasonRedirectFailure model.FailureReason = "redirect_failure"
	FailureReasonCancellation    model.FailureReason = "cancellation"
	// FailureReasonCanceled is retained as a spelling-friendly alias.
	FailureReasonCanceled = FailureReasonCancellation
)

// Config controls a Probe created with New. A zero value is useful and uses
// bounded defaults. Client may be supplied to inject a deterministic local
// transport in tests; its transport and other safe settings are retained.
type Config struct {
	Client       *stdhttp.Client
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRedirects int
}

// Option customizes a Probe.
type Option func(*Config)

// WithClient injects an HTTP client, normally for a custom transport or local
// test server.
func WithClient(client *stdhttp.Client) Option {
	return func(config *Config) { config.Client = client }
}

// WithTimeout sets the maximum duration of one request.
func WithTimeout(timeout time.Duration) Option {
	return func(config *Config) { config.Timeout = timeout }
}

// WithMaxBodyBytes opts into bounded response-body collection. The default is
// zero, which omits the body entirely.
func WithMaxBodyBytes(limit int64) Option {
	return func(config *Config) { config.MaxBodyBytes = limit }
}

// WithMaxRedirects sets the maximum number of redirects followed. A value of
// zero uses DefaultMaxRedirects.
func WithMaxRedirects(limit int) Option {
	return func(config *Config) { config.MaxRedirects = limit }
}

// Probe performs one bounded HTTP or HTTPS request.
type Probe struct {
	Client       *stdhttp.Client
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRedirects int
}

// HTTPProbe is a descriptive alias for Probe.
type HTTPProbe = Probe

var _ probe.Probe = (*Probe)(nil)

// New creates an HTTP probe. At most one Config value may be supplied; the
// variadic form permits both New() and New(Config{...}) while keeping the
// zero-value constructor convenient.
func New(config ...Config) *Probe {
	var settings Config
	if len(config) > 0 {
		settings = config[0]
	}
	return &Probe{
		Client:       settings.Client,
		Timeout:      settings.Timeout,
		MaxBodyBytes: settings.MaxBodyBytes,
		MaxRedirects: settings.MaxRedirects,
	}
}

// NewWithOptions creates an HTTP probe using functional options.
func NewWithOptions(options ...Option) *Probe {
	config := Config{}
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}
	return New(config)
}

// NewProbe is an explicit constructor useful to callers that prefer a named
// config argument.
func NewProbe(config Config) *Probe { return New(config) }

// NewHTTPProbe is the descriptive constructor alias used by callers that
// keep several protocol probes in one registry.
func NewHTTPProbe(config ...Config) *Probe { return New(config...) }

// Name implements probe.Probe.
func (*Probe) Name() string { return HTTPProbeName }

// ProbeURL performs a one-off request to an explicit URL with default bounds.
// It is a convenience wrapper around Probe.Run.
func ProbeURL(ctx context.Context, targetURL string) model.ProbeResult {
	target, err := model.ParseTarget(model.TargetIntent{Input: targetURL})
	if err != nil {
		return New().Run(ctx, probe.ExecutionContext{Target: model.Target{OriginalInput: targetURL}})
	}
	return New().Run(ctx, probe.ExecutionContext{Target: target})
}

// Run implements probe.Probe. The canonical target owns URL construction;
// this probe does not reinterpret an opaque input string.
func (p *Probe) Run(ctx context.Context, execution probe.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now().UTC()
	target := model.NormalizeTarget(execution.Target)
	result := model.ProbeResult{
		Name:   p.Name(),
		Target: target,
		Status: model.ProbeStatusError,
		Timing: model.Timing{StartedAt: timePtr(started)},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonUnknown,
			Layer:         model.LayerHTTP,
			FaultDomain:   model.FaultDomainHTTP,
		},
	}

	finish := func() model.ProbeResult {
		completed := time.Now()
		result.Timing.CompletedAt = timePtr(completed)
		result.Timing.DurationMS = completed.Sub(started).Milliseconds()
		return result
	}

	if err := ctx.Err(); err != nil {
		result.Interpretation = interpretationForContext(err)
		result.Evidence = []model.Evidence{errorEvidence(target.OriginalInput, result.Interpretation, err)}
		return finish()
	}

	targetURL, err := target.HTTPURL()
	if err != nil {
		result.Interpretation.FailureReason = FailureReasonMalformedURL
		result.Evidence = []model.Evidence{errorEvidence(target.OriginalInput, result.Interpretation, err)}
		return finish()
	}

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := stdhttp.NewRequestWithContext(requestCtx, stdhttp.MethodGet, targetURL, nil)
	if err != nil {
		result.Interpretation.FailureReason = FailureReasonMalformedURL
		result.Evidence = []model.Evidence{errorEvidence(targetURL, result.Interpretation, err)}
		return finish()
	}

	client := p.Client
	if client == nil {
		client = &stdhttp.Client{}
	}
	clientCopy := *client
	maxRedirects := p.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	redirectTargets := make([]string, 0, maxRedirects)
	redirectCallbackFailed := false
	redirectLimitErr := errors.New("maximum redirects exceeded")
	if client.CheckRedirect != nil {
		// A caller's policy is still honored after our hard bound. This keeps
		// redirect behavior observable while ensuring the probe remains bounded.
		callerCheckRedirect := client.CheckRedirect
		clientCopy.CheckRedirect = func(req *stdhttp.Request, via []*stdhttp.Request) error {
			if len(via) >= maxRedirects {
				redirectCallbackFailed = true
				return redirectLimitErr
			}
			redirectTargets = append(redirectTargets, req.URL.String())
			if callbackErr := callerCheckRedirect(req, via); callbackErr != nil {
				redirectCallbackFailed = true
				return callbackErr
			}
			return nil
		}
	} else {
		clientCopy.CheckRedirect = func(req *stdhttp.Request, via []*stdhttp.Request) error {
			if len(via) >= maxRedirects {
				redirectCallbackFailed = true
				return redirectLimitErr
			}
			redirectTargets = append(redirectTargets, req.URL.String())
			return nil
		}
	}

	observations := &responseRecorder{}
	transport := client.Transport
	if transport == nil {
		transport = stdhttp.DefaultTransport
	}
	transport = transportForSelectedEndpoint(transport, target)
	clientCopy.Transport = &recordingTransport{base: transport, recorder: observations}

	response, err := clientCopy.Do(request)
	if err != nil {
		interpretation := classifyRequestError(err, requestCtx, ctx, redirectLimitErr, redirectCallbackFailed, observations.hasRedirect())
		result.Interpretation = interpretation
		result.Evidence = []model.Evidence{errorEvidence(targetURL, interpretation, err)}
		if observations.hasRedirect() {
			result.Evidence[0] = errorEvidenceWithRedirects(targetURL, interpretation, err, observations.snapshot(), redirectTargets)
		}
		return finish()
	}
	if response.Body == nil {
		response.Body = io.NopCloser(strings.NewReader(""))
	}
	defer response.Body.Close()

	metadata := responseMetadata{
		ResponseReceived: true,
		URL:              targetURL,
		StatusCode:       response.StatusCode,
		Status:           response.Status,
		Protocol:         response.Proto,
		Headers:          safeHeaders(response.Header),
		Redirects:        redirectHops(observations.snapshot(), redirectTargets),
	}
	if response.Request != nil && response.Request.URL != nil {
		metadata.URL = response.Request.URL.String()
	}
	if metadata.URL == "" {
		metadata.URL = targetURL
	}
	if p.MaxBodyBytes > 0 {
		body, readErr := readBoundedBody(response.Body, p.MaxBodyBytes)
		metadata.Body = string(body.Bytes)
		metadata.BodyBytes = len(body.Bytes)
		metadata.BodyTruncated = body.Truncated
		if readErr != nil {
			metadata.BodyReadError = readErr.Error()
		}
	}

	result.Evidence = []model.Evidence{responseEvidence(metadata)}
	result.Status = model.ProbeStatusPassed
	result.Interpretation = model.ProbeInterpretation{
		FailureReason: model.FailureReasonNone,
		Layer:         model.LayerHTTP,
		FaultDomain:   model.FaultDomainHTTP,
	}
	if response.StatusCode >= 400 {
		result.Status = model.ProbeStatusFailed
		result.Interpretation.FailureReason = model.FailureReasonHTTPStatusCode
	}
	return finish()
}

func transportForSelectedEndpoint(base stdhttp.RoundTripper, target model.Target) stdhttp.RoundTripper {
	if target.SelectedEndpoint == nil || target.SelectedEndpoint.Address == "" {
		return base
	}
	transport, ok := base.(*stdhttp.Transport)
	if !ok || transport.Proxy != nil {
		// A custom transport or a proxy owns its own dialing semantics. Do not
		// claim that the selected endpoint was used when this adapter cannot
		// safely preserve those semantics.
		return base
	}
	endpoint, err := target.EndpointAddress()
	if err != nil {
		return base
	}
	clone := transport.Clone()
	dial := clone.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	requestedHost := strings.Trim(strings.TrimSpace(target.RequestedIdentity), "[]")
	clone.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr == nil && strings.EqualFold(strings.Trim(host, "[]"), requestedHost) {
			return dial(ctx, network, endpoint)
		}
		return dial(ctx, network, address)
	}
	return clone
}

type responseMetadata struct {
	ResponseReceived bool              `json:"response_received"`
	URL              string            `json:"url,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	Status           string            `json:"status,omitempty"`
	Protocol         string            `json:"protocol,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Redirects        []redirectHop     `json:"redirects,omitempty"`
	Body             string            `json:"body,omitempty"`
	BodyBytes        int               `json:"body_bytes,omitempty"`
	BodyTruncated    bool              `json:"body_truncated,omitempty"`
	BodyReadError    string            `json:"body_read_error,omitempty"`
}

type redirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
	ToURL      string `json:"to_url,omitempty"`
}

type errorMetadata struct {
	ResponseReceived bool          `json:"response_received"`
	URL              string        `json:"url,omitempty"`
	ErrorKind        string        `json:"error_kind"`
	Error            string        `json:"error"`
	Redirects        []redirectHop `json:"redirects,omitempty"`
}

func responseEvidence(metadata responseMetadata) model.Evidence {
	raw, _ := json.Marshal(metadata)
	return model.Evidence{
		ID:         "http-1",
		Kind:       model.EvidenceKindHTTPResponse,
		Source:     "net/http",
		CapturedAt: timePtr(time.Now().UTC()),
		Raw:        raw,
	}
}

func errorEvidence(targetURL string, interpretation model.ProbeInterpretation, err error) model.Evidence {
	kind := string(interpretation.FailureReason)
	if kind == string(model.FailureReasonUnknown) {
		kind = "http_failure"
	}
	metadata := errorMetadata{
		ResponseReceived: false,
		URL:              targetURL,
		ErrorKind:        kind,
		Error:            err.Error(),
	}
	raw, _ := json.Marshal(metadata)
	return model.Evidence{
		ID:         "http-1",
		Kind:       EvidenceKindHTTPError,
		Source:     "net/http",
		CapturedAt: timePtr(time.Now().UTC()),
		Raw:        raw,
	}
}

func errorEvidenceWithRedirects(targetURL string, interpretation model.ProbeInterpretation, err error, observations []responseObservation, targets []string) model.Evidence {
	evidence := errorEvidence(targetURL, interpretation, err)
	metadata := errorMetadata{
		ResponseReceived: len(observations) > 0,
		URL:              targetURL,
		ErrorKind:        string(interpretation.FailureReason),
		Error:            err.Error(),
		Redirects:        redirectHops(observations, targets),
	}
	evidence.Raw, _ = json.Marshal(metadata)
	return evidence
}

func classifyRequestError(err error, requestCtx, callerCtx context.Context, redirectLimitErr error, redirectCallbackFailed, hadRedirect bool) model.ProbeInterpretation {
	if errors.Is(callerCtx.Err(), context.Canceled) || (errors.Is(requestCtx.Err(), context.Canceled) && errors.Is(callerCtx.Err(), context.Canceled)) {
		return interpretation(FailureReasonCancellation, model.LayerHTTP, model.FaultDomainHTTP)
	}
	if errors.Is(callerCtx.Err(), context.DeadlineExceeded) || errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
		return interpretation(FailureReasonRequestTimeout, model.LayerHTTP, model.FaultDomainHTTP)
	}
	if errors.Is(err, context.Canceled) {
		return interpretation(FailureReasonCancellation, model.LayerHTTP, model.FaultDomainHTTP)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return interpretation(FailureReasonRequestTimeout, model.LayerHTTP, model.FaultDomainHTTP)
	}
	if errors.Is(err, redirectLimitErr) || redirectCallbackFailed || hadRedirect && isRedirectError(err) {
		return interpretation(FailureReasonRedirectFailure, model.LayerHTTP, model.FaultDomainHTTP)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		reason := model.FailureReasonDNSResolverFailure
		if dnsErr.IsNotFound {
			reason = model.FailureReasonDNSNXDomain
		} else if dnsErr.IsTimeout {
			reason = model.FailureReasonDNSTimeout
		}
		return interpretation(reason, model.LayerDNS, model.FaultDomainDNS)
	}
	var certErr x509.UnknownAuthorityError
	if errors.As(err, &certErr) {
		return interpretation(model.FailureReasonCertificateValidationFailure, model.LayerTLS, model.FaultDomainTLS)
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return interpretation(model.FailureReasonCertificateValidationFailure, model.LayerTLS, model.FaultDomainTLS)
	}
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return interpretation(model.FailureReasonCertificateValidationFailure, model.LayerTLS, model.FaultDomainTLS)
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return interpretation(model.FailureReasonCertificateValidationFailure, model.LayerTLS, model.FaultDomainTLS)
	}
	var tlsRecordErr tls.RecordHeaderError
	if errors.As(err, &tlsRecordErr) {
		return interpretation(model.FailureReasonTLSHandshakeFailure, model.LayerTLS, model.FaultDomainTLS)
	}
	// Some transports (including the standard library's HTTPS transport when
	// it receives a plaintext response) flatten the TLS error to a string
	// rather than retaining tls.RecordHeaderError in the unwrap chain.
	if isTLSHandshakeError(err) {
		return interpretation(model.FailureReasonTLSHandshakeFailure, model.LayerTLS, model.FaultDomainTLS)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return interpretation(model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport)
		}
	}
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.ECONNREFUSED:
			return interpretation(model.FailureReasonTCPConnectionRefused, model.LayerTCP, model.FaultDomainTransport)
		case syscall.ECONNRESET, syscall.EPIPE:
			return interpretation(model.FailureReasonTCPConnectionReset, model.LayerTCP, model.FaultDomainTransport)
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
			return interpretation(model.FailureReasonNetworkUnreachable, model.LayerNetwork, model.FaultDomainNetwork)
		}
	}
	return interpretation(model.FailureReasonHTTPFailure, model.LayerHTTP, model.FaultDomainHTTP)
}

func interpretation(reason model.FailureReason, layer model.Layer, domain model.FaultDomain) model.ProbeInterpretation {
	return model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain}
}

func interpretationForContext(err error) model.ProbeInterpretation {
	if errors.Is(err, context.Canceled) {
		return interpretation(FailureReasonCancellation, model.LayerHTTP, model.FaultDomainHTTP)
	}
	return interpretation(FailureReasonRequestTimeout, model.LayerHTTP, model.FaultDomainHTTP)
}

func isRedirectError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "redirect")
}

func isTLSHandshakeError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "tls:") || strings.Contains(message, "tls handshake") || strings.Contains(message, "ssl handshake") || strings.Contains(message, "server gave http response to https client")
}

func safeHeaders(headers stdhttp.Header) map[string]string {
	allowed := []string{
		"Cache-Control", "Content-Length", "Content-Type", "Date", "ETag",
		"Expires", "Last-Modified", "Location", "Retry-After", "Server",
		"Transfer-Encoding", "Vary",
	}
	result := make(map[string]string)
	for _, name := range allowed {
		value := headers.Get(name)
		if value == "" {
			continue
		}
		if len(value) > maxHeaderValueBytes {
			value = value[:maxHeaderValueBytes]
		}
		result[name] = value
	}
	return result
}

type boundedBody struct {
	Bytes     []byte
	Truncated bool
}

func readBoundedBody(body io.Reader, limit int64) (boundedBody, error) {
	if limit <= 0 {
		return boundedBody{}, nil
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return boundedBody{Bytes: data, Truncated: truncated}, err
}

type responseObservation struct {
	URL        string
	StatusCode int
	Location   string
}

type responseRecorder struct {
	items []responseObservation
}

func (r *responseRecorder) add(response responseObservation) { r.items = append(r.items, response) }

func (r *responseRecorder) snapshot() []responseObservation {
	items := make([]responseObservation, len(r.items))
	copy(items, r.items)
	return items
}

func (r *responseRecorder) hasRedirect() bool {
	for _, item := range r.items {
		if item.StatusCode >= 300 && item.StatusCode < 400 && item.Location != "" {
			return true
		}
	}
	return false
}

type recordingTransport struct {
	base     stdhttp.RoundTripper
	recorder *responseRecorder
}

func (t *recordingTransport) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	response, err := t.base.RoundTrip(request)
	if response != nil {
		t.recorder.add(responseObservation{
			URL:        request.URL.String(),
			StatusCode: response.StatusCode,
			Location:   response.Header.Get("Location"),
		})
	}
	return response, err
}

func redirectHops(observations []responseObservation, targets []string) []redirectHop {
	hops := make([]redirectHop, 0)
	targetIndex := 0
	for _, observation := range observations {
		if observation.StatusCode < 300 || observation.StatusCode >= 400 || observation.Location == "" {
			continue
		}
		hop := redirectHop{
			URL:        observation.URL,
			StatusCode: observation.StatusCode,
			Location:   observation.Location,
		}
		if targetIndex < len(targets) {
			hop.ToURL = targets[targetIndex]
			targetIndex++
		}
		hops = append(hops, hop)
	}
	return hops
}

func timePtr(value time.Time) *time.Time { return &value }
