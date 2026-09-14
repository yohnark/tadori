package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/yohnark/tadori/internal/model"
	parentprobe "github.com/yohnark/tadori/internal/probe"
)

// Name is the stable name of the Windows proxy discovery probe.
const Name = "proxy_discovery"

// A proxy list normally contains one or two endpoints. This cap keeps a
// malformed or hostile local configuration from turning reachability into an
// unbounded sequence of network operations.
const maxReachabilityChecks = 16

const maxReachabilityTimeout = 30 * time.Second

// ErrUnsupportedPlatform is returned by the platform implementation when
// proxy discovery is not available on the current operating system.
var ErrUnsupportedPlatform = errors.New("proxy discovery is unsupported on this platform")

// ConfigurationState is the normalized state retained in proxy evidence. The
// model package deliberately does not define proxy-specific states; these are
// observations, not report-level failure reasons.
type ConfigurationState string

const (
	StateDirect                   ConfigurationState = "direct"
	StateStaticProxyConfigured    ConfigurationState = "static_proxy_configured"
	StatePACConfigured            ConfigurationState = "pac_configured"
	StateConfigurationUnavailable ConfigurationState = "proxy_configuration_unavailable"
	StateMalformedProxyEndpoint   ConfigurationState = "malformed_proxy_endpoint"
	StateProxyEndpointUnreachable ConfigurationState = "proxy_endpoint_unreachable"
	StateProxyEndpointTimeout     ConfigurationState = "proxy_endpoint_timeout"
	StateUnsupportedPlatform      ConfigurationState = "unsupported_platform"
)

// SourceConfiguration is the internal output of one native proxy
// configuration source. Native values remain private to the probe boundary;
// callers must use NormalizeConfiguration before placing this value in
// evidence, and URL resolution redacts values before using them.
type SourceConfiguration struct {
	Available  bool
	Proxy      string
	Bypass     []string
	PACURL     string
	AutoDetect bool
	Error      string
}

// Discovery contains the two independent Windows proxy configuration views.
// WinHTTP and WinINET must remain separate because applications can observe
// different settings on the same machine.
type Discovery struct {
	WinHTTP SourceConfiguration
	WinINET SourceConfiguration
}

// ConfigurationObservation is the redacted, normalized view of one proxy
// source. It is safe to place in canonical evidence: proxy user-info, PAC URL
// query strings, and malformed native values are removed before this value is
// returned.
type ConfigurationObservation struct {
	State                 ConfigurationState `json:"state"`
	Direct                bool               `json:"direct"`
	StaticProxyConfigured bool               `json:"static_proxy_configured"`
	ProxyEndpoints        []string           `json:"proxy_endpoints,omitempty"`
	ProxyBypass           []string           `json:"proxy_bypass,omitempty"`
	PACConfigured         bool               `json:"pac_configured"`
	PACURL                string             `json:"pac_url,omitempty"`
	AutoDetect            bool               `json:"auto_detect,omitempty"`
	Error                 string             `json:"error,omitempty"`
}

// URLProxyResolution is the redacted result of resolving a target URL through
// a Windows proxy source. PAC is resolved by the native Windows API; PAC code
// is never exposed to or evaluated by Tadori.
type URLProxyResolution struct {
	Direct        bool     `json:"direct"`
	Proxy         string   `json:"proxy,omitempty"`
	Bypass        []string `json:"bypass,omitempty"`
	BypassMatched bool     `json:"bypass_matched"`
	UsedPAC       bool     `json:"used_pac"`
	AutoDetect    bool     `json:"auto_detect"`
	Configuration string   `json:"configuration"`
}

// Discover returns the platform proxy configuration. On Windows it uses the
// WinHTTP and WinINET-compatible native APIs; other platforms return
// ErrUnsupportedPlatform. The result keeps the two sources independent.
func Discover(ctx context.Context) (Discovery, error) { return discoverPlatform(ctx) }

// ResolveProxyForURL resolves the effective proxy for targetURL using one
// discovered Windows source. Static settings are normalized locally and PAC or
// auto-detect settings are resolved by the platform adapter.
func ResolveProxyForURL(ctx context.Context, targetURL string, config SourceConfiguration) (URLProxyResolution, error) {
	return resolveProxyForURL(ctx, targetURL, config)
}

// resolveStaticProxyForURL evaluates the target-dependent part of a static
// proxy configuration without consulting host state. Keeping this logic
// platform-neutral makes deterministic tests possible and lets the Windows
// adapter reserve native APIs for PAC and auto-detect resolution.
func resolveStaticProxyForURL(targetURL string, config SourceConfiguration) (URLProxyResolution, error) {
	if !config.Available {
		return URLProxyResolution{}, errors.New("proxy configuration unavailable")
	}
	bypass := sanitizeBypass(config.Bypass)
	endpoints, _, parseErr := parseProxyEndpoints(config.Proxy)
	if parseErr != "" {
		return URLProxyResolution{}, errors.New(parseErr)
	}
	if len(endpoints) > 0 && ProxyBypasses(targetURL, bypass) {
		return URLProxyResolution{
			Direct:        true,
			Bypass:        bypass,
			BypassMatched: true,
			Configuration: string(StateDirect),
		}, nil
	}
	endpoint, direct, err := ProxyEndpointForURL(config.Proxy, targetURL)
	if err != nil {
		return URLProxyResolution{}, err
	}
	if direct || endpoint == "" {
		return URLProxyResolution{Direct: true, Bypass: bypass, Configuration: string(StateDirect)}, nil
	}
	return URLProxyResolution{Proxy: endpoint, Bypass: bypass, Configuration: string(StateStaticProxyConfigured)}, nil
}

// NormalizeConfiguration returns a safe canonical view of config. Callers
// should use this instead of serializing SourceConfiguration directly because
// native proxy strings can contain user-info or other sensitive values.
func NormalizeConfiguration(config SourceConfiguration) ConfigurationObservation {
	normalized := normalizeConfiguration(config)
	return ConfigurationObservation{
		State:                 normalized.state,
		Direct:                normalized.state == StateDirect,
		StaticProxyConfigured: len(normalized.endpoints) > 0,
		ProxyEndpoints:        append([]string(nil), normalized.endpoints...),
		ProxyBypass:           append([]string(nil), normalized.bypass...),
		PACConfigured:         normalized.pacConfigured(),
		PACURL:                normalized.pacURL,
		AutoDetect:            normalized.autoDetect,
		Error:                 normalized.err,
	}
}

// ProxyEndpoints returns redacted, normalized endpoints from a native proxy
// string. It never returns user-info and rejects malformed endpoint values.
func ProxyEndpoints(value string) ([]string, error) {
	endpoints, _, parseErr := parseProxyEndpoints(value)
	if parseErr != "" {
		return endpoints, errors.New(parseErr)
	}
	return endpoints, nil
}

// ProxyEndpointForURL selects the endpoint for targetURL from a WinHTTP proxy
// list such as "http=proxy-a:8080;https=proxy-b:8443". It returns direct=true
// for an explicit DIRECT or an empty list. The selected endpoint is always
// normalized and redacted.
func ProxyEndpointForURL(value, targetURL string) (endpoint string, direct bool, err error) {
	parsedURL, parseErr := url.Parse(targetURL)
	if parseErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || parsedURL.User != nil {
		return "", false, errors.New("target URL is malformed")
	}
	original := strings.TrimSpace(value)
	if original == "" {
		return "", true, nil
	}
	var fallback string
	var selected string
	var schemeDirect bool
	var schemeEntry bool
	var fallbackDirect bool
	var fallbackEntry bool
	parseFailure := false
	for _, rawPart := range splitProxyList(original) {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		label := ""
		valuePart := part
		if equals := strings.IndexByte(part, '='); equals >= 0 {
			label = strings.ToLower(strings.TrimSpace(part[:equals]))
			valuePart = strings.TrimSpace(part[equals+1:])
		}
		if strings.EqualFold(valuePart, "DIRECT") {
			if label == strings.ToLower(parsedURL.Scheme) {
				schemeEntry = true
				schemeDirect = true
			} else if label == "" && !fallbackEntry {
				fallbackEntry = true
				fallbackDirect = true
			}
			continue
		}
		candidate, candidateErr := safeEndpoint(valuePart)
		if candidateErr != nil {
			parseFailure = true
			continue
		}
		if label == strings.ToLower(parsedURL.Scheme) && !schemeEntry {
			schemeEntry = true
			selected = candidate
		} else if label == "" && !fallbackEntry {
			fallbackEntry = true
			fallback = candidate
		}
	}
	if schemeEntry {
		if schemeDirect {
			return "", true, nil
		}
		return selected, false, nil
	}
	if fallbackEntry && fallbackDirect {
		return "", true, nil
	}
	if fallbackEntry && fallback != "" {
		return fallback, false, nil
	}
	if parseFailure {
		return "", false, errors.New(string(StateMalformedProxyEndpoint))
	}
	return "", true, nil
}

// ProxyBypasses reports whether targetURL matches one of the Windows proxy
// bypass patterns. It covers the documented literal, wildcard, and <local>
// forms without evaluating scripts or retaining any configuration beyond the
// boolean result.
func ProxyBypasses(targetURL string, bypass []string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	targetPort := parsed.Port()
	if targetPort == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			targetPort = "443"
		case "http":
			targetPort = "80"
		}
	}
	for _, raw := range bypass {
		patterns := strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' || unicode.IsSpace(r) })
		for _, rawPattern := range patterns {
			pattern := strings.ToLower(strings.TrimSpace(rawPattern))
			if pattern == "" {
				continue
			}
			if pattern == "<local>" && !strings.Contains(host, ".") {
				return true
			}
			pattern = strings.TrimSuffix(pattern, ".")
			if strings.HasPrefix(pattern, "<") && strings.HasSuffix(pattern, ">") {
				continue
			}
			pattern = strings.TrimPrefix(pattern, "http://")
			pattern = strings.TrimPrefix(pattern, "https://")
			if slash := strings.IndexByte(pattern, '/'); slash >= 0 {
				pattern = pattern[:slash]
			}
			patternPort := ""
			if strings.HasPrefix(pattern, "[") {
				if closing := strings.IndexByte(pattern, ']'); closing >= 0 {
					if suffix := pattern[closing+1:]; strings.HasPrefix(suffix, ":") {
						patternPort = suffix[1:]
					}
					pattern = pattern[1:closing]
				}
			} else if colon := strings.LastIndexByte(pattern, ':'); colon >= 0 && strings.Count(pattern, ":") == 1 && !strings.Contains(pattern[colon+1:], ":") {
				if _, portErr := strconv.ParseUint(pattern[colon+1:], 10, 16); portErr == nil {
					patternPort = pattern[colon+1:]
					pattern = pattern[:colon]
				}
			}
			if patternPort != "" && patternPort != targetPort {
				continue
			}
			pattern = strings.Trim(pattern, "[]")
			if pattern == host {
				return true
			}
			if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
				return true
			}
			if strings.Contains(pattern, "*") {
				if matched, matchErr := pathMatch(pattern, host); matchErr == nil && matched {
					return true
				}
			}
		}
	}
	return false
}

func pathMatch(pattern, value string) (bool, error) {
	// Keep wildcard matching local and bounded; filepath.Match is platform
	// dependent, so the small matcher below uses only the Windows host syntax.
	if pattern == "*" {
		return true, nil
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value, nil
	}
	position := 0
	for index, part := range parts {
		if part == "" {
			continue
		}
		found := strings.Index(value[position:], part)
		if found < 0 || index == 0 && found != 0 {
			return false, nil
		}
		position += found + len(part)
	}
	if !strings.HasSuffix(pattern, "*") && position != len(value) {
		return false, nil
	}
	return true, nil
}

// DialContextFunc permits deterministic reachability tests without changing
// the production path. It has the same shape as net.Dialer.DialContext.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DiscoverFunc permits deterministic tests and keeps native discovery behind
// a small platform boundary.
type DiscoverFunc func(ctx context.Context) (Discovery, error)

// Options configures Probe. The zero value is useful with
// NewProbeWithOptions: it performs configuration discovery and does not make
// a network request. NewProbe enables bounded endpoint reachability checks.
type Options struct {
	// CheckReachability enables a TCP connect to each valid configured proxy
	// endpoint. It is bounded by ReachabilityTimeout and the caller context.
	CheckReachability   bool
	ReachabilityTimeout time.Duration
	Discover            DiscoverFunc
	DialContext         DialContextFunc
	Now                 func() time.Time
}

// Probe discovers WinHTTP and WinINET proxy settings. It implements
// internal/probe.Probe and never evaluates PAC JavaScript.
type Probe struct {
	checkReachability   bool
	reachabilityTimeout time.Duration
	discover            DiscoverFunc
	dialContext         DialContextFunc
	now                 func() time.Time
}

// ProxyProbe is an expressive alias for Probe for callers that import
// several probe packages together.
type ProxyProbe = Probe

// NewProbe returns the production proxy discovery probe. Endpoint checks are
// enabled, but each check has a short timeout and honors caller cancellation.
func NewProbe(options ...Options) *Probe {
	if len(options) > 0 {
		return NewProbeWithOptions(options[0])
	}
	return NewProbeWithOptions(Options{
		CheckReachability:   true,
		ReachabilityTimeout: 2 * time.Second,
	})
}

// New creates a production proxy probe. Passing an Options value is useful
// for callers that need deterministic local fixtures; omitting it enables the
// bounded production reachability checks.
func New(options ...Options) *Probe { return NewProbe(options...) }

// Run executes one production proxy discovery operation.
func Run(ctx context.Context, target model.Target) model.ProbeResult {
	return NewProbe().Run(ctx, parentprobe.ExecutionContext{Target: target})
}

// NewProbeWithOptions returns a probe configured for production or tests.
func NewProbeWithOptions(options Options) *Probe {
	timeout := options.ReachabilityTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout > maxReachabilityTimeout {
		timeout = maxReachabilityTimeout
	}
	discover := options.Discover
	if discover == nil {
		discover = discoverPlatform
	}
	dial := options.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Probe{
		checkReachability:   options.CheckReachability,
		reachabilityTimeout: timeout,
		discover:            discover,
		dialContext:         dial,
		now:                 now,
	}
}

var _ parentprobe.Probe = Probe{}
var _ parentprobe.Probe = (*Probe)(nil)

// Name implements internal/probe.Probe.
func (Probe) Name() string { return Name }

// Run implements internal/probe.Probe. Native configuration errors are
// represented in evidence and normalized interpretation; they are not
// returned as Go errors because Probe.Run has no error return.
func (p Probe) Run(ctx context.Context, execution parentprobe.ExecutionContext) model.ProbeResult {
	if p.now == nil {
		p.now = time.Now
	}
	if p.discover == nil {
		p.discover = discoverPlatform
	}
	if p.dialContext == nil {
		dialer := &net.Dialer{}
		p.dialContext = dialer.DialContext
	}
	started := p.now()
	result := model.ProbeResult{
		Name:   Name,
		Target: execution.Target,
		Status: model.ProbeStatusError,
		Timing: model.Timing{StartedAt: &started},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonProxyConfigurationFailure,
			Layer:         model.LayerProxy,
			FaultDomain:   model.FaultDomainProxy,
		},
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return p.finish(result, started, model.ProbeStatusError, model.FailureReasonProbeExecution)
	}

	discovery, err := p.discover(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return p.finish(result, started, model.ProbeStatusError, model.FailureReasonProbeExecution)
		}
		if errors.Is(err, ErrUnsupportedPlatform) {
			result.Evidence = []model.Evidence{p.evidence("proxy.platform", model.EvidenceKindProxyConfiguration, "platform", sourceEvidence{
				State: string(StateUnsupportedPlatform),
				Error: string(StateUnsupportedPlatform),
			})}
			return p.finish(result, started, model.ProbeStatusSkipped, model.FailureReasonUnsupported)
		}
		result.Evidence = []model.Evidence{p.evidence("proxy.platform", model.EvidenceKindProxyConfiguration, "proxy", sourceEvidence{
			State: string(StateConfigurationUnavailable),
			Error: safeError(err),
		})}
		return p.finish(result, started, model.ProbeStatusError, model.FailureReasonProxyConfigurationFailure)
	}

	configs := []struct {
		id     string
		source string
		kind   model.EvidenceKind
		value  SourceConfiguration
	}{
		{id: "proxy.winhttp.configuration", source: "winhttp", kind: model.EvidenceKindWinHTTPProxy, value: discovery.WinHTTP},
		{id: "proxy.wininet.configuration", source: "wininet", kind: model.EvidenceKindWinINETProxy, value: discovery.WinINET},
	}

	configurationFailure := false
	endpointUnavailable := false
	for _, item := range configs {
		observed := normalizeConfiguration(item.value)
		if p.checkReachability && len(observed.endpoints) > 0 && (observed.state == StateStaticProxyConfigured || observed.state == StatePACConfigured || observed.state == StateMalformedProxyEndpoint) {
			p.checkEndpoints(ctx, &observed)
		}
		result.Evidence = append(result.Evidence, p.evidence(item.id, item.kind, item.source, observed.raw()))
		if observed.pacConfigured() {
			result.Evidence = append(result.Evidence, p.evidence(item.id+".pac", model.EvidenceKindPAC, item.source, pacEvidence{
				Configured: true,
				URL:        observed.pacURL,
				AutoDetect: observed.autoDetect,
			}))
		}
		if observed.state == StateConfigurationUnavailable || observed.state == StateMalformedProxyEndpoint {
			configurationFailure = true
		}
		if observed.state == StateProxyEndpointUnreachable || observed.state == StateProxyEndpointTimeout {
			endpointUnavailable = true
		}
	}

	status := model.ProbeStatusPassed
	reason := model.FailureReasonNone
	if endpointUnavailable {
		status = model.ProbeStatusFailed
		reason = model.FailureReasonProxyUnavailable
	}
	if configurationFailure {
		status = model.ProbeStatusError
		reason = model.FailureReasonProxyConfigurationFailure
	}
	if ctx.Err() != nil {
		status = model.ProbeStatusError
		reason = model.FailureReasonProbeExecution
	}

	result.Status = status
	result.Interpretation.FailureReason = reason
	return p.finish(result, started, status, reason)
}

func (p *Probe) finish(result model.ProbeResult, started time.Time, status model.ProbeStatus, reason model.FailureReason) model.ProbeResult {
	completed := p.now()
	result.Status = status
	result.Interpretation.FailureReason = reason
	result.Timing.CompletedAt = &completed
	result.Timing.DurationMS = completed.Sub(started).Milliseconds()
	if result.Timing.DurationMS < 0 {
		result.Timing.DurationMS = 0
	}
	return result
}

type normalizedConfiguration struct {
	state                ConfigurationState
	proxy                string
	endpoints            []string
	bypass               []string
	pacURL               string
	pacPresent           bool
	autoDetect           bool
	endpointReachability []endpointResult
	err                  string
}

type endpointResult struct {
	Endpoint string `json:"endpoint"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type sourceEvidence struct {
	State                 string           `json:"state"`
	Direct                bool             `json:"direct"`
	StaticProxyConfigured bool             `json:"static_proxy_configured"`
	ProxyEndpoints        []string         `json:"proxy_endpoints,omitempty"`
	ProxyBypass           []string         `json:"proxy_bypass,omitempty"`
	PACConfigured         bool             `json:"pac_configured"`
	PACURL                string           `json:"pac_url,omitempty"`
	AutoDetect            bool             `json:"auto_detect,omitempty"`
	EndpointReachability  []endpointResult `json:"endpoint_reachability,omitempty"`
	Error                 string           `json:"error,omitempty"`
}

type pacEvidence struct {
	Configured bool   `json:"configured"`
	URL        string `json:"url,omitempty"`
	AutoDetect bool   `json:"auto_detect,omitempty"`
	Executed   bool   `json:"executed"`
}

func (n normalizedConfiguration) pacConfigured() bool {
	return n.pacPresent || n.autoDetect
}

func (n normalizedConfiguration) raw() sourceEvidence {
	return sourceEvidence{
		State:                 string(n.state),
		Direct:                n.state == StateDirect,
		StaticProxyConfigured: len(n.endpoints) > 0,
		ProxyEndpoints:        n.endpoints,
		ProxyBypass:           n.bypass,
		PACConfigured:         n.pacConfigured(),
		PACURL:                n.pacURL,
		AutoDetect:            n.autoDetect,
		EndpointReachability:  n.endpointReachability,
		Error:                 n.err,
	}
}

func normalizeConfiguration(config SourceConfiguration) normalizedConfiguration {
	n := normalizedConfiguration{
		bypass:     sanitizeBypass(config.Bypass),
		pacURL:     sanitizePACURL(config.PACURL),
		pacPresent: strings.TrimSpace(config.PACURL) != "",
		autoDetect: config.AutoDetect,
	}
	if !config.Available {
		n.state = StateConfigurationUnavailable
		n.err = safeError(errors.New(config.Error))
		if config.Error == "" {
			n.err = string(StateConfigurationUnavailable)
		}
		return n
	}

	n.endpoints, n.proxy, n.err = parseProxyEndpoints(config.Proxy)
	if config.Proxy != "" && n.err != "" {
		n.state = StateMalformedProxyEndpoint
		return n
	}
	if n.pacConfigured() {
		n.state = StatePACConfigured
		return n
	}
	if len(n.endpoints) > 0 {
		n.state = StateStaticProxyConfigured
		return n
	}
	n.state = StateDirect
	return n
}

func (p *Probe) checkEndpoints(ctx context.Context, config *normalizedConfiguration) {
	for index, endpoint := range config.endpoints {
		if index >= maxReachabilityChecks {
			config.endpointReachability = append(config.endpointReachability, endpointResult{Endpoint: endpoint, Status: "not_checked", Error: "reachability check limit reached"})
			continue
		}
		if err := ctx.Err(); err != nil {
			config.endpointReachability = append(config.endpointReachability, endpointResult{Endpoint: endpoint, Status: "canceled", Error: "operation canceled"})
			config.state = StateProxyEndpointTimeout
			continue
		}
		checkCtx, cancel := context.WithTimeout(ctx, p.reachabilityTimeout)
		conn, err := p.dialContext(checkCtx, "tcp", endpoint)
		cancel()
		if err != nil {
			status := "unreachable"
			state := StateProxyEndpointUnreachable
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
				status = "timeout"
				state = StateProxyEndpointTimeout
			}
			config.endpointReachability = append(config.endpointReachability, endpointResult{Endpoint: endpoint, Status: status, Error: safeNetworkError(err)})
			config.state = state
			continue
		}
		if conn != nil {
			_ = conn.Close()
		}
		config.endpointReachability = append(config.endpointReachability, endpointResult{Endpoint: endpoint, Status: "reachable"})
	}
}

func (p *Probe) evidence(id string, kind model.EvidenceKind, source string, raw any) model.Evidence {
	encoded, err := json.Marshal(raw)
	if err != nil {
		encoded = []byte(`{"state":"proxy_configuration_failure","error":"evidence serialization failure"}`)
	}
	captured := p.now()
	return model.Evidence{ID: id, Kind: kind, Source: source, CapturedAt: &captured, Raw: encoded}
}

// parseProxyEndpoints parses native proxy strings while dropping user-info,
// paths, and other values that could carry credentials or unrelated secrets.
// It accepts both a single endpoint and WinHTTP's scheme=endpoint list.
func parseProxyEndpoints(value string) (endpoints []string, original string, parseErr string) {
	original = strings.TrimSpace(value)
	if original == "" {
		return nil, "", ""
	}
	parts := splitProxyList(original)
	directSeen := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if equals := strings.IndexByte(part, '='); equals >= 0 {
			part = strings.TrimSpace(part[equals+1:])
		}
		if strings.EqualFold(part, "DIRECT") {
			directSeen = true
			continue
		}
		endpoint, err := safeEndpoint(part)
		if err != nil {
			if parseErr == "" {
				parseErr = string(StateMalformedProxyEndpoint)
			}
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 && parseErr == "" && !directSeen {
		parseErr = string(StateMalformedProxyEndpoint)
	}
	return endpoints, original, parseErr
}

func splitProxyList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || unicode.IsSpace(r)
	})
}

func safeEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty proxy endpoint")
	}
	parseValue := value
	if !strings.Contains(parseValue, "://") {
		parseValue = "http://" + parseValue
	}
	parsed, err := url.Parse(parseValue)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		// User info is not an error: it is intentionally discarded so that a
		// valid endpoint never causes credentials to enter evidence.
		if err != nil || parsed.Host == "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", errors.New("malformed proxy endpoint")
		}
	}
	host := parsed.Hostname()
	if host == "" || strings.ContainsAny(host, "\r\n\x00") {
		return "", errors.New("malformed proxy endpoint")
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", errors.New("malformed proxy endpoint")
	}
	return net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), nil
}

func sanitizePACURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	// A PAC URL is optional evidence. If it cannot be parsed as an absolute
	// host-bearing URL, omit it rather than preserving malformed text that may
	// contain credentials, query tokens, or fragments.
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	// PAC URLs are evidence of configuration presence; query strings and
	// fragments commonly carry tokens and are not needed for diagnosis.
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func sanitizeBypass(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, redactUserInfo(value))
	}
	return result
}

func redactUserInfo(value string) string {
	if strings.Contains(value, "@") {
		if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
			parsed.User = nil
			return parsed.String()
		}
		if index := strings.LastIndex(value, "@"); index >= 0 {
			if scheme := strings.Index(value, "://"); scheme >= 0 {
				return value[:scheme+3] + value[index+1:]
			}
			return value[index+1:]
		}
	}
	return value
}

var sensitiveErrorPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|credential|authorization)\b`)

func safeError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "proxy configuration failure"
	}
	// Native errors should be stable and useful, but arbitrary injected or
	// platform-provided text may contain values in forms such as
	// "password: hunter2", "token = abc", or "Authorization: Bearer xyz".
	// Once a credential-bearing keyword is present, returning one generic
	// message is the only reliable way to avoid leaking the complete value.
	if sensitiveErrorPattern.MatchString(message) {
		return "sensitive configuration value redacted"
	}
	message = redactUserInfo(message)
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}

func safeNetworkError(err error) string {
	if err == nil {
		return ""
	}
	// Network errors can contain host names, but never include the endpoint
	// string itself or any user-provided proxy configuration.
	message := safeError(err)
	if message == "" {
		return "proxy endpoint unreachable"
	}
	return message
}
