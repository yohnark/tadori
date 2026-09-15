package enterprise

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	stdhttp "net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
	parentprobe "github.com/yohnark/tadori/internal/probe"
	"github.com/yohnark/tadori/internal/probe/proxy"
)

const (
	// Name is the stable canonical probe name for the Windows enterprise lane.
	Name = "windows_enterprise"
	// DefaultTimeout bounds native configuration and active path observations.
	DefaultTimeout   = 8 * time.Second
	maxEvidenceError = 256
)

// ErrUnsupportedPlatform indicates that the Windows enterprise lane has no
// native provider on the current operating system.
var ErrUnsupportedPlatform = errors.New("Windows enterprise diagnostics are unsupported on this platform")

// Path names identify the application and user/service paths being compared.
const (
	PathApplicationDirect = "application_direct"
	PathBrowserWinINET    = "browser_wininet"
	PathServiceWinHTTP    = "service_winhttp"
)

// Path modes describe the effective transport choice, including a PAC result.
const (
	PathModeDirect  = "direct"
	PathModeProxy   = "proxy"
	PathModePAC     = "pac"
	PathModeUnknown = "unknown"
)

// CONNECT outcomes are intentionally small and do not retain challenge
// values, proxy headers, or credentials.
const (
	ConnectNotApplicable = "not_applicable"
	ConnectSucceeded     = "succeeded"
	ConnectDenied        = "denied"
	ConnectAuthRequired  = "authentication_required"
	ConnectUnavailable   = "unavailable"
	ConnectTimeout       = "timeout"
	ConnectNotTested     = "not_tested"
)

// SnapshotProvider collects platform state and bounded active path results.
// It is deliberately target-aware because PAC resolution and effective route
// selection depend on the endpoint being diagnosed.
type SnapshotProvider interface {
	Snapshot(context.Context, model.Target) (Snapshot, error)
}

// SnapshotProviderFunc adapts a function to SnapshotProvider.
type SnapshotProviderFunc func(context.Context, model.Target) (Snapshot, error)

func (f SnapshotProviderFunc) Snapshot(ctx context.Context, target model.Target) (Snapshot, error) {
	return f(ctx, target)
}

// Snapshot is the internal collection boundary for one Windows enterprise
// diagnosis. It is not a second report model: Probe.Run projects it into the
// canonical model.ProbeResult and model.Evidence values.
type Snapshot struct {
	Proxy          proxy.Discovery
	EffectiveProxy []EffectiveProxy
	Paths          []PathObservation
	TLS            TLSComparison
	TrustStore     TrustStoreObservation
	Firewall       FirewallObservation
	Adapters       []AdapterObservation
	Routes         []RouteObservation
	Issues         []ObservationIssue
}

// EffectiveProxy is the URL-specific result of static or PAC/auto-config
// resolution. Endpoint is expected to be host:port and is sanitized again
// before evidence is emitted.
type EffectiveProxy struct {
	Source              string   `json:"source"`
	Decision            string   `json:"decision"`
	Mode                string   `json:"mode"`
	Endpoint            string   `json:"endpoint,omitempty"`
	Bypass              []string `json:"bypass,omitempty"`
	BypassMatched       bool     `json:"bypass_matched"`
	PACUsed             bool     `json:"pac_used"`
	AutoDetect          bool     `json:"auto_detect"`
	ResolutionAttempted bool     `json:"resolution_attempted"`
	ResolutionOK        bool     `json:"resolution_ok"`
	Error               string   `json:"error,omitempty"`
}

// PathObservation records the result of one direct, WinINET, or WinHTTP path.
// It contains enough protocol detail to distinguish TCP failure, CONNECT
// denial, proxy authentication, TLS trust failure, and HTTP response status.
type PathObservation struct {
	Name                    string                  `json:"name"`
	Source                  string                  `json:"source,omitempty"`
	Mode                    string                  `json:"mode"`
	Endpoint                string                  `json:"endpoint,omitempty"`
	RequestAttempted        bool                    `json:"request_attempted"`
	TCPConnected            bool                    `json:"tcp_connected"`
	ConnectOutcome          string                  `json:"connect_outcome"`
	ConnectStatusCode       int                     `json:"connect_status_code,omitempty"`
	ProxyAuthenticationHint bool                    `json:"proxy_authentication_hint,omitempty"`
	HTTPResponse            bool                    `json:"http_response"`
	HTTPStatusCode          int                     `json:"http_status_code,omitempty"`
	TLSHandshake            bool                    `json:"tls_handshake"`
	TLSAttempted            bool                    `json:"tls_attempted"`
	CertificateTrusted      bool                    `json:"certificate_trusted"`
	HostnameVerified        bool                    `json:"hostname_verified"`
	Certificate             *CertificateObservation `json:"certificate,omitempty"`
	FailureReason           model.FailureReason     `json:"failure_reason"`
	Error                   string                  `json:"error,omitempty"`
}

// CertificateObservation is safe certificate metadata. Raw certificates,
// public keys, and trust-store contents are intentionally not retained.
type CertificateObservation struct {
	ChainIndex   int      `json:"chain_index,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	SerialNumber string   `json:"serial_number,omitempty"`
	NotBefore    string   `json:"not_before,omitempty"`
	NotAfter     string   `json:"not_after,omitempty"`
	DNSNames     []string `json:"dns_names,omitempty"`
	SHA256       string   `json:"sha256,omitempty"`
}

// TLSComparison summarizes the conservative paired-certificate comparison.
// A difference is only considered possible interception when both peer
// certificates are independently trusted and hostname-valid; issuer strings
// alone never set PossibleInterception.
type TLSComparison struct {
	DirectCertificateSHA256  string `json:"direct_certificate_sha256,omitempty"`
	ProxyCertificateSHA256   string `json:"proxy_certificate_sha256,omitempty"`
	DirectCertificateSubject string `json:"direct_certificate_subject,omitempty"`
	ProxyCertificateSubject  string `json:"proxy_certificate_subject,omitempty"`
	DirectCertificateIssuer  string `json:"direct_certificate_issuer,omitempty"`
	ProxyCertificateIssuer   string `json:"proxy_certificate_issuer,omitempty"`
	CertificatesDiffer       bool   `json:"certificates_differ"`
	CertificatesDifferKnown  bool   `json:"certificates_differ_known"`
	IssuersDiffer            bool   `json:"issuers_differ"`
	IssuersDifferKnown       bool   `json:"issuers_differ_known"`
	BothTrusted              bool   `json:"both_trusted"`
	BothTrustedKnown         bool   `json:"both_trusted_known"`
	BothHostnameVerified     bool   `json:"both_hostname_verified"`
	BothHostnameKnown        bool   `json:"both_hostname_verified_known"`
	PossibleInterception     bool   `json:"possible_interception"`
	InterceptionBasis        string `json:"interception_basis,omitempty"`
	TrustMismatch            bool   `json:"trust_mismatch"`
}

// TrustStoreObservation reports availability and count only; it does not dump
// Windows roots or certificate subjects.
type TrustStoreObservation struct {
	Source                           string `json:"source,omitempty"`
	Available                        bool   `json:"available"`
	RootCount                        int    `json:"root_count,omitempty"`
	TrustedCorporatePrivateRootKnown bool   `json:"trusted_corporate_private_root_known"`
	TrustedCorporatePrivateRoot      bool   `json:"trusted_corporate_private_root"`
	Error                            string `json:"error,omitempty"`
	Insufficient                     bool   `json:"insufficient_privilege,omitempty"`
}

// FirewallObservation contains selected profile state, never the complete
// firewall ruleset. Profile names are fixed Windows profile names.
type FirewallObservation struct {
	Source       string            `json:"source,omitempty"`
	Available    bool              `json:"available"`
	Profiles     []FirewallProfile `json:"profiles,omitempty"`
	Error        string            `json:"error,omitempty"`
	Insufficient bool              `json:"insufficient_privilege,omitempty"`
}

type FirewallProfile struct {
	Name                   string `json:"name"`
	FirewallEnabled        *bool  `json:"firewall_enabled,omitempty"`
	BlockInboundExceptions *bool  `json:"block_inbound_exceptions,omitempty"`
	PolicyPresent          bool   `json:"policy_present"`
}

// AdapterObservation captures routing context without retaining unrelated
// adapter configuration. VPN and virtual flags are conservative classifications
// based on native interface type and bounded interface names.
type AdapterObservation struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	IfType      uint32 `json:"if_type,omitempty"`
	Operational bool   `json:"operational"`
	VPN         bool   `json:"vpn"`
	Virtual     bool   `json:"virtual"`
}

// RouteObservation is an effective route selected for one path endpoint.
type RouteObservation struct {
	Path           string `json:"path"`
	Destination    string `json:"destination,omitempty"`
	Interface      string `json:"interface,omitempty"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	NextHop        string `json:"next_hop,omitempty"`
	Available      bool   `json:"available"`
	Error          string `json:"error,omitempty"`
}

// ObservationIssue explains a partial native collection without turning an
// optional subsystem into an unrelated connectivity failure.
type ObservationIssue struct {
	Subsystem    string `json:"subsystem"`
	Kind         string `json:"kind"`
	Error        string `json:"error,omitempty"`
	Unsupported  bool   `json:"unsupported,omitempty"`
	Insufficient bool   `json:"insufficient_privilege,omitempty"`
}

// Options configures one enterprise probe.
type Options struct {
	Provider SnapshotProvider
	Timeout  time.Duration
	Now      func() time.Time
}

// Probe implements the shared canonical probe contract.
type Probe struct {
	provider SnapshotProvider
	timeout  time.Duration
	now      func() time.Time
}

// EnterpriseProbe is an expressive alias for Probe.
type EnterpriseProbe = Probe

// New returns a Windows enterprise probe. The production provider is a no-op
// unsupported result on non-Windows hosts.
func New(options ...Options) *Probe {
	var option Options
	if len(options) != 0 {
		option = options[0]
	}
	timeout := option.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	now := option.Now
	if now == nil {
		now = time.Now
	}
	provider := option.Provider
	if provider == nil {
		provider = platformSnapshotProvider{}
	}
	return &Probe{provider: provider, timeout: timeout, now: now}
}

// NewProbe is the named-constructor alias.
func NewProbe(options ...Options) *Probe { return New(options...) }

// Run is a convenience wrapper for one production diagnosis.
func Run(ctx context.Context, target model.Target) model.ProbeResult {
	return New().Run(ctx, parentprobe.ExecutionContext{Target: target})
}

var _ parentprobe.Probe = (*Probe)(nil)

// Name implements probe.Probe.
func (*Probe) Name() string { return Name }

// Run collects and correlates the Windows enterprise observations into the
// existing canonical result. Optional collection failures remain evidence and
// do not prevent direct, proxy, TLS, or route observations from being emitted.
func (p *Probe) Run(ctx context.Context, execution parentprobe.ExecutionContext) model.ProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if p == nil {
		p = New()
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.provider == nil {
		p.provider = platformSnapshotProvider{}
	}
	started := p.now().UTC()
	result := model.ProbeResult{
		Name:   Name,
		Target: execution.Target,
		Status: model.ProbeStatusError,
		Timing: model.Timing{StartedAt: &started},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonProbeExecution,
			Layer:         model.LayerProxy,
			FaultDomain:   model.FaultDomainProxy,
		},
	}
	finish := func() model.ProbeResult {
		completed := p.now().UTC()
		result.Timing.CompletedAt = &completed
		result.Timing.DurationMS = completed.Sub(started).Milliseconds()
		if result.Timing.DurationMS < 0 {
			result.Timing.DurationMS = 0
		}
		return result
	}
	if err := ctx.Err(); err != nil {
		return finish()
	}

	callCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	snapshot, err := p.provider.Snapshot(callCtx, execution.Target)
	if err != nil && errors.Is(err, ErrUnsupportedPlatform) {
		result.Evidence = []model.Evidence{p.evidence("windows-enterprise/platform", model.EvidenceKindProxyConfiguration, "windows-enterprise", map[string]any{
			"state": "unsupported_platform",
			"error": "Windows enterprise diagnostics are unsupported on this platform",
		})}
		result.Status = model.ProbeStatusSkipped
		result.Interpretation = model.ProbeInterpretation{FailureReason: model.FailureReasonUnsupported, Layer: model.LayerProxy, FaultDomain: model.FaultDomainProxy}
		return finish()
	}
	if err != nil && len(snapshot.Paths) == 0 && len(snapshot.EffectiveProxy) == 0 && len(snapshot.Adapters) == 0 && len(snapshot.Routes) == 0 && !snapshot.Firewall.Available && !snapshot.TrustStore.Available {
		result.Evidence = []model.Evidence{p.evidence("windows-enterprise/error", model.EvidenceKindProxyConfiguration, "windows-enterprise", map[string]any{
			"state": "collection_error",
			"error": safeErrorString(err.Error()),
		})}
		return finish()
	}
	if err != nil {
		snapshot.Issues = append(snapshot.Issues, ObservationIssue{Subsystem: "provider", Kind: "partial_collection", Error: err.Error()})
	}

	result.Evidence = append(result.Evidence, p.configurationEvidence(snapshot.Proxy.WinHTTP, "winhttp", model.EvidenceKindWinHTTPProxy))
	result.Evidence = append(result.Evidence, p.configurationEvidence(snapshot.Proxy.WinINET, "wininet", model.EvidenceKindWinINETProxy))
	for _, source := range []struct {
		name   string
		config proxy.SourceConfiguration
	}{
		{name: "winhttp", config: snapshot.Proxy.WinHTTP},
		{name: "wininet", config: snapshot.Proxy.WinINET},
	} {
		observed := proxy.NormalizeConfiguration(source.config)
		if observed.PACConfigured {
			result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/"+source.name+"/pac", model.EvidenceKindPAC, source.name, map[string]any{
				"configured":  true,
				"url":         observed.PACURL,
				"auto_detect": observed.AutoDetect,
				"executed":    hasPACResolution(snapshot.EffectiveProxy, source.name),
			}))
		}
	}

	snapshot.Paths = safePaths(snapshot.Paths)
	snapshot.EffectiveProxy = safeEffectiveProxies(snapshot.EffectiveProxy)
	snapshot.Routes = safeRoutes(snapshot.Routes)
	snapshot.Adapters = safeAdapters(snapshot.Adapters)
	snapshot.Issues = safeIssues(snapshot.Issues)
	snapshot.TrustStore = safeTrustStore(snapshot.TrustStore)
	snapshot.Firewall = safeFirewall(snapshot.Firewall)
	if len(snapshot.Paths) > 0 || len(snapshot.EffectiveProxy) > 0 {
		result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/connectivity", model.EvidenceKindProxyConnectivity, "windows-enterprise", connectivityEvidence(snapshot)))
	}
	if snapshot.TLS == (TLSComparison{}) {
		snapshot.TLS = compareTLS(snapshot.Paths)
	}
	result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/tls", model.EvidenceKindTLSTrust, "crypto/x509", tlsEvidence(snapshot)))
	if snapshot.Firewall.Available || snapshot.Firewall.Error != "" || snapshot.Firewall.Insufficient {
		result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/firewall", model.EvidenceKindFirewallProfile, "windows-firewall-profile", snapshot.Firewall))
	}
	if len(snapshot.Adapters) > 0 || len(snapshot.Routes) > 0 || hasIssue(snapshot.Issues, "adapter") || hasIssue(snapshot.Issues, "route") {
		result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/routing", model.EvidenceKindAdapterRouting, "windows-ip-helper", map[string]any{
			"adapters": snapshot.Adapters,
			"routes":   snapshot.Routes,
		}))
	}
	if len(snapshot.Issues) > 0 {
		result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/collection", model.EvidenceKindProxyConfiguration, "windows-enterprise", map[string]any{"issues": snapshot.Issues}))
	}

	reason, layer, domain := correlate(snapshot)
	result.Interpretation = model.ProbeInterpretation{FailureReason: reason, Layer: layer, FaultDomain: domain}
	if reason == model.FailureReasonNone {
		result.Status = model.ProbeStatusPassed
	} else if reason == model.FailureReasonProbeExecution {
		result.Status = model.ProbeStatusError
	} else {
		result.Status = model.ProbeStatusFailed
	}
	result.Evidence = append(result.Evidence, p.evidence("windows-enterprise/correlation", model.EvidenceKindRouteComparison, "windows-enterprise", correlationEvidence(snapshot, reason)))
	return finish()
}

func (p *Probe) configurationEvidence(config proxy.SourceConfiguration, source string, kind model.EvidenceKind) model.Evidence {
	return p.evidence("windows-enterprise/"+source+"/configuration", kind, source, proxy.NormalizeConfiguration(config))
}

func (p *Probe) evidence(id string, kind model.EvidenceKind, source string, value any) model.Evidence {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte(`{"error":"evidence serialization failure"}`)
	}
	captured := p.now().UTC()
	return model.Evidence{ID: id, Kind: kind, Source: source, CapturedAt: &captured, Raw: raw}
}

func connectivityEvidence(snapshot Snapshot) map[string]any {
	return map[string]any{
		"effective_proxy": snapshot.EffectiveProxy,
		"paths":           snapshot.Paths,
		"direct_vs_proxy": comparePaths(snapshot.Paths),
	}
}

func tlsEvidence(snapshot Snapshot) map[string]any {
	return map[string]any{
		"comparison":   snapshot.TLS,
		"trust_store":  snapshot.TrustStore,
		"certificates": certificatesByPath(snapshot.Paths),
	}
}

func correlationEvidence(snapshot Snapshot, reason model.FailureReason) map[string]any {
	return map[string]any{
		"primary_reason":              reason,
		"winhttp_wininet_diverge":     configurationsDiverge(snapshot.Proxy),
		"browser_path_works":          pathWorks(findPath(snapshot.Paths, PathBrowserWinINET)),
		"proxy_path_works":            proxyPathWorks(snapshot.Paths),
		"application_direct_works":    pathWorks(findPath(snapshot.Paths, PathApplicationDirect)),
		"proxy_connect_denied":        hasConnectOutcome(snapshot.Paths, ConnectDenied),
		"proxy_authentication_needed": hasConnectOutcome(snapshot.Paths, ConnectAuthRequired),
		"effective_route_differs":     routesDiffer(snapshot.Routes),
		"intentional_policy_possible": reason == model.FailureReasonDirectEgressRestricted,
	}
}

func correlate(snapshot Snapshot) (model.FailureReason, model.Layer, model.FaultDomain) {
	if hasConnectOutcome(snapshot.Paths, ConnectAuthRequired) {
		return model.FailureReasonProxyAuthenticationRequired, model.LayerProxy, model.FaultDomainProxy
	}
	if hasConnectOutcome(snapshot.Paths, ConnectDenied) {
		return model.FailureReasonProxyConnectDenied, model.LayerProxy, model.FaultDomainProxy
	}
	if snapshot.TLS.PossibleInterception {
		return model.FailureReasonTLSInterceptionSuspected, model.LayerTLS, model.FaultDomainTLS
	}
	if snapshot.TLS.TrustMismatch {
		return model.FailureReasonTLSTrustStoreMismatch, model.LayerTLS, model.FaultDomainTLS
	}
	application := findPath(snapshot.Paths, PathApplicationDirect)
	if proxyPathWorks(snapshot.Paths) &&
		application != nil && !pathWorks(application) && application.Mode == PathModeDirect {
		return model.FailureReasonDirectEgressRestricted, model.LayerNetwork, model.FaultDomainPolicy
	}
	if configurationsDiverge(snapshot.Proxy) {
		return model.FailureReasonProxyConfigurationDivergence, model.LayerProxy, model.FaultDomainProxy
	}
	for _, path := range snapshot.Paths {
		if path.FailureReason == model.FailureReasonProxyUnavailable {
			return path.FailureReason, model.LayerProxy, model.FaultDomainProxy
		}
	}
	if routesDiffer(snapshot.Routes) {
		return model.FailureReasonEffectiveRouteDifference, model.LayerRoute, model.FaultDomainRouting
	}
	if hasProxyResolutionFailure(snapshot) {
		return model.FailureReasonProxyConfigurationFailure, model.LayerProxy, model.FaultDomainProxy
	}
	for _, path := range snapshot.Paths {
		if path.FailureReason == model.FailureReasonProxyConfigurationFailure {
			return path.FailureReason, model.LayerProxy, model.FaultDomainProxy
		}
	}
	return model.FailureReasonNone, model.LayerProxy, model.FaultDomainProxy
}

func proxyPathWorks(paths []PathObservation) bool {
	for index := range paths {
		path := &paths[index]
		if (path.Mode == PathModeProxy || path.Mode == PathModePAC) && pathWorks(path) {
			return true
		}
	}
	return false
}

func hasProxyResolutionFailure(snapshot Snapshot) bool {
	for _, effective := range snapshot.EffectiveProxy {
		if effective.ResolutionOK || effective.Error == "" {
			continue
		}
		var configured bool
		switch effective.Source {
		case "winhttp":
			configured = snapshot.Proxy.WinHTTP.Available
		case "wininet":
			configured = snapshot.Proxy.WinINET.Available
		}
		if configured {
			return true
		}
	}
	return false
}

func configurationsDiverge(discovery proxy.Discovery) bool {
	left, right := proxy.NormalizeConfiguration(discovery.WinHTTP), proxy.NormalizeConfiguration(discovery.WinINET)
	if !discovery.WinHTTP.Available || !discovery.WinINET.Available {
		return false
	}
	return left.State != right.State || left.Direct != right.Direct || left.PACConfigured != right.PACConfigured ||
		left.AutoDetect != right.AutoDetect || left.PACURL != right.PACURL ||
		!sameStrings(left.ProxyEndpoints, right.ProxyEndpoints) || !sameStrings(left.ProxyBypass, right.ProxyBypass)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasPACResolution(values []EffectiveProxy, source string) bool {
	for _, value := range values {
		if value.Source == source && value.PACUsed && value.ResolutionOK {
			return true
		}
	}
	return false
}

func findPath(paths []PathObservation, name string) *PathObservation {
	for index := range paths {
		if paths[index].Name == name {
			return &paths[index]
		}
	}
	return nil
}

func pathWorks(path *PathObservation) bool {
	if path == nil {
		return false
	}
	if path.FailureReason != "" && path.FailureReason != model.FailureReasonNone {
		return false
	}
	if path.HTTPResponse && path.HTTPStatusCode >= 200 && path.HTTPStatusCode < 400 {
		return true
	}
	return path.TLSHandshake && path.CertificateTrusted && path.HostnameVerified
}

func hasConnectOutcome(paths []PathObservation, outcome string) bool {
	for _, path := range paths {
		if path.ConnectOutcome == outcome {
			return true
		}
	}
	return false
}

func comparePaths(paths []PathObservation) map[string]any {
	return map[string]any{
		"direct":          pathWorks(findPath(paths, PathApplicationDirect)),
		"browser_wininet": pathWorks(findPath(paths, PathBrowserWinINET)),
		"service_winhttp": pathWorks(findPath(paths, PathServiceWinHTTP)),
	}
}

func compareTLS(paths []PathObservation) TLSComparison {
	var direct, proxyPath *PathObservation
	for index := range paths {
		path := &paths[index]
		if path.Name == PathApplicationDirect {
			direct = path
		}
		if path.Name == PathBrowserWinINET || path.Name == PathServiceWinHTTP {
			if path.Mode == PathModeProxy || path.Mode == PathModePAC {
				if proxyPath == nil || path.Name == PathBrowserWinINET && proxyPath.Name != PathBrowserWinINET {
					proxyPath = path
				}
			}
		}
	}
	comparison := TLSComparison{}
	if direct != nil && direct.Certificate != nil {
		comparison.DirectCertificateSHA256 = direct.Certificate.SHA256
		comparison.DirectCertificateSubject = direct.Certificate.Subject
		comparison.DirectCertificateIssuer = direct.Certificate.Issuer
	}
	if proxyPath != nil && proxyPath.Certificate != nil {
		comparison.ProxyCertificateSHA256 = proxyPath.Certificate.SHA256
		comparison.ProxyCertificateSubject = proxyPath.Certificate.Subject
		comparison.ProxyCertificateIssuer = proxyPath.Certificate.Issuer
	}
	comparison.CertificatesDiffer = comparison.DirectCertificateSHA256 != "" && comparison.ProxyCertificateSHA256 != "" && comparison.DirectCertificateSHA256 != comparison.ProxyCertificateSHA256
	comparison.CertificatesDifferKnown = comparison.DirectCertificateSHA256 != "" && comparison.ProxyCertificateSHA256 != ""
	comparison.IssuersDiffer = comparison.DirectCertificateIssuer != "" && comparison.ProxyCertificateIssuer != "" && !strings.EqualFold(comparison.DirectCertificateIssuer, comparison.ProxyCertificateIssuer)
	comparison.IssuersDifferKnown = comparison.DirectCertificateIssuer != "" && comparison.ProxyCertificateIssuer != ""
	comparison.BothTrusted = direct != nil && proxyPath != nil && direct.CertificateTrusted && proxyPath.CertificateTrusted
	comparison.BothTrustedKnown = direct != nil && proxyPath != nil && (direct.TLSAttempted || direct.Certificate != nil) && (proxyPath.TLSAttempted || proxyPath.Certificate != nil)
	comparison.BothHostnameVerified = direct != nil && proxyPath != nil && direct.HostnameVerified && proxyPath.HostnameVerified
	comparison.BothHostnameKnown = direct != nil && proxyPath != nil && (direct.TLSAttempted || direct.Certificate != nil) && (proxyPath.TLSAttempted || proxyPath.Certificate != nil)
	comparison.PossibleInterception = comparison.CertificatesDiffer && comparison.BothTrusted && comparison.BothHostnameVerified
	if comparison.PossibleInterception {
		comparison.InterceptionBasis = "trusted hostname-valid peer certificates differ between direct and proxy paths"
	}
	comparison.TrustMismatch = proxyPath != nil && pathWorks(proxyPath) && direct != nil &&
		(direct.TLSAttempted || direct.Certificate != nil) && direct.Certificate != nil && !direct.CertificateTrusted
	return comparison
}

func routesDiffer(routes []RouteObservation) bool {
	var direct, proxyRoute *RouteObservation
	for index := range routes {
		route := &routes[index]
		if route.Path == PathApplicationDirect {
			direct = route
		} else if route.Path == PathBrowserWinINET || route.Path == PathServiceWinHTTP {
			if proxyRoute == nil || route.Path == PathBrowserWinINET && proxyRoute.Path != PathBrowserWinINET {
				proxyRoute = route
			}
		}
	}
	return direct != nil && proxyRoute != nil && direct.Available && proxyRoute.Available &&
		direct.InterfaceIndex != 0 && proxyRoute.InterfaceIndex != 0 &&
		(direct.InterfaceIndex != proxyRoute.InterfaceIndex || direct.NextHop != proxyRoute.NextHop)
}

func certificatesByPath(paths []PathObservation) map[string]*CertificateObservation {
	result := make(map[string]*CertificateObservation)
	for _, path := range paths {
		if path.Certificate != nil {
			result[path.Name] = path.Certificate
		}
	}
	return result
}

func safeEffectiveProxies(values []EffectiveProxy) []EffectiveProxy {
	result := make([]EffectiveProxy, 0, len(values))
	for _, value := range values {
		copyValue := value
		copyValue.Decision = normalizeEffectiveDecision(copyValue)
		if copyValue.ResolutionOK {
			copyValue.ResolutionAttempted = true
		}
		if endpoints, err := proxy.ProxyEndpoints(value.Endpoint); err == nil && len(endpoints) > 0 {
			copyValue.Endpoint = endpoints[0]
		} else if strings.TrimSpace(value.Endpoint) != "" {
			copyValue.Endpoint = ""
		}
		copyValue.Bypass = sanitizeBypass(value.Bypass)
		copyValue.Error = safeErrorString(value.Error)
		result = append(result, copyValue)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		return result[i].Endpoint < result[j].Endpoint
	})
	return result
}

func normalizeEffectiveDecision(value EffectiveProxy) string {
	if decision := strings.TrimSpace(value.Decision); decision != "" {
		return decision
	}
	if value.BypassMatched {
		return model.EnterpriseProxyDecisionBypassMatch
	}
	if !value.ResolutionOK && (value.PACUsed || value.AutoDetect) {
		return model.EnterpriseProxyDecisionPACResultUnavailable
	}
	switch value.Mode {
	case PathModeDirect:
		return model.EnterpriseProxyDecisionDirect
	case PathModeProxy:
		return model.EnterpriseProxyDecisionStaticProxy
	case PathModePAC:
		return model.EnterpriseProxyDecisionPACSelectedProxy
	default:
		return model.EnterpriseProxyDecisionUnknown
	}
}

func safePaths(values []PathObservation) []PathObservation {
	result := make([]PathObservation, 0, len(values))
	for _, value := range values {
		copyValue := value
		if endpoints, err := proxy.ProxyEndpoints(value.Endpoint); err == nil && len(endpoints) > 0 {
			copyValue.Endpoint = endpoints[0]
		} else if strings.TrimSpace(value.Endpoint) != "" {
			copyValue.Endpoint = ""
		}
		copyValue.Error = safeErrorString(value.Error)
		if copyValue.Certificate != nil {
			copyValue.Certificate = safeCertificate(copyValue.Certificate)
		}
		result = append(result, copyValue)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func safeCertificate(value *CertificateObservation) *CertificateObservation {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.Subject = boundedString(copyValue.Subject, maxEvidenceError)
	copyValue.Issuer = boundedString(copyValue.Issuer, maxEvidenceError)
	copyValue.SerialNumber = boundedString(copyValue.SerialNumber, maxEvidenceError)
	copyValue.NotBefore = boundedString(copyValue.NotBefore, maxEvidenceError)
	copyValue.NotAfter = boundedString(copyValue.NotAfter, maxEvidenceError)
	if len(copyValue.DNSNames) > 32 {
		copyValue.DNSNames = copyValue.DNSNames[:32]
	}
	copyValue.DNSNames = append([]string(nil), copyValue.DNSNames...)
	for index := range copyValue.DNSNames {
		copyValue.DNSNames[index] = boundedString(copyValue.DNSNames[index], maxEvidenceError)
	}
	copyValue.SHA256 = boundedString(copyValue.SHA256, maxEvidenceError)
	return &copyValue
}

func safeRoutes(values []RouteObservation) []RouteObservation {
	result := append([]RouteObservation(nil), values...)
	for index := range result {
		result[index].Error = safeErrorString(result[index].Error)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func safeAdapters(values []AdapterObservation) []AdapterObservation {
	result := append([]AdapterObservation(nil), values...)
	for index := range result {
		result[index].Name = boundedString(result[index].Name, maxEvidenceError)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Index != result[j].Index {
			return result[i].Index < result[j].Index
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func safeIssues(values []ObservationIssue) []ObservationIssue {
	result := append([]ObservationIssue(nil), values...)
	for index := range result {
		result[index].Error = safeErrorString(result[index].Error)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Subsystem != result[j].Subsystem {
			return result[i].Subsystem < result[j].Subsystem
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}

func safeTrustStore(value TrustStoreObservation) TrustStoreObservation {
	value.Error = safeErrorString(value.Error)
	return value
}

func safeFirewall(value FirewallObservation) FirewallObservation {
	value.Error = safeErrorString(value.Error)
	value.Profiles = append([]FirewallProfile(nil), value.Profiles...)
	return value
}

func sanitizeBypass(values []string) []string {
	// Reuse the proxy probe's redaction rules so unusual fixture/native values
	// such as user:password@host are handled consistently with configuration
	// evidence. Bypass matching itself still only consumes a boolean result.
	redacted := proxy.NormalizeConfiguration(proxy.SourceConfiguration{Available: true, Bypass: values}).ProxyBypass
	result := make([]string, 0, len(redacted))
	for _, value := range redacted {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, boundedString(value, maxEvidenceError))
	}
	return result
}

var sensitiveWords = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|credential|authorization)\b`)
var userInfoURL = regexp.MustCompile(`(?i)(https?://)[^/\s@]+@`)

func safeErrorString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if sensitiveWords.MatchString(value) {
		return "sensitive configuration value redacted"
	}
	value = userInfoURL.ReplaceAllString(value, "$1")
	return boundedString(value, maxEvidenceError)
}

func boundedString(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func hasIssue(issues []ObservationIssue, subsystem string) bool {
	for _, issue := range issues {
		if issue.Subsystem == subsystem {
			return true
		}
	}
	return false
}

// CertificateMetadata turns a peer certificate into safe evidence metadata.
// It is exported so the Windows transport adapter and deterministic fixtures
// use one certificate representation.
func CertificateMetadata(cert *x509.Certificate) *CertificateObservation {
	if cert == nil {
		return nil
	}
	digest := sha256.Sum256(cert.Raw)
	dnsNames := append([]string(nil), cert.DNSNames...)
	return &CertificateObservation{
		ChainIndex:   0,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:     dnsNames,
		SHA256:       hex.EncodeToString(digest[:]),
	}
}

// ProbeHTTPPath is the platform-neutral bounded HTTP path helper used by the
// Windows provider. It is exported for deterministic Windows fixture tests and
// never uses ambient proxy environment variables.
func ProbeHTTPPath(ctx context.Context, target model.Target, name, source, mode, endpoint string, timeout time.Duration) PathObservation {
	path := PathObservation{Name: name, Source: source, Mode: mode, Endpoint: endpoint, ConnectOutcome: ConnectNotApplicable}
	if ctx == nil {
		ctx = context.Background()
	}
	targetURL, err := target.HTTPURL()
	if err != nil {
		path.FailureReason = model.FailureReasonProbeExecution
		path.Error = err.Error()
		return path
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		path.FailureReason = model.FailureReasonProbeExecution
		path.Error = "canonical target URL is malformed"
		return path
	}
	if mode == PathModeProxy || mode == PathModePAC {
		endpoints, endpointErr := proxy.ProxyEndpoints(endpoint)
		if endpointErr != nil || len(endpoints) == 0 {
			path.Endpoint = ""
			path.FailureReason = model.FailureReasonProxyConfigurationFailure
			path.Error = "proxy endpoint is malformed"
			return path
		}
		endpoint = endpoints[0]
		path.Endpoint = endpoint
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &stdhttp.Transport{Proxy: nil}
	if mode == PathModeProxy || mode == PathModePAC {
		proxyURL, parseErr := url.Parse("http://" + endpoint)
		if parseErr != nil || proxyURL.Host == "" {
			path.FailureReason = model.FailureReasonProxyConfigurationFailure
			path.Error = "proxy endpoint is malformed"
			return path
		}
		transport.Proxy = stdhttp.ProxyURL(proxyURL)
		if parsed.Scheme == "https" {
			path.ConnectOutcome = ConnectNotTested
		}
	}
	client := &stdhttp.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *stdhttp.Request, _ []*stdhttp.Request) error {
			return stdhttp.ErrUseLastResponse
		},
	}
	request, err := stdhttp.NewRequestWithContext(requestCtx, stdhttp.MethodGet, parsed.String(), nil)
	if err != nil {
		path.FailureReason = model.FailureReasonProbeExecution
		path.Error = safeErrorString(err.Error())
		return path
	}
	path.RequestAttempted = true
	response, err := client.Do(request)
	if err != nil {
		path.FailureReason = classifyHTTPError(err, requestCtx)
		path.Error = safeErrorString(err.Error())
		if certificates := certificatesFromTLSError(err); len(certificates) > 0 {
			// A peer certificate is only available after the TCP connection has
			// been established and TLS has started, even though the handshake
			// may have failed verification.
			path.TCPConnected = true
			path.TLSAttempted = true
			path.CertificateTrusted = certificateChainTrusted(err)
			path.Certificate = CertificateMetadata(certificates[0])
			path.HostnameVerified = certificates[0].VerifyHostname(parsed.Hostname()) == nil
		}
		return path
	}
	defer response.Body.Close()
	path.TCPConnected = true
	path.HTTPResponse = true
	path.HTTPStatusCode = response.StatusCode
	if response.TLS != nil {
		path.TLSHandshake = response.TLS.HandshakeComplete
		path.TLSAttempted = true
		path.CertificateTrusted = true
		path.HostnameVerified = true
		if len(response.TLS.PeerCertificates) > 0 {
			path.Certificate = CertificateMetadata(response.TLS.PeerCertificates[0])
		}
	}
	if response.StatusCode == stdhttp.StatusProxyAuthRequired {
		path.ConnectOutcome = ConnectAuthRequired
		path.ProxyAuthenticationHint = true
		path.FailureReason = model.FailureReasonProxyAuthenticationRequired
		return path
	}
	if response.StatusCode >= 400 {
		path.FailureReason = model.FailureReasonHTTPStatusCode
		return path
	}
	path.FailureReason = model.FailureReasonNone
	return path
}

func certificateChainTrusted(err error) bool {
	// A hostname error means the chain was otherwise verified but the peer
	// identity did not match the requested host. Keep that distinction from
	// an untrusted/invalid chain so trust-store mismatch correlation remains
	// conservative.
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	// Keep the nested check explicit for Go versions or wrappers that expose
	// the TLS verification error without traversing its underlying x509 error
	// through errors.As.
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		var nestedHostnameErr x509.HostnameError
		return errors.As(verificationErr.Err, &nestedHostnameErr)
	}
	return false
}

func certificatesFromTLSError(err error) []*x509.Certificate {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		if len(verificationErr.UnverifiedCertificates) > 0 {
			return verificationErr.UnverifiedCertificates
		}
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) && unknownAuthority.Cert != nil {
		return []*x509.Certificate{unknownAuthority.Cert}
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) && hostnameErr.Certificate != nil {
		return []*x509.Certificate{hostnameErr.Certificate}
	}
	return nil
}

func classifyHTTPError(err error, ctx context.Context) model.FailureReason {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return model.FailureReasonTCPTimeout
	}
	if errors.Is(err, context.Canceled) {
		return model.FailureReasonProbeExecution
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return model.FailureReasonDNSNXDomain
		}
		return model.FailureReasonDNSResolverFailure
	}
	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		return model.FailureReasonCertificateValidationFailure
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return model.FailureReasonCertificateValidationFailure
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return model.FailureReasonCertificateValidationFailure
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.FailureReasonTCPTimeout
	}
	return model.FailureReasonNetworkUnreachable
}
