package model

import "strings"

// EnterpriseObservationState describes the availability of an optional
// Windows enterprise subsystem. It is deliberately separate from
// ObservationCertainty: a collected value can be observed while the overall
// subsystem is only partially available.
type EnterpriseObservationState string

const (
	EnterpriseObservationStateUnknown     EnterpriseObservationState = "unknown"
	EnterpriseObservationStateObserved    EnterpriseObservationState = "observed"
	EnterpriseObservationStatePartial     EnterpriseObservationState = "partial"
	EnterpriseObservationStateUnsupported EnterpriseObservationState = "unsupported"
	EnterpriseObservationStateUnavailable EnterpriseObservationState = "unavailable"
)

const (
	EnterpriseProxyModeDirect  = "direct"
	EnterpriseProxyModeProxy   = "proxy"
	EnterpriseProxyModePAC     = "pac"
	EnterpriseProxyModeUnknown = "unknown"
)

// EnterpriseProxyDecision is the target-specific outcome of evaluating one
// proxy source. It is deliberately separate from EnterpriseProxyMode: mode
// describes the selected transport mechanism, while decision also records
// bypass, authentication, unavailable PAC, and conflicting evidence states.
const (
	EnterpriseProxyDecisionDirect                 = "direct"
	EnterpriseProxyDecisionStaticProxy            = "static_proxy"
	EnterpriseProxyDecisionPACSelectedProxy       = "pac_selected_proxy"
	EnterpriseProxyDecisionBypassMatch            = "bypass_match"
	EnterpriseProxyDecisionAuthenticationRequired = "authentication_required"
	EnterpriseProxyDecisionPACResultUnavailable   = "pac_result_unavailable"
	EnterpriseProxyDecisionUnsupported            = "unsupported"
	EnterpriseProxyDecisionUnknown                = "unknown"
	EnterpriseProxyDecisionConflicting            = "conflicting"
)

// Short aliases keep callers from having to encode the distinction between a
// PAC-selected proxy and a bypass match themselves.
const (
	EnterpriseProxyDecisionPACProxy = EnterpriseProxyDecisionPACSelectedProxy
	EnterpriseProxyDecisionBypass   = EnterpriseProxyDecisionBypassMatch
)

const (
	EnterpriseEndpointReachable   = "reachable"
	EnterpriseEndpointUnavailable = "unavailable"
	EnterpriseEndpointTimeout     = "timeout"
	EnterpriseEndpointUnknown     = "unknown"
	EnterpriseEndpointNotTested   = "not_tested"
)

const (
	EnterprisePathComparisonUnknown                 = "unknown"
	EnterprisePathComparisonBothWork                = "both_work"
	EnterprisePathComparisonDirectFailureProxyWorks = "direct_failure_proxy_success"
	EnterprisePathComparisonDirectWorksProxyFailure = "direct_success_proxy_failure"
	EnterprisePathComparisonBothFail                = "both_fail"
	EnterpriseFirewallCausalityNotEstablished       = "not_established"
	EnterpriseInterceptionSuspicionNotEstablished   = "not_established"
	EnterpriseInterceptionSuspicionPossible         = "possible"
)

// EnterpriseProxyConfigurationObservation is the normalized configuration
// view for one Windows proxy source. Its fields describe local configuration;
// they do not claim that an application selected or used the setting.
type EnterpriseProxyConfigurationObservation struct {
	State                 string               `json:"state"`
	Direct                bool                 `json:"direct"`
	StaticProxyConfigured bool                 `json:"static_proxy_configured"`
	ProxyEndpoints        []string             `json:"proxy_endpoints,omitempty"`
	ProxyBypass           []string             `json:"proxy_bypass,omitempty"`
	PACConfigured         bool                 `json:"pac_configured"`
	PACURL                string               `json:"pac_url,omitempty"`
	AutoDetect            bool                 `json:"auto_detect,omitempty"`
	Error                 string               `json:"error,omitempty"`
	Certainty             ObservationCertainty `json:"certainty"`
	Provenance            []string             `json:"provenance,omitempty"`
	EvidenceIDs           []string             `json:"evidence_ids,omitempty"`
	Limitations           []string             `json:"limitations,omitempty"`
}

// EnterpriseProxyEffectiveObservation is the URL-specific result returned
// by native proxy/PAC resolution. It is runtime evidence, not configuration.
type EnterpriseProxyEffectiveObservation struct {
	Observed            bool                 `json:"observed"`
	Decision            string               `json:"decision"`
	Mode                string               `json:"mode"`
	Endpoint            string               `json:"endpoint,omitempty"`
	Bypass              []string             `json:"bypass,omitempty"`
	BypassMatched       bool                 `json:"bypass_matched"`
	PACUsed             bool                 `json:"pac_used"`
	AutoDetect          bool                 `json:"auto_detect"`
	ResolutionAttempted bool                 `json:"resolution_attempted"`
	ResolutionOK        bool                 `json:"resolution_ok"`
	Error               string               `json:"error,omitempty"`
	Certainty           ObservationCertainty `json:"certainty"`
	Provenance          []string             `json:"provenance,omitempty"`
	EvidenceIDs         []string             `json:"evidence_ids,omitempty"`
	Limitations         []string             `json:"limitations,omitempty"`
}

// EnterprisePACObservation keeps PAC configuration and the URL-specific
// resolution result in separate fields. A configured PAC URL is never
// promoted to a selected PAC result without effective-proxy evidence.
type EnterprisePACObservation struct {
	Configured         bool                 `json:"configured"`
	AutoDetect         bool                 `json:"auto_detect"`
	URL                string               `json:"url,omitempty"`
	ResolutionObserved bool                 `json:"resolution_observed"`
	ResolutionOK       bool                 `json:"resolution_ok"`
	Used               bool                 `json:"used"`
	Mode               string               `json:"mode"`
	Decision           string               `json:"decision"`
	Endpoint           string               `json:"endpoint,omitempty"`
	Bypass             []string             `json:"bypass,omitempty"`
	BypassMatched      bool                 `json:"bypass_matched"`
	Certainty          ObservationCertainty `json:"certainty"`
	Provenance         []string             `json:"provenance,omitempty"`
	EvidenceIDs        []string             `json:"evidence_ids,omitempty"`
	Limitations        []string             `json:"limitations,omitempty"`
}

// EnterpriseProxyEndpointObservation correlates an effective path with its
// proxy endpoint. Reaching a proxy and receiving CONNECT denial are distinct
// facts: endpoint reachability does not imply request success.
type EnterpriseProxyEndpointObservation struct {
	Endpoint       string               `json:"endpoint"`
	Reachability   string               `json:"reachability"`
	TCPConnected   bool                 `json:"tcp_connected"`
	ConnectOutcome string               `json:"connect_outcome"`
	StatusCode     int                  `json:"status_code,omitempty"`
	Certainty      ObservationCertainty `json:"certainty"`
	Provenance     []string             `json:"provenance,omitempty"`
	EvidenceIDs    []string             `json:"evidence_ids,omitempty"`
	Limitations    []string             `json:"limitations,omitempty"`
}

// EnterpriseProxySourceObservation is one independent WinHTTP or WinINET
// view. Keeping sources separate makes divergence explicit and deterministic.
type EnterpriseProxySourceObservation struct {
	Source               string                                  `json:"source"`
	Configuration        EnterpriseProxyConfigurationObservation `json:"configuration"`
	Effective            EnterpriseProxyEffectiveObservation     `json:"effective"`
	PAC                  EnterprisePACObservation                `json:"pac"`
	EndpointReachability []EnterpriseProxyEndpointObservation    `json:"endpoint_reachability,omitempty"`
	Certainty            ObservationCertainty                    `json:"certainty"`
	Provenance           []string                                `json:"provenance,omitempty"`
	EvidenceIDs          []string                                `json:"evidence_ids,omitempty"`
	Limitations          []string                                `json:"limitations,omitempty"`
}

// EnterprisePathObservation is the canonical runtime result for one direct,
// browser, or service path. It is intentionally a path fact rather than a
// report diagnosis.
type EnterprisePathObservation struct {
	Name                    string               `json:"name"`
	Source                  string               `json:"source,omitempty"`
	Mode                    string               `json:"mode"`
	Endpoint                string               `json:"endpoint,omitempty"`
	RequestAttempted        bool                 `json:"request_attempted"`
	TCPConnected            bool                 `json:"tcp_connected"`
	ConnectOutcome          string               `json:"connect_outcome"`
	ConnectStatusCode       int                  `json:"connect_status_code,omitempty"`
	ProxyAuthenticationHint bool                 `json:"proxy_authentication_hint,omitempty"`
	HTTPResponse            bool                 `json:"http_response"`
	HTTPStatusCode          int                  `json:"http_status_code,omitempty"`
	TLSHandshake            bool                 `json:"tls_handshake"`
	TLSAttempted            bool                 `json:"tls_attempted"`
	CertificateTrusted      bool                 `json:"certificate_trusted"`
	HostnameVerified        bool                 `json:"hostname_verified"`
	CertificateSHA256       string               `json:"certificate_sha256,omitempty"`
	CertificateSubject      string               `json:"certificate_subject,omitempty"`
	CertificateIssuer       string               `json:"certificate_issuer,omitempty"`
	FailureReason           FailureReason        `json:"failure_reason"`
	Error                   string               `json:"error,omitempty"`
	Certainty               ObservationCertainty `json:"certainty"`
	Provenance              []string             `json:"provenance,omitempty"`
	EvidenceIDs             []string             `json:"evidence_ids,omitempty"`
	Limitations             []string             `json:"limitations,omitempty"`
}

// EnterprisePathComparisonObservation is a comparison of collected path
// outcomes. PolicyPossible is an inference and is never a firewall-causality
// claim.
type EnterprisePathComparisonObservation struct {
	DirectPath       string               `json:"direct_path,omitempty"`
	ProxyPaths       []string             `json:"proxy_paths,omitempty"`
	DirectWorks      bool                 `json:"direct_works"`
	DirectWorksKnown bool                 `json:"direct_works_known"`
	ProxyWorks       bool                 `json:"proxy_works"`
	ProxyWorksKnown  bool                 `json:"proxy_works_known"`
	State            string               `json:"state"`
	PolicyPossible   bool                 `json:"policy_possible"`
	Certainty        ObservationCertainty `json:"certainty"`
	Provenance       []string             `json:"provenance,omitempty"`
	EvidenceIDs      []string             `json:"evidence_ids,omitempty"`
	Limitations      []string             `json:"limitations,omitempty"`
}

// EnterpriseFirewallProfileObservation reports profile state only. Enabled
// is configuration/effective profile evidence; BlockCausality intentionally
// remains not_established unless a separate causal probe exists.
type EnterpriseFirewallProfileObservation struct {
	Name                   string               `json:"name"`
	FirewallEnabled        *bool                `json:"firewall_enabled,omitempty"`
	BlockInboundExceptions *bool                `json:"block_inbound_exceptions,omitempty"`
	PolicyPresent          bool                 `json:"policy_present"`
	EffectiveState         string               `json:"effective_state"`
	BlockCausality         string               `json:"block_causality"`
	Certainty              ObservationCertainty `json:"certainty"`
	Provenance             []string             `json:"provenance,omitempty"`
	EvidenceIDs            []string             `json:"evidence_ids,omitempty"`
	Limitations            []string             `json:"limitations,omitempty"`
}

type EnterpriseFirewallObservation struct {
	State          EnterpriseObservationState             `json:"state"`
	Available      bool                                   `json:"available"`
	Profiles       []EnterpriseFirewallProfileObservation `json:"profiles,omitempty"`
	Error          string                                 `json:"error,omitempty"`
	Insufficient   bool                                   `json:"insufficient_privilege,omitempty"`
	BlockCausality string                                 `json:"block_causality"`
	Certainty      ObservationCertainty                   `json:"certainty"`
	Provenance     []string                               `json:"provenance,omitempty"`
	EvidenceIDs    []string                               `json:"evidence_ids,omitempty"`
	Limitations    []string                               `json:"limitations,omitempty"`
}

// EnterpriseAdapterParticipationObservation retains only adapter facts that
// matter to enterprise path correlation. Full route selection remains in the
// canonical NetworkContext and is referenced rather than copied here.
type EnterpriseAdapterParticipationObservation struct {
	Index       int                  `json:"index"`
	Name        string               `json:"name"`
	Type        string               `json:"type,omitempty"`
	IfType      uint32               `json:"if_type,omitempty"`
	Operational bool                 `json:"operational"`
	VPN         bool                 `json:"vpn"`
	Virtual     bool                 `json:"virtual"`
	Certainty   ObservationCertainty `json:"certainty"`
	Provenance  []string             `json:"provenance,omitempty"`
	EvidenceIDs []string             `json:"evidence_ids,omitempty"`
}

// EnterpriseNetworkCorrelationObservation links enterprise evidence to the
// already-normalized NetworkContext without introducing a second route model.
type EnterpriseNetworkCorrelationObservation struct {
	AdapterParticipation          []EnterpriseAdapterParticipationObservation `json:"adapter_participation,omitempty"`
	VPNAdapterPresent             bool                                        `json:"vpn_adapter_present"`
	VPNAdapterPresentKnown        bool                                        `json:"vpn_adapter_present_known"`
	VirtualAdapterPresent         bool                                        `json:"virtual_adapter_present"`
	VirtualAdapterPresentKnown    bool                                        `json:"virtual_adapter_present_known"`
	SelectedRouteUsesVPN          bool                                        `json:"selected_route_uses_vpn"`
	SelectedRouteUsesVPNKnown     bool                                        `json:"selected_route_uses_vpn_known"`
	SelectedRouteUsesVirtual      bool                                        `json:"selected_route_uses_virtual_adapter"`
	SelectedRouteUsesVirtualKnown bool                                        `json:"selected_route_uses_virtual_adapter_known"`
	RouteDifference               bool                                        `json:"route_difference"`
	RouteDifferenceKnown          bool                                        `json:"route_difference_known"`
	NetworkContextReferenced      bool                                        `json:"network_context_referenced"`
	NetworkContextCertainty       ObservationCertainty                        `json:"network_context_certainty"`
	NetworkContextEvidenceIDs     []string                                    `json:"network_context_evidence_ids,omitempty"`
	Certainty                     ObservationCertainty                        `json:"certainty"`
	Provenance                    []string                                    `json:"provenance,omitempty"`
	EvidenceIDs                   []string                                    `json:"evidence_ids,omitempty"`
	Limitations                   []string                                    `json:"limitations,omitempty"`
}

// EnterpriseTLSPolicyObservation retains trust-store and paired-certificate
// facts that can support a policy/interception suspicion. Suspicion is never
// elevated to certainty merely because certificates differ.
type EnterpriseTLSPolicyObservation struct {
	State                            EnterpriseObservationState `json:"state"`
	TrustStoreAvailable              bool                       `json:"trust_store_available"`
	TrustStoreRootCount              int                        `json:"trust_store_root_count,omitempty"`
	TrustStoreInsufficient           bool                       `json:"trust_store_insufficient_privilege,omitempty"`
	DirectCertificateSHA256          string                     `json:"direct_certificate_sha256,omitempty"`
	ProxyCertificateSHA256           string                     `json:"proxy_certificate_sha256,omitempty"`
	DirectCertificateSubject         string                     `json:"direct_certificate_subject,omitempty"`
	ProxyCertificateSubject          string                     `json:"proxy_certificate_subject,omitempty"`
	DirectCertificateIssuer          string                     `json:"direct_certificate_issuer,omitempty"`
	ProxyCertificateIssuer           string                     `json:"proxy_certificate_issuer,omitempty"`
	CertificatesDiffer               bool                       `json:"certificates_differ"`
	CertificatesDifferKnown          bool                       `json:"certificates_differ_known"`
	IssuersDiffer                    bool                       `json:"issuers_differ"`
	IssuersDifferKnown               bool                       `json:"issuers_differ_known"`
	BothTrusted                      bool                       `json:"both_trusted"`
	BothTrustedKnown                 bool                       `json:"both_trusted_known"`
	BothHostnameVerified             bool                       `json:"both_hostname_verified"`
	BothHostnameKnown                bool                       `json:"both_hostname_verified_known"`
	PossibleInterception             bool                       `json:"possible_interception"`
	InterceptionSuspicion            string                     `json:"interception_suspicion"`
	InterceptionBasis                string                     `json:"interception_basis,omitempty"`
	TrustMismatch                    bool                       `json:"trust_mismatch"`
	TrustMismatchKnown               bool                       `json:"trust_mismatch_known"`
	TrustedCorporatePrivateRootKnown bool                       `json:"trusted_corporate_private_root_known"`
	TrustedCorporatePrivateRoot      bool                       `json:"trusted_corporate_private_root"`
	Certainty                        ObservationCertainty       `json:"certainty"`
	Provenance                       []string                   `json:"provenance,omitempty"`
	EvidenceIDs                      []string                   `json:"evidence_ids,omitempty"`
	Limitations                      []string                   `json:"limitations,omitempty"`
	Conflicts                        []ObservationConflict      `json:"conflicts,omitempty"`
}

// EnterprisePolicyObservation is the single report-level enterprise/policy
// domain. It projects raw Windows enterprise evidence into normalized facts;
// raw evidence remains available on the originating ProbeResult.
type EnterprisePolicyObservation struct {
	RequestedIdentity          string                                  `json:"requested_identity"`
	State                      EnterpriseObservationState              `json:"state"`
	Unsupported                bool                                    `json:"unsupported"`
	WinHTTP                    EnterpriseProxySourceObservation        `json:"winhttp"`
	WinINET                    EnterpriseProxySourceObservation        `json:"wininet"`
	ProxyConfigurationDiverges bool                                    `json:"proxy_configuration_diverges"`
	ProxyConfigurationKnown    bool                                    `json:"proxy_configuration_divergence_known"`
	EffectiveDecisionDiverges  bool                                    `json:"effective_decision_diverges"`
	EffectiveDecisionKnown     bool                                    `json:"effective_decision_divergence_known"`
	Paths                      []EnterprisePathObservation             `json:"paths,omitempty"`
	DirectVsProxy              EnterprisePathComparisonObservation     `json:"direct_vs_proxy"`
	Firewall                   EnterpriseFirewallObservation           `json:"firewall"`
	Network                    EnterpriseNetworkCorrelationObservation `json:"network"`
	TLS                        EnterpriseTLSPolicyObservation          `json:"tls"`
	Certainty                  ObservationCertainty                    `json:"certainty"`
	Provenance                 []string                                `json:"provenance,omitempty"`
	EvidenceIDs                []string                                `json:"evidence_ids,omitempty"`
	ProbeNames                 []string                                `json:"probe_names,omitempty"`
	Limitations                []string                                `json:"limitations,omitempty"`
	Conflicts                  []ObservationConflict                   `json:"conflicts,omitempty"`
}

// NormalizeEnterprisePolicyObservation returns a detached normalized copy.
// It keeps configuration, runtime, and inference fields separate and does not
// manufacture values when a subsystem did not provide evidence.
func NormalizeEnterprisePolicyObservation(observation EnterprisePolicyObservation) EnterprisePolicyObservation {
	result := observation
	result.Provenance = uniqueStringValues(observation.Provenance)
	result.EvidenceIDs = uniqueStringValues(observation.EvidenceIDs)
	result.ProbeNames = uniqueStringValues(observation.ProbeNames)
	result.Limitations = uniqueStringValues(observation.Limitations)
	result.Conflicts = cloneObservationConflicts(observation.Conflicts)
	result.WinHTTP = normalizeEnterpriseProxySource(observation.WinHTTP)
	result.WinINET = normalizeEnterpriseProxySource(observation.WinINET)
	result.Paths = cloneEnterprisePaths(observation.Paths)
	result.DirectVsProxy = normalizeEnterprisePathComparison(observation.DirectVsProxy)
	result.Firewall = normalizeEnterpriseFirewall(observation.Firewall)
	result.Network = normalizeEnterpriseNetwork(observation.Network)
	result.TLS = normalizeEnterpriseTLS(observation.TLS)
	return result
}

func normalizeEnterpriseProxySource(value EnterpriseProxySourceObservation) EnterpriseProxySourceObservation {
	value.Source = normalizeNameValue(value.Source)
	value.Configuration = normalizeEnterpriseProxyConfiguration(value.Configuration)
	value.Effective = normalizeEnterpriseProxyEffective(value.Effective)
	value.PAC = normalizeEnterprisePAC(value.PAC)
	value.EndpointReachability = cloneEnterpriseEndpoints(value.EndpointReachability)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	return value
}

func normalizeEnterpriseProxyConfiguration(value EnterpriseProxyConfigurationObservation) EnterpriseProxyConfigurationObservation {
	value.State = strings.TrimSpace(value.State)
	value.ProxyEndpoints = uniqueStringValues(value.ProxyEndpoints)
	value.ProxyBypass = uniqueStringValues(value.ProxyBypass)
	value.Error = boundedObservationText(value.Error)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	return value
}

func normalizeEnterpriseProxyEffective(value EnterpriseProxyEffectiveObservation) EnterpriseProxyEffectiveObservation {
	value.Decision = strings.TrimSpace(value.Decision)
	if value.Decision == "" {
		value.Decision = EnterpriseProxyDecisionUnknown
	}
	value.Mode = strings.TrimSpace(value.Mode)
	value.Endpoint = strings.TrimSpace(value.Endpoint)
	value.Bypass = uniqueStringValues(value.Bypass)
	value.Error = boundedObservationText(value.Error)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	return value
}

func normalizeEnterprisePAC(value EnterprisePACObservation) EnterprisePACObservation {
	value.URL = strings.TrimSpace(value.URL)
	value.Mode = strings.TrimSpace(value.Mode)
	value.Decision = strings.TrimSpace(value.Decision)
	if value.Decision == "" {
		value.Decision = EnterpriseProxyDecisionUnknown
	}
	value.Endpoint = strings.TrimSpace(value.Endpoint)
	value.Bypass = uniqueStringValues(value.Bypass)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	return value
}

func cloneEnterpriseEndpoints(values []EnterpriseProxyEndpointObservation) []EnterpriseProxyEndpointObservation {
	if values == nil {
		return nil
	}
	result := make([]EnterpriseProxyEndpointObservation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Endpoint = strings.TrimSpace(value.Endpoint)
		result[index].Provenance = uniqueStringValues(value.Provenance)
		result[index].EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
		result[index].Limitations = uniqueStringValues(value.Limitations)
	}
	return result
}

func cloneEnterprisePaths(values []EnterprisePathObservation) []EnterprisePathObservation {
	if values == nil {
		return nil
	}
	result := make([]EnterprisePathObservation, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Provenance = uniqueStringValues(value.Provenance)
		result[index].EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
		result[index].Limitations = uniqueStringValues(value.Limitations)
		result[index].Error = boundedObservationText(value.Error)
	}
	return result
}

func normalizeEnterprisePathComparison(value EnterprisePathComparisonObservation) EnterprisePathComparisonObservation {
	value.ProxyPaths = uniqueStringValues(value.ProxyPaths)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	return value
}

func normalizeEnterpriseFirewall(value EnterpriseFirewallObservation) EnterpriseFirewallObservation {
	value.Error = boundedObservationText(value.Error)
	value.BlockCausality = strings.TrimSpace(value.BlockCausality)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	for index := range value.Profiles {
		value.Profiles[index].Name = strings.TrimSpace(value.Profiles[index].Name)
		value.Profiles[index].EffectiveState = strings.TrimSpace(value.Profiles[index].EffectiveState)
		value.Profiles[index].BlockCausality = strings.TrimSpace(value.Profiles[index].BlockCausality)
		value.Profiles[index].Provenance = uniqueStringValues(value.Profiles[index].Provenance)
		value.Profiles[index].EvidenceIDs = uniqueStringValues(value.Profiles[index].EvidenceIDs)
		value.Profiles[index].Limitations = uniqueStringValues(value.Profiles[index].Limitations)
	}
	return value
}

func normalizeEnterpriseNetwork(value EnterpriseNetworkCorrelationObservation) EnterpriseNetworkCorrelationObservation {
	value.NetworkContextEvidenceIDs = uniqueStringValues(value.NetworkContextEvidenceIDs)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	for index := range value.AdapterParticipation {
		value.AdapterParticipation[index].Name = strings.TrimSpace(value.AdapterParticipation[index].Name)
		value.AdapterParticipation[index].Type = strings.TrimSpace(value.AdapterParticipation[index].Type)
		value.AdapterParticipation[index].Provenance = uniqueStringValues(value.AdapterParticipation[index].Provenance)
		value.AdapterParticipation[index].EvidenceIDs = uniqueStringValues(value.AdapterParticipation[index].EvidenceIDs)
	}
	return value
}

func normalizeEnterpriseTLS(value EnterpriseTLSPolicyObservation) EnterpriseTLSPolicyObservation {
	value.InterceptionSuspicion = strings.TrimSpace(value.InterceptionSuspicion)
	value.Provenance = uniqueStringValues(value.Provenance)
	value.EvidenceIDs = uniqueStringValues(value.EvidenceIDs)
	value.Limitations = uniqueStringValues(value.Limitations)
	value.Conflicts = cloneObservationConflicts(value.Conflicts)
	return value
}

func boundedObservationText(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 256 {
		return value[:256]
	}
	return value
}
