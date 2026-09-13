// Package model owns the versioned, JSON-serializable diagnostic contracts.
//
// Raw observations are carried by Evidence.Raw. Normalized interpretation is
// carried by ProbeInterpretation and DiagnosticFinding. Keeping those values
// in separate fields prevents a human-facing explanation from becoming the
// source of truth for a result.
package model

import (
	"encoding/json"
	"time"
)

// DiagnosticSchemaVersion is the schema version emitted in a
// DiagnosticReport. It changes only when the canonical JSON contract changes.
const DiagnosticSchemaVersion = "3"

// ProbeStatus describes what happened when a probe ran. Failed means that the
// probe observed a negative result; Error means that it could not produce a
// valid observation. The normalized reason for either case belongs in
// ProbeInterpretation.
type ProbeStatus string

const (
	ProbeStatusUnknown ProbeStatus = "unknown"
	ProbeStatusPassed  ProbeStatus = "passed"
	ProbeStatusFailed  ProbeStatus = "failed"
	ProbeStatusSkipped ProbeStatus = "skipped"
	ProbeStatusError   ProbeStatus = "error"
)

// ReportStatus describes execution completeness of a diagnostic report. It
// does not encode a diagnosis; DiagnosticReport.Findings carries that
// interpretation separately.
type ReportStatus string

const (
	ReportStatusUnknown    ReportStatus = "unknown"
	ReportStatusComplete   ReportStatus = "complete"
	ReportStatusIncomplete ReportStatus = "incomplete"
	ReportStatusError      ReportStatus = "error"
)

// FailureReason is a stable machine-readable classification. These values
// are deliberately not presentation strings. New probe-specific reasons may
// be added without changing the shape of a result.
type FailureReason string

const (
	FailureReasonNone                         FailureReason = "none"
	FailureReasonUnknown                      FailureReason = "unknown"
	FailureReasonProbeExecution               FailureReason = "probe_execution_failure"
	FailureReasonUnsupported                  FailureReason = "unsupported"
	FailureReasonInterfaceDown                FailureReason = "interface_down"
	FailureReasonNoIPAddress                  FailureReason = "no_ip_address"
	FailureReasonNoRoute                      FailureReason = "no_route"
	FailureReasonInvalidRoute                 FailureReason = "invalid_route"
	FailureReasonGatewayUnreachable           FailureReason = "gateway_unreachable"
	FailureReasonNetworkUnreachable           FailureReason = "network_unreachable"
	FailureReasonDNSNXDomain                  FailureReason = "dns_nxdomain"
	FailureReasonDNSNoAnswer                  FailureReason = "dns_no_answer"
	FailureReasonDNSTimeout                   FailureReason = "dns_timeout"
	FailureReasonDNSResolverFailure           FailureReason = "dns_resolver_failure"
	FailureReasonFirewallBlocked              FailureReason = "firewall_blocked"
	FailureReasonProxyConfigurationFailure    FailureReason = "proxy_configuration_failure"
	FailureReasonProxyConfigurationDivergence FailureReason = "proxy_configuration_divergence"
	FailureReasonProxyUnavailable             FailureReason = "proxy_unavailable"
	FailureReasonProxyConnectDenied           FailureReason = "proxy_connect_denied"
	FailureReasonProxyAuthenticationRequired  FailureReason = "proxy_authentication_required"
	FailureReasonDirectEgressRestricted       FailureReason = "direct_egress_restricted"
	FailureReasonEffectiveRouteDifference     FailureReason = "effective_route_difference"
	FailureReasonTCPTimeout                   FailureReason = "tcp_timeout"
	FailureReasonTCPConnectionRefused         FailureReason = "tcp_connection_refused"
	FailureReasonTCPConnectionReset           FailureReason = "tcp_connection_reset"
	FailureReasonTCPSYNNotObserved            FailureReason = "tcp_syn_not_observed"
	FailureReasonTLSHandshakeFailure          FailureReason = "tls_handshake_failure"
	FailureReasonCertificateValidationFailure FailureReason = "certificate_validation_failure"
	FailureReasonTLSTrustStoreMismatch        FailureReason = "tls_trust_store_mismatch"
	FailureReasonTLSInterceptionSuspected     FailureReason = "tls_interception_suspected"
	FailureReasonHTTPFailure                  FailureReason = "http_failure"
	FailureReasonHTTPStatusCode               FailureReason = "http_status_code"
	FailureReasonSSHHandshakeFailure          FailureReason = "ssh_handshake_failure"
	FailureReasonSSHTimeout                   FailureReason = "ssh_timeout"
	FailureReasonSSHBannerMalformed           FailureReason = "ssh_banner_malformed"
	FailureReasonSSHNonSSHResponse            FailureReason = "ssh_non_ssh_response"
	FailureReasonRDPNegotiationFailure        FailureReason = "rdp_negotiation_failure"
	FailureReasonRDPTimeout                   FailureReason = "rdp_timeout"
	FailureReasonRDPNegotiationMalformed      FailureReason = "rdp_negotiation_malformed"
	FailureReasonRDPNegotiationRejected       FailureReason = "rdp_negotiation_rejected"
	FailureReasonICMPFailure                  FailureReason = "icmp_failure"
	FailureReasonPathObservation              FailureReason = "path_observation_failure"
	FailureReasonPathCancellation             FailureReason = "path_cancellation"
)

// FaultDomain identifies the component or boundary most closely associated
// with an interpretation. It is intentionally distinct from Layer: a DNS
// probe can be at the DNS layer while a finding is owned by a local resolver,
// network, or firewall domain.
type FaultDomain string

const (
	FaultDomainUnknown     FaultDomain = "unknown"
	FaultDomainLocal       FaultDomain = "local"
	FaultDomainRouting     FaultDomain = "routing"
	FaultDomainGateway     FaultDomain = "gateway"
	FaultDomainDNS         FaultDomain = "dns"
	FaultDomainNetwork     FaultDomain = "network"
	FaultDomainFirewall    FaultDomain = "firewall"
	FaultDomainProxy       FaultDomain = "proxy"
	FaultDomainTransport   FaultDomain = "transport"
	FaultDomainTLS         FaultDomain = "tls"
	FaultDomainHTTP        FaultDomain = "http"
	FaultDomainSSH         FaultDomain = "ssh"
	FaultDomainRDP         FaultDomain = "rdp"
	FaultDomainDestination FaultDomain = "destination"
	FaultDomainICMP        FaultDomain = "icmp"
	FaultDomainPolicy      FaultDomain = "policy"
)

// Layer identifies the diagnostic protocol or system layer at which a probe
// made its observation.
type Layer string

const (
	LayerUnknown         Layer = "unknown"
	LayerInterface       Layer = "interface"
	LayerIPConfiguration Layer = "ip_configuration"
	LayerRoute           Layer = "route"
	LayerGateway         Layer = "gateway"
	LayerDNS             Layer = "dns"
	LayerNetwork         Layer = "network"
	LayerProxy           Layer = "proxy"
	LayerTCP             Layer = "tcp"
	LayerTLS             Layer = "tls"
	LayerHTTP            Layer = "http"
	LayerSSH             Layer = "ssh"
	LayerRDP             Layer = "rdp"
	LayerICMP            Layer = "icmp"
	LayerDestination     Layer = "destination"
)

// EvidenceKind names the raw observation shape. The raw payload itself is
// intentionally not prescribed so native Windows APIs and command output can
// be preserved without lossy conversion.
type EvidenceKind string

const (
	EvidenceKindUnknown             EvidenceKind = "unknown"
	EvidenceKindInterfaceState      EvidenceKind = "interface_state"
	EvidenceKindIPConfiguration     EvidenceKind = "ip_configuration"
	EvidenceKindRoute               EvidenceKind = "route"
	EvidenceKindGatewayReachability EvidenceKind = "gateway_reachability"
	EvidenceKindDNSConfiguration    EvidenceKind = "dns_configuration"
	EvidenceKindDNSResolution       EvidenceKind = "dns_resolution"
	EvidenceKindDNSService          EvidenceKind = "dns_service"
	EvidenceKindTCPConnection       EvidenceKind = "tcp_connection"
	EvidenceKindTLSHandshake        EvidenceKind = "tls_handshake"
	EvidenceKindCertificate         EvidenceKind = "certificate"
	EvidenceKindHTTPResponse        EvidenceKind = "http_response"
	EvidenceKindSSHHandshake        EvidenceKind = "ssh_handshake"
	EvidenceKindRDPNegotiation      EvidenceKind = "rdp_negotiation"
	EvidenceKindPathObservation     EvidenceKind = "path_observation"
	EvidenceKindProxyConfiguration  EvidenceKind = "proxy_configuration"
	EvidenceKindWinHTTPProxy        EvidenceKind = "winhttp_proxy"
	EvidenceKindWinINETProxy        EvidenceKind = "wininet_proxy"
	EvidenceKindPAC                 EvidenceKind = "pac"
	EvidenceKindProxyConnectivity   EvidenceKind = "proxy_connectivity"
	EvidenceKindTLSTrust            EvidenceKind = "tls_trust"
	EvidenceKindFirewallProfile     EvidenceKind = "firewall_profile"
	EvidenceKindAdapterRouting      EvidenceKind = "adapter_routing"
	EvidenceKindRouteComparison     EvidenceKind = "route_comparison"
	EvidenceKindICMP                EvidenceKind = "icmp"
	EvidenceKindPacketFlow          EvidenceKind = "packet_flow"
)

// Timing records execution timing. Timestamps are optional to support probes
// that only have a duration, while DurationMS is always an integer number of
// milliseconds when timing is available.
type Timing struct {
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	DurationMS  int64      `json:"duration_ms"`
}

// Evidence is an unmodified observation captured by a probe. Raw must be a
// valid JSON value: use a JSON string for text output and a JSON object or
// array for structured native data. Interpretation never belongs inside Raw.
type Evidence struct {
	ID         string          `json:"id"`
	Kind       EvidenceKind    `json:"kind"`
	Source     string          `json:"source,omitempty"`
	CapturedAt *time.Time      `json:"captured_at,omitempty"`
	Raw        json.RawMessage `json:"raw"`
}

// ProbeInterpretation contains only normalized, machine-readable meaning
// assigned to one probe result. It is separate from Evidence so callers can
// re-run diagnosis against the original observation.
type ProbeInterpretation struct {
	FailureReason FailureReason `json:"failure_reason"`
	Layer         Layer         `json:"layer"`
	FaultDomain   FaultDomain   `json:"fault_domain"`
}

// ProbeResult is the canonical output of one probe invocation. A successful
// result uses FailureReasonNone. A probe that only tests ICMP may report
// FailureReasonICMPFailure, but this field alone has no authority to set the
// report status or create a network finding.
type ProbeResult struct {
	Name           string                     `json:"name"`
	Target         Target                     `json:"target"`
	SessionID      string                     `json:"session_id,omitempty"`
	ProbeID        string                     `json:"probe_id,omitempty"`
	CorrelationID  string                     `json:"correlation_id,omitempty"`
	Status         ProbeStatus                `json:"status"`
	Timing         Timing                     `json:"timing"`
	Evidence       []Evidence                 `json:"evidence,omitempty"`
	NameResolution *NameResolutionObservation `json:"name_resolution,omitempty"`
	Interpretation ProbeInterpretation        `json:"interpretation"`
}

// DiagnosticFinding is a diagnosis engine output. It references probe and
// evidence identifiers rather than copying or rewriting raw observations.
// No human-facing message is part of the canonical contract.
type DiagnosticFinding struct {
	FailureReason FailureReason `json:"failure_reason"`
	Layer         Layer         `json:"layer"`
	FaultDomain   FaultDomain   `json:"fault_domain"`
	ProbeNames    []string      `json:"probe_names,omitempty"`
	EvidenceIDs   []string      `json:"evidence_ids,omitempty"`
}

// DiagnosticReport is the top-level canonical JSON document. Observations is
// the canonical cross-probe world model; probes retain raw evidence and
// per-probe interpretation, while Findings contains optional diagnosis.
type DiagnosticReport struct {
	SchemaVersion string              `json:"schema_version"`
	Target        Target              `json:"target"`
	SessionID     string              `json:"session_id,omitempty"`
	Status        ReportStatus        `json:"status"`
	StartedAt     *time.Time          `json:"started_at,omitempty"`
	CompletedAt   *time.Time          `json:"completed_at,omitempty"`
	Probes        []ProbeResult       `json:"probes"`
	Observations  Observations        `json:"observations"`
	Findings      []DiagnosticFinding `json:"findings,omitempty"`
}
