package model

import (
	"sort"
	"strings"
	"time"
)

// EnvironmentSnapshotSchemaVersion is independent of the diagnostic report
// schema. An environment snapshot has no destination and can be compared or
// exported without interpreting a target-specific report.
const EnvironmentSnapshotSchemaVersion = "1"

// EnvironmentObservationState describes the strength and availability of a
// local environment fact. In particular, configured is not observed use and
// present is not selected route participation.
type EnvironmentObservationState string

const (
	EnvironmentStateConfigured  EnvironmentObservationState = "configured"
	EnvironmentStateObserved    EnvironmentObservationState = "observed"
	EnvironmentStateInferred    EnvironmentObservationState = "inferred"
	EnvironmentStateUnknown     EnvironmentObservationState = "unknown"
	EnvironmentStateUnsupported EnvironmentObservationState = "unsupported"
	EnvironmentStateConflicting EnvironmentObservationState = "conflicting"
	EnvironmentStatePartial     EnvironmentObservationState = "partial"
)

// EnvironmentCapabilityState records whether a capability was available to
// the collector. It is intentionally separate from a fact's observation
// state: an unavailable capability is not a negative network result.
type EnvironmentCapabilityState string

const (
	EnvironmentCapabilityAvailable   EnvironmentCapabilityState = "available"
	EnvironmentCapabilityPartial     EnvironmentCapabilityState = "partial"
	EnvironmentCapabilityUnsupported EnvironmentCapabilityState = "unsupported"
	EnvironmentCapabilityUnknown     EnvironmentCapabilityState = "unknown"
	EnvironmentCapabilityDenied      EnvironmentCapabilityState = "insufficient_privilege"
)

// EnvironmentAddress is an interface address with its reported prefix.
type EnvironmentAddress struct {
	IP     string `json:"ip"`
	Prefix int    `json:"prefix"`
}

// EnvironmentInterface is the canonical, presentation-independent view of a
// local interface. VPN and virtual are conservative adapter classifications;
// they do not claim that traffic selected the adapter.
type EnvironmentInterface struct {
	Index         int                         `json:"index"`
	Name          string                      `json:"name"`
	Description   string                      `json:"description,omitempty"`
	Type          string                      `json:"type,omitempty"`
	Hardware      string                      `json:"hardware_address,omitempty"`
	MTU           int                         `json:"mtu"`
	Up            bool                        `json:"up"`
	Loopback      bool                        `json:"loopback"`
	VPN           bool                        `json:"vpn,omitempty"`
	Virtual       bool                        `json:"virtual,omitempty"`
	Addresses     []EnvironmentAddress        `json:"addresses,omitempty"`
	DNSServers    []string                    `json:"dns_servers,omitempty"`
	DNSSuffix     string                      `json:"dns_suffix,omitempty"`
	DNSSearchList []string                    `json:"dns_search_list,omitempty"`
	State         EnvironmentObservationState `json:"state"`
	Certainty     ObservationCertainty        `json:"certainty"`
	Provenance    []string                    `json:"provenance,omitempty"`
	EvidenceIDs   []string                    `json:"evidence_ids,omitempty"`
	Limitations   []string                    `json:"limitations,omitempty"`
}

// EnvironmentDNSObservation captures resolver configuration and policy only.
// It does not identify a server as effective for a query because no target is
// present in an environment snapshot.
type EnvironmentDNSObservation struct {
	State            EnvironmentObservationState `json:"state"`
	Servers          []string                    `json:"servers,omitempty"`
	Suffixes         []string                    `json:"suffixes,omitempty"`
	SearchList       []string                    `json:"search_list,omitempty"`
	NRPT             []NameResolutionPolicyRule  `json:"nrpt,omitempty"`
	HostsFileEntries []NameResolutionHostEntry   `json:"hosts_file_entries,omitempty"`
	ResolverError    string                      `json:"resolver_error,omitempty"`
	NRPTError        string                      `json:"nrpt_error,omitempty"`
	HostsFileError   string                      `json:"hosts_file_error,omitempty"`
	Certainty        ObservationCertainty        `json:"certainty"`
	Provenance       []string                    `json:"provenance,omitempty"`
	EvidenceIDs      []string                    `json:"evidence_ids,omitempty"`
	Limitations      []string                    `json:"limitations,omitempty"`
	Conflicts        []ObservationConflict       `json:"conflicts,omitempty"`
}

// EnvironmentRoute is a route-table row retained for target-independent
// default/effective routing context. Selected means preferred for its address
// family using the existing route-selection authority.
type EnvironmentRoute struct {
	RoutePrefix    string `json:"route_prefix"`
	Gateway        string `json:"gateway,omitempty"`
	NextHop        string `json:"next_hop,omitempty"`
	Interface      string `json:"interface,omitempty"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	SourceAddress  string `json:"source_address,omitempty"`
	Metric         int    `json:"metric"`
	InterfaceType  string `json:"interface_type,omitempty"`
	VPNOrTunnel    bool   `json:"vpn_or_tunnel,omitempty"`
	VirtualAdapter bool   `json:"virtual_adapter,omitempty"`
	Selected       bool   `json:"selected,omitempty"`
}

// EnvironmentRoutingObservation is deliberately not a target route. It
// reports the route table and selected default routes by family; a target
// report may reference NetworkContext for destination-specific selection.
type EnvironmentRoutingObservation struct {
	State           EnvironmentObservationState `json:"state"`
	Routes          []EnvironmentRoute          `json:"routes,omitempty"`
	DefaultIPv4     *EnvironmentRoute           `json:"default_ipv4,omitempty"`
	DefaultIPv6     *EnvironmentRoute           `json:"default_ipv6,omitempty"`
	RouteTableKnown bool                        `json:"route_table_known"`
	Error           string                      `json:"error,omitempty"`
	Certainty       ObservationCertainty        `json:"certainty"`
	Provenance      []string                    `json:"provenance,omitempty"`
	EvidenceIDs     []string                    `json:"evidence_ids,omitempty"`
	Limitations     []string                    `json:"limitations,omitempty"`
	Conflicts       []ObservationConflict       `json:"conflicts,omitempty"`
}

// EnvironmentProxySource is configuration evidence for one independent
// Windows proxy source. Effective use is intentionally absent because it
// requires a destination URL and application context.
type EnvironmentProxySource struct {
	Source                string                      `json:"source"`
	State                 EnvironmentObservationState `json:"state"`
	Direct                bool                        `json:"direct"`
	StaticProxyConfigured bool                        `json:"static_proxy_configured"`
	ProxyEndpoints        []string                    `json:"proxy_endpoints,omitempty"`
	ProxyBypass           []string                    `json:"proxy_bypass,omitempty"`
	PACConfigured         bool                        `json:"pac_configured"`
	PACURL                string                      `json:"pac_url,omitempty"`
	AutoDetect            bool                        `json:"auto_detect,omitempty"`
	Error                 string                      `json:"error,omitempty"`
	Certainty             ObservationCertainty        `json:"certainty"`
	Provenance            []string                    `json:"provenance,omitempty"`
	EvidenceIDs           []string                    `json:"evidence_ids,omitempty"`
	Limitations           []string                    `json:"limitations,omitempty"`
}

type EnvironmentProxyObservation struct {
	State                     EnvironmentObservationState `json:"state"`
	WinHTTP                   EnvironmentProxySource      `json:"winhttp"`
	WinINET                   EnvironmentProxySource      `json:"wininet"`
	ConfigurationDiverges     bool                        `json:"configuration_diverges"`
	ConfigurationKnown        bool                        `json:"configuration_known"`
	PACUseObserved            bool                        `json:"pac_use_observed"`
	EffectiveUseTargetBounded bool                        `json:"effective_use_target_bounded"`
	Certainty                 ObservationCertainty        `json:"certainty"`
	Provenance                []string                    `json:"provenance,omitempty"`
	EvidenceIDs               []string                    `json:"evidence_ids,omitempty"`
	Limitations               []string                    `json:"limitations,omitempty"`
	Conflicts                 []ObservationConflict       `json:"conflicts,omitempty"`
}

// EnvironmentVPNObservation keeps adapter presence separate from route
// selection. A VPN adapter can be present while no observed default route
// uses it.
type EnvironmentVPNObservation struct {
	State                   EnvironmentObservationState `json:"state"`
	Present                 bool                        `json:"present"`
	PresentKnown            bool                        `json:"present_known"`
	ActiveAdapters          []string                    `json:"active_adapters,omitempty"`
	VirtualAdapters         []string                    `json:"virtual_adapters,omitempty"`
	RouteParticipationKnown bool                        `json:"route_participation_known"`
	RouteParticipation      []string                    `json:"route_participation,omitempty"`
	Certainty               ObservationCertainty        `json:"certainty"`
	Provenance              []string                    `json:"provenance,omitempty"`
	EvidenceIDs             []string                    `json:"evidence_ids,omitempty"`
	Limitations             []string                    `json:"limitations,omitempty"`
}

// EnvironmentTrustObservation reports safe trust-store counts and access
// status. It does not dump roots or claim that any remote TLS connection used
// an enterprise CA.
type EnvironmentTrustObservation struct {
	State                 EnvironmentObservationState `json:"state"`
	Available             bool                        `json:"available"`
	RootCount             int                         `json:"root_count,omitempty"`
	EnterpriseRootSummary string                      `json:"enterprise_root_summary,omitempty"`
	InsufficientPrivilege bool                        `json:"insufficient_privilege,omitempty"`
	Error                 string                      `json:"error,omitempty"`
	Certainty             ObservationCertainty        `json:"certainty"`
	Provenance            []string                    `json:"provenance,omitempty"`
	EvidenceIDs           []string                    `json:"evidence_ids,omitempty"`
	Limitations           []string                    `json:"limitations,omitempty"`
}

// EnvironmentCapability exposes the capability context needed to interpret a
// missing or unsupported subsystem.
type EnvironmentCapability struct {
	Name   string                     `json:"name"`
	State  EnvironmentCapabilityState `json:"state"`
	Detail string                     `json:"detail,omitempty"`
}

type EnvironmentRuntimeObservation struct {
	State          EnvironmentObservationState `json:"state"`
	OS             string                      `json:"os"`
	Arch           string                      `json:"arch"`
	OSVersion      string                      `json:"os_version,omitempty"`
	RuntimeVersion string                      `json:"runtime_version"`
	TadoriVersion  string                      `json:"tadori_version"`
	Privilege      string                      `json:"privilege"`
	Capabilities   []EnvironmentCapability     `json:"capabilities"`
	Provenance     []string                    `json:"provenance,omitempty"`
	EvidenceIDs    []string                    `json:"evidence_ids,omitempty"`
	Limitations    []string                    `json:"limitations,omitempty"`
}

// EnvironmentSnapshot is the canonical target-independent local context.
// Every component retains explicit state and provenance so consumers can
// compare snapshots without reinterpreting presentation labels or raw probe
// payloads.
type EnvironmentSnapshot struct {
	SchemaVersion   string                        `json:"schema_version"`
	CapturedAt      time.Time                     `json:"captured_at"`
	State           EnvironmentObservationState   `json:"state"`
	Interfaces      []EnvironmentInterface        `json:"interfaces"`
	InterfacesState EnvironmentObservationState   `json:"interfaces_state"`
	DNS             EnvironmentDNSObservation     `json:"dns"`
	Routing         EnvironmentRoutingObservation `json:"routing"`
	Proxy           EnvironmentProxyObservation   `json:"proxy"`
	VPN             EnvironmentVPNObservation     `json:"vpn"`
	Firewall        EnterpriseFirewallObservation `json:"firewall"`
	Trust           EnvironmentTrustObservation   `json:"trust"`
	Runtime         EnvironmentRuntimeObservation `json:"runtime"`
	Provenance      []string                      `json:"provenance,omitempty"`
	EvidenceIDs     []string                      `json:"evidence_ids,omitempty"`
	Limitations     []string                      `json:"limitations,omitempty"`
	Conflicts       []ObservationConflict         `json:"conflicts,omitempty"`
}

// NormalizeEnvironmentSnapshot returns a detached, deterministic copy. It
// sorts collections whose order is not semantically meaningful and keeps
// contradictory values in Conflicts rather than selecting a winner.
func NormalizeEnvironmentSnapshot(snapshot *EnvironmentSnapshot) *EnvironmentSnapshot {
	if snapshot == nil {
		return nil
	}
	result := *snapshot
	if result.SchemaVersion == "" {
		result.SchemaVersion = EnvironmentSnapshotSchemaVersion
	}
	result.Interfaces = append([]EnvironmentInterface(nil), snapshot.Interfaces...)
	for index := range result.Interfaces {
		result.Interfaces[index].Addresses = append([]EnvironmentAddress(nil), snapshot.Interfaces[index].Addresses...)
		result.Interfaces[index].DNSServers = uniqueSorted(snapshot.Interfaces[index].DNSServers)
		result.Interfaces[index].DNSSearchList = uniqueSorted(snapshot.Interfaces[index].DNSSearchList)
		result.Interfaces[index].Provenance = uniqueSorted(snapshot.Interfaces[index].Provenance)
		result.Interfaces[index].EvidenceIDs = uniqueSorted(snapshot.Interfaces[index].EvidenceIDs)
		result.Interfaces[index].Limitations = uniqueSorted(snapshot.Interfaces[index].Limitations)
	}
	sort.SliceStable(result.Interfaces, func(i, j int) bool {
		if result.Interfaces[i].Index != result.Interfaces[j].Index {
			return result.Interfaces[i].Index < result.Interfaces[j].Index
		}
		return result.Interfaces[i].Name < result.Interfaces[j].Name
	})
	result.DNS.Servers = uniqueSorted(snapshot.DNS.Servers)
	result.DNS.Suffixes = uniqueSorted(snapshot.DNS.Suffixes)
	result.DNS.SearchList = uniqueSorted(snapshot.DNS.SearchList)
	result.DNS.Provenance = uniqueSorted(snapshot.DNS.Provenance)
	result.DNS.EvidenceIDs = uniqueSorted(snapshot.DNS.EvidenceIDs)
	result.DNS.Limitations = uniqueSorted(snapshot.DNS.Limitations)
	result.DNS.Conflicts = cloneObservationConflicts(snapshot.DNS.Conflicts)
	result.Routing.Routes = append([]EnvironmentRoute(nil), snapshot.Routing.Routes...)
	sort.SliceStable(result.Routing.Routes, func(i, j int) bool {
		return environmentRouteKey(result.Routing.Routes[i]) < environmentRouteKey(result.Routing.Routes[j])
	})
	result.Routing.Provenance = uniqueSorted(snapshot.Routing.Provenance)
	result.Routing.EvidenceIDs = uniqueSorted(snapshot.Routing.EvidenceIDs)
	result.Routing.Limitations = uniqueSorted(snapshot.Routing.Limitations)
	result.Routing.Conflicts = cloneObservationConflicts(snapshot.Routing.Conflicts)
	result.Routing.DefaultIPv4 = cloneEnvironmentRoute(snapshot.Routing.DefaultIPv4)
	result.Routing.DefaultIPv6 = cloneEnvironmentRoute(snapshot.Routing.DefaultIPv6)
	result.Proxy = normalizeEnvironmentProxy(snapshot.Proxy)
	result.VPN.ActiveAdapters = uniqueSorted(snapshot.VPN.ActiveAdapters)
	result.VPN.VirtualAdapters = uniqueSorted(snapshot.VPN.VirtualAdapters)
	result.VPN.RouteParticipation = uniqueSorted(snapshot.VPN.RouteParticipation)
	result.VPN.Provenance = uniqueSorted(snapshot.VPN.Provenance)
	result.VPN.EvidenceIDs = uniqueSorted(snapshot.VPN.EvidenceIDs)
	result.VPN.Limitations = uniqueSorted(snapshot.VPN.Limitations)
	result.Firewall = NormalizeEnterprisePolicyObservation(modelEnterpriseOnly(result.Firewall)).Firewall
	result.Trust.Provenance = uniqueSorted(snapshot.Trust.Provenance)
	result.Trust.EvidenceIDs = uniqueSorted(snapshot.Trust.EvidenceIDs)
	result.Trust.Limitations = uniqueSorted(snapshot.Trust.Limitations)
	result.Runtime.Capabilities = append([]EnvironmentCapability(nil), snapshot.Runtime.Capabilities...)
	sort.SliceStable(result.Runtime.Capabilities, func(i, j int) bool { return result.Runtime.Capabilities[i].Name < result.Runtime.Capabilities[j].Name })
	result.Runtime.Provenance = uniqueSorted(snapshot.Runtime.Provenance)
	result.Runtime.EvidenceIDs = uniqueSorted(snapshot.Runtime.EvidenceIDs)
	result.Runtime.Limitations = uniqueSorted(snapshot.Runtime.Limitations)
	result.Provenance = uniqueSorted(snapshot.Provenance)
	result.EvidenceIDs = uniqueSorted(snapshot.EvidenceIDs)
	result.Limitations = uniqueSorted(snapshot.Limitations)
	result.Conflicts = cloneObservationConflicts(snapshot.Conflicts)
	return &result
}

func normalizeEnvironmentProxy(value EnvironmentProxyObservation) EnvironmentProxyObservation {
	value.WinHTTP = normalizeEnvironmentProxySource(value.WinHTTP)
	value.WinINET = normalizeEnvironmentProxySource(value.WinINET)
	value.Provenance = uniqueSorted(value.Provenance)
	value.EvidenceIDs = uniqueSorted(value.EvidenceIDs)
	value.Limitations = uniqueSorted(value.Limitations)
	value.Conflicts = cloneObservationConflicts(value.Conflicts)
	return value
}

func normalizeEnvironmentProxySource(value EnvironmentProxySource) EnvironmentProxySource {
	value.Source = strings.TrimSpace(value.Source)
	value.ProxyEndpoints = uniqueSorted(value.ProxyEndpoints)
	value.ProxyBypass = uniqueSorted(value.ProxyBypass)
	value.Provenance = uniqueSorted(value.Provenance)
	value.EvidenceIDs = uniqueSorted(value.EvidenceIDs)
	value.Limitations = uniqueSorted(value.Limitations)
	return value
}

func cloneEnvironmentRoute(value *EnvironmentRoute) *EnvironmentRoute {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func environmentRouteKey(value EnvironmentRoute) string {
	return strings.Join([]string{value.RoutePrefix, value.Gateway, value.Interface, value.SourceAddress, value.InterfaceType}, "|")
}

// modelEnterpriseOnly gives NormalizeEnterprisePolicyObservation a stable
// normalization path for the shared firewall component without carrying a
// target-specific policy object in the environment contract.
func modelEnterpriseOnly(firewall EnterpriseFirewallObservation) EnterprisePolicyObservation {
	return EnterprisePolicyObservation{Firewall: firewall}
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
