package model

// NetworkScope is the best-supported scope of a selected destination. Scope
// is derived from the selected route and interface evidence; an address
// range alone is never sufficient to assign one.
type NetworkScope string

const (
	NetworkScopeLoopback        NetworkScope = "loopback"
	NetworkScopeLinkLocal       NetworkScope = "link_local"
	NetworkScopeSameLink        NetworkScope = "same_link"
	NetworkScopePrivateRouted   NetworkScope = "private_routed"
	NetworkScopeVPNTunnelRouted NetworkScope = "vpn_tunnel_routed"
	NetworkScopeExternalRouted  NetworkScope = "external_routed"
	NetworkScopeUnknown         NetworkScope = "unknown"
)

// NetworkScopeVPNRouted is a descriptive compatibility alias for callers
// that use the shorter VPN wording.
const NetworkScopeVPNRouted = NetworkScopeVPNTunnelRouted

// RouteDisposition describes whether the selected route carries the target
// directly on the link or through a next hop. Unknown is distinct from a
// valid on-link route with no gateway.
type RouteDisposition string

const (
	RouteDispositionOnLink  RouteDisposition = "on_link"
	RouteDispositionRouted  RouteDisposition = "routed"
	RouteDispositionUnknown RouteDisposition = "unknown"
)

// NeighborObservation describes what a read-only neighbor-cache lookup
// established. NotObserved is intentionally not a reachability result.
type NeighborObservation string

const (
	NeighborObservationNotApplicable NeighborObservation = "not_applicable"
	NeighborObservationObserved      NeighborObservation = "observed"
	NeighborObservationNotObserved   NeighborObservation = "not_observed"
	NeighborObservationUnsupported   NeighborObservation = "unsupported"
	NeighborObservationError         NeighborObservation = "error"
	NeighborObservationUnknown       NeighborObservation = "unknown"
)

// NeighborEntry is a sanitized ARP/NDP cache entry. LinkAddress is retained
// only as the cache-reported hardware address; no neighbor operation is
// performed by the diagnostic runtime.
type NeighborEntry struct {
	Address        string `json:"address"`
	Interface      string `json:"interface,omitempty"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	LinkAddress    string `json:"link_address,omitempty"`
	State          string `json:"state,omitempty"`
}

// NeighborEvidence is supporting cache evidence. A missing entry means only
// that the cache did not expose one at capture time.
type NeighborEvidence struct {
	Observation NeighborObservation `json:"observation"`
	Source      string              `json:"source,omitempty"`
	Entries     []NeighborEntry     `json:"entries,omitempty"`
	Note        string              `json:"note,omitempty"`
}

// RouteCandidate is the normalized subset of a route table row needed to
// explain selection and competing-route context without copying a platform
// route table into the canonical target.
type RouteCandidate struct {
	RoutePrefix    string `json:"route_prefix"`
	Gateway        string `json:"gateway,omitempty"`
	NextHop        string `json:"next_hop,omitempty"`
	Interface      string `json:"interface,omitempty"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
	SourceAddress  string `json:"source_address,omitempty"`
	Metric         int    `json:"metric"`
	VPNOrTunnel    bool   `json:"vpn_or_tunnel,omitempty"`
	VirtualAdapter bool   `json:"virtual_adapter,omitempty"`
	Selected       bool   `json:"selected,omitempty"`
}

// NetworkContext is the normalized, target-specific routing context. It is
// derived from observed route/interface state and is deliberately separate
// from raw route evidence so diagnosis and presentation do not need to
// infer semantics from platform-specific payloads.
type NetworkContext struct {
	RequestedIdentity            string                `json:"requested_identity"`
	SelectedDestinationAddress   string                `json:"selected_destination_address,omitempty"`
	SelectedSourceInterface      string                `json:"selected_source_interface,omitempty"`
	SelectedSourceInterfaceIndex int                   `json:"selected_source_interface_index,omitempty"`
	SelectedSourceAddress        string                `json:"selected_source_address,omitempty"`
	EffectiveRoute               RouteDisposition      `json:"effective_route"`
	RoutePrefix                  string                `json:"route_prefix,omitempty"`
	NextHop                      string                `json:"next_hop,omitempty"`
	Gateway                      string                `json:"gateway,omitempty"`
	RouteMetric                  int                   `json:"route_metric"`
	CompetingRoutes              []RouteCandidate      `json:"competing_routes,omitempty"`
	RouteSelectionAmbiguous      bool                  `json:"route_selection_ambiguous,omitempty"`
	VPNOrTunnelInvolvement       bool                  `json:"vpn_or_tunnel_involvement,omitempty"`
	VirtualAdapterInvolvement    bool                  `json:"virtual_adapter_involvement,omitempty"`
	Neighbor                     *NeighborEvidence     `json:"neighbor,omitempty"`
	NetworkScope                 NetworkScope          `json:"network_scope"`
	Provenance                   []string              `json:"provenance,omitempty"`
	EvidenceIDs                  []string              `json:"evidence_ids,omitempty"`
	Certainty                    ObservationCertainty  `json:"certainty"`
	ProbeNames                   []string              `json:"probe_names,omitempty"`
	Limitations                  []string              `json:"limitations,omitempty"`
	FailureReason                FailureReason         `json:"failure_reason"`
	FaultDomain                  FaultDomain           `json:"fault_domain"`
	Conflicts                    []ObservationConflict `json:"conflicts,omitempty"`
}
