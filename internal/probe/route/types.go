package route

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

// FailureReasonProbeTimeout is local until the shared contract defines a
// timeout constant.  Results still carry model.FailureReason values.
const FailureReasonProbeTimeout model.FailureReason = "probe_timeout"

// FailureReasonInsufficientPrivilege is reserved for route APIs that reject
// an observation due to caller privileges.
const FailureReasonInsufficientPrivilege model.FailureReason = "insufficient_privilege"

// ErrUnsupported indicates that the host has no supported native route API.
var ErrUnsupported = errors.New("route inspection is unsupported")

// ErrGatewayReachabilityUnsupported indicates that route discovery succeeded,
// but the optional gateway reachability check is not available on this host.
// It is deliberately distinct from ErrUnsupported so a gateway result cannot
// describe an unavailable reachability check as a route-inspection failure.
var ErrGatewayReachabilityUnsupported = errors.New("gateway reachability checking is unsupported")

// Route is one kernel route entry. Destination is always a valid network
// prefix; a zero Gateway means the destination is directly connected.
type Route struct {
	Destination    netip.Prefix `json:"destination"`
	Gateway        netip.Addr   `json:"gateway,omitempty"`
	Interface      string       `json:"interface,omitempty"`
	InterfaceIndex int          `json:"interface_index,omitempty"`
	Metric         int          `json:"metric,omitempty"`
	// Source is the source address selected or observed for this route when
	// the platform exposes it. It is not guessed from the destination class.
	Source         netip.Addr `json:"source,omitempty"`
	InterfaceType  string     `json:"interface_type,omitempty"`
	VPNOrTunnel    bool       `json:"vpn_or_tunnel,omitempty"`
	VirtualAdapter bool       `json:"virtual_adapter,omitempty"`
}

// Selection is the normalized result of applying route precedence to a
// target. Candidates are retained so callers can explain competing metrics;
// an equal-precedence tie is marked ambiguous because a generic route table
// does not expose every platform-specific tie-breaker.
type Selection struct {
	Target     netip.Addr
	Selected   Route
	Candidates []Route
	Ambiguous  bool
}

// RouteEvidenceCandidate is the raw-evidence counterpart of model.RouteCandidate.
// It is kept in this package so platform route observations can be decoded by
// presentation and orchestration code without parsing arbitrary JSON maps.
type RouteEvidenceCandidate struct {
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

// RouteObservation is the normalized shape serialized inside route evidence.
// It includes the selected route and enough competing context to reconstruct
// model.NetworkContext without re-reading the host route table.
type RouteObservation struct {
	RouteType               string                   `json:"route_type"`
	TargetIP                string                   `json:"target_ip,omitempty"`
	Destination             string                   `json:"destination,omitempty"`
	Gateway                 string                   `json:"gateway,omitempty"`
	Interface               string                   `json:"interface,omitempty"`
	InterfaceIndex          int                      `json:"interface_index,omitempty"`
	SourceAddress           string                   `json:"source_address,omitempty"`
	Metric                  int                      `json:"metric"`
	EffectiveRoute          model.RouteDisposition   `json:"effective_route"`
	RoutePrefix             string                   `json:"route_prefix,omitempty"`
	NextHop                 string                   `json:"next_hop,omitempty"`
	InterfaceType           string                   `json:"interface_type,omitempty"`
	VPNOrTunnel             bool                     `json:"vpn_or_tunnel,omitempty"`
	VirtualAdapter          bool                     `json:"virtual_adapter,omitempty"`
	RouteSelectionAmbiguous bool                     `json:"route_selection_ambiguous,omitempty"`
	CompetingRoutes         []RouteEvidenceCandidate `json:"competing_routes,omitempty"`
	Neighbor                *model.NeighborEvidence  `json:"neighbor,omitempty"`
	// DefaultRouteApplicable distinguishes a real default-route observation
	// from a valid more-specific target route that makes a default unnecessary.
	DefaultRouteApplicable *bool  `json:"default_route_applicable,omitempty"`
	SupportingOnly         bool   `json:"supporting_only,omitempty"`
	GatewayTested          *bool  `json:"gateway_tested,omitempty"`
	Reachable              *bool  `json:"reachable,omitempty"`
	Error                  string `json:"error,omitempty"`
}

// NeighborTable supplies a read-only neighbor-cache observation. It must not
// send probes, add cache entries, or mutate network configuration.
type NeighborTable interface {
	Neighbors(context.Context, netip.Addr, int) (model.NeighborEvidence, error)
}

// NeighborTableFunc adapts a function to NeighborTable.
type NeighborTableFunc func(context.Context, netip.Addr, int) (model.NeighborEvidence, error)

func (f NeighborTableFunc) Neighbors(ctx context.Context, target netip.Addr, interfaceIndex int) (model.NeighborEvidence, error) {
	return f(ctx, target, interfaceIndex)
}

// RouteTable supplies route entries. Implementations are kept behind this
// interface so route selection can be tested entirely offline.
type RouteTable interface {
	Routes(context.Context) ([]Route, error)
}

// RouteTableFunc adapts a function to RouteTable.
type RouteTableFunc func(context.Context) ([]Route, error)

func (f RouteTableFunc) Routes(ctx context.Context) ([]Route, error) { return f(ctx) }

// ReachabilityChecker tests a gateway. It should only provide supporting
// evidence; callers must not use its failure as an end-to-end conclusion. The
// default checker reports unsupported because UDP setup is not reachability;
// callers may inject a platform-native bounded ICMP checker.
type ReachabilityChecker func(context.Context, netip.Addr) error

const defaultProbeTimeout = 2 * time.Second

func boundedContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	return context.WithTimeout(parent, timeout)
}
