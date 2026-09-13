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
