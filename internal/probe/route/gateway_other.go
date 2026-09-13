//go:build !windows

package route

import (
	"context"
	"errors"
	"net/netip"
)

// The standard library has no portable ICMP API, and UDP setup is not a
// reachability test. Keep the result honest on non-Windows hosts until a
// native ICMP adapter is supplied.
func defaultGatewayChecker(ctx context.Context, gateway netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !gateway.IsValid() {
		return errors.New("gateway address is invalid")
	}
	return ErrGatewayReachabilityUnsupported
}
