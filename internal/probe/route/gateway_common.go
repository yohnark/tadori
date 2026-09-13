package route

import (
	"errors"
	"net/netip"
)

var errGatewayUnreachable = errors.New("gateway is unreachable")

// pingArguments is shared by platform checkers and keeps the destination
// constrained to a validated netip.Addr. The count and wait values are fixed;
// CommandContext supplies the outer execution deadline.
func pingArguments(gateway netip.Addr) ([]string, error) {
	if !gateway.IsValid() {
		return nil, errors.New("gateway address is invalid")
	}
	return []string{"-n", "1", "-w", "1000", gateway.String()}, nil
}
