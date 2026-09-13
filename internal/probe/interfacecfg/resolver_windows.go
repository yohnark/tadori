//go:build windows

package interfacecfg

import (
	"context"
	"net/netip"

	"github.com/yohnark/tadori/internal/probe/dns"
)

// Windows resolver configuration is delegated to the canonical DNS lane. This
// keeps ipconfig's fixed, structured discovery in one place and avoids two
// subtly different interpretations of configured nameservers.
func readConfiguredDNSServers(ctx context.Context, path string) ([]netip.Addr, string, error) {
	config := dns.SystemResolverConfig{Path: path}
	addresses, err := config.ResolverAddresses(ctx)
	parsed := make([]netip.Addr, 0, len(addresses))
	for _, value := range addresses {
		if address, parseErr := netip.ParseAddr(value); parseErr == nil {
			parsed = append(parsed, address.Unmap())
		}
	}
	return parsed, config.Source(), err
}
