package interfacecfg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

// FailureReasonProbeTimeout is local until the shared contract grows a
// first-class timeout value.  It still uses model.FailureReason in results,
// so consumers can match the stable machine-readable value.
const FailureReasonProbeTimeout model.FailureReason = "probe_timeout"

// FailureReasonInsufficientPrivilege is used when the operating system
// refuses a configuration observation because the caller lacks permission.
const FailureReasonInsufficientPrivilege model.FailureReason = "insufficient_privilege"

// ErrUnsupported indicates that the current operating system cannot provide a
// requested observation through the provider in use.
var ErrUnsupported = errors.New("interface configuration is unsupported")

// Address is an IP address and its network prefix as reported by the host.
// Prefix is the number of network bits (0 through 32 for IPv4 and 0 through
// 128 for IPv6).
type Address struct {
	IP     netip.Addr `json:"ip"`
	Prefix int        `json:"prefix"`
}

// InterfaceState is a lossless-enough, JSON-friendly snapshot of one network
// interface.  Loopback interfaces are retained in evidence but are not
// considered usable for the active-interface interpretation.
type InterfaceState struct {
	Index     int       `json:"index"`
	Name      string    `json:"name"`
	Hardware  string    `json:"hardware_address,omitempty"`
	MTU       int       `json:"mtu"`
	Up        bool      `json:"up"`
	Loopback  bool      `json:"loopback"`
	Addresses []Address `json:"addresses,omitempty"`
}

// Snapshot contains local interface and resolver configuration.  DNS servers
// are evidence only; this package does not query or rank them.
type Snapshot struct {
	Interfaces    []InterfaceState `json:"interfaces"`
	DNSServers    []netip.Addr     `json:"dns_servers,omitempty"`
	Source        string           `json:"source,omitempty"`
	ResolverError string           `json:"resolver_error,omitempty"`
	CapturedAt    time.Time        `json:"captured_at"`
}

// SnapshotProvider allows tests and platform adapters to provide deterministic
// snapshots without touching the host network.
type SnapshotProvider interface {
	Snapshot(context.Context) (Snapshot, error)
}

// SnapshotProviderFunc adapts a function to SnapshotProvider.
type SnapshotProviderFunc func(context.Context) (Snapshot, error)

func (f SnapshotProviderFunc) Snapshot(ctx context.Context) (Snapshot, error) {
	return f(ctx)
}

// SystemProvider reads interface state using net.Interfaces and resolver
// configuration using the platform's standard resolver configuration file.
// It performs no shell execution.
type SystemProvider struct {
	// ResolverConfigPath is primarily useful for tests.  An empty path uses
	// the platform default (/etc/resolv.conf on Unix-like systems).
	ResolverConfigPath string
}

// Collect captures one system snapshot using the native provider.
func Collect(ctx context.Context) (Snapshot, error) {
	return (SystemProvider{}).Snapshot(ctx)
}

func (p SystemProvider) Snapshot(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return Snapshot{}, err
	}

	snapshot := Snapshot{Interfaces: make([]InterfaceState, 0, len(interfaces)), Source: "net.Interfaces", CapturedAt: time.Now().UTC()}
	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		state := InterfaceState{
			Index:    iface.Index,
			Name:     iface.Name,
			Hardware: iface.HardwareAddr.String(),
			MTU:      iface.MTU,
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
		}
		if addresses, addressErr := iface.Addrs(); addressErr == nil {
			for _, address := range addresses {
				if parsed, ok := parseAddress(address); ok {
					state.Addresses = append(state.Addresses, parsed)
				}
			}
		}
		snapshot.Interfaces = append(snapshot.Interfaces, state)
	}

	servers, resolverSource, resolverErr := readConfiguredDNSServers(p.ResolverConfigPath)
	if resolverErr != nil && !errors.Is(resolverErr, ErrUnsupported) {
		// Interface observations remain useful even if resolver configuration
		// cannot be read.  Keep the error for the dedicated DNS config probe,
		// but do not discard the interface snapshot here.
		return snapshot, resolverErr
	}
	if resolverErr != nil {
		snapshot.ResolverError = resolverErr.Error()
	}
	snapshot.DNSServers = servers
	if resolverSource != "" {
		snapshot.Source += ";" + resolverSource
	}
	return snapshot, nil
}

func parseAddress(address net.Addr) (Address, bool) {
	if address == nil {
		return Address{}, false
	}
	if ipnet, ok := address.(*net.IPNet); ok {
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			return Address{}, false
		}
		prefix, _ := ipnet.Mask.Size()
		if prefix < 0 {
			return Address{}, false
		}
		return Address{IP: ip, Prefix: prefix}, true
	}
	if ipaddr, ok := address.(*net.IPAddr); ok {
		ip, ok := netip.AddrFromSlice(ipaddr.IP)
		if !ok {
			return Address{}, false
		}
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		return Address{IP: ip, Prefix: bits}, true
	}
	// A few platform implementations return a textual CIDR type.  Parsing
	// this representation keeps the collector useful without shelling out.
	text := strings.TrimSpace(address.String())
	if ip, network, err := net.ParseCIDR(text); err == nil {
		parsed, ok := netip.AddrFromSlice(ip)
		if !ok {
			return Address{}, false
		}
		prefix, _ := network.Mask.Size()
		return Address{IP: parsed, Prefix: prefix}, true
	}
	if ip, err := netip.ParseAddr(text); err == nil {
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		return Address{IP: ip, Prefix: bits}, true
	}
	return Address{}, false
}

func usableAddress(address Address) bool {
	ip := address.IP
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
