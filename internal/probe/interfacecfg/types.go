package interfacecfg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
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
	Index          int          `json:"index"`
	Name           string       `json:"name"`
	Description    string       `json:"description,omitempty"`
	Hardware       string       `json:"hardware_address,omitempty"`
	MTU            int          `json:"mtu"`
	Up             bool         `json:"up"`
	Loopback       bool         `json:"loopback"`
	VirtualAdapter bool         `json:"virtual_adapter,omitempty"`
	VPN            bool         `json:"vpn,omitempty"`
	Addresses      []Address    `json:"addresses,omitempty"`
	DNSServers     []netip.Addr `json:"dns_servers,omitempty"`
	DNSSuffix      string       `json:"dns_suffix,omitempty"`
	DNSSearchList  []string     `json:"dns_search_list,omitempty"`
}

// Snapshot contains local interface and resolver configuration.  DNS servers
// are evidence only; this package does not query or rank them.
type Snapshot struct {
	Interfaces        []InterfaceState                 `json:"interfaces"`
	DNSServers        []netip.Addr                     `json:"dns_servers,omitempty"`
	DNSSuffixes       []string                         `json:"dns_suffixes,omitempty"`
	SearchList        []string                         `json:"search_list,omitempty"`
	NRPT              []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
	NRPTError         string                           `json:"nrpt_error,omitempty"`
	HostsFileEntries  []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
	HostsFileError    string                           `json:"hosts_file_error,omitempty"`
	Source            string                           `json:"source,omitempty"`
	ResolverError     string                           `json:"resolver_error,omitempty"`
	ResolverErrorKind string                           `json:"resolver_error_kind,omitempty"`
	CapturedAt        time.Time                        `json:"captured_at"`
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

// SystemProvider reads interface and resolver state through platform-native
// adapters. The Windows implementation uses GetAdaptersAddresses and native
// registry/file APIs; it never executes a shell command.
type SystemProvider struct {
	// ResolverConfigPath is primarily useful for tests. On Unix-like systems a
	// blank path uses /etc/resolv.conf; on Windows a blank path uses native
	// adapter state and a non-blank path is a fixture override.
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
	interfaces, err := collectInterfaceStates(ctx)
	if err != nil {
		return Snapshot{}, err
	}

	servers, resolverSource, resolverErr := readConfiguredDNSServers(ctx, p.ResolverConfigPath)
	snapshot := Snapshot{Interfaces: normalizeInterfaceStates(interfaces), Source: interfaceSource(), CapturedAt: time.Now().UTC()}
	if resolverErr != nil {
		snapshot.ResolverError = resolverErr.Error()
		snapshot.ResolverErrorKind = classifyResolverError(resolverErr)
		// Preserve normal resolver discovery failures in the snapshot so the
		// interface lane can still report useful local state. Caller
		// cancellation/deadline is different: propagate it so probes honor
		// their execution context and do not report a late success.
		if errors.Is(resolverErr, context.Canceled) || errors.Is(resolverErr, context.DeadlineExceeded) || ctx.Err() != nil {
			return snapshot, resolverErr
		}
	}
	snapshot.DNSServers = servers
	if len(snapshot.DNSServers) == 0 {
		snapshot.DNSServers = configuredServersFromInterfaces(snapshot.Interfaces)
	}
	snapshot.DNSSuffixes, snapshot.SearchList = suffixesFromInterfaces(snapshot.Interfaces)
	policy, policyErr := readNameResolutionPolicy(ctx)
	if policyErr != nil {
		snapshot.NRPTError = policyErr.Error()
	} else {
		snapshot.NRPT = policy
	}
	hosts, hostsErr := readHostsFileEntries(ctx)
	if hostsErr != nil {
		snapshot.HostsFileError = hostsErr.Error()
	} else {
		snapshot.HostsFileEntries = hosts
	}
	if resolverSource != "" && !strings.Contains(snapshot.Source, resolverSource) {
		snapshot.Source += ";" + resolverSource
	}
	return snapshot, nil
}

func classifyResolverError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, ErrUnsupported) {
		return "unsupported"
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return "insufficient_privilege"
	}
	return "resolver_failure"
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
		return normalizeAddress(Address{IP: ip, Prefix: prefix}), true
	}
	if ipaddr, ok := address.(*net.IPAddr); ok {
		ip, ok := netip.AddrFromSlice(ipaddr.IP)
		if !ok {
			return Address{}, false
		}
		bits := 32
		if !ip.Is4() && !ip.Is4In6() {
			bits = 128
		}
		return normalizeAddress(Address{IP: ip, Prefix: bits}), true
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
		if prefix < 0 {
			return Address{}, false
		}
		return normalizeAddress(Address{IP: parsed, Prefix: prefix}), true
	}
	if ip, err := netip.ParseAddr(text); err == nil {
		bits := 128
		if ip.Is4() || ip.Is4In6() {
			bits = 32
		}
		return normalizeAddress(Address{IP: ip, Prefix: bits}), true
	}
	return Address{}, false
}

func usableAddress(address Address) bool {
	ip := model.NormalizeAddr(address.IP)
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func configuredServersFromInterfaces(interfaces []InterfaceState) []netip.Addr {
	servers := make([]netip.Addr, 0)
	for _, iface := range interfaces {
		for _, server := range iface.DNSServers {
			server = model.NormalizeAddr(server)
			if !server.IsValid() {
				continue
			}
			duplicate := false
			for _, existing := range servers {
				if existing == server {
					duplicate = true
					break
				}
			}
			if !duplicate {
				servers = append(servers, server)
			}
		}
	}
	return servers
}

func suffixesFromInterfaces(interfaces []InterfaceState) ([]string, []string) {
	suffixes, searchList := make([]string, 0), make([]string, 0)
	for _, iface := range interfaces {
		suffixes = appendUniqueString(suffixes, iface.DNSSuffix)
		for _, suffix := range iface.DNSSearchList {
			searchList = appendUniqueString(searchList, suffix)
			suffixes = appendUniqueString(suffixes, suffix)
		}
	}
	return suffixes, searchList
}

func appendUniqueIP(values []netip.Addr, candidate netip.Addr) []netip.Addr {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func appendUniqueString(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return values
		}
	}
	return append(values, candidate)
}
