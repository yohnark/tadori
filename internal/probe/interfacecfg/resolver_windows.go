//go:build windows

package interfacecfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"github.com/yohnark/tadori/internal/model"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	nrptPolicyPath  = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	nrptRuntimePath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
)

func collectInterfaceStates(ctx context.Context) ([]InterfaceState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	bufferSize := uint32(15 * 1024)
	for attempt := 0; attempt < 4; attempt++ {
		buffer := make([]byte, bufferSize)
		if len(buffer) == 0 {
			return nil, errors.New("GetAdaptersAddresses returned an empty buffer")
		}
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_ALL_INTERFACES|windows.GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])),
			&bufferSize,
		)
		if err == nil {
			return parseWindowsAdapterAddresses(buffer), nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		if bufferSize <= uint32(len(buffer)) || bufferSize > 1024*1024 {
			return nil, fmt.Errorf("GetAdaptersAddresses returned invalid buffer size %d", bufferSize)
		}
	}
	return nil, errors.New("GetAdaptersAddresses exceeded buffer retry limit")
}

func interfaceSource() string { return "GetAdaptersAddresses" }

func parseWindowsAdapterAddresses(buffer []byte) []InterfaceState {
	if len(buffer) == 0 {
		return nil
	}
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	states := make([]InterfaceState, 0)
	for adapter := first; adapter != nil; adapter = adapter.Next {
		state := InterfaceState{
			Index:       int(adapter.IfIndex),
			Name:        utf16Pointer(adapter.FriendlyName),
			Description: utf16Pointer(adapter.Description),
			MTU:         int(adapter.Mtu),
			Up:          adapter.OperStatus == windows.IfOperStatusUp,
			Loopback:    adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			Virtual:     windowsVirtualAdapter(adapter),
		}
		if state.Name == "" {
			state.Name = state.Description
		}
		state.VPN = windowsVPNAdapter(state.Name, state.Description, adapter.IfType, adapter.TunnelType)
		switch {
		case state.Loopback:
			state.Type = "loopback"
		case state.VPN:
			state.Type = "vpn"
		case state.Virtual:
			state.Type = "virtual"
		default:
			state.Type = "physical_or_unknown"
		}
		if adapter.PhysicalAddressLength > 0 && adapter.PhysicalAddressLength <= uint32(len(adapter.PhysicalAddress)) {
			state.Hardware = net.HardwareAddr(adapter.PhysicalAddress[:adapter.PhysicalAddressLength]).String()
		}
		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			if ip := socketAddressIP(&address.Address); ip.IsValid() {
				prefix := int(address.OnLinkPrefixLength)
				if ip.Is4() && prefix > 32 {
					prefix = 32
				}
				if ip.Is6() && prefix > 128 {
					prefix = 128
				}
				state.Addresses = append(state.Addresses, Address{IP: ip, Prefix: prefix})
			}
		}
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			if ip := socketAddressIP(&server.Address); ip.IsValid() {
				state.DNSServers = appendUniqueIP(state.DNSServers, ip)
			}
		}
		state.DNSSuffix = utf16Pointer(adapter.DnsSuffix)
		if state.DNSSuffix != "" {
			state.DNSSearchList = appendUniqueString(state.DNSSearchList, state.DNSSuffix)
		}
		for suffix := adapter.FirstDnsSuffix; suffix != nil; suffix = suffix.Next {
			value := windows.UTF16ToString(suffix.String[:])
			if value != "" {
				state.DNSSearchList = appendUniqueString(state.DNSSearchList, value)
			}
		}
		states = append(states, state)
	}
	return states
}

func socketAddressIP(address *windows.SocketAddress) netip.Addr {
	if address == nil || address.Sockaddr == nil {
		return netip.Addr{}
	}
	ip := address.IP()
	if len(ip) == 0 {
		return netip.Addr{}
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return model.NormalizeAddr(parsed)
}

func utf16Pointer(pointer *uint16) string {
	if pointer == nil {
		return ""
	}
	return strings.TrimSpace(windows.UTF16PtrToString(pointer))
}

func windowsVirtualAdapter(adapter *windows.IpAdapterAddresses) bool {
	if adapter == nil {
		return false
	}
	return adapter.IfType == windows.IF_TYPE_PPP || adapter.IfType == windows.IF_TYPE_TUNNEL || windowsTextSuggestsVirtual(utf16Pointer(adapter.FriendlyName)+" "+utf16Pointer(adapter.Description))
}

func windowsVPNAdapter(name, description string, ifType, tunnelType uint32) bool {
	if ifType == windows.IF_TYPE_PPP || ifType == windows.IF_TYPE_TUNNEL || tunnelType != 0 {
		return true
	}
	return windowsTextSuggestsVPN(name + " " + description)
}

func windowsTextSuggestsVirtual(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"virtual", "vmware", "hyper-v", "hyperv", "veth", "tap", "tun", "wireguard", "loopback"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func windowsTextSuggestsVPN(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"vpn", "wireguard", "openvpn", "anyconnect", "globalprotect", "forticlient", "tunnel", "ras"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func readConfiguredDNSServers(ctx context.Context, path string) ([]netip.Addr, string, error) {
	source := "GetAdaptersAddresses"
	if path != "" {
		source = "resolver-fixture"
	}
	if err := ctx.Err(); err != nil {
		return nil, source, err
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, source, nil
			}
			return nil, source, err
		}
		return parseResolverFileAddresses(data), source, nil
	}
	interfaces, err := collectInterfaceStates(ctx)
	if err != nil {
		return nil, source, err
	}
	return configuredServersFromInterfaces(interfaces), source, nil
}

func parseResolverFileAddresses(data []byte) []netip.Addr {
	values := make([]netip.Addr, 0)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		if address, err := netip.ParseAddr(strings.Trim(fields[1], "[]")); err == nil {
			values = appendUniqueIP(values, model.NormalizeAddr(address))
		}
	}
	return values
}

func readNameResolutionPolicy(ctx context.Context) ([]model.NameResolutionPolicyRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rules := make([]model.NameResolutionPolicyRule, 0)
	for _, sourcePath := range []string{nrptPolicyPath, nrptRuntimePath} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, sourcePath, registry.READ)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return rules, fmt.Errorf("open NRPT registry key %q: %w", sourcePath, err)
		}
		sourceRules, readErr := readNRPTKey(key, sourcePath)
		_ = key.Close()
		if readErr != nil {
			return rules, readErr
		}
		for _, rule := range sourceRules {
			if !containsPolicyRule(rules, rule) {
				rules = append(rules, rule)
			}
		}
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Source != rules[j].Source {
			return rules[i].Source < rules[j].Source
		}
		return rules[i].RuleID < rules[j].RuleID
	})
	return rules, nil
}

func readNRPTKey(parent registry.Key, sourcePath string) ([]model.NameResolutionPolicyRule, error) {
	children, err := parent.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate NRPT registry key %q: %w", sourcePath, err)
	}
	sort.Strings(children)
	rules := make([]model.NameResolutionPolicyRule, 0, len(children))
	for _, child := range children {
		key, openErr := registry.OpenKey(parent, child, registry.READ)
		if openErr != nil {
			return rules, fmt.Errorf("open NRPT rule %q: %w", child, openErr)
		}
		namespaces, _, namesErr := key.GetStringsValue("Name")
		if errors.Is(namesErr, registry.ErrNotExist) {
			_ = key.Close()
			continue
		}
		if namesErr != nil {
			_ = key.Close()
			return rules, fmt.Errorf("read NRPT rule %q namespace: %w", child, namesErr)
		}
		servers := readNRPTServers(key, "GenericDNSServers")
		servers = appendUniqueStringSlice(servers, readNRPTServers(key, "DirectAccessDNSServers")...)
		rules = append(rules, model.NameResolutionPolicyRule{
			Namespaces:               uniquePolicyStrings(namespaces),
			NameServers:              uniquePolicyStrings(servers),
			Source:                   "registry:" + sourcePath,
			RuleID:                   child,
			VPNRequired:              readNRPTInteger(key, "VpnRequired") != 0,
			DNSSECValidationRequired: readNRPTInteger(key, "DNSSECValidationRequired") != 0,
		})
		_ = key.Close()
	}
	return rules, nil
}

func readNRPTServers(key registry.Key, name string) []string {
	if values, _, err := key.GetStringsValue(name); err == nil {
		result := make([]string, 0, len(values))
		for _, value := range values {
			result = appendUniqueStringSlice(result, strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ',' })...)
		}
		return result
	}
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return nil
	}
	return strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ',' })
}

func readNRPTInteger(key registry.Key, name string) uint64 {
	value, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return value
}

func containsPolicyRule(rules []model.NameResolutionPolicyRule, candidate model.NameResolutionPolicyRule) bool {
	for _, rule := range rules {
		if rule.Source == candidate.Source && rule.RuleID == candidate.RuleID {
			return true
		}
	}
	return false
}

func readHostsFileEntries(ctx context.Context) ([]model.NameResolutionHostEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("GetSystemDirectory: %w", err)
	}
	path := filepath.Join(systemDirectory, "drivers", "etc", "hosts")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Windows hosts file: %w", err)
	}
	return ParseHostsFileEntries(data, path), nil
}

func appendUniqueStringSlice(values []string, candidates ...string) []string {
	for _, candidate := range candidates {
		values = appendUniqueString(values, candidate)
	}
	return values
}

func uniquePolicyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = appendUniqueString(result, value)
	}
	return result
}
