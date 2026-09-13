//go:build linux

package route

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// SystemRouteTable reads Linux's kernel route tables. Reading procfs is a
// native, read-only operation and does not invoke a shell or require network
// access.
type SystemRouteTable struct {
	IPv4Path string
	IPv6Path string
}

func (t SystemRouteTable) Routes(ctx context.Context) ([]Route, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ipv4Path := t.IPv4Path
	if ipv4Path == "" {
		ipv4Path = "/proc/net/route"
	}
	ipv6Path := t.IPv6Path
	if ipv6Path == "" {
		ipv6Path = "/proc/net/ipv6_route"
	}
	routes, ipv4Err := parseLinuxIPv4Routes(ipv4Path)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ipv6Routes, ipv6Err := parseLinuxIPv6Routes(ipv6Path)
	routes = append(routes, ipv6Routes...)
	if len(routes) != 0 {
		return routes, nil
	}
	if ipv4Err != nil {
		return nil, ipv4Err
	}
	if ipv6Err != nil {
		return nil, ipv6Err
	}
	return routes, nil
}

func parseLinuxIPv4Routes(path string) ([]Route, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return nil, ErrUnsupported
		}
		return nil, err
	}
	defer file.Close()

	interfaces := linuxInterfaceMetadata()
	routes := make([]Route, 0)
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo == 1 {
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		destination, ok := parseHexIPv4(fields[1])
		if !ok {
			continue
		}
		gateway, ok := parseHexIPv4(fields[2])
		if !ok {
			continue
		}
		mask, ok := parseHexUint32(fields[7])
		if !ok {
			continue
		}
		prefix, ok := maskPrefix(mask)
		if !ok {
			continue
		}
		// /proc/net/route's metric is displayed as a decimal field.
		metric := 0
		if len(fields) > 6 {
			metric, _ = strconv.Atoi(fields[6])
		}
		name := fields[0]
		routes = append(routes, normalizeRoute(enrichLinuxRoute(Route{
			Destination: normalizeRoutePrefix(netip.PrefixFrom(destination, prefix)),
			Gateway:     gateway,
			Interface:   name,
			Metric:      metric,
		}, interfaces[name])))
	}
	if err := scanner.Err(); err != nil {
		return routes, err
	}
	return routes, nil
}

func parseLinuxIPv6Routes(path string) ([]Route, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return nil, ErrUnsupported
		}
		return nil, err
	}
	defer file.Close()

	interfaces := linuxInterfaceMetadata()
	routes := make([]Route, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Linux format: destination, destination prefix, source, source
		// prefix, next hop, metric, ref count, use, flags, interface.
		if len(fields) < 10 {
			continue
		}
		destination, ok := parseHexIPv6(fields[0])
		if !ok {
			continue
		}
		prefix, err := strconv.Atoi(fields[1])
		if err != nil || prefix < 0 || prefix > 128 {
			continue
		}
		gateway, ok := parseHexIPv6(fields[4])
		if !ok {
			continue
		}
		// /proc/net/ipv6_route stores metric as an eight-digit hexadecimal
		// value (unlike the IPv4 table's decimal metric).
		metricValue, metricErr := strconv.ParseUint(fields[5], 16, 32)
		metric := 0
		if metricErr == nil {
			metric = int(metricValue)
		}
		name := fields[9]
		routes = append(routes, normalizeRoute(enrichLinuxRoute(Route{
			Destination: normalizeRoutePrefix(netip.PrefixFrom(destination, prefix)),
			Gateway:     gateway,
			Interface:   name,
			Metric:      metric,
		}, interfaces[name])))
	}
	if err := scanner.Err(); err != nil {
		return routes, err
	}
	return routes, nil
}

type linuxInterfaceInfo struct {
	Index       int
	Type        string
	VPNOrTunnel bool
	Virtual     bool
}

func linuxInterfaceMetadata() map[string]linuxInterfaceInfo {
	result := make(map[string]linuxInterfaceInfo)
	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range interfaces {
		vpn, virtual := classifyLinuxInterface(iface.Name, iface.Flags&net.FlagLoopback != 0)
		info := linuxInterfaceInfo{Index: iface.Index, Type: linuxInterfaceType(iface.Name, vpn, virtual), VPNOrTunnel: vpn, Virtual: virtual}
		result[iface.Name] = info
	}
	return result
}

func interfaceIndices() map[string]int {
	result := make(map[string]int)
	for name, info := range linuxInterfaceMetadata() {
		result[name] = info.Index
	}
	return result
}

func enrichLinuxRoute(route Route, info linuxInterfaceInfo) Route {
	route.InterfaceIndex = info.Index
	route.InterfaceType = info.Type
	route.VPNOrTunnel = info.VPNOrTunnel
	route.VirtualAdapter = info.Virtual
	return route
}

func classifyLinuxInterface(name string, loopback bool) (vpn, virtual bool) {
	lower := strings.ToLower(name)
	if loopback || lower == "lo" {
		return false, true
	}
	vpn = containsLinuxInterfaceHint(lower, "vpn", "wireguard", "openvpn", "tun", "tap", "wg", "tailscale", "zerotier")
	virtual = vpn || containsLinuxInterfaceHint(lower, "docker", "container", "veth", "br-", "virbr", "cni", "podman", "vmnet", "virtual", "dummy")
	return vpn, virtual
}

func containsLinuxInterfaceHint(value string, hints ...string) bool {
	for _, hint := range hints {
		if value == hint || strings.Contains(value, hint) {
			return true
		}
	}
	return false
}

func linuxInterfaceType(name string, vpn, virtual bool) string {
	if strings.EqualFold(name, "lo") {
		return "loopback"
	}
	if vpn {
		return "vpn"
	}
	if virtual {
		return "virtual"
	}
	return "physical_or_unknown"
}

func parseHexUint32(value string) (uint32, bool) {
	if len(value) != 8 {
		return 0, false
	}
	number, err := strconv.ParseUint(value, 16, 32)
	return uint32(number), err == nil
}

func maskPrefix(mask uint32) (int, bool) {
	// Linux stores the mask in the same little-endian display form as the
	// destination. Normalize before counting network bits.
	mask = uint32(byte(mask))<<24 | uint32(byte(mask>>8))<<16 | uint32(byte(mask>>16))<<8 | uint32(byte(mask>>24))
	bits := 0
	for bit := uint32(0x80000000); bit != 0 && mask&bit != 0; bit >>= 1 {
		bits++
	}
	if mask != (uint32(0xffffffff)<<(32-bits)) && bits != 32 {
		return 0, false
	}
	return bits, true
}

func parseHexIPv4(value string) (netip.Addr, bool) {
	number, ok := parseHexUint32(value)
	if !ok {
		return netip.Addr{}, false
	}
	// /proc/net/route displays IPv4 words in host (little-endian) order.
	return netip.AddrFrom4([4]byte{byte(number), byte(number >> 8), byte(number >> 16), byte(number >> 24)}), true
}

func parseHexIPv6(value string) (netip.Addr, bool) {
	if len(value) != 32 {
		return netip.Addr{}, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return netip.Addr{}, false
	}
	var bytes [16]byte
	copy(bytes[:], decoded)
	return netip.AddrFrom16(bytes), true
}
