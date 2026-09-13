package route

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// parseWindowsRouteOutput parses the tabular output of the fixed `route
// print` command. It does not interpret labels (which are localized); rows
// are recognized by their structured IP/prefix fields instead. The parser is
// deliberately pure so captured output can be tested without a Windows host.
func parseWindowsRouteOutput(output string, family int) []Route {
	routes := make([]Route, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if family == 4 {
			if route, ok := parseWindowsIPv4Row(fields); ok {
				routes = append(routes, route)
			}
		} else if family == 6 {
			if route, ok := parseWindowsIPv6Row(fields); ok {
				routes = append(routes, route)
			}
		}
	}
	return routes
}

func parseWindowsIPv4Row(fields []string) (Route, bool) {
	if len(fields) < 4 {
		return Route{}, false
	}
	destination, err := netip.ParseAddr(fields[0])
	if err != nil || !destination.Is4() {
		return Route{}, false
	}
	mask, err := netip.ParseAddr(fields[1])
	if err != nil || !mask.Is4() {
		return Route{}, false
	}
	prefix, ok := ipv4MaskPrefix(mask)
	if !ok {
		return Route{}, false
	}
	metric := 0
	if len(fields) > 4 {
		metric, _ = strconv.Atoi(fields[4])
	}
	var gateway netip.Addr
	if parsed, parseErr := netip.ParseAddr(fields[2]); parseErr == nil && parsed.Is4() {
		gateway = parsed
	}
	return Route{Destination: netip.PrefixFrom(destination, prefix).Masked(), Gateway: gateway, Interface: fields[3], Metric: metric}, true
}

func parseWindowsIPv6Row(fields []string) (Route, bool) {
	if len(fields) < 2 {
		return Route{}, false
	}
	prefixIndex := -1
	var destination netip.Prefix
	for index, field := range fields {
		if parsed, err := netip.ParsePrefix(stripZone(field)); err == nil && !parsed.Addr().Is4() {
			prefixIndex = index
			destination = parsed.Masked()
			break
		}
	}
	if prefixIndex < 0 {
		return Route{}, false
	}
	// route.exe has appeared in two layouts over Windows versions:
	//   If Metric Prefix Gateway
	// and a verbose form with the metric before the prefix and interface
	// index after it. Find numeric fields around the structured prefix.
	metric := 0
	interfaceIndex := 0
	for index := prefixIndex - 1; index >= 0; index-- {
		value, err := strconv.Atoi(fields[index])
		if err != nil {
			continue
		}
		if metric == 0 {
			metric = value
		} else if interfaceIndex == 0 {
			interfaceIndex = value
		}
	}
	if prefixIndex+1 < len(fields) {
		if value, err := strconv.Atoi(fields[prefixIndex+1]); err == nil && interfaceIndex == 0 {
			interfaceIndex = value
		}
	}
	var gateway netip.Addr
	for _, field := range fields[prefixIndex+1:] {
		if parsed, err := netip.ParseAddr(stripZone(field)); err == nil && !parsed.Is4() {
			gateway = parsed
			break
		}
	}
	return Route{Destination: destination, Gateway: gateway, InterfaceIndex: interfaceIndex, Metric: metric}, true
}

func stripZone(value string) string {
	if percent := strings.LastIndexByte(value, '%'); percent > 0 {
		return value[:percent]
	}
	return value
}

func ipv4MaskPrefix(mask netip.Addr) (int, bool) {
	if !mask.Is4() {
		return 0, false
	}
	bytes := mask.As4()
	bits := 0
	seenZero := false
	for _, octet := range bytes {
		for bit := byte(0x80); bit != 0; bit >>= 1 {
			if octet&bit != 0 {
				if seenZero {
					return 0, false
				}
				bits++
			} else {
				seenZero = true
			}
		}
	}
	return bits, true
}

func decorateWindowsInterfaces(routes []Route) []Route {
	interfaces, err := net.Interfaces()
	if err != nil {
		return routes
	}
	byIndex := make(map[int]string, len(interfaces))
	addresses := make(map[string]string)
	for _, iface := range interfaces {
		byIndex[iface.Index] = iface.Name
		if ifaceAddresses, addrErr := iface.Addrs(); addrErr == nil {
			for _, address := range ifaceAddresses {
				if ip, _, parseErr := net.ParseCIDR(address.String()); parseErr == nil {
					addresses[ip.String()] = iface.Name
				} else {
					addresses[address.String()] = iface.Name
				}
			}
		}
	}
	for index := range routes {
		if routes[index].Interface == "" && routes[index].InterfaceIndex != 0 {
			routes[index].Interface = byIndex[routes[index].InterfaceIndex]
		}
		if name, ok := addresses[routes[index].Interface]; ok {
			routes[index].Interface = name
		}
	}
	return routes
}
