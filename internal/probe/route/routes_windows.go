//go:build windows

package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"
)

// SystemRouteTable reads Windows' kernel route table through IP Helper. No
// command interpreter, PowerShell process, or user-selected executable is
// involved.
type SystemRouteTable struct{}

var (
	iphlpapiDLL        = syscall.NewLazyDLL("iphlpapi.dll")
	getIPForwardTable2 = iphlpapiDLL.NewProc("GetIpForwardTable2")
	freeMibTable       = iphlpapiDLL.NewProc("FreeMibTable")
)

const (
	windowsAFUnspec      = 0
	windowsAFInet        = 2
	windowsAFInet6       = 23
	windowsErrorNotFound = 1168
	windowsErrorNoData   = 232
	windowsMaxRouteRows  = 1 << 20
)

type windowsSockaddrInet struct {
	Family uint16
	Port   uint16
	Data   [24]byte
}

type windowsIPAddressPrefix struct {
	Prefix       windowsSockaddrInet
	PrefixLength uint8
	Padding      [3]byte
}

type windowsMIBIPForwardRow2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    windowsIPAddressPrefix
	NextHop              windowsSockaddrInet
	SitePrefixLength     uint8
	Padding              [3]byte
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

type windowsMIBIPForwardTable2 struct {
	NumEntries uint32
	// The native table uses an inline variable-length array. The one-element
	// declaration preserves the header offset; treating it as a pointer would
	// interpret the first route row as an address on 64-bit Windows.
	Table [1]windowsMIBIPForwardRow2
}

func (SystemRouteTable) Routes(ctx context.Context) ([]Route, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var table *windowsMIBIPForwardTable2
	ret, _, _ := getIPForwardTable2.Call(windowsAFUnspec, uintptr(unsafe.Pointer(&table)))
	if ret != 0 {
		err := syscall.Errno(ret)
		if ret == windowsErrorNotFound || ret == windowsErrorNoData {
			return nil, ErrUnsupported
		}
		return nil, err
	}
	if table == nil || table.NumEntries == 0 {
		return nil, ErrUnsupported
	}
	defer freeMibTable.Call(uintptr(unsafe.Pointer(table)))
	if table.NumEntries > windowsMaxRouteRows {
		return nil, errors.New("GetIpForwardTable2 returned an unreasonable row count")
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		interfaces = nil
	}
	byIndex := make(map[int]net.Interface, len(interfaces))
	for _, iface := range interfaces {
		byIndex[iface.Index] = iface
	}
	routes := make([]Route, 0, table.NumEntries)
	rows := unsafe.Slice(&table.Table[0], int(table.NumEntries))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		destination, ok := windowsPrefix(row.DestinationPrefix)
		if !ok {
			continue
		}
		gateway, _ := windowsSockaddrAddr(row.NextHop)
		interfaceIndex := int(row.InterfaceIndex)
		name := ""
		if value, exists := byIndex[interfaceIndex]; exists {
			name = value.Name
		}
		vpn, virtual := classifyWindowsInterface(name)
		route := Route{
			Destination:    destination,
			Gateway:        gateway,
			Interface:      name,
			InterfaceIndex: interfaceIndex,
			Metric:         int(row.Metric),
			InterfaceType:  windowsInterfaceType(vpn, virtual),
			VPNOrTunnel:    vpn,
			VirtualAdapter: virtual,
		}
		routes = append(routes, normalizeRoute(route))
	}
	if len(routes) == 0 {
		return nil, ErrUnsupported
	}
	return routes, nil
}

func windowsPrefix(value windowsIPAddressPrefix) (netip.Prefix, bool) {
	address, ok := windowsSockaddrAddr(value.Prefix)
	if !ok || value.PrefixLength > 128 {
		return netip.Prefix{}, false
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}
	if int(value.PrefixLength) > bits {
		return netip.Prefix{}, false
	}
	return normalizeRoutePrefix(netip.PrefixFrom(address, int(value.PrefixLength))), true
}

func windowsSockaddrAddr(value windowsSockaddrInet) (netip.Addr, bool) {
	switch value.Family {
	case windowsAFInet:
		return netip.AddrFrom4([4]byte{value.Data[0], value.Data[1], value.Data[2], value.Data[3]}), true
	case windowsAFInet6:
		var bytes [16]byte
		copy(bytes[:], value.Data[4:20])
		return netip.AddrFrom16(bytes), true
	default:
		return netip.Addr{}, false
	}
}

func classifyWindowsInterface(name string) (vpn, virtual bool) {
	lower := strings.ToLower(name)
	vpn = containsWindowsInterfaceHint(lower, "vpn", "wireguard", "openvpn", "tun", "tap", "anyconnect", "globalprotect", "fortinet")
	virtual = vpn || containsWindowsInterfaceHint(lower, "virtual", "hyper-v", "vmware", "virtualbox", "vbox", "wsl", "docker", "container")
	return vpn, virtual
}

func containsWindowsInterfaceHint(value string, hints ...string) bool {
	for _, hint := range hints {
		if value == hint || strings.Contains(value, hint) {
			return true
		}
	}
	return false
}

func windowsInterfaceType(vpn, virtual bool) string {
	if vpn {
		return "vpn"
	}
	if virtual {
		return "virtual"
	}
	return "physical_or_unknown"
}
