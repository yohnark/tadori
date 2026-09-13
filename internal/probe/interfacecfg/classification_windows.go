//go:build windows

package interfacecfg

import "strings"

// net.Interfaces does not expose Windows' IF_TYPE. Names are therefore only
// a conservative hint here; route selection never treats a name match as
// proof of a VPN or physical topology.
func classifyInterface(name string, loopback bool) (vpn, virtual bool) {
	lower := strings.ToLower(name)
	if loopback {
		return false, true
	}
	vpn = containsInterfaceHint(lower, "vpn", "wireguard", "openvpn", "tun", "tap", "anyconnect", "globalprotect", "fortinet")
	virtual = vpn || containsInterfaceHint(lower, "virtual", "hyper-v", "vmware", "virtualbox", "vbox", "wsl", "docker", "container")
	return vpn, virtual
}

func interfaceType(name string, loopback bool) string {
	if loopback {
		return "loopback"
	}
	vpn, virtual := classifyInterface(name, false)
	if vpn {
		return "vpn"
	}
	if virtual {
		return "virtual"
	}
	return "physical_or_unknown"
}

func containsInterfaceHint(value string, hints ...string) bool {
	for _, hint := range hints {
		if value == hint || strings.Contains(value, hint) {
			return true
		}
	}
	return false
}
