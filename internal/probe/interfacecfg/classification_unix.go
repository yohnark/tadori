//go:build !windows

package interfacecfg

import "strings"

func classifyInterface(name string, loopback bool) (vpn, virtual bool) {
	lower := strings.ToLower(name)
	if loopback || lower == "lo" || lower == "lo0" {
		return false, true
	}
	vpn = containsInterfaceHint(lower, "vpn", "wireguard", "wg", "tun", "tap", "zt", "tailscale", "openvpn")
	virtual = vpn || containsInterfaceHint(lower, "docker", "container", "veth", "br-", "virbr", "cni", "podman", "vmnet", "hyper-v", "virtual", "dummy")
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
