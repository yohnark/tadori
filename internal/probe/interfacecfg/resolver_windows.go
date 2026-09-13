//go:build windows

package interfacecfg

import "net/netip"

// Windows resolver configuration is exposed by GetAdaptersAddresses.  The
// portable package deliberately does not shell out to ipconfig or PowerShell;
// until a native adapter is supplied, report this observation as unsupported.
func readConfiguredDNSServers(_ string) ([]netip.Addr, string, error) {
	return nil, "windows-adapter-api", ErrUnsupported
}
