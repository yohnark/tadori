//go:build !windows

package interfacecfg

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

func collectInterfaceStates(ctx context.Context) ([]InterfaceState, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	states := make([]InterfaceState, 0, len(interfaces))
	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return nil, err
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
		states = append(states, state)
	}
	return states, nil
}

func interfaceSource() string { return "net.Interfaces" }

func readConfiguredDNSServers(ctx context.Context, path string) ([]netip.Addr, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "resolv.conf", err
	}
	if path == "" {
		path = "/etc/resolv.conf"
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return nil, "resolv.conf", ErrUnsupported
		}
		return nil, "resolv.conf", err
	}
	defer file.Close()

	servers := make([]netip.Addr, 0, 3)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, "resolv.conf", err
		}
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		value := strings.TrimSpace(fields[1])
		if zone := strings.LastIndexByte(value, '%'); zone >= 0 {
			value = value[:zone]
		}
		if address, parseErr := netip.ParseAddr(value); parseErr == nil {
			servers = append(servers, address.Unmap())
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "resolv.conf", err
	}
	return servers, "resolv.conf", nil
}

func readNameResolutionPolicy(context.Context) ([]model.NameResolutionPolicyRule, error) {
	return nil, nil
}

func readHostsFileEntries(context.Context) ([]model.NameResolutionHostEntry, error) {
	return nil, nil
}
