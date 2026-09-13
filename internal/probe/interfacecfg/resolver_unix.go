//go:build !windows

package interfacecfg

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
)

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
