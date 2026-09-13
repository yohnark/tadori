//go:build linux

package route

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLinuxIPv4Routes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	routes, err := parseLinuxIPv4Routes(path)
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	if routes[0].Metric != 100 {
		t.Fatalf("IPv4 metric = %d, want 100", routes[0].Metric)
	}
	if got := routes[0].Gateway.String(); got != "172.17.0.1" {
		t.Fatalf("gateway = %q", got)
	}
	if got := routes[1].Destination.String(); got != "192.168.2.0/24" {
		t.Fatalf("destination = %q", got)
	}
	if _, err := (SystemRouteTable{IPv4Path: path, IPv6Path: filepath.Join(dir, "missing")}).Routes(context.Background()); err != nil {
		t.Fatalf("system table with valid IPv4 should succeed: %v", err)
	}
}

func TestParseLinuxIPv6MetricIsHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipv6_route")
	// Destination, destination prefix, source, source prefix, next hop,
	// metric, refcount, use, flags, interface. Metric 0x64 must become 100.
	content := "00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000064 00000000 00000000 00000000 eth0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	routes, err := parseLinuxIPv6Routes(path)
	if err != nil {
		t.Fatalf("parse IPv6 routes: %v", err)
	}
	if len(routes) != 1 || routes[0].Metric != 100 {
		t.Fatalf("IPv6 routes = %#v, want metric 100", routes)
	}
}
