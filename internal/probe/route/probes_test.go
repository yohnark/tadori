package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

type fixtureRouteTable struct {
	routes []Route
	err    error
}

func (f fixtureRouteTable) Routes(context.Context) ([]Route, error) { return f.routes, f.err }

func fixtureRoutes() []Route {
	return []Route{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "eth-default", InterfaceIndex: 3, Metric: 100},
		{Destination: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "eth-default", InterfaceIndex: 3, Metric: 100},
		{Destination: netip.MustParsePrefix("192.0.2.128/25"), Gateway: netip.MustParseAddr("192.0.2.129"), Interface: "eth-specific", InterfaceIndex: 4, Metric: 200},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "eth-backup", InterfaceIndex: 5, Metric: 50},
	}
}

func TestSelectUsesLongestPrefixThenMetric(t *testing.T) {
	routes := fixtureRoutes()
	selected, ok := Select(routes, netip.MustParseAddr("192.0.2.200"))
	if !ok || selected.Interface != "eth-specific" {
		t.Fatalf("selected = %#v, ok=%v", selected, ok)
	}
	selected, ok = Select(routes, netip.MustParseAddr("203.0.113.8"))
	if !ok || selected.Interface != "eth-backup" {
		t.Fatalf("default selected = %#v, ok=%v", selected, ok)
	}
}

func TestSelectRejectsInvalidOrUnmatchedTarget(t *testing.T) {
	if _, ok := Select(fixtureRoutes(), netip.Addr{}); ok {
		t.Fatal("invalid target unexpectedly selected a route")
	}
	if _, ok := Select([]Route{{Destination: netip.MustParsePrefix("192.0.2.0/24")}}, netip.MustParseAddr("198.51.100.4")); ok {
		t.Fatal("unmatched route unexpectedly selected")
	}
}

func TestParseWindowsRouteOutputIsStructuredAndOffline(t *testing.T) {
	ipv4 := `IPv4 Route Table
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.0.2.1      192.0.2.10     25
	        192.0.2.0    255.255.255.0         On-link      192.0.2.10    281
Persistent Routes:
          0.0.0.0          0.0.0.0      192.0.2.1             1`
	routes := parseWindowsRouteOutput(ipv4, 4)
	if len(routes) != 2 || routes[0].Destination.String() != "0.0.0.0/0" || routes[0].Metric != 25 {
		t.Fatalf("IPv4 parsed routes = %#v", routes)
	}
	if routes[1].Gateway.IsValid() {
		t.Fatalf("On-link gateway should be absent: %#v", routes[1])
	}
	ipv6 := `IPv6 Route Table
Active Routes:
 If Metric Network Destination      Gateway
 11    331 ::/0                     fe80::1
 No Manual 256 2001:db8::/64        16`
	routes = parseWindowsRouteOutput(ipv6, 6)
	if len(routes) != 2 {
		t.Fatalf("IPv6 parsed routes = %#v", routes)
	}
	if routes[0].Destination.String() != "::/0" || routes[0].Gateway.String() != "fe80::1" || routes[0].Metric != 331 || routes[0].InterfaceIndex != 11 {
		t.Fatalf("IPv6 default route = %#v", routes[0])
	}
	if routes[1].Destination.String() != "2001:db8::/64" || routes[1].Metric != 256 || routes[1].InterfaceIndex != 16 {
		t.Fatalf("IPv6 verbose route = %#v", routes[1])
	}
}

func TestDefaultRouteProbeIsDistinctFromTargetRouteProbe(t *testing.T) {
	table := fixtureRouteTable{routes: fixtureRoutes()}
	target := model.Target{Host: "192.0.2.200", Port: 443}
	defaultResult := NewDefaultRouteProbe(table).Run(context.Background(), probe.ExecutionContext{Target: target})
	targetResult := NewTargetRouteProbe(table).Run(context.Background(), probe.ExecutionContext{Target: target})
	if defaultResult.Name != DefaultRouteProbeName || targetResult.Name != TargetRouteProbeName {
		t.Fatalf("probe names: %q, %q", defaultResult.Name, targetResult.Name)
	}
	if string(defaultResult.Evidence[0].Raw) == string(targetResult.Evidence[0].Raw) {
		t.Fatal("default and target evidence unexpectedly identical")
	}
	if defaultResult.Interpretation.FailureReason != model.FailureReasonNone || targetResult.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("unexpected route result: %#v %#v", defaultResult, targetResult)
	}
}

func TestTargetRouteProbeCanUseResolvedAddressWithoutDNS(t *testing.T) {
	p := NewTargetRouteProbe(fixtureRouteTable{routes: fixtureRoutes()})
	got := p.RunForAddress(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "target.example"}}, netip.MustParseAddr("192.0.2.200"))
	if got.Status != model.ProbeStatusPassed || got.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("resolved-address route result = %#v", got)
	}
}

func TestDefaultRouteProbeNormalizesNoRoute(t *testing.T) {
	p := NewDefaultRouteProbe(fixtureRouteTable{routes: []Route{{Destination: netip.MustParsePrefix("192.0.2.0/24")}}})
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "192.0.2.4"}})
	if got.Status != model.ProbeStatusFailed || got.Interpretation.FailureReason != model.FailureReasonNoRoute {
		t.Fatalf("result = %#v", got)
	}
}

func TestTargetRouteProbeNormalizesNoRouteAndInvalidTarget(t *testing.T) {
	p := NewTargetRouteProbe(fixtureRouteTable{routes: []Route{{Destination: netip.MustParsePrefix("192.0.2.0/24")}}})
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "198.51.100.10"}})
	if got.Interpretation.FailureReason != model.FailureReasonNoRoute {
		t.Fatalf("no route reason = %q", got.Interpretation.FailureReason)
	}
	got = p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "target.example"}})
	if got.Interpretation.FailureReason != model.FailureReasonInvalidRoute {
		t.Fatalf("invalid target reason = %q", got.Interpretation.FailureReason)
	}
}

func TestGatewayProbeSuccessAndFailureAreSupportingEvidence(t *testing.T) {
	table := fixtureRouteTable{routes: fixtureRoutes()}
	success := NewGatewayProbe(table)
	success.Checker = func(context.Context, netip.Addr) error { return nil }
	got := success.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "192.0.2.200"}})
	if got.Status != model.ProbeStatusPassed || got.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("success result = %#v", got)
	}
	failure := NewGatewayProbe(table)
	failure.Checker = func(context.Context, netip.Addr) error { return errors.New("fixture gateway down") }
	got = failure.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "192.0.2.200"}})
	if got.Status != model.ProbeStatusFailed || got.Interpretation.FailureReason != model.FailureReasonGatewayUnreachable {
		t.Fatalf("failure result = %#v", got)
	}
	if got.Interpretation.FaultDomain != model.FaultDomainGateway {
		t.Fatalf("gateway failure domain = %q", got.Interpretation.FaultDomain)
	}
	if string(got.Evidence[0].Raw) == "" {
		t.Fatal("gateway evidence absent")
	}
}

func TestGatewayProbeDefaultIsHonestAboutUnsupportedICMP(t *testing.T) {
	p := NewGatewayProbe(fixtureRouteTable{routes: fixtureRoutes()})
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "192.0.2.200"}})
	if got.Status != model.ProbeStatusError || got.Interpretation.FailureReason != model.FailureReasonUnsupported {
		t.Fatalf("default checker result = %#v", got)
	}
	if len(got.Evidence) != 1 || !strings.Contains(string(got.Evidence[0].Raw), "supporting_only") {
		t.Fatalf("unsupported gateway evidence = %#v", got.Evidence)
	}
}

func TestPingArgumentsAreFixedAndAddressValidated(t *testing.T) {
	args, err := pingArguments(netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatalf("valid gateway rejected: %v", err)
	}
	want := []string{"-n", "1", "-w", "1000", "2001:db8::1"}
	if len(args) != len(want) {
		t.Fatalf("ping args = %#v, want %#v", args, want)
	}
	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("ping args = %#v, want %#v", args, want)
		}
	}
	if _, err := pingArguments(netip.Addr{}); err == nil {
		t.Fatal("invalid gateway accepted")
	}
}

func TestGatewayProbeDirectRouteDoesNotInventGatewayFailure(t *testing.T) {
	table := fixtureRouteTable{routes: []Route{{Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: "eth", InterfaceIndex: 2}}}
	checkerCalled := false
	p := NewGatewayProbe(table)
	p.Checker = func(context.Context, netip.Addr) error { checkerCalled = true; return errors.New("must not run") }
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "192.0.2.8"}})
	if checkerCalled || got.Interpretation.FailureReason != model.FailureReasonNone || got.Status != model.ProbeStatusPassed {
		t.Fatalf("direct route result = %#v, checker=%v", got, checkerCalled)
	}
}

func TestRouteProbeNormalizesTimeoutAndUnsupported(t *testing.T) {
	timeoutTable := RouteTableFunc(func(ctx context.Context) ([]Route, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	p := NewTargetRouteProbe(timeoutTable)
	p.Timeout = 5 * time.Millisecond
	started := time.Now()
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "192.0.2.8"}})
	if time.Since(started) > 500*time.Millisecond {
		t.Fatalf("timeout was not bounded")
	}
	if got.Interpretation.FailureReason != model.FailureReason(FailureReasonProbeTimeout) {
		t.Fatalf("timeout reason = %q", got.Interpretation.FailureReason)
	}
	pDefault := NewDefaultRouteProbe(fixtureRouteTable{err: ErrUnsupported})
	got = pDefault.Run(context.Background(), probe.ExecutionContext{})
	if got.Interpretation.FailureReason != model.FailureReasonUnsupported || got.Status != model.ProbeStatusError {
		t.Fatalf("unsupported result = %#v", got)
	}
}
