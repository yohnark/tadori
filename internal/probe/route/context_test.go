package route

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
)

func TestBuildNetworkContextClassifiesObservedRouteScope(t *testing.T) {
	tests := []struct {
		name            string
		target          string
		route           Route
		interfaces      []interfacecfg.InterfaceState
		wantScope       model.NetworkScope
		wantDisposition model.RouteDisposition
		wantGateway     string
		wantSource      string
		wantInterface   string
		wantVPN         bool
		wantVirtual     bool
	}{
		{
			name:       "private address on-link is local link",
			target:     "10.0.10.25",
			route:      Route{Destination: netip.MustParsePrefix("10.0.10.0/24"), Interface: "Ethernet", InterfaceIndex: 2},
			interfaces: []interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("10.0.10.10"), Prefix: 24}}}},
			wantScope:  model.NetworkScopeSameLink, wantDisposition: model.RouteDispositionOnLink,
			wantSource: "10.0.10.10", wantInterface: "Ethernet",
		},
		{
			name:       "private address is routed",
			target:     "10.30.14.22",
			route:      Route{Destination: netip.MustParsePrefix("10.30.0.0/16"), Gateway: netip.MustParseAddr("10.20.4.1"), Interface: "Ethernet", InterfaceIndex: 2, Metric: 25},
			interfaces: []interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("10.20.4.18"), Prefix: 24}}}},
			wantScope:  model.NetworkScopePrivateRouted, wantDisposition: model.RouteDispositionRouted,
			wantGateway: "10.20.4.1", wantSource: "10.20.4.18", wantInterface: "Ethernet",
		},
		{
			name:       "private address is VPN routed",
			target:     "10.30.14.22",
			route:      Route{Destination: netip.MustParsePrefix("10.30.0.0/16"), Gateway: netip.MustParseAddr("10.20.4.1"), Interface: "Contoso VPN", InterfaceIndex: 8, Metric: 10, VPNOrTunnel: true, VirtualAdapter: true, InterfaceType: "vpn"},
			interfaces: []interfacecfg.InterfaceState{{Index: 8, Name: "Contoso VPN", Type: "vpn", VPN: true, Virtual: true, Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("10.20.4.18"), Prefix: 24}}}},
			wantScope:  model.NetworkScopeVPNTunnelRouted, wantDisposition: model.RouteDispositionRouted,
			wantGateway: "10.20.4.1", wantSource: "10.20.4.18", wantInterface: "Contoso VPN", wantVPN: true, wantVirtual: true,
		},
		{
			name:       "loopback",
			target:     "127.0.0.1",
			route:      Route{Destination: netip.MustParsePrefix("127.0.0.0/8"), Interface: "lo", InterfaceIndex: 1},
			interfaces: []interfacecfg.InterfaceState{{Index: 1, Name: "lo", Loopback: true, Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("127.0.0.1"), Prefix: 8}}}},
			wantScope:  model.NetworkScopeLoopback, wantDisposition: model.RouteDispositionOnLink,
			wantSource: "127.0.0.1", wantInterface: "lo",
		},
		{
			name:       "IPv4 link-local",
			target:     "169.254.10.25",
			route:      Route{Destination: netip.MustParsePrefix("169.254.0.0/16"), Interface: "Ethernet", InterfaceIndex: 2},
			interfaces: []interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("169.254.10.10"), Prefix: 16}}}},
			wantScope:  model.NetworkScopeLinkLocal, wantDisposition: model.RouteDispositionOnLink,
			wantSource: "169.254.10.10", wantInterface: "Ethernet",
		},
		{
			name:       "IPv6 link-local",
			target:     "fe80::25",
			route:      Route{Destination: netip.MustParsePrefix("fe80::/64"), Interface: "Ethernet", InterfaceIndex: 2},
			interfaces: []interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("fe80::10"), Prefix: 64}}}},
			wantScope:  model.NetworkScopeLinkLocal, wantDisposition: model.RouteDispositionOnLink,
			wantSource: "fe80::10", wantInterface: "Ethernet",
		},
		{
			name:       "external default route",
			target:     "198.51.100.25",
			route:      Route{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "Ethernet", InterfaceIndex: 2, Metric: 100},
			interfaces: []interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("192.0.2.10"), Prefix: 24}}}},
			wantScope:  model.NetworkScopeExternalRouted, wantDisposition: model.RouteDispositionRouted,
			wantGateway: "192.0.2.1", wantSource: "192.0.2.10", wantInterface: "Ethernet",
		},
		{
			name:       "public address over virtual adapter",
			target:     "198.51.100.25",
			route:      Route{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "vEthernet (Corp)", InterfaceIndex: 12, VirtualAdapter: true, InterfaceType: "virtual"},
			interfaces: []interfacecfg.InterfaceState{{Index: 12, Name: "vEthernet (Corp)", Type: "virtual", Virtual: true, Up: true, Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("192.0.2.10"), Prefix: 24}}}},
			wantScope:  model.NetworkScopeExternalRouted, wantDisposition: model.RouteDispositionRouted,
			wantGateway: "192.0.2.1", wantSource: "192.0.2.10", wantInterface: "vEthernet (Corp)", wantVirtual: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := model.ParseTarget(model.TargetIntent{Input: test.target})
			if err != nil {
				t.Fatal(err)
			}
			address := netip.MustParseAddr(test.target)
			selection := Selection{Target: address, Selected: test.route, Candidates: []Route{test.route}}
			got := BuildNetworkContext(target, selection, test.interfaces, nil, []string{"native-route-api", "native-interface-api"}, []string{"route-1", "interface-1"})
			if got.NetworkScope != test.wantScope || got.EffectiveRoute != test.wantDisposition {
				t.Fatalf("context scope/route = %q/%q, want %q/%q: %#v", got.NetworkScope, got.EffectiveRoute, test.wantScope, test.wantDisposition, got)
			}
			if got.Gateway != test.wantGateway || got.SelectedSourceAddress != test.wantSource || got.SelectedSourceInterface != test.wantInterface {
				t.Fatalf("normalized endpoints = gateway %q source %q interface %q, want %q %q %q", got.Gateway, got.SelectedSourceAddress, got.SelectedSourceInterface, test.wantGateway, test.wantSource, test.wantInterface)
			}
			if got.VPNOrTunnelInvolvement != test.wantVPN || got.VirtualAdapterInvolvement != test.wantVirtual {
				t.Fatalf("adapter involvement = vpn %t virtual %t, want vpn %t virtual %t", got.VPNOrTunnelInvolvement, got.VirtualAdapterInvolvement, test.wantVPN, test.wantVirtual)
			}
		})
	}
}

func TestBuildNetworkContextRetainsCompetingRouteMetrics(t *testing.T) {
	target := model.NewTarget("203.0.113.25", 443)
	selected := Route{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "primary", InterfaceIndex: 2, Metric: 10}
	backup := Route{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "backup", InterfaceIndex: 3, Metric: 50}
	selection, ok := SelectDetailed([]Route{backup, selected}, netip.MustParseAddr("203.0.113.25"))
	if !ok || selection.Selected.Interface != "primary" {
		t.Fatalf("selection = %#v, ok=%v", selection, ok)
	}
	context := BuildNetworkContext(target, selection, nil, nil, nil, nil)
	if context.NetworkScope != model.NetworkScopeExternalRouted || context.RouteMetric != 10 {
		t.Fatalf("context = %#v", context)
	}
	if len(context.CompetingRoutes) != 1 || context.CompetingRoutes[0].Interface != "backup" || context.CompetingRoutes[0].Metric != 50 {
		t.Fatalf("competing routes = %#v", context.CompetingRoutes)
	}
}

func TestBuildNetworkContextUsesGatewaySubnetForDefaultSource(t *testing.T) {
	target := model.NewTarget("198.51.100.25", 443)
	selection := Selection{
		Target: netip.MustParseAddr("198.51.100.25"),
		Selected: Route{
			Destination:    netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:        netip.MustParseAddr("192.0.2.1"),
			Interface:      "Ethernet",
			InterfaceIndex: 2,
		},
		Candidates: []Route{{
			Destination:    netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:        netip.MustParseAddr("192.0.2.1"),
			Interface:      "Ethernet",
			InterfaceIndex: 2,
		}},
	}
	context := BuildNetworkContext(target, selection, []interfacecfg.InterfaceState{{
		Index: 2,
		Name:  "Ethernet",
		Addresses: []interfacecfg.Address{
			{IP: netip.MustParseAddr("10.0.0.10"), Prefix: 24},
			{IP: netip.MustParseAddr("192.0.2.10"), Prefix: 24},
		},
	}}, nil, nil, nil)
	if context.SelectedSourceAddress != "192.0.2.10" {
		t.Fatalf("default-route source = %q, want gateway-subnet address", context.SelectedSourceAddress)
	}
}

func TestBuildNetworkContextMarksEqualPrecedenceRoutesAmbiguous(t *testing.T) {
	target := model.NewTarget("203.0.113.25", 443)
	routes := []Route{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "primary", InterfaceIndex: 2, Metric: 10},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "backup", InterfaceIndex: 3, Metric: 10},
	}
	selection, ok := SelectDetailed(routes, netip.MustParseAddr("203.0.113.25"))
	if !ok || !selection.Ambiguous {
		t.Fatalf("selection ambiguity = %#v, ok=%v", selection, ok)
	}
	context := BuildNetworkContext(target, selection, nil, nil, nil, nil)
	if context.NetworkScope != model.NetworkScopeUnknown || !context.RouteSelectionAmbiguous {
		t.Fatalf("ambiguous context = %#v", context)
	}
}

func TestTargetRouteProbeOnLinkDoesNotNeedGatewayOrNeighborEntry(t *testing.T) {
	called := false
	targetRouteProbe := NewTargetRouteProbe(RouteTableFunc(func(context.Context) ([]Route, error) {
		return []Route{{Destination: netip.MustParsePrefix("10.0.10.0/24"), Interface: "Ethernet", InterfaceIndex: 2}}, nil
	}))
	targetRouteProbe.Neighbors = NeighborTableFunc(func(context.Context, netip.Addr, int) (model.NeighborEvidence, error) {
		called = true
		return model.NeighborEvidence{Observation: model.NeighborObservationNotObserved, Note: "fixture cache is empty"}, nil
	})
	got := targetRouteProbe.Run(context.Background(), probe.ExecutionContext{Target: model.NewTarget("10.0.10.25", 80)})
	if got.Status != model.ProbeStatusPassed || got.Interpretation.FailureReason != model.FailureReasonNone || !called {
		t.Fatalf("on-link result = %#v, neighbor called=%v", got, called)
	}
	observation, err := DecodeRouteEvidence(got.Evidence[0])
	if err != nil {
		t.Fatal(err)
	}
	if observation.EffectiveRoute != model.RouteDispositionOnLink || observation.Gateway != "" || observation.Neighbor == nil || observation.Neighbor.Observation != model.NeighborObservationNotObserved {
		t.Fatalf("on-link route evidence = %#v", observation)
	}
}

func TestGatewayProbeSkipsLoopbackGatewayCheck(t *testing.T) {
	called := false
	gateway := NewGatewayProbe(RouteTableFunc(func(context.Context) ([]Route, error) {
		return []Route{{Destination: netip.MustParsePrefix("127.0.0.0/8"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "lo", InterfaceIndex: 1}}, nil
	}))
	gateway.Checker = func(context.Context, netip.Addr) error {
		called = true
		return nil
	}
	got := gateway.Run(context.Background(), probe.ExecutionContext{Target: model.NewTarget("127.0.0.1", 80)})
	if called || got.Status != model.ProbeStatusPassed || got.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("loopback gateway result = %#v, checker called=%v", got, called)
	}
}

func TestNetworkContextFromProbeResultsPreservesUnknownRouteEvidence(t *testing.T) {
	target := model.NewTarget("198.51.100.25", 443)
	probeResult := model.ProbeResult{Name: TargetRouteProbeName, Target: target, Status: model.ProbeStatusError, Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonUnsupported, Layer: model.LayerRoute, FaultDomain: model.FaultDomainRouting}}
	probeResult.Evidence = []model.Evidence{{ID: "target-route-error", Kind: model.EvidenceKindRoute, Source: "fixture", Raw: json.RawMessage(`{"error":"unsupported"}`)}}
	context, ok := NetworkContextFromProbeResults(target, []model.ProbeResult{probeResult})
	if !ok || context.NetworkScope != model.NetworkScopeUnknown || context.EffectiveRoute != model.RouteDispositionUnknown {
		t.Fatalf("unknown context = %#v, ok=%v", context, ok)
	}
	if !reflect.DeepEqual(context.EvidenceIDs, []string{"target-route-error"}) {
		t.Fatalf("unknown evidence IDs = %#v", context.EvidenceIDs)
	}
}
