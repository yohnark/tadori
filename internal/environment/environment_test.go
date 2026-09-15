package environment

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/enterprise"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	"github.com/yohnark/tadori/internal/probe/proxy"
	"github.com/yohnark/tadori/internal/probe/route"
	"github.com/yohnark/tadori/internal/report"
)

var environmentTestTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func TestBuildOrdinaryLANIsTargetIndependent(t *testing.T) {
	collection := baseCollection()
	collection.Interfaces = []interfacecfg.InterfaceState{{
		Index: 2, Name: "Ethernet", Type: "ethernet", Up: true,
		Addresses: []interfacecfg.Address{{IP: netip.MustParseAddr("192.0.2.20"), Prefix: 24}},
	}}
	collection.DNS = interfacecfg.Snapshot{DNSServers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, DNSSuffixes: []string{"corp.example"}}
	collection.Routes = []route.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "Ethernet", InterfaceIndex: 2, Metric: 25}}

	got := Build(collection, environmentTestTime)
	if got.State != model.EnvironmentStateObserved || got.InterfacesState != model.EnvironmentStateObserved {
		t.Fatalf("ordinary LAN state = %q/%q, want observed", got.State, got.InterfacesState)
	}
	if got.Routing.DefaultIPv4 == nil || !got.Routing.DefaultIPv4.Selected || got.Routing.DefaultIPv4.Interface != "Ethernet" {
		t.Fatalf("default route = %#v", got.Routing.DefaultIPv4)
	}
	if got.VPN.Present || len(got.VPN.RouteParticipation) != 0 {
		t.Fatalf("LAN was classified as VPN: %#v", got.VPN)
	}
	if got.DNS.Servers[0] != "192.0.2.53" || got.DNS.Suffixes[0] != "corp.example" {
		t.Fatalf("DNS configuration = %#v", got.DNS)
	}
}

func TestBuildVPNSplitDNSKeepsPresenceSeparateFromRouteUse(t *testing.T) {
	collection := baseCollection()
	collection.Interfaces = []interfacecfg.InterfaceState{{Index: 7, Name: "CorpVPN", Type: "vpn", Up: true, VPN: true, Virtual: true}}
	collection.DNS = interfacecfg.Snapshot{
		DNSServers:  []netip.Addr{netip.MustParseAddr("10.20.0.53")},
		DNSSuffixes: []string{"internal.example"}, SearchList: []string{"internal.example"},
		NRPT: []model.NameResolutionPolicyRule{{Namespaces: []string{"internal.example"}, NameServers: []string{"10.20.0.53"}, VPNRequired: true}},
	}
	collection.Routes = []route.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.20.0.1"), Interface: "CorpVPN", InterfaceIndex: 7, Metric: 5, VPNOrTunnel: true, VirtualAdapter: true}}

	got := Build(collection, environmentTestTime)
	if !got.VPN.Present || !reflect.DeepEqual(got.VPN.ActiveAdapters, []string{"CorpVPN"}) {
		t.Fatalf("VPN presence = %#v", got.VPN)
	}
	if !reflect.DeepEqual(got.VPN.RouteParticipation, []string{"ipv4:CorpVPN"}) {
		t.Fatalf("VPN route participation = %#v", got.VPN.RouteParticipation)
	}
	if len(got.DNS.NRPT) != 1 || !got.DNS.NRPT[0].VPNRequired || got.DNS.Certainty != model.ObservationCertaintyConfigured {
		t.Fatalf("split DNS policy = %#v", got.DNS)
	}
}

func TestBuildProxyPACAndDivergenceRemainExplicit(t *testing.T) {
	collection := baseCollection()
	collection.WinHTTP = proxy.ConfigurationObservation{State: proxy.StateStaticProxyConfigured, StaticProxyConfigured: true, ProxyEndpoints: []string{"proxy.corp.example:8080"}}
	collection.WinINET = proxy.ConfigurationObservation{State: proxy.StatePACConfigured, PACConfigured: true, PACURL: "https://pac.corp.example/proxy.pac", AutoDetect: true}

	got := Build(collection, environmentTestTime)
	if got.Proxy.State != model.EnvironmentStateConflicting || !got.Proxy.ConfigurationDiverges || !got.Proxy.ConfigurationKnown {
		t.Fatalf("proxy divergence = %#v", got.Proxy)
	}
	if !got.Proxy.WinINET.PACConfigured || got.Proxy.WinINET.State != model.EnvironmentStateConfigured {
		t.Fatalf("PAC source = %#v", got.Proxy.WinINET)
	}
	if got.Proxy.PACUseObserved || !got.Proxy.EffectiveUseTargetBounded {
		t.Fatalf("PAC use was overclaimed = %#v", got.Proxy)
	}
	if got.State != model.EnvironmentStateConflicting || len(got.Conflicts) != 0 || len(got.Proxy.Conflicts) != 1 {
		t.Fatalf("conflicting snapshot = %#v", got)
	}
}

func TestBuildMultipleInterfacesSelectsDeterministicDefaults(t *testing.T) {
	collection := baseCollection()
	collection.Interfaces = []interfacecfg.InterfaceState{
		{Index: 20, Name: "WiFi", Type: "wifi", Up: true},
		{Index: 4, Name: "Ethernet", Type: "ethernet", Up: true},
	}
	collection.Routes = []route.Route{
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "WiFi", InterfaceIndex: 20, Metric: 50},
		{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "Ethernet", InterfaceIndex: 4, Metric: 10},
	}

	got := Build(collection, environmentTestTime)
	if got.Routing.DefaultIPv4 == nil || got.Routing.DefaultIPv4.Interface != "Ethernet" {
		t.Fatalf("selected IPv4 default = %#v", got.Routing.DefaultIPv4)
	}
	selected := 0
	for _, value := range got.Routing.Routes {
		if value.Selected {
			selected++
			if value.Interface != "Ethernet" {
				t.Fatalf("wrong selected route = %#v", value)
			}
		}
	}
	if selected != 1 {
		t.Fatalf("selected route count = %d, want 1", selected)
	}
}

func TestBuildUnsupportedSubsystemsRemainExplicit(t *testing.T) {
	collection := Collection{
		InterfacesUnsupported: true, DNSUnsupported: true, RoutesKnown: false, RouteUnsupported: true,
		ProxyUnsupported: true, EnterpriseUnsupported: true, RuntimeKnown: true,
		Runtime: model.EnvironmentRuntimeObservation{State: model.EnvironmentStateObserved, OS: "windows", Arch: "amd64", RuntimeVersion: "go1.23"},
	}

	got := Build(collection, environmentTestTime)
	if got.InterfacesState != model.EnvironmentStateUnsupported || got.DNS.State != model.EnvironmentStateUnsupported || got.Routing.State != model.EnvironmentStateUnsupported || got.Proxy.State != model.EnvironmentStateUnsupported {
		t.Fatalf("unsupported components = %#v", got)
	}
	if got.Firewall.State != model.EnterpriseObservationStateUnsupported || got.Trust.State != model.EnvironmentStateUnsupported {
		t.Fatalf("unsupported enterprise components = %#v/%#v", got.Firewall, got.Trust)
	}
	capabilities := make(map[string]model.EnvironmentCapabilityState)
	for _, capability := range got.Runtime.Capabilities {
		capabilities[capability.Name] = capability.State
	}
	if capabilities["route_table"] != model.EnvironmentCapabilityUnsupported || capabilities["winhttp_proxy"] != model.EnvironmentCapabilityUnsupported {
		t.Fatalf("capabilities = %#v", capabilities)
	}
}

func TestBuildIncompleteEvidenceIsPartialAndDoesNotInventValues(t *testing.T) {
	collection := baseCollection()
	collection.Interfaces = []interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true}}
	collection.DNS = interfacecfg.Snapshot{ResolverError: "resolver access denied"}
	collection.DNSError = "resolver access denied"
	collection.RoutesKnown = false
	collection.RouteError = "route table unavailable"
	collection.WinHTTPKnown = true
	collection.WinHTTP = proxy.ConfigurationObservation{State: proxy.StateDirect, Direct: true}
	collection.WinINETKnown = false

	got := Build(collection, environmentTestTime)
	if got.State != model.EnvironmentStatePartial || got.DNS.State != model.EnvironmentStatePartial || got.Routing.State != model.EnvironmentStateUnknown || got.Proxy.State != model.EnvironmentStatePartial {
		t.Fatalf("incomplete states = %#v", got)
	}
	if got.Routing.DefaultIPv4 != nil || got.Proxy.WinINET.State != model.EnvironmentStateUnknown {
		t.Fatalf("incomplete values were invented = %#v/%#v", got.Routing, got.Proxy)
	}
}

func TestBuildFromProbeResultsProjectsOnlyTargetIndependentLanes(t *testing.T) {
	defaultEvidence := route.RouteObservation{RouteType: "default", RoutePrefix: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "Ethernet", InterfaceIndex: 2, Metric: 10}
	targetEvidence := route.RouteObservation{RouteType: "target", RoutePrefix: "203.0.113.0/24", Gateway: "192.0.2.1", Interface: "Ethernet", InterfaceIndex: 2, Metric: 10, TargetIP: "203.0.113.8"}
	defaultRaw, _ := json.Marshal(defaultEvidence)
	targetRaw, _ := json.Marshal(targetEvidence)
	interfacesRaw, _ := json.Marshal([]interfacecfg.InterfaceState{{Index: 2, Name: "Ethernet", Up: true}})
	probes := []model.ProbeResult{{Name: "target_route", Evidence: []model.Evidence{{ID: "target-route", Kind: model.EvidenceKindRoute, Raw: targetRaw}}}, {Name: "default_route", Evidence: []model.Evidence{{ID: "default-route", Kind: model.EvidenceKindRoute, Raw: defaultRaw}}}, {Name: "interface_state", Evidence: []model.Evidence{{ID: "interfaces", Kind: model.EvidenceKindInterfaceState, Raw: interfacesRaw}}}}

	got := BuildFromProbeResults(probes, environmentTestTime)
	if got.Routing.DefaultIPv4 == nil || got.Routing.DefaultIPv4.RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("default route was not projected = %#v", got.Routing)
	}
	if len(got.Routing.Routes) != 1 || got.Routing.Routes[0].RoutePrefix != "0.0.0.0/0" {
		t.Fatalf("target route leaked into environment = %#v", got.Routing.Routes)
	}
	if strings.Contains(string(mustJSON(got)), "203.0.113.8") {
		t.Fatal("target-specific address leaked into environment snapshot")
	}
}

func TestCollectorUsesFixedCaptureTimeAndVersion(t *testing.T) {
	collection := baseCollection()
	collection.Interfaces = []interfacecfg.InterfaceState{{Index: 1, Name: "Ethernet", Up: true}}
	collection.RuntimeKnown = true
	collection.Runtime = model.EnvironmentRuntimeObservation{State: model.EnvironmentStateObserved, OS: "test", Arch: "test", RuntimeVersion: "runtime"}
	provider := ProviderFunc(func(context.Context) (Collection, error) { return collection, nil })

	got, err := Collect(context.Background(), Options{Provider: provider, Now: func() time.Time { return environmentTestTime }, TadoriVersion: "test-version"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !got.CapturedAt.Equal(environmentTestTime) || got.Runtime.TadoriVersion != "test-version" {
		t.Fatalf("capture identity = %#v", got)
	}
	first, firstErr := report.RenderEnvironmentJSON(got)
	second, secondErr := report.RenderEnvironmentJSON(got)
	if firstErr != nil || secondErr != nil || string(first) != string(second) {
		t.Fatalf("environment JSON is not deterministic: %v/%v", firstErr, secondErr)
	}
}

func baseCollection() Collection {
	return Collection{
		InterfacesKnown: true, DNSKnown: true, RoutesKnown: true,
		WinHTTPKnown: true, WinINETKnown: true, FirewallKnown: true, TrustKnown: true, RuntimeKnown: true,
		WinHTTP:    proxy.ConfigurationObservation{State: proxy.StateDirect, Direct: true},
		WinINET:    proxy.ConfigurationObservation{State: proxy.StateDirect, Direct: true},
		Firewall:   enterprise.FirewallObservation{Available: true},
		TrustStore: enterprise.TrustStoreObservation{Available: true, RootCount: 3},
		Runtime:    model.EnvironmentRuntimeObservation{State: model.EnvironmentStateObserved, OS: "test", Arch: "test", RuntimeVersion: "runtime"},
	}
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
