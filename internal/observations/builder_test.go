package observations

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/dns"
	enterpriseprobe "github.com/yohnark/tadori/internal/probe/enterprise"
	"github.com/yohnark/tadori/internal/probe/interfacecfg"
	proxyprobe "github.com/yohnark/tadori/internal/probe/proxy"
	"github.com/yohnark/tadori/internal/probe/route"
)

func mustTarget(t *testing.T, input string) model.Target {
	t.Helper()
	target, err := model.ParseTarget(model.TargetIntent{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func mustRaw(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixtureEvidence(t *testing.T, id string, kind model.EvidenceKind, source string, value any) model.Evidence {
	t.Helper()
	return model.Evidence{ID: id, Kind: kind, Source: source, Raw: mustRaw(t, value)}
}

func fixtureDNSProbe(t *testing.T, name string, a, aaaa []string, id string) model.ProbeResult {
	t.Helper()
	resolution := model.NameResolutionObservation{
		RequestedName:   name,
		A:               append([]string(nil), a...),
		AAAA:            append([]string(nil), aaaa...),
		SelectedAddress: firstAnswer(a, aaaa),
		SelectedFamily:  "A",
		EffectivePath: &model.NameResolutionPath{
			State:       model.NameResolutionPathEffective,
			Mechanism:   model.NameResolutionMechanismDNS,
			Certainty:   model.NameResolutionCertaintyObserved,
			Provenance:  "fixture resolver result; server/interface unavailable",
			EvidenceIDs: []string{id},
		},
		EvidenceIDs: []string{id},
		Certainty:   model.ObservationCertaintyObserved,
	}
	if len(aaaa) != 0 && len(a) == 0 {
		resolution.SelectedFamily = "AAAA"
	}
	return model.ProbeResult{
		Name:           "dns",
		Status:         model.ProbeStatusPassed,
		NameResolution: &resolution,
		Evidence:       []model.Evidence{fixtureEvidence(t, id, model.EvidenceKindDNSResolution, "fixture:dns", dns.DNSResolutionEvidence{Host: name, A: a, AAAA: aaaa})},
	}
}

func fixtureRouteProbe(t *testing.T, id, targetIP, prefix, gateway, iface string, index, metric int, vpn, virtual bool) model.ProbeResult {
	t.Helper()
	value := route.RouteObservation{
		RouteType:      "target",
		TargetIP:       targetIP,
		RoutePrefix:    prefix,
		Destination:    prefix,
		Gateway:        gateway,
		Interface:      iface,
		InterfaceIndex: index,
		Metric:         metric,
		EffectiveRoute: model.RouteDispositionRouted,
		InterfaceType:  "ethernet",
		VPNOrTunnel:    vpn,
		VirtualAdapter: virtual,
		NextHop:        gateway,
		Neighbor:       &model.NeighborEvidence{Observation: model.NeighborObservationObserved, Source: "fixture:neighbor", Entries: []model.NeighborEntry{{Address: gateway, Interface: iface, InterfaceIndex: index, State: "reachable"}}},
	}
	if gateway == "" {
		value.EffectiveRoute = model.RouteDispositionOnLink
		value.NextHop = "on-link"
	}
	return model.ProbeResult{
		Name: "target_route", Status: model.ProbeStatusPassed,
		Evidence: []model.Evidence{fixtureEvidence(t, id, model.EvidenceKindRoute, "fixture:route", value)},
	}
}

func fixtureInterfaceProbe(t *testing.T, id, name string, index int, address string, prefix int, vpn, virtual bool) model.ProbeResult {
	t.Helper()
	return model.ProbeResult{
		Name: "interface_state", Status: model.ProbeStatusPassed,
		Evidence: []model.Evidence{fixtureEvidence(t, id, model.EvidenceKindInterfaceState, "fixture:interfaces", []interfacecfg.InterfaceState{{
			Index: index, Name: name, Up: true, VPN: vpn, Virtual: virtual,
			Addresses: []interfacecfg.Address{{IP: mustAddr(address), Prefix: prefix}},
		}})},
	}
}

func mustAddr(value string) (address netip.Addr) {
	address, _ = netip.ParseAddr(value)
	return address
}

func TestBuildLiteralIPProjectsIntentEndpointAndLiteralResolution(t *testing.T) {
	target := mustTarget(t, "192.0.2.44:443")
	got := Build(target, nil)

	if got.Endpoint.OriginalInput != "192.0.2.44:443" || got.Endpoint.RequestedIdentity != "192.0.2.44" {
		t.Fatalf("endpoint intent = %#v", got.Endpoint)
	}
	if len(got.Endpoint.ResolvedCandidates) != 1 || got.Endpoint.ResolvedCandidates[0].Address != "192.0.2.44" || got.Endpoint.ResolvedCandidates[0].Family != model.EndpointFamilyIPv4 {
		t.Fatalf("literal candidates = %#v", got.Endpoint.ResolvedCandidates)
	}
	if got.Endpoint.SelectedEndpoint == nil || got.Endpoint.SelectedEndpoint.Address != "192.0.2.44" {
		t.Fatalf("literal selected endpoint = %#v", got.Endpoint.SelectedEndpoint)
	}
	if got.NameResolution.EffectivePath == nil || got.NameResolution.EffectivePath.Mechanism != model.NameResolutionMechanismLiteralIP || got.NameResolution.SelectedAddress != "192.0.2.44" {
		t.Fatalf("literal name resolution = %#v", got.NameResolution)
	}
	if got.NameResolution.EffectivePath.Certainty != model.NameResolutionCertaintyObserved || got.NameResolution.Certainty != model.ObservationCertaintyObserved {
		t.Fatalf("literal certainty = %#v", got.NameResolution)
	}
	if got.NetworkContext.EffectiveRoute != model.RouteDispositionUnknown || got.NetworkContext.NetworkScope != model.NetworkScopeUnknown {
		t.Fatalf("literal network context = %#v", got.NetworkContext)
	}
}

func TestBuildPublicHostnamePreservesAAndAAAAAndUnknownDNSProvenance(t *testing.T) {
	target := mustTarget(t, "www.example.test:443")
	probe := fixtureDNSProbe(t, "www.example.test", []string{"93.184.216.34"}, []string{"2001:db8::34"}, "dns-resolution-1")
	got := Build(target, []model.ProbeResult{probe})

	if got.Endpoint.RequestedIdentity != "www.example.test" || got.Endpoint.Port != 443 {
		t.Fatalf("hostname endpoint = %#v", got.Endpoint)
	}
	if len(got.Endpoint.ResolvedCandidates) != 2 || got.Endpoint.ResolvedCandidates[0].Family != model.EndpointFamilyIPv4 || got.Endpoint.ResolvedCandidates[1].Family != model.EndpointFamilyIPv6 {
		t.Fatalf("A/AAAA candidates = %#v", got.Endpoint.ResolvedCandidates)
	}
	if got.Endpoint.ResolvedCandidates[0].Certainty != model.ObservationCertaintyObserved || len(got.Endpoint.ResolvedCandidates[0].EvidenceIDs) != 1 {
		t.Fatalf("candidate provenance = %#v", got.Endpoint.ResolvedCandidates[0])
	}
	if got.NameResolution.SelectedAddress != "93.184.216.34" || !contains(got.NameResolution.EvidenceIDs, "dns-resolution-1") {
		t.Fatalf("resolution answer = %#v", got.NameResolution)
	}
	if got.NameResolution.EffectivePath.Resolver != "" || got.NameResolution.EffectivePath.Provenance == "" {
		t.Fatalf("unknown resolver provenance was guessed: %#v", got.NameResolution.EffectivePath)
	}
	if !contains(got.Endpoint.Provenance, "probe:dns") || !contains(got.Endpoint.EvidenceIDs, "dns-resolution-1") {
		t.Fatalf("endpoint provenance = %#v", got.Endpoint)
	}
}

func TestBuildSplitDNSRetainsConfiguredPolicyAndEffectivePathRoles(t *testing.T) {
	target := mustTarget(t, "fileserver:445")
	dnsProbe := fixtureDNSProbe(t, "fileserver", []string{"10.30.14.22"}, nil, "resolution-effective")
	dnsProbe.NameResolution.CandidateSuffixes = []string{"corp.example"}
	dnsProbe.NameResolution.EffectivePath.VPN = true
	dnsProbe.NameResolution.EffectivePath.PolicySource = "fixture:nrpt"
	dnsProbe.NameResolution.EffectivePath.PolicyRule = "corp"
	configuration := dns.DNSConfigurationEvidence{
		Configured: true,
		Resolvers:  []string{"192.0.2.53", "10.20.0.53"},
		Source:     "fixture:dns-config",
		Environment: &dns.ResolutionEnvironment{
			CandidateSuffixes: []string{"corp.example"},
			Interfaces: []dns.ResolutionInterface{
				{Index: 7, Name: "Wi-Fi", DNSServers: []string{"192.0.2.53"}, DNSSuffix: "public.example"},
				{Index: 19, Name: "Contoso VPN", VPN: true, VirtualAdapter: true, DNSServers: []string{"10.20.0.53"}, DNSSuffix: "corp.example"},
			},
			NRPT:             []model.NameResolutionPolicyRule{{Namespaces: []string{".corp.example"}, NameServers: []string{"10.20.0.53"}, Source: "fixture:nrpt", RuleID: "corp", VPNRequired: true}},
			HostsFileEntries: []model.NameResolutionHostEntry{{Name: "fileserver", Addresses: []string{"10.0.0.5"}, Source: "fixture:hosts"}},
		},
	}
	configProbe := model.ProbeResult{Name: "dns_configuration", Status: model.ProbeStatusPassed, Evidence: []model.Evidence{fixtureEvidence(t, "dns-config-1", model.EvidenceKindDNSConfiguration, "fixture:dns-config", configuration)}}

	got := Build(target, []model.ProbeResult{configProbe, dnsProbe})
	if !contains(got.NameResolution.CandidateSuffixes, "corp.example") || !contains(got.NameResolution.CandidateSuffixes, "public.example") {
		t.Fatalf("candidate suffixes = %#v", got.NameResolution.CandidateSuffixes)
	}
	if !contains(got.NameResolution.CandidateNamespaces, ".corp.example") {
		t.Fatalf("candidate namespaces = %#v", got.NameResolution.CandidateNamespaces)
	}
	var configured, policy, effective bool
	for _, path := range got.NameResolution.Paths {
		switch path.State {
		case model.NameResolutionPathConfiguredCandidate:
			configured = true
		case model.NameResolutionPathPolicyCandidate:
			policy = true
		case model.NameResolutionPathEffective:
			effective = true
		}
	}
	if !configured || !policy || !effective {
		t.Fatalf("split DNS path roles = %#v", got.NameResolution.Paths)
	}
	if got.NameResolution.EffectivePath == nil || !got.NameResolution.EffectivePath.VPN || got.NameResolution.EffectivePath.PolicyRule != "corp" {
		t.Fatalf("effective split-DNS path = %#v", got.NameResolution.EffectivePath)
	}
	if len(got.NameResolution.HostsFileEntries) != 1 || got.NameResolution.HostsFileEntries[0].Source != "fixture:hosts" {
		t.Fatalf("hosts provenance = %#v", got.NameResolution.HostsFileEntries)
	}
	if got.NameResolution.EffectivePath.Certainty != model.NameResolutionCertaintyObserved {
		t.Fatalf("configured path was promoted to effective certainty: %#v", got.NameResolution.EffectivePath)
	}
}

func TestBuildNetworkScopesPreservesRouteInterfaceVPNAndNeighborSemantics(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		prefix    string
		gateway   string
		iface     string
		index     int
		address   string
		vpn       bool
		virtual   bool
		wantScope model.NetworkScope
		wantRoute model.RouteDisposition
	}{
		{name: "local link", target: "10.0.10.25:80", prefix: "10.0.10.0/24", iface: "Ethernet", index: 2, address: "10.0.10.10", wantScope: model.NetworkScopeSameLink, wantRoute: model.RouteDispositionOnLink},
		{name: "private routed", target: "10.30.14.22:443", prefix: "10.30.0.0/16", gateway: "10.20.4.1", iface: "Ethernet", index: 2, address: "10.20.4.18", wantScope: model.NetworkScopePrivateRouted, wantRoute: model.RouteDispositionRouted},
		{name: "VPN routed", target: "10.30.14.22:443", prefix: "10.30.0.0/16", gateway: "10.20.4.1", iface: "Contoso VPN", index: 8, address: "10.20.4.18", vpn: true, virtual: true, wantScope: model.NetworkScopeVPNTunnelRouted, wantRoute: model.RouteDispositionRouted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := mustTarget(t, test.target)
			routeProbe := fixtureRouteProbe(t, "route-1", test.target[:len(test.target)-len(":80")], test.prefix, test.gateway, test.iface, test.index, 10, test.vpn, test.virtual)
			// The route target is easier to read as a parsed address than as a
			// substring of a host:port fixture.
			if test.name == "private routed" || test.name == "VPN routed" {
				interfaceType := "ethernet"
				if test.vpn {
					interfaceType = "vpn"
				}
				routeProbe.Evidence[0].Raw = mustRaw(t, route.RouteObservation{RouteType: "target", TargetIP: "10.30.14.22", RoutePrefix: test.prefix, Destination: test.prefix, Gateway: test.gateway, Interface: test.iface, InterfaceIndex: test.index, Metric: 10, EffectiveRoute: model.RouteDispositionRouted, NextHop: test.gateway, InterfaceType: interfaceType, VPNOrTunnel: test.vpn, VirtualAdapter: test.virtual, Neighbor: &model.NeighborEvidence{Observation: model.NeighborObservationObserved, Source: "fixture:neighbor", Entries: []model.NeighborEntry{{Address: test.gateway, Interface: test.iface, InterfaceIndex: test.index}}}})
			} else {
				routeProbe.Evidence[0].Raw = mustRaw(t, route.RouteObservation{RouteType: "target", TargetIP: "10.0.10.25", RoutePrefix: test.prefix, Destination: test.prefix, Interface: test.iface, InterfaceIndex: test.index, Metric: 10, EffectiveRoute: model.RouteDispositionOnLink, NextHop: "on-link", InterfaceType: "ethernet", Neighbor: &model.NeighborEvidence{Observation: model.NeighborObservationNotObserved, Source: "fixture:neighbor", Note: "empty cache"}})
			}
			interfaceProbe := fixtureInterfaceProbe(t, "interface-1", test.iface, test.index, test.address, 24, test.vpn, test.virtual)
			got := Build(target, []model.ProbeResult{interfaceProbe, routeProbe})
			if got.NetworkContext.NetworkScope != test.wantScope || got.NetworkContext.EffectiveRoute != test.wantRoute {
				t.Fatalf("network scope/route = %q/%q, want %q/%q: %#v", got.NetworkContext.NetworkScope, got.NetworkContext.EffectiveRoute, test.wantScope, test.wantRoute, got.NetworkContext)
			}
			if got.NetworkContext.SelectedSourceInterface != test.iface || got.NetworkContext.SelectedSourceAddress != test.address {
				t.Fatalf("source context = %#v", got.NetworkContext)
			}
			if got.NetworkContext.Neighbor == nil || got.NetworkContext.Neighbor.Source != "fixture:neighbor" {
				t.Fatalf("neighbor provenance = %#v", got.NetworkContext.Neighbor)
			}
			if got.NetworkContext.Certainty != model.ObservationCertaintyDerived || !contains(got.NetworkContext.ProbeNames, "target_route") {
				t.Fatalf("network certainty/probes = %#v", got.NetworkContext)
			}
		})
	}
}

func TestBuildNetworkRetainsCompetingRoutesAndIncompleteEvidence(t *testing.T) {
	target := mustTarget(t, "198.51.100.25:443")
	routeValue := route.RouteObservation{
		RouteType: "target", TargetIP: "198.51.100.25", RoutePrefix: "0.0.0.0/0", Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "Ethernet", InterfaceIndex: 2, Metric: 10, EffectiveRoute: model.RouteDispositionRouted, NextHop: "192.0.2.1",
		CompetingRoutes: []route.RouteEvidenceCandidate{{RoutePrefix: "0.0.0.0/0", Gateway: "198.51.100.1", Interface: "Backup", InterfaceIndex: 3, Metric: 50}},
	}
	got := Build(target, []model.ProbeResult{{Name: "target_route", Evidence: []model.Evidence{fixtureEvidence(t, "route-1", model.EvidenceKindRoute, "fixture:route", routeValue)}}})
	if len(got.NetworkContext.CompetingRoutes) != 1 || got.NetworkContext.CompetingRoutes[0].Metric != 50 {
		t.Fatalf("competing routes = %#v", got.NetworkContext.CompetingRoutes)
	}

	unsupported := model.ProbeResult{Name: "target_route", Status: model.ProbeStatusError, Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonUnsupported, Layer: model.LayerRoute, FaultDomain: model.FaultDomainRouting}, Evidence: []model.Evidence{{ID: "route-error", Kind: model.EvidenceKindRoute, Source: "fixture:route", Raw: json.RawMessage(`{"error":"unsupported"}`)}}}
	unknown := Build(target, []model.ProbeResult{unsupported})
	if unknown.NetworkContext.EffectiveRoute != model.RouteDispositionUnknown || unknown.NetworkContext.NetworkScope != model.NetworkScopeUnknown {
		t.Fatalf("incomplete route context = %#v", unknown.NetworkContext)
	}
	if unknown.NetworkContext.Certainty != model.ObservationCertaintyUnsupported || !contains(unknown.NetworkContext.EvidenceIDs, "route-error") {
		t.Fatalf("unsupported route semantics = %#v", unknown.NetworkContext)
	}
}

func TestBuildPreservesMultipleCandidatesAndDoesNotTreatThemAsConflict(t *testing.T) {
	target := mustTarget(t, "dual.example.test:443")
	probe := fixtureDNSProbe(t, "dual.example.test", []string{"192.0.2.10", "192.0.2.11"}, []string{"2001:db8::10"}, "dns-many")
	got := Build(target, []model.ProbeResult{probe})
	if len(got.Endpoint.ResolvedCandidates) != 3 || len(got.Endpoint.ProbeCandidates) != 3 {
		t.Fatalf("candidate sets = resolved %#v probe %#v", got.Endpoint.ResolvedCandidates, got.Endpoint.ProbeCandidates)
	}
	if len(got.Endpoint.Conflicts) != 0 {
		t.Fatalf("normal multiple candidates became conflict = %#v", got.Endpoint.Conflicts)
	}
	if got.Endpoint.SelectedEndpoint == nil || got.Endpoint.SelectedEndpoint.Address != "192.0.2.10" || got.Endpoint.SelectedEndpoint.SelectionReason != model.EndpointSelectionDeterministic {
		t.Fatalf("probe selection = %#v", got.Endpoint.SelectedEndpoint)
	}
	if got.NameResolution.AAAA[0] != "2001:db8::10" || got.NameResolution.SelectedFamily != "A" {
		t.Fatalf("family distinction = %#v", got.NameResolution)
	}
}

func TestBuildRetainsConflictingSourceFactsAndRawEvidence(t *testing.T) {
	target := mustTarget(t, "conflicting.example:443")
	first := fixtureDNSProbe(t, "conflicting.example", []string{"192.0.2.10"}, nil, "dns-a")
	second := fixtureDNSProbe(t, "conflicting.example", []string{"192.0.2.20"}, nil, "dns-b")
	rawBefore := append([]byte(nil), first.Evidence[0].Raw...)
	first.NameResolution.SelectedAddress = "192.0.2.10"
	second.NameResolution.SelectedAddress = "192.0.2.20"
	got := Build(target, []model.ProbeResult{second, first})
	if !bytes.Equal(first.Evidence[0].Raw, rawBefore) {
		t.Fatal("projector changed raw probe evidence")
	}
	if len(got.Endpoint.Conflicts) == 0 || len(got.NameResolution.Conflicts) == 0 {
		t.Fatalf("conflicting DNS facts were collapsed: endpoint=%#v name=%#v", got.Endpoint.Conflicts, got.NameResolution.Conflicts)
	}
	if !contains(got.Endpoint.EvidenceIDs, "dns-a") || !contains(got.Endpoint.EvidenceIDs, "dns-b") || !contains(got.NameResolution.EvidenceIDs, "dns-a") || !contains(got.NameResolution.EvidenceIDs, "dns-b") {
		t.Fatalf("conflict provenance = endpoint %#v name %#v", got.Endpoint, got.NameResolution)
	}
	if got.NameResolution.SelectedAddress != "192.0.2.10" {
		t.Fatalf("deterministic representative changed with input order: %q", got.NameResolution.SelectedAddress)
	}
}

func TestBuildIsDeterministicAcrossProbeOrderAndDetachedFromInputs(t *testing.T) {
	target := mustTarget(t, "service.example:443")
	dnsProbe := fixtureDNSProbe(t, "service.example", []string{"192.0.2.10"}, []string{"2001:db8::10"}, "dns-1")
	routeProbe := fixtureRouteProbe(t, "route-1", "192.0.2.10", "192.0.2.0/24", "192.0.2.1", "Ethernet", 2, 10, false, false)
	interfaceProbe := fixtureInterfaceProbe(t, "interface-1", "Ethernet", 2, "192.0.2.20", 24, false, false)
	probes := []model.ProbeResult{routeProbe, interfaceProbe, dnsProbe}
	left := Build(target, probes)
	right := Build(target, []model.ProbeResult{dnsProbe, routeProbe, interfaceProbe})
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("projection depends on probe order\nleft=%#v\nright=%#v", left, right)
	}
	probes[0].Evidence[0].Raw[0] = 'x'
	if left.Endpoint.EvidenceIDs == nil || left.NameResolution.EvidenceIDs == nil {
		t.Fatalf("projection lost evidence references = %#v", left)
	}
	if left.NetworkContext.SelectedSourceInterface != "Ethernet" {
		t.Fatalf("network projection = %#v", left.NetworkContext)
	}
}

func TestBuildUsesLegacyDNSConfigurationShapeAndPreservesUnknownLimitations(t *testing.T) {
	target := mustTarget(t, "fileserver.corp.example:445")
	legacy := struct {
		Servers          []string                         `json:"servers"`
		Interfaces       []interfacecfg.InterfaceState    `json:"interfaces,omitempty"`
		Suffixes         []string                         `json:"suffixes,omitempty"`
		SearchList       []string                         `json:"search_list,omitempty"`
		NRPT             []model.NameResolutionPolicyRule `json:"nrpt,omitempty"`
		NRPTError        string                           `json:"nrpt_error,omitempty"`
		HostsFileEntries []model.NameResolutionHostEntry  `json:"hosts_file_entries,omitempty"`
		HostsFileError   string                           `json:"hosts_file_error,omitempty"`
		Error            string                           `json:"error,omitempty"`
	}{
		Servers: []string{"10.20.0.53"}, Suffixes: []string{"corp.example"}, SearchList: []string{"corp.example"},
		Interfaces: []interfacecfg.InterfaceState{{Index: 8, Name: "Contoso VPN", VPN: true, Virtual: true, DNSServers: []netip.Addr{mustAddr("10.20.0.53")}, DNSSuffix: "corp.example"}},
		NRPT:       []model.NameResolutionPolicyRule{{Namespaces: []string{".corp.example"}, NameServers: []string{"10.20.0.53"}, Source: "fixture:nrpt", RuleID: "corp", VPNRequired: true}},
		NRPTError:  "policy read incomplete", HostsFileError: "hosts read denied", Error: "resolver state incomplete",
	}
	probe := model.ProbeResult{Name: "dns_configuration", Status: model.ProbeStatusError, Evidence: []model.Evidence{fixtureEvidence(t, "legacy-dns", model.EvidenceKindDNSConfiguration, "fixture:legacy", legacy)}}
	got := Build(target, []model.ProbeResult{probe})
	if len(got.NameResolution.Paths) < 2 || !contains(got.NameResolution.CandidateSuffixes, "corp.example") {
		t.Fatalf("legacy DNS shape not projected = %#v", got.NameResolution)
	}
	if len(got.NameResolution.Limitations) < 2 || got.NameResolution.Certainty != model.ObservationCertaintyInferred {
		t.Fatalf("legacy limitations/certainty = %#v", got.NameResolution)
	}
	if got.NameResolution.EffectivePath != nil {
		t.Fatalf("configured DNS was silently promoted to effective path = %#v", got.NameResolution.EffectivePath)
	}
}

func TestNormalizeObservationsDetachesNestedProvenance(t *testing.T) {
	endpoint := model.EndpointObservation{
		ResolvedCandidates: []model.EndpointCandidate{{Address: "192.0.2.1", EvidenceIDs: []string{"e1"}}},
		CandidateAttempts:  []model.EndpointAttempt{{Candidate: model.EndpointCandidate{Address: "192.0.2.1", EvidenceIDs: []string{"e2"}}}},
		Conflicts:          []model.ObservationConflict{{Field: "x", Values: []string{"a"}, EvidenceIDs: []string{"e3"}}},
	}
	observations := model.NormalizeObservations(model.Observations{Endpoint: endpoint})
	endpoint.ResolvedCandidates[0].EvidenceIDs[0] = "changed"
	endpoint.CandidateAttempts[0].Candidate.EvidenceIDs[0] = "changed"
	endpoint.Conflicts[0].EvidenceIDs[0] = "changed"
	if observations.Endpoint.ResolvedCandidates[0].EvidenceIDs[0] != "e1" || observations.Endpoint.CandidateAttempts[0].Candidate.EvidenceIDs[0] != "e2" || observations.Endpoint.Conflicts[0].EvidenceIDs[0] != "e3" {
		t.Fatalf("nested observation slices share input state = %#v", observations)
	}
}

func enterpriseFixtureProbe(t *testing.T, evidence ...model.Evidence) model.ProbeResult {
	t.Helper()
	return model.ProbeResult{Name: enterpriseprobe.Name, Status: model.ProbeStatusPassed, Evidence: evidence}
}

func enterpriseConfigEvidence(t *testing.T, id, source string, value proxyprobe.ConfigurationObservation) model.Evidence {
	t.Helper()
	kind := model.EvidenceKindWinHTTPProxy
	if source == "wininet" {
		kind = model.EvidenceKindWinINETProxy
	}
	return fixtureEvidence(t, id, kind, source, value)
}

func enterpriseConnectivityFixture(t *testing.T, id string, effective []enterpriseprobe.EffectiveProxy, paths []enterpriseprobe.PathObservation) model.Evidence {
	t.Helper()
	return fixtureEvidence(t, id, model.EvidenceKindProxyConnectivity, "windows-enterprise", enterpriseConnectivityEvidence{EffectiveProxy: effective, Paths: paths})
}

func enterpriseDirectConfig() proxyprobe.ConfigurationObservation {
	return proxyprobe.ConfigurationObservation{State: proxyprobe.StateDirect, Direct: true}
}

func enterpriseStaticConfig(endpoint string) proxyprobe.ConfigurationObservation {
	return proxyprobe.ConfigurationObservation{State: proxyprobe.StateStaticProxyConfigured, StaticProxyConfigured: true, ProxyEndpoints: []string{endpoint}}
}

func TestBuildEnterpriseDirectConfigurationDoesNotClaimRuntimeUse(t *testing.T) {
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConfigEvidence(t, "enterprise-winhttp", "winhttp", enterpriseDirectConfig()),
		enterpriseConfigEvidence(t, "enterprise-wininet", "wininet", enterpriseDirectConfig()),
	)})
	enterprise := got.EnterprisePolicy
	if enterprise.State != model.EnterpriseObservationStateObserved || enterprise.Certainty != model.ObservationCertaintyConfigured && enterprise.Certainty != model.ObservationCertaintyObserved {
		t.Fatalf("enterprise state = %#v", enterprise)
	}
	if enterprise.WinHTTP.Configuration.State != string(proxyprobe.StateDirect) || enterprise.WinHTTP.Configuration.Certainty != model.ObservationCertaintyConfigured {
		t.Fatalf("WinHTTP configuration = %#v", enterprise.WinHTTP.Configuration)
	}
	if enterprise.WinHTTP.Effective.Observed || enterprise.WinHTTP.PAC.ResolutionObserved || len(enterprise.Paths) != 0 {
		t.Fatalf("configuration was promoted to runtime use = %#v", enterprise.WinHTTP)
	}
	if enterprise.ProxyConfigurationDiverges || !enterprise.ProxyConfigurationKnown {
		t.Fatalf("direct source comparison = %#v", enterprise)
	}
}

func TestBuildEnterpriseProjectsWinHTTPRuntimeAndReachability(t *testing.T) {
	endpoint := "proxy.corp.example:8080"
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConfigEvidence(t, "enterprise-winhttp-config", "winhttp", enterpriseStaticConfig(endpoint)),
		enterpriseConnectivityFixture(t, "enterprise-connectivity", []enterpriseprobe.EffectiveProxy{{Source: "winhttp", Mode: enterpriseprobe.PathModeProxy, Endpoint: endpoint, ResolutionOK: true}}, []enterpriseprobe.PathObservation{{
			Name: enterpriseprobe.PathServiceWinHTTP, Source: "winhttp", Mode: enterpriseprobe.PathModeProxy, Endpoint: endpoint,
			RequestAttempted: true, TCPConnected: true, ConnectOutcome: enterpriseprobe.ConnectSucceeded, HTTPResponse: true, HTTPStatusCode: 204,
		}}),
	)})
	proxy := got.EnterprisePolicy.WinHTTP
	if !proxy.Effective.Observed || proxy.Effective.Mode != enterpriseprobe.PathModeProxy || proxy.Effective.Endpoint != endpoint || proxy.Effective.Certainty != model.ObservationCertaintyObserved {
		t.Fatalf("effective WinHTTP result = %#v", proxy.Effective)
	}
	if proxy.Effective.Decision != model.EnterpriseProxyDecisionStaticProxy || !proxy.Effective.ResolutionAttempted {
		t.Fatalf("effective WinHTTP decision = %#v", proxy.Effective)
	}
	if len(proxy.EndpointReachability) != 1 || proxy.EndpointReachability[0].Reachability != model.EnterpriseEndpointReachable || !proxy.EndpointReachability[0].TCPConnected {
		t.Fatalf("endpoint reachability = %#v", proxy.EndpointReachability)
	}
	if len(got.EnterprisePolicy.Paths) != 1 || got.EnterprisePolicy.Paths[0].Certainty != model.ObservationCertaintyObserved {
		t.Fatalf("path observation = %#v", got.EnterprisePolicy.Paths)
	}
}

func TestBuildEnterpriseProjectsDistinctEffectiveProxyDecisions(t *testing.T) {
	tests := []struct {
		name      string
		effective enterpriseprobe.EffectiveProxy
		want      string
	}{
		{name: "direct", effective: enterpriseprobe.EffectiveProxy{Source: "winhttp", Mode: enterpriseprobe.PathModeDirect, ResolutionOK: true}, want: model.EnterpriseProxyDecisionDirect},
		{name: "static proxy", effective: enterpriseprobe.EffectiveProxy{Source: "winhttp", Mode: enterpriseprobe.PathModeProxy, Endpoint: "proxy.corp.example:8080", ResolutionOK: true}, want: model.EnterpriseProxyDecisionStaticProxy},
		{name: "PAC-selected proxy", effective: enterpriseprobe.EffectiveProxy{Source: "winhttp", Mode: enterpriseprobe.PathModePAC, Endpoint: "pac.corp.example:8080", PACUsed: true, ResolutionOK: true}, want: model.EnterpriseProxyDecisionPACSelectedProxy},
		{name: "bypass", effective: enterpriseprobe.EffectiveProxy{Source: "winhttp", Mode: enterpriseprobe.PathModeDirect, BypassMatched: true, ResolutionOK: true}, want: model.EnterpriseProxyDecisionBypassMatch},
		{name: "PAC unavailable", effective: enterpriseprobe.EffectiveProxy{Source: "winhttp", Mode: enterpriseprobe.PathModeUnknown, PACUsed: true, ResolutionAttempted: true, ResolutionOK: false, Error: "PAC result unavailable"}, want: model.EnterpriseProxyDecisionPACResultUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
				enterpriseConnectivityFixture(t, "enterprise-effective", []enterpriseprobe.EffectiveProxy{test.effective}, nil),
			)})
			value := got.EnterprisePolicy.WinHTTP.Effective
			if value.Decision != test.want || !value.Observed {
				t.Fatalf("effective decision = %#v, want %q", value, test.want)
			}
			if test.name == "PAC unavailable" && (value.ResolutionOK || value.Endpoint != "") {
				t.Fatalf("PAC failure claimed a selected endpoint = %#v", value)
			}
		})
	}
}

func TestBuildEnterprisePreservesWinHTTPWinINETDivergence(t *testing.T) {
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConfigEvidence(t, "enterprise-http", "winhttp", enterpriseStaticConfig("proxy.service.example:8080")),
		enterpriseConfigEvidence(t, "enterprise-inet", "wininet", enterpriseStaticConfig("proxy.browser.example:8080")),
	)})
	if !got.EnterprisePolicy.ProxyConfigurationKnown || !got.EnterprisePolicy.ProxyConfigurationDiverges {
		t.Fatalf("source divergence = %#v", got.EnterprisePolicy)
	}
	if len(got.EnterprisePolicy.Conflicts) != 1 || len(got.EnterprisePolicy.Conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("divergence provenance = %#v", got.EnterprisePolicy.Conflicts)
	}
	if got.EnterprisePolicy.WinHTTP.Configuration.Certainty != model.ObservationCertaintyConfigured || got.EnterprisePolicy.WinINET.Configuration.Certainty != model.ObservationCertaintyConfigured {
		t.Fatalf("configuration certainty was lost = %#v", got.EnterprisePolicy)
	}
}

func TestBuildEnterprisePACConfigurationStaysUnknownUntilEffectiveResult(t *testing.T) {
	config := proxyprobe.ConfigurationObservation{State: proxyprobe.StatePACConfigured, PACConfigured: true, PACURL: "https://pac.corp.example/proxy.pac", AutoDetect: true}
	pac := enterprisePACEvidence{Configured: true, URL: config.PACURL, AutoDetect: true, Executed: false}
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConfigEvidence(t, "enterprise-pac-config", "wininet", config),
		fixtureEvidence(t, "enterprise-pac", model.EvidenceKindPAC, "wininet", pac),
	)})
	value := got.EnterprisePolicy.WinINET.PAC
	if !value.Configured || !value.AutoDetect || value.URL != config.PACURL || value.Certainty != model.ObservationCertaintyConfigured {
		t.Fatalf("PAC configuration = %#v", value)
	}
	if value.ResolutionObserved || value.Used || value.Mode != model.EnterpriseProxyModeUnknown || value.Endpoint != "" {
		t.Fatalf("PAC configuration claimed a selected result = %#v", value)
	}
}

func TestBuildEnterprisePACConfiguredButEffectiveResultUnavailable(t *testing.T) {
	config := proxyprobe.ConfigurationObservation{State: proxyprobe.StatePACConfigured, PACConfigured: true, PACURL: "https://pac.corp.example/proxy.pac"}
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConfigEvidence(t, "enterprise-pac-config", "wininet", config),
		enterpriseConnectivityFixture(t, "enterprise-pac-failure", []enterpriseprobe.EffectiveProxy{{
			Source: "wininet", Mode: enterpriseprobe.PathModeUnknown, PACUsed: true, ResolutionAttempted: true,
			ResolutionOK: false, Error: "PAC result unavailable",
		}}, nil),
	)})
	value := got.EnterprisePolicy.WinINET
	if value.Effective.Decision != model.EnterpriseProxyDecisionPACResultUnavailable || !value.Effective.Observed || value.Effective.ResolutionOK {
		t.Fatalf("PAC unavailable effective result = %#v", value.Effective)
	}
	if !value.PAC.Configured || !value.PAC.ResolutionObserved || value.PAC.ResolutionOK || value.PAC.Decision != model.EnterpriseProxyDecisionPACResultUnavailable {
		t.Fatalf("PAC unavailable configuration/result = %#v", value.PAC)
	}
}

func TestBuildEnterpriseDistinguishesReachableProxyFromCONNECT407(t *testing.T) {
	endpoint := "proxy.corp.example:8080"
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConfigEvidence(t, "enterprise-inet-config", "wininet", enterpriseStaticConfig(endpoint)),
		enterpriseConnectivityFixture(t, "enterprise-407", nil, []enterpriseprobe.PathObservation{{
			Name: enterpriseprobe.PathBrowserWinINET, Source: "wininet", Mode: enterpriseprobe.PathModeProxy, Endpoint: endpoint,
			TCPConnected: true, ConnectOutcome: enterpriseprobe.ConnectAuthRequired, ConnectStatusCode: 407, ProxyAuthenticationHint: true,
		}}),
	)})
	path := got.EnterprisePolicy.Paths[0]
	endpointObservation := got.EnterprisePolicy.WinINET.EndpointReachability[0]
	if path.ConnectOutcome != enterpriseprobe.ConnectAuthRequired || path.ConnectStatusCode != 407 || !path.ProxyAuthenticationHint {
		t.Fatalf("CONNECT authentication result = %#v", path)
	}
	if endpointObservation.Reachability != model.EnterpriseEndpointReachable || endpointObservation.ConnectOutcome != enterpriseprobe.ConnectAuthRequired {
		t.Fatalf("407 was confused with endpoint unreachability = %#v", endpointObservation)
	}
	if got.EnterprisePolicy.WinINET.Effective.Decision != model.EnterpriseProxyDecisionAuthenticationRequired {
		t.Fatalf("effective decision did not retain 407 = %#v", got.EnterprisePolicy.WinINET.Effective)
	}
}

func TestBuildEnterpriseProjectsEffectiveWinHTTPWinINETDivergence(t *testing.T) {
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConnectivityFixture(t, "enterprise-effective-divergence", []enterpriseprobe.EffectiveProxy{
			{Source: "winhttp", Mode: enterpriseprobe.PathModeDirect, ResolutionOK: true},
			{Source: "wininet", Mode: enterpriseprobe.PathModeProxy, Endpoint: "proxy.browser.example:8080", ResolutionOK: true},
		}, nil),
	)})
	if !got.EnterprisePolicy.EffectiveDecisionKnown || !got.EnterprisePolicy.EffectiveDecisionDiverges {
		t.Fatalf("effective source divergence = %#v", got.EnterprisePolicy)
	}
	if got.EnterprisePolicy.WinHTTP.Effective.Decision != model.EnterpriseProxyDecisionDirect || got.EnterprisePolicy.WinINET.Effective.Decision != model.EnterpriseProxyDecisionStaticProxy {
		t.Fatalf("source decisions collapsed = %#v", got.EnterprisePolicy)
	}
}

func TestBuildEnterpriseDirectFailureProxySuccessIsAnInference(t *testing.T) {
	endpoint := "proxy.corp.example:8080"
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t,
		enterpriseConnectivityFixture(t, "enterprise-paths", []enterpriseprobe.EffectiveProxy{{Source: "wininet", Mode: enterpriseprobe.PathModeProxy, Endpoint: endpoint, ResolutionOK: true}}, []enterpriseprobe.PathObservation{
			{Name: enterpriseprobe.PathApplicationDirect, Source: "direct", Mode: enterpriseprobe.PathModeDirect, RequestAttempted: true, FailureReason: model.FailureReasonTCPTimeout},
			{Name: enterpriseprobe.PathBrowserWinINET, Source: "wininet", Mode: enterpriseprobe.PathModeProxy, Endpoint: endpoint, RequestAttempted: true, TCPConnected: true, ConnectOutcome: enterpriseprobe.ConnectSucceeded, HTTPResponse: true, HTTPStatusCode: 200},
		}),
	)})
	comparison := got.EnterprisePolicy.DirectVsProxy
	if comparison.State != model.EnterprisePathComparisonDirectFailureProxyWorks || !comparison.PolicyPossible || comparison.Certainty != model.ObservationCertaintyInferred {
		t.Fatalf("path comparison = %#v", comparison)
	}
	if got.EnterprisePolicy.Firewall.BlockCausality != model.EnterpriseFirewallCausalityNotEstablished {
		t.Fatalf("path inference leaked into firewall causality = %#v", got.EnterprisePolicy.Firewall)
	}
}

func TestBuildEnterpriseFirewallAndVPNCorrelationRemainEvidenceBounded(t *testing.T) {
	enabled := true
	firewall := enterpriseprobe.FirewallObservation{Source: "windows-firewall-profile", Available: true, Profiles: []enterpriseprobe.FirewallProfile{{Name: "Domain", FirewallEnabled: &enabled, PolicyPresent: true}}}
	routing := enterpriseRoutingEvidence{
		Adapters: []enterpriseprobe.AdapterObservation{{Index: 12, Name: "Contoso VPN", Type: "vpn", Operational: true, VPN: true, Virtual: true}},
		Routes: []enterpriseprobe.RouteObservation{
			{Path: enterpriseprobe.PathApplicationDirect, InterfaceIndex: 4, NextHop: "192.0.2.1", Available: true},
			{Path: enterpriseprobe.PathBrowserWinINET, InterfaceIndex: 12, NextHop: "10.0.0.1", Available: true},
		},
	}
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{
		enterpriseFixtureProbe(t, fixtureEvidence(t, "enterprise-firewall", model.EvidenceKindFirewallProfile, "windows-firewall-profile", firewall), fixtureEvidence(t, "enterprise-routing", model.EvidenceKindAdapterRouting, "windows-ip-helper", routing)),
		fixtureRouteProbe(t, "route-canonical", "192.0.2.10", "0.0.0.0/0", "192.0.2.1", "Ethernet", 4, 10, false, false),
	})
	value := got.EnterprisePolicy
	if len(value.Firewall.Profiles) != 1 || value.Firewall.Profiles[0].EffectiveState != "enabled" || value.Firewall.Profiles[0].BlockCausality != model.EnterpriseFirewallCausalityNotEstablished {
		t.Fatalf("firewall state = %#v", value.Firewall)
	}
	if value.Network.RouteDifferenceKnown != true || !value.Network.RouteDifference || len(value.Network.AdapterParticipation) != 1 || !value.Network.VPNAdapterPresent {
		t.Fatalf("enterprise route/VPN correlation = %#v", value.Network)
	}
	if !value.Network.NetworkContextReferenced || !contains(value.Network.NetworkContextEvidenceIDs, "route-canonical") {
		t.Fatalf("network context reference = %#v", value.Network)
	}
	if value.Network.SelectedRouteUsesVPN {
		t.Fatalf("enterprise VPN presence was promoted to selected route = %#v", value.Network)
	}
}

func TestBuildEnterpriseTLSPolicySuspicionIsConservative(t *testing.T) {
	tls := enterpriseTLSEvidence{
		Comparison: enterpriseprobe.TLSComparison{
			DirectCertificateSHA256: strings.Repeat("a", 64), ProxyCertificateSHA256: strings.Repeat("b", 64), CertificatesDiffer: true,
			BothTrusted: true, BothHostnameVerified: true, PossibleInterception: true,
			InterceptionBasis: "trusted hostname-valid peer certificates differ between direct and proxy paths",
		},
		TrustStore: enterpriseprobe.TrustStoreObservation{Source: "windows-root-store", Available: true, RootCount: 42},
	}
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t, fixtureEvidence(t, "enterprise-tls", model.EvidenceKindTLSTrust, "crypto/x509", tls))})
	value := got.EnterprisePolicy.TLS
	if !value.PossibleInterception || value.InterceptionSuspicion != model.EnterpriseInterceptionSuspicionPossible || value.Certainty != model.ObservationCertaintyInferred {
		t.Fatalf("TLS suspicion = %#v", value)
	}
	if value.InterceptionBasis == "" || !value.CertificatesDifferKnown || !value.BothTrustedKnown || !value.BothHostnameKnown {
		t.Fatalf("TLS provenance/known flags = %#v", value)
	}

	tls.Comparison.PossibleInterception = false
	tls.Comparison.BothTrusted = false
	got = Build(mustTarget(t, "service.example:443"), []model.ProbeResult{enterpriseFixtureProbe(t, fixtureEvidence(t, "enterprise-tls-untrusted", model.EvidenceKindTLSTrust, "crypto/x509", tls))})
	if got.EnterprisePolicy.TLS.PossibleInterception || got.EnterprisePolicy.TLS.InterceptionSuspicion != model.EnterpriseInterceptionSuspicionNotEstablished {
		t.Fatalf("certificate difference overclaimed interception = %#v", got.EnterprisePolicy.TLS)
	}
}

func TestBuildEnterpriseUnsupportedStatePreserved(t *testing.T) {
	probe := model.ProbeResult{Name: enterpriseprobe.Name, Status: model.ProbeStatusSkipped, Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonUnsupported}, Evidence: []model.Evidence{fixtureEvidence(t, "enterprise-unsupported", model.EvidenceKindProxyConfiguration, "windows-enterprise", map[string]string{"state": "unsupported_platform"})}}
	got := Build(mustTarget(t, "service.example:443"), []model.ProbeResult{probe})
	value := got.EnterprisePolicy
	if value.State != model.EnterpriseObservationStateUnsupported || !value.Unsupported || value.Certainty != model.ObservationCertaintyUnsupported {
		t.Fatalf("unsupported enterprise state = %#v", value)
	}
	if len(value.Limitations) == 0 || !contains(value.EvidenceIDs, "enterprise-unsupported") {
		t.Fatalf("unsupported provenance = %#v", value)
	}
}

func TestBuildEnterpriseProjectionIsDeterministicAndLeavesRawEvidenceUntouched(t *testing.T) {
	config := enterpriseConfigEvidence(t, "enterprise-winhttp", "winhttp", enterpriseStaticConfig("proxy.corp.example:8080"))
	connectivity := enterpriseConnectivityFixture(t, "enterprise-connectivity", []enterpriseprobe.EffectiveProxy{{Source: "winhttp", Mode: enterpriseprobe.PathModeProxy, Endpoint: "proxy.corp.example:8080", ResolutionOK: true}}, []enterpriseprobe.PathObservation{{Name: enterpriseprobe.PathServiceWinHTTP, Source: "winhttp", Mode: enterpriseprobe.PathModeProxy, Endpoint: "proxy.corp.example:8080", TCPConnected: true, ConnectOutcome: enterpriseprobe.ConnectSucceeded, HTTPResponse: true, HTTPStatusCode: 200}})
	rawConfig := append([]byte(nil), config.Raw...)
	probe := enterpriseFixtureProbe(t, connectivity, config)
	target := mustTarget(t, "service.example:443")
	left := Build(target, []model.ProbeResult{probe})
	right := Build(target, []model.ProbeResult{enterpriseFixtureProbe(t, config, connectivity)})
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("enterprise projection depends on evidence order\nleft=%#v\nright=%#v", left.EnterprisePolicy, right.EnterprisePolicy)
	}
	if !bytes.Equal(config.Raw, rawConfig) {
		t.Fatal("enterprise projection changed raw evidence")
	}
	if !contains(left.EnterprisePolicy.WinHTTP.Configuration.EvidenceIDs, "enterprise-winhttp") || left.EnterprisePolicy.WinHTTP.Configuration.Certainty != model.ObservationCertaintyConfigured {
		t.Fatalf("configuration provenance/certainty = %#v", left.EnterprisePolicy.WinHTTP.Configuration)
	}
}
func TestBuildPathAndPacketFlowObservationsRetainVisibilityAndDivergence(t *testing.T) {
	target := mustTarget(t, "203.0.113.45:443")
	path := model.PathObservation{
		Status:                  model.PathObservationStatusObserved,
		Protocol:                model.PathProtocolTCP,
		Destination:             "203.0.113.45",
		DestinationPort:         443,
		PortAware:               true,
		MaxTTL:                  5,
		AttemptsPerTTL:          2,
		DestinationReached:      true,
		DestinationTCPConnected: true,
		Hops: []model.PathHop{
			{TTL: 1, State: model.PathHopStateObserved, Attempts: 2, Responders: []model.PathResponder{{Address: "192.0.2.1"}, {Address: "192.0.2.2"}}},
			{TTL: 2, State: model.PathHopStateUnobservable, Attempts: 2},
			{TTL: 3, State: model.PathHopStateUnobservable, Attempts: 2},
			{TTL: 5, State: model.PathHopStateObserved, Attempts: 2, Responders: []model.PathResponder{{Address: "203.0.113.45", DestinationReached: true}}},
		},
		Segments: []model.PathSegment{
			{Kind: model.PathSegmentObservedResponder, FromTTL: 1, ToTTL: 1, Responders: []model.PathResponder{{Address: "192.0.2.1"}, {Address: "192.0.2.2"}}},
			{Kind: model.PathSegmentUnobservable, FromTTL: 2, ToTTL: 3},
			{Kind: model.PathSegmentObservedResponder, FromTTL: 5, ToTTL: 5, Responders: []model.PathResponder{{Address: "203.0.113.45", DestinationReached: true}}},
		},
	}
	conflictingPath := path
	conflictingPath.DestinationReached = false
	conflictingPath.DestinationTCPConnected = false
	conflictingPath.Hops = append([]model.PathHop(nil), path.Hops...)
	conflictingPath.Hops[3].Responders = []model.PathResponder{{Address: "203.0.113.45"}}
	flow := model.PacketFlowEvidence{
		SessionID:         "session-1",
		ProbeID:           "tcp-1",
		CorrelationID:     "session-1/tcp-1",
		Target:            target,
		CaptureStatus:     model.PacketCaptureStatusAvailable,
		WindowCompletedAt: timeForTest(2),
		ProbeEmission:     model.PacketEmissionObserved,
		Outcome:           model.PacketFlowOutcomeNoMatchingResponse,
		Certainty:         model.EvidenceCertaintyUnobservableSegment,
		Observations: []model.PacketObservation{{
			ID: "syn", SessionID: "session-1", ProbeID: "tcp-1", CorrelationID: "session-1/tcp-1",
			Kind: model.PacketObservationOutboundTCPSYN, Protocol: model.PacketProtocolTCP, Direction: model.PacketDirectionOutbound,
			SourceAddress: "192.0.2.10", SourcePort: 50000, DestinationAddress: "203.0.113.45", DestinationPort: 443,
		}},
	}
	pathRaw := mustRaw(t, path)
	conflictingPathRaw := mustRaw(t, conflictingPath)
	flowRaw := mustRaw(t, flow)
	first := model.ProbeResult{Name: "path-b", ProbeID: "path-2", Evidence: []model.Evidence{{ID: "path-b", Kind: model.EvidenceKindPathObservation, Source: "path:second", Raw: conflictingPathRaw}}}
	second := model.ProbeResult{Name: "path-a", ProbeID: "path-1", Evidence: []model.Evidence{{ID: "path-a", Kind: model.EvidenceKindPathObservation, Source: "path:first", Raw: pathRaw}}}
	third := model.ProbeResult{Name: "tcp", ProbeID: "tcp-1", Evidence: []model.Evidence{{ID: "flow-1", Kind: model.EvidenceKindPacketFlow, Source: "capture:fixture", Raw: flowRaw}}}

	left := Build(target, []model.ProbeResult{first, third, second})
	right := Build(target, []model.ProbeResult{second, first, third})
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("path/flow projection depends on input order\nleft=%#v\nright=%#v", left, right)
	}
	if !bytes.Equal(first.Evidence[0].Raw, conflictingPathRaw) || !bytes.Equal(second.Evidence[0].Raw, pathRaw) || !bytes.Equal(third.Evidence[0].Raw, flowRaw) {
		t.Fatal("path or packet-flow raw evidence was mutated")
	}
	if len(left.Paths) != 2 || len(left.PacketFlows) != 1 || len(left.PathCorrelations) != 1 {
		t.Fatalf("path/flow collections = paths:%d flows:%d correlations:%d", len(left.Paths), len(left.PacketFlows), len(left.PathCorrelations))
	}
	var confirmedPath model.PathObservation
	for _, observation := range left.Paths {
		if observation.DestinationReached {
			confirmedPath = observation
			break
		}
	}
	if len(confirmedPath.Hops) == 0 || len(confirmedPath.Hops[0].Responders) != 2 || confirmedPath.Hops[1].State != model.PathHopStateUnobservable {
		t.Fatalf("visibility or multiple responders were collapsed: %#v", left.Paths)
	}
	if !confirmedPath.DestinationReached || !confirmedPath.DestinationTCPConnected {
		t.Fatalf("destination confirmation was lost behind unobservable TTLs: %#v", confirmedPath)
	}
	if len(left.PathProvenance) != 2 || left.PathProvenance[0].EvidenceIDs[0] != "path-a" || left.PacketFlowProvenance[0].EvidenceIDs[0] != "flow-1" {
		t.Fatalf("aligned provenance = paths:%#v flows:%#v", left.PathProvenance, left.PacketFlowProvenance)
	}
	if !hasObservationConflictField(left.Conflicts, "destination_reached") || !hasObservationDivergence(left.Divergences, "destination_confirmation") {
		t.Fatalf("conflict/divergence semantics missing: conflicts=%#v divergences=%#v", left.Conflicts, left.Divergences)
	}
	if !contains(left.Conflicts[0].EvidenceIDs, "path-a") || !contains(left.Conflicts[0].EvidenceIDs, "path-b") {
		t.Fatalf("conflict provenance lost: %#v", left.Conflicts)
	}
}

func TestBuildPacketFlowConflictRetainsBothOutcomesDeterministically(t *testing.T) {
	target := mustTarget(t, "198.51.100.8:443")
	base := model.PacketFlowEvidence{
		SessionID: "session-2", ProbeID: "tcp", CorrelationID: "session-2/tcp", Target: target,
		CaptureStatus: model.PacketCaptureStatusAvailable, ProbeEmission: model.PacketEmissionObserved,
		Observations: []model.PacketObservation{{Kind: model.PacketObservationOutboundTCPSYN, Protocol: model.PacketProtocolTCP, Direction: model.PacketDirectionOutbound, DestinationAddress: "198.51.100.8", DestinationPort: 443}},
	}
	accepted := base
	accepted.Outcome = model.PacketFlowOutcomeTCPSYNACK
	accepted.Observations = append(append([]model.PacketObservation(nil), base.Observations...), model.PacketObservation{Kind: model.PacketObservationInboundTCPSYNACK, Protocol: model.PacketProtocolTCP, Direction: model.PacketDirectionInbound, SourceAddress: "198.51.100.8", SourcePort: 443})
	noResponse := base
	noResponse.Outcome = model.PacketFlowOutcomeNoMatchingResponse
	first := model.ProbeResult{Name: "tcp-second", Evidence: []model.Evidence{{ID: "flow-b", Kind: model.EvidenceKindPacketFlow, Source: "capture:b", Raw: mustRaw(t, noResponse)}}}
	second := model.ProbeResult{Name: "tcp-first", Evidence: []model.Evidence{{ID: "flow-a", Kind: model.EvidenceKindPacketFlow, Source: "capture:a", Raw: mustRaw(t, accepted)}}}
	got := Build(target, []model.ProbeResult{first, second})
	if len(got.PacketFlows) != 2 || len(got.PacketFlowProvenance) != 2 {
		t.Fatalf("packet flow records = %#v / %#v", got.PacketFlows, got.PacketFlowProvenance)
	}
	if got.PacketFlows[0].Outcome != model.PacketFlowOutcomeNoMatchingResponse || got.PacketFlows[1].Outcome != model.PacketFlowOutcomeTCPSYNACK {
		t.Fatalf("packet flow ordering = %#v", got.PacketFlows)
	}
	if !hasObservationConflictField(got.Conflicts, "outcome") || !contains(got.Conflicts[0].EvidenceIDs, "flow-a") || !contains(got.Conflicts[0].EvidenceIDs, "flow-b") {
		t.Fatalf("packet-flow conflict provenance = %#v", got.Conflicts)
	}
}

func hasObservationConflictField(values []model.ObservationConflict, suffix string) bool {
	for _, value := range values {
		if strings.HasSuffix(value.Field, suffix) {
			return true
		}
	}
	return false
}

func hasObservationDivergence(values []model.ObservationDivergence, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value.Field, prefix) {
			return true
		}
	}
	return false
}

func timeForTest(second int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, second, 0, time.UTC)
}
