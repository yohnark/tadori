package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

type fakeResolver struct {
	addresses map[string][]netip.Addr
	errors    map[string]error
	calls     []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	f.calls = append(f.calls, network)
	return f.addresses[network], f.errors[network]
}

func target() model.Target {
	parsed, err := model.ParseTarget(model.TargetIntent{Input: "https://service.example.test/path"})
	if err != nil {
		panic(err)
	}
	return parsed
}

func deterministicClock() func() time.Time {
	current := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	return func() time.Time { return current }
}

func TestProbeSuccessPreservesConfigurationAndAAndAAAA(t *testing.T) {
	resolver := &fakeResolver{addresses: map[string][]netip.Addr{
		"ip4": {netip.MustParseAddr("192.0.2.10")},
		"ip6": {netip.MustParseAddr("2001:db8::10")},
	}}
	p := New(
		WithResolver(resolver),
		WithResolverConfig(StaticResolverConfig{"192.0.2.53", "2001:db8::53"}),
		WithNow(deterministicClock()),
	)

	result := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %q, want passed", result.Status)
	}
	if result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("reason = %q, want none", result.Interpretation.FailureReason)
	}
	if len(result.Evidence) != 2 {
		t.Fatalf("evidence count = %d, want configuration and resolution", len(result.Evidence))
	}

	var configuration struct {
		Configured bool     `json:"configured"`
		Resolvers  []string `json:"resolvers"`
	}
	if err := json.Unmarshal(result.Evidence[0].Raw, &configuration); err != nil {
		t.Fatalf("configuration evidence is not JSON: %v", err)
	}
	if !configuration.Configured || len(configuration.Resolvers) != 2 || configuration.Resolvers[0] != "192.0.2.53" {
		t.Fatalf("configuration evidence = %#v", configuration)
	}

	var resolution resolutionEvidence
	if err := json.Unmarshal(result.Evidence[1].Raw, &resolution); err != nil {
		t.Fatalf("resolution evidence is not JSON: %v", err)
	}
	if len(resolution.A) != 1 || resolution.A[0] != "192.0.2.10" || len(resolution.AAAA) != 1 || resolution.AAAA[0] != "2001:db8::10" {
		t.Fatalf("resolution evidence = %#v", resolution)
	}
	if len(resolver.calls) != 2 || resolver.calls[0] != "ip4" || resolver.calls[1] != "ip6" {
		t.Fatalf("lookup calls = %#v, want ip4 then ip6", resolver.calls)
	}
}

func TestProbeNormalizesMappedResolverAddresses(t *testing.T) {
	resolver := &fakeResolver{addresses: map[string][]netip.Addr{
		"ip4": {netip.MustParseAddr("::ffff:192.0.2.10")},
		"ip6": {netip.MustParseAddr("2001:db8::10")},
	}}
	p := New(
		WithResolver(resolver),
		WithResolverConfig(StaticResolverConfig{"::ffff:192.0.2.53"}),
	)

	result := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %q, want passed", result.Status)
	}
	var resolution DNSResolutionEvidence
	if err := json.Unmarshal(result.Evidence[1].Raw, &resolution); err != nil {
		t.Fatalf("decode resolution evidence: %v", err)
	}
	if len(resolution.A) != 1 || resolution.A[0] != "192.0.2.10" || len(resolution.AAAA) != 1 || resolution.AAAA[0] != "2001:db8::10" {
		t.Fatalf("resolution evidence = %#v", resolution)
	}
	var configuration DNSConfigurationEvidence
	if err := json.Unmarshal(result.Evidence[0].Raw, &configuration); err != nil {
		t.Fatalf("decode configuration evidence: %v", err)
	}
	if len(configuration.Resolvers) != 1 || configuration.Resolvers[0] != "192.0.2.53" {
		t.Fatalf("configuration evidence = %#v", configuration)
	}
}

func TestProbeNXDOMAINIsDistinctFromTimeout(t *testing.T) {
	nxdomain := &net.DNSError{Err: "no such host", Name: "missing.example.test", IsNotFound: true}
	resolver := &fakeResolver{errors: map[string]error{"ip4": nxdomain, "ip6": nxdomain}}
	p := New(
		WithResolver(resolver),
		WithResolverConfig(StaticResolverConfig{"192.0.2.53"}),
	)
	nx := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if nx.Interpretation.FailureReason != model.FailureReasonDNSNXDomain || nx.Status != model.ProbeStatusFailed {
		t.Fatalf("NXDOMAIN result = status %q reason %q", nx.Status, nx.Interpretation.FailureReason)
	}

	timeout := &net.DNSError{Err: "i/o timeout", Name: "service.example.test", IsTimeout: true}
	resolver.errors = map[string]error{"ip4": timeout, "ip6": timeout}
	result := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if result.Interpretation.FailureReason != model.FailureReasonDNSTimeout {
		t.Fatalf("timeout reason = %q, want %q", result.Interpretation.FailureReason, model.FailureReasonDNSTimeout)
	}
}

func TestProbeNoAnswerIsDistinctFromNXDOMAIN(t *testing.T) {
	noAnswer := &net.DNSError{Err: "no answer", Name: "service.example.test", IsNotFound: true}
	resolver := &fakeResolver{errors: map[string]error{"ip4": noAnswer, "ip6": noAnswer}}
	p := New(
		WithResolver(resolver),
		WithResolverConfig(StaticResolverConfig{"192.0.2.53"}),
	)
	result := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if result.Interpretation.FailureReason != model.FailureReasonDNSNoAnswer {
		t.Fatalf("no-answer reason = %q, want %q", result.Interpretation.FailureReason, model.FailureReasonDNSNoAnswer)
	}
}

func TestProbeResolverFailureAndNoConfiguredResolver(t *testing.T) {
	resolverErr := errors.New("dial udp 192.0.2.53:53: network is unreachable")
	resolver := &fakeResolver{errors: map[string]error{"ip4": resolverErr, "ip6": resolverErr}}
	p := New(WithResolver(resolver), WithResolverConfig(StaticResolverConfig{"192.0.2.53"}))
	result := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if result.Interpretation.FailureReason != model.FailureReasonDNSResolverFailure {
		t.Fatalf("resolver failure reason = %q", result.Interpretation.FailureReason)
	}
	if result.Status != model.ProbeStatusFailed {
		t.Fatalf("resolver failure status = %q, want failed", result.Status)
	}

	noConfig := New(
		WithResolver(resolver),
		WithResolverConfig(StaticResolverConfig{}),
	)
	result = noConfig.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if result.Interpretation.FailureReason != model.FailureReasonDNSResolverFailure || result.Status != model.ProbeStatusError {
		t.Fatalf("no-config result = status %q reason %q", result.Status, result.Interpretation.FailureReason)
	}
	if !evidenceContains(result.Evidence, "no_configured_resolver") {
		t.Fatalf("no-config result did not preserve no_configured_resolver evidence")
	}
}

func TestProbeMalformedTargetDoesNotCallResolver(t *testing.T) {
	resolver := &fakeResolver{}
	p := New(WithResolver(resolver), WithResolverConfig(StaticResolverConfig{"192.0.2.53"}))
	result := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{RequestedIdentity: "bad..name"}})
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != model.FailureReasonProbeExecution {
		t.Fatalf("malformed result = status %q reason %q", result.Status, result.Interpretation.FailureReason)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %#v, want none", resolver.calls)
	}
	if !evidenceContains(result.Evidence, "malformed_target") {
		t.Fatalf("malformed result did not preserve malformed_target evidence")
	}
}

func TestLiteralIPUsesCanonicalAddressWithoutResolver(t *testing.T) {
	resolver := &fakeResolver{}
	target, err := model.ParseTarget(model.TargetIntent{Input: "10.0.10.25"})
	if err != nil {
		t.Fatal(err)
	}
	result := New(WithResolver(resolver), WithResolverConfig(StaticResolverConfig{"192.0.2.53"})).Run(context.Background(), probe.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("literal result = %#v", result)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("literal target invoked resolver: %#v", resolver.calls)
	}
	if !evidenceContains(result.Evidence, "10.0.10.25") {
		t.Fatalf("literal resolution evidence missing address: %#v", result.Evidence)
	}
	if result.NameResolution == nil || result.NameResolution.EffectivePath == nil || result.NameResolution.EffectivePath.Mechanism != model.NameResolutionMechanismLiteralIP || result.NameResolution.SelectedAddress != "10.0.10.25" {
		t.Fatalf("literal name-resolution observation = %#v", result.NameResolution)
	}
}

func TestNameResolutionFixtures(t *testing.T) {
	privateAnswer := netip.MustParseAddr("10.30.14.22")
	publicAnswer := netip.MustParseAddr("93.184.216.34")
	vpnResolver := netip.MustParseAddr("10.20.0.53")
	publicResolver := netip.MustParseAddr("192.0.2.53")

	publicInterface := ResolutionInterface{
		Index:      7,
		Name:       "Wi-Fi",
		Up:         true,
		DNSServers: []string{publicResolver.String()},
		DNSSuffix:  "example.test",
	}
	vpnInterface := ResolutionInterface{
		Index:          19,
		Name:           "Contoso VPN",
		Up:             true,
		VirtualAdapter: true,
		VPN:            true,
		DNSServers:     []string{vpnResolver.String()},
		DNSSuffix:      "corp.example",
		DNSSearchList:  []string{"corp.example"},
	}

	tests := []struct {
		name             string
		host             string
		resolver         *fakeResolver
		environment      ResolutionEnvironment
		configured       []string
		wantStatus       model.ProbeStatus
		wantReason       model.FailureReason
		wantA            []string
		wantAAAA         []string
		wantSelected     string
		wantFamily       string
		wantPathResolver string
		wantPathState    model.NameResolutionPathState
		wantVPNPolicy    bool
		wantLimitations  bool
	}{
		{
			name:             "normal public DNS",
			host:             "www.example.test",
			resolver:         fixtureResolver(map[string][]netip.Addr{"ip4": {publicAnswer}}, nil),
			environment:      ResolutionEnvironment{Interfaces: []ResolutionInterface{publicInterface}, Source: "fixture:adapters"},
			configured:       []string{publicResolver.String()},
			wantStatus:       model.ProbeStatusPassed,
			wantReason:       model.FailureReasonNone,
			wantA:            []string{publicAnswer.String()},
			wantSelected:     publicAnswer.String(),
			wantFamily:       "A",
			wantPathResolver: publicResolver.String(),
			wantPathState:    model.NameResolutionPathConfiguredCandidate,
		},
		{
			name:             "split DNS with private corporate answer",
			host:             "fileserver.corp.example",
			resolver:         fixtureResolver(map[string][]netip.Addr{"ip4": {privateAnswer}}, nil),
			environment:      ResolutionEnvironment{Interfaces: []ResolutionInterface{publicInterface, vpnInterface}, CandidateSuffixes: []string{"public.example"}, Source: "fixture:split-dns"},
			configured:       []string{publicResolver.String(), vpnResolver.String()},
			wantStatus:       model.ProbeStatusPassed,
			wantReason:       model.FailureReasonNone,
			wantA:            []string{privateAnswer.String()},
			wantSelected:     privateAnswer.String(),
			wantFamily:       "A",
			wantPathResolver: vpnResolver.String(),
			wantPathState:    model.NameResolutionPathConfiguredCandidate,
		},
		{
			name:     "VPN namespace routing and NRPT match",
			host:     "fileserver",
			resolver: fixtureResolver(map[string][]netip.Addr{"ip4": {privateAnswer}}, nil),
			environment: ResolutionEnvironment{
				Interfaces:        []ResolutionInterface{publicInterface, vpnInterface},
				CandidateSuffixes: []string{"corp.example"},
				NRPT:              []model.NameResolutionPolicyRule{{Namespaces: []string{".corp.example"}, NameServers: []string{vpnResolver.String()}, Source: "fixture:nrpt", RuleID: "corp", VPNRequired: true}},
				Source:            "fixture:vpn-nrpt",
			},
			configured:       []string{publicResolver.String(), vpnResolver.String()},
			wantStatus:       model.ProbeStatusPassed,
			wantReason:       model.FailureReasonNone,
			wantA:            []string{privateAnswer.String()},
			wantSelected:     privateAnswer.String(),
			wantFamily:       "A",
			wantPathResolver: vpnResolver.String(),
			wantPathState:    model.NameResolutionPathPolicyCandidate,
			wantVPNPolicy:    true,
		},
		{
			name:             "multiple configured resolvers remain candidates",
			host:             "public.example.test",
			resolver:         fixtureResolver(map[string][]netip.Addr{"ip4": {publicAnswer}}, nil),
			environment:      ResolutionEnvironment{Interfaces: []ResolutionInterface{{Index: 3, Name: "Ethernet", Up: true, DNSServers: []string{"192.0.2.53", "192.0.2.54"}}}, Source: "fixture:multiple-resolvers"},
			configured:       []string{"192.0.2.53", "192.0.2.54"},
			wantStatus:       model.ProbeStatusPassed,
			wantReason:       model.FailureReasonNone,
			wantA:            []string{publicAnswer.String()},
			wantSelected:     publicAnswer.String(),
			wantFamily:       "A",
			wantPathResolver: "192.0.2.53",
			wantPathState:    model.NameResolutionPathConfiguredCandidate,
		},
		{
			name:             "A and AAAA diverge",
			host:             "dual.example.test",
			resolver:         fixtureResolver(map[string][]netip.Addr{"ip4": {privateAnswer}}, map[string]error{"ip6": &net.DNSError{Err: "no answer", IsNotFound: true}}),
			environment:      ResolutionEnvironment{Interfaces: []ResolutionInterface{vpnInterface}, Source: "fixture:dual-stack"},
			configured:       []string{vpnResolver.String()},
			wantStatus:       model.ProbeStatusPassed,
			wantReason:       model.FailureReasonNone,
			wantA:            []string{privateAnswer.String()},
			wantSelected:     privateAnswer.String(),
			wantFamily:       "A",
			wantPathResolver: vpnResolver.String(),
			wantPathState:    model.NameResolutionPathConfiguredCandidate,
		},
		{
			name:             "failed effective resolution",
			host:             "offline.corp.example",
			resolver:         fixtureResolver(nil, map[string]error{"ip4": errors.New("resolver unavailable"), "ip6": errors.New("resolver unavailable")}),
			environment:      ResolutionEnvironment{Interfaces: []ResolutionInterface{vpnInterface}, Source: "fixture:unavailable", ResolverError: "effective path unavailable"},
			configured:       []string{vpnResolver.String()},
			wantStatus:       model.ProbeStatusFailed,
			wantReason:       model.FailureReasonDNSResolverFailure,
			wantPathResolver: vpnResolver.String(),
			wantPathState:    model.NameResolutionPathConfiguredCandidate,
			wantLimitations:  true,
		},
		{
			name:             "unknown provenance",
			host:             "unknown.example.test",
			resolver:         fixtureResolver(map[string][]netip.Addr{"ip4": {publicAnswer}}, nil),
			environment:      ResolutionEnvironment{Interfaces: []ResolutionInterface{{Index: 4, Name: "Ethernet", Up: true, DNSServers: []string{"192.0.2.55"}}}, Source: "fixture:unknown-provenance"},
			configured:       []string{"192.0.2.55"},
			wantStatus:       model.ProbeStatusPassed,
			wantReason:       model.FailureReasonNone,
			wantA:            []string{publicAnswer.String()},
			wantSelected:     publicAnswer.String(),
			wantFamily:       "A",
			wantPathResolver: "192.0.2.55",
			wantPathState:    model.NameResolutionPathConfiguredCandidate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := New(
				WithResolver(test.resolver),
				WithResolverConfig(StaticResolverConfig(test.configured)),
				WithEnvironmentProvider(EnvironmentProviderFunc(func(context.Context) (ResolutionEnvironment, error) {
					return test.environment, nil
				})),
				WithNow(deterministicClock()),
			).Run(context.Background(), probe.ExecutionContext{Target: namedTarget(test.host)})
			if result.Status != test.wantStatus || result.Interpretation.FailureReason != test.wantReason {
				t.Fatalf("status/reason = %q/%q, want %q/%q", result.Status, result.Interpretation.FailureReason, test.wantStatus, test.wantReason)
			}
			if result.NameResolution == nil {
				t.Fatal("missing normalized name-resolution observation")
			}
			observation := result.NameResolution
			if strings.Join(observation.A, ",") != strings.Join(test.wantA, ",") || observation.SelectedAddress != test.wantSelected || observation.SelectedFamily != test.wantFamily {
				t.Fatalf("answers/selection = A=%v AAAA=%v selected=%q family=%q", observation.A, observation.AAAA, observation.SelectedAddress, observation.SelectedFamily)
			}
			if test.wantLimitations && len(observation.Limitations) == 0 {
				t.Fatalf("limitations = %#v, want evidence of unavailable effective state", observation.Limitations)
			}
			path := findResolutionPath(observation.Paths, test.wantPathResolver, test.wantPathState)
			if path == nil {
				t.Fatalf("paths = %#v; wanted %s/%s", observation.Paths, test.wantPathState, test.wantPathResolver)
			}
			if test.wantVPNPolicy && (!path.VPN || path.Namespace != "corp.example" || path.PolicyRule != "corp") {
				t.Fatalf("NRPT path = %#v", *path)
			}
			if observation.EffectivePath == nil {
				t.Fatal("missing effective path")
			}
			if test.name == "unknown provenance" && (observation.EffectivePath.Resolver != "" || observation.EffectivePath.Interface != "" || !strings.Contains(observation.EffectivePath.Provenance, "unavailable")) {
				t.Fatalf("effective path overclaimed provenance: %#v", *observation.EffectivePath)
			}
		})
	}
}

func TestObservableEffectivePathCanNameResolverAndInterface(t *testing.T) {
	resolver := &effectiveFixtureResolver{
		fakeResolver: fixtureResolver(map[string][]netip.Addr{"ip4": {netip.MustParseAddr("10.30.14.22")}}, nil),
		path: model.NameResolutionPath{
			Mechanism:  model.NameResolutionMechanismDNS,
			Resolver:   "10.20.0.53",
			Interface:  "Contoso VPN",
			VPN:        true,
			Certainty:  model.NameResolutionCertaintyObserved,
			Provenance: "fixture exposes effective resolver selection",
		},
	}
	result := New(
		WithResolver(resolver),
		WithResolverConfig(StaticResolverConfig{"192.0.2.53", "10.20.0.53"}),
		WithEnvironmentProvider(EnvironmentProviderFunc(func(context.Context) (ResolutionEnvironment, error) {
			return ResolutionEnvironment{Interfaces: []ResolutionInterface{{Index: 19, Name: "Contoso VPN", Up: true, VPN: true, DNSServers: []string{"10.20.0.53"}}}}, nil
		})),
	).Run(context.Background(), probe.ExecutionContext{Target: namedTarget("fileserver.corp.example")})
	if result.NameResolution == nil || result.NameResolution.EffectivePath == nil {
		t.Fatalf("observation = %#v, want effective path", result.NameResolution)
	}
	effective := result.NameResolution.EffectivePath
	if effective.Resolver != "10.20.0.53" || effective.Interface != "Contoso VPN" || effective.Certainty != model.NameResolutionCertaintyObserved {
		t.Fatalf("effective path = %#v", *effective)
	}
}

func TestNameResolutionIncludesMatchingHostsFileCandidate(t *testing.T) {
	answer := netip.MustParseAddr("10.30.14.22")
	result := New(
		WithResolver(fixtureResolver(map[string][]netip.Addr{"ip4": {answer}}, nil)),
		WithResolverConfig(StaticResolverConfig{"192.0.2.53"}),
		WithEnvironmentProvider(EnvironmentProviderFunc(func(context.Context) (ResolutionEnvironment, error) {
			return ResolutionEnvironment{
				HostsFileEntries: []model.NameResolutionHostEntry{{Name: "fileserver.corp.example", Addresses: []string{answer.String()}, Source: "fixture:hosts"}},
			}, nil
		})),
	).Run(context.Background(), probe.ExecutionContext{Target: namedTarget("fileserver.corp.example")})
	if result.NameResolution == nil || len(result.NameResolution.HostsFileEntries) != 1 {
		t.Fatalf("hosts-file observation = %#v", result.NameResolution)
	}
	path := findResolutionPath(result.NameResolution.Paths, "", model.NameResolutionPathConfiguredCandidate)
	if path == nil || path.Mechanism != model.NameResolutionMechanismHostsFile || len(path.A) != 1 || path.A[0] != answer.String() {
		t.Fatalf("hosts-file candidate paths = %#v", result.NameResolution.Paths)
	}
}

type effectiveFixtureResolver struct {
	*fakeResolver
	path model.NameResolutionPath
}

func (r *effectiveFixtureResolver) EffectivePath(context.Context, string) (model.NameResolutionPath, error) {
	return r.path, nil
}

func fixtureResolver(addresses map[string][]netip.Addr, lookupErrors map[string]error) *fakeResolver {
	return &fakeResolver{addresses: addresses, errors: lookupErrors}
}

func namedTarget(host string) model.Target {
	parsed, err := model.ParseTarget(model.TargetIntent{Input: host})
	if err != nil {
		panic(err)
	}
	return parsed
}

func findResolutionPath(paths []model.NameResolutionPath, resolver string, state model.NameResolutionPathState) *model.NameResolutionPath {
	for index := range paths {
		if paths[index].State == state && paths[index].Resolver == resolver {
			return &paths[index]
		}
	}
	return nil
}

func TestProbeLookupTimeoutIsBoundedByContext(t *testing.T) {
	resolver := blockingResolver{}
	p := New(
		WithResolver(&resolver),
		WithResolverConfig(StaticResolverConfig{"192.0.2.53"}),
		WithTimeout(20*time.Millisecond),
	)
	started := time.Now()
	result := p.Run(context.Background(), probe.ExecutionContext{Target: target()})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("lookup took %v; timeout was not bounded", elapsed)
	}
	if result.Interpretation.FailureReason != model.FailureReasonDNSTimeout {
		t.Fatalf("bounded lookup reason = %q", result.Interpretation.FailureReason)
	}
}

type blockingResolver struct{}

func (blockingResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func evidenceContains(evidence []model.Evidence, want string) bool {
	for _, item := range evidence {
		if strings.Contains(string(item.Raw), want) {
			return true
		}
	}
	return false
}

func TestParseResolverAddresses(t *testing.T) {
	data := []byte("# local\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # v6\nnameserver 192.0.2.53\n")
	got := ParseResolverAddresses(data)
	want := []string{"192.0.2.53", "2001:db8::53"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("addresses = %#v, want %#v", got, want)
	}
}

func TestParseWindowsResolverAddresses(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "ipv4 and continuation",
			data: "Windows IP Configuration\n    DNS Servers . . . . . . . . . . . : 192.0.2.53\n                                      192.0.2.54\n    NetBIOS over Tcpip. . . . . . . . : Enabled\n",
			want: []string{"192.0.2.53", "192.0.2.54"},
		},
		{
			name: "ipv6 first",
			data: "    DNS Servers . . . . . . . . . . : 2001:db8::53\n                                      192.0.2.53\n",
			want: []string{"2001:db8::53", "192.0.2.53"},
		},
		{
			name: "ipv6 only",
			data: "    DNS Servers . . . . . . . . . . : 2001:db8:1::53\n    NetBIOS over Tcpip. . . . . . . . : Disabled\n",
			want: []string{"2001:db8:1::53"},
		},
		{
			name: "duplicates and unrelated fields",
			data: "    DNS Servers . . . . . . . . . . : 2001:db8::53\n                                      2001:db8::53\n    Default Gateway . . . . . . . . . : 192.0.2.1\n                                      192.0.2.2\n",
			want: []string{"2001:db8::53"},
		},
		{
			name: "value on continuation line",
			data: "    DNS Servers . . . . . . . . . . :\n                                      2001:db8::53\n                                      192.0.2.53\n    DHCPv6 IAID . . . . . . . . . . . : 1\n",
			want: []string{"2001:db8::53", "192.0.2.53"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ParseWindowsResolverAddresses([]byte(test.data))
			if len(got) != len(test.want) {
				t.Fatalf("addresses = %#v, want %#v", got, test.want)
			}
			for index := range test.want {
				if got[index] != test.want[index] {
					t.Fatalf("addresses = %#v, want %#v", got, test.want)
				}
			}
		})
	}
}
