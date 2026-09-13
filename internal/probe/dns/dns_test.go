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
	return model.Target{URL: "https://service.example.test/path", Scheme: "https", Host: "service.example.test", Port: 443}
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
	result := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "bad..name"}})
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
