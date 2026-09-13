package interfacecfg

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

func fixtureSnapshot() Snapshot {
	return Snapshot{
		Interfaces: []InterfaceState{
			{Index: 1, Name: "lo", Loopback: true, Up: true, Addresses: []Address{{IP: netip.MustParseAddr("127.0.0.1"), Prefix: 8}}},
			{Index: 2, Name: "eth-test", Up: true, Addresses: []Address{
				{IP: netip.MustParseAddr("192.0.2.10"), Prefix: 24},
				{IP: netip.MustParseAddr("2001:db8::10"), Prefix: 64},
			},
			},
		},
		DNSServers: []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")},
		Source:     "fixture",
		CapturedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
	}
}

func TestInterfaceProbeSuccessPreservesAddressesAndPrefixes(t *testing.T) {
	p := NewInterfaceProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) { return fixtureSnapshot(), nil }))
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "198.51.100.20", Port: 443}})
	if got.Status != model.ProbeStatusPassed || got.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("unexpected result: %#v", got)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Kind != model.EvidenceKindInterfaceState {
		t.Fatalf("interface evidence = %#v", got.Evidence)
	}
	var interfaces []InterfaceState
	if err := json.Unmarshal(got.Evidence[0].Raw, &interfaces); err != nil {
		t.Fatalf("decode interface evidence: %v", err)
	}
	if len(interfaces) != 2 || len(interfaces[1].Addresses) != 2 || interfaces[1].Addresses[1].Prefix != 64 {
		t.Fatalf("address/prefix evidence lost: %#v", interfaces)
	}
}

func TestInterfaceProbeNormalizesNoActiveInterface(t *testing.T) {
	p := NewInterfaceProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) {
		return Snapshot{Interfaces: []InterfaceState{{Name: "eth-test", Up: false}}}, nil
	}))
	got := p.Run(context.Background(), probe.ExecutionContext{})
	if got.Status != model.ProbeStatusFailed || got.Interpretation.FailureReason != model.FailureReasonInterfaceDown {
		t.Fatalf("result = %#v", got)
	}
}

func TestInterfaceProbeNormalizesNoUsableAddress(t *testing.T) {
	p := NewInterfaceProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) {
		return Snapshot{Interfaces: []InterfaceState{{Name: "eth-test", Up: true, Addresses: []Address{{IP: netip.MustParseAddr("169.254.1.2"), Prefix: 16}}}}}, nil
	}))
	got := p.Run(context.Background(), probe.ExecutionContext{})
	if got.Interpretation.FailureReason != model.FailureReasonNoIPAddress {
		t.Fatalf("reason = %q, want %q", got.Interpretation.FailureReason, model.FailureReasonNoIPAddress)
	}
}

func TestInterfaceProbeTimeoutReason(t *testing.T) {
	p := NewInterfaceProbe(SnapshotProviderFunc(func(ctx context.Context) (Snapshot, error) {
		<-ctx.Done()
		return Snapshot{}, ctx.Err()
	}))
	p.Timeout = 5 * time.Millisecond
	started := time.Now()
	got := p.Run(context.Background(), probe.ExecutionContext{})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("probe exceeded bounded timeout: %s", elapsed)
	}
	if got.Interpretation.FailureReason != model.FailureReason(FailureReasonProbeTimeout) {
		t.Fatalf("reason = %q, want probe_timeout", got.Interpretation.FailureReason)
	}
}

func TestDNSProbeIsLocalEvidenceOnly(t *testing.T) {
	p := NewDNSProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) { return fixtureSnapshot(), nil }))
	got := p.Run(context.Background(), probe.ExecutionContext{Target: model.Target{Host: "does-not-resolve.invalid"}})
	if got.Status != model.ProbeStatusPassed || got.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("DNS config result = %#v", got)
	}
	if !strings.Contains(string(got.Evidence[0].Raw), "192.0.2.53") {
		t.Fatalf("DNS server missing from evidence: %s", got.Evidence[0].Raw)
	}
}

func TestSystemProviderReadsResolverConfigFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("# fixture\nnameserver 192.0.2.53\nnameserver 2001:db8::53%eth0\nnameserver invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := (SystemProvider{ResolverConfigPath: path}).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.DNSServers) != 2 {
		t.Fatalf("DNS servers = %#v", snapshot.DNSServers)
	}
}

func TestInterfaceProbeNormalizesUnsupported(t *testing.T) {
	p := NewInterfaceProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) { return Snapshot{}, ErrUnsupported }))
	got := p.Run(context.Background(), probe.ExecutionContext{})
	if got.Status != model.ProbeStatusError || got.Interpretation.FailureReason != model.FailureReasonUnsupported {
		t.Fatalf("result = %#v", got)
	}
}

func TestInterfaceProbeNormalizesExecutionError(t *testing.T) {
	p := NewInterfaceProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) { return Snapshot{}, errors.New("fixture failure") }))
	got := p.Run(context.Background(), probe.ExecutionContext{})
	if got.Interpretation.FailureReason != model.FailureReasonProbeExecution {
		t.Fatalf("reason = %q", got.Interpretation.FailureReason)
	}
}

func TestResolverFailureDoesNotDiscardInterfaceSnapshot(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.ResolverError = "resolver process failed"
	snapshot.ResolverErrorKind = "resolver_failure"
	provider := SnapshotProviderFunc(func(context.Context) (Snapshot, error) { return snapshot, nil })
	interfaceResult := NewInterfaceProbe(provider).Run(context.Background(), probe.ExecutionContext{})
	if interfaceResult.Status != model.ProbeStatusPassed || interfaceResult.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("interface result = %#v", interfaceResult)
	}
	dnsResult := NewDNSProbe(provider).Run(context.Background(), probe.ExecutionContext{})
	if dnsResult.Status != model.ProbeStatusError || dnsResult.Interpretation.FailureReason != model.FailureReasonDNSResolverFailure {
		t.Fatalf("DNS result = %#v", dnsResult)
	}
}

func TestSystemProviderPropagatesResolverCancellationWithPartialSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := readConfiguredDNSServers(ctx, filepath.Join(t.TempDir(), "resolv.conf")); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolver cancellation error = %v, want context.Canceled", err)
	}
}

func TestInterfaceProbeReportsTimeoutWhenProviderPropagatesDeadline(t *testing.T) {
	snapshot := fixtureSnapshot()
	p := NewInterfaceProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) {
		return snapshot, context.DeadlineExceeded
	}))
	got := p.Run(context.Background(), probe.ExecutionContext{})
	if got.Status != model.ProbeStatusFailed || got.Interpretation.FailureReason != model.FailureReason(FailureReasonProbeTimeout) {
		t.Fatalf("deadline result = %#v", got)
	}
	if len(got.Evidence) < 2 {
		t.Fatalf("partial interface evidence was discarded: %#v", got.Evidence)
	}
}

func TestDNSProbeNormalizesTopLevelResolverErrors(t *testing.T) {
	snapshot := fixtureSnapshot()
	resolverFailure := NewDNSProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) {
		return snapshot, errors.New("resolver discovery failed")
	})).Run(context.Background(), probe.ExecutionContext{})
	if resolverFailure.Status != model.ProbeStatusError || resolverFailure.Interpretation.FailureReason != model.FailureReasonDNSResolverFailure {
		t.Fatalf("resolver failure result = %#v", resolverFailure)
	}
	timeout := NewDNSProbe(SnapshotProviderFunc(func(context.Context) (Snapshot, error) {
		return snapshot, context.DeadlineExceeded
	})).Run(context.Background(), probe.ExecutionContext{})
	if timeout.Status != model.ProbeStatusFailed || timeout.Interpretation.FailureReason != model.FailureReasonDNSTimeout {
		t.Fatalf("resolver timeout result = %#v", timeout)
	}
}
