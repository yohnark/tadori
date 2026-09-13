package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

type selectionConn struct {
	local  net.Addr
	remote net.Addr
}

func (c *selectionConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *selectionConn) Write(value []byte) (int, error)  { return len(value), nil }
func (c *selectionConn) Close() error                     { return nil }
func (c *selectionConn) LocalAddr() net.Addr              { return c.local }
func (c *selectionConn) RemoteAddr() net.Addr             { return c.remote }
func (c *selectionConn) SetDeadline(time.Time) error      { return nil }
func (c *selectionConn) SetReadDeadline(time.Time) error  { return nil }
func (c *selectionConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedDialer struct {
	calls    []string
	failures map[string]error
	remotes  map[string]string
}

func (d *scriptedDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.calls = append(d.calls, address)
	if err := d.failures[address]; err != nil {
		return nil, err
	}
	remote := address
	if value := d.remotes[address]; value != "" {
		remote = value
	}
	return &selectionConn{
		local:  &net.TCPAddr{IP: net.ParseIP("192.0.2.200"), Port: 40000},
		remote: tcpAddr(remote),
	}, nil
}

func tcpAddr(value string) net.Addr {
	address, err := net.ResolveTCPAddr("tcp", value)
	if err != nil {
		return &net.TCPAddr{}
	}
	return address
}

func candidateTarget(a, aaaa []string) model.Target {
	return model.Target{
		RequestedIdentity:  "service.example.test",
		Port:               443,
		ResolvedCandidates: model.EndpointCandidatesFromAnswers(a, aaaa),
	}
}

func candidateAddress(address string, port uint16) string {
	return net.JoinHostPort(address, strconv.Itoa(int(port)))
}

func TestProbeFirstDNSAnswerFailsLaterCandidateSucceeds(t *testing.T) {
	target := candidateTarget([]string{"192.0.2.10", "192.0.2.11"}, nil)
	first := candidateAddress("192.0.2.10", target.Port)
	second := candidateAddress("192.0.2.11", target.Port)
	dialer := &scriptedDialer{failures: map[string]error{first: errors.New("connection refused")}}

	result := NewWithConfig(Config{Timeout: time.Second, Dialer: dialer}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("result = status %q reason %q, want passed/none", result.Status, result.Interpretation.FailureReason)
	}
	if !reflect.DeepEqual(dialer.calls, []string{first, second}) {
		t.Fatalf("dial order = %#v, want %#v", dialer.calls, []string{first, second})
	}
	if result.Target.SelectedEndpoint == nil || result.Target.SelectedEndpoint.Address != "192.0.2.10" {
		t.Fatalf("probe candidate = %#v, want first DNS candidate", result.Target.SelectedEndpoint)
	}
	if result.Target.TestedEndpoint == nil || result.Target.TestedEndpoint.Address != "192.0.2.11" {
		t.Fatalf("tested endpoint = %#v, want later successful candidate", result.Target.TestedEndpoint)
	}
	if len(result.Target.CandidateAttempts) != 2 || result.Target.CandidateAttempts[0].Status != model.ProbeStatusFailed || result.Target.CandidateAttempts[1].Status != model.ProbeStatusPassed {
		t.Fatalf("candidate attempts = %#v", result.Target.CandidateAttempts)
	}

	var evidence struct {
		CandidateAttempts []model.EndpointAttempt `json:"candidate_attempts"`
		TestedEndpoint    string                  `json:"tested_endpoint"`
	}
	if err := json.Unmarshal(result.Evidence[0].Raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.CandidateAttempts) != 2 || evidence.TestedEndpoint != second {
		t.Fatalf("transport evidence = %#v, want both attempts and %q", evidence, second)
	}
}

func TestProbeDualStackFallbackHandlesEitherFamily(t *testing.T) {
	tests := []struct {
		name          string
		failures      []string
		wantAddress   string
		wantFamily    model.EndpointFamily
		wantCallCount int
	}{
		{
			name:          "ipv6 succeeds after ipv4 fails",
			failures:      []string{"192.0.2.10"},
			wantAddress:   "2001:db8::10",
			wantFamily:    model.EndpointFamilyIPv6,
			wantCallCount: 2,
		},
		{
			name:          "ipv4 succeeds before ipv6 fails",
			failures:      []string{"2001:db8::10"},
			wantAddress:   "192.0.2.10",
			wantFamily:    model.EndpointFamilyIPv4,
			wantCallCount: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := candidateTarget([]string{"192.0.2.10"}, []string{"2001:db8::10"})
			failures := make(map[string]error)
			for _, address := range test.failures {
				failures[candidateAddress(address, target.Port)] = errors.New("connection refused")
			}
			dialer := &scriptedDialer{failures: failures}
			result := NewWithConfig(Config{Timeout: time.Second, Dialer: dialer}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
			if result.Status != model.ProbeStatusPassed {
				t.Fatalf("status = %q, want passed; attempts = %#v", result.Status, result.Target.CandidateAttempts)
			}
			if result.Target.TestedEndpoint == nil || result.Target.TestedEndpoint.Address != test.wantAddress || result.Target.TestedEndpoint.Family != test.wantFamily {
				t.Fatalf("tested endpoint = %#v, want %s/%s", result.Target.TestedEndpoint, test.wantAddress, test.wantFamily)
			}
			if len(dialer.calls) != test.wantCallCount {
				t.Fatalf("dial calls = %#v, want %d", dialer.calls, test.wantCallCount)
			}
		})
	}
}

func TestProbeAllCandidatesFailRetainsComparativeEvidence(t *testing.T) {
	target := candidateTarget([]string{"192.0.2.10", "192.0.2.11"}, []string{"2001:db8::10"})
	failures := make(map[string]error)
	for _, candidate := range target.ResolvedCandidates {
		failures[candidateAddress(candidate.Address, target.Port)] = errors.New("connection refused")
	}
	dialer := &scriptedDialer{failures: failures}
	result := NewWithConfig(Config{Timeout: time.Second, Dialer: dialer}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonTCPConnectionRefused {
		t.Fatalf("result = status %q reason %q, want failed/connection refused", result.Status, result.Interpretation.FailureReason)
	}
	if len(result.Target.CandidateAttempts) != 3 || len(dialer.calls) != 3 {
		t.Fatalf("attempts/calls = %d/%d, want 3/3", len(result.Target.CandidateAttempts), len(dialer.calls))
	}
	for index, attempt := range result.Target.CandidateAttempts {
		if attempt.Status != model.ProbeStatusFailed || attempt.Candidate.Order != index+1 || attempt.Error == "" {
			t.Errorf("attempt %d = %#v, want failed ordered evidence", index, attempt)
		}
	}
	if result.Target.TestedEndpoint != nil {
		t.Fatalf("failed comparison produced tested endpoint: %#v", result.Target.TestedEndpoint)
	}
}

func TestProbeCandidateLimitIsDeterministicAndBounded(t *testing.T) {
	addresses := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"}
	target := candidateTarget(addresses, nil)
	failures := make(map[string]error)
	for _, address := range addresses {
		failures[candidateAddress(address, target.Port)] = errors.New("connection refused")
	}
	dialer := &scriptedDialer{failures: failures}
	result := NewWithConfig(Config{Timeout: time.Second, Dialer: dialer, MaxCandidates: 3}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusFailed {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	wantCalls := []string{candidateAddress("192.0.2.1", 443), candidateAddress("192.0.2.2", 443), candidateAddress("192.0.2.3", 443)}
	if !reflect.DeepEqual(dialer.calls, wantCalls) {
		t.Fatalf("bounded dial order = %#v, want %#v", dialer.calls, wantCalls)
	}
	if len(result.Target.ResolvedCandidates) != len(addresses) || len(result.Target.CandidateAttempts) != 3 {
		t.Fatalf("complete/active candidate counts = %d/%d, want %d/3", len(result.Target.ResolvedCandidates), len(result.Target.CandidateAttempts), len(addresses))
	}
}

func TestProbeLiteralAddressesRemainSingleCandidates(t *testing.T) {
	for _, test := range []struct {
		name    string
		literal string
		family  model.EndpointFamily
	}{
		{name: "ipv4", literal: "192.0.2.44", family: model.EndpointFamilyIPv4},
		{name: "ipv6", literal: "2001:db8::44", family: model.EndpointFamilyIPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := test.literal + ":443"
			if test.family == model.EndpointFamilyIPv6 {
				input = "[" + test.literal + "]:443"
			}
			target, err := model.ParseTarget(model.TargetIntent{Input: input})
			if err != nil {
				t.Fatal(err)
			}
			dialer := &scriptedDialer{}
			result := NewWithConfig(Config{Timeout: time.Second, Dialer: dialer}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
			if result.Status != model.ProbeStatusPassed || len(dialer.calls) != 1 {
				t.Fatalf("status/calls = %q/%d, want passed/1", result.Status, len(dialer.calls))
			}
			if result.Target.TestedEndpoint == nil || result.Target.TestedEndpoint.Address != test.literal || result.Target.TestedEndpoint.Family != test.family {
				t.Fatalf("tested endpoint = %#v, want %s/%s", result.Target.TestedEndpoint, test.literal, test.family)
			}
		})
	}
}

func TestProbeUsesConcreteRemoteAddrForTestedEndpoint(t *testing.T) {
	target := candidateTarget([]string{"192.0.2.10"}, nil)
	requested := candidateAddress("192.0.2.10", target.Port)
	dialer := &scriptedDialer{
		remotes: map[string]string{requested: candidateAddress("192.0.2.99", target.Port)},
	}
	result := NewWithConfig(Config{Timeout: time.Second, Dialer: dialer}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %q, want passed", result.Status)
	}
	if result.Target.TestedEndpoint == nil || result.Target.TestedEndpoint.Address != "192.0.2.99" {
		t.Fatalf("tested endpoint = %#v, want concrete remote address", result.Target.TestedEndpoint)
	}
	if result.Target.TestedEndpoint.SelectionReason != model.EndpointSelectionTransport {
		t.Fatalf("tested endpoint reason = %q, want transport observation", result.Target.TestedEndpoint.SelectionReason)
	}
}

func TestProbeConnectsToLocalListenerAndRecordsEndpoints(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	target := model.NewTarget("127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port))
	result := New(500*time.Millisecond).Run(context.Background(), probecontract.ExecutionContext{Target: target})

	if result.Name != "tcp" {
		t.Fatalf("name = %q, want tcp", result.Name)
	}
	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %q, want passed (evidence: %s)", result.Status, result.Evidence[0].Raw)
	}
	if result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("reason = %q, want none", result.Interpretation.FailureReason)
	}
	if result.Timing.StartedAt == nil || result.Timing.CompletedAt == nil {
		t.Fatal("timing timestamps were not recorded")
	}
	if result.Timing.CompletedAt.Before(*result.Timing.StartedAt) {
		t.Fatal("completed timestamp precedes started timestamp")
	}
	if result.Timing.DurationMS < 0 {
		t.Fatalf("duration = %d, want non-negative", result.Timing.DurationMS)
	}

	var evidence struct {
		RequestedEndpoint string `json:"requested_endpoint"`
		LocalEndpoint     string `json:"local_endpoint"`
		RemoteEndpoint    string `json:"remote_endpoint"`
		ResolvedEndpoint  string `json:"resolved_endpoint"`
		ElapsedNS         int64  `json:"elapsed_ns"`
	}
	if err := json.Unmarshal(result.Evidence[0].Raw, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	wantAddress := listener.Addr().String()
	if evidence.RequestedEndpoint != wantAddress {
		t.Fatalf("requested endpoint = %q, want %q", evidence.RequestedEndpoint, wantAddress)
	}
	if evidence.LocalEndpoint == "" || evidence.RemoteEndpoint == "" || evidence.ResolvedEndpoint == "" {
		t.Fatalf("socket endpoint evidence incomplete: %#v", evidence)
	}
	if evidence.ElapsedNS <= 0 {
		t.Fatalf("elapsed_ns = %d, want positive", evidence.ElapsedNS)
	}

	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("listener did not accept the probe connection")
	}
}

func TestProbeDistinguishesConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()

	underlying := errors.New("dial tcp: connect: connection refused")
	result := NewWithConfig(Config{
		Timeout: 500 * time.Millisecond,
		Dialer: DialContextFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, underlying
		}),
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("127.0.0.1", port)})

	if result.Status != model.ProbeStatusFailed {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	if result.Interpretation.FailureReason != model.FailureReasonTCPConnectionRefused {
		t.Fatalf("reason = %q, want connection refused", result.Interpretation.FailureReason)
	}
	assertRawError(t, result, underlying.Error())
}

func TestProbeTimeoutIsBoundedAndDistinctFromRefused(t *testing.T) {
	const timeout = 25 * time.Millisecond
	result := NewWithConfig(Config{
		Timeout: timeout,
		Dialer: DialContextFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("192.0.2.1", 443)})

	if result.Status != model.ProbeStatusFailed {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	if result.Interpretation.FailureReason != model.FailureReasonTCPTimeout {
		t.Fatalf("reason = %q, want timeout", result.Interpretation.FailureReason)
	}
	if result.Timing.DurationMS < 0 || result.Timing.DurationMS > int64(timeout/time.Millisecond)+100 {
		t.Fatalf("duration = %dms, outside bounded timeout", result.Timing.DurationMS)
	}
}

func TestProbeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	underlying := context.Canceled
	result := NewWithConfig(Config{
		Timeout: time.Second,
		Dialer: DialContextFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nil, ctx.Err()
		}),
	}).Run(ctx, probecontract.ExecutionContext{Target: model.NewTarget("127.0.0.1", 1)})

	if result.Status != model.ProbeStatusError {
		t.Fatalf("status = %q, want error", result.Status)
	}
	if result.Interpretation.FailureReason != FailureReasonTCPCancellation {
		t.Fatalf("reason = %q, want cancellation", result.Interpretation.FailureReason)
	}
	assertRawError(t, result, underlying.Error())
}

func TestProbeNormalizesSocketErrnos(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason model.FailureReason
	}{
		{name: "reset", err: syscall.ECONNRESET, reason: model.FailureReasonTCPConnectionReset},
		{name: "network unreachable", err: syscall.ENETUNREACH, reason: model.FailureReasonNetworkUnreachable},
		{name: "host unreachable", err: syscall.EHOSTUNREACH, reason: FailureReasonTCPHostUnreachable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := NewWithConfig(Config{Dialer: DialContextFunc(func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: test.err}
			})}).Run(context.Background(), probecontract.ExecutionContext{Target: model.NewTarget("127.0.0.1", 443)})
			if result.Interpretation.FailureReason != test.reason {
				t.Fatalf("reason = %q, want %q (evidence: %s)", result.Interpretation.FailureReason, test.reason, result.Evidence[0].Raw)
			}
			if result.Status != model.ProbeStatusFailed {
				t.Fatalf("status = %q, want failed", result.Status)
			}
		})
	}
}

func TestProbeRejectsMalformedAddressAndInvalidPort(t *testing.T) {
	tests := []model.Target{
		{RequestedIdentity: "", Port: 443},
		{RequestedIdentity: "127.0.0.1", Service: model.ServiceProfile{ID: model.ServiceProfileCustomTCP}, Port: 0},
		{RequestedIdentity: "127.0.0.1:80", Port: 443},
		{RequestedIdentity: "[not-an-ip]", Port: 443},
	}
	for _, target := range tests {
		result := New(time.Second).Run(context.Background(), probecontract.ExecutionContext{Target: target})
		if result.Status != model.ProbeStatusError {
			t.Errorf("target %#v status = %q, want error", target, result.Status)
		}
		if result.Interpretation.FailureReason != FailureReasonTCPInvalidAddress {
			t.Errorf("target %#v reason = %q, want invalid address", target, result.Interpretation.FailureReason)
		}
		assertRawError(t, result, "TCP")
	}
}

func assertRawError(t *testing.T, result model.ProbeResult, want string) {
	t.Helper()
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence count = %d, want one", len(result.Evidence))
	}
	var evidence struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(result.Evidence[0].Raw, &evidence); err != nil {
		t.Fatalf("decode error evidence: %v", err)
	}
	if evidence.Error != want && !strings.Contains(evidence.Error, want) {
		t.Fatalf("evidence error = %q, want %q", evidence.Error, want)
	}
}
