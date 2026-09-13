package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

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

	target := model.Target{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}
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
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.Target{Host: "127.0.0.1", Port: port}})

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
	}).Run(context.Background(), probecontract.ExecutionContext{Target: model.Target{Host: "192.0.2.1", Port: 443}})

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
	}).Run(ctx, probecontract.ExecutionContext{Target: model.Target{Host: "127.0.0.1", Port: 1}})

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
			})}).Run(context.Background(), probecontract.ExecutionContext{Target: model.Target{Host: "127.0.0.1", Port: 443}})
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
		{Host: "", Port: 443},
		{Host: "127.0.0.1", Port: 0},
		{Host: "127.0.0.1:80", Port: 443},
		{Host: "[not-an-ip]", Port: 443},
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
