package ssh

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

func sshTarget(t *testing.T, host string, port uint16) model.Target {
	t.Helper()
	profile, err := model.LookupServiceProfile(model.ServiceProfileSSH)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{OriginalInput: net.JoinHostPort(host, strconv.Itoa(int(port))), RequestedIdentity: host, Service: profile, ApplicationProtocol: profile.ApplicationProtocol, TransportProtocol: profile.TransportProtocol, Port: port}
	if net.ParseIP(host) != nil {
		target.LiteralIP = host
	}
	return target
}

func sshFixture(t *testing.T, response string, hold bool) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = bufio.NewReader(conn).ReadString('\n')
		if response != "" {
			_, _ = io.WriteString(conn, response)
		}
		if hold {
			select {}
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("SSH fixture did not stop")
		}
	}
}

func decodeSSH(t *testing.T, result model.ProbeResult) SSHHandshakeEvidence {
	t.Helper()
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
	var value SSHHandshakeEvidence
	if err := json.Unmarshal(result.Evidence[0].Raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestProbeValidBannerSupportsLiteralCustomPortAndRetainsIdentification(t *testing.T) {
	address, stop := sshFixture(t, "SSH-2.0-OpenSSH_9.8\r\n", false)
	defer stop()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.ParseUint(portText, 10, 16)
	result := New(500*time.Millisecond).Run(context.Background(), probecontract.ExecutionContext{Target: sshTarget(t, host, uint16(port))})
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone || result.Interpretation.Layer != model.LayerSSH {
		t.Fatalf("result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
	}
	value := decodeSSH(t, result)
	if !value.TransportConnected || !value.BannerValid || value.ServerProtocol != "2.0" || value.ServerSoftware != "OpenSSH_9.8" {
		t.Fatalf("SSH evidence = %#v", value)
	}
	if value.RequestedEndpoint != address || !strings.Contains(value.ServerIdentification, "OpenSSH_9.8") {
		t.Fatalf("endpoint/banner = %#v", value)
	}
}

func TestProbeSupportsHostnameTargetAndPrelude(t *testing.T) {
	address, stop := sshFixture(t, "notice before banner\r\nSSH-2.0-Fixture_1\r\n", false)
	defer stop()
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.ParseUint(portText, 10, 16)
	result := New(500*time.Millisecond).Run(context.Background(), probecontract.ExecutionContext{Target: sshTarget(t, "localhost", uint16(port))})
	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("hostname result = status %q reason %q", result.Status, result.Interpretation.FailureReason)
	}
	if got := decodeSSH(t, result).ServerSoftware; got != "Fixture_1" {
		t.Fatalf("server software = %q", got)
	}
}

func TestProbeSeparatesMalformedAndNonSSHResponsesFromTransport(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		reason model.FailureReason
		class  string
	}{
		{name: "malformed", body: "not-a-banner\r\n", reason: model.FailureReasonSSHBannerMalformed, class: "malformed"},
		{name: "non ssh", body: "HTTP/1.1 200 OK\r\n\r\n", reason: model.FailureReasonSSHNonSSHResponse, class: "non_ssh"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, stop := sshFixture(t, test.body, false)
			defer stop()
			host, portText, _ := net.SplitHostPort(address)
			port, _ := strconv.ParseUint(portText, 10, 16)
			result := New(500*time.Millisecond).Run(context.Background(), probecontract.ExecutionContext{Target: sshTarget(t, host, uint16(port))})
			if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != test.reason || result.Interpretation.Layer != model.LayerSSH {
				t.Fatalf("result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
			}
			value := decodeSSH(t, result)
			if !value.TransportConnected || value.ResponseClass != test.class {
				t.Fatalf("evidence = %#v", value)
			}
		})
	}
}

func TestProbeTimeoutAndRefusedRemainTransportOrBoundedHandshakeOutcomes(t *testing.T) {
	t.Run("timeout after TCP connect", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_, _ = bufio.NewReader(server).ReadString('\n')
			select {}
		}()
		target := sshTarget(t, "fixture.test", 2222)
		result := NewWithConfig(Config{Timeout: 25 * time.Millisecond, Dialer: DialContextFunc(func(context.Context, string, string) (net.Conn, error) { return client, nil })}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
		if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonSSHTimeout || result.Interpretation.Layer != model.LayerSSH {
			t.Fatalf("timeout result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
		}
		if !decodeSSH(t, result).TransportConnected {
			t.Fatal("timeout after connect lost transport success")
		}
	})

	t.Run("refused before handshake", func(t *testing.T) {
		target := sshTarget(t, "fixture.test", 2222)
		result := NewWithConfig(Config{Timeout: time.Second, Dialer: DialContextFunc(func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED })}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
		if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonTCPConnectionRefused || result.Interpretation.Layer != model.LayerTCP {
			t.Fatalf("refused result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
		}
		if decodeSSH(t, result).TransportConnected {
			t.Fatal("refused transport was marked connected")
		}
	})
}

func TestProbeHonorsCanceledContextWithoutDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	target := sshTarget(t, "fixture.test", 22)
	result := NewWithDialer(time.Second, DialContextFunc(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("must not dial")
	})).Run(ctx, probecontract.ExecutionContext{Target: target})
	if called || result.Status != model.ProbeStatusError {
		t.Fatalf("canceled result = %#v, dial called=%v", result, called)
	}
}
