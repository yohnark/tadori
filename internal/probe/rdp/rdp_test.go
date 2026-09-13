package rdp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	probecontract "github.com/yohnark/tadori/internal/probe"
)

func rdpTarget(t *testing.T, host string, port uint16) model.Target {
	t.Helper()
	profile, err := model.LookupServiceProfile(model.ServiceProfileRDP)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{OriginalInput: net.JoinHostPort(host, strconv.Itoa(int(port))), RequestedIdentity: host, Service: profile, ApplicationProtocol: profile.ApplicationProtocol, TransportProtocol: profile.TransportProtocol, Port: port}
	if net.ParseIP(host) != nil {
		target.LiteralIP = host
	}
	return target
}

func rdpResponse(responseType byte, value uint32) []byte {
	body := []byte{0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, responseType, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(body[11:], value)
	packet := make([]byte, 4, 4+len(body))
	packet[0] = 0x03
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)+len(body)))
	return append(packet, body...)
}

func rdpFixture(t *testing.T, response []byte, hold bool) (string, func()) {
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
		request := make([]byte, len(NegotiationRequest(ProtocolTLS|ProtocolCredSSP)))
		_, _ = io.ReadFull(conn, request)
		if len(response) > 0 {
			_, _ = conn.Write(response)
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
			t.Errorf("RDP fixture did not stop")
		}
	}
}

func decodeRDP(t *testing.T, result model.ProbeResult) RDPNegotiationEvidence {
	t.Helper()
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
	var value RDPNegotiationEvidence
	if err := json.Unmarshal(result.Evidence[0].Raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestProbeNegotiatesRDPOnLiteralCustomPort(t *testing.T) {
	address, stop := rdpFixture(t, rdpResponse(0x02, ProtocolTLS), false)
	defer stop()
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.ParseUint(portText, 10, 16)
	result := New(Config{Timeout: 500 * time.Millisecond, RequestedProtocols: ProtocolTLS | ProtocolCredSSP}).Run(context.Background(), probecontract.ExecutionContext{Target: rdpTarget(t, host, uint16(port))})
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone || result.Interpretation.Layer != model.LayerRDP {
		t.Fatalf("result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
	}
	value := decodeRDP(t, result)
	if !value.TransportConnected || !value.NegotiationComplete || value.NegotiatedProtocol != "tls" || value.NegotiatedProtocolID != ProtocolTLS {
		t.Fatalf("RDP evidence = %#v", value)
	}
	if value.RequestedEndpoint != address || len(value.RequestedProtocols) != 2 {
		t.Fatalf("request facts = %#v", value)
	}
}

func TestProbeSupportsHostnameAndPreservesRequestedSecurityProtocols(t *testing.T) {
	address, stop := rdpFixture(t, rdpResponse(0x02, ProtocolCredSSP), false)
	defer stop()
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.ParseUint(portText, 10, 16)
	target := rdpTarget(t, "localhost", uint16(port))
	result := New(Config{Timeout: 500 * time.Millisecond, RequestedProtocols: ProtocolTLS | ProtocolCredSSP}).Run(context.Background(), probecontract.ExecutionContext{Target: target})
	value := decodeRDP(t, result)
	if result.Status != model.ProbeStatusPassed || value.NegotiatedProtocol != "credssp" || value.RequestedProtocolBits != ProtocolTLS|ProtocolCredSSP {
		t.Fatalf("hostname result = status %q evidence %#v", result.Status, value)
	}
}

func TestProbeNegotiationRejectionAndMalformedResponse(t *testing.T) {
	tests := []struct {
		name   string
		body   []byte
		reason model.FailureReason
		kind   string
	}{
		{name: "rejected", body: rdpResponse(0x03, 0x00000002), reason: model.FailureReasonRDPNegotiationRejected, kind: "rejected"},
		{name: "malformed", body: []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0, 0, 0, 0, 0}, reason: model.FailureReasonRDPNegotiationMalformed, kind: "malformed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, stop := rdpFixture(t, test.body, false)
			defer stop()
			host, portText, _ := net.SplitHostPort(address)
			port, _ := strconv.ParseUint(portText, 10, 16)
			result := New(Config{Timeout: 500 * time.Millisecond}).Run(context.Background(), probecontract.ExecutionContext{Target: rdpTarget(t, host, uint16(port))})
			if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != test.reason || result.Interpretation.Layer != model.LayerRDP {
				t.Fatalf("result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
			}
			value := decodeRDP(t, result)
			if !value.TransportConnected || value.ResponseType != test.kind {
				t.Fatalf("evidence = %#v", value)
			}
		})
	}
}

func TestProbeTimeoutAndRefusedDoNotBecomeNegotiationSuccess(t *testing.T) {
	t.Run("timeout after TCP connect", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			request := make([]byte, len(NegotiationRequest(ProtocolTLS|ProtocolCredSSP)))
			_, _ = io.ReadFull(server, request)
			select {}
		}()
		result := NewWithConfig(Config{Timeout: 25 * time.Millisecond, Dialer: DialContextFunc(func(context.Context, string, string) (net.Conn, error) { return client, nil })}).Run(context.Background(), probecontract.ExecutionContext{Target: rdpTarget(t, "fixture.test", 3389)})
		if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonRDPTimeout || result.Interpretation.Layer != model.LayerRDP {
			t.Fatalf("timeout result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
		}
		if !decodeRDP(t, result).TransportConnected {
			t.Fatal("timeout after connect lost transport success")
		}
	})

	t.Run("refused before negotiation", func(t *testing.T) {
		result := NewWithConfig(Config{Timeout: time.Second, Dialer: DialContextFunc(func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED })}).Run(context.Background(), probecontract.ExecutionContext{Target: rdpTarget(t, "fixture.test", 3389)})
		if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonTCPConnectionRefused || result.Interpretation.Layer != model.LayerTCP {
			t.Fatalf("refused result = status %q reason %q layer %q", result.Status, result.Interpretation.FailureReason, result.Interpretation.Layer)
		}
		if decodeRDP(t, result).TransportConnected {
			t.Fatal("refused transport was marked connected")
		}
	})
}

func TestProbeHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	result := NewWithDialer(time.Second, DialContextFunc(func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("must not dial")
	})).Run(ctx, probecontract.ExecutionContext{Target: rdpTarget(t, "fixture.test", 3389)})
	if called || result.Status != model.ProbeStatusError {
		t.Fatalf("canceled result = %#v, dial called=%v", result, called)
	}
}
