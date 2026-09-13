package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

func TestNegotiationSuccessExtractsDialectCapabilitiesAndUsesOneRequest(t *testing.T) {
	response := smbResponseFrame(0x0311, 0x0000000d)
	target, requests, cleanup := localFixture(t, response, false)
	defer cleanup()

	result := New(Config{Timeout: time.Second}).Run(context.Background(), probe.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("result = %#v", result)
	}
	if result.Interpretation.Layer != model.LayerSMB || result.Interpretation.FaultDomain != model.FaultDomainSMB {
		t.Fatalf("interpretation = %#v", result.Interpretation)
	}
	evidence := negotiationEvidence(t, result)
	if !evidence.Connected || !evidence.ResponseReceived || !evidence.Negotiated {
		t.Fatalf("evidence connection state = %#v", evidence)
	}
	if evidence.Dialect != "SMB 3.1.1" || evidence.DialectRevision != 0x0311 {
		t.Fatalf("dialect = %q/%#x", evidence.Dialect, evidence.DialectRevision)
	}
	if !equalStrings(evidence.Capabilities, []string{"DFS", "LARGE_MTU", "MULTI_CHANNEL"}) {
		t.Fatalf("capabilities = %#v", evidence.Capabilities)
	}
	if evidence.ServerGUID != "00112233445566778899aabbccddeeff" || evidence.MaxReadSize != 0x100000 {
		t.Fatalf("negotiated facts = %#v", evidence)
	}
	request := <-requests
	if len(request) < 4+64 || string(request[4:8]) != "\xfeSMB" {
		t.Fatalf("request header = %x", request)
	}
	if binary.LittleEndian.Uint16(request[16:18]) != 0 {
		t.Fatalf("request command = %d, want NEGOTIATE", binary.LittleEndian.Uint16(request[16:18]))
	}
	if bytes.Contains(request, []byte("SESSION_SETUP")) || bytes.Contains(request, []byte("TREE_CONNECT")) {
		t.Fatal("request contains a non-negotiate operation")
	}
}

func TestNegotiationFailureBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		response   []byte
		hold       bool
		wantStatus model.ProbeStatus
		wantReason model.FailureReason
		wantResult model.SMBResult
	}{
		{name: "non SMB responder", response: []byte("HTTP/1.1 200 OK\r\n"), wantStatus: model.ProbeStatusFailed, wantReason: model.FailureReasonSMBProtocolRejection, wantResult: model.SMBResultProtocolRejection},
		{name: "malformed truncated response", response: []byte{0, 0, 0, 100, 0xfe, 'S'}, wantStatus: model.ProbeStatusFailed, wantReason: model.FailureReasonSMBMalformedResponse, wantResult: model.SMBResultMalformedResponse},
		{name: "silent timeout", hold: true, wantStatus: model.ProbeStatusFailed, wantReason: model.FailureReasonSMBTimeout, wantResult: model.SMBResultTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, _, cleanup := localFixture(t, test.response, test.hold)
			defer cleanup()
			result := New(Config{Timeout: 40 * time.Millisecond}).Run(context.Background(), probe.ExecutionContext{Target: target})
			if result.Status != test.wantStatus || result.Interpretation.FailureReason != test.wantReason {
				t.Fatalf("result = %#v", result)
			}
			evidence := negotiationEvidence(t, result)
			if evidence.Negotiated || evidence.FailureReason != test.wantReason {
				t.Fatalf("evidence = %#v", evidence)
			}
			if got := canonicalResult(evidence); got != test.wantResult {
				t.Fatalf("canonical result helper = %q, want %q", got, test.wantResult)
			}
		})
	}
}

func TestConnectionRefusedRemainsATCPFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	target := targetForAddress(t, address)
	result := New(Config{Timeout: time.Second}).Run(context.Background(), probe.ExecutionContext{Target: target})
	if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonTCPConnectionRefused {
		t.Fatalf("result = %#v", result)
	}
	if result.Interpretation.Layer != model.LayerTCP || result.Interpretation.FaultDomain != model.FaultDomainTransport {
		t.Fatalf("transport interpretation = %#v", result.Interpretation)
	}
	evidence := negotiationEvidence(t, result)
	if evidence.Connected || evidence.ResponseReceived || evidence.FailureReason != model.FailureReasonTCPConnectionRefused {
		t.Fatalf("evidence = %#v", evidence)
	}
}

func TestExplicitCustomPortLiteralIPAndUNCPreserveResource(t *testing.T) {
	response := smbResponseFrame(0x0210, 0x00000003)
	tests := []struct {
		name     string
		input    string
		resource string
	}{
		{name: "literal IP", input: "127.0.0.1", resource: ""},
		{name: "UNC resource", input: `\fileserver01\diagnostics`, resource: "/diagnostics"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, requests, cleanup := localFixture(t, response, false)
			defer cleanup()
			port := target.Port
			parsed, err := model.ParseTarget(model.TargetIntent{Input: test.input, Service: model.ServiceProfileSMB, Port: &port})
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Resource != test.resource {
				t.Fatalf("resource = %q, want %q", parsed.Resource, test.resource)
			}
			parsed.SelectedEndpoint = target.SelectedEndpoint
			parsed.TestedEndpoint = target.TestedEndpoint
			result := New(Config{Timeout: time.Second}).Run(context.Background(), probe.ExecutionContext{Target: parsed})
			if result.Status != model.ProbeStatusPassed {
				t.Fatalf("result = %#v", result)
			}
			if result.Target.Resource != test.resource || result.Target.RequestedIdentity == "" {
				t.Fatalf("probe target = %#v", result.Target)
			}
			evidence := negotiationEvidence(t, result)
			if !strings.HasSuffix(evidence.RequestedEndpoint, ":"+strconv.Itoa(int(port))) {
				t.Fatalf("requested endpoint = %q", evidence.RequestedEndpoint)
			}
			request := <-requests
			if len(request) == 0 {
				t.Fatal("fixture did not receive negotiate request")
			}
		})
	}
}

func TestReadResponseBoundsFraming(t *testing.T) {
	if _, err := readResponse(strings.NewReader("\x00\x00\x10\x00"), 4096); err != errMalformedResponse {
		t.Fatalf("oversized response error = %v", err)
	}
	if _, err := readResponse(strings.NewReader("\x00\x00\x00\x04xxxx"), 4096); err != errMalformedResponse {
		t.Fatalf("short response error = %v", err)
	}
}

func localFixture(t *testing.T, response []byte, hold bool) (model.Target, <-chan []byte, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := targetForAddress(t, listener.Addr().String())
	requests := make(chan []byte, 1)
	release := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		request, readErr := readFixtureFrame(conn)
		if readErr == nil {
			requests <- request
		}
		if hold {
			<-release
			return
		}
		if len(response) > 0 {
			_, _ = conn.Write(response)
		}
	}()
	cleanup := func() {
		close(release)
		_ = listener.Close()
	}
	return target, requests, cleanup
}

func targetForAddress(t *testing.T, address string) model.Target {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(portNumber)
	target, err := model.ParseTarget(model.TargetIntent{Input: host, Service: model.ServiceProfileSMB, Port: &port})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &model.Endpoint{Address: host, Port: port, Family: model.EndpointFamilyIPv4}
	target.SelectedEndpoint = endpoint
	target.TestedEndpoint = endpoint
	return target
}

func readFixtureFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > 4096 {
		return nil, io.ErrShortBuffer
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return append(header[:0:0], append(header[:], body...)...), nil
}

func smbResponseFrame(dialect uint16, capabilities uint32) []byte {
	body := make([]byte, 128)
	copy(body[:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(body[4:6], 64)
	binary.LittleEndian.PutUint16(body[12:14], 0)
	binary.LittleEndian.PutUint16(body[64:66], 65)
	binary.LittleEndian.PutUint16(body[66:68], 1)
	binary.LittleEndian.PutUint16(body[68:70], dialect)
	copy(body[72:88], []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.LittleEndian.PutUint32(body[88:92], capabilities)
	binary.LittleEndian.PutUint32(body[92:96], 0x200000)
	binary.LittleEndian.PutUint32(body[96:100], 0x100000)
	binary.LittleEndian.PutUint32(body[100:104], 0x100000)
	frame := make([]byte, 4+len(body))
	frame[0] = 0
	frame[1] = byte(len(body) >> 16)
	frame[2] = byte(len(body) >> 8)
	frame[3] = byte(len(body))
	copy(frame[4:], body)
	return frame
}

func negotiationEvidence(t *testing.T, result model.ProbeResult) NegotiationEvidence {
	t.Helper()
	if len(result.Evidence) != 1 || result.Evidence[0].Kind != model.EvidenceKindSMBNegotiation {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
	var evidence NegotiationEvidence
	if err := json.Unmarshal(result.Evidence[0].Raw, &evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func canonicalResult(evidence NegotiationEvidence) model.SMBResult {
	if evidence.Negotiated {
		return model.SMBResultNegotiated
	}
	switch evidence.FailureReason {
	case model.FailureReasonSMBTimeout:
		return model.SMBResultTimeout
	case model.FailureReasonSMBProtocolRejection:
		return model.SMBResultProtocolRejection
	case model.FailureReasonSMBMalformedResponse:
		return model.SMBResultMalformedResponse
	case model.FailureReasonTCPConnectionRefused, model.FailureReasonSMBConnectionRefused, model.FailureReasonTCPTimeout:
		return model.SMBResultTCPFailure
	default:
		return model.SMBResultUnknown
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
