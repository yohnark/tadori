//go:build windows

package packet

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestETWBackendRejectsUnscopedCapture(t *testing.T) {
	_, err := NewETWBackend().Start(context.Background(), Scope{})
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("error = %v, want ErrInvalidScope", err)
	}
}

func TestETWSocketAddressDecoding(t *testing.T) {
	ipv4 := []byte{2, 0, 1, 187, 192, 0, 2, 10}
	address, port := etwSocketAddress(ipv4)
	if address != "192.0.2.10" || port != 443 {
		t.Fatalf("IPv4 address = %q:%d", address, port)
	}

	ipv6 := make([]byte, 24)
	binary.LittleEndian.PutUint16(ipv6[0:2], 23)
	binary.BigEndian.PutUint16(ipv6[2:4], 8443)
	ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15] = 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1
	address, port = etwSocketAddress(ipv6)
	if address != "2001:db8::1" || port != 8443 {
		t.Fatalf("IPv6 address = %q:%d", address, port)
	}
}

func TestETWTCPRequestPayloadDecoding(t *testing.T) {
	local := []byte{2, 0, 0xc0, 0x00, 192, 0, 2, 5}
	remote := []byte{2, 0, 1, 187, 203, 0, 113, 10}
	payload := make([]byte, 8+4+len(local)+4+len(remote))
	binary.LittleEndian.PutUint64(payload[0:8], 0x1234)
	offset := 8
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(len(local)))
	offset += 4
	copy(payload[offset:], local)
	offset += len(local)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(len(remote)))
	offset += 4
	copy(payload[offset:], remote)

	flow, ok := parseETWTCPRequest(payload, false, 7)
	if !ok || flow.localAddress != "192.0.2.5" || flow.localPort != 49152 || flow.remoteAddress != "203.0.113.10" || flow.remotePort != 443 || flow.processID != 7 {
		t.Fatalf("decoded flow = %#v, ok=%v", flow, ok)
	}
}

func TestETWConnectCompletePayloadRetainsTCBIdentity(t *testing.T) {
	local := []byte{2, 0, 0xc0, 0x00, 192, 0, 2, 5}
	remote := []byte{2, 0, 1, 187, 203, 0, 113, 10}
	payload := make([]byte, 4+len(local)+4+len(remote)+4+4+4+8)
	offset := 0
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(len(local)))
	offset += 4
	copy(payload[offset:], local)
	offset += len(local)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(len(remote)))
	offset += 4
	copy(payload[offset:], remote)
	offset += len(remote)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 0)
	offset += 4
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 7)
	offset += 4
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 1)
	offset += 4
	binary.LittleEndian.PutUint64(payload[offset:offset+8], 0x1234)

	flow, ok := parseETWEndpointEvent(payload, false)
	if !ok || flow.connectionID != "tcb-1234" || flow.processID != 7 || flow.remotePort != 443 {
		t.Fatalf("decoded connect-complete flow = %#v, ok=%v", flow, ok)
	}
}

func TestETWSystemTimeConfiguration(t *testing.T) {
	properties, _ := newETWProperties([]uint16{'x', 0})
	if properties.Wnode.ClientContext != 2 {
		t.Fatalf("ETW clock = %d, want system time", properties.Wnode.ClientContext)
	}
	if properties.Wnode.Flags != etwNodeFlagTracedGUID {
		t.Fatalf("ETW WNODE flags = %#x, want traced-guid flag", properties.Wnode.Flags)
	}
}
