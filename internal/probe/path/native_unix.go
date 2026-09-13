//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris

package path

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

func observeNativeICMP(ctx context.Context, request Request) (Observation, error) {
	destination, address, err := nativeDestination(ctx, request.Target.RequestedIdentity)
	if err != nil {
		return Observation{}, err
	}
	if !address.IsValid() || !address.Is4() {
		return Observation{}, fmt.Errorf("%w: ICMP native observer requires an IPv4 destination", ErrUnsupported)
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}

	conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.IP(address.AsSlice())})
	if err != nil {
		if nativeUnsupported(err) {
			return Observation{}, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
		return Observation{}, err
	}
	defer conn.Close()
	if err := setICMPTTL(conn, int(request.TTL)); err != nil {
		if nativeUnsupported(err) {
			return Observation{}, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
		return Observation{}, err
	}

	id := uint16(os.Getpid())
	sequence := uint16((int(request.TTL) << 8) ^ (request.Attempt & 0xff))
	packet := icmpEchoPacket(id, sequence)
	started := time.Now()
	if _, err := conn.Write(packet); err != nil {
		if nativeUnsupported(err) {
			return Observation{}, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
		return Observation{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(request.Timeout))
	}

	buffer := make([]byte, 1500)
	for {
		count, source, readErr := conn.ReadFromIP(buffer)
		if readErr != nil {
			if ctx.Err() != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return Observation{}, nil
				}
				return Observation{}, ctx.Err()
			}
			if isNetTimeout(readErr) {
				return Observation{}, nil
			}
			return Observation{}, readErr
		}
		packet := buffer[:count]
		if len(packet) >= 20 && packet[0]>>4 == 4 {
			headerLength := int(packet[0]&0x0f) * 4
			if headerLength <= len(packet) {
				packet = packet[headerLength:]
			}
		}
		response, reached, matched := parseICMPResponse(packet, id, sequence)
		if !matched {
			continue
		}
		responder := destination
		if source != nil && source.IP != nil {
			if parsed, ok := netip.AddrFromSlice(source.IP); ok {
				responder = model.NormalizeAddr(parsed).String()
			}
		}
		return Observation{
			Responders: []model.PathResponder{{
				Address: responder, RTTMS: time.Since(started).Milliseconds(),
				Response: response, DestinationReached: reached,
			}},
			DestinationReached: reached,
		}, nil
	}
}

func setICMPTTL(conn *net.IPConn, ttl int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); err != nil {
		return err
	}
	return controlErr
}

func observeNativeTCP(ctx context.Context, request Request) (Observation, error) {
	destination, address, err := nativeDestination(ctx, request.Target.RequestedIdentity)
	if err != nil {
		return Observation{}, err
	}
	port := request.Target.Port
	if port == 0 {
		return Observation{}, errors.New("TCP path target port is required")
	}
	network := "tcp"
	if address.IsValid() {
		if address.Is4() {
			network = "tcp4"
		} else {
			network = "tcp6"
		}
	}
	host := strings.TrimPrefix(strings.TrimSuffix(request.Target.RequestedIdentity, "]"), "[")
	dialer := net.Dialer{Timeout: request.Timeout}
	dialer.Control = func(network, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, int(request.TTL))
			} else {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, int(request.TTL))
			}
		}); err != nil {
			return err
		}
		return controlErr
	}
	started := time.Now()
	conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(port))))
	if dialErr == nil {
		defer conn.Close()
		responder := endpointHost(conn.RemoteAddr())
		if responder == "" {
			responder = destination
		}
		return Observation{
			Responders: []model.PathResponder{{
				Address: responder, RTTMS: time.Since(started).Milliseconds(),
				Response: "tcp_connected", DestinationReached: true,
			}},
			DestinationReached: true,
		}, nil
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Observation{}, nil
		}
		return Observation{}, ctx.Err()
	}
	if nativeUnsupported(dialErr) {
		return Observation{}, fmt.Errorf("%w: %v", ErrUnsupported, dialErr)
	}
	// A TCP RST/refusal is a response from the destination, not an
	// unobservable intermediate hop. It proves that the endpoint was reached
	// even though the requested application port is not accepting connections.
	if connectionRefused(dialErr) || connectionReset(dialErr) {
		responder := destination
		if opErr := new(net.OpError); errors.As(dialErr, &opErr) && opErr.Addr != nil {
			if host := endpointHost(opErr.Addr); host != "" {
				responder = host
			}
		}
		response := "tcp_refused"
		if connectionReset(dialErr) {
			response = "tcp_reset"
		}
		return Observation{
			Responders: []model.PathResponder{{
				Address: responder, RTTMS: time.Since(started).Milliseconds(),
				Response: response, DestinationReached: true,
			}},
			DestinationReached: true,
		}, nil
	}
	// A timeout, unreachable network, or filtered SYN is simply an
	// unobservable TTL. The separate TCP connectivity probe owns application
	// failure diagnosis.
	return Observation{}, nil
}

func nativeDestination(ctx context.Context, host string) (string, netip.Addr, error) {
	destination, address, _ := normalizeDestinationAddress(host)
	if address.IsValid() {
		return destination, address, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "", host)
	if err != nil {
		return destination, netip.Addr{}, err
	}
	for _, candidate := range addresses {
		candidate = model.NormalizeAddr(candidate)
		if candidate.Is4() {
			return candidate.String(), candidate, nil
		}
	}
	if len(addresses) != 0 {
		return destination, model.NormalizeAddr(addresses[0]), nil
	}
	return destination, netip.Addr{}, errors.New("path destination has no address")
}

func icmpEchoPacket(id, sequence uint16) []byte {
	packet := make([]byte, 20)
	packet[0] = 8 // Echo request.
	binary.BigEndian.PutUint16(packet[4:6], id)
	binary.BigEndian.PutUint16(packet[6:8], sequence)
	copy(packet[8:], []byte("tadori-path"))
	binary.BigEndian.PutUint16(packet[2:4], checksum(packet))
	return packet
}

func checksum(packet []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(packet); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	if len(packet)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func parseICMPResponse(packet []byte, id, sequence uint16) (string, bool, bool) {
	if len(packet) < 8 {
		return "", false, false
	}
	switch packet[0] {
	case 0: // Echo reply.
		if binary.BigEndian.Uint16(packet[4:6]) != id || binary.BigEndian.Uint16(packet[6:8]) != sequence {
			return "", false, false
		}
		return "icmp_echo_reply", true, true
	case 3, 11: // Destination unreachable or time exceeded.
		payload := packet[8:]
		if len(payload) >= 20 && payload[0]>>4 == 4 {
			headerLength := int(payload[0]&0x0f) * 4
			if headerLength <= len(payload) {
				payload = payload[headerLength:]
			}
		}
		if len(payload) < 8 || payload[0] != 8 || binary.BigEndian.Uint16(payload[4:6]) != id || binary.BigEndian.Uint16(payload[6:8]) != sequence {
			return "", false, false
		}
		if packet[0] == 11 {
			return "icmp_time_exceeded", false, true
		}
		return "icmp_destination_unreachable", false, true
	default:
		return "", false, false
	}
}

func nativeUnsupported(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOPROTOOPT) ||
		strings.Contains(strings.ToLower(err.Error()), "raw socket")
}

func connectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

func connectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "connection reset")
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
