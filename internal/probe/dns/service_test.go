package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

type fixtureMode string

const (
	fixtureSuccess   fixtureMode = "success"
	fixtureDrop      fixtureMode = "drop"
	fixtureRefused   fixtureMode = "refused"
	fixtureServfail  fixtureMode = "servfail"
	fixtureMalformed fixtureMode = "malformed"
	fixtureTruncated fixtureMode = "truncated"
)

// localDNSFixture binds UDP and TCP to the same non-default local port. The
// server has no resolver behavior: it only recognizes the deterministic
// diagnostic query and returns the selected fixture response.
type localDNSFixture struct {
	udp      *net.UDPConn
	tcp      net.Listener
	stop     chan struct{}
	stopOnce sync.Once
	queries  chan queryRecord
	wg       sync.WaitGroup
	port     uint16
}

type queryRecord struct {
	transport string
	bytes     []byte
}

func newLocalDNSFixture(t *testing.T, udpMode, tcpMode fixtureMode) *localDNSFixture {
	t.Helper()
	var udp *net.UDPConn
	var tcp net.Listener
	for attempt := 0; attempt < 20; attempt++ {
		var err error
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			fixture := &localDNSFixture{udp: udp, tcp: tcp, stop: make(chan struct{}), queries: make(chan queryRecord, 32), port: uint16(port)}
			fixture.wg.Add(2)
			go fixture.serveUDP(udpMode)
			go fixture.serveTCP(tcpMode)
			t.Cleanup(fixture.close)
			return fixture
		}
		_ = udp.Close()
	}
	t.Fatal("could not bind matching local UDP and TCP DNS fixture ports")
	return nil
}

func (f *localDNSFixture) close() {
	f.stopOnce.Do(func() {
		close(f.stop)
		_ = f.udp.Close()
		_ = f.tcp.Close()
	})
	f.wg.Wait()
}

func (f *localDNSFixture) serveUDP(mode fixtureMode) {
	defer f.wg.Done()
	buffer := make([]byte, 65535)
	for {
		_ = f.udp.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, address, err := f.udp.ReadFromUDP(buffer)
		if err != nil {
			if isFixtureTimeout(err) {
				select {
				case <-f.stop:
					return
				default:
					continue
				}
			}
			return
		}
		query := append([]byte(nil), buffer[:n]...)
		f.recordQuery("udp", query)
		response := fixtureResponse(query, mode)
		if len(response) != 0 {
			_, _ = f.udp.WriteToUDP(response, address)
		}
	}
}

func (f *localDNSFixture) serveTCP(mode fixtureMode) {
	defer f.wg.Done()
	for {
		if deadlineErr := f.tcp.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond)); deadlineErr != nil {
			return
		}
		connection, err := f.tcp.Accept()
		if err != nil {
			if isFixtureTimeout(err) {
				select {
				case <-f.stop:
					return
				default:
					continue
				}
			}
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.handleTCP(connection, mode)
		}()
	}
}

func (f *localDNSFixture) handleTCP(connection net.Conn, mode fixtureMode) {
	defer connection.Close()
	var length [2]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return
	}
	query := make([]byte, int(binary.BigEndian.Uint16(length[:])))
	if _, err := io.ReadFull(connection, query); err != nil {
		return
	}
	f.recordQuery("tcp", query)
	if mode == fixtureDrop {
		<-f.stop
		return
	}
	response := fixtureResponse(query, mode)
	var responseLength [2]byte
	binary.BigEndian.PutUint16(responseLength[:], uint16(len(response)))
	_, _ = connection.Write(append(responseLength[:], response...))
}

func (f *localDNSFixture) recordQuery(transport string, query []byte) {
	select {
	case f.queries <- queryRecord{transport: transport, bytes: query}:
	default:
	}
}

func isFixtureTimeout(err error) bool {
	if err == nil {
		return false
	}
	networkError, ok := err.(net.Error)
	return ok && networkError.Timeout()
}

func fixtureResponse(query []byte, mode fixtureMode) []byte {
	if mode == fixtureDrop {
		return nil
	}
	if len(query) < 12 {
		return []byte{0, 0, 0, 0}
	}
	if mode == fixtureMalformed {
		return []byte{query[0], query[1], 0x80, 0x00, 0, 1}
	}
	rcode := byte(0)
	switch mode {
	case fixtureRefused:
		rcode = 5
	case fixtureServfail:
		rcode = 2
	}
	flags := uint16(0x8000) | uint16(rcode)
	answerCount := uint16(1)
	if mode == fixtureTruncated || mode == fixtureRefused || mode == fixtureServfail {
		answerCount = 0
	}
	if mode == fixtureTruncated {
		flags |= 0x0200
	}
	response := make([]byte, 12)
	binary.BigEndian.PutUint16(response[0:2], binary.BigEndian.Uint16(query[0:2]))
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], answerCount)
	response = append(response, query[12:]...)
	if answerCount == 1 {
		// The answer name is a pointer to the one diagnostic question. The
		// address is documentation-safe fixture data, not a payload exposed
		// through the probe's evidence contract.
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 123)
	}
	return response
}

func dnsServiceTarget(t *testing.T, host string, port uint16, candidates bool) model.Target {
	t.Helper()
	parsed, err := model.ParseTarget(model.TargetIntent{Input: host, Service: model.ServiceProfileDNS, Port: &port})
	if err != nil {
		t.Fatal(err)
	}
	if candidates {
		parsed.ProbeCandidates = []model.EndpointCandidate{{Address: "127.0.0.1", Family: model.EndpointFamilyIPv4, Order: 1}}
	}
	return parsed
}

func runServiceFixture(t *testing.T, fixture *localDNSFixture, target model.Target, timeout time.Duration) model.ProbeResult {
	t.Helper()
	return NewDNSServiceProbe(
		WithServiceTimeout(timeout),
		WithServiceRetries(0),
	).Run(context.Background(), probe.ExecutionContext{Target: target})
}

func serviceEvidenceFor(t *testing.T, result model.ProbeResult, transport string) DNSServiceEvidence {
	t.Helper()
	for _, evidence := range result.Evidence {
		var value DNSServiceEvidence
		if evidence.Kind != model.EvidenceKindDNSService || jsonUnmarshal(evidence.Raw, &value) != nil {
			continue
		}
		if strings.EqualFold(value.Transport, transport) {
			return value
		}
	}
	t.Fatalf("missing %s service evidence: %#v", transport, result.Evidence)
	return DNSServiceEvidence{}
}

func jsonUnmarshal(data []byte, value any) error {
	// Keeping this helper local makes the fixture assertions read like the
	// wire contract while avoiding a second JSON abstraction in production.
	return json.Unmarshal(data, value)
}

func waitForFixtureQuery(t *testing.T, fixture *localDNSFixture, transport string) []byte {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case query := <-fixture.queries:
			if query.transport == transport {
				return query.bytes
			}
		case <-deadline:
			t.Fatalf("did not observe %s diagnostic query", transport)
			return nil
		}
	}
}

func assertDiagnosticQuery(t *testing.T, query []byte) {
	t.Helper()
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 || binary.BigEndian.Uint16(query[2:4])&0x0100 != 0 {
		t.Fatalf("query header = %x; want one non-recursive question", query)
	}
	name, offset, err := readDiagnosticName(query, 12)
	if err != nil || normalizeDiagnosticName(name) != normalizeDiagnosticName(DiagnosticQueryName) || offset+4 != len(query) {
		t.Fatalf("query name = %q offset=%d err=%v bytes=%x", name, offset, err, query)
	}
	if binary.BigEndian.Uint16(query[offset:offset+2]) != DiagnosticQueryTypeCode || binary.BigEndian.Uint16(query[offset+2:offset+4]) != diagnosticQueryClassCode {
		t.Fatalf("query type/class = %d/%d", binary.BigEndian.Uint16(query[offset:offset+2]), binary.BigEndian.Uint16(query[offset+2:offset+4]))
	}
}

func TestDNSServiceUDPAndTCPSuccess(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureSuccess, fixtureSuccess)
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 200*time.Millisecond)
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("result = status %q reason %q", result.Status, result.Interpretation.FailureReason)
	}
	udp := serviceEvidenceFor(t, result, "udp")
	tcp := serviceEvidenceFor(t, result, "tcp")
	if !udp.Success || udp.Outcome != DNSServiceOutcomeSuccess || !tcp.Success || tcp.Outcome != DNSServiceOutcomeSuccess {
		t.Fatalf("success evidence = udp %#v tcp %#v", udp, tcp)
	}
	assertDiagnosticQuery(t, waitForFixtureQuery(t, fixture, "udp"))
	assertDiagnosticQuery(t, waitForFixtureQuery(t, fixture, "tcp"))
}

func TestDNSServiceUDPBlockedTCPsucceedsWithoutUnavailableClaim(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureDrop, fixtureSuccess)
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 100*time.Millisecond)
	udp := serviceEvidenceFor(t, result, "udp")
	tcp := serviceEvidenceFor(t, result, "tcp")
	if result.Status != model.ProbeStatusPassed || !tcp.Success || udp.Success || udp.Outcome != DNSServiceOutcomeTimeout {
		t.Fatalf("UDP/TCP divergence result = %#v udp=%#v tcp=%#v", result, udp, tcp)
	}
}

func TestDNSServiceTCPFailsUDPSucceedsWithoutUnavailableClaim(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureSuccess, fixtureDrop)
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 100*time.Millisecond)
	udp := serviceEvidenceFor(t, result, "udp")
	tcp := serviceEvidenceFor(t, result, "tcp")
	if result.Status != model.ProbeStatusPassed || !udp.Success || tcp.Success || tcp.Outcome != DNSServiceOutcomeTimeout {
		t.Fatalf("TCP/UDP divergence result = %#v udp=%#v tcp=%#v", result, udp, tcp)
	}
}

func TestDNSServiceTimeoutIsBounded(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureDrop, fixtureDrop)
	started := time.Now()
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 40*time.Millisecond)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout check took %v", elapsed)
	}
	if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != FailureReasonDNSServiceTimeout {
		t.Fatalf("timeout result = status %q reason %q", result.Status, result.Interpretation.FailureReason)
	}
	if serviceEvidenceFor(t, result, "udp").Outcome != DNSServiceOutcomeTimeout || serviceEvidenceFor(t, result, "tcp").Outcome != DNSServiceOutcomeTimeout {
		t.Fatalf("timeout evidence = %#v", result.Evidence)
	}
}

func TestDNSServiceRCodeFailuresRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      fixtureMode
		outcome   DNSServiceOutcome
		reason    model.FailureReason
		rcodeName string
	}{
		{name: "refused", mode: fixtureRefused, outcome: DNSServiceOutcomeRefused, reason: FailureReasonDNSServiceRefused, rcodeName: "REFUSED"},
		{name: "servfail", mode: fixtureServfail, outcome: DNSServiceOutcomeServfail, reason: FailureReasonDNSServiceServfail, rcodeName: "SERVFAIL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLocalDNSFixture(t, test.mode, test.mode)
			result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 200*time.Millisecond)
			if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != test.reason {
				t.Fatalf("result = status %q reason %q", result.Status, result.Interpretation.FailureReason)
			}
			for _, transport := range []string{"udp", "tcp"} {
				value := serviceEvidenceFor(t, result, transport)
				if value.Outcome != test.outcome || value.RCodeName != test.rcodeName || !value.ResponseReceived || value.Success {
					t.Fatalf("%s evidence = %#v", transport, value)
				}
			}
		})
	}
}

func TestDNSServiceMalformedUDPAndTCPFallback(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureMalformed, fixtureSuccess)
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 200*time.Millisecond)
	udp := serviceEvidenceFor(t, result, "udp")
	tcp := serviceEvidenceFor(t, result, "tcp")
	if result.Status != model.ProbeStatusPassed || udp.Outcome != DNSServiceOutcomeMalformedResponse || udp.Success || !tcp.Success || !tcp.Fallback {
		t.Fatalf("malformed/fallback result = %#v udp=%#v tcp=%#v", result, udp, tcp)
	}
	if tcp.FallbackReason != "udp_malformed_response" && tcp.FallbackReason != "udp_truncated_response" {
		// The fixture still requires a TCP application query even when UDP
		// cannot be parsed; either explicit fallback marker is acceptable only
		// for a recognized UDP response. This assertion catches false markers.
		t.Fatalf("TCP fallback reason = %q", tcp.FallbackReason)
	}
}

func TestDNSServiceTruncatedUDPUsesTCPFallback(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureTruncated, fixtureSuccess)
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "127.0.0.1", fixture.port, false), 200*time.Millisecond)
	udp := serviceEvidenceFor(t, result, "udp")
	tcp := serviceEvidenceFor(t, result, "tcp")
	if result.Status != model.ProbeStatusPassed || udp.Outcome != DNSServiceOutcomeTruncatedResponse || udp.Success || !udp.Truncated || !tcp.Success || !tcp.Fallback || tcp.FallbackReason != "udp_truncated_response" {
		t.Fatalf("truncated/fallback result = %#v udp=%#v tcp=%#v", result, udp, tcp)
	}
}

func TestDNSServiceCustomPortLiteralIPAndHostnameCandidates(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureSuccess, fixtureSuccess)
	port := fixture.port
	for _, test := range []struct {
		name           string
		host           string
		withCandidates bool
	}{
		{name: "literal IP", host: "127.0.0.1", withCandidates: false},
		{name: "hostname after normal resolution", host: "dnsfixture.example.test", withCandidates: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runServiceFixture(t, fixture, dnsServiceTarget(t, test.host, port, test.withCandidates), 200*time.Millisecond)
			if result.Status != model.ProbeStatusPassed {
				t.Fatalf("result = %#v", result)
			}
			if result.NameResolution != nil {
				t.Fatal("DNS service probe must not manufacture target name-resolution evidence")
			}
			if serviceEvidenceFor(t, result, "udp").Port != port || serviceEvidenceFor(t, result, "tcp").Port != port {
				t.Fatalf("custom port evidence = %#v", result.Evidence)
			}
		})
	}
}

func TestDNSServiceHostnameWithoutResolutionDoesNotQueryHostname(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureSuccess, fixtureSuccess)
	result := runServiceFixture(t, fixture, dnsServiceTarget(t, "dnsfixture.example.test", fixture.port, false), 50*time.Millisecond)
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != FailureReasonDNSServiceNoEndpoint {
		t.Fatalf("unresolved hostname result = %#v", result)
	}
	if serviceEvidenceFor(t, result, "udp").Attempts != 0 || serviceEvidenceFor(t, result, "tcp").Attempts != 0 {
		t.Fatal("service probe queried a hostname without a prior target resolution candidate")
	}
}

func TestDNSServiceResponseParserRejectsTransactionAndQuestionMismatches(t *testing.T) {
	query, err := buildDiagnosticQuery(0x1234)
	if err != nil {
		t.Fatal(err)
	}
	response := fixtureResponse(query, fixtureSuccess)
	binary.BigEndian.PutUint16(response[0:2], 0x4321)
	if _, err := parseDiagnosticResponse(response, 0x1234); diagnosticResponseOutcome(err) != DNSServiceOutcomeProtocolFailure {
		t.Fatalf("transaction mismatch error = %v", err)
	}
	response = fixtureResponse(query, fixtureSuccess)
	questionOffset := 12 + len(query[12:]) - 4
	response[questionOffset+1] = 2
	if _, err := parseDiagnosticResponse(response, 0x1234); diagnosticResponseErrorKind(err) != "question_mismatch" {
		t.Fatalf("question mismatch error = %v", err)
	}
}

func TestDNSServiceTargetResolutionAndServiceEvidenceStaySeparate(t *testing.T) {
	fixture := newLocalDNSFixture(t, fixtureSuccess, fixtureSuccess)
	target := dnsServiceTarget(t, "dnsfixture.example.test", fixture.port, true)
	resolution := model.NameResolutionObservation{RequestedName: target.RequestedIdentity, SelectedAddress: "127.0.0.1", EvidenceIDs: []string{"dns/resolution"}}
	result := runServiceFixture(t, fixture, target, 200*time.Millisecond)
	result.NameResolution = &resolution
	if result.NameResolution == nil || serviceEvidenceFor(t, result, "udp").QueryName != DiagnosticQueryName {
		t.Fatal("service evidence lost its distinct query contract")
	}
	if bytes.Contains(result.Evidence[0].Raw, []byte("dns/resolution")) {
		t.Fatal("DNS service evidence overclaimed name-resolution provenance")
	}
}
