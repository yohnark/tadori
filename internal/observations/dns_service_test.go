package observations

import (
	"encoding/json"
	"testing"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe/dns"
)

func TestBuildDNSApplicationObservationKeepsUDPAndTCPDivergence(t *testing.T) {
	target := profileTarget(t, "127.0.0.1:5353", model.ServiceProfileDNS)
	udp := dns.DNSServiceEvidence{
		Transport: "udp", RequestedEndpoint: "127.0.0.1:5353", ResolvedAddress: "127.0.0.1", Endpoint: "127.0.0.1:5353", Port: 5353,
		QueryName: dns.DiagnosticQueryName, QueryType: dns.DiagnosticQueryType, TransactionID: 11, QueryBytes: 35,
		ResponseReceived: true, ResponseBytes: 51, QuestionCount: 1, AnswerCount: 1, RCodeName: "NOERROR", Outcome: dns.DNSServiceOutcomeSuccess, Success: true, Attempts: 1,
	}
	tcp := dns.DNSServiceEvidence{
		Transport: "tcp", RequestedEndpoint: "127.0.0.1:5353", ResolvedAddress: "127.0.0.1", Endpoint: "127.0.0.1:5353", Port: 5353,
		QueryName: dns.DiagnosticQueryName, QueryType: dns.DiagnosticQueryType, TransactionID: 11, QueryBytes: 35,
		ResponseReceived: true, ResponseBytes: 35, QuestionCount: 1, RCode: 5, RCodeName: "REFUSED", Outcome: dns.DNSServiceOutcomeRefused, Attempts: 1,
	}
	result := model.ProbeResult{
		Name: "dns_service", Status: model.ProbeStatusPassed,
		Interpretation: model.ProbeInterpretation{FailureReason: model.FailureReasonNone, Layer: model.LayerDNS, FaultDomain: model.FaultDomainDNS},
		Evidence: []model.Evidence{
			{ID: "dns-service/udp", Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustRaw(t, udp)},
			{ID: "dns-service/tcp", Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustRaw(t, tcp)},
		},
	}

	got := Build(target, []model.ProbeResult{result})
	if got.Application.DNS == nil {
		t.Fatal("missing canonical DNS application observation")
	}
	dnsObservation := got.Application.DNS
	if dnsObservation.Result != model.DNSApplicationResultPartial || !dnsObservation.Divergence {
		t.Fatalf("DNS result/divergence = %q/%v", dnsObservation.Result, dnsObservation.Divergence)
	}
	if dnsObservation.UDP.Outcome != string(dns.DNSServiceOutcomeSuccess) || dnsObservation.TCP.Outcome != string(dns.DNSServiceOutcomeRefused) {
		t.Fatalf("UDP/TCP outcomes = %q/%q", dnsObservation.UDP.Outcome, dnsObservation.TCP.Outcome)
	}
	if dnsObservation.TCP.FailureReason != dns.FailureReasonDNSServiceRefused || got.Application.FailureReason != model.FailureReasonNone {
		t.Fatalf("failure projection = tcp:%q application:%q", dnsObservation.TCP.FailureReason, got.Application.FailureReason)
	}
	if containsString(got.NameResolution.EvidenceIDs, "dns-service/udp") || containsString(got.NameResolution.EvidenceIDs, "dns-service/tcp") {
		t.Fatalf("DNS service evidence contaminated name resolution: %#v", got.NameResolution)
	}
	if got.Application.Result != model.HTTPResultPartial || !got.Application.ResponseReceived || !got.Application.RequestAttempted {
		t.Fatalf("application envelope = %#v", got.Application)
	}

	encoded, err := json.Marshal(got.Application)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsBytes(encoded, []byte("192.0.2.123")) {
		t.Fatalf("canonical application unexpectedly contains arbitrary response payload: %s", encoded)
	}
}

func TestBuildDNSApplicationObservationMapsBothTransportFailures(t *testing.T) {
	target := profileTarget(t, "192.0.2.53:5300", model.ServiceProfileDNS)
	makeEvidence := func(id, transport string, outcome dns.DNSServiceOutcome) model.Evidence {
		value := dns.DNSServiceEvidence{
			Transport: transport, RequestedEndpoint: "192.0.2.53:5300", Port: 5300,
			QueryName: dns.DiagnosticQueryName, QueryType: dns.DiagnosticQueryType, Attempts: 1,
			ResponseReceived: true, RCodeName: "SERVFAIL", Outcome: outcome,
		}
		return model.Evidence{ID: id, Kind: model.EvidenceKindDNSService, Source: "dns-service-wire", Raw: mustRaw(t, value)}
	}
	got := Build(target, []model.ProbeResult{{Name: "dns_service", Status: model.ProbeStatusFailed, Evidence: []model.Evidence{
		makeEvidence("dns-service/udp", "udp", dns.DNSServiceOutcomeServfail),
		makeEvidence("dns-service/tcp", "tcp", dns.DNSServiceOutcomeServfail),
	}}})
	if got.Application.DNS == nil || got.Application.DNS.Result != model.DNSApplicationResultFailure {
		t.Fatalf("DNS failure observation = %#v", got.Application.DNS)
	}
	if got.Application.DNS.UDP.FailureReason != dns.FailureReasonDNSServiceServfail || got.Application.DNS.TCP.FailureReason != dns.FailureReasonDNSServiceServfail || got.Application.FailureReason != dns.FailureReasonDNSServiceServfail {
		t.Fatalf("SERVFAIL reasons = app:%q udp:%q tcp:%q", got.Application.FailureReason, got.Application.DNS.UDP.FailureReason, got.Application.DNS.TCP.FailureReason)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsBytes(value, want []byte) bool {
	for index := 0; index+len(want) <= len(value); index++ {
		match := true
		for offset := range want {
			if value[index+offset] != want[offset] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
