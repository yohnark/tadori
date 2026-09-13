package diagnosis

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func failed(name string, reason model.FailureReason, layer model.Layer, domain model.FaultDomain, ids ...string) model.ProbeResult {
	evidence := make([]model.Evidence, 0, len(ids))
	for _, id := range ids {
		evidence = append(evidence, model.Evidence{ID: id, Kind: model.EvidenceKindUnknown})
	}
	return model.ProbeResult{
		Name:     name,
		Status:   model.ProbeStatusFailed,
		Evidence: evidence,
		Interpretation: model.ProbeInterpretation{
			FailureReason: reason,
			Layer:         layer,
			FaultDomain:   domain,
		},
	}
}

func passed(name string, layer model.Layer) model.ProbeResult {
	return model.ProbeResult{
		Name:   name,
		Status: model.ProbeStatusPassed,
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         layer,
		},
	}
}

func TestDiagnoseLocalAndRouteBoundaries(t *testing.T) {
	t.Run("unusable interface", func(t *testing.T) {
		got := Diagnose([]model.ProbeResult{
			failed("interface", model.FailureReasonInterfaceDown, model.LayerInterface, model.FaultDomainLocal, "iface-2", "iface-1"),
			failed("ip", model.FailureReasonNoIPAddress, model.LayerIPConfiguration, model.FaultDomainLocal, "ip-1"),
		})
		want := []model.DiagnosticFinding{{
			FailureReason: model.FailureReasonInterfaceDown,
			Layer:         model.LayerInterface,
			FaultDomain:   model.FaultDomainLocal,
			ProbeNames:    []string{"interface"},
			EvidenceIDs:   []string{"iface-1", "iface-2"},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected local diagnosis: %#v", got)
		}
	})

	t.Run("route is preferred to later evidence", func(t *testing.T) {
		got := Diagnose([]model.ProbeResult{
			failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport),
			failed("route", model.FailureReasonNoRoute, model.LayerRoute, model.FaultDomainRouting, "route-1"),
		})
		if len(got) != 1 || got[0].FailureReason != model.FailureReasonNoRoute || got[0].Layer != model.LayerRoute {
			t.Fatalf("route did not win: %#v", got)
		}
	})

	t.Run("downstream success rejects contradictory route failure", func(t *testing.T) {
		got := Diagnose([]model.ProbeResult{
			failed("route", model.FailureReasonNoRoute, model.LayerRoute, model.FaultDomainRouting),
			passed("tcp", model.LayerTCP),
		})
		if len(got) != 0 {
			t.Fatalf("route failure overrode successful transport evidence: %#v", got)
		}
	})
}

func TestDiagnoseDNSRulesAndContradictions(t *testing.T) {
	t.Run("NXDOMAIN is more specific than resolver timeout", func(t *testing.T) {
		got := Diagnose([]model.ProbeResult{
			failed("dns-timeout", model.FailureReasonDNSTimeout, model.LayerDNS, model.FaultDomainDNS, "dns-timeout"),
			failed("dns-answer", model.FailureReasonDNSNXDomain, model.LayerDNS, model.FaultDomainDNS, "dns-answer"),
		})
		if len(got) != 1 || got[0].FailureReason != model.FailureReasonDNSNXDomain || got[0].Layer != model.LayerDNS {
			t.Fatalf("unexpected DNS diagnosis: %#v", got)
		}
	})

	t.Run("a DNS success contradicts a DNS failure", func(t *testing.T) {
		got := Diagnose([]model.ProbeResult{
			failed("dns", model.FailureReasonDNSTimeout, model.LayerDNS, model.FaultDomainDNS),
			passed("dns-retry", model.LayerDNS),
		})
		if len(got) != 0 {
			t.Fatalf("contradictory DNS evidence was over-interpreted: %#v", got)
		}
	})
}

func TestDiagnoseTransportTLSHTTPBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		probes []model.ProbeResult
		want   model.FailureReason
		layer  model.Layer
		domain model.FaultDomain
	}{
		{
			name: "DNS success plus TCP timeout",
			probes: []model.ProbeResult{
				passed("dns", model.LayerDNS),
				failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport),
			},
			want: model.FailureReasonTCPTimeout, layer: model.LayerTCP, domain: model.FaultDomainTransport,
		},
		{
			name: "DNS success plus TCP refused",
			probes: []model.ProbeResult{
				passed("dns", model.LayerDNS),
				failed("tcp", model.FailureReasonTCPConnectionRefused, model.LayerTCP, model.FaultDomainTransport),
			},
			want: model.FailureReasonTCPConnectionRefused, layer: model.LayerTCP, domain: model.FaultDomainTransport,
		},
		{
			name: "TCP success plus TLS failure",
			probes: []model.ProbeResult{
				passed("tcp", model.LayerTCP),
				failed("tls", model.FailureReasonTLSHandshakeFailure, model.LayerTLS, model.FaultDomainTLS),
			},
			want: model.FailureReasonTLSHandshakeFailure, layer: model.LayerTLS, domain: model.FaultDomainTLS,
		},
		{
			name: "TLS success contradicts TCP failure",
			probes: []model.ProbeResult{
				failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport),
				passed("tls", model.LayerTLS),
			},
			want: model.FailureReasonNone, layer: model.LayerUnknown, domain: model.FaultDomainUnknown,
		},
		{
			name: "TLS success plus HTTP status",
			probes: []model.ProbeResult{
				passed("tls", model.LayerTLS),
				failed("http", model.FailureReasonHTTPStatusCode, model.LayerHTTP, model.FaultDomainHTTP),
			},
			want: model.FailureReasonHTTPStatusCode, layer: model.LayerHTTP, domain: model.FaultDomainHTTP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Diagnose(test.probes)
			if test.want == model.FailureReasonNone {
				if len(got) != 0 {
					t.Fatalf("contradictory evidence was over-interpreted: %#v", got)
				}
				return
			}
			if len(got) == 0 || got[0].FailureReason != test.want || got[0].Layer != test.layer || got[0].FaultDomain != test.domain {
				t.Fatalf("unexpected diagnosis: %#v", got)
			}
		})
	}
}

func TestDiagnoseGatewayIsSupportingEvidence(t *testing.T) {
	got := Diagnose([]model.ProbeResult{
		failed("gateway", model.FailureReasonGatewayUnreachable, model.LayerGateway, model.FaultDomainGateway, "gw-1"),
		failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport, "tcp-1"),
	})
	if len(got) != 2 || got[0].FailureReason != model.FailureReasonTCPTimeout || got[1].FailureReason != model.FailureReasonGatewayUnreachable {
		t.Fatalf("gateway support was not represented deterministically: %#v", got)
	}

	got = Diagnose([]model.ProbeResult{
		failed("gateway", model.FailureReasonGatewayUnreachable, model.LayerGateway, model.FaultDomainGateway),
		passed("tcp", model.LayerTCP),
	})
	if len(got) != 0 {
		t.Fatalf("gateway failure overrode successful path: %#v", got)
	}
}

func TestDiagnoseDoesNotReportGatewayFailureForOnLinkRoute(t *testing.T) {
	onLinkGateway := failed("gateway", model.FailureReasonGatewayUnreachable, model.LayerGateway, model.FaultDomainGateway, "gateway-on-link")
	onLinkGateway.Evidence[0] = model.Evidence{
		ID:   "gateway-on-link",
		Kind: model.EvidenceKindGatewayReachability,
		Raw:  json.RawMessage(`{"route_type":"gateway","destination":"10.0.10.0/24","effective_route":"on_link","gateway_tested":false}`),
	}
	got := Diagnose([]model.ProbeResult{onLinkGateway})
	if len(got) != 0 {
		t.Fatalf("on-link gateway failure became a finding: %#v", got)
	}
}

func TestDiagnoseProxyEvidenceDoesNotInventAProxyFault(t *testing.T) {
	got := Diagnose([]model.ProbeResult{
		failed("direct-tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport),
		passed("proxy-config", model.LayerProxy),
	})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPTimeout || got[0].FaultDomain == model.FaultDomainProxy {
		t.Fatalf("proxy-required behavior was treated as a proxy fault: %#v", got)
	}
}

func TestDiagnoseRetainsEnterpriseCrossPathReasonsWithSupportingConfiguration(t *testing.T) {
	proxyConfiguration := passed("proxy-config", model.LayerProxy)
	proxyConfiguration.Evidence = []model.Evidence{{Kind: model.EvidenceKindWinINETProxy, ID: "wininet-config"}}
	for _, test := range []struct {
		name   string
		reason model.FailureReason
		layer  model.Layer
		domain model.FaultDomain
	}{
		{name: "connect denied", reason: model.FailureReasonProxyConnectDenied, layer: model.LayerProxy, domain: model.FaultDomainProxy},
		{name: "authentication", reason: model.FailureReasonProxyAuthenticationRequired, layer: model.LayerProxy, domain: model.FaultDomainProxy},
		{name: "direct egress policy", reason: model.FailureReasonDirectEgressRestricted, layer: model.LayerNetwork, domain: model.FaultDomainPolicy},
		{name: "TLS interception", reason: model.FailureReasonTLSInterceptionSuspected, layer: model.LayerTLS, domain: model.FaultDomainTLS},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Diagnose([]model.ProbeResult{
				failed("windows-enterprise", test.reason, test.layer, test.domain, "enterprise-evidence"),
				proxyConfiguration,
			})
			if len(got) != 1 || got[0].FailureReason != test.reason || got[0].Layer != test.layer || got[0].FaultDomain != test.domain {
				t.Fatalf("diagnosis = %#v", got)
			}
		})
	}
}

func TestDiagnoseDoesNotHideComparativeEnterpriseFindingsBehindSinglePathSuccess(t *testing.T) {
	for _, test := range []struct {
		name    string
		reason  model.FailureReason
		layer   model.Layer
		domain  model.FaultDomain
		success model.Layer
	}{
		{name: "direct egress policy", reason: model.FailureReasonDirectEgressRestricted, layer: model.LayerNetwork, domain: model.FaultDomainPolicy, success: model.LayerHTTP},
		{name: "route difference", reason: model.FailureReasonEffectiveRouteDifference, layer: model.LayerRoute, domain: model.FaultDomainRouting, success: model.LayerTCP},
		{name: "TLS trust mismatch", reason: model.FailureReasonTLSTrustStoreMismatch, layer: model.LayerTLS, domain: model.FaultDomainTLS, success: model.LayerTLS},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Diagnose([]model.ProbeResult{
				failed("windows-enterprise", test.reason, test.layer, test.domain, "enterprise-evidence"),
				passed("single-path-success", test.success),
			})
			if len(got) != 1 || got[0].FailureReason != test.reason {
				t.Fatalf("diagnosis = %#v", got)
			}
		})
	}
}

func TestDiagnosePrefersSpecificEnterpriseProxyAndPolicyFindings(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason model.FailureReason
		layer  model.Layer
		domain model.FaultDomain
	}{
		{name: "proxy authentication", reason: model.FailureReasonProxyAuthenticationRequired, layer: model.LayerProxy, domain: model.FaultDomainProxy},
		{name: "connect denied", reason: model.FailureReasonProxyConnectDenied, layer: model.LayerProxy, domain: model.FaultDomainProxy},
		{name: "direct egress policy", reason: model.FailureReasonDirectEgressRestricted, layer: model.LayerNetwork, domain: model.FaultDomainPolicy},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Diagnose([]model.ProbeResult{
				failed("windows-enterprise", test.reason, test.layer, test.domain, "enterprise-evidence"),
				failed("proxy", model.FailureReasonProxyUnavailable, model.LayerProxy, model.FaultDomainProxy, "proxy-evidence"),
				failed("tcp", model.FailureReasonNetworkUnreachable, model.LayerNetwork, model.FaultDomainNetwork, "tcp-evidence"),
			})
			if len(got) != 1 || got[0].FailureReason != test.reason {
				t.Fatalf("diagnosis = %#v", got)
			}
		})
	}
}

func TestDiagnoseIgnoresICMPOnlyFailure(t *testing.T) {
	got := Diagnose([]model.ProbeResult{
		failed("icmp", model.FailureReasonICMPFailure, model.LayerICMP, model.FaultDomainICMP, "icmp-1"),
	})
	if got != nil {
		t.Fatalf("ICMP-only failure became a connectivity diagnosis: %#v", got)
	}

	got = Diagnose([]model.ProbeResult{
		failed("icmp-extension", model.FailureReason("icmp_vendor_detail"), model.LayerICMP, model.FaultDomainICMP),
	})
	if got != nil {
		t.Fatalf("ICMP extension failure became a connectivity diagnosis: %#v", got)
	}
}

func TestDiagnoseRetainsProbeSpecificExtensionReasons(t *testing.T) {
	tlsExpired := model.FailureReason("tls_certificate_expired")
	routeExtension := model.FailureReason("route_scope_mismatch")
	probes := []model.ProbeResult{
		failed("tls", tlsExpired, model.LayerTLS, model.FaultDomainTLS, "tls-evidence"),
		failed("route", routeExtension, model.LayerRoute, model.FaultDomainRouting, "route-evidence"),
	}

	got := Diagnose(probes)
	if len(got) != 1 {
		t.Fatalf("unexpected extension findings: %#v", got)
	}
	if got[0].FailureReason != routeExtension || got[0].Layer != model.LayerRoute || got[0].FaultDomain != model.FaultDomainRouting {
		t.Fatalf("extension reason was interpreted by text or input order: %#v", got[0])
	}
	if !reflect.DeepEqual(got[0].ProbeNames, []string{"route"}) || !reflect.DeepEqual(got[0].EvidenceIDs, []string{"route-evidence"}) {
		t.Fatalf("extension references were not retained: %#v", got[0])
	}

	// Layer precedence is independent of collector ordering. With no route
	// extension, the opaque TLS reason is retained verbatim and its canonical
	// interpretation is used unchanged.
	got = Diagnose([]model.ProbeResult{probes[0]})
	if len(got) != 1 || got[0].FailureReason != tlsExpired || got[0].Layer != model.LayerTLS || got[0].FaultDomain != model.FaultDomainTLS {
		t.Fatalf("TLS extension reason was not retained: %#v", got)
	}
	got = Diagnose([]model.ProbeResult{
		probes[0],
		func() model.ProbeResult {
			result := failed("tls-retry", tlsExpired, model.LayerTLS, model.FaultDomainTLS, "tls-evidence-2")
			result.Status = model.ProbeStatusError
			return result
		}(),
	})
	if len(got) != 1 || !reflect.DeepEqual(got[0].ProbeNames, []string{"tls", "tls-retry"}) || !reflect.DeepEqual(got[0].EvidenceIDs, []string{"tls-evidence", "tls-evidence-2"}) {
		t.Fatalf("extension references were not aggregated: %#v", got)
	}

	reversed := Diagnose([]model.ProbeResult{probes[1], probes[0]})
	if len(reversed) != 1 || reversed[0].FailureReason != routeExtension {
		t.Fatalf("extension precedence was not deterministic: %#v", reversed)
	}
}

func TestDiagnoseMixedExtensionAndBuiltInUseLayerPrecedence(t *testing.T) {
	routeExtension := model.FailureReason("route_scope_mismatch")
	route := failed("route", routeExtension, model.LayerRoute, model.FaultDomainRouting, "route-evidence")
	tls := failed("tls", model.FailureReasonTLSHandshakeFailure, model.LayerTLS, model.FaultDomainTLS, "tls-evidence")
	for _, probes := range [][]model.ProbeResult{{route, tls}, {tls, route}} {
		got := Diagnose(probes)
		if len(got) != 1 || got[0].FailureReason != routeExtension || got[0].Layer != model.LayerRoute || got[0].FaultDomain != model.FaultDomainRouting {
			t.Fatalf("lower-layer extension was hidden by built-in TLS rule: %#v", got)
		}
		if !reflect.DeepEqual(got[0].ProbeNames, []string{"route"}) || !reflect.DeepEqual(got[0].EvidenceIDs, []string{"route-evidence"}) {
			t.Fatalf("wrong mixed-rule references: %#v", got[0])
		}
	}
}

func TestDiagnoseUsesCanonicalReasonAndStableReferences(t *testing.T) {
	probes := []model.ProbeResult{
		failed("z-tcp", model.FailureReasonTCPConnectionReset, model.LayerUnknown, model.FaultDomainUnknown, "e-2", "e-1"),
		failed("a-tcp", model.FailureReasonTCPConnectionReset, model.LayerTCP, model.FaultDomainTransport, "e-1"),
	}
	got := Diagnose(probes)
	want := []model.DiagnosticFinding{{
		FailureReason: model.FailureReasonTCPConnectionReset,
		Layer:         model.LayerTCP,
		FaultDomain:   model.FaultDomainTransport,
		ProbeNames:    []string{"a-tcp", "z-tcp"},
		EvidenceIDs:   []string{"e-1", "e-2"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unstable or non-canonical diagnosis: %#v", got)
	}

	if got := DiagnoseReport(model.DiagnosticReport{Probes: probes}); len(got.Findings) != 1 || got.Findings[0].FailureReason != model.FailureReasonTCPConnectionReset {
		t.Fatalf("report application failed: %#v", got)
	}
}

func TestDiagnoseCorrelatesTCPPathDestinationSuccessWithRequestedPort(t *testing.T) {
	raw, err := json.Marshal(model.PathObservation{
		Status:                  model.PathObservationStatusObserved,
		Protocol:                model.PathProtocolTCP,
		Destination:             "198.51.100.10",
		DestinationPort:         8443,
		PortAware:               true,
		MaxTTL:                  3,
		AttemptsPerTTL:          1,
		Hops:                    []model.PathHop{{TTL: 1, State: model.PathHopStateUnobservable}, {TTL: 2, State: model.PathHopStateUnobservable}, {TTL: 3, State: model.PathHopStateObserved, Responders: []model.PathResponder{{Address: "198.51.100.10", DestinationReached: true}}}},
		Segments:                []model.PathSegment{{Kind: model.PathSegmentUnobservable, FromTTL: 1, ToTTL: 2}},
		DestinationReached:      true,
		DestinationTCPConnected: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	pathResult := model.ProbeResult{
		Name:   "path",
		Target: model.NewTarget("198.51.100.10", 8443),
		Status: model.ProbeStatusPassed,
		Evidence: []model.Evidence{{
			ID:   "path/tcp",
			Kind: model.EvidenceKindPathObservation,
			Raw:  raw,
		}},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         model.LayerNetwork,
			FaultDomain:   model.FaultDomainNetwork,
		},
	}
	got := Diagnose([]model.ProbeResult{
		failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport, "tcp-1"),
		pathResult,
	})
	if got != nil {
		t.Fatalf("TCP path destination success was not used to contradict timeout: %#v", got)
	}

	// A response for another port cannot be correlated to this endpoint.
	otherPort := pathResult
	otherPort.Evidence = append([]model.Evidence(nil), pathResult.Evidence...)
	otherObservation := model.PathObservation{}
	if err := json.Unmarshal(raw, &otherObservation); err != nil {
		t.Fatal(err)
	}
	otherObservation.DestinationPort = 9443
	otherRaw, err := json.Marshal(otherObservation)
	if err != nil {
		t.Fatal(err)
	}
	otherPort.Evidence[0].Raw = otherRaw
	got = Diagnose([]model.ProbeResult{
		failed("tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport, "tcp-1"),
		otherPort,
	})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPTimeout {
		t.Fatalf("different TCP destination port was incorrectly correlated: %#v", got)
	}
}

func TestDiagnosePathICMPFailureNeverBecomesApplicationFailure(t *testing.T) {
	got := Diagnose([]model.ProbeResult{failed("path", model.FailureReasonICMPFailure, model.LayerICMP, model.FaultDomainICMP, "path/icmp")})
	if got != nil {
		t.Fatalf("ICMP path failure became a connectivity finding: %#v", got)
	}
}

func TestDiagnoseKeepsTCPRefusalFindingDespitePathDestinationResponse(t *testing.T) {
	raw, err := json.Marshal(model.PathObservation{
		Status:                  model.PathObservationStatusObserved,
		Protocol:                model.PathProtocolTCP,
		Destination:             "198.51.100.10",
		DestinationPort:         8443,
		PortAware:               true,
		MaxTTL:                  1,
		AttemptsPerTTL:          1,
		Hops:                    []model.PathHop{{TTL: 1, State: model.PathHopStateObserved, Responders: []model.PathResponder{{Address: "198.51.100.10", Response: "tcp_refused", DestinationReached: true}}}},
		Segments:                []model.PathSegment{{Kind: model.PathSegmentObservedResponder, FromTTL: 1, ToTTL: 1}},
		DestinationReached:      true,
		DestinationTCPConnected: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	pathResult := model.ProbeResult{
		Name:     "path",
		Target:   model.NewTarget("198.51.100.10", 8443),
		Status:   model.ProbeStatusPassed,
		Evidence: []model.Evidence{{ID: "path/tcp", Kind: model.EvidenceKindPathObservation, Raw: raw}},
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonNone,
			Layer:         model.LayerNetwork,
			FaultDomain:   model.FaultDomainNetwork,
		},
	}
	got := Diagnose([]model.ProbeResult{failed("tcp", model.FailureReasonTCPConnectionRefused, model.LayerTCP, model.FaultDomainTransport), pathResult})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPConnectionRefused {
		t.Fatalf("TCP refusal was incorrectly suppressed by path response: %#v", got)
	}
}

func TestDiagnoseDoesNotCrossSuppressDifferentTCPPorts(t *testing.T) {
	failedPort := failed("tcp-22", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport)
	failedPort.Target = model.NewTarget("db.example", 22)
	successPort := passed("tcp-443", model.LayerTCP)
	successPort.Target = model.NewTarget("db.example", 443)

	got := Diagnose([]model.ProbeResult{failedPort, successPort})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPTimeout {
		t.Fatalf("TCP success on another port suppressed the failure: %#v", got)
	}
}
