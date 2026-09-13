package diagnosis

import (
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

func TestDiagnoseProxyEvidenceDoesNotInventAProxyFault(t *testing.T) {
	got := Diagnose([]model.ProbeResult{
		failed("direct-tcp", model.FailureReasonTCPTimeout, model.LayerTCP, model.FaultDomainTransport),
		passed("proxy-config", model.LayerProxy),
	})
	if len(got) != 1 || got[0].FailureReason != model.FailureReasonTCPTimeout || got[0].FaultDomain == model.FaultDomainProxy {
		t.Fatalf("proxy-required behavior was treated as a proxy fault: %#v", got)
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
