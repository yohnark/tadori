package orchestrate

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

// TestRunAgainstLocalFixture exercises the full wiring path end to end
// against a deterministic local HTTP server: target parsing, every probe
// package, the diagnosis engine, and the canonical report shape. It uses a
// loopback fixture instead of the network so it is deterministic in CI-less
// environments and does not depend on external connectivity.
func TestRunAgainstLocalFixture(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusOK)
	}))
	defer server.Close()

	target, err := ParseTarget(server.URL)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", server.URL, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := Run(ctx, target, Options{ProbeTimeout: 5 * time.Second})

	if got.SchemaVersion != model.DiagnosticSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", got.SchemaVersion, model.DiagnosticSchemaVersion)
	}
	if got.Target.URL != server.URL {
		t.Errorf("Target.URL = %q, want %q", got.Target.URL, server.URL)
	}
	if got.StartedAt == nil || got.CompletedAt == nil {
		t.Fatalf("expected StartedAt/CompletedAt to be populated")
	}
	if got.CompletedAt.Before(*got.StartedAt) {
		t.Errorf("CompletedAt %v is before StartedAt %v", got.CompletedAt, got.StartedAt)
	}

	wantProbes := map[string]bool{
		"interface_state":      false,
		"dns_configuration":    false,
		"dns":                  false,
		"default_route":        false,
		"target_route":         false,
		"gateway_reachability": false,
		"proxy_discovery":      false,
		"tcp":                  false,
		"tls":                  false,
		"http":                 false,
	}
	for _, probeResult := range got.Probes {
		if _, ok := wantProbes[probeResult.Name]; !ok {
			t.Errorf("unexpected probe result %q in report", probeResult.Name)
			continue
		}
		wantProbes[probeResult.Name] = true
		if probeResult.Status == "" {
			t.Errorf("probe %q has empty status", probeResult.Name)
		}
		if probeResult.Timing.StartedAt == nil || probeResult.Timing.CompletedAt == nil {
			t.Errorf("probe %q missing timing", probeResult.Name)
		}
	}
	for name, seen := range wantProbes {
		if !seen {
			t.Errorf("expected probe %q in report, got none", name)
		}
	}

	// The target is plain HTTP, so the TCP and HTTP probes must succeed
	// regardless of what the platform's route/gateway/proxy probes report in
	// a sandboxed test environment; this is the partial-result guarantee.
	httpResult := findProbe(t, got.Probes, "http")
	if httpResult.Status != model.ProbeStatusPassed {
		t.Errorf("http probe status = %s, want passed", httpResult.Status)
	}
	tcpResult := findProbe(t, got.Probes, "tcp")
	if tcpResult.Status != model.ProbeStatusPassed {
		t.Errorf("tcp probe status = %s, want passed", tcpResult.Status)
	}
}

// TestRunPreservesPartialResultsOnUnreachableTarget confirms that a probe
// which cannot succeed against an unreachable target (closed TCP port) does
// not prevent independent probes, such as interface/route/DNS observations,
// from being collected in the same report.
func TestRunPreservesPartialResultsOnUnreachableTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // nothing listens on this port once closed

	target, err := ParseTarget("http://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := Run(ctx, target, Options{ProbeTimeout: 5 * time.Second})

	httpResult := findProbe(t, got.Probes, "http")
	if httpResult.Status == model.ProbeStatusPassed {
		t.Errorf("http probe unexpectedly passed against a closed port")
	}

	interfaceResult := findProbe(t, got.Probes, "interface_state")
	if interfaceResult.Status != model.ProbeStatusPassed {
		t.Errorf("interface_state probe status = %s, want passed even though HTTP failed", interfaceResult.Status)
	}

	if len(got.Probes) != 10 {
		t.Errorf("len(Probes) = %d, want 10 even with a failing probe", len(got.Probes))
	}
}

func TestReportStatusAggregatesCanonicalProbeOutcomes(t *testing.T) {
	unsupportedGateway := model.ProbeResult{
		Name:   "gateway_reachability",
		Status: model.ProbeStatusError,
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonUnsupported,
			Layer:         model.LayerGateway,
			FaultDomain:   model.FaultDomainGateway,
		},
	}
	unsupportedProxy := model.ProbeResult{
		Name:   "proxy_discovery",
		Status: model.ProbeStatusSkipped,
		Interpretation: model.ProbeInterpretation{
			FailureReason: model.FailureReasonUnsupported,
			Layer:         model.LayerProxy,
			FaultDomain:   model.FaultDomainProxy,
		},
	}

	t.Run("HTTP success ignores unsupported gateway and proxy support", func(t *testing.T) {
		got := reportStatus([]model.ProbeResult{
			unsupportedGateway,
			unsupportedProxy,
			{
				Name:   "http",
				Status: model.ProbeStatusPassed,
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonNone,
					Layer:         model.LayerHTTP,
					FaultDomain:   model.FaultDomainHTTP,
				},
			},
		})
		if got != model.ReportStatusComplete {
			t.Fatalf("report status = %s, want complete", got)
		}
	})

	t.Run("missing HTTP observation remains incomplete", func(t *testing.T) {
		got := reportStatus([]model.ProbeResult{
			unsupportedGateway,
			unsupportedProxy,
			{
				Name:   "http",
				Status: model.ProbeStatusError,
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonHTTPFailure,
					Layer:         model.LayerHTTP,
					FaultDomain:   model.FaultDomainHTTP,
				},
			},
		})
		if got != model.ReportStatusIncomplete {
			t.Fatalf("report status = %s, want incomplete", got)
		}
	})

	t.Run("received HTTP failure is complete evidence", func(t *testing.T) {
		got := reportStatus([]model.ProbeResult{
			unsupportedGateway,
			unsupportedProxy,
			{
				Name:   "http",
				Status: model.ProbeStatusFailed,
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonHTTPStatusCode,
					Layer:         model.LayerHTTP,
					FaultDomain:   model.FaultDomainHTTP,
				},
			},
		})
		if got != model.ReportStatusComplete {
			t.Fatalf("report status = %s, want complete", got)
		}
	})

	t.Run("unsupported required evidence is still incomplete", func(t *testing.T) {
		got := reportStatus([]model.ProbeResult{
			{
				Name:   "dns",
				Status: model.ProbeStatusError,
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonUnsupported,
					Layer:         model.LayerDNS,
					FaultDomain:   model.FaultDomainDNS,
				},
			},
		})
		if got != model.ReportStatusIncomplete {
			t.Fatalf("report status = %s, want incomplete", got)
		}
	})
}

func findProbe(t *testing.T, probes []model.ProbeResult, name string) model.ProbeResult {
	t.Helper()
	for _, probeResult := range probes {
		if probeResult.Name == name {
			return probeResult
		}
	}
	t.Fatalf("probe %q not found in report", name)
	return model.ProbeResult{}
}
