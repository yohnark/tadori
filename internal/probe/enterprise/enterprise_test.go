package enterprise

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	parentprobe "github.com/yohnark/tadori/internal/probe"
	"github.com/yohnark/tadori/internal/probe/proxy"
)

func enterpriseTarget() model.Target {
	return parseEnterpriseTarget("https://service.example.test/health")
}

func parseEnterpriseTarget(raw string) model.Target {
	target, err := model.ParseTarget(model.TargetIntent{Input: raw})
	if err != nil {
		panic(err)
	}
	return target
}

func testProbe(snapshot Snapshot) model.ProbeResult {
	return New(Options{
		Provider: SnapshotProviderFunc(func(context.Context, model.Target) (Snapshot, error) { return snapshot, nil }),
		Now:      func() time.Time { return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC) },
	}).Run(context.Background(), parentprobe.ExecutionContext{Target: enterpriseTarget()})
}

func availableProxy(value string) proxy.SourceConfiguration {
	return proxy.SourceConfiguration{Available: true, Proxy: value}
}

func TestBrowserWorksApplicationDirectFailsIsPolicyAwareDiagnosis(t *testing.T) {
	result := testProbe(Snapshot{
		Proxy: proxy.Discovery{
			WinHTTP: availableProxy("proxy.corp.example:8080"),
			WinINET: availableProxy("proxy.corp.example:8080"),
		},
		Paths: []PathObservation{
			{Name: PathApplicationDirect, Source: "direct", Mode: PathModeDirect, RequestAttempted: true, FailureReason: model.FailureReasonTCPTimeout, Error: "i/o timeout"},
			{Name: PathBrowserWinINET, Source: "wininet", Mode: PathModeProxy, Endpoint: "proxy.corp.example:8080", RequestAttempted: true, TCPConnected: true, ConnectOutcome: ConnectSucceeded, HTTPResponse: true, HTTPStatusCode: 200, FailureReason: model.FailureReasonNone},
		},
	})
	if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonDirectEgressRestricted {
		t.Fatalf("result = %#v, want policy-aware direct egress diagnosis", result)
	}
	if result.Interpretation.FaultDomain != model.FaultDomainPolicy {
		t.Fatalf("fault domain = %q, want policy", result.Interpretation.FaultDomain)
	}
	correlation := evidenceByKind(t, result, model.EvidenceKindRouteComparison)
	var raw map[string]any
	if err := json.Unmarshal(correlation.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["intentional_policy_possible"] != true || raw["browser_path_works"] != true {
		t.Fatalf("correlation evidence = %#v", raw)
	}
}

func TestWorkingWinHTTPProxyAndFailedDirectPathAreCompared(t *testing.T) {
	result := testProbe(Snapshot{
		Proxy: proxy.Discovery{WinHTTP: availableProxy("proxy.corp.example:8080")},
		Paths: []PathObservation{
			{Name: PathApplicationDirect, Source: "direct", Mode: PathModeDirect, RequestAttempted: true, FailureReason: model.FailureReasonNetworkUnreachable},
			{Name: PathServiceWinHTTP, Source: "winhttp", Mode: PathModeProxy, Endpoint: "proxy.corp.example:8080", RequestAttempted: true, TCPConnected: true, HTTPResponse: true, HTTPStatusCode: 204, FailureReason: model.FailureReasonNone},
		},
	})
	if result.Interpretation.FailureReason != model.FailureReasonDirectEgressRestricted {
		t.Fatalf("reason = %q, want direct egress restriction", result.Interpretation.FailureReason)
	}
}

func TestWinHTTPAndWinINETDivergenceIsCorrelated(t *testing.T) {
	result := testProbe(Snapshot{Proxy: proxy.Discovery{
		WinHTTP: availableProxy("proxy.service.example:8080"),
		WinINET: availableProxy("proxy.browser.example:8080"),
	}})
	if result.Interpretation.FailureReason != model.FailureReasonProxyConfigurationDivergence {
		t.Fatalf("reason = %q, want configuration divergence", result.Interpretation.FailureReason)
	}
	if result.Interpretation.Layer != model.LayerProxy || result.Interpretation.FaultDomain != model.FaultDomainProxy {
		t.Fatalf("interpretation = %#v", result.Interpretation)
	}
}

func TestProxyCONNECTDeniedAndAuthenticationRequired(t *testing.T) {
	for _, test := range []struct {
		name    string
		outcome string
		status  int
		want    model.FailureReason
	}{
		{name: "denied", outcome: ConnectDenied, status: 403, want: model.FailureReasonProxyConnectDenied},
		{name: "authentication", outcome: ConnectAuthRequired, status: 407, want: model.FailureReasonProxyAuthenticationRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := testProbe(Snapshot{
				Proxy: proxy.Discovery{WinINET: availableProxy("proxy.corp.example:8080")},
				Paths: []PathObservation{{
					Name: PathBrowserWinINET, Source: "wininet", Mode: PathModeProxy, Endpoint: "proxy.corp.example:8080",
					TCPConnected: true, ConnectOutcome: test.outcome, ConnectStatusCode: test.status,
					ProxyAuthenticationHint: test.outcome == ConnectAuthRequired,
				}},
			})
			if result.Interpretation.FailureReason != test.want {
				t.Fatalf("reason = %q, want %q", result.Interpretation.FailureReason, test.want)
			}
		})
	}
}

func TestProxyEndpointUnreachableIsCorrelated(t *testing.T) {
	result := testProbe(Snapshot{
		Proxy: proxy.Discovery{WinHTTP: availableProxy("proxy.corp.example:8080")},
		Paths: []PathObservation{{
			Name: PathServiceWinHTTP, Source: "winhttp", Mode: PathModeProxy,
			Endpoint: "proxy.corp.example:8080", ConnectOutcome: ConnectUnavailable,
			FailureReason: model.FailureReasonProxyUnavailable,
		}},
	})
	if result.Interpretation.FailureReason != model.FailureReasonProxyUnavailable {
		t.Fatalf("reason = %q, want proxy unavailable", result.Interpretation.FailureReason)
	}
}

func TestPACResolutionFailureIsCorrelatedWithoutExposingPACDetails(t *testing.T) {
	result := testProbe(Snapshot{
		Proxy:          proxy.Discovery{WinINET: proxy.SourceConfiguration{Available: true, PACURL: "https://pac.corp.example/proxy.pac"}},
		EffectiveProxy: []EffectiveProxy{{Source: "wininet", Mode: PathModeUnknown, PACUsed: true, ResolutionOK: false, Error: "WinHTTP automatic proxy resolution failed"}},
	})
	if result.Interpretation.FailureReason != model.FailureReasonProxyConfigurationFailure {
		t.Fatalf("reason = %q, want proxy configuration failure", result.Interpretation.FailureReason)
	}
}

func TestProbeHTTPPathCapturesProxy407WithoutCredentials(t *testing.T) {
	proxyServer := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if request.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("proxy authorization header was sent: %q", request.Header.Get("Proxy-Authorization"))
		}
		writer.Header().Set("Proxy-Authenticate", "Negotiate")
		writer.WriteHeader(stdhttp.StatusProxyAuthRequired)
	}))
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := ProbeHTTPPath(context.Background(), parseEnterpriseTarget("http://service.example.test/health"), PathBrowserWinINET, "wininet", PathModeProxy, "user:password@"+net.JoinHostPort(proxyURL.Hostname(), proxyURL.Port()), time.Second)
	if path.FailureReason != model.FailureReasonProxyAuthenticationRequired || !path.ProxyAuthenticationHint || !path.TCPConnected {
		t.Fatalf("407 path = %#v", path)
	}
	if strings.Contains(path.Endpoint, "password") {
		t.Fatalf("proxy credentials leaked in path endpoint: %#v", path)
	}
}

func TestProbeHTTPPathRetainsPeerCertificateOnTrustFailure(t *testing.T) {
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = io.WriteString(writer, "not reached")
	}))
	defer server.Close()
	path := ProbeHTTPPath(context.Background(), parseEnterpriseTarget(server.URL), PathApplicationDirect, "direct", PathModeDirect, "", time.Second)
	if path.FailureReason != model.FailureReasonCertificateValidationFailure || !path.TCPConnected || !path.TLSAttempted || path.Certificate == nil {
		t.Fatalf("TLS trust path = %#v", path)
	}
}

func TestTLSHostnameMismatchIsNotReportedAsTrustMismatch(t *testing.T) {
	certificate := &x509.Certificate{}
	err := &tls.CertificateVerificationError{
		UnverifiedCertificates: []*x509.Certificate{certificate},
		Err:                    x509.HostnameError{Certificate: certificate, Host: "service.example.test"},
	}
	if !certificateChainTrusted(err) {
		t.Fatal("hostname-only verification failure should retain trusted-chain evidence")
	}
	if certificates := certificatesFromTLSError(err); len(certificates) != 1 || certificates[0] != certificate {
		t.Fatalf("hostname verification error lost peer certificate: %#v", certificates)
	}
}

func TestTLSInterceptionRequiresPairedTrustedHostnameValidCertificates(t *testing.T) {
	result := testProbe(Snapshot{Paths: []PathObservation{
		{Name: PathApplicationDirect, Source: "direct", Mode: PathModeDirect, TLSHandshake: true, CertificateTrusted: true, HostnameVerified: true, Certificate: &CertificateObservation{SHA256: strings.Repeat("a", 64)}},
		{Name: PathBrowserWinINET, Source: "wininet", Mode: PathModeProxy, Endpoint: "proxy.corp.example:8080", ConnectOutcome: ConnectSucceeded, TLSHandshake: true, CertificateTrusted: true, HostnameVerified: true, Certificate: &CertificateObservation{SHA256: strings.Repeat("b", 64)}},
	}})
	if result.Interpretation.FailureReason != model.FailureReasonTLSInterceptionSuspected {
		t.Fatalf("reason = %q, want conservative interception suspicion", result.Interpretation.FailureReason)
	}

	result = testProbe(Snapshot{Paths: []PathObservation{
		{Name: PathApplicationDirect, Source: "direct", Mode: PathModeDirect, TLSHandshake: true, CertificateTrusted: false, HostnameVerified: false, Certificate: &CertificateObservation{SHA256: strings.Repeat("a", 64)}},
		{Name: PathBrowserWinINET, Source: "wininet", Mode: PathModeProxy, Endpoint: "proxy.corp.example:8080", ConnectOutcome: ConnectSucceeded, TLSHandshake: true, CertificateTrusted: true, HostnameVerified: true, Certificate: &CertificateObservation{SHA256: strings.Repeat("b", 64)}},
	}})
	if result.Interpretation.FailureReason != model.FailureReasonTLSTrustStoreMismatch {
		t.Fatalf("untrusted direct path reason = %q, want trust-store mismatch", result.Interpretation.FailureReason)
	}
}

func TestEffectiveRouteDifferenceIsEvidenceAndDiagnosis(t *testing.T) {
	result := testProbe(Snapshot{Paths: []PathObservation{
		{Name: PathApplicationDirect, Mode: PathModeDirect},
		{Name: PathBrowserWinINET, Mode: PathModeProxy, Endpoint: "proxy.corp.example:8080"},
	}, Routes: []RouteObservation{
		{Path: PathApplicationDirect, Destination: "198.51.100.10", InterfaceIndex: 4, Available: true},
		{Path: PathBrowserWinINET, Destination: "192.0.2.10", InterfaceIndex: 12, Available: true},
	}})
	if result.Interpretation.FailureReason != model.FailureReasonEffectiveRouteDifference {
		t.Fatalf("reason = %q, want effective route difference", result.Interpretation.FailureReason)
	}
	if evidenceByKind(t, result, model.EvidenceKindAdapterRouting).Kind != model.EvidenceKindAdapterRouting {
		t.Fatal("route evidence was not retained")
	}
}

func TestSensitiveProxyValuesAreNotEmitted(t *testing.T) {
	result := testProbe(Snapshot{Proxy: proxy.Discovery{
		WinHTTP: availableProxy("http://user:password@proxy.corp.example:8080"),
		WinINET: proxy.SourceConfiguration{Available: true, PACURL: "https://user:password@pac.corp.example/config.pac?token=secret"},
	}, EffectiveProxy: []EffectiveProxy{{Source: "winhttp", Endpoint: "http://user:password@proxy.corp.example:8080", Bypass: []string{"user:password@intranet.example"}}}})
	for _, evidence := range result.Evidence {
		if strings.Contains(string(evidence.Raw), "password") || strings.Contains(string(evidence.Raw), "secret") || strings.Contains(string(evidence.Raw), "token=") {
			t.Fatalf("sensitive value leaked in %s: %s", evidence.ID, evidence.Raw)
		}
	}
}

func TestUnsupportedPlatformDoesNotBecomeAConnectivityFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows fallback test")
	}
	result := New().Run(context.Background(), parentprobe.ExecutionContext{Target: enterpriseTarget()})
	if result.Status != model.ProbeStatusSkipped || result.Interpretation.FailureReason != model.FailureReasonUnsupported {
		t.Fatalf("result = %#v", result)
	}
}

func evidenceByKind(t *testing.T, result model.ProbeResult, kind model.EvidenceKind) model.Evidence {
	t.Helper()
	for _, evidence := range result.Evidence {
		if evidence.Kind == kind {
			return evidence
		}
	}
	t.Fatalf("evidence kind %q not found in %#v", kind, result.Evidence)
	return model.Evidence{}
}
