package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	parentprobe "github.com/yohnark/tadori/internal/probe"
)

func TestProbeKeepsWinHTTPAndWinINETEvidenceSeparateAndDoesNotExecutePAC(t *testing.T) {
	probe := NewProbeWithOptions(Options{
		Discover: func(context.Context) (Discovery, error) {
			return Discovery{
				WinHTTP: SourceConfiguration{
					Available: true,
					Proxy:     "http=alice:secret@proxy.corp.example:8080;https=proxy2.corp.example:8443",
					Bypass:    []string{"localhost", "http://user:password@intranet.example"},
				},
				WinINET: SourceConfiguration{
					Available:  true,
					PACURL:     "https://user:password@pac.corp.example/config.pac?token=secret",
					AutoDetect: true,
				},
			}, nil
		},
		CheckReachability: false,
		Now:               func() time.Time { return time.Date(2026, 9, 13, 1, 2, 3, 0, time.UTC) },
	})

	result := probe.Run(context.Background(), parentprobe.ExecutionContext{Target: model.NewTarget("service.example", 443)})
	if result.Status != model.ProbeStatusPassed {
		t.Fatalf("status = %s, want passed", result.Status)
	}
	if result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("failure reason = %s, want none", result.Interpretation.FailureReason)
	}
	if len(result.Evidence) != 3 {
		t.Fatalf("evidence count = %d, want 3 (WinHTTP, WinINET, PAC)", len(result.Evidence))
	}

	var winHTTP, winINET, pac bool
	for _, evidence := range result.Evidence {
		if strings.Contains(string(evidence.Raw), "secret") || strings.Contains(string(evidence.Raw), "password") {
			t.Fatalf("sensitive value leaked in %s evidence: %s", evidence.ID, evidence.Raw)
		}
		switch evidence.Kind {
		case model.EvidenceKindWinHTTPProxy:
			winHTTP = true
			if !strings.Contains(string(evidence.Raw), "proxy.corp.example:8080") {
				t.Fatalf("sanitized WinHTTP endpoint missing: %s", evidence.Raw)
			}
		case model.EvidenceKindWinINETProxy:
			winINET = true
		case model.EvidenceKindPAC:
			pac = true
			var raw pacEvidence
			if err := json.Unmarshal(evidence.Raw, &raw); err != nil {
				t.Fatalf("decode PAC evidence: %v", err)
			}
			if !raw.Configured || !raw.AutoDetect || raw.Executed {
				t.Fatalf("unexpected PAC evidence: %#v", raw)
			}
			if raw.URL != "https://pac.corp.example/config.pac" {
				t.Fatalf("PAC URL was not safely normalized: %q", raw.URL)
			}
		}
	}
	if !winHTTP || !winINET || !pac {
		t.Fatalf("evidence kinds = winhttp:%v wininet:%v pac:%v", winHTTP, winINET, pac)
	}
}

func TestProbeDirectConfiguration(t *testing.T) {
	result := testProbe(SourceConfiguration{Available: true}, SourceConfiguration{Available: true}, false, nil)
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, evidence := range result.Evidence {
		if evidence.Kind != model.EvidenceKindWinHTTPProxy && evidence.Kind != model.EvidenceKindWinINETProxy {
			continue
		}
		var raw sourceEvidence
		if err := json.Unmarshal(evidence.Raw, &raw); err != nil {
			t.Fatal(err)
		}
		if raw.State != string(StateDirect) || !raw.Direct || raw.StaticProxyConfigured || raw.PACConfigured {
			t.Fatalf("direct evidence = %#v", raw)
		}
	}
}

func TestProbeNormalizesMalformedProxyEndpoint(t *testing.T) {
	result := testProbe(SourceConfiguration{Available: true, Proxy: "http://:not-a-port"}, SourceConfiguration{Available: true}, false, nil)
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != model.FailureReasonProxyConfigurationFailure {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !hasState(result, StateMalformedProxyEndpoint) {
		t.Fatalf("malformed state not found in evidence: %#v", result.Evidence)
	}
}

func TestProbeRetainsValidEndpointsButReportsMixedMalformedConfiguration(t *testing.T) {
	result := testProbe(SourceConfiguration{Available: true, Proxy: "http=proxy.example:8080;https://:bad"}, SourceConfiguration{Available: true}, false, nil)
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != model.FailureReasonProxyConfigurationFailure {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !hasState(result, StateMalformedProxyEndpoint) {
		t.Fatalf("malformed state not found in evidence: %#v", result.Evidence)
	}
	for _, evidence := range result.Evidence {
		if evidence.Kind != model.EvidenceKindWinHTTPProxy {
			continue
		}
		var raw sourceEvidence
		if err := json.Unmarshal(evidence.Raw, &raw); err != nil {
			t.Fatal(err)
		}
		if len(raw.ProxyEndpoints) != 1 || raw.ProxyEndpoints[0] != "proxy.example:8080" {
			t.Fatalf("valid endpoint was not retained safely: %#v", raw)
		}
	}
}

func TestProbeNormalizesUnreachableProxyEndpoint(t *testing.T) {
	dialCalls := 0
	result := testProbe(SourceConfiguration{Available: true, Proxy: "proxy.corp.example:8080"}, SourceConfiguration{Available: true}, true, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCalls++
		if network != "tcp" || address != "proxy.corp.example:8080" {
			t.Fatalf("dial(%q, %q)", network, address)
		}
		return nil, context.DeadlineExceeded
	})
	if dialCalls != 1 {
		t.Fatalf("dial calls = %d, want 1", dialCalls)
	}
	if result.Status != model.ProbeStatusFailed || result.Interpretation.FailureReason != model.FailureReasonProxyUnavailable {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !hasState(result, StateProxyEndpointTimeout) {
		t.Fatalf("unreachable state not found in evidence: %#v", result.Evidence)
	}
}

func TestProbeReportsUnavailableSourceWithoutBreakingOtherEvidence(t *testing.T) {
	result := testProbe(SourceConfiguration{Available: false, Error: "access denied token=should-not-leak"}, SourceConfiguration{Available: true}, false, nil)
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != model.FailureReasonProxyConfigurationFailure {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, evidence := range result.Evidence {
		if strings.Contains(string(evidence.Raw), "should-not-leak") {
			t.Fatalf("sensitive error leaked: %s", evidence.Raw)
		}
	}
}

func TestSafeErrorRedactsCredentialValuesInAllCommonForms(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "password colon", in: "proxy failure; password: hunter2"},
		{name: "password equals", in: "proxy failure; password = hunter2"},
		{name: "token equals", in: "proxy failure; token = abc123"},
		{name: "authorization bearer", in: "proxy failure; Authorization: Bearer xyz123"},
		{name: "secret spaced", in: "proxy failure; secret super secret value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := safeError(errors.New(test.in))
			if got != "sensitive configuration value redacted" {
				t.Fatalf("safeError(%q) = %q, want generic redaction", test.in, got)
			}
			for _, secret := range []string{"hunter2", "abc123", "xyz123", "super secret value"} {
				if strings.Contains(got, secret) {
					t.Fatalf("safeError leaked %q: %q", secret, got)
				}
			}
		})
	}
}

func TestSanitizePACURLFailsClosedAndStripsUserInfoAndQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "valid URL with userinfo and token query",
			in:   "https://user:password@pac.example/config.pac?token=secret#fragment",
			want: "https://pac.example/config.pac",
		},
		{
			name: "valid URL with userinfo",
			in:   "https://user:password@pac.example/config.pac",
			want: "https://pac.example/config.pac",
		},
		{
			name: "malformed escape",
			in:   "https://%zz/config.pac?token=secret#fragment",
			want: "",
		},
		{
			name: "relative URL",
			in:   "config.pac?token=secret#fragment",
			want: "",
		},
		{
			name: "hostless absolute URL",
			in:   "https:///config.pac?token=secret#fragment",
			want: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sanitizePACURL(test.in); got != test.want {
				t.Fatalf("sanitizePACURL(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestProbePreservesUnsafePACPresenceWithoutEmittingURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "malformed", url: "https://%zz/config.pac?token=secret"},
		{name: "relative", url: "config.pac?token=secret"},
		{name: "hostless", url: "https:///config.pac?token=secret#fragment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := testProbe(SourceConfiguration{Available: true}, SourceConfiguration{Available: true, PACURL: test.url}, false, nil)
			if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
				t.Fatalf("unexpected result: %#v", result)
			}

			var configuration, pac bool
			for _, evidence := range result.Evidence {
				if strings.Contains(string(evidence.Raw), "secret") || strings.Contains(string(evidence.Raw), "token=") {
					t.Fatalf("unsafe PAC value leaked in %s evidence: %s", evidence.ID, evidence.Raw)
				}
				switch evidence.Kind {
				case model.EvidenceKindWinINETProxy:
					var raw sourceEvidence
					if err := json.Unmarshal(evidence.Raw, &raw); err != nil {
						t.Fatal(err)
					}
					if raw.State != string(StatePACConfigured) || raw.Direct || !raw.PACConfigured || raw.PACURL != "" {
						t.Fatalf("unsafe PAC configuration was normalized incorrectly: %#v", raw)
					}
					configuration = true
				case model.EvidenceKindPAC:
					var raw pacEvidence
					if err := json.Unmarshal(evidence.Raw, &raw); err != nil {
						t.Fatal(err)
					}
					if !raw.Configured || raw.URL != "" || raw.Executed {
						t.Fatalf("unsafe PAC evidence was emitted incorrectly: %#v", raw)
					}
					pac = true
				}
			}
			if !configuration || !pac {
				t.Fatalf("missing unsafe PAC evidence: configuration=%v pac=%v", configuration, pac)
			}
		})
	}
}

func TestProbeUnsupportedPlatformIsSkipped(t *testing.T) {
	if isWindows() {
		t.Skip("platform-specific fallback is only expected on non-Windows")
	}
	result := NewProbeWithOptions(Options{CheckReachability: false}).Run(context.Background(), parentprobe.ExecutionContext{})
	if result.Status != model.ProbeStatusSkipped || result.Interpretation.FailureReason != model.FailureReasonUnsupported {
		t.Fatalf("unexpected unsupported result: %#v", result)
	}
	if !hasState(result, StateUnsupportedPlatform) {
		t.Fatalf("unsupported state not found: %#v", result.Evidence)
	}
}

func TestParseProxyEndpointsRedactsCredentialsAndSupportsSchemeLists(t *testing.T) {
	got, _, errText := parseProxyEndpoints("http=user:pass@proxy.example:8080;https://[2001:db8::1]:8443;DIRECT")
	if errText != "" || len(got) != 2 {
		t.Fatalf("parse = %#v, err = %q", got, errText)
	}
	if got[0] != "proxy.example:8080" || got[1] != "[2001:db8::1]:8443" {
		t.Fatalf("endpoints = %#v", got)
	}
	got, _, errText = parseProxyEndpoints("http=proxy-a.example:8080 https=proxy-b.example:8443")
	if errText != "" || len(got) != 2 || got[0] != "proxy-a.example:8080" || got[1] != "proxy-b.example:8443" {
		t.Fatalf("whitespace-separated endpoints = %#v, error %q", got, errText)
	}
}

func TestParseProxyEndpointsTreatsDIRECTAsDirectConfiguration(t *testing.T) {
	got, _, errText := parseProxyEndpoints("DIRECT")
	if errText != "" || len(got) != 0 {
		t.Fatalf("parse DIRECT = endpoints %#v, error %q", got, errText)
	}
	got, _, errText = parseProxyEndpoints("https=DIRECT")
	if errText != "" || len(got) != 0 {
		t.Fatalf("parse scheme-specific DIRECT = endpoints %#v, error %q", got, errText)
	}
}

func TestProxyEndpointForURLSelectsSchemeSpecificEndpoint(t *testing.T) {
	endpoint, direct, err := ProxyEndpointForURL("http=http-proxy.example:8080;https=https-proxy.example:8443", "https://service.example/health")
	if err != nil || direct || endpoint != "https-proxy.example:8443" {
		t.Fatalf("https selection = endpoint %q, direct %v, error %v", endpoint, direct, err)
	}
	endpoint, direct, err = ProxyEndpointForURL("http=http-proxy.example:8080;https=https-proxy.example:8443", "http://service.example/health")
	if err != nil || direct || endpoint != "http-proxy.example:8080" {
		t.Fatalf("http selection = endpoint %q, direct %v, error %v", endpoint, direct, err)
	}
	endpoint, direct, err = ProxyEndpointForURL("http=http-proxy.example:8080 https=https-proxy.example:8443", "https://service.example/health")
	if err != nil || direct || endpoint != "https-proxy.example:8443" {
		t.Fatalf("whitespace-separated https selection = endpoint %q, direct %v, error %v", endpoint, direct, err)
	}
}

func TestProxyEndpointForURLHonorsSchemeSpecificDIRECT(t *testing.T) {
	endpoint, direct, err := ProxyEndpointForURL("http=proxy.example:8080;https=DIRECT", "https://service.example/health")
	if err != nil || !direct || endpoint != "" {
		t.Fatalf("DIRECT selection = endpoint %q, direct %v, error %v", endpoint, direct, err)
	}
	endpoint, direct, err = ProxyEndpointForURL("DIRECT;proxy.example:8080", "https://service.example/health")
	if err != nil || !direct || endpoint != "" {
		t.Fatalf("ordered DIRECT selection = endpoint %q, direct %v, error %v", endpoint, direct, err)
	}
}

func TestResolveProxyForURLDistinguishesStaticProxyAndBypass(t *testing.T) {
	config := SourceConfiguration{
		Available: true,
		Proxy:     "proxy.corp.example:8080",
		Bypass:    []string{"*.internal.example"},
	}

	resolution, err := ResolveProxyForURL(context.Background(), "https://api.external.example/health", config)
	if err != nil {
		t.Fatalf("external resolution: %v", err)
	}
	if resolution.Direct || resolution.Proxy != "proxy.corp.example:8080" || resolution.BypassMatched {
		t.Fatalf("external resolution = %#v, want selected static proxy", resolution)
	}

	resolution, err = ResolveProxyForURL(context.Background(), "https://api.internal.example/health", config)
	if err != nil {
		t.Fatalf("bypass resolution: %v", err)
	}
	if !resolution.Direct || resolution.Proxy != "" || !resolution.BypassMatched {
		t.Fatalf("bypass resolution = %#v, want direct bypass match", resolution)
	}

	resolution, err = ResolveProxyForURL(context.Background(), "https://api.external.example/health", SourceConfiguration{Available: true})
	if err != nil {
		t.Fatalf("direct resolution: %v", err)
	}
	if !resolution.Direct || resolution.BypassMatched || resolution.Configuration != string(StateDirect) {
		t.Fatalf("direct resolution = %#v, want configured direct", resolution)
	}
}

func TestProxyBypassesSupportsWindowsLocalAndWildcardPatterns(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		bypass []string
		want   bool
	}{
		{name: "local host", url: "https://intranet/health", bypass: []string{"<local>"}, want: true},
		{name: "wildcard suffix", url: "https://api.corp.example/health", bypass: []string{"*.corp.example"}, want: true},
		{name: "combined bypass list", url: "https://api.corp.example/health", bypass: []string{"localhost;*.corp.example"}, want: true},
		{name: "whitespace bypass list", url: "https://api.corp.example/health", bypass: []string{"localhost *.corp.example"}, want: true},
		{name: "literal host with port", url: "https://service.example:443/health", bypass: []string{"service.example:443"}, want: true},
		{name: "literal host with different port", url: "https://service.example:8443/health", bypass: []string{"service.example:443"}, want: false},
		{name: "IPv6 literal", url: "https://[2001:db8::10]/health", bypass: []string{"[2001:db8::10]"}, want: true},
		{name: "not matched", url: "https://public.example/health", bypass: []string{"*.corp.example"}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ProxyBypasses(test.url, test.bypass); got != test.want {
				t.Fatalf("ProxyBypasses(%q, %#v) = %v, want %v", test.url, test.bypass, got, test.want)
			}
		})
	}
}

func TestProbeHonorsCanceledContext(t *testing.T) {
	called := false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := NewProbeWithOptions(Options{
		Discover: func(context.Context) (Discovery, error) {
			called = true
			return Discovery{}, errors.New("must not be called")
		},
	})
	result := probe.Run(ctx, parentprobe.ExecutionContext{})
	if called || result.Interpretation.FailureReason != model.FailureReasonProbeExecution {
		t.Fatalf("canceled result = %#v, discover called = %v", result, called)
	}
}

func testProbe(winHTTP, winINET SourceConfiguration, check bool, dial DialContextFunc) model.ProbeResult {
	return NewProbeWithOptions(Options{
		Discover: func(context.Context) (Discovery, error) {
			return Discovery{WinHTTP: winHTTP, WinINET: winINET}, nil
		},
		CheckReachability:   check,
		ReachabilityTimeout: time.Millisecond,
		DialContext:         dial,
	}).Run(context.Background(), parentprobe.ExecutionContext{})
}

func hasState(result model.ProbeResult, state ConfigurationState) bool {
	for _, evidence := range result.Evidence {
		var raw sourceEvidence
		if json.Unmarshal(evidence.Raw, &raw) == nil && raw.State == string(state) {
			return true
		}
	}
	return false
}

func isWindows() bool { return runtime.GOOS == "windows" }
