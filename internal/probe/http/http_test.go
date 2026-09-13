package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/probe"
)

func TestProbeCapturesResponseAndSafeMetadataWithoutBodyByDefault(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Private-Header", "must not be captured")
		writer.WriteHeader(stdhttp.StatusNotFound)
		_, _ = io.WriteString(writer, "private response body")
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "/missing"}
	result := New().Run(context.Background(), probe.ExecutionContext{Target: target})

	if result.Status != model.ProbeStatusFailed {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	if result.Interpretation.FailureReason != model.FailureReasonHTTPStatusCode {
		t.Fatalf("failure reason = %q, want HTTP status code", result.Interpretation.FailureReason)
	}
	if result.Interpretation.Layer != model.LayerHTTP || result.Interpretation.FaultDomain != model.FaultDomainHTTP {
		t.Fatalf("interpretation = %#v, want HTTP layer/domain", result.Interpretation)
	}
	if result.Timing.DurationMS < 0 || result.Timing.StartedAt == nil || result.Timing.CompletedAt == nil {
		t.Fatalf("invalid timing: %#v", result.Timing)
	}

	metadata := decodeEvidence[responseMetadata](t, result)
	if !metadata.ResponseReceived || metadata.StatusCode != stdhttp.StatusNotFound {
		t.Fatalf("metadata = %#v, want received 404", metadata)
	}
	if metadata.Headers["Content-Type"] != "text/plain" {
		t.Fatalf("headers = %#v, want content type", metadata.Headers)
	}
	if _, found := metadata.Headers["X-Private-Header"]; found {
		t.Fatalf("unsafe header was captured: %#v", metadata.Headers)
	}
	if metadata.Body != "" || metadata.BodyBytes != 0 {
		t.Fatalf("body should be omitted by default: %#v", metadata)
	}
}

func TestProbeBoundsOptionalResponseBody(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "0123456789")
	}))
	defer server.Close()

	result := New(Config{MaxBodyBytes: 4}).Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: server.URL},
	})
	metadata := decodeEvidence[responseMetadata](t, result)
	if metadata.Body != "0123" || metadata.BodyBytes != 4 || !metadata.BodyTruncated {
		t.Fatalf("bounded body metadata = %#v, want 4-byte truncation", metadata)
	}
}

func TestProbeCapturesRedirectBehavior(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		switch request.URL.Path {
		case "/start":
			stdhttp.Redirect(writer, request, "/finish", stdhttp.StatusFound)
		case "/finish":
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(writer, "done")
		default:
			stdhttp.NotFound(writer, request)
		}
	}))
	defer server.Close()

	result := New().Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: server.URL + "/start"},
	})
	if result.Status != model.ProbeStatusPassed || result.Interpretation.FailureReason != model.FailureReasonNone {
		t.Fatalf("result = %#v, want successful redirected response", result)
	}
	metadata := decodeEvidence[responseMetadata](t, result)
	if len(metadata.Redirects) != 1 {
		t.Fatalf("redirects = %#v, want one redirect", metadata.Redirects)
	}
	hop := metadata.Redirects[0]
	if hop.StatusCode != stdhttp.StatusFound || hop.Location != "/finish" || !strings.HasSuffix(hop.ToURL, "/finish") {
		t.Fatalf("redirect hop = %#v", hop)
	}
}

func TestProbeNormalizesRedirectLoop(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		stdhttp.Redirect(writer, request, request.URL.Path, stdhttp.StatusTemporaryRedirect)
	}))
	defer server.Close()

	result := New(Config{MaxRedirects: 2}).Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: server.URL + "/loop"},
	})
	if result.Status != model.ProbeStatusError {
		t.Fatalf("status = %q, want error", result.Status)
	}
	if result.Interpretation.FailureReason != FailureReasonRedirectFailure {
		t.Fatalf("failure reason = %q, want redirect failure", result.Interpretation.FailureReason)
	}
	metadata := decodeEvidence[errorMetadata](t, result)
	if !metadata.ResponseReceived || len(metadata.Redirects) < 2 {
		t.Fatalf("redirect evidence = %#v, want received redirect hops", metadata)
	}
}

func TestProbeNormalizesRequestTimeout(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	result := New(Config{Timeout: 20 * time.Millisecond}).Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: server.URL},
	})
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != FailureReasonRequestTimeout {
		t.Fatalf("result = %#v, want request timeout", result)
	}
	metadata := decodeEvidence[errorMetadata](t, result)
	if metadata.ResponseReceived {
		t.Fatalf("timeout unexpectedly reported response: %#v", metadata)
	}
}

func TestProbeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := New().Run(ctx, probe.ExecutionContext{Target: model.Target{URL: "http://127.0.0.1:1"}})
	if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != FailureReasonCancellation {
		t.Fatalf("result = %#v, want cancellation", result)
	}
}

func TestProbeRejectsMalformedAndNonHTTPURLs(t *testing.T) {
	for _, targetURL := range []string{"", "not a URL", "ftp://example.test/file", "http://", " http://example.test"} {
		result := New().Run(context.Background(), probe.ExecutionContext{Target: model.Target{URL: targetURL}})
		if result.Status != model.ProbeStatusError || result.Interpretation.FailureReason != FailureReasonMalformedURL {
			t.Errorf("URL %q result = %#v, want malformed URL", targetURL, result)
		}
	}
}

func TestProbeKeepsDNSFailureAtDNSLayer(t *testing.T) {
	transport := roundTripperFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
		return nil, &url.Error{Op: "Get", URL: request.URL.String(), Err: &net.DNSError{
			Err: "no such host", Name: "local.invalid", IsNotFound: true,
		}}
	})
	result := New(Config{Client: &stdhttp.Client{Transport: transport}}).Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: "http://local.invalid/"},
	})
	if result.Interpretation.FailureReason != model.FailureReasonDNSNXDomain || result.Interpretation.Layer != model.LayerDNS {
		t.Fatalf("interpretation = %#v, want DNS NXDOMAIN at DNS layer", result.Interpretation)
	}
	if decodeEvidence[errorMetadata](t, result).ResponseReceived {
		t.Fatal("DNS failure reported an HTTP response")
	}
	if result.Evidence[0].Kind != EvidenceKindHTTPError {
		t.Fatalf("DNS evidence kind = %q, want HTTP error", result.Evidence[0].Kind)
	}
}

func TestProbeKeepsTransportFailureAtTCPLayer(t *testing.T) {
	transport := roundTripperFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
		return nil, &url.Error{Op: "Get", URL: request.URL.String(), Err: &net.OpError{
			Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED,
		}}
	})
	result := New(Config{Client: &stdhttp.Client{Transport: transport}}).Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: "http://127.0.0.1:9/"},
	})
	if result.Interpretation.FailureReason != model.FailureReasonTCPConnectionRefused || result.Interpretation.Layer != model.LayerTCP {
		t.Fatalf("interpretation = %#v, want TCP refused at TCP layer", result.Interpretation)
	}
}

func TestProbeKeepsTLSFailureAtTLSLayer(t *testing.T) {
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = io.WriteString(writer, "would not be reached")
	}))
	defer server.Close()

	result := New().Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: server.URL},
	})
	if result.Interpretation.FailureReason != model.FailureReasonCertificateValidationFailure || result.Interpretation.Layer != model.LayerTLS {
		t.Fatalf("interpretation = %#v, want TLS certificate failure", result.Interpretation)
	}
}

func TestProbeTLSHandshakeFailureIsNotHTTPResponse(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = io.WriteString(writer, "plain HTTP")
	}))
	defer server.Close()

	result := New(Config{Client: &stdhttp.Client{Transport: &stdhttp.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local fixture only
	}}}).Run(context.Background(), probe.ExecutionContext{
		Target: model.Target{URL: "https://" + strings.TrimPrefix(server.URL, "http://")},
	})
	if result.Interpretation.FailureReason != model.FailureReasonTLSHandshakeFailure || result.Interpretation.Layer != model.LayerTLS {
		t.Fatalf("interpretation = %#v, want TLS handshake failure", result.Interpretation)
	}
	if decodeEvidence[errorMetadata](t, result).ResponseReceived {
		t.Fatal("TLS failure reported an HTTP response")
	}
}

func TestProbeImplementsSharedProbeContract(t *testing.T) {
	var _ probe.Probe = New()
}

type roundTripperFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (function roundTripperFunc) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	return function(request)
}

func decodeEvidence[T any](t *testing.T, result model.ProbeResult) T {
	t.Helper()
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence = %#v, want one item", result.Evidence)
	}
	var decoded T
	if err := json.Unmarshal(result.Evidence[0].Raw, &decoded); err != nil {
		t.Fatalf("decode evidence %q: %v", result.Evidence[0].Raw, err)
	}
	return decoded
}
