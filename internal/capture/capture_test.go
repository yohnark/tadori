package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

type testProcess struct {
	done chan struct{}
	once sync.Once
}

func newTestProcess() *testProcess {
	return &testProcess{done: make(chan struct{})}
}

func (process *testProcess) Wait() error {
	<-process.done
	return nil
}

func (process *testProcess) Kill() error {
	process.once.Do(func() { close(process.done) })
	return nil
}

func startTestSession(t *testing.T, opts Options) (*Session, *testProcess, []string) {
	t.Helper()
	process := newTestProcess()
	var launchedPath string
	var launchedArgs []string
	opts.Browser = BrowserEdge
	opts.BrowserPath = filepath.Join(t.TempDir(), "fake-edge")
	opts.Launcher = func(_ context.Context, path string, args []string) (Process, error) {
		launchedPath = path
		launchedArgs = append([]string(nil), args...)
		return process, nil
	}
	session, err := Start(context.Background(), "capture-test", opts)
	if err != nil {
		t.Fatalf("start capture: %v", err)
	}
	t.Cleanup(func() { session.Stop() })
	if launchedPath != opts.BrowserPath {
		t.Fatalf("launcher path = %q, want %q", launchedPath, opts.BrowserPath)
	}
	return session, process, launchedArgs
}

func TestPlainHTTPObservationKeepsCanonicalEndpointFactsSeparate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("proxy authorization was forwarded")
		}
		_, _ = io.WriteString(w, "captured response")
	}))
	defer upstream.Close()

	session, _, args := startTestSession(t, Options{})
	proxyURL, err := url.Parse("http://" + session.Snapshot().ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/workflow", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "secret-value")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "captured response" {
		t.Fatalf("response body = %q", body)
	}

	snapshot := session.Snapshot()
	if snapshot.UniqueDestinationCount != 1 || snapshot.ObservationCount != 1 || snapshot.FailureCount != 0 {
		t.Fatalf("snapshot counts = %#v", snapshot)
	}
	destination := snapshot.Destinations[0]
	if destination.RequestedHostname != "127.0.0.1" || destination.Port == 0 {
		t.Fatalf("requested destination = %#v", destination)
	}
	if destination.Mechanism != model.BrowserCaptureMechanismHTTP || destination.Outcome != model.BrowserCaptureOutcomeConnected {
		t.Fatalf("destination outcome = %#v", destination)
	}
	if destination.ConnectedAddress != "127.0.0.1" || destination.ConnectedEndpoint == "" || len(destination.ResolvedAddressCandidates) != 1 {
		t.Fatalf("endpoint facts = %#v", destination)
	}
	for _, argument := range args {
		if strings.HasPrefix(argument, "--user-data-dir=") {
			profileDir := strings.TrimPrefix(argument, "--user-data-dir=")
			session.Stop()
			if _, err := os.Stat(profileDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("profile directory still exists after stop: %q (%v)", profileDir, err)
			}
		}
	}
}

func TestCONNECTObservationTunnelsWithoutReadingTLSPayload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		buffer := make([]byte, 32)
		count, readErr := connection.Read(buffer)
		if readErr == nil {
			_, _ = connection.Write(buffer[:count])
		}
	}()

	session, _, _ := startTestSession(t, Options{})
	client, err := net.Dial("tcp", session.Snapshot().ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if _, err := fmt.Fprintf(client, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port, port); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %d", response.StatusCode)
	}
	if _, err := client.Write([]byte("opaque-tls-bytes")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("opaque-tls-bytes"))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "opaque-tls-bytes" {
		t.Fatalf("tunnel echo = %q", echo)
	}

	snapshot := session.Snapshot()
	if len(snapshot.Destinations) != 1 {
		t.Fatalf("destinations = %#v", snapshot.Destinations)
	}
	destination := snapshot.Destinations[0]
	if destination.Mechanism != model.BrowserCaptureMechanismCONNECT || destination.Outcome != model.BrowserCaptureOutcomeConnected {
		t.Fatalf("CONNECT destination = %#v", destination)
	}
	if destination.ConnectedAddress != "127.0.0.1" || destination.ConnectedEndpoint == "" {
		t.Fatalf("connected endpoint = %#v", destination)
	}
	encoded, err := json.Marshal(session.CanonicalReport())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "opaque-tls-bytes") || strings.Contains(string(encoded), "Authorization") {
		t.Fatalf("canonical report retained payload data: %s", encoded)
	}
}

func TestDNSFailureIsRetained(t *testing.T) {
	session, _, _ := startTestSession(t, Options{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return nil, errors.New("fixture DNS failure")
		},
	})
	proxyURL, _ := url.Parse("http://" + session.Snapshot().ProxyAddress)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, _ := http.NewRequest(http.MethodGet, "http://blocked.example/workflow", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadGateway)
	}
	snapshot := session.Snapshot()
	if len(snapshot.Destinations) != 1 || snapshot.FailureCount != 1 {
		t.Fatalf("failure snapshot = %#v", snapshot)
	}
	destination := snapshot.Destinations[0]
	if destination.Outcome != model.BrowserCaptureOutcomeDNSFailed || destination.FailureReason != "name_resolution_failed" {
		t.Fatalf("failure destination = %#v", destination)
	}
	if destination.ConnectionCount != 0 {
		t.Fatalf("DNS failure counted as upstream connection: %#v", destination)
	}
}

func TestManagerBoundsSessionsAndCleansUp(t *testing.T) {
	processes := make([]*testProcess, 0, 2)
	manager := NewManager(ManagerOptions{
		MaxConcurrentSessions: 1,
		Capture: Options{
			BrowserPath: filepath.Join(t.TempDir(), "fake-edge"),
			Launcher: func(context.Context, string, []string) (Process, error) {
				process := newTestProcess()
				processes = append(processes, process)
				return process, nil
			},
		},
		NewID: func() string { return "capture-manager-test" },
	})
	defer manager.Close()
	first, err := manager.Start(context.Background(), BrowserEdge)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "capture-manager-test" {
		t.Fatalf("id = %q", first.ID)
	}
	if _, err := manager.Start(context.Background(), BrowserEdge); !errors.Is(err, ErrBusy) {
		t.Fatalf("second start error = %v, want ErrBusy", err)
	}
	if _, err := manager.Stop(first.ID); err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 {
		t.Fatalf("process count = %d", len(processes))
	}
	if _, err := manager.Start(context.Background(), BrowserEdge); err != nil {
		t.Fatalf("start after stop: %v", err)
	}
}

func TestParseProxyAuthorityRejectsAmbiguousTargets(t *testing.T) {
	for _, authority := range []string{"", "example.com:", "example.com:0", "2001:db8::1:443", "https://example.com:443", "user@example.com:443"} {
		if _, _, err := parseProxyAuthority(authority, 443); err == nil {
			t.Errorf("parseProxyAuthority(%q) accepted invalid authority", authority)
		}
	}
	for _, test := range []struct {
		authority string
		wantHost  string
		wantPort  uint16
	}{
		{authority: "Example.COM", wantHost: "example.com", wantPort: 443},
		{authority: "[::1]:8443", wantHost: "::1", wantPort: 8443},
	} {
		host, port, err := parseProxyAuthority(test.authority, 443)
		if err != nil || host != test.wantHost || port != test.wantPort {
			t.Errorf("parseProxyAuthority(%q) = %q/%d/%v", test.authority, host, port, err)
		}
	}
}

func TestSessionStopIsBoundedWhenContextCancels(t *testing.T) {
	process := newTestProcess()
	session, err := Start(context.Background(), "cancel-test", Options{
		BrowserPath:        filepath.Join(t.TempDir(), "fake-edge"),
		MaxSessionDuration: 20 * time.Millisecond,
		Launcher:           func(context.Context, string, []string) (Process, error) { return process, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.stopDone:
	case <-time.After(time.Second):
		t.Fatal("session did not stop at its duration bound")
	}
	if got := session.Snapshot().State; got != model.BrowserCaptureStateCompleted {
		t.Fatalf("state = %q", got)
	}
}
