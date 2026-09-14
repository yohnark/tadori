package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yohnark/tadori/internal/capture"
	"github.com/yohnark/tadori/internal/model"
)

type browserCaptureTestProcess struct {
	done chan struct{}
	once sync.Once
}

func (process *browserCaptureTestProcess) Wait() error {
	<-process.done
	return nil
}

func (process *browserCaptureTestProcess) Kill() error {
	process.once.Do(func() { close(process.done) })
	return nil
}

func newBrowserCaptureTestManager(t *testing.T) *capture.Manager {
	t.Helper()
	return capture.NewManager(capture.ManagerOptions{
		Capture: capture.Options{
			BrowserPath: filepath.Join(t.TempDir(), "fake-edge"),
			Launcher: func(context.Context, string, []string) (capture.Process, error) {
				return &browserCaptureTestProcess{done: make(chan struct{})}, nil
			},
		},
		NewID: func() string { return "browser-capture-api-test" },
	})
}

func TestBrowserCaptureAPIProjectsLifecycleAndCanonicalJSON(t *testing.T) {
	manager := newBrowserCaptureTestManager(t)
	handler := NewHandler(HandlerOptions{CaptureManager: manager})
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/api/browser-captures", "application/json", stringsReader(`{"browser":"edge"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created capture.Snapshot
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || created.ID != "browser-capture-api-test" || created.State != model.BrowserCaptureStateRunning {
		t.Fatalf("create response = %d/%#v", response.StatusCode, created)
	}

	proxyURL, err := url.Parse("http://" + created.ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	request.Header.Set("Authorization", "must-not-be-retained")
	upstreamResponse, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(upstreamResponse.Body)
	upstreamResponse.Body.Close()

	statusResponse, err := server.Client().Get(server.URL + "/api/browser-captures/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	var status capture.Snapshot
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		statusResponse.Body.Close()
		t.Fatal(err)
	}
	statusResponse.Body.Close()
	if status.ObservationCount != 1 || len(status.Destinations) != 1 {
		t.Fatalf("status = %#v", status)
	}

	stopRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/browser-captures/"+created.ID, nil)
	stopResponse, err := server.Client().Do(stopRequest)
	if err != nil {
		t.Fatal(err)
	}
	var stopped capture.Snapshot
	if err := json.NewDecoder(stopResponse.Body).Decode(&stopped); err != nil {
		stopResponse.Body.Close()
		t.Fatal(err)
	}
	stopResponse.Body.Close()
	if stopResponse.StatusCode != http.StatusOK || stopped.State != model.BrowserCaptureStateCompleted {
		t.Fatalf("stop response = %d/%#v", stopResponse.StatusCode, stopped)
	}

	reportResponse, err := server.Client().Get(server.URL + "/api/browser-captures/" + created.ID + "/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report model.BrowserCaptureReport
	if err := json.NewDecoder(reportResponse.Body).Decode(&report); err != nil {
		reportResponse.Body.Close()
		t.Fatal(err)
	}
	reportResponse.Body.Close()
	if reportResponse.StatusCode != http.StatusOK || report.SchemaVersion != model.BrowserCaptureSchemaVersion || report.Observations.BrowserCapture == nil {
		t.Fatalf("report response = %d/%#v", reportResponse.StatusCode, report)
	}
	encoded, _ := json.Marshal(report)
	if string(encoded) == "" || contains(string(encoded), "must-not-be-retained") {
		t.Fatalf("report retained request credentials: %s", encoded)
	}
	fqdnResponse, err := server.Client().Get(server.URL + "/api/browser-captures/" + created.ID + "/fqdns.txt")
	if err != nil {
		t.Fatal(err)
	}
	fqdnBytes, _ := io.ReadAll(fqdnResponse.Body)
	fqdnResponse.Body.Close()
	if fqdnResponse.StatusCode != http.StatusOK || string(fqdnBytes) == "" || !strings.HasSuffix(string(fqdnBytes), "\n") {
		t.Fatalf("FQDN export = %d/%q", fqdnResponse.StatusCode, fqdnBytes)
	}
}

func TestBrowserCaptureAdmissionRejectsCrossOriginStart(t *testing.T) {
	manager := newBrowserCaptureTestManager(t)
	handler := NewHandler(HandlerOptions{CaptureManager: manager})
	defer handler.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/browser-captures", stringsReader(`{"browser":"edge"}`))
	request.Host = "127.0.0.1:8080"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body.String())
	}
}

func TestBrowserCaptureMalformedRequestDoesNotStartSession(t *testing.T) {
	manager := newBrowserCaptureTestManager(t)
	handler := NewHandler(HandlerOptions{CaptureManager: manager})
	defer handler.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/browser-captures", stringsReader(`{"browser":"edge"} {}`))
	request.Host = "127.0.0.1:8080"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

func stringsReader(value string) io.Reader {
	return strings.NewReader(value)
}

func contains(value, fragment string) bool {
	return strings.Contains(value, fragment)
}
