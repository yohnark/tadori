package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/session"
)

func TestHandlerIntegrationServesUIAndCanonicalReport(t *testing.T) {
	var called bool
	var gotTarget model.Target
	runner := func(_ context.Context, target model.Target) model.DiagnosticReport {
		called = true
		gotTarget = target
		return fixtureReport(target)
	}
	server := httptest.NewServer(NewHandler(HandlerOptions{Run: runner}))
	defer server.Close()

	client := server.Client()
	page := getBody(t, client, server.URL+"/")
	if !strings.Contains(page, "<form id=\"diagnose-form\">") {
		t.Errorf("UI page does not contain the diagnose form")
	}
	if !strings.Contains(page, "Raw evidence") || !strings.Contains(page, "Canonical JSON") {
		t.Errorf("UI page is missing required report sections")
	}
	if !strings.Contains(page, "HTML Report") || !strings.Contains(page, "json-report-link") {
		t.Errorf("UI page is missing report export affordances")
	}
	for _, fragment := range []string{
		`id="observed-path-panel"`,
		`id="path-graph-tab"`,
		`id="path-table-tab"`,
		`id="path-graph-viewport"`,
		`id="path-graph-empty"`,
		`id="path-graph-loading"`,
		`id="path-graph-unsupported"`,
		`Node selection → Evidence inspector`,
		`not physical topology`,
	} {
		if !strings.Contains(page, fragment) {
			t.Errorf("UI page is missing Observed Path workbench fragment %q", fragment)
		}
	}

	style := getBody(t, client, server.URL+"/style.css")
	if !strings.Contains(style, ".target-row") {
		t.Errorf("style.css was not served")
	}
	script := getBody(t, client, server.URL+"/app.js")
	if !strings.Contains(script, "raw.textContent") {
		t.Errorf("app.js does not render raw evidence as text")
	}
	if strings.Contains(script, "innerHTML") {
		t.Errorf("app.js must not render evidence with innerHTML")
	}
	if !strings.Contains(script, "/report.html") || !strings.Contains(script, "/report.json") {
		t.Errorf("app.js does not expose report export URLs")
	}
	for _, fragment := range []string{"selectPathView", "renderPathGraph", "setPathGraphState", "data-path-view"} {
		if !strings.Contains(script, fragment) {
			t.Errorf("app.js is missing Observed Path projection behavior %q", fragment)
		}
	}
	composer := getBody(t, client, server.URL+"/composer.js")
	if !strings.Contains(composer, "TadoriTargetComposer") || !strings.Contains(composer, "PROVENANCE") {
		t.Errorf("composer.js does not expose the deterministic composer model")
	}

	targetURL := "https://example.com:8443/diagnose"
	body := `{"target":"` + targetURL + `"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/diagnose", strings.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /api/diagnose: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read diagnose response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/diagnose status = %d, want 200: %s", response.StatusCode, responseBody)
	}
	if got := response.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("diagnose Content-Type = %q", got)
	}

	parsedTarget, err := model.ParseTarget(model.TargetIntent{Input: targetURL})
	if err != nil {
		t.Fatalf("parse expected target: %v", err)
	}
	expected := fixtureReport(parsedTarget)
	wantJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("marshal expected report: %v", err)
	}
	if string(responseBody) != string(wantJSON) {
		t.Fatalf("diagnose response is not canonical JSON\n got: %s\nwant: %s", responseBody, wantJSON)
	}
	if !called {
		t.Fatal("diagnostic runner was not invoked")
	}
	if !reflect.DeepEqual(gotTarget, parsedTarget) {
		t.Errorf("runner target = %+v, want %+v", gotTarget, parsedTarget)
	}
}

func TestDiagnosticViewEndpointKeepsCanonicalReportAndAcceptsProgressAdapter(t *testing.T) {
	var runCalled bool
	var progressCalled bool
	runner := func(_ context.Context, target model.Target) model.DiagnosticReport {
		runCalled = true
		return fixtureReport(target)
	}
	progress := func(_ context.Context, target model.Target, emit func(ProgressEvent)) model.DiagnosticReport {
		progressCalled = true
		emit(ProgressEvent{ProbeName: "dns", State: "running"})
		return fixtureReport(target)
	}
	server := httptest.NewServer(NewHandler(HandlerOptions{Run: runner, Progress: progress}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/diagnose/view", strings.NewReader(`{"target":"https://example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("POST /api/diagnose/view: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want 200: %s", response.StatusCode, body)
	}

	var view DiagnosticViewModel
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatalf("decode diagnostic view: %v", err)
	}
	canonical, err := json.Marshal(view.Report)
	if err != nil {
		t.Fatal(err)
	}
	if view.CanonicalJSON != string(canonical) {
		t.Fatalf("view canonical_json differs from embedded report")
	}
	if !progressCalled || runCalled {
		t.Fatalf("adapter selection = progressCalled %t, runCalled %t", progressCalled, runCalled)
	}
	if len(view.Progress) < 2 || view.Progress[1].State != "running" {
		t.Fatalf("progress events = %#v", view.Progress)
	}
	if len(view.Probes) != len(view.Report.Probes) || len(view.Evidence) == 0 {
		t.Fatalf("view projection omitted report content: probes=%d report=%d evidence=%d", len(view.Probes), len(view.Report.Probes), len(view.Evidence))
	}
}

func TestStructuredTargetIntentRoundTripsThroughAPI(t *testing.T) {
	var received model.Target
	handler := NewHandler(HandlerOptions{Run: func(_ context.Context, target model.Target) model.DiagnosticReport {
		received = target
		return fixtureReport(target)
	}})
	defer handler.Close()

	request := httptest.NewRequest(http.MethodPost, "/api/diagnose", strings.NewReader(`{"target":{"input":"fileserver01","service":"smb","port":1445}}`))
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("structured target status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if received.OriginalInput != "fileserver01" || received.RequestedIdentity != "fileserver01" || received.Service.ID != model.ServiceProfileSMB || received.Port != 1445 {
		t.Fatalf("structured target was not normalized authoritatively: %#v", received)
	}
	var report model.DiagnosticReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode structured target report: %v", err)
	}
	if !reflect.DeepEqual(report.Target, received) {
		t.Fatalf("structured target did not round-trip in report: got %#v want %#v", report.Target, received)
	}
}

func TestSessionViewEndpointProjectsTerminalCanonicalReport(t *testing.T) {
	target := fixtureTarget(443)
	representative := representativeUIFixtures()["icmp-unobservable-tcp-reaches"]
	handler := NewHandler(HandlerOptions{
		SessionRun: func(context.Context, model.Target, session.Progress) model.DiagnosticReport {
			return representative
		},
	})
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/api/diagnoses", "application/json", strings.NewReader(`{"target":"https://203.0.113.10:443/health"}`))
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatalf("decode session: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || created.ID == "" {
		t.Fatalf("create response = %d/%q", response.StatusCode, created.ID)
	}
	if _, err := handler.sessions.Wait(context.Background(), created.ID); err != nil {
		t.Fatalf("wait for session: %v", err)
	}

	viewResponse, err := server.Client().Get(server.URL + "/api/diagnoses/" + created.ID + "/view")
	if err != nil {
		t.Fatalf("get session view: %v", err)
	}
	defer viewResponse.Body.Close()
	if viewResponse.StatusCode != http.StatusOK {
		t.Fatalf("session view status = %d, want 200", viewResponse.StatusCode)
	}
	var view DiagnosticViewModel
	if err := json.NewDecoder(viewResponse.Body).Decode(&view); err != nil {
		t.Fatalf("decode session view: %v", err)
	}
	if len(view.Paths) != 2 || view.Overall.Destination.State != "confirmed" || !reflect.DeepEqual(view.Report.Target, target) {
		t.Fatalf("session view projection = paths %d, destination %q, target %#v", len(view.Paths), view.Overall.Destination.State, view.Report.Target)
	}
}

func TestDiagnoseHandlerRejectsInvalidTargetWithoutRunning(t *testing.T) {
	called := false
	handler := NewHandler(HandlerOptions{Run: func(context.Context, model.Target) model.DiagnosticReport {
		called = true
		return model.DiagnosticReport{}
	}})
	request := httptest.NewRequest(http.MethodPost, "/api/diagnose", strings.NewReader(`{"target":"javascript:alert(1)"}`))
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if called {
		t.Fatal("runner was invoked for an invalid target")
	}
	if !strings.Contains(recorder.Body.String(), "unsupported diagnose target scheme") {
		t.Errorf("error response = %q", recorder.Body.String())
	}
}

func TestDiagnoseHandlerForwardsRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	handler := NewHandler(HandlerOptions{
		Run: func(ctx context.Context, target model.Target) model.DiagnosticReport {
			close(started)
			<-ctx.Done()
			close(canceled)
			return fixtureReport(target)
		},
		OverallTimeout: time.Minute,
	})
	requestContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/diagnose", strings.NewReader(`{"target":"http://example.com"}`)).WithContext(requestContext)
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("diagnostic runner did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("diagnostic runner did not receive request cancellation")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not return after request cancellation")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 partial report", recorder.Code)
	}
}

func TestValidateLoopbackAddress(t *testing.T) {
	cases := []struct {
		address string
		valid   bool
	}{
		{address: "127.0.0.1:8080", valid: true},
		{address: "[::1]:8080", valid: true},
		{address: "127.0.0.1:0", valid: true},
		{address: ":8080", valid: false},
		{address: "localhost:8080", valid: false},
		{address: "0.0.0.0:8080", valid: false},
		{address: "192.0.2.1:8080", valid: false},
		{address: "127.0.0.1", valid: false},
	}
	for _, tc := range cases {
		t.Run(tc.address, func(t *testing.T) {
			err := ValidateLoopbackAddress(tc.address)
			if tc.valid && err != nil {
				t.Fatalf("ValidateLoopbackAddress(%q): %v", tc.address, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("ValidateLoopbackAddress(%q) unexpectedly succeeded", tc.address)
			}
		})
	}
}

func TestHandlerMethodAndPathBoundaries(t *testing.T) {
	handler := NewHandler(HandlerOptions{Run: func(context.Context, model.Target) model.DiagnosticReport {
		return model.DiagnosticReport{}
	}})

	request := httptest.NewRequest(http.MethodGet, "/api/diagnose", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/diagnose status = %d, want 405", recorder.Code)
	}
	if recorder.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET /api/diagnose Allow = %q, want POST", recorder.Header().Get("Allow"))
	}

	request = httptest.NewRequest(http.MethodGet, "/not-a-static-file", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("GET unknown path status = %d, want 404", recorder.Code)
	}
}

func getBody(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(body)
}

func fixtureReport(target model.Target) model.DiagnosticReport {
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("fixture", 9*60*60))
	completed := started.Add(250 * time.Millisecond)
	return model.DiagnosticReport{
		SchemaVersion: model.DiagnosticSchemaVersion,
		Target:        target,
		Status:        model.ReportStatusComplete,
		StartedAt:     &started,
		CompletedAt:   &completed,
		Probes: []model.ProbeResult{
			{
				Name:   "dns",
				Target: target,
				Status: model.ProbeStatusPassed,
				Timing: model.Timing{DurationMS: 10},
				Evidence: []model.Evidence{
					{ID: "dns-1", Kind: model.EvidenceKindDNSResolution, Raw: json.RawMessage(`"<script>alert(1)</script>"`)},
				},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonNone,
					Layer:         model.LayerDNS,
					FaultDomain:   model.FaultDomainDNS,
				},
			},
			{
				Name:   "http",
				Target: target,
				Status: model.ProbeStatusFailed,
				Timing: model.Timing{DurationMS: 20},
				Interpretation: model.ProbeInterpretation{
					FailureReason: model.FailureReasonHTTPStatusCode,
					Layer:         model.LayerHTTP,
					FaultDomain:   model.FaultDomainHTTP,
				},
			},
		},
		Findings: []model.DiagnosticFinding{
			{
				FailureReason: model.FailureReasonHTTPStatusCode,
				Layer:         model.LayerHTTP,
				FaultDomain:   model.FaultDomainHTTP,
				ProbeNames:    []string{"http"},
				EvidenceIDs:   []string{"http-1"},
			},
		},
	}
}
