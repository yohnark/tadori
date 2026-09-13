package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yohnark/tadori/internal/model"
	reportpkg "github.com/yohnark/tadori/internal/report"
	"github.com/yohnark/tadori/internal/session"
)

func TestSessionAPIStreamsProgressAndReturnsCanonicalReport(t *testing.T) {
	release := make(chan struct{})
	runnerStarted := make(chan struct{})
	target, err := model.ParseTarget(model.TargetIntent{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	wantReport := fixtureReport(target)
	handler := NewHandler(HandlerOptions{
		OverallTimeout: time.Second,
		SessionRun: func(ctx context.Context, gotTarget model.Target, progress session.Progress) model.DiagnosticReport {
			progress.ProbeStarted("fake")
			progress.ProbeCompleted(wantReport.Probes[0])
			close(runnerStarted)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return fixtureReport(gotTarget)
		},
	})
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/api/diagnoses", "application/json", strings.NewReader(`{"target":"https://example.com"}`))
	if err != nil {
		t.Fatalf("POST /api/diagnoses: %v", err)
	}
	var created session.Snapshot
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatalf("decode create response: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("create status = %d, want 202", response.StatusCode)
	}
	if created.ID == "" || created.State != session.StateRunning {
		t.Fatalf("created snapshot = %#v", created)
	}
	if got := response.Header.Get("Location"); got != "/api/diagnoses/"+created.ID {
		t.Fatalf("Location = %q", got)
	}

	eventNames := make(chan string, 16)
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		streamResponse, streamErr := server.Client().Get(server.URL + "/api/diagnoses/" + created.ID + "/events")
		if streamErr != nil {
			eventNames <- "error:" + streamErr.Error()
			return
		}
		defer streamResponse.Body.Close()
		if streamResponse.StatusCode != http.StatusOK {
			eventNames <- "status:" + streamResponse.Status
			return
		}
		scanner := bufio.NewScanner(streamResponse.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "event: ") {
				eventNames <- strings.TrimPrefix(line, "event: ")
			}
		}
		if err := scanner.Err(); err != nil {
			eventNames <- "error:" + err.Error()
		}
	}()

	select {
	case <-runnerStarted:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	seen := make(map[string]bool)
	for len(seen) < 3 {
		select {
		case eventName := <-eventNames:
			if strings.HasPrefix(eventName, "error:") || strings.HasPrefix(eventName, "status:") {
				t.Fatal(eventName)
			}
			seen[eventName] = true
			if eventName == string(session.EventProbeCompleted) {
				close(release)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for progress events; seen = %#v", seen)
		}
	}
	select {
	case <-streamDone:
	case <-time.After(time.Second):
		t.Fatal("SSE stream did not close after completion")
	}

	getResponse, err := server.Client().Get(server.URL + "/api/diagnoses/" + created.ID)
	if err != nil {
		t.Fatalf("GET session: %v", err)
	}
	defer getResponse.Body.Close()
	var completed session.Snapshot
	if err := json.NewDecoder(getResponse.Body).Decode(&completed); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if completed.State != session.StateCompleted || completed.Report == nil {
		t.Fatalf("completed snapshot = %#v", completed)
	}
	if !webTestReportsEqual(completed.Report, &wantReport) {
		t.Fatalf("session report differs from canonical runner report\n got: %#v\nwant: %#v", completed.Report, &wantReport)
	}

	for _, exported := range []struct {
		name        string
		suffix      string
		contentType string
		want        []byte
	}{
		{name: "HTML", suffix: "/report.html", contentType: "text/html; charset=utf-8", want: mustRenderHTML(t, wantReport)},
		{name: "JSON", suffix: "/report.json", contentType: "application/json; charset=utf-8", want: mustRenderJSON(t, wantReport)},
	} {
		t.Run(exported.name, func(t *testing.T) {
			response, err := server.Client().Get(server.URL + "/api/diagnoses/" + created.ID + exported.suffix)
			if err != nil {
				t.Fatalf("GET export: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read export: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("export status = %d: %s", response.StatusCode, body)
			}
			if response.Header.Get("Content-Type") != exported.contentType {
				t.Fatalf("content type = %q, want %q", response.Header.Get("Content-Type"), exported.contentType)
			}
			if response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("security/cache headers = nosniff=%q referrer=%q cache=%q", response.Header.Get("X-Content-Type-Options"), response.Header.Get("Referrer-Policy"), response.Header.Get("Cache-Control"))
			}
			if exported.name == "HTML" {
				contentSecurityPolicy := response.Header.Get("Content-Security-Policy")
				if contentSecurityPolicy != exportContentSecurityPolicy() {
					t.Fatalf("HTML export CSP = %q, want %q", contentSecurityPolicy, exportContentSecurityPolicy())
				}
				document := string(body)
				styleStart := strings.Index(document, "<style>")
				styleEnd := strings.Index(document, "</style>")
				if styleStart < 0 || styleEnd <= styleStart+len("<style>") {
					t.Fatal("HTML export has no inline report style block")
				}
				if !strings.Contains(contentSecurityPolicy, "style-src "+reportpkg.HTMLInlineStyleCSPSource()+";") {
					t.Fatalf("HTML export CSP does not permit its exact inline style block: CSP=%q", contentSecurityPolicy)
				}
			}
			if string(body) != string(exported.want) {
				t.Fatalf("export is not deterministic canonical projection")
			}
		})
	}
}

func mustRenderHTML(t *testing.T, report model.DiagnosticReport) []byte {
	t.Helper()
	encoded, err := reportpkg.RenderHTML(report)
	if err != nil {
		t.Fatalf("render HTML: %v", err)
	}
	return encoded
}

func mustRenderJSON(t *testing.T, report model.DiagnosticReport) []byte {
	t.Helper()
	encoded, err := reportpkg.RenderJSON(report)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	return encoded
}

func TestSessionAPIValidationAndCancellation(t *testing.T) {
	started := make(chan struct{})
	cancelObserved := make(chan struct{})
	handler := NewHandler(HandlerOptions{
		SessionRun: func(ctx context.Context, target model.Target, _ session.Progress) model.DiagnosticReport {
			close(started)
			<-ctx.Done()
			close(cancelObserved)
			return model.DiagnosticReport{
				SchemaVersion: model.DiagnosticSchemaVersion,
				Target:        target,
				Status:        model.ReportStatusIncomplete,
				Probes:        []model.ProbeResult{},
			}
		},
	})
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()

	invalid, err := client.Post(server.URL+"/api/diagnoses", "application/json", strings.NewReader(`{"target":"javascript:alert(1)"}`))
	if err != nil {
		t.Fatalf("invalid POST: %v", err)
	}
	if invalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid target status = %d, want 400", invalid.StatusCode)
	}
	invalid.Body.Close()

	tooLarge, err := client.Post(server.URL+"/api/diagnoses", "application/json", strings.NewReader(`{"target":"http://example.com/`+strings.Repeat("x", 9000)+`"}`))
	if err != nil {
		t.Fatalf("large POST: %v", err)
	}
	if tooLarge.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status = %d, want 413", tooLarge.StatusCode)
	}
	tooLarge.Body.Close()

	createdResponse, err := client.Post(server.URL+"/api/diagnoses", "application/json", strings.NewReader(`{"target":"http://example.com"}`))
	if err != nil {
		t.Fatalf("valid POST: %v", err)
	}
	var created session.Snapshot
	if err := json.NewDecoder(createdResponse.Body).Decode(&created); err != nil {
		createdResponse.Body.Close()
		t.Fatalf("decode valid response: %v", err)
	}
	createdResponse.Body.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("cancellable runner did not start")
	}

	deleteRequest, err := http.NewRequest(http.MethodDelete, server.URL+"/api/diagnoses/"+created.ID, nil)
	if err != nil {
		t.Fatalf("new DELETE: %v", err)
	}
	deleteResponse, err := client.Do(deleteRequest)
	if err != nil {
		t.Fatalf("DELETE session: %v", err)
	}
	if deleteResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("DELETE status = %d, want 202", deleteResponse.StatusCode)
	}
	deleteResponse.Body.Close()
	select {
	case <-cancelObserved:
	case <-time.After(time.Second):
		t.Fatal("runner did not observe cancellation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		getResponse, err := client.Get(server.URL + "/api/diagnoses/" + created.ID)
		if err != nil {
			t.Fatalf("GET cancelled session: %v", err)
		}
		var snapshot session.Snapshot
		decodeErr := json.NewDecoder(getResponse.Body).Decode(&snapshot)
		getResponse.Body.Close()
		if decodeErr != nil {
			t.Fatalf("decode cancelled session: %v", decodeErr)
		}
		if snapshot.State == session.StateCancelled {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("cancelled session did not reach terminal state: %#v", snapshot)
		default:
			time.Sleep(time.Millisecond)
		}
	}

	methodRequest := httptest.NewRequest(http.MethodGet, "/api/diagnoses", nil)
	methodRecorder := httptest.NewRecorder()
	handler.ServeHTTP(methodRecorder, methodRequest)
	if methodRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET collection status = %d, want 405", methodRecorder.Code)
	}
}

func webTestReportsEqual(left, right *model.DiagnosticReport) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
