package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestStateChangingRequestAdmissionPolicy(t *testing.T) {
	var calls int
	handler := NewHandler(HandlerOptions{Run: func(context.Context, model.Target) model.DiagnosticReport {
		calls++
		return model.DiagnosticReport{}
	}})
	defer handler.Close()

	cases := []struct {
		name        string
		method      string
		path        string
		host        string
		origin      string
		fetchSite   string
		contentType string
		wantStatus  int
	}{
		{
			name:        "same-origin browser request",
			method:      http.MethodPost,
			path:        "/api/diagnose",
			host:        "127.0.0.1:8080",
			origin:      "http://127.0.0.1:8080",
			fetchSite:   "same-origin",
			contentType: "application/json",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "missing-origin non-browser request",
			method:      http.MethodPost,
			path:        "/api/diagnose",
			host:        "127.0.0.1:8080",
			contentType: "application/json; charset=utf-8",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "hostile origin",
			method:      http.MethodPost,
			path:        "/api/diagnose",
			host:        "127.0.0.1:8080",
			origin:      "https://attacker.example",
			fetchSite:   "cross-site",
			contentType: "application/json",
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "malformed content type",
			method:      http.MethodPost,
			path:        "/api/diagnose",
			host:        "127.0.0.1:8080",
			contentType: "application/json; charset=\"",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "host confusion",
			method:      http.MethodPost,
			path:        "/api/diagnose",
			host:        "diagnostic.attacker.example:8080",
			contentType: "application/json",
			wantStatus:  http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"target":"https://example.com"}`))
			request.Host = tc.host
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
		})
	}

	if calls != 2 {
		t.Fatalf("runner calls = %d, want 2 accepted POST requests", calls)
	}
}

func TestStateChangingRequestAdmissionChecksDelete(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	defer handler.Close()

	request := httptest.NewRequest(http.MethodDelete, "/api/diagnoses/session-1", nil)
	request.Host = "127.0.0.1:8080"
	request.Header.Set("Origin", "http://127.0.0.1:8080")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("same-origin DELETE status = %d, want 404 after admission: %s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/diagnoses/session-1", nil)
	request.Host = "127.0.0.1:8080"
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("hostile DELETE status = %d, want 403", recorder.Code)
	}
}
