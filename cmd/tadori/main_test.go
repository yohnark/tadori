package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yohnark/tadori/internal/model"
)

func TestRunDiagnoseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	stdout, stderr := captureFiles(t)

	code := run([]string{"diagnose", server.URL, "--json"}, stdout.w, stderr.w)
	stdout.close()
	stderr.close()

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr=%s", code, stderr.read(t))
	}

	var report model.DiagnosticReport
	if err := json.Unmarshal([]byte(stdout.read(t)), &report); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if report.Target.URL != server.URL {
		t.Errorf("Target.URL = %q, want %q", report.Target.URL, server.URL)
	}
	if len(report.Probes) == 0 {
		t.Errorf("expected at least one probe result in the report")
	}
}

func TestRunDiagnoseHuman(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	stdout, stderr := captureFiles(t)
	code := run([]string{"diagnose", server.URL}, stdout.w, stderr.w)
	stdout.close()
	stderr.close()

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr=%s", code, stderr.read(t))
	}
	out := stdout.read(t)
	if !strings.Contains(out, "Status:") || !strings.Contains(out, "Target: "+server.URL) {
		t.Errorf("human output missing expected sections:\n%s", out)
	}
}

func TestRunDiagnoseRejectsBadTarget(t *testing.T) {
	stdout, stderr := captureFiles(t)
	code := run([]string{"diagnose", "not-a-url"}, stdout.w, stderr.w)
	stdout.close()
	stderr.close()

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.read(t), "tadori:") {
		t.Errorf("expected stderr to contain an error message, got %q", stderr.read(t))
	}
}

func TestRunUsageWithNoArgs(t *testing.T) {
	stdout, stderr := captureFiles(t)
	code := run(nil, stdout.w, stderr.w)
	stdout.close()
	stderr.close()

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.read(t), "usage:") {
		t.Errorf("expected usage message, got %q", stderr.read(t))
	}
}

func TestRunServeRejectsNonLoopbackAddress(t *testing.T) {
	stdout, stderr := captureFiles(t)
	code := run([]string{"serve", "-addr", "0.0.0.0:0"}, stdout.w, stderr.w)
	stdout.close()
	stderr.close()

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.read(t), "loopback") {
		t.Errorf("expected loopback validation error, got %q", stderr.read(t))
	}
}

type capturedFile struct {
	w    *os.File
	path string
}

func captureFile(t *testing.T) capturedFile {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "tadori-test-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	return capturedFile{w: f, path: f.Name()}
}

func (c capturedFile) close() {
	c.w.Close()
}

func (c capturedFile) read(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(data)
}

func captureFiles(t *testing.T) (capturedFile, capturedFile) {
	return captureFile(t), captureFile(t)
}
