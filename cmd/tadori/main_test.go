package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

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
	if report.Target.OriginalInput != server.URL || report.Target.RequestedIdentity != "127.0.0.1" {
		t.Errorf("canonical target = %#v, want original input and loopback identity", report.Target)
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
	if !strings.Contains(out, "Status:") || !strings.Contains(out, "Target: 127.0.0.1") || !strings.Contains(out, "Service: HTTP") {
		t.Errorf("human output missing expected sections:\n%s", out)
	}
}

func TestRunDiagnoseHostPortJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	target := "127.0.0.1:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	stdout, stderr := captureFiles(t)
	code := run([]string{"diagnose", target, "--json"}, stdout.w, stderr.w)
	stdout.close()
	stderr.close()
	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr=%s", code, stderr.read(t))
	}
	var report model.DiagnosticReport
	if err := json.Unmarshal([]byte(stdout.read(t)), &report); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if report.Target.OriginalInput == "" || report.Target.RequestedIdentity != "127.0.0.1" || report.Target.Port != uint16(listener.Addr().(*net.TCPAddr).Port) {
		t.Fatalf("host:port target was not preserved: %#v", report.Target)
	}
	if !strings.Contains(stdout.read(t), `"kind":"path_observation"`) {
		t.Fatalf("JSON report did not include path evidence: %s", stdout.read(t))
	}
}

func TestRunDiagnoseRejectsBadTarget(t *testing.T) {
	stdout, stderr := captureFiles(t)
	code := run([]string{"diagnose", "javascript:alert(1)"}, stdout.w, stderr.w)
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

func TestRunServeContextSelectsFreePortAndOpensBrowserByDefault(t *testing.T) {
	stdout, stderr := captureFiles(t)
	defer stdout.close()
	defer stderr.close()

	ctx, cancel := context.WithCancel(context.Background())
	var openedURL string
	code := runServeContext(ctx, []string{"--port", "0"}, stdout.w, stderr.w, func(rawURL string) error {
		openedURL = rawURL
		cancel()
		return nil
	})
	if code != 0 {
		t.Fatalf("runServeContext() exit code = %d; stderr=%s", code, stderr.read(t))
	}
	if !strings.HasPrefix(openedURL, "http://127.0.0.1:") || !strings.HasSuffix(openedURL, "/") {
		t.Fatalf("browser URL = %q, want loopback URL with selected port", openedURL)
	}
	if !strings.Contains(stdout.read(t), openedURL) {
		t.Fatalf("stdout does not report browser URL %q: %s", openedURL, stdout.read(t))
	}
}

func TestRunServeContextNoOpenOptOut(t *testing.T) {
	stdout, stderr := captureFiles(t)
	defer stdout.close()
	defer stderr.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()
	opened := false
	code := runServeContext(ctx, []string{"--port", "0", "--no-open"}, stdout.w, stderr.w, func(string) error {
		opened = true
		return nil
	})
	if code != 0 {
		t.Fatalf("runServeContext() exit code = %d; stderr=%s", code, stderr.read(t))
	}
	if opened {
		t.Fatal("browser opener was called with --no-open")
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
