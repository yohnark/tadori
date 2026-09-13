// Package web provides the local browser UI for a diagnostic run.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/orchestrate"
	"github.com/yohnark/tadori/internal/report"
)

// DefaultOverallTimeout bounds one request for the complete diagnostic run.
// The orchestration package continues to enforce its own per-probe timeout
// and returns all partial results it can collect before the request ends.
const DefaultOverallTimeout = 30 * time.Second

const maxDiagnoseRequestBytes = 8 << 10

//go:embed static/index.html static/style.css static/app.js
var staticFiles embed.FS

// Runner is the existing diagnostic orchestration function used by Handler.
// It is a function type so HTTP tests can use deterministic reports without
// replacing the production orchestration path.
type Runner func(context.Context, model.Target) model.DiagnosticReport

// HandlerOptions controls the HTTP adapter. Zero values select the production
// runner and DefaultOverallTimeout.
type HandlerOptions struct {
	Run            Runner
	OverallTimeout time.Duration
}

// NewHandler returns the local UI and its JSON API.
func NewHandler(opts HandlerOptions) http.Handler {
	run := opts.Run
	if run == nil {
		run = func(ctx context.Context, target model.Target) model.DiagnosticReport {
			return orchestrate.Run(ctx, target, orchestrate.Options{})
		}
	}
	if opts.OverallTimeout <= 0 {
		opts.OverallTimeout = DefaultOverallTimeout
	}

	mux := http.NewServeMux()
	indexHandler := staticHandler("index.html", "text/html; charset=utf-8")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		indexHandler(w, r)
	})
	mux.HandleFunc("/style.css", staticHandler("style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/app.js", staticHandler("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/api/diagnose", diagnoseHandler(run, opts.OverallTimeout))
	return mux
}

func staticHandler(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, http.MethodGet+", "+http.MethodHead)
			return
		}

		data, err := staticFiles.ReadFile("static/" + name)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(data)
	}
}

type diagnoseRequest struct {
	Target string `json:"target"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func diagnoseHandler(run Runner, overallTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		var request diagnoseRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDiagnoseRequestBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "request body must be JSON with a target")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "request body must contain one JSON object")
			return
		}

		target, err := orchestrate.ParseTarget(request.Target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), overallTimeout)
		defer cancel()
		diagnosticReport := run(ctx, target)

		encoded, err := report.MarshalJSON(diagnosticReport)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode diagnostic report: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(encoded)
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message})
}

// ValidateLoopbackAddress accepts only a host:port address whose host is a
// literal loopback IP. Requiring a literal avoids depending on DNS when
// enforcing the local-only boundary.
func ValidateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("listen address must be a loopback host and port, for example 127.0.0.1:8080")
	}
	if host == "" {
		return errors.New("listen address must use a loopback IP, not all interfaces")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("listen address must use a literal loopback IP (127.0.0.1 or ::1)")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber > 65535 {
		return errors.New("listen address has an invalid port")
	}
	return nil
}
