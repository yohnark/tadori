// Package web provides the loopback HTTP adapter and embedded browser UI for
// local diagnostic sessions.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/orchestrate"
	"github.com/yohnark/tadori/internal/report"
	"github.com/yohnark/tadori/internal/session"
)

// DefaultOverallTimeout bounds one diagnostic execution. The orchestration
// package continues to enforce its own per-probe timeout and returns partial
// results it can collect before this session deadline.
const DefaultOverallTimeout = session.DefaultOverallTimeout

const maxDiagnoseRequestBytes = 8 << 10

//go:embed static/index.html static/style.css static/app.js
var staticFiles embed.FS

// Runner is retained for compatibility with the #26 synchronous endpoint and
// for simple HTTP tests. New code should use SessionRunner so progress hooks
// can reach the canonical orchestration path.
type Runner func(context.Context, model.Target) model.DiagnosticReport

// SessionRunner is the in-process orchestration function used by new
// diagnosis sessions. It must return the canonical final DiagnosticReport.
type SessionRunner = session.Runner

// HandlerOptions controls the HTTP adapter. Zero values select the production
// orchestration runner and bounded local defaults.
type HandlerOptions struct {
	// Run is the legacy runner for POST /api/diagnose and, when SessionRun is
	// unset, is also adapted for the session API.
	Run Runner
	// SessionRun supplies the direct runner for POST /api/diagnoses.
	SessionRun SessionRunner
	// SessionManager can be supplied by tests or an embedding application.
	// When nil, NewHandler creates an in-memory manager.
	SessionManager        *session.Manager
	OverallTimeout        time.Duration
	MaxConcurrentSessions int
}

// Handler serves embedded static assets and the session API. Its session
// state is process-local and is closed explicitly by the CLI during graceful
// shutdown.
type Handler struct {
	mux            http.Handler
	sessions       *session.Manager
	legacyRun      Runner
	legacyTimeout  time.Duration
	legacyCapacity chan struct{}
	closeOnce      sync.Once
}

// NewHandler returns the local UI and structured diagnosis API.
func NewHandler(opts HandlerOptions) *Handler {
	legacyRun := opts.Run
	if legacyRun == nil {
		legacyRun = func(ctx context.Context, target model.Target) model.DiagnosticReport {
			return orchestrate.Run(ctx, target, orchestrate.Options{})
		}
	}

	sessionRun := opts.SessionRun
	if sessionRun == nil {
		if opts.Run != nil {
			sessionRun = func(ctx context.Context, target model.Target, _ session.Progress) model.DiagnosticReport {
				return opts.Run(ctx, target)
			}
		} else {
			sessionRun = func(ctx context.Context, target model.Target, progress session.Progress) model.DiagnosticReport {
				return orchestrate.Run(ctx, target, orchestrate.Options{
					OnProbeStarted:   progress.ProbeStarted,
					OnProbeCompleted: progress.ProbeCompleted,
				})
			}
		}
	}

	overallTimeout := opts.OverallTimeout
	if overallTimeout <= 0 {
		overallTimeout = DefaultOverallTimeout
	}
	legacyMaxConcurrent := opts.MaxConcurrentSessions
	if legacyMaxConcurrent <= 0 {
		legacyMaxConcurrent = session.DefaultMaxConcurrentSessions
	}
	manager := opts.SessionManager
	if manager == nil {
		manager = session.NewManager(session.Options{
			Run:                   sessionRun,
			OverallTimeout:        overallTimeout,
			MaxConcurrentSessions: opts.MaxConcurrentSessions,
		})
	}

	h := &Handler{
		sessions:       manager,
		legacyRun:      legacyRun,
		legacyTimeout:  overallTimeout,
		legacyCapacity: make(chan struct{}, legacyMaxConcurrent),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.staticIndex)
	mux.HandleFunc("/style.css", staticHandler("style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/app.js", staticHandler("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/api/diagnose", h.legacyDiagnose)
	mux.HandleFunc("/api/diagnoses", h.diagnosisCollection)
	mux.HandleFunc("/api/diagnoses/", h.diagnosisResource)
	h.mux = mux
	return h
}

// Close cancels active sessions and rejects new ones. It is safe to call more
// than once and is intended to be paired with http.Server.Shutdown.
func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		if h.sessions != nil {
			h.sessions.Close()
		}
	})
}

// ServeHTTP adds browser-safe response headers and delegates to the route
// handler. The network listener, rather than this adapter, enforces the
// loopback-only boundary.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) staticIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	staticHandler("index.html", "text/html; charset=utf-8")(w, r)
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
		w.Header().Set("Cache-Control", "no-store")
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

func (h *Handler) diagnosisCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	target, ok := decodeTarget(w, r)
	if !ok {
		return
	}
	snapshot, err := h.sessions.Create(target)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrBusy):
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, err.Error())
		case errors.Is(err, session.ErrClosed):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.Header().Set("Location", "/api/diagnoses/"+snapshot.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, snapshot)
}

func (h *Handler) diagnosisResource(w http.ResponseWriter, r *http.Request) {
	id, events, ok := parseDiagnosisPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if events {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.diagnosisEvents(w, r, id)
		return
	}

	switch r.Method {
	case http.MethodGet:
		snapshot, err := h.sessions.Get(id)
		if err != nil {
			writeSessionError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, snapshot)
	case http.MethodDelete:
		snapshot, err := h.sessions.Cancel(id)
		if err != nil {
			writeSessionError(w, err)
			return
		}
		status := http.StatusOK
		if snapshot.State == session.StateCancelling {
			status = http.StatusAccepted
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, status, snapshot)
	default:
		methodNotAllowed(w, http.MethodGet+", "+http.MethodDelete)
	}
}

func (h *Handler) diagnosisEvents(w http.ResponseWriter, r *http.Request, id string) {
	after, err := eventCursor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.sessions.Get(id); err != nil {
		writeSessionError(w, err)
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		writeError(w, http.StatusInternalServerError, "SSE is not supported by this response writer")
		return
	}
	stream, unsubscribe, err := h.sessions.Subscribe(id, after)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher := w.(http.Flusher)
	flusher.Flush()

	for {
		select {
		case event, open := <-stream:
			if !open {
				return
			}
			if err := writeSSE(w, event); err != nil {
				return
			}
			flusher.Flush()
			if event.Type == session.EventDiagnosisCompleted || event.Type == session.EventDiagnosisCancelled {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func (h *Handler) legacyDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	target, ok := decodeTarget(w, r)
	if !ok {
		return
	}
	select {
	case h.legacyCapacity <- struct{}{}:
		defer func() { <-h.legacyCapacity }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "diagnostic session capacity is full")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.legacyTimeout)
	defer cancel()
	diagnosticReport := h.legacyRun(ctx, target)
	encoded, err := report.MarshalJSON(diagnosticReport)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode diagnostic report: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(encoded)
}

func decodeTarget(w http.ResponseWriter, r *http.Request) (model.Target, bool) {
	var request diagnoseRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDiagnoseRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		if isBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		} else {
			writeError(w, http.StatusBadRequest, "request body must be JSON with a target")
		}
		return model.Target{}, false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if isBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		} else {
			writeError(w, http.StatusBadRequest, "request body must contain one JSON object")
		}
		return model.Target{}, false
	}

	target, err := orchestrate.ParseTarget(request.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return model.Target{}, false
	}
	return target, true
}

func isBodyTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func parseDiagnosisPath(path string) (id string, events bool, ok bool) {
	const prefix = "/api/diagnoses/"
	if !strings.HasPrefix(path, prefix) {
		return "", false, false
	}
	remainder := strings.TrimPrefix(path, prefix)
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && validSessionID(parts[0]) {
		return parts[0], false, true
	}
	if len(parts) == 2 && parts[1] == "events" && validSessionID(parts[0]) {
		return parts[0], true, true
	}
	return "", false, false
}

func validSessionID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, character := range id {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func eventCursor(r *http.Request) (uint64, error) {
	value := r.Header.Get("Last-Event-ID")
	if query := r.URL.Query().Get("after"); query != "" {
		value = query
	}
	if value == "" {
		return 0, nil
	}
	cursor, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("event cursor must be a non-negative integer")
	}
	return cursor, nil
}

func writeSSE(w io.Writer, event session.Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	eventName := string(event.Type)
	if !validSSEEventName(eventName) {
		eventName = "message"
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Sequence, eventName, encoded)
	return err
}

func validSSEEventName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func writeSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
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
