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
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yohnark/tadori/internal/batch"
	"github.com/yohnark/tadori/internal/capture"
	"github.com/yohnark/tadori/internal/environment"
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

const workbenchContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'"

const exportContentSecurityPolicyPrefix = "default-src 'none'; script-src 'none'; style-src "

func exportContentSecurityPolicy() string {
	return exportContentSecurityPolicyPrefix + report.HTMLInlineStyleCSPSource() + "; style-src-attr 'none'; img-src 'none'; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

//go:embed static/index.html static/style.css static/composer.js static/display.js static/locale.js static/app.js
var staticFiles embed.FS

// Runner is retained for compatibility with the #26 synchronous endpoint and
// for simple HTTP tests. New code should use SessionRunner so progress hooks
// can reach the canonical orchestration path.
type Runner func(context.Context, model.Target) model.DiagnosticReport

// SessionRunner is the in-process orchestration function used by new
// diagnosis sessions. It must return the canonical final DiagnosticReport.
type SessionRunner = session.Runner

// EnvironmentRunner collects target-independent local context. It has no
// target argument by design; callers cannot accidentally turn an environment
// inspection into a destination diagnosis.
type EnvironmentRunner func(context.Context) (model.EnvironmentSnapshot, error)

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
	SessionManager *session.Manager
	// CaptureManager owns browser-scoped loopback proxy sessions. When nil,
	// NewHandler creates a bounded single-session manager.
	CaptureManager *capture.Manager
	// CaptureOptions configures the production browser capture manager.
	CaptureOptions capture.Options
	// ValidationManager can be supplied by tests or an embedding application.
	// When nil, NewHandler creates a bounded in-memory manager that uses the
	// canonical orchestration runner.
	ValidationManager *batch.Manager
	// ValidationOptions configures the production batch validation manager when
	// ValidationManager is nil.
	ValidationOptions batch.Options
	// Progress is the optional UI projection adapter for the legacy synchronous
	// view endpoint. Session/SSE consumers use SessionRun instead.
	Progress              ProgressRunner
	EnvironmentRun        EnvironmentRunner
	OverallTimeout        time.Duration
	MaxConcurrentSessions int
}

// Handler serves embedded static assets and the session API. Its session
// state is process-local and is closed explicitly by the CLI during graceful
// shutdown.
type Handler struct {
	mux            http.Handler
	sessions       *session.Manager
	captures       *capture.Manager
	validations    *batch.Manager
	environmentRun EnvironmentRunner
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
					SessionID:        progress.SessionID,
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
	captureManager := opts.CaptureManager
	if captureManager == nil {
		captureManager = capture.NewManager(capture.ManagerOptions{Capture: opts.CaptureOptions})
	}
	validationManager := opts.ValidationManager
	if validationManager == nil {
		validationManager = batch.NewManager(opts.ValidationOptions)
	}
	environmentRun := opts.EnvironmentRun
	if environmentRun == nil {
		environmentRun = func(ctx context.Context) (model.EnvironmentSnapshot, error) {
			return environment.Collect(ctx)
		}
	}

	h := &Handler{
		sessions:       manager,
		captures:       captureManager,
		validations:    validationManager,
		legacyRun:      legacyRun,
		legacyTimeout:  overallTimeout,
		legacyCapacity: make(chan struct{}, legacyMaxConcurrent),
		environmentRun: environmentRun,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.staticIndex)
	mux.HandleFunc("/style.css", staticHandler("style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("/composer.js", staticHandler("composer.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/display.js", staticHandler("display.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/locale.js", staticHandler("locale.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/app.js", staticHandler("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("/api/diagnose", h.legacyDiagnose)
	mux.HandleFunc("/api/environment", h.environmentSnapshot)
	mux.HandleFunc("/api/environment.json", h.environmentExport)
	mux.HandleFunc("/api/diagnose/view", diagnoseViewHandler(legacyRun, opts.Progress, overallTimeout))
	mux.HandleFunc("/api/diagnoses", h.diagnosisCollection)
	mux.HandleFunc("/api/diagnoses/", h.diagnosisResource)
	mux.HandleFunc("/api/browser-captures", h.browserCaptureCollection)
	mux.HandleFunc("/api/browser-captures/", h.browserCaptureResource)
	mux.HandleFunc("/api/browser-capture-validations/", h.browserCaptureValidationResource)
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
		if h.captures != nil {
			h.captures.Close()
		}
		if h.validations != nil {
			h.validations.Close()
		}
	})
}

// ServeHTTP adds browser-safe response headers and delegates to the route
// handler. The network listener, rather than this adapter, enforces the
// loopback-only boundary.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", workbenchContentSecurityPolicy)
	if admissionErr := admitRequest(r); admissionErr != nil {
		writeError(w, admissionErr.status, admissionErr.message)
		return
	}
	h.mux.ServeHTTP(w, r)
}

type requestAdmissionError struct {
	status  int
	message string
}

// admitRequest is the single admission policy for endpoints that can start or
// cancel diagnostic activity. A request with no browser metadata is the
// explicit non-browser policy: it is accepted for a literal loopback Host so
// CLI and other local HTTP clients remain usable. Browser-signaled requests
// must identify this server as their same-origin destination.
func admitRequest(r *http.Request) *requestAdmissionError {
	if !requiresRequestAdmission(r) {
		return nil
	}

	requestAuthority, err := parseLocalAuthority(r.Host)
	if err != nil {
		return &requestAdmissionError{
			status:  http.StatusForbidden,
			message: "request Host must be a literal loopback address",
		}
	}

	if err := validateFetchSite(r); err != nil {
		return &requestAdmissionError{status: http.StatusForbidden, message: err.Error()}
	}
	if err := validateOrigin(r, requestAuthority); err != nil {
		return &requestAdmissionError{status: http.StatusForbidden, message: err.Error()}
	}
	if r.Method == http.MethodPost {
		if err := requireJSONContentType(r); err != nil {
			return &requestAdmissionError{status: http.StatusUnsupportedMediaType, message: err.Error()}
		}
	}
	return nil
}

func requiresRequestAdmission(r *http.Request) bool {
	switch {
	case r.Method == http.MethodPost:
		if r.URL.Path == "/api/diagnoses" || r.URL.Path == "/api/diagnose" || r.URL.Path == "/api/diagnose/view" ||
			r.URL.Path == "/api/browser-captures" || r.URL.Path == "/api/environment" {
			return true
		}
		_, action, ok := parseBrowserCapturePath(r.URL.Path)
		return ok && action == browserCaptureValidationCollection
	case r.Method == http.MethodDelete:
		if _, events, ok := parseDiagnosisPath(r.URL.Path); ok && !events {
			return true
		}
		_, action, ok := parseBrowserCapturePath(r.URL.Path)
		if ok && action == browserCaptureSession {
			return true
		}
		_, _, _, ok = parseBrowserCaptureValidationPath(r.URL.Path)
		return ok
	default:
		return false
	}
}

func validateFetchSite(r *http.Request) error {
	values := r.Header.Values("Sec-Fetch-Site")
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 || values[0] != "same-origin" {
		return errors.New("request fetch site is not same-origin")
	}
	return nil
}

func validateOrigin(r *http.Request, requestAuthority localAuthority) error {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 || values[0] == "" || values[0] == "null" {
		return errors.New("request Origin is not allowed")
	}

	origin, err := url.Parse(values[0])
	if err != nil || origin.User != nil || origin.Opaque != "" || origin.Host == "" ||
		origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("request Origin is not allowed")
	}
	originScheme := strings.ToLower(origin.Scheme)
	if originScheme != "http" && originScheme != "https" {
		return errors.New("request Origin is not allowed")
	}
	originAuthority, err := parseLocalAuthority(origin.Host)
	if err != nil || originAuthority.identity != requestAuthority.identity {
		return errors.New("request Origin is not same-origin")
	}

	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}
	if originScheme != requestScheme {
		return errors.New("request Origin is not same-origin")
	}
	if effectiveOriginPort(originScheme, originAuthority.port, originAuthority.hasPort) !=
		effectiveOriginPort(requestScheme, requestAuthority.port, requestAuthority.hasPort) {
		return errors.New("request Origin is not same-origin")
	}
	return nil
}

func requireJSONContentType(r *http.Request) error {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return errors.New("request Content-Type must be application/json")
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil || strings.ToLower(mediaType) != "application/json" {
		return errors.New("request Content-Type must be application/json")
	}
	return nil
}

func effectiveOriginPort(scheme string, port uint16, hasPort bool) uint16 {
	if hasPort {
		return port
	}
	if scheme == "https" {
		return 443
	}
	return 80
}

type localAuthority struct {
	identity string
	port     uint16
	hasPort  bool
}

// parseLocalAuthority parses Host or Origin authority text. Apart from the
// conventional localhost name, hostnames are intentionally not resolved:
// accepting only literal loopback IPs prevents a rebinding-controlled
// hostname from being treated as local.
func parseLocalAuthority(authority string) (localAuthority, error) {
	if authority == "" || strings.TrimSpace(authority) != authority ||
		strings.ContainsAny(authority, "/?#@") {
		return localAuthority{}, errors.New("invalid authority")
	}

	host := authority
	portText := ""
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return localAuthority{}, errors.New("invalid authority")
		}
		host = authority[1:end]
		rest := authority[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return localAuthority{}, errors.New("invalid authority")
			}
			portText = rest[1:]
			hasPort = true
		}
	} else {
		switch strings.Count(authority, ":") {
		case 0:
		case 1:
			parts := strings.SplitN(authority, ":", 2)
			host, portText, hasPort = parts[0], parts[1], true
			if portText == "" {
				return localAuthority{}, errors.New("invalid authority")
			}
		default:
			return localAuthority{}, errors.New("IPv6 authority must be bracketed")
		}
	}

	identity := ""
	if strings.EqualFold(host, "localhost") {
		identity = "localhost"
	} else {
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Zone() != "" || !addr.IsLoopback() {
			return localAuthority{}, errors.New("authority is not loopback")
		}
		identity = addr.String()
	}
	if !hasPort {
		return localAuthority{identity: identity}, nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return localAuthority{}, errors.New("invalid authority port")
	}
	return localAuthority{identity: identity, port: uint16(port), hasPort: true}, nil
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
	Target model.TargetIntent `json:"target"`
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
	if id, format, ok := parseDiagnosisExportPath(r.URL.Path); ok {
		h.diagnosisExport(w, r, id, format)
		return
	}
	if id, ok := parseDiagnosisViewPath(r.URL.Path); ok {
		h.diagnosisView(w, r, id)
		return
	}
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

type diagnosisExportFormat string

const (
	diagnosisExportHTML    diagnosisExportFormat = "html"
	diagnosisExportJSON    diagnosisExportFormat = "json"
	diagnosisExportPrivacy diagnosisExportFormat = "privacy"
)

// diagnosisExport serves only the canonical final report held by the session.
// The HTML projection is presentation-only; the JSON bytes remain the report
// package's canonical representation.
func (h *Handler) diagnosisExport(w http.ResponseWriter, r *http.Request, id string, format diagnosisExportFormat) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	snapshot, err := h.sessions.Get(id)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	if snapshot.Report == nil {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusAccepted, snapshot)
		return
	}
	if format == diagnosisExportPrivacy {
		metadata, err := report.PrivacyPreview(*snapshot.Report)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode privacy preview: "+err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, metadata)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	switch format {
	case diagnosisExportHTML:
		w.Header().Set("Content-Security-Policy", exportContentSecurityPolicy())
		encoded, err := report.RenderHTML(*snapshot.Report)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode HTML report: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `inline; filename="tadori-report.html"`)
		_, _ = w.Write(encoded)
	case diagnosisExportJSON:
		encoded, err := report.RenderJSON(*snapshot.Report)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode JSON report: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tadori-report.json"`)
		_, _ = w.Write(encoded)
	default:
		http.NotFound(w, r)
	}
}

// diagnosisView returns the server-built UI projection after a session has a
// canonical final report. Running sessions remain available through the
// session snapshot and SSE event endpoints; the browser requests this
// projection when the terminal event arrives.
func (h *Handler) diagnosisView(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	snapshot, err := h.sessions.Get(id)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	if snapshot.Report == nil {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusAccepted, snapshot)
		return
	}
	view, err := BuildDiagnosticView(*snapshot.Report)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode diagnostic view: "+err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, view)
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
	encoded, err := report.MarshalRedactedJSON(diagnosticReport)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode diagnostic report: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(encoded)
}

// environmentSnapshot collects target-independent local context for the
// Inspect this PC workflow. The response is the canonical snapshot itself;
// presentation code never needs to infer facts from probe evidence.
func (h *Handler) environmentSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.legacyTimeout)
	defer cancel()
	snapshot, err := h.environmentRun(ctx)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusGatewayTimeout
		}
		writeError(w, status, "collect environment snapshot: "+err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, model.NormalizeEnvironmentSnapshot(&snapshot))
}

// environmentExport returns the exact JSON encoding of a fresh canonical
// environment snapshot as a download.
func (h *Handler) environmentExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.legacyTimeout)
	defer cancel()
	snapshot, err := h.environmentRun(ctx)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusGatewayTimeout
		}
		writeError(w, status, "collect environment snapshot: "+err.Error())
		return
	}
	encoded, err := json.Marshal(model.NormalizeEnvironmentSnapshot(&snapshot))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode environment snapshot: "+err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="tadori-environment.json"`)
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

	target, err := model.ParseTarget(request.Target)
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

func parseDiagnosisViewPath(path string) (id string, ok bool) {
	const prefix = "/api/diagnoses/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 2 && parts[1] == "view" && validSessionID(parts[0]) {
		return parts[0], true
	}
	return "", false
}

func parseDiagnosisExportPath(path string) (id string, format diagnosisExportFormat, ok bool) {
	const prefix = "/api/diagnoses/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || !validSessionID(parts[0]) {
		return "", "", false
	}
	switch parts[1] {
	case "report.html":
		return parts[0], diagnosisExportHTML, true
	case "report.json":
		return parts[0], diagnosisExportJSON, true
	case "privacy.json":
		return parts[0], diagnosisExportPrivacy, true
	default:
		return "", "", false
	}
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

// diagnoseViewHandler is an additive synchronous projection for callers that
// still use the legacy endpoint. The browser uses the session API below so
// probe progress remains live; this endpoint is useful to embedders and keeps
// the canonical /api/diagnose response unchanged.
func diagnoseViewHandler(run Runner, progress ProgressRunner, overallTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		target, ok := decodeTarget(w, r)
		if !ok {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), overallTimeout)
		defer cancel()

		events := []ProgressEvent{{State: "started"}}
		var eventsMu sync.Mutex
		emit := func(event ProgressEvent) {
			eventsMu.Lock()
			events = append(events, event)
			eventsMu.Unlock()
		}
		var diagnosticReport model.DiagnosticReport
		if progress != nil {
			diagnosticReport = progress(ctx, target, emit)
		} else {
			diagnosticReport = run(ctx, target)
		}

		view, err := BuildDiagnosticView(diagnosticReport)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode diagnostic view: "+err.Error())
			return
		}
		eventsMu.Lock()
		view.Progress = append([]ProgressEvent(nil), events...)
		seenComplete := make(map[string]bool)
		for _, event := range view.Progress {
			if event.ProbeName != "" && event.State == "complete" {
				seenComplete[event.ProbeName] = true
			}
		}
		for _, probe := range view.Probes {
			if !seenComplete[probe.Name] {
				view.Progress = append(view.Progress, ProgressEvent{ProbeName: probe.Name, State: "complete", Status: probe.Status})
			}
		}
		eventsMu.Unlock()
		writeJSON(w, http.StatusOK, view)
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
