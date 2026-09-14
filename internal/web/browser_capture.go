package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/yohnark/tadori/internal/capture"
)

const maxBrowserCaptureRequestBytes = 2 << 10

type browserCaptureRequest struct {
	Browser capture.Browser `json:"browser"`
}

type browserCapturePathAction string

const (
	browserCaptureSession browserCapturePathAction = "session"
	browserCaptureReport  browserCapturePathAction = "report"
	browserCaptureFQDN    browserCapturePathAction = "fqdns"
)

func (h *Handler) browserCaptureCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var request browserCaptureRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBrowserCaptureRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		if isBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "browser capture request is too large")
		} else {
			writeError(w, http.StatusBadRequest, "request body must be JSON with an optional browser")
		}
		return
	}
	if err := requireSingleJSONValue(decoder); err != nil {
		if isBodyTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, "browser capture request is too large")
		} else {
			writeError(w, http.StatusBadRequest, "request body must contain one JSON object")
		}
		return
	}

	// A successful capture outlives the POST request. Handler.Close owns its
	// process context, so a browser disconnect cannot cancel the new session.
	snapshot, err := h.captures.Start(context.Background(), request.Browser)
	if err != nil {
		switch {
		case errors.Is(err, capture.ErrBusy):
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, err.Error())
		case errors.Is(err, capture.ErrClosed):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, capture.ErrInvalidBrowser), errors.Is(err, capture.ErrBrowserNotFound):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.Header().Set("Location", "/api/browser-captures/"+snapshot.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, snapshot)
}

func requireSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func (h *Handler) browserCaptureResource(w http.ResponseWriter, r *http.Request) {
	id, action, ok := parseBrowserCapturePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch action {
	case browserCaptureSession:
		switch r.Method {
		case http.MethodGet:
			snapshot, err := h.captures.Get(id)
			if err != nil {
				writeCaptureError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, snapshot)
		case http.MethodDelete:
			snapshot, err := h.captures.Stop(id)
			if err != nil {
				writeCaptureError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, snapshot)
		default:
			methodNotAllowed(w, http.MethodGet+", "+http.MethodDelete)
		}
	case browserCaptureReport:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		report, err := h.captures.Report(id)
		if err != nil {
			writeCaptureError(w, err)
			return
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode browser capture report: "+err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tadori-browser-capture.json"`)
		_, _ = w.Write(encoded)
	case browserCaptureFQDN:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		values, err := h.captures.FQDNs(id)
		if err != nil {
			writeCaptureError(w, err)
			return
		}
		sort.Strings(values)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tadori-browser-destinations.txt"`)
		if len(values) > 0 {
			_, _ = w.Write([]byte(strings.Join(values, "\n") + "\n"))
		}
	}
}

func parseBrowserCapturePath(path string) (string, browserCapturePathAction, bool) {
	const prefix = "/api/browser-captures/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 1 && validSessionID(parts[0]) {
		return parts[0], browserCaptureSession, true
	}
	if len(parts) == 2 && parts[1] == "report.json" && validSessionID(parts[0]) {
		return parts[0], browserCaptureReport, true
	}
	if len(parts) == 2 && parts[1] == "fqdns.txt" && validSessionID(parts[0]) {
		return parts[0], browserCaptureFQDN, true
	}
	return "", "", false
}

func writeCaptureError(w http.ResponseWriter, err error) {
	if errors.Is(err, capture.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}
