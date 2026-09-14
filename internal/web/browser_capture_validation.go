package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yohnark/tadori/internal/batch"
	"github.com/yohnark/tadori/internal/report"
)

func (h *Handler) browserCaptureValidationResource(w http.ResponseWriter, r *http.Request) {
	id, action, entryID, ok := parseBrowserCaptureValidationPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch action {
	case browserCaptureValidationSession:
		switch r.Method {
		case http.MethodGet:
			snapshot, err := h.validations.Get(id)
			if err != nil {
				writeBatchError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, snapshot)
		case http.MethodDelete:
			snapshot, err := h.validations.Cancel(id)
			if err != nil {
				writeBatchError(w, err)
				return
			}
			status := http.StatusOK
			if snapshot.State == batch.StateCancelling {
				status = http.StatusAccepted
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, status, snapshot)
		default:
			methodNotAllowed(w, http.MethodGet+", "+http.MethodDelete)
		}
	case browserCaptureValidationReport:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		value, err := h.validations.Report(id)
		if err != nil {
			writeBatchError(w, err)
			return
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode validation batch report: "+err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tadori-browser-validation.json"`)
		_, _ = w.Write(encoded)
	case browserCaptureValidationFailed:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		values, err := h.validations.FailedIdentities(id)
		if err != nil {
			writeBatchError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tadori-browser-validation-failed.txt"`)
		if len(values) > 0 {
			_, _ = w.Write([]byte(strings.Join(values, "\n") + "\n"))
		}
	case browserCaptureValidationEndpointReport:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		value, err := h.validations.EndpointReport(id, entryID)
		if err != nil {
			writeBatchError(w, err)
			return
		}
		encoded, err := report.MarshalJSON(value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode endpoint report: "+err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tadori-endpoint-report.json"`)
		_, _ = w.Write(encoded)
	}
}

type browserCaptureValidationPathAction string

const (
	browserCaptureValidationSession        browserCaptureValidationPathAction = "session"
	browserCaptureValidationReport         browserCaptureValidationPathAction = "report"
	browserCaptureValidationFailed         browserCaptureValidationPathAction = "failed"
	browserCaptureValidationEndpointReport browserCaptureValidationPathAction = "endpoint_report"
)

func parseBrowserCaptureValidationPath(path string) (id string, action browserCaptureValidationPathAction, entryID string, ok bool) {
	const prefix = "/api/browser-capture-validations/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 1 && validSessionID(parts[0]) {
		return parts[0], browserCaptureValidationSession, "", true
	}
	if len(parts) == 2 && validSessionID(parts[0]) {
		switch parts[1] {
		case "report.json":
			return parts[0], browserCaptureValidationReport, "", true
		case "failed.txt", "failed-identities.txt":
			return parts[0], browserCaptureValidationFailed, "", true
		}
	}
	if len(parts) == 4 && parts[3] == "report.json" && parts[1] == "endpoints" && validSessionID(parts[0]) && validSessionID(parts[2]) {
		return parts[0], browserCaptureValidationEndpointReport, parts[2], true
	}
	return "", "", "", false
}

func writeBatchError(w http.ResponseWriter, err error) {
	if errors.Is(err, batch.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if errors.Is(err, batch.ErrEndpointReportUnavailable) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}
