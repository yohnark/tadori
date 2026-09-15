package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/yohnark/tadori/internal/model"
	"github.com/yohnark/tadori/internal/privacy"
)

// PrivacyMetadata is the export inventory shared by JSON, HTML, browser
// capture, and FQDN projections.
type PrivacyMetadata = privacy.Metadata

// ExportProjection is the report plus the policy inventory used to serialize
// a shareable export.
type ExportProjection struct {
	Report  model.DiagnosticReport
	Privacy PrivacyMetadata
	Changed bool
}

// DefaultPrivacyMetadata returns the policy inventory for preview endpoints
// whose payload is already bounded by an upstream subsystem, such as the
// metadata-only Browser Capture report.
func DefaultPrivacyMetadata() PrivacyMetadata {
	return privacy.DefaultMetadata()
}

// Project returns the detached, redacted report consumed by exporters and UI
// projections.
func Project(source model.DiagnosticReport) (ExportProjection, error) {
	projection, err := privacy.ProjectReport(source)
	if err != nil {
		return ExportProjection{}, err
	}
	return ExportProjection{Report: projection.Report, Privacy: projection.Metadata, Changed: projection.Changed}, nil
}

// PrivacyPreview returns the same inventory attached to an export without
// exposing or mutating the source report.
func PrivacyPreview(source model.DiagnosticReport) (PrivacyMetadata, error) {
	projection, err := Project(source)
	if err != nil {
		return PrivacyMetadata{}, err
	}
	return projection.Privacy, nil
}

// MarshalExportJSON adds machine-readable privacy metadata to the redacted
// report while retaining the report's top-level JSON shape.
func MarshalExportJSON(source model.DiagnosticReport) ([]byte, error) {
	projection, err := Project(source)
	if err != nil {
		return nil, err
	}
	return json.Marshal(projection.Report)
}

// MarshalRedactedJSON serializes the safe report projection without the
// export inventory. It is used by the legacy JSON API, whose response shape
// predates export metadata; shareable exports use MarshalExportJSON.
func MarshalRedactedJSON(source model.DiagnosticReport) ([]byte, error) {
	projection, err := Project(source)
	if err != nil {
		return nil, err
	}
	return json.Marshal(projection.Report)
}

// MarshalBrowserCaptureJSON serializes a browser-capture report through the
// same policy used for diagnostic exports.
func MarshalBrowserCaptureJSON(source model.BrowserCaptureReport) ([]byte, error) {
	projection, err := privacy.ProjectBrowserCapture(source)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(projection.Report)
	if err != nil {
		return nil, fmt.Errorf("marshal redacted browser capture: %w", err)
	}
	return addPrivacyMetadata(encoded, projection.Metadata)
}

// RenderFQDNExport returns a deterministic hostname-only export with a
// comment header that records the policy applied to the text artifact.
func RenderFQDNExport(values []string) []byte {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	hostnames := make([]string, 0, len(unique))
	for value := range unique {
		hostnames = append(hostnames, value)
	}
	sort.Strings(hostnames)
	metadata := privacy.DefaultMetadata()
	var output strings.Builder
	fmt.Fprintf(&output, "# tadori_privacy_policy=%s\n", metadata.Policy)
	fmt.Fprintf(&output, "# tadori_privacy_version=%s\n", metadata.Version)
	fmt.Fprintf(&output, "# tadori_privacy_included=%s\n", strings.Join(metadata.Included, ","))
	fmt.Fprintf(&output, "# tadori_privacy_redacted=%s\n", strings.Join(metadata.Redacted, ","))
	fmt.Fprintf(&output, "# tadori_privacy_excluded=%s\n", strings.Join(metadata.Excluded, ","))
	for _, hostname := range hostnames {
		output.WriteString(hostname)
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

func marshalReportWithPrivacy(source model.DiagnosticReport) ([]byte, error) {
	encoded, err := json.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("marshal report export: %w", err)
	}
	return encoded, nil
}

func addPrivacyMetadata(encoded []byte, metadata PrivacyMetadata) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("decode export document: %w", err)
	}
	privacyEncoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal export privacy metadata: %w", err)
	}
	document["privacy"] = privacyEncoded
	return json.Marshal(document)
}

// writeExportJSON keeps stream framing under the caller's control.
func writeExportJSON(w io.Writer, source model.DiagnosticReport) error {
	if w == nil {
		return errors.New("report: nil JSON writer")
	}
	encoded, err := MarshalExportJSON(source)
	if err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}
