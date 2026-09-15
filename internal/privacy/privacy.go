// Package privacy owns the deterministic export redaction policy.
//
// Diagnostic collection keeps its canonical in-memory evidence unchanged.
// Exporters call the projection functions in this package before serializing
// data that can leave the process or be shown as a shareable report.
package privacy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/yohnark/tadori/internal/model"
)

// PolicyName identifies the export policy recorded in every machine-readable
// export. It is a stable identifier, not a human-facing policy description.
const PolicyName = "tadori/export-redaction"

// PolicyVersion changes when the categories or transformation semantics of
// the export policy change.
const PolicyVersion = "1"

const redactedValue = "[REDACTED]"

// Metadata is the deterministic inventory attached to an export.
type Metadata = model.PrivacyMetadata

// DefaultMetadata returns a detached copy of the policy inventory.
func DefaultMetadata() Metadata {
	return model.DefaultPrivacyMetadata()
}

// ReportProjection is the redacted, detached report used by diagnostic
// exporters and presentation adapters.
type ReportProjection struct {
	Report   model.DiagnosticReport
	Metadata Metadata
	Changed  bool
}

// BrowserCaptureProjection is the equivalent projection for browser capture
// exports. Browser Capture already excludes payloads at acquisition time; the
// shared policy still runs at export so that its guarantee remains explicit.
type BrowserCaptureProjection struct {
	Report   model.BrowserCaptureReport
	Metadata Metadata
	Changed  bool
}

// ProjectReport returns a detached report with the export policy applied. It
// never changes source or canonical in-memory evidence.
func ProjectReport(source model.DiagnosticReport) (ReportProjection, error) {
	encoded, err := json.Marshal(source)
	if err != nil {
		return ReportProjection{}, fmt.Errorf("marshal report for privacy projection: %w", err)
	}
	projected, changed, err := projectJSON(encoded)
	if err != nil {
		return ReportProjection{}, fmt.Errorf("redact report: %w", err)
	}
	if !changed {
		return ReportProjection{Report: source, Metadata: DefaultMetadata()}, nil
	}
	var report model.DiagnosticReport
	if err := json.Unmarshal(projected, &report); err != nil {
		return ReportProjection{}, fmt.Errorf("decode redacted report: %w", err)
	}
	return ReportProjection{Report: report, Metadata: DefaultMetadata(), Changed: changed}, nil
}

// ProjectBrowserCapture returns a detached browser-capture report with the
// same export policy as a diagnostic report.
func ProjectBrowserCapture(source model.BrowserCaptureReport) (BrowserCaptureProjection, error) {
	encoded, err := json.Marshal(source)
	if err != nil {
		return BrowserCaptureProjection{}, fmt.Errorf("marshal browser capture for privacy projection: %w", err)
	}
	projected, changed, err := projectJSON(encoded)
	if err != nil {
		return BrowserCaptureProjection{}, fmt.Errorf("redact browser capture: %w", err)
	}
	if !changed {
		return BrowserCaptureProjection{Report: source, Metadata: DefaultMetadata()}, nil
	}
	var report model.BrowserCaptureReport
	if err := json.Unmarshal(projected, &report); err != nil {
		return BrowserCaptureProjection{}, fmt.Errorf("decode redacted browser capture: %w", err)
	}
	return BrowserCaptureProjection{Report: report, Metadata: DefaultMetadata(), Changed: changed}, nil
}

// RedactRaw returns a safe JSON value for an evidence payload. It is useful
// to presentation projections that expose one evidence item independently of
// a complete report.
func RedactRaw(raw json.RawMessage) (json.RawMessage, bool, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{"redacted":true,"reason":"empty evidence"}`), true, nil
	}
	projected, changed, err := projectJSON(raw)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return append(json.RawMessage(nil), raw...), false, nil
	}
	return json.RawMessage(projected), changed, nil
}

func projectJSON(encoded []byte) ([]byte, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false, err
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		return nil, false, err
	}
	state := projectionState{}
	value = redactNode(value, nil, &state)
	projected, err := json.Marshal(value)
	if err != nil {
		return nil, false, err
	}
	return projected, state.changed, nil
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("JSON contains multiple values")
	} else if err != io.EOF {
		return err
	}
	return nil
}

type projectionState struct {
	changed bool
}

func redactNode(value any, path []string, state *projectionState) any {
	switch typed := value.(type) {
	case map[string]any:
		redactMap(typed, path, state)
		return typed
	case []any:
		for index := range typed {
			typed[index] = redactNode(typed[index], path, state)
		}
		return typed
	case string:
		return redactString(lastPathField(path), typed, path, state)
	default:
		return value
	}
}

func redactMap(value map[string]any, path []string, state *projectionState) {
	for key, child := range value {
		field := normalizedField(key)
		childPath := appendPath(path, key)

		if isEvidenceRawField(path, field) {
			value[key] = redactEvidenceRaw(child, childPath, state)
			continue
		}
		if disposition := fieldDisposition(field); disposition != fieldKeep {
			switch disposition {
			case fieldExclude:
				delete(value, key)
				state.changed = true
			case fieldRedact:
				value[key] = redactedValue
				state.changed = true
			}
			continue
		}

		if childMap, ok := child.(map[string]any); ok {
			redactMap(childMap, childPath, state)
			value[key] = childMap
			continue
		}
		if childList, ok := child.([]any); ok {
			for index := range childList {
				childList[index] = redactNode(childList[index], childPath, state)
			}
			value[key] = childList
			continue
		}
		if childString, ok := child.(string); ok {
			value[key] = redactString(field, childString, childPath, state)
			continue
		}
		value[key] = redactNode(child, childPath, state)
	}
}

func redactEvidenceRaw(value any, path []string, state *projectionState) any {
	if typed, ok := value.(string); ok {
		redacted := redactFreeText(typed)
		if redacted != typed {
			state.changed = true
		}
		return redacted
	}
	if value == nil {
		state.changed = true
		return map[string]any{"redacted": true, "reason": "empty evidence"}
	}
	return redactNode(value, path, state)
}

type fieldDispositionValue uint8

const (
	fieldKeep fieldDispositionValue = iota
	fieldRedact
	fieldExclude
)

func fieldDisposition(field string) fieldDispositionValue {
	switch field {
	case "username", "user_name", "user", "profile", "profile_path", "home", "home_directory", "local_path", "file_path", "working_directory", "local_profile_path":
		return fieldRedact
	case "email_addresses", "email_address", "emailaddresses", "request_body", "response_body", "body", "payload", "request_payload", "response_payload", "raw_body", "body_content", "private_key", "private_key_bytes", "certificate_bytes", "certificate_der", "certificate_pem", "query", "query_string", "querystring", "query_params", "queryparameters", "query_parameters", "raw_query", "rawquery", "fragment":
		return fieldExclude
	case "token", "accesstoken", "refreshtoken", "idtoken", "sessiontoken", "csrftoken", "auth", "authheader", "authorizationheader", "proxyauth", "proxyauthheader", "proxyauthorizationheader", "proxyauthenticate", "wwwauthenticate":
		return fieldExclude
	}
	if strings.Contains(field, "authorization") || strings.Contains(field, "cookie") || strings.Contains(field, "password") || strings.Contains(field, "passwd") || strings.Contains(field, "credential") || strings.Contains(field, "secret") || strings.Contains(field, "api_key") || strings.Contains(field, "apikey") {
		return fieldExclude
	}
	if strings.HasSuffix(field, "_token") || strings.HasSuffix(field, "token") || strings.HasSuffix(field, "_key") || strings.HasSuffix(field, "privatekey") || strings.HasSuffix(field, "_body") || strings.HasSuffix(field, "body") || strings.HasSuffix(field, "_query") || strings.HasSuffix(field, "query") || strings.HasSuffix(field, "_auth") || strings.HasSuffix(field, "auth") {
		return fieldExclude
	}
	return fieldKeep
}

func redactString(field, value string, path []string, state *projectionState) string {
	original := value
	if isURLField(field) {
		value = redactURL(value)
	} else if isLocalPathField(field) {
		value = redactLocalPath(value)
	} else if isFreeTextField(field) {
		value = redactFreeText(value)
	} else {
		value = redactEmbeddedURLAndLocalPath(value)
	}
	if value != original {
		state.changed = true
	}
	return value
}

func isURLField(field string) bool {
	if field == "url" || field == "uri" || field == "location" || field == "to_url" || field == "pac_url" || field == "resource" || field == "requested_resource" || field == "original_input" || field == "authority" {
		return true
	}
	return strings.HasSuffix(field, "_url") || strings.HasSuffix(field, "_uri")
}

func isLocalPathField(field string) bool {
	return field == "path" || field == "file" || field == "file_path" || field == "local_path" || field == "profile" || field == "profile_path" || field == "home" || field == "home_directory" || field == "working_directory"
}

func isFreeTextField(field string) bool {
	return field == "error" || field == "note" || field == "detail" || field == "description" || field == "limitation" || field == "limitations" || field == "interception_basis" || field == "block_causality"
}

func redactURL(value string) string {
	if value == "" {
		return value
	}
	if localAbsolutePathPattern.MatchString(value) || windowsPathPattern.MatchString(value) || unixProfilePathPattern.MatchString(value) {
		return redactedValue
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "?") {
		return stripQueryAndFragment(value)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return stripQueryAndFragment(value)
	}
	if parsed.Path != "" && (windowsPathPattern.MatchString(parsed.Path) || unixProfilePathPattern.MatchString(parsed.Path)) {
		parsed.Path = redactedValue
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.RawFragment = ""
		return parsed.String()
	}
	return parsed.String()
}

func stripQueryAndFragment(value string) string {
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		return value[:index]
	}
	return value
}

func redactLocalPath(value string) string {
	if value == "" {
		return value
	}
	if windowsPathPattern.MatchString(value) || unixProfilePathPattern.MatchString(value) || localAbsolutePathPattern.MatchString(value) || unixAbsolutePathPattern.MatchString(value) {
		return redactedValue
	}
	return value
}

func redactFreeText(value string) string {
	value = credentialPattern.ReplaceAllString(value, "$1=[REDACTED]")
	value = embeddedURLPattern.ReplaceAllStringFunc(value, redactURL)
	value = windowsPathPattern.ReplaceAllString(value, redactedValue)
	value = unixProfilePathPattern.ReplaceAllString(value, redactedValue)
	return value
}

func redactEmbeddedURLAndLocalPath(value string) string {
	value = credentialPattern.ReplaceAllString(value, "$1=[REDACTED]")
	value = embeddedURLPattern.ReplaceAllStringFunc(value, redactURL)
	value = windowsPathPattern.ReplaceAllString(value, redactedValue)
	value = unixProfilePathPattern.ReplaceAllString(value, redactedValue)
	return value
}

func normalizedField(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			builder.WriteRune(character)
			continue
		}
		builder.WriteByte('_')
	}
	return strings.Trim(builder.String(), "_")
}

func appendPath(path []string, field string) []string {
	result := make([]string, len(path), len(path)+1)
	copy(result, path)
	return append(result, field)
}

func lastPathField(path []string) string {
	if len(path) == 0 {
		return ""
	}
	return normalizedField(path[len(path)-1])
}

func isEvidenceRawField(path []string, field string) bool {
	if field != "raw" || len(path) == 0 {
		return false
	}
	return normalizedField(path[len(path)-1]) == "evidence"
}

var (
	credentialPattern        = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret|api[-_]?key|credential)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|(?:[a-z]+\s+)?[^\s,;]+)`)
	embeddedURLPattern       = regexp.MustCompile(`https?://[^\s"'<>]+`)
	windowsPathPattern       = regexp.MustCompile(`(?i)(?:[a-z]:[\\/]+users[\\/]+[^\\/\s]+(?:[\\/][^\s"']*)?|\\\\[^\\/\s]+[\\/]users[\\/]+[^\\/\s]+(?:[\\/][^\s"']*)?)`)
	unixProfilePathPattern   = regexp.MustCompile(`(?i)/(?:home|users|private/var)/[^/\s"']+(?:/[^\s"']*)?`)
	localAbsolutePathPattern = regexp.MustCompile(`(?i)^[a-z]:[\\/]|^/(?:home|users|private/var)/`)
	unixAbsolutePathPattern  = regexp.MustCompile(`^/(?:[^/\s"']+/)*[^/\s"']+`)
)
