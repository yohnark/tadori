package batch

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// SelectionMode controls which captured destinations become validation work.
type SelectionMode string

const (
	SelectionAll        SelectionMode = "all"
	SelectionFailedOnly SelectionMode = "failed_only"
	SelectionSelected   SelectionMode = "selected"
)

var (
	ErrCaptureObservationsMissing = errors.New("browser capture report has no observations")
	ErrEmptySelection             = errors.New("selected validation destinations are empty")
	ErrInvalidSelectionMode       = errors.New("invalid validation selection mode")
	ErrEmptyValidationPlan        = errors.New("validation plan is empty")
)

// Request is the selection portion of a batch validation request. Selected
// values may be plan IDs, canonical hostnames, host:port authorities, or
// canonical service identities. A hostname selects every captured service for
// that hostname; an ID selects one semantic service/port entry.
type Request struct {
	Selection   SelectionMode `json:"selection,omitempty"`
	Selected    []string      `json:"selected,omitempty"`
	Concurrency int           `json:"concurrency,omitempty"`
}

// CaptureProvenance retains the capture session identity and the source
// observation that caused an endpoint to enter a plan. Active validation never
// replaces this value with a later probe result.
type CaptureProvenance struct {
	SessionID string                          `json:"session_id"`
	Browser   string                          `json:"browser,omitempty"`
	Observed  model.BrowserCaptureDestination `json:"observed"`
}

// PlanEntry is one semantically unique requested service endpoint. Target is
// produced by model.ParseTarget and is the exact value passed to the existing
// diagnostic orchestrator. Unsupported entries remain in the plan so a
// partial capture cannot silently disappear.
type PlanEntry struct {
	ID                      string                            `json:"id"`
	RequestedHostname       string                            `json:"requested_hostname"`
	RequestedIdentity       string                            `json:"requested_identity"`
	Port                    uint16                            `json:"port"`
	Service                 model.ServiceProfile              `json:"service"`
	Target                  *model.Target                     `json:"target,omitempty"`
	CaptureMechanism        model.BrowserCaptureMechanism     `json:"capture_mechanism"`
	CaptureOutcome          model.BrowserCaptureOutcome       `json:"capture_outcome"`
	CaptureFailed           bool                              `json:"capture_failed"`
	CaptureObservationCount uint64                            `json:"capture_observation_count"`
	CaptureConnectionCount  uint64                            `json:"capture_connection_count"`
	CaptureSuccessCount     uint64                            `json:"capture_success_count"`
	CaptureFailureCount     uint64                            `json:"capture_failure_count"`
	Capture                 CaptureProvenance                 `json:"capture"`
	CaptureObservations     []model.BrowserCaptureDestination `json:"capture_observations,omitempty"`
	Unsupported             bool                              `json:"unsupported,omitempty"`
	UnsupportedReason       string                            `json:"unsupported_reason,omitempty"`
}

// Plan is the deterministic work list created from one completed capture.
type Plan struct {
	SchemaVersion    string                    `json:"schema_version"`
	CaptureSessionID string                    `json:"capture_session_id"`
	CaptureBrowser   string                    `json:"capture_browser,omitempty"`
	CaptureState     model.BrowserCaptureState `json:"capture_state"`
	Selection        SelectionMode             `json:"selection"`
	Requested        []string                  `json:"requested,omitempty"`
	Concurrency      int                       `json:"concurrency"`
	Entries          []PlanEntry               `json:"entries"`
}

const PlanSchemaVersion = "1"

// BuildPlan projects a browser-capture report into stable semantic targets.
// It normalizes identities through model.ParseTarget and deduplicates only
// after service and port have been established. Thus HTTP and HTTPS on the
// same host/port remain distinct, while repeated observations of the same
// service do not create duplicate diagnoses.
func BuildPlan(captureReport model.BrowserCaptureReport, request Request) (Plan, error) {
	observation := captureReport.Observations.BrowserCapture
	if observation == nil {
		return Plan{}, ErrCaptureObservationsMissing
	}
	selection, err := normalizeSelection(request.Selection)
	if err != nil {
		return Plan{}, err
	}
	if selection == SelectionSelected && len(request.Selected) == 0 {
		return Plan{}, ErrEmptySelection
	}

	type accumulated struct {
		entry PlanEntry
	}
	entries := make(map[string]*accumulated)
	for _, sourceDestination := range observation.Destinations {
		destination := cloneCaptureDestination(sourceDestination)
		mechanisms := destinationMechanisms(destination)
		for _, mechanism := range mechanisms {
			entry, key := planEntryForDestination(captureReport, destination, mechanism)
			if !selectedDestination(entry, selection, request.Selected) {
				continue
			}
			current := entries[key]
			if current == nil {
				current = &accumulated{
					entry: entry,
				}
				entries[key] = current
			}
			mergePlanEntry(&current.entry, destination, captureReport)
		}
	}

	result := Plan{
		SchemaVersion:    PlanSchemaVersion,
		CaptureSessionID: firstNonEmpty(captureReport.SessionID, observation.SessionID),
		CaptureBrowser:   firstNonEmpty(captureReport.Browser, observation.Browser),
		CaptureState:     firstNonEmptyCaptureState(captureReport.State, observation.State),
		Selection:        selection,
		Requested:        uniqueStrings(request.Selected),
		Concurrency:      request.Concurrency,
		Entries:          make([]PlanEntry, 0, len(entries)),
	}
	for _, value := range entries {
		value.entry.CaptureObservations = append([]model.BrowserCaptureDestination(nil), value.entry.CaptureObservations...)
		result.Entries = append(result.Entries, value.entry)
	}
	sort.SliceStable(result.Entries, func(i, j int) bool {
		left, right := result.Entries[i], result.Entries[j]
		if left.RequestedIdentity != right.RequestedIdentity {
			return left.RequestedIdentity < right.RequestedIdentity
		}
		if left.Service.ID != right.Service.ID {
			return left.Service.ID < right.Service.ID
		}
		return left.Port < right.Port
	})
	for index := range result.Entries {
		result.Entries[index].ID = fmt.Sprintf("endpoint-%03d", index+1)
	}
	if len(result.Entries) == 0 {
		return Plan{}, ErrEmptyValidationPlan
	}
	return result, nil
}

// TargetIdentity returns the canonical service identity used in exports and
// failed-endpoint copy actions. It is parseable by the normal target parser.
func TargetIdentity(entry PlanEntry) string {
	port := entry.Port
	if scheme := serviceScheme(entry.Service.ID); scheme != "" {
		return scheme + "://" + net.JoinHostPort(entry.RequestedHostname, strconv.Itoa(int(port)))
	}
	return net.JoinHostPort(entry.RequestedHostname, strconv.Itoa(int(entry.Port)))
}

func serviceScheme(service model.ServiceProfileID) string {
	switch service {
	case model.ServiceProfileHTTP:
		return "http"
	case model.ServiceProfileHTTPS:
		return "https"
	case model.ServiceProfileSMB:
		return "smb"
	case model.ServiceProfileRDP:
		return "rdp"
	case model.ServiceProfileSSH:
		return "ssh"
	case model.ServiceProfileDNS:
		return "dns"
	case model.ServiceProfileCustomTCP:
		return "tcp"
	case model.ServiceProfileCustomTLS:
		return "tls"
	default:
		return ""
	}
}

func planEntryForDestination(captureReport model.BrowserCaptureReport, destination model.BrowserCaptureDestination, mechanism model.BrowserCaptureMechanism) (PlanEntry, string) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(destination.RequestedHostname), "."))
	port := destination.Port
	serviceID, service, serviceErr := serviceForMechanism(mechanism)
	entry := PlanEntry{
		RequestedHostname: host,
		Port:              port,
		CaptureMechanism:  mechanism,
		CaptureOutcome:    destination.Outcome,
		CaptureFailed:     captureFailed(destination),
		Capture: CaptureProvenance{
			SessionID: firstNonEmpty(captureReport.SessionID, observationSessionID(captureReport.Observations)),
			Browser:   firstNonEmpty(captureReport.Browser, observationBrowser(captureReport.Observations)),
			Observed:  destination,
		},
	}
	if serviceErr != nil {
		entry.Unsupported = true
		entry.UnsupportedReason = serviceErr.Error()
		entry.RequestedIdentity = host
		return entry, strings.Join([]string{host, string(serviceID), strconv.Itoa(int(port))}, "\x00")
	}
	entry.Service = service
	portValue := port
	target, err := model.ParseTarget(model.TargetIntent{Input: host, Service: service.ID, Port: &portValue})
	if err != nil {
		entry.Unsupported = true
		entry.UnsupportedReason = err.Error()
		entry.RequestedIdentity = host
		return entry, strings.Join([]string{host, string(service.ID), strconv.Itoa(int(port))}, "\x00")
	}
	entry.Target = &target
	entry.RequestedHostname = target.RequestedIdentity
	entry.RequestedIdentity = target.RequestedIdentity
	return entry, strings.Join([]string{target.RequestedIdentity, string(service.ID), strconv.Itoa(int(target.Port))}, "\x00")
}

func mergePlanEntry(entry *PlanEntry, destination model.BrowserCaptureDestination, captureReport model.BrowserCaptureReport) {
	entry.CaptureObservations = append(entry.CaptureObservations, destination)
	entry.CaptureObservationCount += destination.ObservationCount
	entry.CaptureConnectionCount += destination.ConnectionCount
	entry.CaptureSuccessCount += destination.SuccessCount
	entry.CaptureFailureCount += destination.FailureCount
	if entry.CaptureFailureCount > 0 || captureFailed(destination) {
		entry.CaptureFailed = true
	}
	entry.CaptureOutcome = mergeCaptureOutcome(entry.CaptureOutcome, destination.Outcome)
	if entry.Capture.Observed.RequestedHostname == "" {
		entry.Capture = CaptureProvenance{SessionID: firstNonEmpty(captureReport.SessionID, observationSessionID(captureReport.Observations)), Browser: firstNonEmpty(captureReport.Browser, observationBrowser(captureReport.Observations)), Observed: destination}
	}
}

func serviceForMechanism(mechanism model.BrowserCaptureMechanism) (model.ServiceProfileID, model.ServiceProfile, error) {
	switch mechanism {
	case model.BrowserCaptureMechanismHTTP:
		service, err := model.LookupServiceProfile(model.ServiceProfileHTTP)
		return model.ServiceProfileHTTP, service, err
	case model.BrowserCaptureMechanismCONNECT:
		service, err := model.LookupServiceProfile(model.ServiceProfileHTTPS)
		return model.ServiceProfileHTTPS, service, err
	default:
		return model.ServiceProfileID("unsupported"), model.ServiceProfile{}, fmt.Errorf("unsupported browser capture mechanism %q", mechanism)
	}
}

func destinationMechanisms(destination model.BrowserCaptureDestination) []model.BrowserCaptureMechanism {
	values := make([]model.BrowserCaptureMechanism, 0, len(destination.Mechanisms)+1)
	appendMechanism := func(value model.BrowserCaptureMechanism) {
		if value == "" {
			return
		}
		for _, existing := range values {
			if existing == value {
				return
			}
		}
		values = append(values, value)
	}
	appendMechanism(destination.Mechanism)
	for _, value := range destination.Mechanisms {
		appendMechanism(value)
	}
	if len(values) == 0 {
		values = append(values, "")
	}
	return values
}

func captureFailed(destination model.BrowserCaptureDestination) bool {
	if destination.FailureCount > 0 || hasConcreteFailureReason(destination.FailureReason) {
		return true
	}
	for _, reason := range destination.FailureReasons {
		if hasConcreteFailureReason(reason) {
			return true
		}
	}
	if destination.Outcome == model.BrowserCaptureOutcomeConnected {
		return false
	}
	return true
}

func hasConcreteFailureReason(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(model.FailureReasonNone), string(model.FailureReasonUnknown):
		return false
	default:
		return true
	}
}

func mergeCaptureOutcome(left, right model.BrowserCaptureOutcome) model.BrowserCaptureOutcome {
	if left == "" {
		return right
	}
	if right == "" || left == right {
		return left
	}
	if (left == model.BrowserCaptureOutcomeConnected && captureOutcomeIsFailure(right)) ||
		(right == model.BrowserCaptureOutcomeConnected && captureOutcomeIsFailure(left)) {
		return model.BrowserCaptureOutcomeMixed
	}
	return model.BrowserCaptureOutcomeMixed
}

func captureOutcomeIsFailure(value model.BrowserCaptureOutcome) bool {
	return value != "" && value != model.BrowserCaptureOutcomeConnected
}

func selectedDestination(entry PlanEntry, selection SelectionMode, selected []string) bool {
	switch selection {
	case SelectionAll:
		return true
	case SelectionFailedOnly:
		return entry.CaptureFailed
	case SelectionSelected:
		for _, value := range selected {
			if selectorMatches(entry, value) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func selectorMatches(entry PlanEntry, selector string) bool {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(selector), "."))
	if value == "" {
		return false
	}
	if value == strings.ToLower(entry.ID) || value == strings.ToLower(entry.RequestedIdentity) || value == strings.ToLower(entry.RequestedHostname) || value == strings.ToLower(TargetIdentity(entry)) {
		return true
	}
	return value == strings.ToLower(net.JoinHostPort(entry.RequestedHostname, strconv.Itoa(int(entry.Port))))
}

func normalizeSelection(value SelectionMode) (SelectionMode, error) {
	switch strings.ToLower(strings.TrimSpace(string(value))) {
	case "", "all":
		return SelectionAll, nil
	case "failed", "failed-only", "failed_only":
		return SelectionFailedOnly, nil
	case "selected", "manual":
		return SelectionSelected, nil
	default:
		return "", fmt.Errorf("%w %q", ErrInvalidSelectionMode, value)
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmptyCaptureState(values ...model.BrowserCaptureState) model.BrowserCaptureState {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func cloneCaptureDestination(value model.BrowserCaptureDestination) model.BrowserCaptureDestination {
	value.Mechanisms = append([]model.BrowserCaptureMechanism(nil), value.Mechanisms...)
	value.ResolvedAddressCandidates = append([]string(nil), value.ResolvedAddressCandidates...)
	value.ConnectedEndpoints = append([]string(nil), value.ConnectedEndpoints...)
	value.FailureReasons = append([]string(nil), value.FailureReasons...)
	return value
}

func observationSessionID(observations model.Observations) string {
	if observations.BrowserCapture == nil {
		return ""
	}
	return observations.BrowserCapture.SessionID
}

func observationBrowser(observations model.Observations) string {
	if observations.BrowserCapture == nil {
		return ""
	}
	return observations.BrowserCapture.Browser
}
