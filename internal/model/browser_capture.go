package model

import "time"

// BrowserCaptureSchemaVersion is the schema version for a browser-capture
// report projection. It is separate from the diagnostic report event schema
// because capture sessions have a different lifecycle and observation shape.
const BrowserCaptureSchemaVersion = "1"

// BrowserCaptureState describes the bounded lifecycle of a live capture.
type BrowserCaptureState string

const (
	BrowserCaptureStateStarting  BrowserCaptureState = "starting"
	BrowserCaptureStateRunning   BrowserCaptureState = "running"
	BrowserCaptureStateStopping  BrowserCaptureState = "stopping"
	BrowserCaptureStateCompleted BrowserCaptureState = "completed"
	BrowserCaptureStateFailed    BrowserCaptureState = "failed"
	BrowserCaptureStateCancelled BrowserCaptureState = "cancelled"
)

// BrowserCaptureOutcome is the transport outcome for one requested
// destination. Mixed means that the same destination produced both success
// and failure observations during one session.
type BrowserCaptureOutcome string

const (
	BrowserCaptureOutcomeConnected     BrowserCaptureOutcome = "connected"
	BrowserCaptureOutcomeFailed        BrowserCaptureOutcome = "failed"
	BrowserCaptureOutcomeMixed         BrowserCaptureOutcome = "mixed"
	BrowserCaptureOutcomeDNSFailed     BrowserCaptureOutcome = "dns_failed"
	BrowserCaptureOutcomeProxyRejected BrowserCaptureOutcome = "proxy_rejected"
	BrowserCaptureOutcomeUnsupported   BrowserCaptureOutcome = "unsupported"
	BrowserCaptureOutcomeUnknown       BrowserCaptureOutcome = "unknown"
)

// BrowserCaptureMechanism identifies what the local proxy observed. CONNECT
// records only the requested authority and never decrypts the tunnel.
type BrowserCaptureMechanism string

const (
	BrowserCaptureMechanismCONNECT BrowserCaptureMechanism = "CONNECT"
	BrowserCaptureMechanismHTTP    BrowserCaptureMechanism = "plain_http"
)

// BrowserCaptureDestination is the canonical semantic identity for one
// hostname/port pair observed through the browser capture proxy. Requested
// hostname, resolver candidates, and the concrete connected endpoint are
// intentionally separate facts.
type BrowserCaptureDestination struct {
	RequestedHostname         string                    `json:"requested_hostname"`
	RequestedAuthority        string                    `json:"requested_authority"`
	Port                      uint16                    `json:"port"`
	Mechanism                 BrowserCaptureMechanism   `json:"mechanism"`
	Mechanisms                []BrowserCaptureMechanism `json:"mechanisms,omitempty"`
	ResolvedAddressCandidates []string                  `json:"resolved_address_candidates,omitempty"`
	ConnectedAddress          string                    `json:"connected_address,omitempty"`
	ConnectedEndpoint         string                    `json:"connected_endpoint,omitempty"`
	ConnectedEndpoints        []string                  `json:"connected_endpoints,omitempty"`
	Outcome                   BrowserCaptureOutcome     `json:"outcome"`
	FailureReason             string                    `json:"failure_reason,omitempty"`
	FailureReasons            []string                  `json:"failure_reasons,omitempty"`
	FirstSeen                 time.Time                 `json:"first_seen"`
	LastSeen                  time.Time                 `json:"last_seen"`
	ObservationCount          uint64                    `json:"observation_count"`
	ConnectionCount           uint64                    `json:"connection_count"`
	SuccessCount              uint64                    `json:"success_count,omitempty"`
	FailureCount              uint64                    `json:"failure_count,omitempty"`
	Provenance                string                    `json:"provenance"`
}

// BrowserCaptureObservation is the canonical live-capture projection. It
// contains no cookies, headers, request bodies, response bodies, or TLS
// payloads.
type BrowserCaptureObservation struct {
	SessionID              string                      `json:"session_id"`
	Browser                string                      `json:"browser"`
	State                  BrowserCaptureState         `json:"state"`
	ProxyAddress           string                      `json:"proxy_address"`
	StartedAt              time.Time                   `json:"started_at"`
	StoppedAt              *time.Time                  `json:"stopped_at,omitempty"`
	Destinations           []BrowserCaptureDestination `json:"destinations"`
	UniqueDestinationCount uint64                      `json:"unique_destination_count"`
	UniqueAddressCount     uint64                      `json:"unique_address_count"`
	ObservationCount       uint64                      `json:"observation_count"`
	FailureCount           uint64                      `json:"failure_count"`
	Limitations            []string                    `json:"limitations,omitempty"`
	Error                  string                      `json:"error,omitempty"`
}

// BrowserCaptureReport is the machine-readable session projection.
// Browser capture is carried under the same Observations envelope used by
// diagnostic, HAR, and future probe adapters.
type BrowserCaptureReport struct {
	SchemaVersion string              `json:"schema_version"`
	SessionID     string              `json:"session_id"`
	Browser       string              `json:"browser"`
	State         BrowserCaptureState `json:"state"`
	StartedAt     time.Time           `json:"started_at"`
	StoppedAt     *time.Time          `json:"stopped_at,omitempty"`
	Observations  Observations        `json:"observations"`
}
