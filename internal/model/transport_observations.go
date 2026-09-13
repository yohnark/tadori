package model

// ObservationApplicability distinguishes a layer that was not relevant from
// one that was relevant but could not be observed.  In particular, a custom
// TLS service can be applicable to Security while Application is explicitly
// inapplicable, and a non-HTTP service must not become an HTTP failure.
type ObservationApplicability string

const (
	ObservationApplicabilityUnknown      ObservationApplicability = "unknown"
	ObservationApplicabilityApplicable   ObservationApplicability = "applicable"
	ObservationApplicabilityInapplicable ObservationApplicability = "inapplicable"
	ObservationApplicabilityNotAttempted ObservationApplicability = "not_attempted"
	ObservationApplicabilityUnsupported  ObservationApplicability = "unsupported"
)

// TransportConnectionOutcome is the normalized outcome of a transport
// attempt.  The original probe interpretation and evidence remain available
// through the references on TransportObservation.
type TransportConnectionOutcome string

const (
	TransportConnectionOutcomeUnknown      TransportConnectionOutcome = "unknown"
	TransportConnectionOutcomeNotAttempted TransportConnectionOutcome = "not_attempted"
	TransportConnectionOutcomeConnected    TransportConnectionOutcome = "connected"
	TransportConnectionOutcomeRefused      TransportConnectionOutcome = "refused"
	TransportConnectionOutcomeReset        TransportConnectionOutcome = "reset"
	TransportConnectionOutcomeTimeout      TransportConnectionOutcome = "timeout"
	TransportConnectionOutcomeUnreachable  TransportConnectionOutcome = "unreachable"
	TransportConnectionOutcomeCanceled     TransportConnectionOutcome = "canceled"
	TransportConnectionOutcomeFailed       TransportConnectionOutcome = "failed"
	TransportConnectionOutcomeUnsupported  TransportConnectionOutcome = "unsupported"
)

// CertificateValidationState records only what can be supported by the TLS
// probe result.  Unknown is different from valid: an evidence item may carry
// a certificate chain even when validation was not completed.
type CertificateValidationState string

const (
	CertificateValidationUnknown          CertificateValidationState = "unknown"
	CertificateValidationValid            CertificateValidationState = "valid"
	CertificateValidationInvalid          CertificateValidationState = "invalid"
	CertificateValidationExpired          CertificateValidationState = "expired"
	CertificateValidationHostnameMismatch CertificateValidationState = "hostname_mismatch"
	CertificateValidationUntrusted        CertificateValidationState = "untrusted"
	CertificateValidationIncomplete       CertificateValidationState = "incomplete"
)

// TLSCertificateObservation is the report-level copy of safe certificate
// metadata collected by the TLS probe.  It intentionally has no raw DER,
// public-key material, or other secret-bearing fields.
type TLSCertificateObservation struct {
	ChainIndex         int      `json:"chain_index"`
	Subject            string   `json:"subject,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	Version            int      `json:"version,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	IsCA               bool     `json:"is_ca"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	SHA256             string   `json:"sha256,omitempty"`
}

// TransportObservation is the canonical report-level projection of TCP
// evidence.  RequestedEndpoint preserves intent, ProbeEndpoint preserves the
// candidate selected for the attempt, and TestedEndpoint is concrete transport
// truth when a connection was established.
type TransportObservation struct {
	Applicability         ObservationApplicability   `json:"applicability"`
	RequestedEndpoint     string                     `json:"requested_endpoint,omitempty"`
	ProbeEndpoint         *Endpoint                  `json:"probe_endpoint,omitempty"`
	TestedEndpoint        *Endpoint                  `json:"tested_endpoint,omitempty"`
	ConnectionOutcome     TransportConnectionOutcome `json:"connection_outcome"`
	Connected             bool                       `json:"connected"`
	LocalEndpoint         string                     `json:"local_endpoint,omitempty"`
	RemoteEndpoint        *Endpoint                  `json:"remote_endpoint,omitempty"`
	Timing                Timing                     `json:"timing"`
	FailureReason         FailureReason              `json:"failure_reason"`
	FaultDomain           FaultDomain                `json:"fault_domain"`
	CandidateAttempts     []EndpointAttempt          `json:"candidate_attempts,omitempty"`
	PacketFlowEvidenceIDs []string                   `json:"packet_flow_evidence_ids,omitempty"`
	Provenance            []string                   `json:"provenance,omitempty"`
	Certainty             ObservationCertainty       `json:"certainty"`
	ProbeNames            []string                   `json:"probe_names,omitempty"`
	EvidenceIDs           []string                   `json:"evidence_ids,omitempty"`
	Limitations           []string                   `json:"limitations,omitempty"`
	Conflicts             []ObservationConflict      `json:"conflicts,omitempty"`
}

// SecurityObservation is the canonical projection of TLS handshake and
// certificate evidence.  Trust/interception fields are references, not
// guesses: the builder populates them only from evidence that explicitly
// carries the corresponding facts.
type SecurityObservation struct {
	Applicability           ObservationApplicability    `json:"applicability"`
	Attempted               bool                        `json:"attempted"`
	HandshakeComplete       bool                        `json:"handshake_complete"`
	NegotiatedProtocol      string                      `json:"negotiated_protocol,omitempty"`
	NegotiatedProtocolID    string                      `json:"negotiated_protocol_id,omitempty"`
	TLSVersion              string                      `json:"tls_version,omitempty"`
	TLSVersionID            uint16                      `json:"tls_version_id,omitempty"`
	CipherSuite             string                      `json:"cipher_suite,omitempty"`
	CipherSuiteID           uint16                      `json:"cipher_suite_id,omitempty"`
	ServerName              string                      `json:"server_name,omitempty"`
	EndpointUsed            *Endpoint                   `json:"endpoint_used,omitempty"`
	CertificateValidation   CertificateValidationState  `json:"certificate_validation"`
	Timing                  Timing                      `json:"timing"`
	Certificates            []TLSCertificateObservation `json:"certificates,omitempty"`
	PeerCertificateCount    int                         `json:"peer_certificate_count"`
	TrustEvidenceIDs        []string                    `json:"trust_evidence_ids,omitempty"`
	InterceptionEvidenceIDs []string                    `json:"interception_evidence_ids,omitempty"`
	FailureReason           FailureReason               `json:"failure_reason"`
	FaultDomain             FaultDomain                 `json:"fault_domain"`
	Provenance              []string                    `json:"provenance,omitempty"`
	Certainty               ObservationCertainty        `json:"certainty"`
	ProbeNames              []string                    `json:"probe_names,omitempty"`
	EvidenceIDs             []string                    `json:"evidence_ids,omitempty"`
	Limitations             []string                    `json:"limitations,omitempty"`
	Conflicts               []ObservationConflict       `json:"conflicts,omitempty"`
}

// ApplicationObservation is the canonical projection of application response
// and request-failure evidence. ResponseReceived is deliberately separate
// from Result so protocol responses such as DNS REFUSED remain distinguishable
// from client-side transport failures. HTTP fields remain populated for HTTP;
// DNS service details use DNS.
type ApplicationObservation struct {
	Applicability              ObservationApplicability   `json:"applicability"`
	RequestAttempted           bool                       `json:"request_attempted"`
	ResponseReceived           bool                       `json:"response_received"`
	TransportConnected         bool                       `json:"transport_connected,omitempty"`
	Protocol                   ApplicationProtocol        `json:"protocol,omitempty"`
	HandshakeAttempted         bool                       `json:"handshake_attempted,omitempty"`
	HandshakeComplete          bool                       `json:"handshake_complete,omitempty"`
	ProtocolResult             ApplicationProtocolResult  `json:"protocol_result,omitempty"`
	ServerIdentification       string                     `json:"server_identification,omitempty"`
	RequestedSecurityProtocols []string                   `json:"requested_security_protocols,omitempty"`
	NegotiatedSecurityProtocol string                     `json:"negotiated_security_protocol,omitempty"`
	HTTPVersion                string                     `json:"http_version,omitempty"`
	StatusCode                 int                        `json:"status_code,omitempty"`
	Status                     string                     `json:"status,omitempty"`
	Result                     HTTPResult                 `json:"result"`
	Timing                     Timing                     `json:"timing"`
	RequestedResource          string                     `json:"requested_resource,omitempty"`
	EndpointUsed               *Endpoint                  `json:"endpoint_used,omitempty"`
	URL                        string                     `json:"url,omitempty"`
	Redirects                  []HTTPRedirectObservation  `json:"redirects,omitempty"`
	DNS                        *DNSApplicationObservation `json:"dns,omitempty"`
	FailureReason              FailureReason              `json:"failure_reason"`
	FaultDomain                FaultDomain                `json:"fault_domain"`
	Provenance                 []string                   `json:"provenance,omitempty"`
	Certainty                  ObservationCertainty       `json:"certainty"`
	ProbeNames                 []string                   `json:"probe_names,omitempty"`
	EvidenceIDs                []string                   `json:"evidence_ids,omitempty"`
	Limitations                []string                   `json:"limitations,omitempty"`
	Conflicts                  []ObservationConflict      `json:"conflicts,omitempty"`
	SMB                        *SMBApplicationObservation `json:"smb,omitempty"`
}

// ApplicationResult is shared by application protocols. HTTPResult remains a
// type alias for source compatibility with the #54 contract.
type ApplicationResult string

type HTTPResult = ApplicationResult

// ApplicationProtocolResult is used by non-HTTP service handshakes. HTTP
// retains HTTPResult for wire compatibility with the existing contract.
type ApplicationProtocolResult string

const (
	ApplicationProtocolResultUnknown      ApplicationProtocolResult = "unknown"
	ApplicationProtocolResultSuccess      ApplicationProtocolResult = "success"
	ApplicationProtocolResultFailure      ApplicationProtocolResult = "failure"
	ApplicationProtocolResultRejected     ApplicationProtocolResult = "rejected"
	ApplicationProtocolResultMalformed    ApplicationProtocolResult = "malformed"
	ApplicationProtocolResultTimeout      ApplicationProtocolResult = "timeout"
	ApplicationProtocolResultNotAttempted ApplicationProtocolResult = "not_attempted"
	ApplicationProtocolResultUnsupported  ApplicationProtocolResult = "unsupported"
)

const (
	HTTPResultUnknown        ApplicationResult = "unknown"
	HTTPResultSuccess        ApplicationResult = "success"
	HTTPResultStatusFailure  ApplicationResult = "status_failure"
	HTTPResultRequestFailure ApplicationResult = "request_failure"
	HTTPResultNotAttempted   ApplicationResult = "not_attempted"
	HTTPResultUnsupported    ApplicationResult = "unsupported"
	HTTPResultPartial        ApplicationResult = "partial"
)

// DNSApplicationResult summarizes the two independent DNS service lanes.
// Partial is an intentional transport divergence, not proof that the
// destination service is unavailable.
type DNSApplicationResult string

const (
	DNSApplicationResultUnknown      DNSApplicationResult = "unknown"
	DNSApplicationResultSuccess      DNSApplicationResult = "success"
	DNSApplicationResultPartial      DNSApplicationResult = "partial"
	DNSApplicationResultFailure      DNSApplicationResult = "failure"
	DNSApplicationResultNotAttempted DNSApplicationResult = "not_attempted"
)

// DNSApplicationTransportObservation is the normalized, metadata-only view
// of one DNS service transport. The wire payload is intentionally absent.
type DNSApplicationTransportObservation struct {
	Transport        string               `json:"transport"`
	Attempted        bool                 `json:"attempted"`
	ResponseReceived bool                 `json:"response_received"`
	Outcome          string               `json:"outcome"`
	RCode            int                  `json:"rcode,omitempty"`
	RCodeName        string               `json:"rcode_name,omitempty"`
	TransactionID    uint16               `json:"transaction_id,omitempty"`
	Truncated        bool                 `json:"truncated,omitempty"`
	QueryBytes       int                  `json:"query_bytes,omitempty"`
	ResponseBytes    int                  `json:"response_bytes,omitempty"`
	QuestionCount    int                  `json:"question_count,omitempty"`
	AnswerCount      int                  `json:"answer_count,omitempty"`
	AuthorityCount   int                  `json:"authority_count,omitempty"`
	AdditionalCount  int                  `json:"additional_count,omitempty"`
	Attempts         int                  `json:"attempts,omitempty"`
	EndpointUsed     *Endpoint            `json:"endpoint_used,omitempty"`
	Fallback         bool                 `json:"fallback,omitempty"`
	FallbackReason   string               `json:"fallback_reason,omitempty"`
	ErrorKind        string               `json:"error_kind,omitempty"`
	Timing           Timing               `json:"timing"`
	FailureReason    FailureReason        `json:"failure_reason"`
	FaultDomain      FaultDomain          `json:"fault_domain"`
	Provenance       []string             `json:"provenance,omitempty"`
	Certainty        ObservationCertainty `json:"certainty"`
	ProbeNames       []string             `json:"probe_names,omitempty"`
	EvidenceIDs      []string             `json:"evidence_ids,omitempty"`
	Limitations      []string             `json:"limitations,omitempty"`
}

// DNSApplicationObservation is the canonical DNS service projection. UDP
// and TCP are retained as separate lanes even when they agree.
type DNSApplicationObservation struct {
	RequestedEndpoint string                             `json:"requested_endpoint,omitempty"`
	QueryName         string                             `json:"query_name"`
	QueryType         string                             `json:"query_type"`
	Result            DNSApplicationResult               `json:"result"`
	UDP               DNSApplicationTransportObservation `json:"udp"`
	TCP               DNSApplicationTransportObservation `json:"tcp"`
	Divergence        bool                               `json:"divergence,omitempty"`
	RequestAttempted  bool                               `json:"request_attempted"`
	ResponseReceived  bool                               `json:"response_received"`
	Timing            Timing                             `json:"timing"`
	FailureReason     FailureReason                      `json:"failure_reason"`
	FaultDomain       FaultDomain                        `json:"fault_domain"`
	Provenance        []string                           `json:"provenance,omitempty"`
	Certainty         ObservationCertainty               `json:"certainty"`
	ProbeNames        []string                           `json:"probe_names,omitempty"`
	EvidenceIDs       []string                           `json:"evidence_ids,omitempty"`
	Limitations       []string                           `json:"limitations,omitempty"`
}

type HTTPRedirectObservation struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
	ToURL      string `json:"to_url,omitempty"`
}

// NormalizeTransportObservation, NormalizeSecurityObservation, and
// NormalizeApplicationObservation return detached values so the canonical
// envelope never shares mutable slices with probe results or callers.
func NormalizeTransportObservation(value TransportObservation) TransportObservation {
	value.Provenance = append([]string(nil), value.Provenance...)
	value.ProbeNames = append([]string(nil), value.ProbeNames...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.PacketFlowEvidenceIDs = append([]string(nil), value.PacketFlowEvidenceIDs...)
	value.Limitations = append([]string(nil), value.Limitations...)
	value.CandidateAttempts = cloneEndpointAttempts(value.CandidateAttempts)
	value.Conflicts = cloneObservationConflicts(value.Conflicts)
	if value.ProbeEndpoint != nil {
		endpoint := cloneEndpoint(*value.ProbeEndpoint)
		value.ProbeEndpoint = &endpoint
	}
	if value.TestedEndpoint != nil {
		endpoint := cloneEndpoint(*value.TestedEndpoint)
		value.TestedEndpoint = &endpoint
	}
	if value.RemoteEndpoint != nil {
		endpoint := cloneEndpoint(*value.RemoteEndpoint)
		value.RemoteEndpoint = &endpoint
	}
	return value
}

func NormalizeSecurityObservation(value SecurityObservation) SecurityObservation {
	value.Provenance = append([]string(nil), value.Provenance...)
	value.ProbeNames = append([]string(nil), value.ProbeNames...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.TrustEvidenceIDs = append([]string(nil), value.TrustEvidenceIDs...)
	value.InterceptionEvidenceIDs = append([]string(nil), value.InterceptionEvidenceIDs...)
	value.Limitations = append([]string(nil), value.Limitations...)
	value.Conflicts = cloneObservationConflicts(value.Conflicts)
	value.Certificates = append([]TLSCertificateObservation(nil), value.Certificates...)
	for index := range value.Certificates {
		value.Certificates[index].DNSNames = append([]string(nil), value.Certificates[index].DNSNames...)
		value.Certificates[index].IPAddresses = append([]string(nil), value.Certificates[index].IPAddresses...)
		value.Certificates[index].EmailAddresses = append([]string(nil), value.Certificates[index].EmailAddresses...)
	}
	if value.EndpointUsed != nil {
		endpoint := cloneEndpoint(*value.EndpointUsed)
		value.EndpointUsed = &endpoint
	}
	return value
}

func NormalizeApplicationObservation(value ApplicationObservation) ApplicationObservation {
	value.Provenance = append([]string(nil), value.Provenance...)
	value.ProbeNames = append([]string(nil), value.ProbeNames...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.RequestedSecurityProtocols = append([]string(nil), value.RequestedSecurityProtocols...)
	value.Limitations = append([]string(nil), value.Limitations...)
	value.Conflicts = cloneObservationConflicts(value.Conflicts)
	value.Redirects = append([]HTTPRedirectObservation(nil), value.Redirects...)
	if value.EndpointUsed != nil {
		endpoint := cloneEndpoint(*value.EndpointUsed)
		value.EndpointUsed = &endpoint
	}
	if value.DNS != nil {
		dns := *value.DNS
		dns.Provenance = append([]string(nil), dns.Provenance...)
		dns.ProbeNames = append([]string(nil), dns.ProbeNames...)
		dns.EvidenceIDs = append([]string(nil), dns.EvidenceIDs...)
		dns.Limitations = append([]string(nil), dns.Limitations...)
		dns.UDP = normalizeDNSApplicationTransportObservation(dns.UDP)
		dns.TCP = normalizeDNSApplicationTransportObservation(dns.TCP)
		value.DNS = &dns
	}
	if value.SMB != nil {
		smb := *value.SMB
		smb.Capabilities = append([]string(nil), smb.Capabilities...)
		value.SMB = &smb
	}
	return value
}

func normalizeDNSApplicationTransportObservation(value DNSApplicationTransportObservation) DNSApplicationTransportObservation {
	value.Provenance = append([]string(nil), value.Provenance...)
	value.ProbeNames = append([]string(nil), value.ProbeNames...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.Limitations = append([]string(nil), value.Limitations...)
	if value.EndpointUsed != nil {
		endpoint := cloneEndpoint(*value.EndpointUsed)
		value.EndpointUsed = &endpoint
	}
	return value
}
