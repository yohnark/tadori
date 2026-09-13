package model

// SMB-specific values extend the canonical application observation contract
// without making the HTTP-shaped fields in that contract protocol-specific.
const (
	EvidenceKindSMBNegotiation EvidenceKind = "smb_negotiation"
	LayerSMB                   Layer        = "smb"
	FaultDomainSMB             FaultDomain  = "smb"
)

type SMBResult string

const (
	SMBResultUnknown           SMBResult = "unknown"
	SMBResultNegotiated        SMBResult = "negotiated"
	SMBResultTCPFailure        SMBResult = "tcp_failure"
	SMBResultProtocolRejection SMBResult = "protocol_rejection"
	SMBResultMalformedResponse SMBResult = "malformed_response"
	SMBResultTimeout           SMBResult = "timeout"
	SMBResultNotAttempted      SMBResult = "not_attempted"
	SMBResultUnsupported       SMBResult = "unsupported"
)

// SMBApplicationObservation is the bounded, unauthenticated application
// projection for an SMB negotiate response. It intentionally contains no
// session, share, credential, or file-operation state.
type SMBApplicationObservation struct {
	Result          SMBResult `json:"result"`
	Negotiated      bool      `json:"negotiated"`
	Dialect         string    `json:"dialect,omitempty"`
	DialectRevision uint16    `json:"dialect_revision,omitempty"`
	Capabilities    []string  `json:"capabilities,omitempty"`
	ServerGUID      string    `json:"server_guid,omitempty"`
	SecurityMode    uint16    `json:"security_mode,omitempty"`
	MaxTransactSize uint32    `json:"max_transact_size,omitempty"`
	MaxReadSize     uint32    `json:"max_read_size,omitempty"`
	MaxWriteSize    uint32    `json:"max_write_size,omitempty"`
	ResponseBytes   int       `json:"response_bytes,omitempty"`
}

const (
	FailureReasonSMBConnectionRefused FailureReason = "smb_connection_refused"
	FailureReasonSMBTimeout           FailureReason = "smb_timeout"
	FailureReasonSMBProtocolRejection FailureReason = "smb_protocol_rejection"
	FailureReasonSMBMalformedResponse FailureReason = "smb_malformed_response"
)
