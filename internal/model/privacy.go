package model

// PrivacyMetadata is the deterministic inventory recorded in exported report
// JSON. It is intentionally not a field on DiagnosticReport: export policy
// metadata is serialization state, while the in-memory report remains the
// canonical diagnostic model.
type PrivacyMetadata struct {
	Policy             string   `json:"policy"`
	Version            string   `json:"version"`
	Included           []string `json:"included"`
	Redacted           []string `json:"redacted"`
	Excluded           []string `json:"excluded"`
	OperatorSelectable []string `json:"operator_selectable"`
}

// DefaultPrivacyMetadata returns the policy inventory used by report JSON.
// Callers receive fresh slices and may safely modify the result.
func DefaultPrivacyMetadata() PrivacyMetadata {
	return PrivacyMetadata{
		Policy:  "tadori/export-redaction",
		Version: "1",
		Included: []string{
			"destination_hostnames",
			"local_and_public_ip_addresses",
			"dns_servers_and_routes",
			"proxy_endpoints",
			"certificate_metadata",
			"evidence_ids",
			"session_ids",
		},
		Redacted: []string{
			"usernames_and_local_profile_paths",
			"url_query_strings_and_fragments",
		},
		Excluded: []string{
			"cookies_and_authorization_headers",
			"request_and_response_bodies",
			"opaque_tokens_and_secrets",
			"raw_certificate_material",
			"certificate_email_addresses",
		},
		// No alternate export mode is currently exposed. Keeping this explicit
		// makes that choice machine-readable and leaves room for a safe,
		// operator-selected policy in a future version.
		OperatorSelectable: []string{},
	}
}
