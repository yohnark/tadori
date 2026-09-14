# Export privacy policy

Tadori applies the `tadori/export-redaction` policy (version `1`) at every
shareable diagnostic projection: diagnostic JSON, HTML reports, Browser Capture
JSON, and the Browser Capture FQDN text export. The policy is deterministic;
the same report produces the same projection, and the canonical in-memory
report is never modified.

## Export inventory

Included by default:

- destination hostnames and FQDNs
- local and public IP addresses
- DNS servers, routes, and proxy endpoints
- certificate metadata such as subject, issuer, validity, algorithms, and
  fingerprints
- evidence and session identifiers for cross-reference

Transformed deterministically:

- usernames and local/profile paths become `[REDACTED]`
- URL user information, query strings, and fragments are removed while the
  diagnostic destination and path remain where safe

Excluded:

- cookies and authorization/proxy-authorization headers
- request and response bodies and payloads
- opaque tokens, passwords, API keys, credentials, and private key material
- certificate email addresses and raw certificate bytes

There is no alternate operator-selectable export mode in this version. Each
JSON export carries a `privacy` object with the policy name, version, and the
complete category inventory. HTML includes the same inventory as an export
preview. The FQDN text artifact carries equivalent `tadori_privacy_*` comment
headers.

Browser Capture remains metadata-only at acquisition time. The export policy
is an additional boundary and does not collect, persist, or restore cookies,
headers, bodies, or TLS payloads.
