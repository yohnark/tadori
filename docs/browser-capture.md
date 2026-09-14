# Browser Capture

Browser Capture is a bounded local workflow for discovering destinations used by
a real browser session. Tadori starts Edge or Chrome with a temporary profile
and an explicit proxy bound to `127.0.0.1` on an ephemeral port. The user's
normal browser profile and proxy configuration are not changed.

The capture records hostname/authority, port, request mechanism, resolver
candidates, concrete upstream endpoint when available, outcome, normalized
failure reason, timestamps, counts, and `browser_capture` provenance. It does
not retain cookies, authorization headers, request or response bodies, or TLS
payloads. HTTPS is represented by the proxy's `CONNECT host:port` authority and
is tunneled without a root CA or certificate substitution.

## Browser/network caveats

- Tabs and windows launched from the dedicated profile share one capture
  session. Browser background traffic in that profile can still appear in the
  destination list; a fresh profile has extensions disabled to reduce this
  noise.
- Redirects produce the destinations requested by each browser request. The
  capture does not store redirect headers or HTTP bodies; use HAR analysis when
  HTTP-layer detail is required.
- The initial plain-HTTP lane forwards ordinary HTTP requests. An HTTP
  `Upgrade` request, including a WebSocket upgrade that is not represented as a
  proxy CONNECT tunnel, is retained as an explicit unsupported observation.
- The launch configuration disables QUIC so the measured workflow uses the
  explicit TCP proxy lane. This is not a claim of equivalence with an
  unproxied HTTP/3 browser stack.
- Browser DoH settings, proxy bypass rules, enterprise policy, authentication
  challenges, and browser-managed background traffic can change what is
  observable. The report preserves partial or unsupported outcomes instead of
  treating them as proof that a destination was unnecessary.
- A hostname is kept separate from resolver candidates and the concrete
  connected address. Observed hostnames are not automatically broadened into a
  wildcard allowlist rule.

Capture state is process-local and bounded by session lifetime, concurrent
connections, request/header limits, and tunnel timeout. Stopping a session
closes the listener and active tunnels and removes the temporary profile.

## Batch validation

After stopping a capture, the workbench can validate all destinations, only
destinations with a captured failure, or manually selected destinations. The
batch plan maps plain HTTP observations to the HTTP profile and CONNECT
observations to the HTTPS profile, then deduplicates by normalized requested
identity, service, and port. A host observed with both mechanisms therefore
produces two intentionally distinct validation targets.

The validation API is process-local and bounded:

- `POST /api/browser-captures/{capture-id}/validation-batches` starts a batch.
  The JSON body is optional; use `{"selection":"all"}`,
  `{"selection":"failed_only"}`, or
  `{"selection":"selected","selected":["endpoint-001"]}`.
- `GET` and `DELETE /api/browser-capture-validations/{batch-id}` retrieve or
  cancel a batch.
- `/report.json` exports the batch summary and each completed endpoint report;
  `/failed.txt` exports canonical failed service identities for allowlist
  review; and `/endpoints/{endpoint-id}/report.json` exports one canonical
  diagnostic report.

Capture outcome and active validation outcome are separate fields. A later
successful validation does not erase a captured failure, and a failed active
validation does not rewrite the original browser observation.
