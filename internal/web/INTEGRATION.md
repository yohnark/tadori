# Diagnostic UI integration boundaries

The localhost UI has a canonical API and a browser projection:

- `POST /api/diagnose` returns the existing canonical `DiagnosticReport` JSON
  unchanged.
- `POST /api/diagnose/view` returns a `DiagnosticViewModel` containing that
  report, the exact canonical JSON text, and server-derived presentation
  fields for paths, evidence, findings, destination state, and progress.
- The browser's normal workflow uses the published session API: `POST
  /api/diagnoses`, `GET /api/diagnoses/{id}/events` (SSE), and `GET
  /api/diagnoses/{id}/view` after the terminal event. This keeps probe progress
  live while the final report is still canonical.

`BuildDiagnosticView` is the only report-to-UI adapter. It consumes the
canonical model and decodes only `EvidenceKindPathObservation` through
`model.DecodePathObservation`; all other evidence remains opaque raw JSON.
The browser only renders this projection and never re-implements diagnosis.

## Integration points

The path view consumes the canonical `PathObservation` shape already supplied
by the path diagnostics lane. Its evidence can flow through the same builder
without a frontend contract change. No path probing or packet capture is
performed by the UI.

`SessionRun` and the existing `session.Event` SSE contract are the live
progress boundary. The browser handles structured event types and requests
the view projection once the terminal event makes the report available. The
legacy `ProgressRunner` is retained only for the additive synchronous view
endpoint and deterministic adapter tests. Neither boundary adds session
concepts to `model.DiagnosticReport`, changes the canonical path contract, or
requires the browser to infer probe meaning from event text.

There are no remaining required #31/#36 integration changes for this UI slice.
If a later probe lane publishes typed incremental path/hop data, the exact
remaining change is to translate that data at the existing session event
boundary and, if needed, extend `BuildDiagnosticView`; the DOM and canonical
report contract do not need to change.

The endpoint is intentionally additive so existing API and CLI consumers keep
receiving canonical JSON. Loopback binding and request validation remain in
the existing handler.

Browser Capture is a separate bounded workflow over the same local handler:

- `POST /api/browser-captures` starts Edge or Chrome with a dedicated temporary
  profile and an explicit loopback proxy.
- `GET /api/browser-captures/{id}` returns live counts and destination rows;
  `DELETE` on the same resource stops the session and cleans up its listener,
  tunnels, browser process, and profile.
- `GET /api/browser-captures/{id}/report.json` exports the canonical report,
  with the browser data under `observations.browser_capture`.
- `GET /api/browser-captures/{id}/fqdns.txt` exports the sorted observed host
  identities without inferring wildcard policy.

The capture adapter retains only destination metadata and records HTTPS from
CONNECT authority. It does not decrypt TLS or store browser payloads. Its
network caveats and explicit unsupported states are documented in
`docs/browser-capture.md`.
