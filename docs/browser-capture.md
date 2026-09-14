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
