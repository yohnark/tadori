(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.TadoriLocale = factory();
  }
})(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  const DEFAULT_LOCALE = "en";
  const SUPPORTED_LOCALES = Object.freeze(["ja", "en"]);

  // This is the only presentation string resource used by the workbench.
  // Canonical values (identities, addresses, evidence, and serialized JSON)
  // are never passed through this table.
  const MESSAGES = Object.freeze({
    en: Object.freeze({
      language: {
        label: "Language",
        japanese: "Japanese",
        english: "English",
      },
      brand: {
        context: "diagnostic workbench",
      },
      runtime: {
        local: "Local process · loopback only",
      },
      meta: {
        description: "Local, evidence-first network diagnosis",
      },
      target: {
        section: "Diagnostic target",
        label: "Target",
        placeholder: "hostname, IP, URL, or \\\\server\\share",
        service: "Service",
        serviceProfile: "Service profile",
        port: "Port",
        transport: "Transport",
        resource: "Resource",
        tcp: "TCP",
        udp: "UDP",
        udpTCP: "UDP + TCP",
        diagnose: "Diagnose",
        diagnoseArrow: "Diagnose →",
        starting: "Starting…",
        running: "Running…",
        ready: "Ready for a diagnosis",
        enterToBegin: "Enter a target to begin.",
      },
      service: {
        http: "HTTP",
        https: "HTTPS",
        smb: "File sharing (SMB)",
        rdp: "RDP",
        ssh: "SSH",
        dns: "DNS",
        customTCP: "Custom TCP",
        customTLS: "Custom TLS",
      },
      browser: {
        workflow: "Browser workflow",
        title: "Browser Capture",
        description: "Launch a dedicated browser profile through a loopback-only proxy to discover workflow destinations. HTTPS is recorded from CONNECT authority; TLS payloads are never decrypted.",
        browser: "Browser",
        edge: "Microsoft Edge",
        chrome: "Google Chrome",
        start: "Start Browser Capture",
        stop: "Stop Capture",
        exportJSON: "Export JSON",
        exportFQDNs: "Export FQDNs",
        copyFQDNs: "Copy FQDNs",
        copiedFQDNs: "Copied FQDNs",
        elapsed: "elapsed",
        destinations: "destinations",
        addresses: "addresses",
        observations: "observations",
        failures: "failures",
        destination: "Destination",
        port: "Port",
        outcome: "Outcome",
        connections: "Connections",
        connectedEndpoint: "Connected endpoint",
        failure: "Failure",
        empty: "No browser destinations observed yet.",
        unknown: "unknown",
        notObserved: "not observed",
        none: "none",
        seconds: "s",
        loadError: "could not load browser capture state",
        requestError: "browser capture request failed",
        stopError: "could not stop browser capture",
        loadFQDNError: "could not load observed FQDNs",
        clipboardUnavailable: "clipboard access is unavailable; use Export FQDNs",
        state: {
          idle: "idle",
          starting: "starting",
          running: "running",
          stopping: "stopping",
          completed: "completed",
          cancelled: "cancelled",
          failed: "failed",
          error: "error",
        },
      },
      session: {
        kicker: "Run state",
        cancel: "Cancel",
        starting: "Starting diagnostic session",
        running: "Collecting diagnostic observations",
        cancelling: "Cancelling diagnostic run",
        completed: "Diagnostic report ready",
        cancelled: "Diagnostic run cancelled",
        failed: "Diagnostic run failed",
        requestFailed: "Diagnostic request failed",
        requestError: "diagnosis request failed",
        reportLoadError: "could not load diagnostic report",
        endedWithoutReport: "diagnostic session ended without a canonical report",
        progressClosed: "progress stream closed before the session completed",
        invalidProgress: "received invalid progress data",
        requestFailedWithStatus: "request failed ({{status}})",
        cancelError: "cancel request failed",
        state: {
          idle: "idle",
          starting: "starting",
          running: "running",
          cancelling: "cancelling",
          completed: "completed",
          cancelled: "cancelled",
          failed: "failed",
          error: "error",
          unknown: "unknown",
        },
      },
      progress: {
        started: "Diagnostic started",
        running: "Collecting observations",
        complete: "Report available",
        error: "Run error",
        waiting: "Waiting for observation",
      },
      probe: {
        duration: "duration",
        layer: "layer",
        faultDomain: "fault domain",
        reason: "Reason",
        lanes: "{{count}} lane{{plural}}",
        none: "No probe results were returned.",
      },
      finding: {
        label: "Finding",
        review: "Review",
        reason: "reason",
        layer: "layer",
        faultDomain: "fault domain",
        probeLanes: "Probe lanes",
        none: "No canonical findings. This does not mean every protocol is observable.",
      },
      comparison: {
        icmpDestination: "ICMP destination",
        tcpDestination: "TCP destination",
        replied: "replied",
        connected: "connected",
        reachedNotConnected: "reached, not connected",
        notConfirmed: "not confirmed",
        protocol: "Protocol",
        observation: "Observation",
        portAware: "Port aware",
        destinationReached: "Destination reached",
        tcpConnected: "TCP connected",
        ttlResponders: "TTL responders",
        evidence: "Evidence",
        none: "No comparable protocol or port observations are available.",
      },
      export: {
        completed: "Export completed diagnosis",
        label: "Export",
        html: "HTML Report",
        json: "JSON",
      },
      destination: {
        status: "Destination Status",
        details: "Destination details",
        serviceNotObserved: "Service not observed",
        identityNotObserved: "Identity not observed",
        reason: "Reason: {{value}}",
        reachable: "Reachable",
        unreachable: "Unreachable",
        degraded: "Degraded",
        indeterminate: "Indeterminate",
        detail: {
          unknown: "Reachability could not be established from the available evidence.",
          unsupported: "The requested application protocol is unsupported.",
          notAttempted: "The requested application service was not attempted.",
          smbSuccess: "SMB negotiation succeeded.",
          smbInsufficient: "SMB transport evidence is insufficient.",
          smbFailed: "SMB protocol negotiation was rejected or failed.",
          httpStatus: "HTTP returned {{code}}.",
          httpSuccess: "HTTP service responded successfully.",
          httpAfterTransport: "HTTP request failed after transport connection.",
          sshSuccess: "{{protocol}} handshake succeeded.",
          sshFailed: "{{protocol}} protocol handshake was rejected or malformed.",
          appFailed: "The requested application service did not complete successfully.",
          tlsSuccess: "TLS handshake succeeded.",
          tlsFailed: "TLS handshake failed after transport connection.",
          transportSuccess: "Transport connection established.",
          tcpSuccess: "TCP destination connection established.",
          tcpRefused: "TCP destination responded without establishing a connection.",
          tcpReset: "TCP destination reset the connection.",
          resolutionFailed: "Name resolution did not establish a usable endpoint.",
          networkUnreachable: "The network reported the destination as unreachable.",
          tcpTimeout: "TCP connection timed out.",
          connectionRefused: "TCP connection was refused.",
          connectionReset: "TCP connection was reset.",
          transportFailed: "Transport connection failed.",
        },
      },
      diagnosis: {
        label: "Diagnosis",
        execution: "Execution",
        clear: "No canonical findings",
        findingsOne: "1 canonical finding",
        findingsMany: "{{count}} canonical findings",
        incomplete: "Evidence is incomplete",
        unavailable: "Diagnosis is unavailable",
        detail: "{{state}}.{{destination}}",
        destination: " Destination: {{value}}.",
      },
      network: {
        eyebrow: "Network context",
        title: "Selected route and scope",
        disclaimer: "Observed forwarding state, not physical topology",
        scope: "Network scope",
        requestedIdentity: "Requested identity",
        selectedDestination: "Selected destination",
        sourceInterface: "Source interface",
        sourceAddress: "Source address",
        route: "Route",
        routePrefix: "Route prefix",
        nextHop: "Next hop",
        gateway: "Gateway",
        gatewayNA: "Not applicable",
        routeMetric: "Route metric",
        certainty: "Certainty",
        provenance: "Provenance",
        evidence: "Evidence",
        vpn: "VPN / tunnel involvement",
        virtualAdapter: "Virtual adapter involvement",
        ambiguous: "Route selection ambiguous",
        neighbor: "Neighbor cache",
        competingOne: "1 competing route retained in canonical context.",
        competingMany: "{{count}} competing routes retained in canonical context.",
      },
      endpoint: {
        eyebrow: "Endpoint",
        title: "Identity and candidate selection",
        originalInput: "Original input",
        requestedIdentity: "Requested identity",
        literalIP: "Literal IP",
        service: "Service",
        applicationProtocol: "Application protocol",
        transportProtocol: "Transport protocol",
        port: "Port",
        resource: "Resource",
        selectedEndpoint: "Selected endpoint",
        testedEndpoint: "Tested endpoint",
        certainty: "Certainty",
        provenance: "Provenance",
        evidence: "Evidence",
        resolvedCandidates: "Resolved candidates",
        probeCandidates: "Probe candidates",
        candidateAttempts: "Candidate attempts",
        candidate: "Candidate",
        status: "Status",
        failure: "Failure",
        unavailable: "Target unavailable",
        identityUnavailable: "identity unavailable",
        notSpecified: "not specified",
      },
      operations: {
        eyebrow: "Operational state",
        title: "Transport, security, and application",
        canonical: "Canonical observations",
        transport: "Transport",
        security: "Security / TLS",
        application: "Application / service",
      },
      policy: {
        eyebrow: "Proxy / policy",
        title: "Enterprise path observations",
        runtime: "Configuration and runtime evidence",
        requestedIdentity: "Requested identity",
        state: "State",
        unsupported: "Unsupported",
        proxyDiverges: "Proxy configuration diverges",
        divergenceKnown: "Divergence known",
        directVsProxy: "Direct vs proxy",
        firewall: "Firewall",
        tlsPolicy: "TLS policy state",
        possibleInterception: "Possible interception",
        interceptionSuspicion: "Interception suspicion",
        certainty: "Certainty",
        provenance: "Provenance",
        evidence: "Evidence",
        paths: "Direct, browser, and service paths",
        path: "Path",
        mode: "Mode",
        endpoint: "Endpoint",
        tcp: "TCP",
        http: "HTTP",
        tls: "TLS",
        profile: "Profile",
        enabled: "Enabled",
        policyPresent: "Policy present",
        causality: "Causality",
        source: "Source",
        configuration: "Configuration",
        configuredEndpoints: "Configured proxy endpoints",
        pacConfigured: "PAC configured",
        effectiveMode: "Effective mode",
        effectiveEndpoint: "Effective endpoint",
        effectiveResolution: "Effective resolution",
        pacUsed: "PAC used",
        winHTTP: "WinHTTP",
        winINET: "WinINET",
        firewallProfiles: "Firewall profiles",
      },
      resolution: {
        eyebrow: "Name resolution",
        title: "Effective resolution path",
        note: "Configured servers and policy paths are candidates unless the host API provides stronger evidence. Empty resolver or interface values mean Windows did not expose that selection.",
        requestedName: "Requested name",
        path: "Resolution path",
        interface: "Interface",
        resolver: "Resolver",
        policy: "Policy",
        answersA: "Answers A",
        answersAAAA: "Answers AAAA",
        representative: "Resolver representative answer (not OS/application selection)",
        certainty: "Certainty",
        candidateNames: "Candidate names",
        suffixes: "Search suffixes",
        namespaces: "Candidate namespaces",
        provenance: "Provenance",
        limitations: "Limitations",
        configuredCandidatesOne: "Configured candidate · 1",
        configuredCandidatesMany: "Configured candidates · {{count}}",
        evidence: "Evidence",
        unavailable: "No normalized name-resolution observation is available.",
        notObservable: "not observable",
        notSelected: "not selected",
        noNamespace: "no namespace",
        certaintyUnknown: "certainty unknown",
        resolverNotObservable: "resolver not observable",
        interfaceNotObservable: "interface not observable",
      },
      path: {
        eyebrow: "Observed path",
        title: "Responder path visibility",
        disclaimer: "Observed responders, not physical topology",
        explanation: "This workbench shows responders and unobservable ranges observed from the diagnostic vantage. It describes responder/path visibility, not physical topology or inferred device identity.",
        projection: "Projection",
        graph: "Graph",
        table: "Table",
        canonicalTable: "Canonical table",
        observedSequence: "Observed responder sequence",
        waiting: "Waiting for canonical path observations.",
        awaitingReport: "Awaiting report",
        noPath: "No responder/path visibility was retained for this report.",
        supportedTable: "The report retained the supported Table projection for this path lane.",
        noGraph: "No graph-compatible canonical path projection is available.",
        graphDescription: "Canonical nodes preserve TTL order, responder visibility, and destination confirmation.",
        graphViewport: "Observed Path graph viewport",
        loading: "Loading observed path",
        loadingDetail: "Waiting for the diagnostic report to provide canonical path observations.",
        empty: "No observed path in this report",
        emptyDetail: "The graph stays available for a run that exposes responder/path visibility. Review the other evidence lanes for retained observations.",
        unsupported: "Graph projection unavailable",
        unsupportedDetail: "This report does not expose a graph-compatible path observation. The canonical Table projection remains the supported view.",
        sequence: "sequence",
        responderVisibility: "responder visibility",
        destinationCheck: "destination check",
        start: "START",
        probeVantage: "Probe vantage",
        localSource: "local source",
        orderedHops: "ORDERED HOPS",
        ttlResponderSlots: "TTL responder slots",
        respondersAtTTL: "one or more responders at a TTL",
        unobservableRange: "UNOBSERVABLE RANGE",
        noResponseInterval: "No response interval",
        notPacketLoss: "not a packet-loss claim",
        destination: "DESTINATION",
        confirmationSlot: "Confirmation slot",
        reachabilityPort: "reachability and port state",
        canonicalOrdering: "canonical ordering",
        multipleResponders: "multiple responders remain distinct",
        selectionReserved: "selection target reserved",
        selection: "Node selection → Evidence inspector",
        selectionDetail: "Canonical graph elements focus retained evidence and semantic details here. The graph does not reconstruct physical topology.",
        observedResponder: "Observed responder",
        inferredRange: "Unobservable range",
        failedObservation: "Failed observation",
        wideScroll: "Wide paths scroll horizontally",
        narrowFallback: "Narrow-screen fallback:",
        readableTable: "Table view keeps the full path details readable on small screens.",
        openTable: "Open Table view",
        tableNote: "Canonical path observations remain available as rows. A missing TTL response is unobservable evidence, not a packet-loss claim.",
        noStructured: "No structured path observation is available in this report.",
        protocolPort: "Protocol / port",
        comparison: "Endpoint comparison",
        comparisonNote: "ICMP reachability and TCP destination-port connectivity are separate observations.",
        checks: "Checks",
        probeResults: "Probe results",
        interpretation: "Interpretation",
        findings: "Findings",
        evidence: "Evidence",
        structuredEvidence: "Structured evidence",
        inspectorNote: "Select a path row, graph element, or finding to focus its evidence and semantic details. Raw evidence remains available here.",
        canonicalJSON: "Canonical JSON",
        canonicalJSONNote: "Canonical diagnostic report. Displayed as text only.",
        observedPath: "observed path",
        observedPathsOne: "1 observed path",
        observedPathsMany: "{{count}} observed paths",
        portAware: "port-aware",
        icmpContext: "ICMP endpoint context",
        notPortAware: "not port-aware",
        tcpConnected: "TCP connected",
        destinationReached: "destination reached",
        observation: "observation",
        destinationConfirmed: "destination confirmed",
        canonicalOrder: "Canonical observation order",
        observedOrder: "observed order",
        startGroup: "START",
        destinationGroup: "DESTINATION",
        ttl: "TTL {{value}}",
        ttlRange: "TTL {{from}}–{{to}}",
        role: "Role",
        ttlHop: "TTL / hop",
        observedAddress: "Observed address",
        rtt: "RTT",
        response: "Response",
        attempts: "Attempts",
        protocol: "Protocol",
        destinationPort: "Destination port",
        certainty: "Certainty",
        provenance: "Provenance",
        limitations: "Limitations",
        notApplicable: "not applicable for this graph element",
        notObserved: "not observed",
        notSpecified: "not specified",
        unknown: "unknown",
        destinationObservation: "Destination observation",
        reached: "Reached: {{value}}",
        tcpConnectedDetail: "TCP connected: {{value}}",
        evidenceSegments: "Evidence segments",
        focusRaw: "Focus the raw path evidence",
        localSourceDetail: "local source",
        responders: "{{count}} responder{{plural}}",
        unobservableTTLs: "{{count}} unobservable TTL{{plural}}",
        noHopDetail: "No hop detail",
      },
      evidence: {
        inspector: "Evidence inspector",
        structured: "Structured evidence",
        itemOne: "Structured evidence · 1 item",
        itemMany: "Structured evidence · {{count}} items",
        source: "source",
        shape: "shape",
        structuredJSON: "structured JSON",
        rawJSON: "raw JSON value",
        captured: "captured",
        rawValue: "Raw evidence value",
        available: "available",
        partial: "partial",
        none: "No evidence was retained.",
        notAvailable: "not available",
        drill: "Drill into evidence",
      },
      application: {
        noObservation: "No canonical application observation is available.",
        applicability: "Applicability",
        protocol: "Protocol",
        requestAttempted: "Request attempted",
        responseReceived: "Response received",
        transportConnected: "Transport connected",
        handshakeAttempted: "Handshake attempted",
        handshakeComplete: "Handshake complete",
        result: "Result",
        protocolResult: "Protocol result",
        endpointUsed: "Endpoint used",
        requestedResource: "Requested resource",
        failureReason: "Failure reason",
        faultDomain: "Fault domain",
        certainty: "Certainty",
        limitations: "Limitations",
        connected: "Connected",
        connectionOutcome: "Connection outcome",
        requestedEndpoint: "Requested endpoint",
        probeEndpoint: "Probe endpoint",
        testedEndpoint: "Tested endpoint",
        localEndpoint: "Local endpoint",
        remoteEndpoint: "Remote endpoint",
        certificateValidation: "Certificate validation",
        peerCertificates: "Peer certificates",
        tlsVersion: "TLS version",
        cipherSuite: "Cipher suite",
        negotiatedProtocol: "Negotiated protocol",
        serverName: "Server name",
        response: "Response",
        from: "From",
        location: "Location",
        to: "To",
        noneObserved: "none observed",
        notExposed: "not exposed",
        notNegotiated: "not negotiated",
        httpResponse: "HTTP / HTTPS response",
        httpVersion: "HTTP version",
        statusCode: "Status code",
        status: "Status",
        url: "URL",
        resource: "Resource",
        redirects: "Redirects",
        redirectChain: "Redirect chain",
        dnsResponse: "DNS service response",
        query: "Query",
        requestedEndpoint: "Requested endpoint",
        divergence: "Divergence",
        lane: "Lane",
        attempted: "Attempted",
        outcome: "Outcome",
        rcode: "RCODE",
        truncated: "Truncated",
        fallback: "Fallback",
        smbNegotiation: "SMB negotiation",
        negotiationResult: "Negotiation result",
        negotiated: "Negotiated",
        dialect: "Dialect",
        dialectRevision: "Dialect revision",
        capabilities: "Capabilities",
        serverGUID: "Server GUID",
        securityMode: "Security mode",
        maxTransact: "Max transact size",
        maxRead: "Max read size",
        maxWrite: "Max write size",
        responseBytes: "Response bytes",
        sshHandshake: "SSH handshake",
        rdpNegotiation: "RDP negotiation",
        serverIdentification: "Server identification",
        negotiatedSecurity: "Negotiated security",
        requestedSecurity: "Requested security",
        serviceView: "Service-specific application view",
        applicationProvenance: "Application provenance",
        probeLanes: "Probe lanes",
        unsupportedOrNotAttempted: "unsupported or not attempted",
      },
      common: {
        yes: "yes",
        no: "no",
        none: "(none)",
        unknown: "unknown",
        notObserved: "not observed",
        notSpecified: "not specified",
        notApplicable: "not applicable",
        notObservable: "not observable",
        notSelected: "not selected",
        identityUnavailable: "identity unavailable",
        targetUnavailable: "Target unavailable",
        milliseconds: "ms",
        noObservation: "No canonical observation is available.",
        notAttempted: "not attempted",
      },
      enum: {
        state: {
          idle: "idle", starting: "starting", running: "running", stopping: "stopping",
          cancelling: "cancelling", completed: "completed", cancelled: "cancelled", failed: "failed",
          error: "error", unknown: "unknown",
        },
        reportStatus: {
          complete: "Run complete", incomplete: "Run incomplete", error: "Run error", unknown: "Run state unknown",
        },
        probeStatus: {
          passed: "Passed", failed: "Failed", error: "Error", skipped: "Skipped / unsupported", unknown: "Unknown",
        },
        pathStatus: {
          observed: "Observed", unsupported: "Unsupported", error: "Error", unknown: "Unknown",
        },
        hopState: { observed: "Observed responder", unobservable: "Unobservable", unknown: "Unknown" },
        applicability: {
          unknown: "Unknown", applicable: "Applicable", inapplicable: "Inapplicable", not_attempted: "Not attempted", unsupported: "Unsupported",
        },
        certainty: { observed: "Observed", configured: "Configured", inferred: "Inferred", unknown: "Unknown", unsupported: "Unsupported" },
        route: { on_link: "On-link", routed: "Routed", unknown: "Unknown" },
        scope: { loopback: "Loopback", link_local: "Link-local", same_link: "Local link", private_routed: "Private routed", vpn_tunnel_routed: "VPN / tunnel routed", external_routed: "External routed", unknown: "Unknown" },
        segment: { observed_responder: "Observed responder", inferred: "Inferred transit range", unobservable: "Unobservable range", unknown: "Unknown segment" },
        observation: { observed: "Observed", unsupported: "Unsupported", error: "Error", unknown: "Unknown" },
        transportOutcome: { unknown: "Unknown", not_attempted: "Not attempted", connected: "Connected", refused: "Refused", reset: "Reset", timeout: "Timeout", unreachable: "Unreachable", canceled: "Canceled", failed: "Failed", unsupported: "Unsupported" },
        result: { unknown: "Unknown", success: "Success", failure: "Failure", status_failure: "Status failure", request_failure: "Request failure", not_attempted: "Not attempted", unsupported: "Unsupported", partial: "Partial" },
        protocolResult: { unknown: "Unknown", success: "Success", failure: "Failure", rejected: "Rejected", malformed: "Malformed", timeout: "Timeout", not_attempted: "Not attempted", unsupported: "Unsupported" },
        failure: {
          none: "No failure", unknown: "Unknown", probe_execution_failure: "Probe execution failure", unsupported: "Unsupported",
          interface_down: "Interface down", no_ip_address: "No IP address", no_route: "No route", invalid_route: "Invalid route",
          gateway_unreachable: "Gateway unreachable", network_unreachable: "Network unreachable", dns_nxdomain: "DNS NXDOMAIN", dns_no_answer: "DNS no answer", dns_timeout: "DNS timeout", dns_resolver_failure: "DNS resolver failure",
          firewall_blocked: "Firewall blocked", proxy_configuration_failure: "Proxy configuration failure", proxy_configuration_divergence: "Proxy configuration divergence", proxy_unavailable: "Proxy unavailable", proxy_connect_denied: "Proxy connect denied", proxy_authentication_required: "Proxy authentication required", direct_egress_restricted: "Direct egress restricted", effective_route_difference: "Effective route difference",
          tcp_timeout: "TCP timeout", tcp_connection_refused: "TCP connection refused", tcp_connection_reset: "TCP connection reset", tcp_syn_not_observed: "TCP SYN not observed", tls_handshake_failure: "TLS handshake failure", certificate_validation_failure: "Certificate validation failure", tls_trust_store_mismatch: "TLS trust store mismatch", tls_interception_suspected: "TLS interception suspected", http_failure: "HTTP failure", http_status_code: "HTTP status code", ssh_handshake_failure: "SSH handshake failure", ssh_timeout: "SSH timeout", ssh_banner_malformed: "SSH banner malformed", ssh_non_ssh_response: "Non-SSH response", rdp_negotiation_failure: "RDP negotiation failure", rdp_timeout: "RDP timeout", rdp_negotiation_malformed: "RDP negotiation malformed", rdp_negotiation_rejected: "RDP negotiation rejected", icmp_failure: "ICMP failure", path_observation_failure: "Path observation failure", path_cancellation: "Path cancelled",
        },
        protocol: { icmp: "ICMP", tcp: "TCP", udp: "UDP", unknown: "Unknown protocol" },
        resolutionState: { configured_candidate: "Configured candidate", policy_candidate: "Policy candidate", effective: "Effective" },
        resolutionMechanism: { dns: "System DNS client", hosts_file: "Hosts file candidate", literal_ip: "Literal IP", unknown: "Unknown" },
        browserOutcome: { connected: "Connected", failed: "Failed", dns_failed: "DNS failed", proxy_rejected: "Proxy rejected", mixed: "Mixed", unknown: "Unknown" },
        destinationState: { reachable: "Reachable", unreachable: "Unreachable", degraded: "Degraded", indeterminate: "Indeterminate" },
        certificateValidation: { unknown: "Unknown", valid: "Valid", invalid: "Invalid", expired: "Expired", hostname_mismatch: "Hostname mismatch", untrusted: "Untrusted", incomplete: "Incomplete" },
        layer: { unknown: "Unknown", interface: "Interface", ip_configuration: "IP configuration", route: "Route", gateway: "Gateway", dns: "DNS", network: "Network", proxy: "Proxy", tcp: "TCP", tls: "TLS", http: "HTTP", ssh: "SSH", rdp: "RDP", icmp: "ICMP", destination: "Destination" },
        faultDomain: { unknown: "Unknown", local: "Local", routing: "Routing", gateway: "Gateway", dns: "DNS", network: "Network", firewall: "Firewall", proxy: "Proxy", transport: "Transport", tls: "TLS", http: "HTTP", ssh: "SSH", rdp: "RDP", destination: "Destination", icmp: "ICMP", policy: "Policy" },
        neighbor: { not_applicable: "Not applicable", observed: "Observed", not_observed: "Not observed", unsupported: "Unsupported", error: "Error", unknown: "Unknown" },
      },
      source: {
        hopObserved: "A responder was observed at this TTL.",
        hopUnobservable: "No responder was observed at this TTL; this is not packet loss.",
        segmentObserved: "Direct responder evidence for this TTL.",
        segmentInferred: "Bounded inference between observations; not an exact physical link.",
        segmentUnobservable: "No responder was observed in this TTL range; this is not packet loss.",
        graphVantage: "Local diagnostic source; this graph preserves observation order.",
        graphResponderOne: "One responder observation retained at this TTL.",
        graphResponderMany: "{{count}} responder observations retained at this TTL; none are collapsed.",
        graphDestination: "Destination reachability and port state are shown separately from intermediate responders.",
        graphUnknown: "The canonical observation does not identify responders for TTL {{range}}.",
        graphDestinationNotConfirmed: "Destination confirmation was not observed in this lane.",
        graphDestinationConfirmed: "Destination confirmed; intermediate visibility may still be incomplete.",
        graphDestinationTCP: "Destination confirmed and TCP connection established.",
        graphResponder: "Responder observed at TTL {{ttl}}; identity is scoped to this observation.",
        graphDestinationResponder: "Destination responder observed at TTL {{ttl}}.",
        graphUnobservable: "No responder was observed for TTL {{range}}; this is not packet loss.",
        edgeObserved: "The edge records canonical observation order, not physical topology.",
        edgeUnobservable: "The sequence crosses a TTL range without a responder; this is not packet loss or an invented device.",
        edgeInferred: "The edge records bounded TTL progression between observations, not an exact physical link.",
        edgeDestination: "Destination confirmation is a separate reachability and port-state observation.",
        limitationGraph: "Graph nodes identify observed TTL responders, not physical devices; edges preserve bounded observation order.",
        limitationICMP: "This ICMP path lane carries endpoint port context but does not prove destination-port connectivity.",
        limitationNotPortAware: "This path lane is not port-aware and does not prove destination-port connectivity.",
        limitationUnobservable: "Unobservable TTLs mean no responder was received before the bounded context ended; they are not packet loss.",
        limitationDestination: "Destination confirmation is independent of visibility at intermediate TTLs.",
        limitationUnsupported: "This protocol lane is unsupported; no reachability conclusion is drawn from the missing capability.",
        limitationError: "The path adapter reported an error; partial TTL evidence remains scoped to what was observed.",
      },
    }),
    ja: Object.freeze({
      language: { label: "言語", japanese: "日本語", english: "英語" },
      brand: { context: "診断ワークベンチ" },
      runtime: { local: "ローカルプロセス · ループバックのみ" },
      target: { section: "診断対象", label: "対象", placeholder: "ホスト名、IP、URL、または \\\\server\\share", service: "サービス", serviceProfile: "サービスプロファイル", port: "ポート", diagnose: "診断", starting: "開始中…", running: "実行中…", ready: "診断の準備ができました", enterToBegin: "対象を入力して開始してください。" },
      service: { http: "HTTP", https: "HTTPS", smb: "ファイル共有 (SMB)", rdp: "RDP", ssh: "SSH", dns: "DNS", customTCP: "カスタム TCP", customTLS: "カスタム TLS" },
      browser: { workflow: "ブラウザワークフロー", title: "ブラウザキャプチャ", description: "ループバックのみのプロキシ経由で専用ブラウザプロファイルを起動し、ワークフローの接続先を検出します。HTTPS は CONNECT の接続先から記録され、TLS ペイロードは復号しません。", browser: "ブラウザ", edge: "Microsoft Edge", chrome: "Google Chrome", start: "ブラウザキャプチャを開始", stop: "キャプチャを停止", exportJSON: "JSON を出力", exportFQDNs: "FQDN を出力", copyFQDNs: "FQDN をコピー", copiedFQDNs: "FQDN をコピーしました", elapsed: "経過", destinations: "接続先", addresses: "アドレス", observations: "観測", failures: "失敗", destination: "接続先", port: "ポート", outcome: "結果", connections: "接続数", connectedEndpoint: "接続済みエンドポイント", failure: "失敗", empty: "ブラウザ接続先はまだ観測されていません。", unknown: "不明", notObserved: "未観測", none: "なし", state: { idle: "待機中", starting: "開始中", running: "実行中", stopping: "停止中", completed: "完了", cancelled: "キャンセル済み", failed: "失敗", error: "エラー" } },
      session: { kicker: "実行状態", cancel: "キャンセル", starting: "診断セッションを開始中", running: "診断観測を収集中", cancelling: "診断実行をキャンセル中", completed: "診断レポートの準備完了", cancelled: "診断実行をキャンセルしました", failed: "診断に失敗しました", requestFailed: "診断リクエストに失敗しました", requestError: "診断リクエストに失敗しました", reportLoadError: "診断レポートを読み込めませんでした", endedWithoutReport: "正規レポートなしで診断セッションが終了しました", progressClosed: "セッション完了前に進捗ストリームが終了しました", invalidProgress: "無効な進捗データを受信しました", cancelError: "キャンセルリクエストに失敗しました", state: { idle: "待機中", starting: "開始中", running: "実行中", cancelling: "キャンセル中", completed: "完了", cancelled: "キャンセル済み", failed: "失敗", error: "エラー", unknown: "不明" } },
      progress: { started: "診断を開始しました", running: "観測を収集中", complete: "レポートを利用できます", error: "実行エラー", waiting: "観測を待機中" },
      export: { completed: "完了した診断の出力", label: "出力", html: "HTML レポート", json: "JSON" },
      destination: { status: "接続先ステータス", details: "接続先の詳細", serviceNotObserved: "サービス未観測", identityNotObserved: "識別情報未観測", reason: "理由: {{value}}", reachable: "到達可能", unreachable: "到達不能", degraded: "一部利用可能", indeterminate: "判定不能", detail: { unknown: "利用可能な証拠から到達性を確立できませんでした。", unsupported: "要求されたアプリケーションプロトコルはサポートされていません。", notAttempted: "要求されたアプリケーションサービスは試行されていません。", smbSuccess: "SMB ネゴシエーションに成功しました。", smbInsufficient: "SMB トランスポートの証拠が不十分です。", smbFailed: "SMB プロトコルのネゴシエーションが拒否または失敗しました。", httpStatus: "HTTP は {{code}} を返しました。", httpSuccess: "HTTP サービスは正常に応答しました。", httpAfterTransport: "トランスポート接続後に HTTP リクエストが失敗しました。", sshSuccess: "{{protocol}} ハンドシェイクに成功しました。", sshFailed: "{{protocol}} プロトコルのハンドシェイクが拒否または不正形式でした。", appFailed: "要求されたアプリケーションサービスは正常に完了しませんでした。", tlsSuccess: "TLS ハンドシェイクに成功しました。", tlsFailed: "トランスポート接続後に TLS ハンドシェイクが失敗しました。", transportSuccess: "トランスポート接続を確立しました。", tcpSuccess: "TCP 接続先への接続を確立しました。", tcpRefused: "TCP 接続先は接続を確立せずに応答しました。", tcpReset: "TCP 接続先が接続をリセットしました。", resolutionFailed: "名前解決から利用可能なエンドポイントを確立できませんでした。", networkUnreachable: "ネットワークは接続先に到達できないと報告しました。", tcpTimeout: "TCP 接続がタイムアウトしました。", connectionRefused: "TCP 接続が拒否されました。", connectionReset: "TCP 接続がリセットされました。", transportFailed: "トランスポート接続に失敗しました。" } },
      diagnosis: { label: "診断", execution: "実行", clear: "正規の所見はありません", findingsOne: "正規の所見 1 件", findingsMany: "正規の所見 {{count}} 件", incomplete: "証拠が不完全です", unavailable: "診断を利用できません", detail: "{{state}}。{{destination}}", destination: " 接続先: {{value}}。" },
      network: { eyebrow: "ネットワークコンテキスト", title: "選択された経路とスコープ", disclaimer: "観測された転送状態であり、物理トポロジーではありません", scope: "ネットワークスコープ", requestedIdentity: "要求された識別情報", selectedDestination: "選択された接続先", sourceInterface: "送信元インターフェース", sourceAddress: "送信元アドレス", route: "経路", routePrefix: "経路プレフィックス", nextHop: "ネクストホップ", gateway: "ゲートウェイ", gatewayNA: "該当なし", routeMetric: "経路メトリック", certainty: "確度", provenance: "プロヴェナンス", evidence: "証拠", vpn: "VPN / トンネルの関与", virtualAdapter: "仮想アダプターの関与", ambiguous: "経路選択があいまい", neighbor: "近隣キャッシュ", competingOne: "正規コンテキストに競合経路を 1 件保持しています。", competingMany: "正規コンテキストに競合経路を {{count}} 件保持しています。" },
      endpoint: { eyebrow: "エンドポイント", title: "識別情報と候補選択", originalInput: "元の入力", requestedIdentity: "要求された識別情報", literalIP: "リテラル IP", service: "サービス", applicationProtocol: "アプリケーションプロトコル", transportProtocol: "トランスポートプロトコル", port: "ポート", resource: "リソース", selectedEndpoint: "選択されたエンドポイント", testedEndpoint: "試験したエンドポイント", certainty: "確度", provenance: "プロヴェナンス", evidence: "証拠", resolvedCandidates: "解決済み候補", probeCandidates: "プローブ候補", candidateAttempts: "候補の試行", candidate: "候補", status: "状態", failure: "失敗", unavailable: "対象を利用できません", identityUnavailable: "識別情報は利用できません", notSpecified: "未指定" },
      operations: { eyebrow: "運用状態", title: "トランスポート、セキュリティ、アプリケーション", canonical: "正規の観測", transport: "トランスポート", security: "セキュリティ / TLS", application: "アプリケーション / サービス" },
      policy: { eyebrow: "プロキシ / ポリシー", title: "エンタープライズ経路の観測", runtime: "設定と実行時の証拠", requestedIdentity: "要求された識別情報", state: "状態", unsupported: "未サポート", proxyDiverges: "プロキシ設定の差異", divergenceKnown: "差異の判明", directVsProxy: "直接接続とプロキシ", firewall: "ファイアウォール", tlsPolicy: "TLS ポリシー状態", possibleInterception: "傍受の可能性", interceptionSuspicion: "傍受の疑い", certainty: "確度", provenance: "プロヴェナンス", evidence: "証拠", paths: "直接、ブラウザ、サービスの経路", path: "経路", mode: "モード", endpoint: "エンドポイント", tcp: "TCP", http: "HTTP", tls: "TLS", profile: "プロファイル", enabled: "有効", policyPresent: "ポリシーの存在", causality: "因果関係", source: "ソース", configuration: "設定", configuredEndpoints: "設定済みプロキシエンドポイント", pacConfigured: "PAC 設定済み", effectiveMode: "実効モード", effectiveEndpoint: "実効エンドポイント", effectiveResolution: "実効解決", pacUsed: "PAC 使用済み", winHTTP: "WinHTTP", winINET: "WinINET", firewallProfiles: "ファイアウォールプロファイル" },
      resolution: { eyebrow: "名前解決", title: "実効解決経路", note: "ホスト API がより強い証拠を提供しない限り、設定済みサーバーとポリシー経路は候補です。空のリゾルバーまたはインターフェース値は、Windows がその選択を公開しなかったことを示します。", requestedName: "要求された名前", path: "解決経路", interface: "インターフェース", resolver: "リゾルバー", policy: "ポリシー", answersA: "A レコード", answersAAAA: "AAAA レコード", representative: "リゾルバー代表応答 (OS/アプリケーションの選択ではありません)", certainty: "確度", candidateNames: "候補名", suffixes: "検索サフィックス", namespaces: "候補名前空間", provenance: "プロヴェナンス", limitations: "制限事項", configuredCandidatesOne: "設定済み候補 · 1", configuredCandidatesMany: "設定済み候補 · {{count}}", evidence: "証拠", unavailable: "正規化された名前解決の観測はありません。", notObservable: "観測不能", notSelected: "未選択", noNamespace: "名前空間なし", certaintyUnknown: "確度不明", resolverNotObservable: "リゾルバー観測不能", interfaceNotObservable: "インターフェース観測不能" },
      path: { eyebrow: "観測された経路", title: "応答者の経路可視性", disclaimer: "観測された応答者であり、物理トポロジーではありません", explanation: "このワークベンチは診断地点から観測された応答者と観測不能範囲を表示します。物理トポロジーや推定デバイス識別ではなく、応答者と経路の可視性を示します。", projection: "表示", graph: "グラフ", table: "テーブル", canonicalTable: "正規テーブル", observedSequence: "観測された応答者の順序", waiting: "正規の経路観測を待機中です。", awaitingReport: "レポート待ち", noPath: "このレポートには応答者/経路の可視性が保持されていません。", supportedTable: "この経路レーンでは、サポートされるテーブル表示が保持されています。", noGraph: "グラフ互換の正規経路表示はありません。", graphDescription: "正規ノードは TTL 順序、応答者の可視性、接続先の確認を保持します。", graphViewport: "観測経路グラフのビューポート", loading: "観測経路を読み込み中", loadingDetail: "診断レポートから正規の経路観測が提供されるのを待機しています。", empty: "このレポートには観測経路がありません", emptyDetail: "応答者/経路の可視性を公開する実行ではグラフを利用できます。他の証拠レーンで保持された観測を確認してください。", unsupported: "グラフ表示を利用できません", unsupportedDetail: "このレポートにはグラフ互換の経路観測がありません。正規テーブル表示がサポートされる表示です。", sequence: "順序", responderVisibility: "応答者の可視性", destinationCheck: "接続先の確認", start: "開始", probeVantage: "プローブ地点", localSource: "ローカルソース", orderedHops: "順序付きホップ", ttlResponderSlots: "TTL 応答者スロット", respondersAtTTL: "TTL ごとの 1 つ以上の応答者", unobservableRange: "観測不能範囲", noResponseInterval: "応答なし区間", notPacketLoss: "パケット損失を示すものではありません", destination: "接続先", confirmationSlot: "確認スロット", reachabilityPort: "到達性とポート状態", canonicalOrdering: "正規の順序", multipleResponders: "複数の応答者を区別して保持", selectionReserved: "選択対象を予約済み", selection: "ノード選択 → 証拠インスペクター", selectionDetail: "正規グラフ要素を選択すると、保持された証拠と意味の詳細をここに表示します。グラフは物理トポロジーを再構成しません。", observedResponder: "観測された応答者", inferredRange: "観測不能範囲", failedObservation: "観測失敗", wideScroll: "広い経路は横スクロールできます", narrowFallback: "狭い画面での代替:", readableTable: "小さい画面ではテーブル表示で経路の詳細を読みやすく確認できます。", openTable: "テーブル表示を開く", tableNote: "正規の経路観測は行として利用できます。TTL の応答欠落は観測不能な証拠であり、パケット損失を示すものではありません。", noStructured: "このレポートには構造化された経路観測がありません。", protocolPort: "プロトコル / ポート", comparison: "エンドポイント比較", comparisonNote: "ICMP 到達性と TCP 宛先ポート接続性は別の観測です。", checks: "チェック", probeResults: "プローブ結果", interpretation: "解釈", findings: "所見", evidence: "証拠", structuredEvidence: "構造化された証拠", inspectorNote: "経路の行、グラフ要素、または所見を選択すると、関連する証拠と意味の詳細にフォーカスします。生の証拠もここで確認できます。", canonicalJSON: "正規 JSON", canonicalJSONNote: "正規の診断レポートです。テキストとしてのみ表示します。", observedPath: "観測経路", observedPathsOne: "観測経路 1 件", observedPathsMany: "観測経路 {{count}} 件", portAware: "ポート対応", icmpContext: "ICMP 接続先コンテキスト", notPortAware: "ポート非対応", tcpConnected: "TCP 接続済み", destinationReached: "接続先に到達", observation: "観測", destinationConfirmed: "接続先を確認済み", canonicalOrder: "正規の観測順序", observedOrder: "観測順序", startGroup: "開始", destinationGroup: "接続先", ttl: "TTL {{value}}", ttlRange: "TTL {{from}}–{{to}}", role: "役割", ttlHop: "TTL / ホップ", observedAddress: "観測アドレス", rtt: "RTT", response: "応答", attempts: "試行回数", protocol: "プロトコル", destinationPort: "接続先ポート", certainty: "確度", provenance: "プロヴェナンス", limitations: "制限事項", notApplicable: "このグラフ要素には該当しません", notObserved: "未観測", notSpecified: "未指定", unknown: "不明", destinationObservation: "接続先の観測", reached: "到達: {{value}}", tcpConnectedDetail: "TCP 接続済み: {{value}}", evidenceSegments: "証拠セグメント", focusRaw: "生の経路証拠にフォーカス", localSourceDetail: "ローカルソース", responders: "応答者 {{count}} 件", unobservableTTLs: "観測不能 TTL {{count}} 件", noHopDetail: "ホップの詳細なし" },
      evidence: { inspector: "証拠インスペクター", structured: "構造化された証拠", itemOne: "構造化された証拠 · 1 件", itemMany: "構造化された証拠 · {{count}} 件", source: "ソース", shape: "形式", structuredJSON: "構造化 JSON", rawJSON: "生の JSON 値", captured: "取得時刻", rawValue: "生の証拠値", available: "利用可能", partial: "一部", none: "証拠は保持されていません。", notAvailable: "利用不可", drill: "証拠を詳しく見る" },
      application: { noObservation: "正規のアプリケーション観測はありません。", applicability: "適用可能性", protocol: "プロトコル", requestAttempted: "リクエスト試行", responseReceived: "応答受信", transportConnected: "トランスポート接続済み", handshakeAttempted: "ハンドシェイク試行", handshakeComplete: "ハンドシェイク完了", result: "結果", protocolResult: "プロトコル結果", endpointUsed: "使用エンドポイント", requestedResource: "要求リソース", failureReason: "失敗理由", faultDomain: "障害ドメイン", certainty: "確度", limitations: "制限事項", httpResponse: "HTTP / HTTPS 応答", httpVersion: "HTTP バージョン", statusCode: "ステータスコード", status: "状態", url: "URL", resource: "リソース", redirects: "リダイレクト", redirectChain: "リダイレクトチェーン", dnsResponse: "DNS サービス応答", query: "クエリ", requestedEndpoint: "要求エンドポイント", divergence: "差異", lane: "レーン", attempted: "試行済み", outcome: "結果", rcode: "RCODE", truncated: "切り詰め", fallback: "フォールバック", smbNegotiation: "SMB ネゴシエーション", negotiationResult: "ネゴシエーション結果", negotiated: "ネゴシエーション済み", dialect: "ダイアレクト", dialectRevision: "ダイアレクトリビジョン", capabilities: "機能", serverGUID: "サーバー GUID", securityMode: "セキュリティモード", maxTransact: "最大トランザクションサイズ", maxRead: "最大読み取りサイズ", maxWrite: "最大書き込みサイズ", responseBytes: "応答バイト数", sshHandshake: "SSH ハンドシェイク", rdpNegotiation: "RDP ネゴシエーション", serverIdentification: "サーバー識別情報", negotiatedSecurity: "ネゴシエートされたセキュリティ", requestedSecurity: "要求されたセキュリティ", serviceView: "サービス固有のアプリケーション表示", applicationProvenance: "アプリケーションのプロヴェナンス", probeLanes: "プローブレーン", unsupportedOrNotAttempted: "未サポートまたは未試行" },
      common: { yes: "はい", no: "いいえ", none: "(なし)", unknown: "不明", notObserved: "未観測", notSpecified: "未指定", notApplicable: "該当なし", notObservable: "観測不能", notSelected: "未選択", identityUnavailable: "識別情報は利用できません", targetUnavailable: "対象を利用できません" },
      enum: {
        state: { idle: "待機中", starting: "開始中", running: "実行中", stopping: "停止中", cancelling: "キャンセル中", completed: "完了", cancelled: "キャンセル済み", failed: "失敗", error: "エラー", unknown: "不明" },
        reportStatus: { complete: "実行完了", incomplete: "実行未完了", error: "実行エラー", unknown: "実行状態不明" },
        probeStatus: { passed: "成功", failed: "失敗", error: "エラー", skipped: "スキップ / 未サポート", unknown: "不明" },
        pathStatus: { observed: "観測済み", unsupported: "未サポート", error: "エラー", unknown: "不明" },
        hopState: { observed: "観測された応答者", unobservable: "観測不能", unknown: "不明" },
        applicability: { unknown: "不明", applicable: "適用可能", inapplicable: "非適用", not_attempted: "未試行", unsupported: "未サポート" },
        certainty: { observed: "観測済み", configured: "設定済み", inferred: "推定", unknown: "不明", unsupported: "未サポート" },
        route: { on_link: "オンリンク", routed: "ルーティング済み", unknown: "不明" },
        scope: { loopback: "ループバック", link_local: "リンクローカル", same_link: "ローカルリンク", private_routed: "プライベートルーティング", vpn_tunnel_routed: "VPN / トンネルルーティング", external_routed: "外部ルーティング", unknown: "不明" },
        segment: { observed_responder: "観測された応答者", inferred: "推定された通過範囲", unobservable: "観測不能範囲", unknown: "不明なセグメント" },
        observation: { observed: "観測済み", unsupported: "未サポート", error: "エラー", unknown: "不明" },
        transportOutcome: { unknown: "不明", not_attempted: "未試行", connected: "接続済み", refused: "拒否", reset: "リセット", timeout: "タイムアウト", unreachable: "到達不能", canceled: "キャンセル", failed: "失敗", unsupported: "未サポート" },
        result: { unknown: "不明", success: "成功", failure: "失敗", status_failure: "ステータス失敗", request_failure: "リクエスト失敗", not_attempted: "未試行", unsupported: "未サポート", partial: "一部成功" },
        protocolResult: { unknown: "不明", success: "成功", failure: "失敗", rejected: "拒否", malformed: "不正形式", timeout: "タイムアウト", not_attempted: "未試行", unsupported: "未サポート" },
        failure: { none: "失敗なし", unknown: "不明", probe_execution_failure: "プローブ実行失敗", unsupported: "未サポート", interface_down: "インターフェース停止", no_ip_address: "IP アドレスなし", no_route: "経路なし", invalid_route: "無効な経路", gateway_unreachable: "ゲートウェイ到達不能", network_unreachable: "ネットワーク到達不能", dns_nxdomain: "DNS NXDOMAIN", dns_no_answer: "DNS 応答なし", dns_timeout: "DNS タイムアウト", dns_resolver_failure: "DNS リゾルバー失敗", firewall_blocked: "ファイアウォールによるブロック", proxy_configuration_failure: "プロキシ設定失敗", proxy_configuration_divergence: "プロキシ設定の差異", proxy_unavailable: "プロキシ利用不可", proxy_connect_denied: "プロキシ接続拒否", proxy_authentication_required: "プロキシ認証が必要", direct_egress_restricted: "直接エグレス制限", effective_route_difference: "実効経路の差異", tcp_timeout: "TCP タイムアウト", tcp_connection_refused: "TCP 接続拒否", tcp_connection_reset: "TCP 接続リセット", tcp_syn_not_observed: "TCP SYN 未観測", tls_handshake_failure: "TLS ハンドシェイク失敗", certificate_validation_failure: "証明書検証失敗", tls_trust_store_mismatch: "TLS 信頼ストア不一致", tls_interception_suspected: "TLS 傍受の疑い", http_failure: "HTTP 失敗", http_status_code: "HTTP ステータスコード", ssh_handshake_failure: "SSH ハンドシェイク失敗", ssh_timeout: "SSH タイムアウト", ssh_banner_malformed: "SSH バナー不正形式", ssh_non_ssh_response: "SSH 以外の応答", rdp_negotiation_failure: "RDP ネゴシエーション失敗", rdp_timeout: "RDP タイムアウト", rdp_negotiation_malformed: "RDP ネゴシーション不正形式", rdp_negotiation_rejected: "RDP ネゴシエーション拒否", icmp_failure: "ICMP 失敗", path_observation_failure: "経路観測失敗", path_cancellation: "経路キャンセル" },
        protocol: { icmp: "ICMP", tcp: "TCP", udp: "UDP", unknown: "不明なプロトコル" },
        resolutionState: { configured_candidate: "設定済み候補", policy_candidate: "ポリシー候補", effective: "実効" },
        resolutionMechanism: { dns: "システム DNS クライアント", hosts_file: "hosts ファイル候補", literal_ip: "リテラル IP", unknown: "不明" },
        browserOutcome: { connected: "接続済み", failed: "失敗", dns_failed: "DNS 失敗", proxy_rejected: "プロキシ拒否", mixed: "混在", unknown: "不明" },
      },
      source: {
        graphVantage: "ローカル診断ソース。このグラフは観測順序を保持します。", graphResponderOne: "この TTL に 1 件の応答者観測を保持しています。", graphResponderMany: "この TTL に {{count}} 件の応答者観測を保持しています。統合していません。", graphDestination: "接続先の到達性とポート状態は中間応答者とは別に表示します。", graphUnknown: "正規の観測では TTL {{range}} の応答者を特定できません。", graphDestinationNotConfirmed: "このレーンでは接続先の確認を観測できませんでした。", graphDestinationConfirmed: "接続先を確認しました。中間の可視性は不完全な場合があります。", graphDestinationTCP: "接続先を確認し、TCP 接続を確立しました。", graphResponder: "TTL {{ttl}} で応答者を観測しました。識別情報はこの観測に限定されます。", graphDestinationResponder: "TTL {{ttl}} で接続先の応答者を観測しました。", graphUnobservable: "TTL {{range}} では応答者を観測できませんでした。これはパケット損失を示しません。", edgeObserved: "このエッジは正規の観測順序を記録するもので、物理トポロジーではありません。", edgeUnobservable: "順序が応答者のない TTL 範囲を越えています。これはパケット損失や架空のデバイスを示しません。", edgeInferred: "このエッジは観測間の TTL の範囲内の進行を記録するもので、正確な物理リンクではありません。", edgeDestination: "接続先の確認は、到達性とポート状態を別に観測したものです。", limitationGraph: "グラフノードは物理デバイスではなく観測された TTL 応答者を識別し、エッジは限定された観測順序を保持します。", limitationICMP: "この ICMP 経路レーンは接続先ポートのコンテキストを持ちますが、接続先ポートの接続性は証明しません。", limitationNotPortAware: "この経路レーンはポートに対応せず、接続先ポートの接続性を証明しません。", limitationUnobservable: "観測不能な TTL は、限定されたコンテキストが終了するまで応答者を受信しなかったことを示します。パケット損失ではありません。", limitationDestination: "接続先の確認は中間 TTL の可視性とは独立しています。", limitationUnsupported: "このプロトコルレーンは未サポートです。機能不足から到達性を結論づけません。", limitationError: "経路アダプターがエラーを報告しました。部分的な TTL 証拠は観測された範囲に限定されます。" },
    }),
  });

  // Keep additions for both locales in the same resource module. The small
  // deep merge lets a locale grow without duplicating the complete English
  // tree, while English remains the deterministic fallback for an omitted
  // translation.
  const EN_EXTRA = Object.freeze({
    page: { title: "tadori · diagnostic workbench", summary: "Diagnostic summary" },
    diagnosis: { findingState: "The report contains canonical findings." },
    target: { transport: "Transport", resource: "Resource", tcp: "TCP", udp: "UDP", udpTCP: "UDP + TCP", diagnoseArrow: "Diagnose →" },
    browser: { seconds: "s", loadError: "could not load browser capture state", requestError: "browser capture request failed", stopError: "could not stop browser capture", loadFQDNError: "could not load observed FQDNs", clipboardUnavailable: "clipboard access is unavailable; use Export FQDNs", copyError: "could not copy observed FQDNs" },
    session: { requestFailedWithStatus: "request failed ({{status}})" },
    probe: { duration: "duration", layer: "layer", faultDomain: "fault domain", reason: "Reason", lanes: "{{count}} lane{{plural}}", none: "No probe results were returned." },
    finding: { label: "Finding", review: "Review", reason: "reason", layer: "layer", faultDomain: "fault domain", probeLanes: "Probe lanes", none: "No canonical findings. This does not mean every protocol is observable." },
    comparison: { icmpDestination: "ICMP destination", tcpDestination: "TCP destination", replied: "replied", connected: "connected", reachedNotConnected: "reached, not connected", notConfirmed: "not confirmed", protocol: "Protocol", observation: "Observation", portAware: "Port aware", destinationReached: "Destination reached", tcpConnected: "TCP connected", ttlResponders: "TTL responders", evidence: "Evidence", none: "No comparable protocol or port observations are available." },
    endpoint: { noObservation: "No normalized endpoint observation is available.", address: "Address", family: "Family", order: "Order" },
    policy: { noObservation: "No canonical proxy or policy observation is available.", failure: "Failure", notEstablished: "not established", received: "received" },
    common: { milliseconds: "ms", noObservation: "No canonical observation is available.", notAttempted: "not attempted", copy: "copy", copied: "copied", unavailable: "unavailable", failed: "failed", copyValue: "Copy {{label}}: {{value}}" },
    evidence: { copyID: "Copy evidence ID", focus: "Focus evidence: {{id}}" },
    application: { connected: "Connected", connectionOutcome: "Connection outcome", requestedEndpoint: "Requested endpoint", probeEndpoint: "Probe endpoint", testedEndpoint: "Tested endpoint", localEndpoint: "Local endpoint", remoteEndpoint: "Remote endpoint", certificateValidation: "Certificate validation", peerCertificates: "Peer certificates", chain: "Chain", certificateSubject: "Certificate subject", certificateIssuer: "Certificate issuer", certificateValidity: "Certificate validity", certificateSerial: "Certificate serial", certificateSHA256: "Certificate SHA-256", tlsVersion: "TLS version", cipherSuite: "Cipher suite", negotiatedProtocol: "Negotiated protocol", serverName: "Server name", response: "Response", from: "From", location: "Location", to: "To", noneObserved: "none observed", notExposed: "not exposed", notNegotiated: "not negotiated", provenance: "Provenance", evidence: "Evidence" },
    path: { legend: "Path legend", destinationConfirmation: "Destination confirmation", destinationResponder: "Destination responder", intermediateResponder: "Intermediate responder", noTTLOsservations: "No TTL observations were retained for this protocol.", noteUnsupported: "This protocol is unsupported here; no conclusion is drawn from the missing capability.", noteError: "The path adapter failed. This is different from a TTL that produced no response.", noteICMP: "ICMP observation; it is not a destination-port connectivity test.", noteNotPortAware: "This path observation is not port-aware; it is not a destination-port connectivity test.", notePortAware: "Port-aware TCP observation for {{port}}.", observationsCount: "{{count}} observations", portUnspecified: "port unspecified", portWord: "port", unknownTTLRange: "Unknown TTL range", unobservableTTLRange: "Unobservable TTL range", edgeObserved: "Observed order", edgeUnobservable: "Unobservable visibility", edgeInferred: "Bounded inferred progression", edgeDestination: "Destination confirmation" },
    source: { hopObserved: "A responder was observed at this TTL.", hopUnobservable: "No responder was observed at this TTL; this is not packet loss.", segmentObserved: "Direct responder evidence for this TTL.", segmentInferred: "Bounded inference between observations; not an exact physical link.", segmentUnobservable: "No responder was observed in this TTL range; this is not packet loss." },
    enum: { destinationState: { reachable: "Reachable", unreachable: "Unreachable", degraded: "Degraded", indeterminate: "Indeterminate" }, certificateValidation: { unknown: "Unknown", valid: "Valid", invalid: "Invalid", expired: "Expired", hostname_mismatch: "Hostname mismatch", untrusted: "Untrusted", incomplete: "Incomplete" }, layer: { unknown: "Unknown", interface: "Interface", ip_configuration: "IP configuration", route: "Route", gateway: "Gateway", dns: "DNS", network: "Network", proxy: "Proxy", tcp: "TCP", tls: "TLS", http: "HTTP", ssh: "SSH", rdp: "RDP", icmp: "ICMP", destination: "Destination" }, faultDomain: { unknown: "Unknown", local: "Local", routing: "Routing", gateway: "Gateway", dns: "DNS", network: "Network", firewall: "Firewall", proxy: "Proxy", transport: "Transport", tls: "TLS", http: "HTTP", ssh: "SSH", rdp: "RDP", destination: "Destination", icmp: "ICMP", policy: "Policy" }, neighbor: { not_applicable: "Not applicable", observed: "Observed", not_observed: "Not observed", unsupported: "Unsupported", error: "Error", unknown: "Unknown" }, role: { probe_vantage: "Probe vantage", intermediate_responder: "Intermediate responder", destination_responder: "Destination responder", unobservable_range: "Unobservable range", unknown_range: "Unknown range", destination_confirmation: "Destination confirmation" }, transportProtocol: { tcp: "TCP", udp: "UDP", "udp+tcp": "UDP + TCP" }, evidenceKind: { unknown: "Unknown", interface_state: "Interface state", ip_configuration: "IP configuration", route: "Route", gateway_reachability: "Gateway reachability", dns_configuration: "DNS configuration", dns_resolution: "DNS resolution", dns_service: "DNS service", tcp_connection: "TCP connection", tls_handshake: "TLS handshake", certificate: "Certificate", http_response: "HTTP response", ssh_handshake: "SSH handshake", rdp_negotiation: "RDP negotiation", path_observation: "Path observation", proxy_configuration: "Proxy configuration", winhttp_proxy: "WinHTTP proxy", wininet_proxy: "WinINET proxy", pac: "PAC", proxy_connectivity: "Proxy connectivity", tls_trust: "TLS trust", firewall_profile: "Firewall profile", adapter_routing: "Adapter routing", route_comparison: "Route comparison", icmp: "ICMP", packet_flow: "Packet flow" } },
  });

  const JA_EXTRA = Object.freeze({
    page: { title: "tadori · 診断ワークベンチ", summary: "診断概要" },
    meta: { description: "ローカルで証拠を重視したネットワーク診断" },
    diagnosis: { findingState: "レポートに正規の所見があります" },
    target: { transport: "トランスポート", resource: "リソース", tcp: "TCP", udp: "UDP", udpTCP: "UDP + TCP", diagnoseArrow: "診断 →" },
    browser: { seconds: "秒", loadError: "ブラウザキャプチャの状態を読み込めませんでした", requestError: "ブラウザキャプチャのリクエストに失敗しました", stopError: "ブラウザキャプチャを停止できませんでした", loadFQDNError: "観測された FQDN を読み込めませんでした", clipboardUnavailable: "クリップボードを利用できません。FQDN を出力してください", copyError: "観測された FQDN をコピーできませんでした" },
    session: { requestFailedWithStatus: "リクエストに失敗しました ({{status}})" },
    probe: { duration: "所要時間", layer: "レイヤー", faultDomain: "障害ドメイン", reason: "理由", lanes: "{{count}} レーン", none: "プローブ結果は返されませんでした。" },
    finding: { label: "所見", review: "確認", reason: "理由", layer: "レイヤー", faultDomain: "障害ドメイン", probeLanes: "プローブレーン", none: "正規の所見はありません。すべてのプロトコルが観測可能とは限りません。" },
    comparison: { icmpDestination: "ICMP 接続先", tcpDestination: "TCP 接続先", replied: "応答あり", connected: "接続済み", reachedNotConnected: "到達したが未接続", notConfirmed: "未確認", protocol: "プロトコル", observation: "観測", portAware: "ポート対応", destinationReached: "接続先に到達", tcpConnected: "TCP 接続済み", ttlResponders: "TTL 応答者", evidence: "証拠", none: "比較可能なプロトコルまたはポート観測はありません。" },
    endpoint: { noObservation: "正規化されたエンドポイント観測はありません。", address: "アドレス", family: "ファミリー", order: "順序" },
    policy: { noObservation: "正規のプロキシまたはポリシー観測はありません。", failure: "失敗", notEstablished: "確立されていません", received: "受信" },
    common: { milliseconds: "ミリ秒", noObservation: "正規の観測はありません。", notAttempted: "未試行", copy: "コピー", copied: "コピー済み", unavailable: "利用不可", failed: "失敗", copyValue: "{{label}}をコピー: {{value}}" },
    evidence: { copyID: "証拠 ID をコピー", focus: "証拠にフォーカス: {{id}}" },
    application: { connected: "接続済み", connectionOutcome: "接続結果", requestedEndpoint: "要求エンドポイント", probeEndpoint: "プローブエンドポイント", testedEndpoint: "試験エンドポイント", localEndpoint: "ローカルエンドポイント", remoteEndpoint: "リモートエンドポイント", certificateValidation: "証明書検証", peerCertificates: "ピア証明書", chain: "チェーン", certificateSubject: "証明書のサブジェクト", certificateIssuer: "証明書の発行者", certificateValidity: "証明書の有効期間", certificateSerial: "証明書シリアル", certificateSHA256: "証明書 SHA-256", tlsVersion: "TLS バージョン", cipherSuite: "暗号スイート", negotiatedProtocol: "ネゴシエートされたプロトコル", serverName: "サーバー名", response: "応答", from: "元", location: "場所", to: "先", noneObserved: "観測なし", notExposed: "公開されていません", notNegotiated: "ネゴシエートされていません", provenance: "プロヴェナンス", evidence: "証拠" },
    path: { legend: "経路の凡例", destinationConfirmation: "接続先の確認", destinationResponder: "接続先の応答者", intermediateResponder: "中間応答者", noTTLOsservations: "このプロトコルには TTL 観測が保持されていません。", noteUnsupported: "このプロトコルはここでは未サポートです。不足している機能から結論を導きません。", noteError: "経路アダプターが失敗しました。TTL に応答がない場合とは異なります。", noteICMP: "ICMP 観測です。接続先ポートの接続性テストではありません。", noteNotPortAware: "この経路観測はポートに対応せず、接続先ポートの接続性を示しません。", notePortAware: "{{port}} の TCP ポート対応観測です。", observationsCount: "{{count}} 件の観測", portUnspecified: "ポート未指定", portWord: "ポート", unknownTTLRange: "不明な TTL 範囲", unobservableTTLRange: "観測不能な TTL 範囲", edgeObserved: "観測順序", edgeUnobservable: "観測不能な可視性", edgeInferred: "範囲内で推定された進行", edgeDestination: "接続先の確認" },
    source: { hopObserved: "この TTL で応答者を観測しました。", hopUnobservable: "この TTL では応答者を観測できませんでした。パケット損失を示しません。", segmentObserved: "この TTL の直接的な応答者証拠です。", segmentInferred: "観測間の限定的な推定であり、正確な物理リンクではありません。", segmentUnobservable: "この TTL 範囲では応答者を観測できませんでした。パケット損失を示しません。" },
    enum: { destinationState: { reachable: "到達可能", unreachable: "到達不能", degraded: "一部利用可能", indeterminate: "判定不能" }, certificateValidation: { unknown: "不明", valid: "有効", invalid: "無効", expired: "期限切れ", hostname_mismatch: "ホスト名不一致", untrusted: "信頼されていない", incomplete: "不完全" }, layer: { unknown: "不明", interface: "インターフェース", ip_configuration: "IP 設定", route: "経路", gateway: "ゲートウェイ", dns: "DNS", network: "ネットワーク", proxy: "プロキシ", tcp: "TCP", tls: "TLS", http: "HTTP", ssh: "SSH", rdp: "RDP", icmp: "ICMP", destination: "接続先" }, faultDomain: { unknown: "不明", local: "ローカル", routing: "ルーティング", gateway: "ゲートウェイ", dns: "DNS", network: "ネットワーク", firewall: "ファイアウォール", proxy: "プロキシ", transport: "トランスポート", tls: "TLS", http: "HTTP", ssh: "SSH", rdp: "RDP", destination: "接続先", icmp: "ICMP", policy: "ポリシー" }, neighbor: { not_applicable: "該当なし", observed: "観測済み", not_observed: "未観測", unsupported: "未サポート", error: "エラー", unknown: "不明" }, role: { probe_vantage: "プローブ地点", intermediate_responder: "中間応答者", destination_responder: "接続先の応答者", unobservable_range: "観測不能範囲", unknown_range: "不明な範囲", destination_confirmation: "接続先の確認" }, transportProtocol: { tcp: "TCP", udp: "UDP", "udp+tcp": "UDP + TCP" }, evidenceKind: { unknown: "不明", interface_state: "インターフェース状態", ip_configuration: "IP 設定", route: "経路", gateway_reachability: "ゲートウェイ到達性", dns_configuration: "DNS 設定", dns_resolution: "DNS 名前解決", dns_service: "DNS サービス", tcp_connection: "TCP 接続", tls_handshake: "TLS ハンドシェイク", certificate: "証明書", http_response: "HTTP 応答", ssh_handshake: "SSH ハンドシェイク", rdp_negotiation: "RDP ネゴシエーション", path_observation: "経路観測", proxy_configuration: "プロキシ設定", winhttp_proxy: "WinHTTP プロキシ", wininet_proxy: "WinINET プロキシ", pac: "PAC", proxy_connectivity: "プロキシ接続性", tls_trust: "TLS 信頼", firewall_profile: "ファイアウォールプロファイル", adapter_routing: "アダプター経路", route_comparison: "経路比較", icmp: "ICMP", packet_flow: "パケットフロー" } },
  });

  function mergeTables(base, extra) {
    const result = { ...(base || {}) };
    for (const [key, value] of Object.entries(extra || {})) {
      result[key] = value && typeof value === "object" && !Array.isArray(value)
        ? mergeTables(result[key], value)
        : value;
    }
    return result;
  }

  const RESOURCES = Object.freeze({
    en: mergeTables(MESSAGES.en, EN_EXTRA),
    ja: mergeTables(MESSAGES.ja, JA_EXTRA),
  });

  const SOURCE_ALIASES = Object.freeze({
    "Reachability could not be established from the available evidence.": "destination.detail.unknown",
    "Name resolution did not establish a usable endpoint.": "destination.detail.resolutionFailed",
    "The requested application protocol is unsupported.": "destination.detail.unsupported",
    "The requested application service was not attempted.": "destination.detail.notAttempted",
    "The requested application service did not complete successfully.": "destination.detail.appFailed",
    "SMB negotiation succeeded.": "destination.detail.smbSuccess",
    "SMB transport evidence is insufficient.": "destination.detail.smbInsufficient",
    "SMB protocol negotiation was rejected or failed.": "destination.detail.smbFailed",
    "HTTP service responded successfully.": "destination.detail.httpSuccess",
    "HTTP request failed after transport connection.": "destination.detail.httpAfterTransport",
    "TLS handshake succeeded.": "destination.detail.tlsSuccess",
    "TLS handshake failed after transport connection.": "destination.detail.tlsFailed",
    "Transport connection established.": "destination.detail.transportSuccess",
    "TCP destination connection established.": "destination.detail.tcpSuccess",
    "TCP destination responded without establishing a connection.": "destination.detail.tcpRefused",
    "TCP destination reset the connection.": "destination.detail.tcpReset",
    "The network reported the destination as unreachable.": "destination.detail.networkUnreachable",
    "TCP connection timed out.": "destination.detail.tcpTimeout",
    "TCP connection was refused.": "destination.detail.connectionRefused",
    "TCP connection was reset.": "destination.detail.connectionReset",
    "Transport connection failed.": "destination.detail.transportFailed",
    "Graph nodes identify observed TTL responders, not physical devices; edges preserve bounded observation order.": "source.limitationGraph",
    "This ICMP path lane carries endpoint port context but does not prove destination-port connectivity.": "source.limitationICMP",
    "This path lane is not port-aware and does not prove destination-port connectivity.": "source.limitationNotPortAware",
    "Unobservable TTLs mean no responder was received before the bounded context ended; they are not packet loss.": "source.limitationUnobservable",
    "Destination confirmation is independent of visibility at intermediate TTLs.": "source.limitationDestination",
    "This protocol lane is unsupported; no reachability conclusion is drawn from the missing capability.": "source.limitationUnsupported",
    "The path adapter reported an error; partial TTL evidence remains scoped to what was observed.": "source.limitationError",
    "The edge records canonical observation order, not physical topology.": "source.edgeObserved",
    "The sequence crosses a TTL range without a responder; this is not packet loss or an invented device.": "source.edgeUnobservable",
    "The edge records bounded TTL progression between observations, not an exact physical link.": "source.edgeInferred",
    "Destination confirmation is a separate reachability and port-state observation.": "source.edgeDestination",
    "Local diagnostic source; this graph preserves observation order.": "source.graphVantage",
    "One responder observation retained at this TTL.": "source.graphResponderOne",
    "Destination reachability and port state are shown separately from intermediate responders.": "source.graphDestination",
  });

  function own(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
  }

  function normalizeLocale(value) {
    const candidate = String(value === undefined || value === null ? "" : value).trim().toLowerCase();
    return candidate === "ja" || candidate.startsWith("ja-") ? "ja" : DEFAULT_LOCALE;
  }

  function lookup(source, key) {
    return String(key).split(".").reduce((value, part) => {
      if (value && typeof value === "object" && own(value, part)) {
        return value[part];
      }
      return undefined;
    }, source);
  }

  function interpolate(value, variables) {
    const values = variables || {};
    return String(value).replace(/\{\{\s*([\w-]+)\s*\}\}/g, (match, name) => {
      return own(values, name) ? String(values[name]) : match;
    });
  }

  function createTranslator(requestedLocale) {
    const selectedLocale = normalizeLocale(requestedLocale);
    const selected = RESOURCES[selectedLocale] || RESOURCES[DEFAULT_LOCALE];
    const fallback = RESOURCES[DEFAULT_LOCALE];
    const translate = function (key, variables) {
      const selectedValue = lookup(selected, key);
      const value = selectedValue === undefined ? lookup(fallback, key) : selectedValue;
      return interpolate(value === undefined ? key : value, variables);
    };
    translate.has = function (key) {
      return lookup(selected, key) !== undefined || lookup(fallback, key) !== undefined;
    };
    translate.locale = selectedLocale;
    return translate;
  }

  function translateSource(value, requestedLocale, variables) {
    const raw = value === undefined || value === null ? "" : String(value);
    let key = SOURCE_ALIASES[raw];
    let values = { ...(variables || {}) };
    if (!key) {
      let match = /^Responder observed at TTL (\d+); identity is scoped to this observation\.$/.exec(raw);
      if (match) {
        key = "source.graphResponder";
        values.ttl = match[1];
      }
      match = /^Destination responder observed at TTL (\d+)\.$/.exec(raw);
      if (match) {
        key = "source.graphDestinationResponder";
        values.ttl = match[1];
      }
      match = /^No responder was observed for TTL (.+); this is not packet loss\.$/.exec(raw);
      if (match) {
        key = "source.graphUnobservable";
        values.range = match[1];
      }
      match = /^The canonical observation does not identify a responder for TTL (.+)\.$/.exec(raw);
      if (match) {
        key = "source.graphUnknown";
        values.range = match[1];
      }
      match = /^(\d+) responder observations retained at this TTL; none are collapsed\.$/.exec(raw);
      if (match) {
        key = "source.graphResponderMany";
        values.count = match[1];
      }
      match = /^(SSH|RDP) handshake succeeded\.$/.exec(raw);
      if (match) {
        key = "destination.detail.sshSuccess";
        values.protocol = match[1];
      }
      match = /^(SSH|RDP) protocol handshake was rejected or malformed\.$/.exec(raw);
      if (match) {
        key = "destination.detail.sshFailed";
        values.protocol = match[1];
      }
      if (raw === "A responder was observed at this TTL.") {
        key = "source.hopObserved";
      } else if (raw === "No responder was observed at this TTL; this is not packet loss.") {
        key = "source.hopUnobservable";
      } else if (raw === "Direct responder evidence for this TTL.") {
        key = "source.segmentObserved";
      } else if (raw === "Bounded inference between observations; not an exact physical link.") {
        key = "source.segmentInferred";
      } else if (raw === "No responder was observed in this TTL range; this is not packet loss.") {
        key = "source.segmentUnobservable";
      }
    }
    if (!key) {
      return raw;
    }
    return createTranslator(requestedLocale)(key, values);
  }

  return Object.freeze({
    DEFAULT_LOCALE,
    SUPPORTED_LOCALES,
    MESSAGES,
    createTranslator,
    interpolate,
    normalizeLocale,
    translateSource,
  });
});
