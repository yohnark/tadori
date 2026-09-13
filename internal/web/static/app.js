(() => {
  "use strict";

  const form = document.querySelector("#diagnose-form");
  const targetInput = document.querySelector("#target");
  const serviceInput = document.querySelector("#service");
  const portInput = document.querySelector("#port");
  const button = form.querySelector("button[type=submit]");
  const cancelButton = document.querySelector("#cancel-button");
  const error = document.querySelector("#error");
  const reportSection = document.querySelector("#report");
  const runStateLabel = document.querySelector("#run-state-label");
  const runStateBadge = document.querySelector("#run-state-badge");
  const progressList = document.querySelector("#progress-list");
  const diagnosisCard = document.querySelector("#diagnosis-card");
  const diagnosisLabel = document.querySelector("#diagnosis-label");
  const diagnosisDetail = document.querySelector("#diagnosis-detail");
  const destinationCard = document.querySelector("#destination-card");
  const destinationLabel = document.querySelector("#destination-label");
  const destinationDetail = document.querySelector("#destination-detail");
  const destinationReferences = document.querySelector("#destination-references");
  const overallStatus = document.querySelector("#overall-status");
  const reportTarget = document.querySelector("#report-target");
  const endpointObservation = document.querySelector("#endpoint-observation");
  const endpointCandidates = document.querySelector("#endpoint-candidates");
  const transportObservation = document.querySelector("#transport-observation");
  const securityObservation = document.querySelector("#security-observation");
  const applicationObservation = document.querySelector("#application-observation");
  const policyObservation = document.querySelector("#policy-observation");
  const nameResolution = document.querySelector("#name-resolution");
  const nameResolutionEmpty = document.querySelector("#name-resolution-empty");
  const networkContextPanel = document.querySelector("#network-context-panel");
  const networkContext = document.querySelector("#network-context");
  const probeCount = document.querySelector("#probe-count");
  const probes = document.querySelector("#probes");
  const findings = document.querySelector("#findings");
  const paths = document.querySelector("#paths");
  const pathEmpty = document.querySelector("#path-empty");
  const pathGraphView = document.querySelector("#path-graph-view");
  const pathTableView = document.querySelector("#path-table-view");
  const pathGraphViewport = document.querySelector("#path-graph-viewport");
  const pathGraphLoading = document.querySelector("#path-graph-loading");
  const pathGraphEmpty = document.querySelector("#path-graph-empty");
  const pathGraphUnsupported = document.querySelector("#path-graph-unsupported");
  const pathGraphReserved = document.querySelector("#path-graph-reserved");
  const pathGraphDescription = document.querySelector("#path-graph-description");
  const pathGraphCount = document.querySelector("#path-graph-count");
  const pathViewStatus = document.querySelector("#path-view-status");
  const pathViewTabs = document.querySelectorAll(".path-view-tab");
  const pathViewControls = document.querySelectorAll("[data-path-view]");
  const comparisons = document.querySelector("#comparisons");
  const evidence = document.querySelector("#evidence");
  const evidenceHeading = document.querySelector("#evidence-heading");
  const canonicalJSON = document.querySelector("#canonical-json");
  const composer = globalThis.TadoriTargetComposer;

  let currentView = null;
  let activeSessionID = "";
  let eventSource = null;
  let activePathView = "graph";
  const progressItems = new Map();
  let composerState = composer.createState({ service: serviceInput.value });

  function renderComposerState() {
    serviceInput.value = composerState.service.value || "";
    portInput.value = composerState.port.value === null ? "" : String(composerState.port.value);
  }

  function transitionComposer(event) {
    composerState = composer.transition(composerState, event);
    renderComposerState();
  }

  serviceInput.addEventListener("change", () => {
    transitionComposer({ type: composer.EVENT.SERVICE_CHANGED, value: serviceInput.value });
  });
  portInput.addEventListener("input", () => {
    transitionComposer({ type: composer.EVENT.PORT_CHANGED, value: portInput.value });
  });
  targetInput.addEventListener("input", () => {
    transitionComposer({ type: composer.EVENT.TARGET_CHANGED, value: targetInput.value });
  });

  for (const control of pathViewControls) {
    control.addEventListener("click", () => selectPathView(control.dataset.pathView));
  }
  renderComposerState();
  setPathGraphState("loading");
  const narrowScreen = typeof globalThis.matchMedia === "function" && globalThis.matchMedia("(max-width: 720px)").matches;
  selectPathView(narrowScreen ? "table" : "graph");

  function text(value) {
    return value === undefined || value === null ? "" : String(value);
  }

  function jsonText(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch (_) {
      return text(value);
    }
  }

  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (value !== undefined) {
      node.textContent = text(value);
    }
    return node;
  }

  function toneClass(base, tone) {
    const allowed = ["positive", "negative", "warning", "neutral"];
    return `${base} ${allowed.includes(tone) ? tone : "neutral"}`;
  }

  function selectPathView(viewName) {
    const selectedView = viewName === "table" ? "table" : "graph";
    activePathView = selectedView;
    for (const tab of pathViewTabs) {
      const selected = tab.dataset.pathView === selectedView;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
    }
    pathGraphView.hidden = selectedView !== "graph";
    pathTableView.hidden = selectedView !== "table";
    pathViewStatus.textContent = selectedView === "graph" ? "Graph layout shell" : "Canonical table";
  }

  function setPathGraphState(state) {
    const states = [pathGraphLoading, pathGraphEmpty, pathGraphUnsupported];
    for (const stateElement of states) {
      stateElement.hidden = stateElement.id !== `path-graph-${state}`;
    }
    pathGraphReserved.hidden = state !== "reserved";
    pathGraphViewport.dataset.state = state;
  }

  function renderPathGraph(view) {
    if (!view) {
      pathGraphCount.textContent = "Awaiting report";
      pathGraphDescription.textContent = "A horizontal layout is reserved for canonical path data.";
      setPathGraphState("loading");
      return;
    }

    const pathViews = Array.isArray(view.paths) ? view.paths : [];
    const pathCount = pathViews.length;
    pathGraphCount.textContent = `${pathCount} observed path${pathCount === 1 ? "" : "s"}`;
    if (!pathCount) {
      pathGraphDescription.textContent = "No responder/path visibility was retained for this report.";
      setPathGraphState("empty");
      return;
    }

    const onlyUnsupported = pathViews.every((path) => path && path.observation_status === "unsupported");
    if (onlyUnsupported) {
      pathGraphDescription.textContent = "The report retained the supported Table projection for this path lane.";
      setPathGraphState("unsupported");
      return;
    }

    pathGraphDescription.textContent = "Canonical graph data will populate ordered responders and unobservable ranges here.";
    setPathGraphState("reserved");
  }

  function badge(label, tone) {
    return element("span", toneClass("badge", tone), label);
  }

  function referenceButton(id, label) {
    const button = element("button", "evidence-link", label || id);
    button.type = "button";
    button.dataset.evidenceId = text(id);
    button.addEventListener("click", () => focusEvidence(id));
    return button;
  }

  function referenceGroup(ids) {
    const group = element("span", "reference-group");
    for (const id of ids || []) {
      group.appendChild(referenceButton(id));
    }
    return group;
  }

  function setProgress(events, label, badgeLabel, tone) {
    runStateLabel.textContent = label;
    runStateBadge.textContent = badgeLabel;
    runStateBadge.className = toneClass("badge", tone);
    progressList.replaceChildren();
    progressItems.clear();
    for (const event of events || []) {
      renderProgressEvent(event);
    }
  }

  function renderProgressEvent(event) {
    const name = text(event.probe_name);
    const key = name || "__lifecycle";
    let item = progressItems.get(key);
    if (!item) {
      item = element("li", "progress-item neutral");
      progressItems.set(key, item);
      progressList.appendChild(item);
    }
    const itemTone = event.state === "error" ? "negative" : event.state === "complete" ? "positive" : "neutral";
    item.className = toneClass("progress-item", itemTone);
    item.replaceChildren();
    item.appendChild(element("span", "progress-marker"));
    const eventLabel = name ? `${name} · ${progressState(event.state)}` : progressState(event.state);
    item.appendChild(element("span", "progress-label", eventLabel));
    if (event.status) {
      item.appendChild(badge(event.status, itemTone));
    }
  }

  function progressState(state) {
    switch (state) {
      case "started":
        return "Diagnostic started";
      case "running":
        return "Collecting observations";
      case "complete":
        return "Report available";
      case "error":
        return "Run error";
      default:
        return "Waiting for observation";
    }
  }

  function clearError() {
    error.textContent = "";
    error.hidden = true;
  }

  function showError(message) {
    error.textContent = text(message);
    error.hidden = false;
  }

  function setSessionState(state) {
    const label = state === "running" ? "Collecting diagnostic observations" :
      state === "cancelling" ? "Cancelling diagnostic run" :
        state === "completed" ? "Diagnostic report ready" :
          state === "cancelled" ? "Diagnostic run cancelled" : text(state);
    const tone = state === "completed" ? "positive" : state === "cancelled" ? "warning" : state === "failed" ? "negative" : "neutral";
    runStateLabel.textContent = label;
    runStateBadge.textContent = text(state);
    runStateBadge.className = toneClass("badge", tone);
    cancelButton.hidden = state !== "running" && state !== "cancelling";
    cancelButton.disabled = state === "cancelling";
  }

  function closeEvents() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  }

  async function readResponse(response) {
    let body = {};
    try {
      body = await response.json();
    } catch (_) {
      body = {};
    }
    if (!response.ok) {
      throw new Error(body.error || `request failed (${response.status})`);
    }
    return body;
  }

  async function loadSessionView(id) {
    const response = await fetch(`/api/diagnoses/${encodeURIComponent(id)}/view`, { cache: "no-store" });
    const view = await readResponse(response);
    if (!view.report || !view.canonical_json) {
      throw new Error("diagnostic session ended without a canonical report");
    }
    renderView(view);
  }

  async function finishSession(state) {
    closeEvents();
    setSessionState(state);
    try {
      if (activeSessionID) {
        await loadSessionView(activeSessionID);
      }
    } catch (err) {
      showError(err instanceof Error ? err.message : "could not load diagnostic report");
    }
    button.disabled = false;
    button.textContent = "Diagnose →";
    activeSessionID = "";
  }

  function handleSessionEvent(event) {
    let body;
    try {
      body = JSON.parse(event.data);
    } catch (_) {
      showError("received invalid progress data");
      return;
    }

    switch (body.type) {
      case "diagnosis_started":
        setSessionState("running");
        renderProgressEvent({ state: "running" });
        break;
      case "probe_started":
        renderProgressEvent({ probe_name: body.probe_name, state: "running" });
        break;
      case "probe_completed":
      case "result_updated":
        renderProgressEvent({ probe_name: body.probe_name || body.result?.name, state: "complete", status: body.result?.status });
        break;
      case "finding_updated":
        renderProgressEvent({ state: "running" });
        break;
      case "diagnosis_completed":
        void finishSession("completed");
        break;
      case "diagnosis_cancelled":
        void finishSession("cancelled");
        break;
      default:
        break;
    }
  }

  function openEvents(id) {
    closeEvents();
    eventSource = new EventSource(`/api/diagnoses/${encodeURIComponent(id)}/events`);
    for (const eventType of [
      "diagnosis_started",
      "probe_started",
      "probe_completed",
      "result_updated",
      "finding_updated",
      "diagnosis_completed",
      "diagnosis_cancelled",
    ]) {
      eventSource.addEventListener(eventType, handleSessionEvent);
    }
    eventSource.onerror = () => {
      if (eventSource && eventSource.readyState === EventSource.CLOSED && activeSessionID) {
        showError("progress stream closed before the session completed");
      }
    };
  }

  function renderProbeBody(probe) {
    const body = element("div", "card-body");
    const metadata = element("div", "metadata");
    metadata.appendChild(metadataItem("duration", `${text(probe.duration_ms)} ms`));
    metadata.appendChild(metadataItem("layer", probe.layer));
    metadata.appendChild(metadataItem("fault domain", probe.fault_domain));
    body.appendChild(metadata);

    const interpretation = element("p", "interpretation", `Reason: ${text(probe.failure_reason)}`);
    body.appendChild(interpretation);
    if (probe.evidence_ids && probe.evidence_ids.length) {
      const refs = element("div", "card-references");
      refs.appendChild(element("span", "reference-label", "Evidence"));
      refs.appendChild(referenceGroup(probe.evidence_ids));
      body.appendChild(refs);
    }
    return body;
  }

  function renderProbe(probe, index) {
    const isSkipped = probe.status === "skipped";
    const isQuiet = probe.tone === "positive" || probe.tone === "neutral" || isSkipped;
    const cardClass = isSkipped ? toneClass("probe-card", "neutral") : toneClass("probe-card", probe.tone);
    const badgeTone = isSkipped ? "neutral" : probe.tone;

    if (!isQuiet) {
      const card = element("article", cardClass);
      const header = element("div", "card-heading");
      header.appendChild(element("h3", "card-title", `${index + 1}. ${text(probe.name)}`));
      header.appendChild(badge(probe.status_label || probe.status, badgeTone));
      card.appendChild(header);
      card.appendChild(renderProbeBody(probe));
      probes.appendChild(card);
      return;
    }

    const card = element("details", cardClass);
    const summary = element("summary", "card-heading");
    const title = element("h3", "card-title", `${index + 1}. ${text(probe.name)}`);
    title.title = text(probe.name);
    summary.appendChild(title);
    summary.appendChild(badge(probe.status_label || probe.status, badgeTone));
    card.appendChild(summary);
    card.appendChild(renderProbeBody(probe));
    probes.appendChild(card);
  }

  function metadataItem(label, value) {
    const item = element("span", "metadata-item");
    item.appendChild(element("span", "metadata-label", `${label}:`));
    item.appendChild(element("code", "metadata-value", value));
    return item;
  }

  function renderFinding(finding) {
    const card = element("article", toneClass("finding-card", finding.tone));
    const header = element("div", "card-heading");
    header.appendChild(element("h3", "card-title", finding.label || finding.failure_reason));
    header.appendChild(badge(finding.tone === "warning" ? "Review" : "Finding", finding.tone));
    card.appendChild(header);

    const metadata = element("div", "metadata");
    metadata.appendChild(metadataItem("reason", finding.failure_reason));
    metadata.appendChild(metadataItem("layer", finding.layer));
    metadata.appendChild(metadataItem("fault domain", finding.fault_domain));
    card.appendChild(metadata);
    if (finding.probe_names && finding.probe_names.length) {
      card.appendChild(element("p", "reference-line", `Probe lanes: ${finding.probe_names.join(", ")}`));
    }
    if (finding.evidence_ids && finding.evidence_ids.length) {
      const refs = element("div", "card-references");
      refs.appendChild(element("span", "reference-label", "Drill into evidence"));
      refs.appendChild(referenceGroup(finding.evidence_ids));
      card.appendChild(refs);
    }
    findings.appendChild(card);
  }

  function renderDestination(destination) {
    destinationLabel.textContent = text(destination.label);
    destinationDetail.textContent = text(destination.detail);
    destinationCard.className = toneClass("overview-card panel", destinationTone(destination.state));
    destinationReferences.replaceChildren();
    if (destination.probe_names && destination.probe_names.length) {
      destinationReferences.appendChild(element("span", "reference-label", `From ${destination.probe_names.join(", ")}`));
    }
    if (destination.evidence_ids && destination.evidence_ids.length) {
      destinationReferences.appendChild(referenceGroup(destination.evidence_ids));
    }
  }

  function renderEndpointObservation(endpoint) {
    endpointObservation.replaceChildren();
    endpointCandidates.replaceChildren();
    if (!endpoint || !endpoint.requested_identity) {
      endpointObservation.appendChild(element("div", "empty-state compact", "No normalized endpoint observation is available."));
      return;
    }
    appendObservationRows(endpointObservation, [
      ["Original input", endpoint.original_input],
      ["Requested identity", endpoint.requested_identity],
      ["Literal IP", endpoint.literal_ip],
      ["Service", endpoint.service && (endpoint.service.label || endpoint.service.id)],
      ["Application protocol", endpoint.application_protocol],
      ["Transport protocol", endpoint.transport_protocol],
      ["Port", endpoint.port || "not specified"],
      ["Resource", endpoint.resource],
      ["Selected endpoint", endpointText(endpoint.selected_endpoint)],
      ["Tested endpoint", endpointText(endpoint.tested_endpoint)],
      ["Certainty", endpoint.certainty],
      ["Provenance", listText(endpoint.provenance)],
      ["Evidence", referenceValue(endpoint.evidence_ids)],
    ]);
    renderCandidateTable(endpointCandidates, "Resolved candidates", endpoint.resolved_candidates);
    renderCandidateTable(endpointCandidates, "Probe candidates", endpoint.probe_candidates);
    if (endpoint.candidate_attempts && endpoint.candidate_attempts.length) {
      const title = element("h3", "observation-subheading", "Candidate attempts");
      endpointCandidates.appendChild(title);
      const table = element("table", "observation-grid");
      appendTableHeader(table, ["Candidate", "Status", "Failure", "Evidence"]);
      const body = table.querySelector("tbody");
      for (const attempt of endpoint.candidate_attempts) {
        const row = element("tr");
        row.appendChild(element("td", "", endpointText(attempt.candidate)));
        row.appendChild(element("td", "", attempt.status));
        row.appendChild(element("td", "", attempt.failure_reason || "none"));
        row.appendChild(referenceCell(attempt.evidence_ids));
        body.appendChild(row);
      }
      endpointCandidates.appendChild(table);
    }
  }

  function renderCandidateTable(container, title, candidates) {
    if (!candidates || !candidates.length) {
      return;
    }
    container.appendChild(element("h3", "observation-subheading", title));
    const table = element("table", "observation-grid");
    appendTableHeader(table, ["Address", "Family", "Order", "Certainty", "Provenance", "Evidence"]);
    const body = table.querySelector("tbody");
    for (const candidate of candidates) {
      const row = element("tr");
      row.appendChild(element("td", "", candidate.address));
      row.appendChild(element("td", "", candidate.family));
      row.appendChild(element("td", "", candidate.order));
      row.appendChild(element("td", "", candidate.certainty || "unknown"));
      row.appendChild(element("td", "", candidate.provenance || "not specified"));
      row.appendChild(referenceCell(candidate.evidence_ids));
      body.appendChild(row);
    }
    container.appendChild(table);
  }

  function renderOperationalObservations(observations, applicationView) {
    renderTransportObservation(observations && observations.transport);
    renderSecurityObservation(observations && observations.security);
    renderApplicationObservation(applicationView || (observations && observations.application));
  }

  function renderTransportObservation(observation) {
    renderObservationOrEmpty(transportObservation, observation, [
      ["Applicability", "applicability"],
      ["Requested endpoint", "requested_endpoint"],
      ["Probe endpoint", "probe_endpoint", endpointText],
      ["Tested endpoint", "tested_endpoint", endpointText],
      ["Connection outcome", "connection_outcome"],
      ["Connected", "connected", booleanText],
      ["Local endpoint", "local_endpoint"],
      ["Remote endpoint", "remote_endpoint", endpointText],
      ["Failure reason", "failure_reason"],
      ["Fault domain", "fault_domain"],
      ["Certainty", "certainty"],
      ["Limitations", "limitations", listText],
      ["Evidence", "evidence_ids", referenceValue],
    ]);
  }

  function renderSecurityObservation(observation) {
    renderObservationOrEmpty(securityObservation, observation, [
      ["Applicability", "applicability"],
      ["Attempted", "attempted", booleanText],
      ["Handshake complete", "handshake_complete", booleanText],
      ["TLS version", "tls_version"],
      ["Cipher suite", "cipher_suite"],
      ["Negotiated protocol", "negotiated_protocol"],
      ["Server name", "server_name"],
      ["Endpoint used", "endpoint_used", endpointText],
      ["Certificate validation", "certificate_validation"],
      ["Peer certificates", "peer_certificate_count"],
      ["Failure reason", "failure_reason"],
      ["Fault domain", "fault_domain"],
      ["Certainty", "certainty"],
      ["Limitations", "limitations", listText],
      ["Evidence", "evidence_ids", referenceValue],
    ]);
  }

  function renderApplicationObservation(observation) {
    applicationObservation.replaceChildren();
    if (!observation) {
      applicationObservation.appendChild(element("div", "empty-state compact", "No canonical application observation is available."));
      return;
    }

    const protocol = text(observation.protocol || "unknown").toLowerCase();
    const commonRows = [
      ["Applicability", observation.applicability || "unknown"],
      ["Protocol", protocol],
      ["Request attempted", booleanText(observation.request_attempted)],
      ["Response received", booleanText(observation.response_received)],
      ["Transport connected", booleanText(observation.transport_connected)],
      ["Handshake attempted", booleanText(observation.handshake_attempted)],
      ["Handshake complete", booleanText(observation.handshake_complete)],
      ["Result", observation.result || "unknown"],
      ["Protocol result", observation.protocol_result || "unknown"],
      ["Endpoint used", endpointText(observation.endpoint_used)],
      ["Requested resource", observation.requested_resource || "not specified"],
      ["Failure reason", observation.failure_reason || "none"],
      ["Fault domain", observation.fault_domain || "unknown"],
      ["Certainty", observation.certainty || "unknown"],
      ["Limitations", listText(observation.limitations)],
    ];
    appendObservationRows(applicationObservation, commonRows);

    if (protocol === "http" || protocol === "https" || observation.http) {
      renderHTTPApplication(applicationObservation, observation.http || observation);
    } else if (protocol === "dns" || observation.dns) {
      renderDNSApplication(applicationObservation, observation.dns);
    } else if (protocol === "smb" || observation.smb) {
      renderSMBApplication(applicationObservation, observation.smb);
    } else if (protocol === "ssh" || observation.ssh) {
      renderProtocolApplication(applicationObservation, "SSH handshake", observation.ssh || observation, false);
    } else if (protocol === "rdp" || observation.rdp) {
      renderProtocolApplication(applicationObservation, "RDP negotiation", observation.rdp || observation, true);
    } else {
      applicationObservation.appendChild(element("h3", "observation-subheading", "Service-specific application view"));
      appendObservationRows(applicationObservation, [["State", "unsupported or not attempted"]]);
    }
    renderApplicationReferences(applicationObservation, observation);
  }

  function renderHTTPApplication(container, http) {
    container.appendChild(element("h3", "observation-subheading", "HTTP / HTTPS response"));
    appendObservationRows(container, [
      ["HTTP version", http.http_version || "not observed"],
      ["Status code", http.status_code || "not observed"],
      ["Status", http.status || "not observed"],
      ["URL", http.url || "not observed"],
      ["Resource", http.requested_resource || "not specified"],
    ]);
    const redirects = http.redirects || [];
    container.appendChild(element("h3", "observation-subheading", "Redirects"));
    if (!redirects.length) {
      appendObservationRows(container, [["Redirect chain", "none observed"]]);
      return;
    }
    const table = element("table", "observation-grid");
    appendTableHeader(table, ["Status", "From", "Location", "To"]);
    const body = table.querySelector("tbody");
    for (const redirect of redirects) {
      const row = element("tr");
      row.appendChild(element("td", "", redirect.status_code || "unknown"));
      row.appendChild(element("td", "", redirect.url || "not observed"));
      row.appendChild(element("td", "", redirect.location || "not observed"));
      row.appendChild(element("td", "", redirect.to_url || "not observed"));
      body.appendChild(row);
    }
    container.appendChild(table);
  }

  function renderDNSApplication(container, dns) {
    container.appendChild(element("h3", "observation-subheading", "DNS service response"));
    if (!dns) {
      appendObservationRows(container, [["State", "not attempted"]]);
      return;
    }
    appendObservationRows(container, [
      ["Query", `${dns.query_name || "unknown"} (${dns.query_type || "unknown"})`],
      ["Requested endpoint", dns.requested_endpoint || "not observed"],
      ["Result", dns.result || "unknown"],
      ["Response received", booleanText(dns.response_received)],
      ["Divergence", booleanText(dns.divergence)],
      ["Failure reason", dns.failure_reason || "none"],
      ["Certainty", dns.certainty || "unknown"],
      ["Limitations", listText(dns.limitations)],
    ]);
    const table = element("table", "observation-grid");
    appendTableHeader(table, ["Lane", "Attempted", "Response", "Outcome", "RCODE", "Truncated", "Fallback", "Provenance", "Evidence"]);
    const body = table.querySelector("tbody");
    const lanes = [
      dns.udp || { transport: "udp" },
      dns.tcp || { transport: "tcp" },
    ];
    for (const lane of lanes) {
      const row = element("tr");
      const fallback = lane.fallback ? `yes${lane.fallback_reason ? ` · ${lane.fallback_reason}` : ""}` : "no";
      row.appendChild(element("td", "", text(lane.transport || "unknown").toUpperCase()));
      row.appendChild(element("td", "", booleanText(lane.attempted)));
      row.appendChild(element("td", "", booleanText(lane.response_received)));
      row.appendChild(element("td", "", lane.outcome || "not_attempted"));
      row.appendChild(element("td", "", rcodeText(lane)));
      row.appendChild(element("td", "", booleanText(lane.truncated)));
      row.appendChild(element("td", "", fallback));
      row.appendChild(element("td", "", listText(lane.provenance)));
      row.appendChild(referenceCell(lane.evidence_ids));
      body.appendChild(row);
    }
    container.appendChild(table);
  }

  function rcodeText(lane) {
    if (lane.rcode_name) {
      return lane.rcode === undefined || lane.rcode === null ? lane.rcode_name : `${lane.rcode_name} (${lane.rcode})`;
    }
    return lane.rcode === undefined || lane.rcode === null ? "not observed" : text(lane.rcode);
  }

  function renderSMBApplication(container, smb) {
    container.appendChild(element("h3", "observation-subheading", "SMB negotiation"));
    if (!smb) {
      appendObservationRows(container, [["State", "not attempted"]]);
      return;
    }
    appendObservationRows(container, [
      ["Negotiation result", smb.result || "unknown"],
      ["Negotiated", booleanText(smb.negotiated)],
      ["Dialect", smb.dialect || "not observed"],
      ["Dialect revision", smb.dialect_revision || "not observed"],
      ["Capabilities", listText(smb.capabilities)],
      ["Server GUID", smb.server_guid || "not exposed"],
      ["Security mode", smb.security_mode || "not exposed"],
      ["Max transact size", smb.max_transact_size || "not exposed"],
      ["Max read size", smb.max_read_size || "not exposed"],
      ["Max write size", smb.max_write_size || "not exposed"],
      ["Response bytes", smb.response_bytes || "not observed"],
    ]);
  }

  function renderProtocolApplication(container, heading, protocol, rdp) {
    container.appendChild(element("h3", "observation-subheading", heading));
    appendObservationRows(container, [
      ["Handshake attempted", booleanText(protocol.handshake_attempted)],
      ["Handshake complete", booleanText(protocol.handshake_complete)],
      ["Response received", booleanText(protocol.response_received)],
      ["Transport connected", booleanText(protocol.transport_connected)],
      ["Result", protocol.result || "unknown"],
      ["Server identification", protocol.server_identification || "not observed"],
      ["Negotiated security", rdp ? (protocol.negotiated_security_protocol || "not negotiated") : "not applicable"],
      ["Requested security", rdp ? listText(protocol.requested_security_protocols) : "not applicable"],
    ]);
  }

  function renderApplicationReferences(container, observation) {
    container.appendChild(element("h3", "observation-subheading", "Application provenance"));
    appendObservationRows(container, [
      ["Provenance", listText(observation.provenance)],
      ["Probe lanes", listText(observation.probe_names)],
      ["Evidence", referenceValue(observation.evidence_ids)],
    ]);
  }

  function renderPolicyObservation(observation) {
    policyObservation.replaceChildren();
    if (!observation || (!observation.requested_identity && !observation.state && !(observation.paths || []).length)) {
      policyObservation.appendChild(element("div", "empty-state compact", "No canonical proxy or policy observation is available."));
      return;
    }
    appendObservationRows(policyObservation, [
      ["Requested identity", observation.requested_identity],
      ["State", observation.state],
      ["Unsupported", booleanText(observation.unsupported)],
      ["Proxy configuration diverges", booleanText(observation.proxy_configuration_diverges)],
      ["Divergence known", booleanText(observation.proxy_configuration_divergence_known)],
      ["Direct vs proxy", comparisonText(observation.direct_vs_proxy)],
      ["Firewall", observation.firewall && observation.firewall.state],
      ["TLS policy state", observation.tls && observation.tls.state],
      ["Possible interception", observation.tls && booleanText(observation.tls.possible_interception)],
      ["Interception suspicion", observation.tls && observation.tls.interception_suspicion],
      ["Certainty", observation.certainty],
      ["Provenance", listText(observation.provenance)],
      ["Evidence", referenceValue(observation.evidence_ids)],
    ]);

    renderProxySource(policyObservation, "WinHTTP", observation.winhttp);
    renderProxySource(policyObservation, "WinINET", observation.wininet);
    if (observation.paths && observation.paths.length) {
      policyObservation.appendChild(element("h3", "observation-subheading", "Direct, browser, and service paths"));
      const table = element("table", "observation-grid");
      appendTableHeader(table, ["Path", "Mode", "Endpoint", "TCP", "HTTP", "TLS", "Failure", "Evidence"]);
      const body = table.querySelector("tbody");
      for (const path of observation.paths) {
        const row = element("tr");
        row.appendChild(element("td", "", path.name));
        row.appendChild(element("td", "", path.mode));
        row.appendChild(element("td", "", path.endpoint || "not specified"));
        row.appendChild(element("td", "", booleanText(path.tcp_connected)));
        row.appendChild(element("td", "", path.http_response ? text(path.http_status_code || "received") : "no"));
        row.appendChild(element("td", "", booleanText(path.tls_handshake)));
        row.appendChild(element("td", "", path.failure_reason || "none"));
        row.appendChild(referenceCell(path.evidence_ids));
        body.appendChild(row);
      }
      policyObservation.appendChild(table);
    }
    if (observation.firewall && observation.firewall.profiles && observation.firewall.profiles.length) {
      policyObservation.appendChild(element("h3", "observation-subheading", "Firewall profiles"));
      const table = element("table", "observation-grid");
      appendTableHeader(table, ["Profile", "Enabled", "Policy present", "Causality", "Evidence"]);
      const body = table.querySelector("tbody");
      for (const profile of observation.firewall.profiles) {
        const row = element("tr");
        row.appendChild(element("td", "", profile.name));
        row.appendChild(element("td", "", profile.firewall_enabled === undefined ? "unknown" : booleanText(profile.firewall_enabled)));
        row.appendChild(element("td", "", booleanText(profile.policy_present)));
        row.appendChild(element("td", "", profile.block_causality || "not established"));
        row.appendChild(referenceCell(profile.evidence_ids));
        body.appendChild(row);
      }
      policyObservation.appendChild(table);
    }
  }

  function renderProxySource(container, label, source) {
    if (!source || (!source.source && !source.configuration && !source.effective)) {
      return;
    }
    container.appendChild(element("h3", "observation-subheading", label));
    appendObservationRows(container, [
      ["Source", source.source],
      ["Configuration", source.configuration && source.configuration.state],
      ["Configured proxy endpoints", source.configuration && listText(source.configuration.proxy_endpoints)],
      ["PAC configured", source.configuration && booleanText(source.configuration.pac_configured)],
      ["Effective mode", source.effective && source.effective.mode],
      ["Effective endpoint", source.effective && source.effective.endpoint],
      ["Effective resolution", source.effective && booleanText(source.effective.resolution_ok)],
      ["PAC used", source.effective && booleanText(source.effective.pac_used)],
      ["Evidence", referenceValue(source.evidence_ids)],
    ]);
  }

  function comparisonText(comparison) {
    if (!comparison) {
      return "not observed";
    }
    return comparison.state || "unknown";
  }

  function renderObservationOrEmpty(container, observation, fields) {
    container.replaceChildren();
    if (!observation || !observation.applicability) {
      container.appendChild(element("div", "empty-state compact", "No canonical observation is available."));
      return;
    }
    const rows = [];
    for (const [label, key, formatter] of fields) {
      const value = observation[key];
      if (value === undefined || value === null || value === "") {
        continue;
      }
      rows.push([label, formatter ? formatter(value) : value]);
    }
    appendObservationRows(container, rows);
  }

  function appendObservationRows(container, rows) {
    const table = element("div", "observation-rows");
    for (const [label, value] of rows) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      const row = element("div", "observation-row");
      row.appendChild(element("span", "observation-label", label));
      if (value && typeof value === "object" && value.nodeType) {
        row.appendChild(value);
      } else {
        row.appendChild(element("span", "observation-value", value));
      }
      table.appendChild(row);
    }
    container.appendChild(table);
  }

  function appendTableHeader(table, labels) {
    const head = element("thead");
    const row = element("tr");
    for (const label of labels) {
      row.appendChild(element("th", "", label));
    }
    head.appendChild(row);
    table.appendChild(head);
    table.appendChild(element("tbody"));
  }

  function referenceCell(ids) {
    const cell = element("td", "");
    if (ids && ids.length) {
      cell.appendChild(referenceGroup(ids));
    } else {
      cell.textContent = "not available";
    }
    return cell;
  }

  function referenceValue(ids) {
    if (!ids || !ids.length) {
      return "not available";
    }
    return referenceGroup(ids);
  }

  function endpointText(endpoint) {
    if (!endpoint) {
      return "not observed";
    }
    if (typeof endpoint === "string") {
      return endpoint;
    }
    if (!endpoint.address) {
      return "not observed";
    }
    const address = endpoint.address.includes(":") && endpoint.port ? `[${endpoint.address}]` : endpoint.address;
    return endpoint.port ? `${address}:${endpoint.port}` : address;
  }

  function booleanText(value) {
    return value ? "yes" : "no";
  }

  function redirectText(values) {
    if (!values || !values.length) {
      return "none";
    }
    return values.map((value) => `${value.status_code} ${value.url}${value.to_url ? ` → ${value.to_url}` : ""}`).join("; ");
  }

  function renderNameResolution(resolution) {
    nameResolution.replaceChildren();
    const available = resolution && (resolution.requested_name || (resolution.paths && resolution.paths.length) || resolution.effective_path);
    nameResolutionEmpty.hidden = Boolean(available);
    if (!available) {
      return;
    }

    const effective = resolution.effective_path || {};
    const fields = [
      ["Requested name", resolution.requested_name || "not observable"],
      ["Resolution path", effective.mechanism || "not observed"],
      ["Interface", effective.interface || "not observable"],
      ["Resolver", effective.resolver || "not observable"],
      ["Policy", policyText(effective)],
      ["Answers A", listText(resolution.a)],
      ["Answers AAAA", listText(resolution.aaaa)],
      ["Resolver representative answer (not OS/application selection)", resolution.selected_address || "not selected"],
      ["Certainty", effective.certainty || "not observable"],
    ];
    const table = element("div", "resolution-table");
    for (const [label, value] of fields) {
      const row = element("div", "resolution-row");
      row.appendChild(element("span", "resolution-label", label));
      row.appendChild(element("span", "resolution-value", value));
      table.appendChild(row);
    }
    nameResolution.appendChild(table);

    if (resolution.candidate_names && resolution.candidate_names.length) {
      nameResolution.appendChild(resolutionMetadata("Candidate names", resolution.candidate_names.join(", ")));
    }
    if (resolution.candidate_suffixes && resolution.candidate_suffixes.length) {
      nameResolution.appendChild(resolutionMetadata("Search suffixes", resolution.candidate_suffixes.join(", ")));
    }
    if (resolution.candidate_namespaces && resolution.candidate_namespaces.length) {
      nameResolution.appendChild(resolutionMetadata("Candidate namespaces", resolution.candidate_namespaces.join(", ")));
    }
    if (effective.provenance) {
      nameResolution.appendChild(resolutionMetadata("Provenance", effective.provenance));
    }
    if (resolution.limitations && resolution.limitations.length) {
      nameResolution.appendChild(resolutionMetadata("Limitations", resolution.limitations.join(" · ")));
    }

    const candidates = (resolution.paths || []).filter((path) => path.state !== "effective");
    if (candidates.length) {
      const details = element("details", "resolution-candidates");
      details.open = true;
      details.appendChild(element("summary", "", `Configured candidates · ${candidates.length}`));
      const list = element("div", "resolution-candidate-list");
      for (const path of candidates) {
        const row = element("div", "resolution-candidate");
        row.appendChild(element("span", "resolution-candidate-state", path.state || "unknown"));
        const description = [
          path.resolver || "resolver not observable",
          path.interface || "interface not observable",
          path.namespace || (path.namespaces && path.namespaces.length ? path.namespaces.join(", ") : "no namespace"),
          path.certainty || "certainty unknown",
        ];
        row.appendChild(element("span", "resolution-candidate-detail", description.join(" · ")));
        if (path.evidence_ids && path.evidence_ids.length) {
          row.appendChild(referenceGroup(path.evidence_ids));
        }
        list.appendChild(row);
      }
      details.appendChild(list);
      nameResolution.appendChild(details);
    }
    if (resolution.evidence_ids && resolution.evidence_ids.length) {
      const refs = element("div", "card-references");
      refs.appendChild(element("span", "reference-label", "Evidence"));
      refs.appendChild(referenceGroup(resolution.evidence_ids));
      nameResolution.appendChild(refs);
    }
  }

  function listText(values) {
    return values && values.length ? values.join(", ") : "(none)";
  }

  function policyText(path) {
    const values = [path.namespace, path.policy_source, path.policy_rule].filter(Boolean);
    return values.length ? values.join(" / ") : "not observed";
  }

  function resolutionMetadata(label, value) {
    const row = element("p", "resolution-metadata");
    row.appendChild(element("span", "resolution-label", label));
    row.appendChild(element("span", "resolution-value", value));
    return row;
  }

  function destinationTone(state) {
    switch (state) {
      case "confirmed":
        return "positive";
      case "failed":
        return "negative";
      case "reached_not_connected":
        return "warning";
      default:
        return "neutral";
    }
  }

  function renderResponder(responder) {
    const chip = element("span", "responder-chip");
    const address = element("strong", "responder-address", responder.address);
    chip.appendChild(address);
    const details = [];
    if (responder.rtt_ms) {
      details.push(`${responder.rtt_ms} ms`);
    }
    if (responder.response) {
      details.push(responder.response);
    }
    if (responder.destination_reached) {
      details.push("destination");
    }
    if (details.length) {
      chip.appendChild(element("span", "responder-details", details.join(" · ")));
    }
    return chip;
  }

  function renderPath(path, index) {
    const card = element("article", "path-card");
    const evidenceIDs = path.evidence_ids || (path.evidence_id ? [path.evidence_id] : []);
    card.dataset.evidenceId = text(evidenceIDs[0]);
    const header = element("div", "path-heading");
    const heading = element("div");
    heading.appendChild(element("h3", "card-title", `${index + 1}. ${text(path.protocol).toUpperCase()} observation`));
    heading.appendChild(element("p", "path-endpoint", `${text(path.destination)} · ${portText(path.destination_port)}`));
    header.appendChild(heading);
    header.appendChild(element("span", toneClass("observation-status", path.observation_status), path.observation_status || "unknown"));
    card.appendChild(header);

    const pathNote = element("p", "path-note", observationNote(path));
    card.appendChild(pathNote);

    const destination = element("div", "path-destination");
    destination.appendChild(element("span", "destination-marker", "◆"));
    const destinationCopy = element("div");
    destinationCopy.appendChild(element("strong", "destination-title", "Destination observation"));
    destinationCopy.appendChild(element("span", "destination-copy", `Reached: ${booleanText(path.destination_reached)} · TCP connected: ${booleanText(path.destination_tcp_connected)}`));
    destination.appendChild(destinationCopy);
    if (evidenceIDs.length) {
      destination.appendChild(referenceGroup(evidenceIDs));
    }
    card.appendChild(destination);

    if (path.hops && path.hops.length) {
      const track = element("div", "path-track");
      track.appendChild(pathOrigin());
      for (const hop of path.hops) {
        track.appendChild(renderHop(hop, evidenceIDs[0]));
      }
      track.appendChild(destinationTrackNode(path));
      card.appendChild(track);
    } else {
      card.appendChild(element("div", "empty-state compact", "No TTL observations were retained for this protocol."));
    }

    if (path.segments && path.segments.length) {
      const segmentDetails = element("details", "segment-details");
      const summary = element("summary", "segment-summary", "Evidence segments");
      segmentDetails.appendChild(summary);
      const segmentList = element("div", "segment-list");
      for (const segment of path.segments) {
        segmentList.appendChild(renderSegment(segment, evidenceIDs[0]));
      }
      segmentDetails.appendChild(segmentList);
      card.appendChild(segmentDetails);
    }
    paths.appendChild(card);
  }

  function pathOrigin() {
    const node = element("div", "track-node origin-node");
    node.appendChild(element("span", "node-marker", "●"));
    node.appendChild(element("strong", "node-title", "Probe vantage"));
    node.appendChild(element("span", "node-detail", "local source"));
    return node;
  }

  function renderHop(hop, evidenceId) {
    const button = element("button", toneClass("track-node hop-node", hop.tone));
    button.type = "button";
    button.dataset.evidenceId = text(evidenceId);
    button.title = "Focus the raw path evidence";
    button.appendChild(element("span", "node-marker", `TTL ${text(hop.ttl)}`));
    const copy = element("span", "node-copy");
    copy.appendChild(element("strong", "node-title", hop.label));
    copy.appendChild(element("span", "node-detail", hop.detail));
    button.appendChild(copy);
    if (hop.responders && hop.responders.length) {
      const responders = element("span", "responder-list");
      for (const responder of hop.responders) {
        responders.appendChild(renderResponder(responder));
      }
      button.appendChild(responders);
    }
    button.addEventListener("click", () => focusEvidence(evidenceId));
    return button;
  }

  function destinationTrackNode(path) {
    const node = element("div", "track-node destination-node");
    node.appendChild(element("span", "node-marker", "◆"));
    node.appendChild(element("strong", "node-title", "Destination"));
    node.appendChild(element("span", "node-detail", `Reached: ${booleanText(path.destination_reached)} · TCP connected: ${booleanText(path.destination_tcp_connected)}`));
    return node;
  }

  function renderSegment(segment, evidenceId) {
    const button = element("button", toneClass("segment-row", segment.tone));
    button.type = "button";
    button.dataset.evidenceId = text(evidenceId);
    const ttl = segment.from_ttl === segment.to_ttl ? `TTL ${segment.from_ttl}` : `TTL ${segment.from_ttl}–${segment.to_ttl}`;
    button.appendChild(element("span", "segment-range", ttl));
    const copy = element("span", "segment-copy");
    copy.appendChild(element("strong", "segment-title", segment.label));
    copy.appendChild(element("span", "segment-detail", segment.detail));
    button.appendChild(copy);
    if (segment.responders && segment.responders.length) {
      const responders = element("span", "segment-responders");
      for (const responder of segment.responders) {
        responders.appendChild(element("code", "responder-inline", responder.address));
      }
      button.appendChild(responders);
    }
    button.addEventListener("click", () => focusEvidence(evidenceId));
    return button;
  }

  function observationNote(path) {
    if (path.observation_status === "unsupported") {
      return "This protocol is unsupported here; no conclusion is drawn from the missing capability.";
    }
    if (path.observation_status === "error") {
      return "The path adapter failed. This is different from a TTL that produced no response.";
    }
    if (path.port_aware) {
      return `Port-aware TCP observation for ${portText(path.destination_port)}.`;
    }
    return "ICMP observation; it is not a destination-port connectivity test.";
  }

  function portText(port) {
    return port ? `port ${text(port)}` : "port unspecified";
  }

  function renderComparison(comparison) {
    const card = element("article", "comparison-card");
    const header = element("div", "card-heading");
    header.appendChild(element("h3", "card-title", `${comparison.destination} · ${comparison.port_label}`));
    header.appendChild(element("span", "count-label", `${(comparison.observations || []).length} observations`));
    card.appendChild(header);

    const summary = element("div", "comparison-summary");
    summary.appendChild(comparisonSignal("ICMP destination", comparison.icmp_destination_reached, "replied", "not confirmed"));
    summary.appendChild(comparisonSignal("TCP destination", comparison.tcp_destination_connected, "connected", comparison.tcp_destination_reached ? "reached, not connected" : "not confirmed"));
    card.appendChild(summary);

    const table = element("table", "comparison-table");
    const head = element("thead");
    const headerRow = element("tr");
    for (const label of ["Protocol", "Observation", "Port aware", "Destination reached", "TCP connected", "TTL responders", "Evidence"]) {
      headerRow.appendChild(element("th", "", label));
    }
    head.appendChild(headerRow);
    table.appendChild(head);
    const body = element("tbody");
    for (const observation of comparison.observations || []) {
      const row = element("tr");
      row.appendChild(element("td", "protocol-cell", text(observation.protocol).toUpperCase()));
      row.appendChild(element("td", "", text(observation.status)));
      row.appendChild(element("td", "", booleanText(observation.port_aware)));
      row.appendChild(element("td", "", booleanText(observation.destination_reached)));
      row.appendChild(element("td", "", booleanText(observation.destination_tcp_connected)));
      const hops = [];
      if (observation.responder_count) {
        hops.push(`${observation.responder_count} responder${observation.responder_count === 1 ? "" : "s"}`);
      }
      if (observation.unobservable_ttls && observation.unobservable_ttls.length) {
        hops.push(`${observation.unobservable_ttls.length} unobservable TTL${observation.unobservable_ttls.length === 1 ? "" : "s"}`);
      }
      row.appendChild(element("td", "", hops.join(" · ") || "No hop detail"));
      const evidenceCell = element("td", "");
      if (observation.evidence_ids && observation.evidence_ids.length) {
        evidenceCell.appendChild(referenceGroup(observation.evidence_ids));
      }
      row.appendChild(evidenceCell);
      body.appendChild(row);
    }
    table.appendChild(body);
    card.appendChild(table);
    comparisons.appendChild(card);
  }

  function comparisonSignal(label, good, goodText, badText) {
    const signal = element("div", toneClass("comparison-signal", good ? "positive" : "neutral"));
    signal.appendChild(element("span", "signal-label", label));
    signal.appendChild(element("strong", "signal-value", good ? goodText : badText));
    return signal;
  }

  function renderEvidenceItem(item) {
    const card = element("article", "evidence-card");
    card.dataset.evidenceId = text(item.id);
    const header = element("div", "card-heading");
    const heading = element("h3", "card-title", `${text(item.probe_name)} / ${text(item.id)}`);
    header.appendChild(heading);
    header.appendChild(badge(item.kind, item.inspector_state === "partial" ? "warning" : "neutral"));
    card.appendChild(header);

    const metadata = element("div", "metadata");
    metadata.appendChild(metadataItem("source", item.source || "not specified"));
    metadata.appendChild(metadataItem("shape", item.structured ? "structured JSON" : "raw JSON value"));
    if (item.captured_at) {
      metadata.appendChild(metadataItem("captured", item.captured_at));
    }
    card.appendChild(metadata);
    if (item.inspector_note) {
      card.appendChild(element("p", "evidence-note warning-text", item.inspector_note));
    }
    const details = element("details", "raw-details");
    details.open = true;
    details.appendChild(element("summary", "", "Raw evidence value"));
    const raw = element("pre", "raw-evidence");
    // textContent is intentional: raw evidence is never interpreted as markup.
    raw.textContent = jsonText(item.raw);
    details.appendChild(raw);
    card.appendChild(details);
    evidence.appendChild(card);
  }

  function renderView(view) {
    currentView = view;
    const overall = view.overall || {};
    const observations = view.observations || {};
    diagnosisLabel.textContent = text(overall.diagnosis_label);
    diagnosisDetail.textContent = diagnosisDetailText(overall);
    diagnosisCard.className = toneClass("overview-card panel", overall.tone);
    overallStatus.textContent = text(overall.execution_label || overall.execution_status);
    renderTargetDetails(observations.endpoint || (view.report && view.report.target));
    renderEndpointObservation(observations.endpoint);
    renderOperationalObservations(observations, view.application);
    renderPolicyObservation(observations.enterprise_policy);
    renderNetworkContext(observations.network_context || view.network_context);
    renderDestination(overall.destination || {});
    renderNameResolution(observations.name_resolution || view.name_resolution);

    probes.replaceChildren();
    const probeViews = view.probes || [];
    probeCount.textContent = `${probeViews.length} lane${probeViews.length === 1 ? "" : "s"}`;
    for (const [index, probe] of probeViews.entries()) {
      renderProbe(probe, index);
    }
    if (!probeViews.length) {
      probes.appendChild(element("div", "empty-state", "No probe results were returned."));
    }

    findings.replaceChildren();
    const findingViews = view.findings || [];
    for (const finding of findingViews) {
      renderFinding(finding);
    }
    if (!findingViews.length) {
      findings.appendChild(element("div", "empty-state", "No canonical findings. This does not mean every protocol is observable."));
    }

    renderPathGraph(view);
    paths.replaceChildren();
    const pathViews = view.paths || [];
    pathEmpty.hidden = pathViews.length !== 0;
    for (const [index, path] of pathViews.entries()) {
      renderPath(path, index);
    }

    comparisons.replaceChildren();
    const comparisonViews = view.comparisons || [];
    for (const comparison of comparisonViews) {
      renderComparison(comparison);
    }
    if (!comparisonViews.length) {
      comparisons.appendChild(element("div", "empty-state", "No comparable protocol or port observations are available."));
    }

    evidence.replaceChildren();
    const evidenceViews = view.evidence || [];
    evidenceHeading.textContent = `Structured evidence · ${evidenceViews.length} item${evidenceViews.length === 1 ? "" : "s"}`;
    for (const item of evidenceViews) {
      renderEvidenceItem(item);
    }
    if (!evidenceViews.length) {
      evidence.appendChild(element("div", "empty-state", "No evidence was retained."));
    }
    canonicalJSON.textContent = view.canonical_json || jsonText(view.report);
    reportSection.hidden = false;
  }

  function renderNetworkContext(context) {
    networkContext.replaceChildren();
    const available = context && (context.requested_identity || context.selected_destination_address || context.network_scope || context.effective_route || (context.provenance && context.provenance.length) || (context.evidence_ids && context.evidence_ids.length));
    networkContextPanel.hidden = !available;
    if (!available) {
      return;
    }
    const fields = [
      ["Network scope", context.network_scope_label || context.network_scope],
      ["Requested identity", context.requested_identity],
      ["Selected destination", context.selected_destination_address],
      ["Source interface", context.selected_source_interface],
      ["Source address", context.selected_source_address],
      ["Route", context.effective_route_label || context.effective_route],
      ["Route prefix", context.route_prefix],
      ["Next hop", context.next_hop],
      ["Gateway", context.gateway || "Not applicable"],
      ["Route metric", context.route_metric],
      ["Certainty", context.certainty],
      ["Provenance", listText(context.provenance)],
      ["Evidence", referenceValue(context.evidence_ids)],
    ];
    fields.push(["VPN / tunnel involvement", booleanText(context.vpn_or_tunnel_involvement)]);
    fields.push(["Virtual adapter involvement", booleanText(context.virtual_adapter_involvement)]);
    fields.push(["Route selection ambiguous", booleanText(context.route_selection_ambiguous)]);
    if (context.neighbor) {
      fields.push(["Neighbor cache", context.neighbor.observation]);
    }
    for (const [label, value] of fields) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      const item = element("div", "context-item");
      item.appendChild(element("span", "context-label", label));
      if (value && typeof value === "object" && value.nodeType) {
        item.appendChild(value);
      } else {
        item.appendChild(element("code", "context-value", value));
      }
      networkContext.appendChild(item);
    }
    if (context.competing_routes && context.competing_routes.length) {
      const note = element("p", "section-note context-note", `${context.competing_routes.length} competing route${context.competing_routes.length === 1 ? "" : "s"} retained in canonical context.`);
      networkContext.appendChild(note);
    }
  }

  function diagnosisDetailText(overall) {
    const destination = overall.destination && overall.destination.label ? ` Destination: ${overall.destination.label}.` : "";
    return `${text(overall.diagnosis_state)}.${destination}`;
  }

  function renderTargetDetails(target) {
    reportTarget.replaceChildren();
    if (!target) {
      reportTarget.appendChild(element("div", "target-detail", "Target unavailable"));
      return;
    }
    const service = target.service || {};
    const fields = [
      ["Target", target.requested_identity || "identity unavailable"],
      ["Service", service.label || target.application_protocol || "not specified"],
      ["Transport", target.transport_protocol || "not specified"],
      ["Port", target.port || "not specified"],
    ];
    if (target.resource) {
      fields.push(["Resource", target.resource]);
    }
    for (const [label, value] of fields) {
      const row = element("div", "target-detail");
      row.appendChild(element("span", "target-detail-label", label));
      row.appendChild(element("span", "target-detail-value", value));
      reportTarget.appendChild(row);
    }
  }

  function focusEvidence(id) {
    let match = null;
    for (const card of evidence.children) {
      if (card.dataset.evidenceId === text(id)) {
        match = card;
        break;
      }
    }
    if (!match) {
      return;
    }
    for (const card of evidence.children) {
      card.classList.remove("is-focused");
    }
    match.classList.add("is-focused");
    match.scrollIntoView({ behavior: "smooth", block: "center" });
    evidenceHeading.textContent = `Evidence inspector · ${text(id)}`;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();
    closeEvents();
    activeSessionID = "";
    reportSection.hidden = true;
    pathGraphCount.textContent = "Awaiting report";
    pathGraphDescription.textContent = "A horizontal layout is reserved for canonical path data.";
    setPathGraphState("loading");
    button.disabled = true;
    button.textContent = "Starting…";
    cancelButton.hidden = true;
    setProgress([{ state: "started" }, { state: "running" }], "Starting diagnostic session", "starting", "neutral");

    try {
      const response = await fetch("/api/diagnoses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(composer.serialize(composerState)),
      });
      const snapshot = await readResponse(response);
      activeSessionID = text(snapshot.id);
      setSessionState(snapshot.state || "running");
      button.textContent = "Running…";
      openEvents(activeSessionID);
    } catch (err) {
      setProgress([{ state: "error" }], "Diagnostic request failed", "error", "negative");
      showError(err instanceof Error ? err.message : "diagnosis request failed");
      button.disabled = false;
      button.textContent = "Diagnose →";
    }
  });

  cancelButton.addEventListener("click", async () => {
    if (!activeSessionID) {
      return;
    }
    clearError();
    setSessionState("cancelling");
    try {
      const response = await fetch(`/api/diagnoses/${encodeURIComponent(activeSessionID)}`, { method: "DELETE" });
      const snapshot = await readResponse(response);
      setSessionState(snapshot.state || "cancelling");
    } catch (err) {
      showError(err instanceof Error ? err.message : "cancel request failed");
      cancelButton.disabled = false;
    }
  });
})();
