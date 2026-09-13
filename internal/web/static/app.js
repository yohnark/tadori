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
  const probeCount = document.querySelector("#probe-count");
  const probes = document.querySelector("#probes");
  const findings = document.querySelector("#findings");
  const paths = document.querySelector("#paths");
  const pathEmpty = document.querySelector("#path-empty");
  const comparisons = document.querySelector("#comparisons");
  const evidence = document.querySelector("#evidence");
  const evidenceHeading = document.querySelector("#evidence-heading");
  const canonicalJSON = document.querySelector("#canonical-json");

  let currentView = null;
  let activeSessionID = "";
  let eventSource = null;
  const progressItems = new Map();
  let portWasEdited = false;

  function selectedServiceOption() {
    return serviceInput.options[serviceInput.selectedIndex];
  }

  function applyServiceDefaultPort() {
    if (!portWasEdited) {
      portInput.value = selectedServiceOption()?.dataset.defaultPort || "";
    }
  }

  function updateComposerFromExplicitInput() {
    const value = targetInput.value.trim();
    const lower = value.toLowerCase();
    let explicitService = "";
    if (lower.startsWith("https://")) {
      explicitService = "https";
    } else if (lower.startsWith("http://")) {
      explicitService = "http";
    } else if (value.startsWith("\\")) {
      explicitService = "smb";
    }
    if (explicitService) {
      serviceInput.value = explicitService;
      applyServiceDefaultPort();
      try {
        const parsed = new URL(value);
        if (parsed.port) {
          portInput.value = parsed.port;
          portWasEdited = true;
        }
      } catch (_) {
        // Backend normalization remains authoritative for incomplete input.
      }
    }
  }

  serviceInput.addEventListener("change", () => {
    portWasEdited = false;
    applyServiceDefaultPort();
  });
  portInput.addEventListener("input", () => {
    portWasEdited = true;
  });
  targetInput.addEventListener("input", updateComposerFromExplicitInput);
  applyServiceDefaultPort();

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
    card.dataset.evidenceId = text(path.evidence_id);
    const header = element("div", "path-heading");
    const heading = element("div");
    heading.appendChild(element("h3", "card-title", `${index + 1}. ${path.protocol_label} observation`));
    heading.appendChild(element("p", "path-endpoint", `${text(path.destination)} · ${portText(path.destination_port)}`));
    header.appendChild(heading);
    header.appendChild(badge(path.observation_label, path.observation_tone));
    card.appendChild(header);

    const pathNote = element("p", "path-note", observationNote(path));
    card.appendChild(pathNote);

    const destination = element("div", toneClass("path-destination", destinationTone(path.destination_state)));
    destination.appendChild(element("span", "destination-marker", "◆"));
    const destinationCopy = element("div");
    destinationCopy.appendChild(element("strong", "destination-title", path.destination_label));
    destinationCopy.appendChild(element("span", "destination-copy", path.destination_detail));
    destination.appendChild(destinationCopy);
    destination.appendChild(referenceButton(path.evidence_id, "Evidence"));
    card.appendChild(destination);

    if (path.hops && path.hops.length) {
      const track = element("div", "path-track");
      track.appendChild(pathOrigin());
      for (const hop of path.hops) {
        track.appendChild(renderHop(hop, path.evidence_id));
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
        segmentList.appendChild(renderSegment(segment, path.evidence_id));
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
    const node = element("div", toneClass("track-node destination-node", destinationTone(path.destination_state)));
    node.appendChild(element("span", "node-marker", "◆"));
    node.appendChild(element("strong", "node-title", "Destination"));
    node.appendChild(element("span", "node-detail", path.destination_label));
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
    for (const label of ["Protocol", "Observation", "Endpoint state", "TTL responders", "Evidence"]) {
      headerRow.appendChild(element("th", "", label));
    }
    head.appendChild(headerRow);
    table.appendChild(head);
    const body = element("tbody");
    for (const observation of comparison.observations || []) {
      const row = element("tr");
      row.appendChild(element("td", "protocol-cell", text(observation.protocol).toUpperCase()));
      row.appendChild(element("td", "", text(observation.status)));
      const stateCell = element("td", "");
      stateCell.appendChild(badge(observation.destination_label, destinationTone(observation.destination_state)));
      row.appendChild(stateCell);
      const hops = [];
      if (observation.responder_count) {
        hops.push(`${observation.responder_count} responder${observation.responder_count === 1 ? "" : "s"}`);
      }
      if (observation.unobservable_ttls && observation.unobservable_ttls.length) {
        hops.push(`${observation.unobservable_ttls.length} unobservable TTL${observation.unobservable_ttls.length === 1 ? "" : "s"}`);
      }
      row.appendChild(element("td", "", hops.join(" · ") || "No hop detail"));
      const evidenceCell = element("td", "");
      evidenceCell.appendChild(referenceButton(observation.evidence_id));
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
    diagnosisLabel.textContent = text(overall.diagnosis_label);
    diagnosisDetail.textContent = diagnosisDetailText(overall);
    diagnosisCard.className = toneClass("overview-card panel", overall.tone);
    overallStatus.textContent = text(overall.execution_label || overall.execution_status);
    renderTargetDetails(view.report && view.report.target);
    renderDestination(overall.destination || {});

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
    button.disabled = true;
    button.textContent = "Starting…";
    cancelButton.hidden = true;
    setProgress([{ state: "started" }, { state: "running" }], "Starting diagnostic session", "starting", "neutral");

    try {
      const response = await fetch("/api/diagnoses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: {
            input: targetInput.value,
            service: serviceInput.value,
            ...(portWasEdited && portInput.value ? { port: Number(portInput.value) } : {}),
          },
        }),
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
