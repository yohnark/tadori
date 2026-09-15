(() => {
  "use strict";

  // Presentation concepts such as “Destination confirmed” and “Limitations”
  // are resolved through the locale resource below; they are not model data.

  const form = document.querySelector("#diagnose-form");
  const targetInput = document.querySelector("#target");
  const serviceInput = document.querySelector("#service");
  const portInput = document.querySelector("#port");
  const button = form.querySelector("button[type=submit]");
  const cancelButton = document.querySelector("#cancel-button");
  const error = document.querySelector("#error");
  const browserCaptureStart = document.querySelector("#browser-capture-start");
  const browserCaptureStop = document.querySelector("#browser-capture-stop");
  const browserCaptureBrowser = document.querySelector("#browser-capture-browser");
  const browserCaptureState = document.querySelector("#browser-capture-state");
  const browserCaptureError = document.querySelector("#browser-capture-error");
  const browserCaptureElapsed = document.querySelector("#browser-capture-elapsed");
  const browserCaptureDestinations = document.querySelector("#browser-capture-destinations");
  const browserCaptureAddresses = document.querySelector("#browser-capture-addresses");
  const browserCaptureObservations = document.querySelector("#browser-capture-observations");
  const browserCaptureFailures = document.querySelector("#browser-capture-failures");
  const browserCaptureDestinationsBody = document.querySelector("#browser-capture-destinations-body");
  const browserCaptureEmpty = document.querySelector("#browser-capture-empty");
  const browserCaptureJSON = document.querySelector("#browser-capture-json");
  const browserCaptureFQDNs = document.querySelector("#browser-capture-fqdns");
  const browserCaptureCopy = document.querySelector("#browser-capture-copy");
  const reportSection = document.querySelector("#report");
  const runStateLabel = document.querySelector("#run-state-label");
  const runStateBadge = document.querySelector("#run-state-badge");
  const progressList = document.querySelector("#progress-list");
  const diagnosisCard = document.querySelector("#diagnosis-card");
  const diagnosisLabel = document.querySelector("#diagnosis-label");
  const diagnosisDetail = document.querySelector("#diagnosis-detail");
  const destinationStatusStrip = document.querySelector("#destination-status-strip");
  const destinationStatusLabel = document.querySelector("#destination-status-label");
  const destinationStatusDetail = document.querySelector("#destination-status-detail");
  const destinationStatusService = document.querySelector("#destination-status-service");
  const destinationStatusIdentity = document.querySelector("#destination-status-identity");
  const destinationStatusEndpoint = document.querySelector("#destination-status-endpoint");
  const destinationStatusReason = document.querySelector("#destination-status-reason");
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
  const pathGraphContent = document.querySelector("#path-graph-content");
  const pathGraphScaffold = document.querySelector("#path-graph-scaffold");
  const pathGraphReservation = document.querySelector("#path-graph-reservation");
  const pathViewStatus = document.querySelector("#path-view-status");
  const pathViewTabs = document.querySelectorAll(".path-view-tab");
  const pathViewControls = document.querySelectorAll("[data-path-view]");
  const comparisons = document.querySelector("#comparisons");
  const evidence = document.querySelector("#evidence");
  const evidenceHeading = document.querySelector("#evidence-heading");
  const pathSelection = document.querySelector("#path-selection");
  const canonicalJSON = document.querySelector("#canonical-json");
  const htmlReportLink = document.querySelector("#html-report-link");
  const jsonReportLink = document.querySelector("#json-report-link");
  const composer = globalThis.TadoriTargetComposer;
  const display = globalThis.TadoriWorkbenchDisplay;
  const locale = globalThis.TadoriLocale;
  const localeButtons = document.querySelectorAll("[data-locale]");
  const localeStorageKey = "tadori.locale";

  let currentView = null;
  let currentLocale = locale.normalizeLocale(readStoredLocale());
  let translate = locale.createTranslator(currentLocale);
  let activeSessionID = "";
  let eventSource = null;
  let activeCaptureID = "";
  let capturePollTimer = null;
  let activePathView = "graph";
  let renderedSessionID = "";
  let currentSessionState = "idle";
  let progressEvents = [];
  let activeCaptureSnapshot = null;
  const progressItems = new Map();
  let progressHeader = { labelKey: "target.ready", badge: "idle", tone: "neutral" };
  let composerState = composer.createState({ service: serviceInput.value });

  function readStoredLocale() {
    try {
      return globalThis.localStorage && globalThis.localStorage.getItem(localeStorageKey);
    } catch (_) {
      return null;
    }
  }

  function storeLocale(value) {
    try {
      if (globalThis.localStorage) {
        globalThis.localStorage.setItem(localeStorageKey, value);
      }
    } catch (_) {
      // Private browsing and embedded webviews may deny local storage.
    }
  }

  function t(key, variables) {
    return translate(key, variables);
  }

  function enumText(namespace, value, fallback) {
    const raw = text(value);
    const key = `enum.${namespace}.${raw}`;
    if (translate.has(key)) {
      return t(key);
    }
    return fallback === undefined ? raw : fallback;
  }

  function sourceText(value, variables) {
    if (typeof locale.translateSource === "function") {
      return locale.translateSource(value, currentLocale, variables);
    }
    return text(value);
  }

  function quantity(oneKey, manyKey, count) {
    return t(count === 1 ? oneKey : manyKey, { count });
  }

  function applyStaticLocale() {
    document.documentElement.lang = currentLocale;
    for (const node of document.querySelectorAll("[data-i18n]")) {
      node.textContent = t(node.dataset.i18n);
    }
    for (const node of document.querySelectorAll("[data-i18n-aria-label]")) {
      node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel));
    }
    for (const node of document.querySelectorAll("[data-i18n-placeholder]")) {
      node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder));
    }
    for (const node of document.querySelectorAll("[data-i18n-content]")) {
      node.setAttribute("content", t(node.dataset.i18nContent));
    }
    for (const node of document.querySelectorAll("[data-i18n-title]")) {
      node.setAttribute("title", t(node.dataset.i18nTitle));
    }
    for (const button of localeButtons) {
      const selected = button.dataset.locale === currentLocale;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-pressed", selected ? "true" : "false");
    }
  }

  function changeLocale(requestedLocale) {
    const nextLocale = locale.normalizeLocale(requestedLocale);
    if (nextLocale === currentLocale) {
      applyStaticLocale();
      return;
    }
    currentLocale = nextLocale;
    translate = locale.createTranslator(currentLocale);
    storeLocale(currentLocale);
    applyStaticLocale();
    if (currentView) {
      renderView(currentView);
    } else {
      renderProgressList();
      if (currentSessionState !== "idle") {
        renderSessionState(currentSessionState);
      }
      if (activeCaptureSnapshot) {
        renderBrowserCapture(activeCaptureSnapshot);
      }
    }
    selectPathView(activePathView);
  }

  for (const button of localeButtons) {
    button.addEventListener("click", () => changeLocale(button.dataset.locale));
  }

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
  applyStaticLocale();
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

  function semanticValueElement(label, value, className = "", tag = "span") {
    const descriptor = display.describeSemanticValue(label, value);
    const classes = ["semantic-value", className, `semantic-${descriptor.kind}`].filter(Boolean).join(" ");
    const wrapper = element(tag, classes);
    const valueText = element("span", "semantic-value-text", descriptor.text);
    if (descriptor.truncated) {
      valueText.title = descriptor.fullText;
      valueText.setAttribute("aria-label", descriptor.fullText);
    }
    wrapper.appendChild(valueText);
    if (descriptor.copyable) {
      wrapper.appendChild(copyValueButton(descriptor.fullText, label));
    }
    return wrapper;
  }

  function copyValueButton(value, label) {
    const button = element("button", "copy-value", t("common.copy"));
    button.type = "button";
    const accessibleLabel = t("common.copyValue", { label, value: text(value) });
    button.title = accessibleLabel;
    button.setAttribute("aria-label", accessibleLabel);
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      void copyValue(value, button);
    });
    return button;
  }

  async function copyValue(value, button) {
    const clipboard = globalThis.navigator && globalThis.navigator.clipboard;
    const original = button.textContent;
    if (!clipboard || typeof clipboard.writeText !== "function") {
      button.textContent = t("common.unavailable");
      setTimeout(() => { button.textContent = original; }, 1500);
      return;
    }
    try {
      await clipboard.writeText(text(value));
      button.textContent = t("common.copied");
    } catch (_) {
      button.textContent = t("common.failed");
    }
    setTimeout(() => { button.textContent = original; }, 1500);
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
    pathViewStatus.textContent = selectedView === "graph" ? t("path.graph") : t("path.canonicalTable");
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
    pathGraphContent.replaceChildren();
    pathGraphScaffold.hidden = true;
    pathGraphReservation.hidden = true;
    if (!view) {
      pathGraphCount.textContent = t("path.awaitingReport");
      pathGraphDescription.textContent = t("path.waiting");
      setPathGraphState("loading");
      return;
    }

    const pathViews = Array.isArray(view.paths) ? view.paths : [];
    const pathCount = pathViews.length;
    pathGraphCount.textContent = quantity("path.observedPathsOne", "path.observedPathsMany", pathCount);
    if (!pathCount) {
      pathGraphDescription.textContent = t("path.noPath");
      setPathGraphState("empty");
      return;
    }

    const graphs = pathViews
      .map((path) => path && path.graph)
      .filter((graph) => graph && graph.supported && Array.isArray(graph.nodes) && Array.isArray(graph.groups));
    const onlyUnsupported = pathViews.every((path) => path && path.graph && !path.graph.supported);
    if (!graphs.length) {
      pathGraphDescription.textContent = onlyUnsupported
        ? t("path.supportedTable")
        : t("path.noGraph");
      setPathGraphState("unsupported");
      return;
    }

    pathGraphDescription.textContent = t("path.graphDescription");
    for (const [index, graph] of graphs.entries()) {
      pathGraphContent.appendChild(renderGraphLane(graph, index));
    }
    setPathGraphState("reserved");
  }

  function renderGraphLane(graph, index) {
    const lane = element("section", "path-graph-lane");
    lane.setAttribute("aria-label", `${protocolText(graph.protocol, graph.protocol_label)} ${t("path.observedPath")} ${index + 1}`);

    const heading = element("div", "path-graph-lane-heading");
    const copy = element("div");
    copy.appendChild(element("strong", "path-graph-lane-title", `${protocolText(graph.protocol, graph.protocol_label).toUpperCase()} ${t("path.observation")}`));
    copy.appendChild(element("span", "path-graph-lane-endpoint", `${text(graph.destination)} · ${portText(graph.destination_port)}`));
    heading.appendChild(copy);
    const laneMetadata = element("div", "path-graph-lane-meta");
    laneMetadata.appendChild(badge(enumText("pathStatus", graph.observation_status, sourceText(graph.observation_label || graph.observation_status)), graph.observation_tone));
    laneMetadata.appendChild(element("span", "path-graph-context", graph.port_aware ? t("path.portAware") : graph.protocol === "icmp" ? t("path.icmpContext") : t("path.notPortAware")));
    if (graph.destination_tcp_connected) {
      laneMetadata.appendChild(badge(t("path.tcpConnected"), "positive"));
    } else if (graph.destination_reached) {
      laneMetadata.appendChild(badge(t("path.destinationReached"), "positive"));
    }
    heading.appendChild(laneMetadata);
    lane.appendChild(heading);

    const track = element("div", "path-graph-lane-track");
    const nodeByID = new Map((graph.nodes || []).map((node) => [node.id, node]));
    const groups = graph.groups || [];
    for (const [groupIndex, group] of groups.entries()) {
      if (groupIndex) {
        track.appendChild(renderGraphConnector(graph, groups[groupIndex - 1], group));
      }
      const groupTone = group.kind === "ttl_hop" || (group.kind === "destination_confirmation" && graph.destination_reached) ? "positive" : "neutral";
      const column = element("div", toneClass("path-graph-group", groupTone));
      column.appendChild(element("span", "path-graph-group-label", graphGroupRangeLabel(group)));
      column.appendChild(element("span", "path-graph-group-detail", graphGroupDetailText(group)));
      const nodeList = element("div", "path-graph-node-list");
      for (const nodeID of group.node_ids || []) {
        const node = nodeByID.get(nodeID);
        if (node) {
          nodeList.appendChild(renderGraphNode(node));
        }
      }
      column.appendChild(nodeList);
      track.appendChild(column);
    }
    lane.appendChild(track);
    if (graph.limitations && graph.limitations.length) {
      lane.appendChild(element("p", "path-graph-limitation", graph.limitations.map(sourceText).join(" · ")));
    }
    return lane;
  }

  function renderGraphConnector(graph, previous, current) {
    const connector = element("div", "path-graph-connector");
    const previousIDs = previous.node_ids || [];
    const currentIDs = current.node_ids || [];
    const edge = (graph.edges || []).find((candidate) => previousIDs.includes(candidate.from) && currentIDs.includes(candidate.to));
    connector.classList.add(edgeTone(edge && edge.kind));
    connector.title = edge ? sourceText(edge.detail) : t("path.canonicalOrder");
    connector.appendChild(element("span", "path-graph-connector-line"));
    connector.appendChild(element("span", "path-graph-connector-label", edge ? graphEdgeLabel(edge.kind, edge.label) : t("path.observedOrder")));
    return connector;
  }

  function edgeTone(kind) {
    if (kind === "unobservable_visibility") {
      return "is-unobservable";
    }
    if (kind === "bounded_inference") {
      return "is-inferred";
    }
    if (kind === "destination_confirmation") {
      return "is-destination";
    }
    return "is-observed";
  }

  function graphGroupRangeLabel(group) {
    if (!group.from_ttl && !group.to_ttl) {
      return group.kind === "destination_confirmation" ? t("path.destinationGroup") : t("path.startGroup");
    }
    return group.from_ttl === group.to_ttl ? t("path.ttl", { value: group.from_ttl }) : t("path.ttlRange", { from: group.from_ttl, to: group.to_ttl });
  }

  function renderGraphNode(node) {
    const button = element("button", toneClass("path-graph-node", node.tone));
    button.type = "button";
    button.dataset.graphNodeId = text(node.id);
    button.dataset.evidenceId = text((node.evidence_ids || [])[0]);
    button.title = graphNodeDetailText(node);
    const heading = element("span", "path-graph-node-heading");
    heading.appendChild(element("strong", "path-graph-node-title", graphNodeLabel(node)));
    if (node.destination_confirmed) {
      heading.appendChild(badge(t("path.destinationConfirmed"), "positive"));
    }
    button.appendChild(heading);
    button.appendChild(element("span", "path-graph-node-detail", graphNodeDetailText(node)));
    if (node.address) {
      button.appendChild(element("code", "path-graph-node-address", node.address));
    }
    const metadata = [];
    if (node.rtt_ms) {
      metadata.push(`${node.rtt_ms} ms ${t("path.rtt")}`);
    }
    if (node.response) {
      metadata.push(node.response);
    }
    if (node.attempts) {
      metadata.push(t("path.attempts", { count: node.attempts, plural: node.attempts === 1 ? "" : "s" }));
    }
    if (node.certainty) {
      metadata.push(`${t("path.certainty")}: ${enumText("certainty", node.certainty)}`);
    }
    if (metadata.length) {
      button.appendChild(element("span", "path-graph-node-meta", metadata.join(" · ")));
    }
    button.addEventListener("click", () => selectGraphNode(node));
    return button;
  }

  function protocolText(protocol, presentationFallback) {
    const raw = text(protocol || presentationFallback);
    return enumText("protocol", raw, raw.toUpperCase());
  }

  function graphNodeLabel(node) {
    switch (node.kind) {
      case "probe_vantage":
        return t("path.probeVantage");
      case "responder":
        return node.role === "destination_responder" ? t("path.destinationResponder") : t("path.intermediateResponder");
      case "unobservable_range":
        return t("path.unobservableTTLRange");
      case "unknown_range":
        return t("path.unknownTTLRange");
      case "destination_confirmation":
        return t("path.destinationConfirmation");
      default:
        return sourceText(node.label) || text(node.label);
    }
  }

  function graphNodeDetailText(node) {
    const range = node.ttl_from === node.ttl_to
      ? text(node.ttl_from)
      : `${text(node.ttl_from)}–${text(node.ttl_to)}`;
    switch (node.kind) {
      case "probe_vantage":
        return t("source.graphVantage");
      case "responder":
        return t(node.role === "destination_responder" ? "source.graphDestinationResponder" : "source.graphResponder", { ttl: node.ttl });
      case "unobservable_range":
        return t("source.graphUnobservable", { range });
      case "unknown_range":
        return t("source.graphUnknown", { range });
      case "destination_confirmation":
        if (node.destination_tcp_connected) {
          return t("source.graphDestinationTCP");
        }
        return node.destination_confirmed ? t("source.graphDestinationConfirmed") : t("source.graphDestinationNotConfirmed");
      default:
        return sourceText(node.detail) || text(node.detail);
    }
  }

  function graphGroupDetailText(group) {
    switch (group.kind) {
      case "probe_vantage":
        return t("source.graphVantage");
      case "ttl_hop":
        return group.node_ids && group.node_ids.length === 1
          ? t("source.graphResponderOne")
          : t("source.graphResponderMany", { count: (group.node_ids || []).length });
      case "unobservable_range":
        return t("source.graphUnobservable", { range: ttlRangeValue(group.from_ttl, group.to_ttl) });
      case "unknown_range":
        return t("source.graphUnknown", { range: ttlRangeValue(group.from_ttl, group.to_ttl) });
      case "destination_confirmation":
        return t("source.graphDestination");
      default:
        return sourceText(group.detail || group.label) || text(group.detail || group.label);
    }
  }

  function graphEdgeLabel(kind, fallback) {
    const keys = {
      unobservable_visibility: "path.edgeUnobservable",
      bounded_inference: "path.edgeInferred",
      destination_confirmation: "path.edgeDestination",
      observation_order: "path.edgeObserved",
    };
    return keys[kind] ? t(keys[kind]) : sourceText(fallback) || text(fallback);
  }

  function ttlRangeValue(from, to) {
    return from === to ? text(from) : `${text(from)}–${text(to)}`;
  }

  function selectGraphNode(node) {
    pathSelection.hidden = false;
    pathSelection.replaceChildren();
    const range = node.ttl_from === node.ttl_to ? `TTL ${text(node.ttl_from)}` : `TTL ${text(node.ttl_from)}–${text(node.ttl_to)}`;
    appendObservationRows(pathSelection, [
      [t("path.role"), enumText("role", node.role, text(node.role))],
      [t("path.ttlHop"), node.kind === "probe_vantage" || node.kind === "destination_confirmation" ? graphNodeLabel(node) : range],
      [t("path.observedAddress"), node.address || t("path.notApplicable")],
      [t("path.rtt"), node.rtt_ms ? `${node.rtt_ms} ms` : t("path.notObserved")],
      [t("path.response"), node.response || t("path.notSpecified")],
      [t("path.attempts"), node.attempts || t("path.notSpecified")],
      [t("path.protocol"), protocolText(node.protocol)],
      [t("path.destinationPort"), portText(node.destination_port)],
      [t("path.portAware"), booleanText(node.port_aware)],
      [t("path.certainty"), enumText("certainty", node.certainty, t("path.unknown"))],
      [t("path.destinationConfirmed"), booleanText(node.destination_confirmed)],
      [t("path.tcpConnected"), booleanText(node.destination_tcp_connected)],
      [t("path.provenance"), listText(node.provenance)],
      [t("path.evidence"), referenceValue(node.evidence_ids)],
      [t("path.limitations"), listText(node.limitations)],
    ]);
    evidenceHeading.textContent = `${t("evidence.inspector")} · ${graphNodeLabel(node)}`;
    const evidenceID = (node.evidence_ids || [])[0];
    if (evidenceID) {
      focusEvidence(evidenceID);
    }
  }

  function badge(label, tone) {
    return element("span", toneClass("badge", tone), label);
  }

  function referenceButton(id, label) {
    const evidenceID = text(id);
    const descriptor = display.describeSemanticValue("Evidence ID", evidenceID);
    const reference = element("span", "evidence-reference");
    const button = element("button", "evidence-link", label || descriptor.text);
    button.type = "button";
    button.dataset.evidenceId = evidenceID;
    button.title = t("evidence.focus", { id: evidenceID });
    button.setAttribute("aria-label", t("evidence.focus", { id: evidenceID }));
    button.addEventListener("click", () => focusEvidence(id));
    reference.appendChild(button);
    reference.appendChild(copyValueButton(evidenceID, t("evidence.copyID")));
    return reference;
  }

  function referenceGroup(ids) {
    const group = element("span", "reference-group");
    for (const id of ids || []) {
      group.appendChild(referenceButton(id));
    }
    return group;
  }

  function setProgress(events, labelKey, badgeLabel, tone) {
    progressHeader = { labelKey, badge: badgeLabel, tone };
    progressEvents = (events || []).map((event) => ({ ...event }));
    renderProgressList();
  }

  function renderProgressList() {
    runStateLabel.textContent = t(progressHeader.labelKey);
    runStateBadge.textContent = enumText("state", progressHeader.badge, progressHeader.badge);
    runStateBadge.className = toneClass("badge", progressHeader.tone);
    progressList.replaceChildren();
    progressItems.clear();
    for (const event of progressEvents) {
      renderProgressEvent(event);
    }
  }

  function renderProgressEvent(event) {
    const name = text(event.probe_name);
    const key = name || "__lifecycle";
    const eventIndex = progressEvents.findIndex((candidate) => (text(candidate.probe_name) || "__lifecycle") === key);
    if (eventIndex >= 0) {
      progressEvents[eventIndex] = { ...event };
    } else {
      progressEvents.push({ ...event });
    }
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
      item.appendChild(badge(enumText("probeStatus", event.status, text(event.status)), itemTone));
    }
  }

  function progressState(state) {
    switch (state) {
      case "started":
        return t("progress.started");
      case "running":
        return t("progress.running");
      case "complete":
        return t("progress.complete");
      case "error":
        return t("progress.error");
      default:
        return t("progress.waiting");
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

  function showBrowserCaptureError(message) {
    browserCaptureError.textContent = text(message);
    browserCaptureError.hidden = false;
  }

  function clearBrowserCaptureError() {
    browserCaptureError.textContent = "";
    browserCaptureError.hidden = true;
  }

  function browserCaptureTone(state) {
    if (state === "completed") {
      return "positive";
    }
    if (state === "failed") {
      return "negative";
    }
    if (state === "stopping" || state === "cancelled") {
      return "warning";
    }
    return "neutral";
  }

  function browserCaptureOutcomeTone(outcome) {
    if (outcome === "connected") {
      return "positive";
    }
    if (outcome === "failed" || outcome === "dns_failed" || outcome === "proxy_rejected") {
      return "negative";
    }
    if (outcome === "mixed") {
      return "warning";
    }
    return "neutral";
  }

  function renderBrowserCapture(snapshot) {
    activeCaptureSnapshot = snapshot;
    const state = text(snapshot.state || "unknown");
    browserCaptureState.textContent = enumText("state", state, state);
    browserCaptureState.className = toneClass("badge", browserCaptureTone(state));
    browserCaptureStart.disabled = state === "starting" || state === "running" || state === "stopping";
    browserCaptureStop.hidden = state !== "starting" && state !== "running";
    browserCaptureBrowser.disabled = browserCaptureStart.disabled;
    browserCaptureDestinations.textContent = text(snapshot.unique_destination_count || 0);
    browserCaptureAddresses.textContent = text(snapshot.unique_address_count || 0);
    browserCaptureObservations.textContent = text(snapshot.observation_count || 0);
    browserCaptureFailures.textContent = text(snapshot.failure_count || 0);
    const started = snapshot.started_at ? Date.parse(snapshot.started_at) : NaN;
    const finished = snapshot.stopped_at ? Date.parse(snapshot.stopped_at) : Date.now();
    browserCaptureElapsed.textContent = formatSeconds(Number.isFinite(started) ? Math.max(0, Math.floor((finished - started) / 1000)) : 0);

    browserCaptureDestinationsBody.replaceChildren();
    const destinations = Array.isArray(snapshot.destinations) ? snapshot.destinations : [];
    browserCaptureEmpty.hidden = destinations.length !== 0;
    for (const destination of destinations) {
      const row = element("tr");
      row.appendChild(element("td", "", destination.requested_hostname || t("browser.unknown")));
      row.appendChild(element("td", "", destination.port || "—"));
      const outcome = text(destination.outcome || "unknown");
      row.appendChild(element("td", `capture-outcome-${browserCaptureOutcomeTone(outcome)}`, enumText("browserOutcome", outcome, outcome)));
      row.appendChild(element("td", "", destination.connection_count || 0));
      row.appendChild(element("td", "", (destination.connected_endpoints || []).join(", ") || destination.connected_endpoint || t("browser.notObserved")));
      row.appendChild(element("td", "", destination.failure_reason ? failureText(destination.failure_reason) : t("browser.none")));
      browserCaptureDestinationsBody.appendChild(row);
    }
    if (snapshot.id) {
      browserCaptureJSON.hidden = false;
      browserCaptureJSON.href = `/api/browser-captures/${encodeURIComponent(snapshot.id)}/report.json`;
      browserCaptureFQDNs.hidden = false;
      browserCaptureFQDNs.href = `/api/browser-captures/${encodeURIComponent(snapshot.id)}/fqdns.txt`;
      browserCaptureCopy.hidden = false;
    }
  }

  function formatSeconds(seconds) {
    return `${seconds}${t("browser.seconds")}`;
  }

  function clearBrowserCapturePoll() {
    if (capturePollTimer !== null) {
      clearTimeout(capturePollTimer);
      capturePollTimer = null;
    }
  }

  async function pollBrowserCapture() {
    if (!activeCaptureID) {
      return;
    }
    try {
      const response = await fetch(`/api/browser-captures/${encodeURIComponent(activeCaptureID)}`, { cache: "no-store" });
      const snapshot = await readResponse(response);
      renderBrowserCapture(snapshot);
      if (snapshot.state === "running" || snapshot.state === "starting" || snapshot.state === "stopping") {
        capturePollTimer = setTimeout(() => void pollBrowserCapture(), 750);
      } else {
        clearBrowserCapturePoll();
      }
    } catch (err) {
      showBrowserCaptureError(err instanceof Error ? err.message : t("browser.loadError"));
      capturePollTimer = setTimeout(() => void pollBrowserCapture(), 1500);
    }
  }

  function setSessionState(state) {
    currentSessionState = state;
    renderSessionState(state);
  }

  function renderSessionState(state) {
    const labelKeys = {
      starting: "session.starting",
      running: "session.running",
      cancelling: "session.cancelling",
      completed: "session.completed",
      cancelled: "session.cancelled",
      failed: "session.failed",
      error: "session.requestFailed",
    };
    const label = labelKeys[state] ? t(labelKeys[state]) : enumText("state", state, text(state));
    const tone = state === "completed" ? "positive" : state === "cancelled" ? "warning" : state === "failed" ? "negative" : "neutral";
    runStateLabel.textContent = label;
    runStateBadge.textContent = enumText("state", state, text(state));
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
      throw new Error(body.error || t("session.requestFailedWithStatus", { status: response.status }));
    }
    return body;
  }

  async function loadSessionView(id) {
    const response = await fetch(`/api/diagnoses/${encodeURIComponent(id)}/view`, { cache: "no-store" });
    const view = await readResponse(response);
    if (!view.report || !view.canonical_json) {
      throw new Error(t("session.endedWithoutReport"));
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
      showError(err instanceof Error ? err.message : t("session.reportLoadError"));
    }
    button.disabled = false;
    button.textContent = t("target.diagnoseArrow");
    activeSessionID = "";
  }

  function handleSessionEvent(event) {
    let body;
    try {
      body = JSON.parse(event.data);
    } catch (_) {
      showError(t("session.invalidProgress"));
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
        showError(t("session.progressClosed"));
      }
    };
  }

  function renderProbeBody(probe) {
    const body = element("div", "card-body");
    const metadata = element("div", "metadata");
    metadata.appendChild(metadataItem(t("probe.duration"), `${text(probe.duration_ms)} ${t("common.milliseconds")}`));
    metadata.appendChild(metadataItem(t("probe.layer"), enumText("layer", probe.layer, probe.layer)));
    metadata.appendChild(metadataItem(t("probe.faultDomain"), enumText("faultDomain", probe.fault_domain, probe.fault_domain)));
    body.appendChild(metadata);

    const interpretation = element("p", "interpretation", `${t("probe.reason")}: ${failureText(probe.failure_reason)}`);
    body.appendChild(interpretation);
    if (probe.evidence_ids && probe.evidence_ids.length) {
      const refs = element("div", "card-references");
      refs.appendChild(element("span", "reference-label", t("evidence.structured")));
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
      header.appendChild(badge(enumText("probeStatus", probe.status, sourceText(probe.status_label || probe.status)), badgeTone));
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
    summary.appendChild(badge(enumText("probeStatus", probe.status, sourceText(probe.status_label || probe.status)), badgeTone));
    card.appendChild(summary);
    card.appendChild(renderProbeBody(probe));
    probes.appendChild(card);
  }

  function metadataItem(label, value) {
    const item = element("span", "metadata-item");
    item.appendChild(element("span", "metadata-label", `${label}:`));
    item.appendChild(semanticValueElement(label, value, "metadata-value", "code"));
    return item;
  }

  function renderFinding(finding) {
    const card = element("article", toneClass("finding-card", finding.tone));
    const header = element("div", "card-heading");
    header.appendChild(element("h3", "card-title", failureText(finding.failure_reason, finding.label)));
    header.appendChild(badge(finding.tone === "warning" ? t("finding.review") : t("finding.label"), finding.tone));
    card.appendChild(header);

    const metadata = element("div", "metadata");
    metadata.appendChild(metadataItem(t("finding.reason"), failureText(finding.failure_reason)));
    metadata.appendChild(metadataItem(t("finding.layer"), enumText("layer", finding.layer, finding.layer)));
    metadata.appendChild(metadataItem(t("finding.faultDomain"), enumText("faultDomain", finding.fault_domain, finding.fault_domain)));
    card.appendChild(metadata);
    if (finding.probe_names && finding.probe_names.length) {
      card.appendChild(element("p", "reference-line", `${t("finding.probeLanes")}: ${finding.probe_names.join(", ")}`));
    }
    if (finding.evidence_ids && finding.evidence_ids.length) {
      const refs = element("div", "card-references");
      refs.appendChild(element("span", "reference-label", t("evidence.drill")));
      refs.appendChild(referenceGroup(finding.evidence_ids));
      card.appendChild(refs);
    }
    findings.appendChild(card);
  }

  function renderDestinationStatus(status) {
    const destination = status || {};
    destinationStatusStrip.className = toneClass("destination-status-strip", destinationTone(destination.status));
    destinationStatusLabel.textContent = destinationStateText(destination.status, destination.label).toUpperCase();
    destinationStatusDetail.textContent = destinationDetailText(destination);
    destinationStatusService.textContent = serviceText(destination.requested_service) || t("destination.serviceNotObserved");
    destinationStatusIdentity.textContent = text(destination.requested_identity) || t("destination.identityNotObserved");
    destinationStatusEndpoint.textContent = endpointText(destination.effective_endpoint);
    if (destination.failure_reason && destination.failure_reason !== "none") {
      destinationStatusReason.hidden = false;
      destinationStatusReason.textContent = t("destination.reason", { value: failureText(destination.failure_reason) });
    } else {
      destinationStatusReason.hidden = true;
      destinationStatusReason.textContent = "";
    }
  }

  function destinationStateText(state, fallback) {
    const keys = {
      reachable: "destination.reachable",
      unreachable: "destination.unreachable",
      degraded: "destination.degraded",
      indeterminate: "destination.indeterminate",
    };
    return keys[state] ? t(keys[state]) : sourceText(fallback || state) || text(fallback || state);
  }

  function destinationDetailText(destination) {
    const detail = text(destination.detail);
    if (detail === "") {
      return "";
    }
    const httpStatus = /^HTTP returned (\d+)\.$/.exec(detail);
    if (httpStatus) {
      return t("destination.detail.httpStatus", { code: httpStatus[1] });
    }
    return sourceText(detail) || detail;
  }

  function serviceText(value) {
    const raw = text(value);
    const keys = {
      http: "service.http",
      https: "service.https",
      smb: "service.smb",
      "file sharing (smb)": "service.smb",
      rdp: "service.rdp",
      ssh: "service.ssh",
      dns: "service.dns",
      custom_tcp: "service.customTCP",
      "custom tcp": "service.customTCP",
      custom_tls: "service.customTLS",
      "custom tls": "service.customTLS",
    };
    const key = keys[raw.toLowerCase()];
    return key ? t(key) : raw;
  }

  function failureText(reason, presentationFallback) {
    const raw = text(reason);
    const key = `enum.failure.${raw}`;
    if (translate.has(key)) {
      return t(key);
    }
    return sourceText(presentationFallback) || (presentationFallback ? text(presentationFallback) : raw);
  }

  function renderEndpointObservation(endpoint) {
    endpointObservation.replaceChildren();
    endpointCandidates.replaceChildren();
    if (!endpoint || !endpoint.requested_identity) {
      endpointObservation.appendChild(element("div", "empty-state compact", t("endpoint.noObservation")));
      return;
    }
    appendObservationRows(endpointObservation, [
      [t("endpoint.originalInput"), endpoint.original_input],
      [t("endpoint.requestedIdentity"), endpoint.requested_identity],
      [t("endpoint.literalIP"), endpoint.literal_ip],
      [t("endpoint.service"), endpoint.service && serviceText(endpoint.service.id || endpoint.service.label)],
      [t("endpoint.applicationProtocol"), protocolText(endpoint.application_protocol)],
      [t("endpoint.transportProtocol"), protocolText(endpoint.transport_protocol)],
      [t("endpoint.port"), endpoint.port || t("endpoint.notSpecified")],
      [t("endpoint.resource"), endpoint.resource],
      [t("endpoint.selectedEndpoint"), endpointText(endpoint.selected_endpoint)],
      [t("endpoint.testedEndpoint"), endpointText(endpoint.tested_endpoint)],
      [t("endpoint.certainty"), enumText("certainty", endpoint.certainty, endpoint.certainty)],
      [t("endpoint.provenance"), listText(endpoint.provenance)],
      [t("endpoint.evidence"), referenceValue(endpoint.evidence_ids)],
    ]);
    renderCandidateTable(endpointCandidates, t("endpoint.resolvedCandidates"), endpoint.resolved_candidates);
    renderCandidateTable(endpointCandidates, t("endpoint.probeCandidates"), endpoint.probe_candidates);
    if (endpoint.candidate_attempts && endpoint.candidate_attempts.length) {
      const title = element("h3", "observation-subheading", t("endpoint.candidateAttempts"));
      endpointCandidates.appendChild(title);
      const table = element("table", "observation-grid");
      appendTableHeader(table, [t("endpoint.candidate"), t("endpoint.status"), t("endpoint.failure"), t("endpoint.evidence")]);
      const body = table.querySelector("tbody");
      for (const attempt of endpoint.candidate_attempts) {
        const row = element("tr");
        row.appendChild(element("td", "", endpointText(attempt.candidate)));
        row.appendChild(element("td", "", enumText("probeStatus", attempt.status, attempt.status)));
        row.appendChild(element("td", "", attempt.failure_reason ? failureText(attempt.failure_reason) : t("common.none")));
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
    appendTableHeader(table, [t("endpoint.address"), t("endpoint.family"), t("endpoint.order"), t("endpoint.certainty"), t("endpoint.provenance"), t("endpoint.evidence")]);
    const body = table.querySelector("tbody");
    for (const candidate of candidates) {
      const row = element("tr");
      row.appendChild(element("td", "", candidate.address));
      row.appendChild(element("td", "", candidate.family));
      row.appendChild(element("td", "", candidate.order));
      row.appendChild(element("td", "", candidate.certainty ? enumText("certainty", candidate.certainty, candidate.certainty) : t("common.unknown")));
      row.appendChild(element("td", "", candidate.provenance || t("common.notSpecified")));
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
      [t("application.applicability"), "applicability", (value) => enumText("applicability", value, value)],
      [t("application.requestedEndpoint"), "requested_endpoint"],
      [t("application.probeEndpoint"), "probe_endpoint", endpointText],
      [t("application.testedEndpoint"), "tested_endpoint", endpointText],
      [t("application.connectionOutcome"), "connection_outcome", (value) => enumText("transportOutcome", value, value)],
      [t("application.connected"), "connected", booleanText],
      [t("application.localEndpoint"), "local_endpoint"],
      [t("application.remoteEndpoint"), "remote_endpoint", endpointText],
      [t("application.failureReason"), "failure_reason", failureText],
      [t("application.faultDomain"), "fault_domain", (value) => enumText("faultDomain", value, value)],
      [t("application.certainty"), "certainty", (value) => enumText("certainty", value, value)],
      [t("application.limitations"), "limitations", listText],
      [t("application.evidence"), "evidence_ids", referenceValue],
    ]);
  }

  function renderSecurityObservation(observation) {
    renderObservationOrEmpty(securityObservation, observation, [
      [t("application.applicability"), "applicability", (value) => enumText("applicability", value, value)],
      [t("application.attempted"), "attempted", booleanText],
      [t("application.handshakeComplete"), "handshake_complete", booleanText],
      [t("application.tlsVersion"), "tls_version"],
      [t("application.cipherSuite"), "cipher_suite"],
      [t("application.negotiatedProtocol"), "negotiated_protocol"],
      [t("application.serverName"), "server_name"],
      [t("application.endpointUsed"), "endpoint_used", endpointText],
      [t("application.certificateValidation"), "certificate_validation", (value) => enumText("certificateValidation", value, value)],
      [t("application.peerCertificates"), "peer_certificate_count"],
      [t("application.failureReason"), "failure_reason", failureText],
      [t("application.faultDomain"), "fault_domain", (value) => enumText("faultDomain", value, value)],
      [t("application.certainty"), "certainty", (value) => enumText("certainty", value, value)],
      [t("application.limitations"), "limitations", listText],
      [t("application.evidence"), "evidence_ids", referenceValue],
    ]);
    if (observation && observation.applicability && observation.certificates && observation.certificates.length) {
      renderCertificateTable(securityObservation, observation.certificates);
    }
    if (observation && observation.tls_inspection) {
      renderTLSInspectionAssessment(securityObservation, observation.tls_inspection);
    }
  }

  function renderTLSInspectionAssessment(container, assessment) {
    container.appendChild(element("h3", "observation-subheading", "TLS inspection assessment"));
    appendObservationRows(container, [
      ["Assessment", assessment.state || "unknown"],
      ["Assessment certainty", assessment.certainty || "unknown"],
      ["Requested hostname", assessment.requested_hostname],
      ["Presented leaf subject", assessment.presented_leaf_subject],
      ["Presented leaf SANs", listText(assessment.presented_leaf_sans)],
      ["Presented leaf issuer", assessment.presented_leaf_issuer],
      ["Presented issuer chain", listText(assessment.presented_issuer_chain)],
      ["Certificate validation", assessment.certificate_validation || "unknown"],
      ["Locally trusted", assessment.local_trust_known ? booleanText(assessment.locally_trusted) : "unknown"],
      ["Trusted corporate/private root", assessment.trusted_corporate_private_root_known ? booleanText(assessment.trusted_corporate_private_root) : "unknown"],
      ["Enterprise proxy observed", assessment.enterprise_proxy_known ? booleanText(assessment.enterprise_proxy_observed) : "unknown"],
      ["Enterprise policy observed", assessment.enterprise_policy_known ? booleanText(assessment.enterprise_policy_observed) : "unknown"],
      ["Origin comparison", assessment.chain_divergence_known ? booleanText(assessment.chain_diverges) : "unknown"],
      ["Origin leaf SHA-256", assessment.origin_leaf_sha256],
      ["Presented leaf SHA-256", assessment.presented_leaf_sha256],
      ["Issuer changed", assessment.issuer_change_known ? booleanText(assessment.issuer_changed) : "unknown"],
      ["Signals", listText(assessment.signals)],
      ["Limitations", listText(assessment.limitations)],
      ["Provenance", listText(assessment.provenance)],
      ["Evidence", referenceValue(assessment.evidence_ids)],
    ]);
    const note = element("p", "section-note", "Proxy configuration, local trust, or an unfamiliar issuer alone does not establish inspection.");
    container.appendChild(note);
  }

  function renderCertificateTable(container, certificates) {
    container.appendChild(element("h3", "observation-subheading", t("application.peerCertificates")));
    const table = element("table", "observation-grid certificate-table");
    appendTableHeader(table, [t("application.chain"), t("application.certificateSubject"), t("application.certificateIssuer"), t("application.certificateValidity"), t("application.certificateSerial"), t("application.certificateSHA256")]);
    const body = table.querySelector("tbody");
    for (const certificate of certificates) {
      const row = element("tr");
      row.appendChild(element("td", "", certificate.chain_index));
      row.appendChild(semanticTableCell(t("application.certificateSubject"), certificate.subject || t("common.notObserved")));
      row.appendChild(semanticTableCell(t("application.certificateIssuer"), certificate.issuer || t("common.notObserved")));
      const validity = [certificate.not_before, certificate.not_after].filter(Boolean).join(" → ") || t("common.notObserved");
      row.appendChild(semanticTableCell(t("application.certificateValidity"), validity));
      row.appendChild(semanticTableCell(t("application.certificateSerial"), certificate.serial_number || t("common.notObserved")));
      row.appendChild(semanticTableCell(t("application.certificateSHA256"), certificate.sha256 || t("common.notObserved")));
      body.appendChild(row);
    }
    container.appendChild(table);
  }

  function semanticTableCell(label, value) {
    const cell = element("td");
    cell.appendChild(semanticValueElement(label, value));
    return cell;
  }

  function renderApplicationObservation(observation) {
    applicationObservation.replaceChildren();
    if (!observation) {
      applicationObservation.appendChild(element("div", "empty-state compact", t("application.noObservation")));
      return;
    }

    const protocol = text(observation.protocol || "unknown").toLowerCase();
    const commonRows = [
      [t("application.applicability"), enumText("applicability", observation.applicability || "unknown")],
      [t("application.protocol"), protocolText(protocol)],
      [t("application.requestAttempted"), booleanText(observation.request_attempted)],
      [t("application.responseReceived"), booleanText(observation.response_received)],
      [t("application.transportConnected"), booleanText(observation.transport_connected)],
      [t("application.handshakeAttempted"), booleanText(observation.handshake_attempted)],
      [t("application.handshakeComplete"), booleanText(observation.handshake_complete)],
      [t("application.result"), enumText("result", observation.result || "unknown")],
      [t("application.protocolResult"), enumText("protocolResult", observation.protocol_result || "unknown")],
      [t("application.endpointUsed"), endpointText(observation.endpoint_used)],
      [t("application.requestedResource"), observation.requested_resource || t("common.notSpecified")],
      [t("application.failureReason"), failureText(observation.failure_reason || "none")],
      [t("application.faultDomain"), enumText("faultDomain", observation.fault_domain || "unknown")],
      [t("application.certainty"), enumText("certainty", observation.certainty || "unknown")],
      [t("application.limitations"), listText(observation.limitations)],
    ];
    appendObservationRows(applicationObservation, commonRows);

    if (protocol === "http" || protocol === "https" || observation.http) {
      renderHTTPApplication(applicationObservation, observation.http || observation);
    } else if (protocol === "dns" || observation.dns) {
      renderDNSApplication(applicationObservation, observation.dns);
    } else if (protocol === "smb" || observation.smb) {
      renderSMBApplication(applicationObservation, observation.smb);
    } else if (protocol === "ssh" || observation.ssh) {
      renderProtocolApplication(applicationObservation, t("application.sshHandshake"), observation.ssh || observation, false);
    } else if (protocol === "rdp" || observation.rdp) {
      renderProtocolApplication(applicationObservation, t("application.rdpNegotiation"), observation.rdp || observation, true);
    } else {
      applicationObservation.appendChild(element("h3", "observation-subheading", t("application.serviceView")));
      appendObservationRows(applicationObservation, [[t("policy.state"), t("application.unsupportedOrNotAttempted")]]);
    }
    renderApplicationReferences(applicationObservation, observation);
  }

  function renderHTTPApplication(container, http) {
    container.appendChild(element("h3", "observation-subheading", t("application.httpResponse")));
    appendObservationRows(container, [
      [t("application.httpVersion"), http.http_version || t("common.notObserved")],
      [t("application.statusCode"), http.status_code || t("common.notObserved")],
      [t("application.status"), http.status || t("common.notObserved")],
      [t("application.url"), http.url || t("common.notObserved")],
      [t("application.resource"), http.requested_resource || t("common.notSpecified")],
    ]);
    const redirects = http.redirects || [];
    container.appendChild(element("h3", "observation-subheading", t("application.redirects")));
    if (!redirects.length) {
      appendObservationRows(container, [[t("application.redirectChain"), t("application.noneObserved")] ]);
      return;
    }
    const table = element("table", "observation-grid");
    appendTableHeader(table, [t("application.status"), t("application.from"), t("application.location"), t("application.to")]);
    const body = table.querySelector("tbody");
    for (const redirect of redirects) {
      const row = element("tr");
      row.appendChild(element("td", "", redirect.status_code || "unknown"));
      row.appendChild(element("td", "", redirect.url || t("common.notObserved")));
      row.appendChild(element("td", "", redirect.location || t("common.notObserved")));
      row.appendChild(element("td", "", redirect.to_url || t("common.notObserved")));
      body.appendChild(row);
    }
    container.appendChild(table);
  }

  function renderDNSApplication(container, dns) {
    container.appendChild(element("h3", "observation-subheading", t("application.dnsResponse")));
    if (!dns) {
      appendObservationRows(container, [[t("policy.state"), t("common.notAttempted")]]);
      return;
    }
    appendObservationRows(container, [
      [t("application.query"), `${dns.query_name || t("common.unknown")} (${dns.query_type || t("common.unknown")})`],
      [t("application.requestedEndpoint"), dns.requested_endpoint || t("common.notObserved")],
      [t("application.result"), enumText("result", dns.result || "unknown")],
      [t("application.responseReceived"), booleanText(dns.response_received)],
      [t("application.divergence"), booleanText(dns.divergence)],
      [t("application.failureReason"), failureText(dns.failure_reason || "none")],
      [t("application.certainty"), enumText("certainty", dns.certainty || "unknown")],
      [t("application.limitations"), listText(dns.limitations)],
    ]);
    const table = element("table", "observation-grid");
    appendTableHeader(table, [t("application.lane"), t("application.attempted"), t("application.response"), t("application.outcome"), t("application.rcode"), t("application.truncated"), t("application.fallback"), t("application.provenance"), t("application.evidence")]);
    const body = table.querySelector("tbody");
    const lanes = [
      dns.udp || { transport: "udp" },
      dns.tcp || { transport: "tcp" },
    ];
    for (const lane of lanes) {
      const row = element("tr");
      const fallback = lane.fallback ? `${t("common.yes")}${lane.fallback_reason ? ` · ${lane.fallback_reason}` : ""}` : t("common.no");
      row.appendChild(element("td", "", text(lane.transport || "unknown").toUpperCase()));
      row.appendChild(element("td", "", booleanText(lane.attempted)));
      row.appendChild(element("td", "", booleanText(lane.response_received)));
      row.appendChild(element("td", "", enumText("result", lane.outcome || "not_attempted")));
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
    return lane.rcode === undefined || lane.rcode === null ? t("common.notObserved") : text(lane.rcode);
  }

  function renderSMBApplication(container, smb) {
    container.appendChild(element("h3", "observation-subheading", t("application.smbNegotiation")));
    if (!smb) {
      appendObservationRows(container, [[t("policy.state"), t("common.notAttempted")]]);
      return;
    }
    appendObservationRows(container, [
      [t("application.negotiationResult"), enumText("result", smb.result || "unknown")],
      [t("application.negotiated"), booleanText(smb.negotiated)],
      [t("application.dialect"), smb.dialect || t("common.notObserved")],
      [t("application.dialectRevision"), smb.dialect_revision || t("common.notObserved")],
      [t("application.capabilities"), listText(smb.capabilities)],
      [t("application.serverGUID"), smb.server_guid || t("application.notExposed")],
      [t("application.securityMode"), smb.security_mode || t("application.notExposed")],
      [t("application.maxTransact"), smb.max_transact_size || t("application.notExposed")],
      [t("application.maxRead"), smb.max_read_size || t("application.notExposed")],
      [t("application.maxWrite"), smb.max_write_size || t("application.notExposed")],
      [t("application.responseBytes"), smb.response_bytes || t("common.notObserved")],
    ]);
  }

  function renderProtocolApplication(container, heading, protocol, rdp) {
    container.appendChild(element("h3", "observation-subheading", heading));
    appendObservationRows(container, [
      [t("application.handshakeAttempted"), booleanText(protocol.handshake_attempted)],
      [t("application.handshakeComplete"), booleanText(protocol.handshake_complete)],
      [t("application.responseReceived"), booleanText(protocol.response_received)],
      [t("application.transportConnected"), booleanText(protocol.transport_connected)],
      [t("application.result"), enumText("protocolResult", protocol.result || "unknown")],
      [t("application.serverIdentification"), protocol.server_identification || t("common.notObserved")],
      [t("application.negotiatedSecurity"), rdp ? (protocol.negotiated_security_protocol || t("application.notNegotiated")) : t("common.notApplicable")],
      [t("application.requestedSecurity"), rdp ? listText(protocol.requested_security_protocols) : t("common.notApplicable")],
    ]);
  }

  function renderApplicationReferences(container, observation) {
    container.appendChild(element("h3", "observation-subheading", t("application.applicationProvenance")));
    appendObservationRows(container, [
      [t("application.provenance"), listText(observation.provenance)],
      [t("application.probeLanes"), listText(observation.probe_names)],
      [t("application.evidence"), referenceValue(observation.evidence_ids)],
    ]);
  }

  function renderPolicyObservation(observation) {
    policyObservation.replaceChildren();
    if (!observation || (!observation.requested_identity && !observation.state && !(observation.paths || []).length)) {
      policyObservation.appendChild(element("div", "empty-state compact", t("policy.noObservation")));
      return;
    }
    appendObservationRows(policyObservation, [
      [t("policy.requestedIdentity"), observation.requested_identity],
      [t("policy.state"), observation.state],
      [t("policy.unsupported"), booleanText(observation.unsupported)],
      [t("policy.proxyDiverges"), booleanText(observation.proxy_configuration_diverges)],
      [t("policy.divergenceKnown"), booleanText(observation.proxy_configuration_divergence_known)],
      ["Effective decision diverges", booleanText(observation.effective_decision_diverges)],
      ["Effective decision divergence known", booleanText(observation.effective_decision_divergence_known)],
      [t("policy.directVsProxy"), comparisonText(observation.direct_vs_proxy)],
      [t("policy.firewall"), observation.firewall && observation.firewall.state],
      [t("policy.tlsPolicy"), observation.tls && observation.tls.state],
      [t("policy.directCertificateIssuer"), observation.tls && observation.tls.direct_certificate_issuer],
      [t("policy.proxyCertificateIssuer"), observation.tls && observation.tls.proxy_certificate_issuer],
      [t("policy.issuersDiffer"), observation.tls && (observation.tls.issuers_differ_known ? booleanText(observation.tls.issuers_differ) : "unknown")],
      [t("policy.possibleInterception"), observation.tls && booleanText(observation.tls.possible_interception)],
      [t("policy.interceptionSuspicion"), observation.tls && observation.tls.interception_suspicion],
      [t("policy.certainty"), enumText("certainty", observation.certainty, observation.certainty)],
      [t("policy.provenance"), listText(observation.provenance)],
      [t("policy.evidence"), referenceValue(observation.evidence_ids)],
    ]);

    renderProxySource(policyObservation, t("policy.winHTTP"), observation.winhttp);
    renderProxySource(policyObservation, t("policy.winINET"), observation.wininet);
    if (observation.paths && observation.paths.length) {
      policyObservation.appendChild(element("h3", "observation-subheading", t("policy.paths")));
      const table = element("table", "observation-grid");
      appendTableHeader(table, [t("policy.path"), t("policy.mode"), t("policy.endpoint"), t("policy.tcp"), "CONNECT", t("policy.http"), t("policy.tls"), t("policy.failure"), t("policy.evidence")]);
      const body = table.querySelector("tbody");
      for (const path of observation.paths) {
        const row = element("tr");
        row.appendChild(element("td", "", path.name));
        row.appendChild(element("td", "", path.mode));
        row.appendChild(element("td", "", path.endpoint || t("common.notSpecified")));
        row.appendChild(element("td", "", booleanText(path.tcp_connected)));
        row.appendChild(element("td", "", path.connect_outcome || "not tested"));
        row.appendChild(element("td", "", path.http_response ? text(path.http_status_code || t("policy.received")) : t("common.no")));
        row.appendChild(element("td", "", booleanText(path.tls_handshake)));
        row.appendChild(element("td", "", path.failure_reason ? failureText(path.failure_reason) : t("common.none")));
        row.appendChild(referenceCell(path.evidence_ids));
        body.appendChild(row);
      }
      policyObservation.appendChild(table);
    }
    if (observation.firewall && observation.firewall.profiles && observation.firewall.profiles.length) {
      policyObservation.appendChild(element("h3", "observation-subheading", t("policy.firewallProfiles")));
      const table = element("table", "observation-grid");
      appendTableHeader(table, [t("policy.profile"), t("policy.enabled"), t("policy.policyPresent"), t("policy.causality"), t("policy.evidence")]);
      const body = table.querySelector("tbody");
      for (const profile of observation.firewall.profiles) {
        const row = element("tr");
        row.appendChild(element("td", "", profile.name));
        row.appendChild(element("td", "", profile.firewall_enabled === undefined ? t("common.unknown") : booleanText(profile.firewall_enabled)));
        row.appendChild(element("td", "", booleanText(profile.policy_present)));
        row.appendChild(element("td", "", profile.block_causality || t("policy.notEstablished")));
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
      [t("policy.source"), source.source],
      [t("policy.configuration"), source.configuration && source.configuration.state],
      [t("policy.configuredEndpoints"), source.configuration && listText(source.configuration.proxy_endpoints)],
      ["PAC URL", source.configuration && source.configuration.pac_url],
      ["Bypass patterns", source.configuration && listText(source.configuration.proxy_bypass)],
      [t("policy.pacConfigured"), source.configuration && booleanText(source.configuration.pac_configured)],
      ["Effective decision", source.effective && source.effective.decision],
      ["Effective result observed", source.effective && booleanText(source.effective.observed)],
      ["Resolution attempted", source.effective && booleanText(source.effective.resolution_attempted)],
      ["Bypass matched", source.effective && booleanText(source.effective.bypass_matched)],
      [t("policy.effectiveMode"), source.effective && source.effective.mode],
      [t("policy.effectiveEndpoint"), source.effective && source.effective.endpoint],
      [t("policy.effectiveResolution"), source.effective && booleanText(source.effective.resolution_ok)],
      [t("policy.pacUsed"), source.effective && booleanText(source.effective.pac_used)],
      ["PAC decision", source.pac && source.pac.decision],
      [t("policy.evidence"), referenceValue(source.evidence_ids)],
    ]);

    if (source.endpoint_reachability && source.endpoint_reachability.length) {
      const table = element("table", "observation-grid");
      appendTableHeader(table, ["Proxy endpoint", "Reachability", "CONNECT", "Status", "Evidence"]);
      const body = table.querySelector("tbody");
      for (const endpoint of source.endpoint_reachability) {
        const row = element("tr");
        row.appendChild(element("td", "", endpoint.endpoint || "not observed"));
        row.appendChild(element("td", "", endpoint.reachability || "unknown"));
        row.appendChild(element("td", "", endpoint.connect_outcome || "not tested"));
        row.appendChild(element("td", "", endpoint.status_code || "not observed"));
        row.appendChild(referenceCell(endpoint.evidence_ids));
        body.appendChild(row);
      }
      container.appendChild(table);
    }
  }

  function comparisonText(comparison) {
    if (!comparison) {
      return t("common.notObserved");
    }
    return comparison.state || "unknown";
  }

  function renderObservationOrEmpty(container, observation, fields) {
    container.replaceChildren();
    if (!observation || !observation.applicability) {
      container.appendChild(element("div", "empty-state compact", t("common.noObservation")));
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
        row.appendChild(semanticValueElement(label, value, "observation-value"));
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
      cell.textContent = t("evidence.notAvailable");
    }
    return cell;
  }

  function referenceValue(ids) {
    if (!ids || !ids.length) {
      return t("evidence.notAvailable");
    }
    return referenceGroup(ids);
  }

  function endpointText(endpoint) {
    if (!endpoint) {
      return t("common.notObserved");
    }
    if (typeof endpoint === "string") {
      return endpoint;
    }
    if (!endpoint.address) {
      return t("common.notObserved");
    }
    const address = endpoint.address.includes(":") && endpoint.port ? `[${endpoint.address}]` : endpoint.address;
    return endpoint.port ? `${address}:${endpoint.port}` : address;
  }

  function booleanText(value) {
    return value ? t("common.yes") : t("common.no");
  }

  function redirectText(values) {
    if (!values || !values.length) {
      return t("common.none");
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
      [t("resolution.requestedName"), resolution.requested_name || t("resolution.notObservable")],
      [t("resolution.path"), resolutionPathText(effective)],
      [t("resolution.interface"), effective.interface || t("resolution.notObservable")],
      [t("resolution.resolver"), effective.resolver || t("resolution.notObservable")],
      [t("resolution.policy"), policyText(effective)],
      [t("resolution.answersA"), listText(resolution.a)],
      [t("resolution.answersAAAA"), listText(resolution.aaaa)],
      [t("resolution.representative"), resolution.selected_address || t("resolution.notSelected")],
      [t("resolution.certainty"), effective.certainty ? enumText("certainty", effective.certainty, effective.certainty) : t("resolution.notObservable")],
    ];
    const table = element("div", "resolution-table");
    for (const [label, value] of fields) {
      const row = element("div", "resolution-row");
      row.appendChild(element("span", "resolution-label", label));
      row.appendChild(semanticValueElement(label, value, "resolution-value"));
      table.appendChild(row);
    }
    nameResolution.appendChild(table);

    if (resolution.candidate_names && resolution.candidate_names.length) {
      nameResolution.appendChild(resolutionMetadata(t("resolution.candidateNames"), resolution.candidate_names.join(", ")));
    }
    if (resolution.candidate_suffixes && resolution.candidate_suffixes.length) {
      nameResolution.appendChild(resolutionMetadata(t("resolution.suffixes"), resolution.candidate_suffixes.join(", ")));
    }
    if (resolution.candidate_namespaces && resolution.candidate_namespaces.length) {
      nameResolution.appendChild(resolutionMetadata(t("resolution.namespaces"), resolution.candidate_namespaces.join(", ")));
    }
    if (effective.provenance) {
      nameResolution.appendChild(resolutionMetadata(t("resolution.provenance"), effective.provenance));
    }
    if (resolution.limitations && resolution.limitations.length) {
      nameResolution.appendChild(resolutionMetadata(t("resolution.limitations"), resolution.limitations.map(sourceText).join(" · ")));
    }

    const candidates = (resolution.paths || []).filter((path) => path.state !== "effective");
    if (candidates.length) {
      const details = element("details", "resolution-candidates");
      details.open = true;
      details.appendChild(element("summary", "", quantity("resolution.configuredCandidatesOne", "resolution.configuredCandidatesMany", candidates.length)));
      const list = element("div", "resolution-candidate-list");
      for (const path of candidates) {
        const row = element("div", "resolution-candidate");
        row.appendChild(element("span", "resolution-candidate-state", enumText("resolutionState", path.state, path.state || t("common.unknown"))));
        const description = [
          path.resolver || t("resolution.resolverNotObservable"),
          path.interface || t("resolution.interfaceNotObservable"),
          path.namespace || (path.namespaces && path.namespaces.length ? path.namespaces.join(", ") : t("resolution.noNamespace")),
          path.certainty ? enumText("certainty", path.certainty, path.certainty) : t("resolution.certaintyUnknown"),
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
      refs.appendChild(element("span", "reference-label", t("resolution.evidence")));
      refs.appendChild(referenceGroup(resolution.evidence_ids));
      nameResolution.appendChild(refs);
    }
  }

  function listText(values) {
    return values && values.length ? values.join(", ") : t("common.none");
  }

  function policyText(path) {
    const values = [path.namespace, path.policy_source, path.policy_rule].filter(Boolean);
    return values.length ? values.join(" / ") : t("common.notObserved");
  }

  function resolutionPathText(path) {
    if (!path || !path.mechanism) {
      return t("common.notObserved");
    }
    return enumText("resolutionMechanism", path.mechanism, sourceText(path.label || path.mechanism));
  }

  function resolutionMetadata(label, value) {
    const row = element("p", "resolution-metadata");
    row.appendChild(element("span", "resolution-label", label));
    row.appendChild(semanticValueElement(label, value, "resolution-value"));
    return row;
  }

  function destinationTone(state) {
    switch (state) {
      case "reachable":
        return "positive";
      case "unreachable":
        return "negative";
      case "degraded":
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
      details.push(t("path.destination"));
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
    heading.appendChild(element("h3", "card-title", `${index + 1}. ${protocolText(path.protocol).toUpperCase()} ${t("path.observation")}`));
    heading.appendChild(element("p", "path-endpoint", `${text(path.destination)} · ${portText(path.destination_port)}`));
    header.appendChild(heading);
    header.appendChild(element("span", toneClass("observation-status", path.observation_tone), enumText("pathStatus", path.observation_status, sourceText(path.observation_status || "unknown"))));
    card.appendChild(header);

    const pathNote = element("p", "path-note", observationNote(path));
    card.appendChild(pathNote);

    const destination = element("div", "path-destination");
    destination.appendChild(element("span", "destination-marker", "◆"));
    const destinationCopy = element("div");
    destinationCopy.appendChild(element("strong", "destination-title", t("path.destinationObservation")));
    destinationCopy.appendChild(element("span", "destination-copy", `${t("path.reached", { value: booleanText(path.destination_reached) })} · ${t("path.tcpConnectedDetail", { value: booleanText(path.destination_tcp_connected) })}`));
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
      card.appendChild(element("div", "empty-state compact", t("path.noTTLOsservations")));
    }

    if (path.segments && path.segments.length) {
      const segmentDetails = element("details", "segment-details");
      const summary = element("summary", "segment-summary", t("path.evidenceSegments"));
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
    node.appendChild(element("strong", "node-title", t("path.probeVantage")));
    node.appendChild(element("span", "node-detail", t("path.localSourceDetail")));
    return node;
  }

  function renderHop(hop, evidenceId) {
    const button = element("button", toneClass("track-node hop-node", hop.tone));
    button.type = "button";
    button.dataset.evidenceId = text(evidenceId);
    button.title = t("path.focusRaw");
    button.appendChild(element("span", "node-marker", t("path.ttl", { value: hop.ttl })));
    const copy = element("span", "node-copy");
    copy.appendChild(element("strong", "node-title", pathHopLabel(hop)));
    copy.appendChild(element("span", "node-detail", pathHopDetail(hop)));
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
    node.appendChild(element("strong", "node-title", t("path.destination")));
    node.appendChild(element("span", "node-detail", `${t("path.reached", { value: booleanText(path.destination_reached) })} · ${t("path.tcpConnectedDetail", { value: booleanText(path.destination_tcp_connected) })}`));
    return node;
  }

  function renderSegment(segment, evidenceId) {
    const button = element("button", toneClass("segment-row", segment.tone));
    button.type = "button";
    button.dataset.evidenceId = text(evidenceId);
    const ttl = segment.from_ttl === segment.to_ttl ? t("path.ttl", { value: segment.from_ttl }) : t("path.ttlRange", { from: segment.from_ttl, to: segment.to_ttl });
    button.appendChild(element("span", "segment-range", ttl));
    const copy = element("span", "segment-copy");
    copy.appendChild(element("strong", "segment-title", pathSegmentLabel(segment)));
    copy.appendChild(element("span", "segment-detail", pathSegmentDetail(segment)));
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
      return t("path.noteUnsupported");
    }
    if (path.observation_status === "error") {
      return t("path.noteError");
    }
    if (path.port_aware) {
      return t("path.notePortAware", { port: portText(path.destination_port) });
    }
    return path.protocol === "icmp"
      ? t("path.noteICMP")
      : t("path.noteNotPortAware");
  }

  function pathHopLabel(hop) {
    return enumText("hopState", hop.state, sourceText(hop.label || hop.state));
  }

  function pathHopDetail(hop) {
    if (hop.state === "observed") {
      return t("source.hopObserved");
    }
    if (hop.state === "unobservable") {
      return t("source.hopUnobservable", { ttl: hop.ttl });
    }
    return sourceText(hop.detail) || text(hop.detail);
  }

  function pathSegmentLabel(segment) {
    return enumText("segment", segment.kind, sourceText(segment.label || segment.kind));
  }

  function pathSegmentDetail(segment) {
    const keys = {
      observed_responder: "source.segmentObserved",
      inferred: "source.segmentInferred",
      unobservable: "source.segmentUnobservable",
    };
    if (keys[segment.kind]) {
      return t(keys[segment.kind]);
    }
    return sourceText(segment.detail) || text(segment.detail);
  }

  function transportText(value) {
    const raw = text(value);
    const keys = { tcp: "target.tcp", udp: "target.udp", "udp+tcp": "target.udpTCP" };
    return keys[raw.toLowerCase()] ? t(keys[raw.toLowerCase()]) : raw;
  }

  function portText(port) {
    return port ? `${t("path.portWord")} ${text(port)}` : t("path.portUnspecified");
  }

  function renderComparison(comparison) {
    const card = element("article", "comparison-card");
    const header = element("div", "card-heading");
    header.appendChild(element("h3", "card-title", `${comparison.destination} · ${portText(comparison.destination_port)}`));
    header.appendChild(element("span", "count-label", t("path.observationsCount", { count: (comparison.observations || []).length })));
    card.appendChild(header);

    const summary = element("div", "comparison-summary");
    summary.appendChild(comparisonSignal(t("comparison.icmpDestination"), comparison.icmp_destination_reached, t("comparison.replied"), t("comparison.notConfirmed")));
    summary.appendChild(comparisonSignal(t("comparison.tcpDestination"), comparison.tcp_destination_connected, t("comparison.connected"), comparison.tcp_destination_reached ? t("comparison.reachedNotConnected") : t("comparison.notConfirmed")));
    card.appendChild(summary);

    const table = element("table", "comparison-table");
    const head = element("thead");
    const headerRow = element("tr");
    for (const label of [t("comparison.protocol"), t("comparison.observation"), t("comparison.portAware"), t("comparison.destinationReached"), t("comparison.tcpConnected"), t("comparison.ttlResponders"), t("comparison.evidence")]) {
      headerRow.appendChild(element("th", "", label));
    }
    head.appendChild(headerRow);
    table.appendChild(head);
    const body = element("tbody");
    for (const observation of comparison.observations || []) {
      const row = element("tr");
      row.appendChild(element("td", "protocol-cell", protocolText(observation.protocol).toUpperCase()));
      row.appendChild(element("td", "", enumText("pathStatus", observation.status, observation.status)));
      row.appendChild(element("td", "", booleanText(observation.port_aware)));
      row.appendChild(element("td", "", booleanText(observation.destination_reached)));
      row.appendChild(element("td", "", booleanText(observation.destination_tcp_connected)));
      const hops = [];
      if (observation.responder_count) {
        hops.push(t("path.responders", { count: observation.responder_count, plural: observation.responder_count === 1 ? "" : "s" }));
      }
      if (observation.unobservable_ttls && observation.unobservable_ttls.length) {
        hops.push(t("path.unobservableTTLs", { count: observation.unobservable_ttls.length, plural: observation.unobservable_ttls.length === 1 ? "" : "s" }));
      }
      row.appendChild(element("td", "", hops.join(" · ") || t("path.noHopDetail")));
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
    header.appendChild(badge(enumText("evidenceKind", item.kind, item.kind), item.inspector_state === "partial" ? "warning" : "neutral"));
    card.appendChild(header);

    const metadata = element("div", "metadata");
    metadata.appendChild(metadataItem(t("evidence.source"), item.source || t("common.notSpecified")));
    metadata.appendChild(metadataItem(t("evidence.shape"), item.structured ? t("evidence.structuredJSON") : t("evidence.rawJSON")));
    if (item.captured_at) {
      metadata.appendChild(metadataItem(t("evidence.captured"), item.captured_at));
    }
    card.appendChild(metadata);
    if (item.inspector_note) {
      card.appendChild(element("p", "evidence-note warning-text", sourceText(item.inspector_note) || item.inspector_note));
    }
    const details = element("details", "raw-details");
    details.open = true;
    details.appendChild(element("summary", "", t("evidence.rawValue")));
    const raw = element("pre", "raw-evidence");
    // textContent is intentional: raw evidence is never interpreted as markup.
    raw.textContent = jsonText(item.raw);
    details.appendChild(raw);
    card.appendChild(details);
    evidence.appendChild(card);
  }

  function renderView(view) {
    currentView = view;
    clearPathSelection();
    evidenceHeading.textContent = t("evidence.structured");
    const overall = view.overall || {};
    const observations = view.observations || {};
    diagnosisLabel.textContent = diagnosisLabelText(overall, view.findings);
    diagnosisDetail.textContent = diagnosisDetailText(overall);
    diagnosisCard.className = toneClass("overview-card panel", overall.tone);
    overallStatus.textContent = enumText("reportStatus", overall.execution_status, sourceText(overall.execution_label || overall.execution_status));
    renderTargetDetails(observations.endpoint || (view.report && view.report.target));
    renderEndpointObservation(observations.endpoint);
    renderOperationalObservations(observations, view.application);
    renderPolicyObservation(observations.enterprise_policy);
    renderNetworkContext(observations.network_context || view.network_context);
    renderDestinationStatus(overall.destination || {});
    renderNameResolution(observations.name_resolution || view.name_resolution);

    probes.replaceChildren();
    const probeViews = view.probes || [];
    probeCount.textContent = t("probe.lanes", { count: probeViews.length, plural: probeViews.length === 1 ? "" : "s" });
    for (const [index, probe] of probeViews.entries()) {
      renderProbe(probe, index);
    }
    if (!probeViews.length) {
      probes.appendChild(element("div", "empty-state", t("probe.none")));
    }

    findings.replaceChildren();
    const findingViews = view.findings || [];
    for (const finding of findingViews) {
      renderFinding(finding);
    }
    if (!findingViews.length) {
      findings.appendChild(element("div", "empty-state", t("finding.none")));
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
      comparisons.appendChild(element("div", "empty-state", t("comparison.none")));
    }

    evidence.replaceChildren();
    const evidenceViews = view.evidence || [];
    evidenceHeading.textContent = quantity("evidence.itemOne", "evidence.itemMany", evidenceViews.length);
    for (const item of evidenceViews) {
      renderEvidenceItem(item);
    }
    if (!evidenceViews.length) {
      evidence.appendChild(element("div", "empty-state", t("evidence.none")));
    }
    canonicalJSON.textContent = view.canonical_json || jsonText(view.report);
    renderExportLinks(activeSessionID || renderedSessionID);
    reportSection.hidden = false;
  }

  function renderExportLinks(sessionID) {
    if (sessionID) {
      renderedSessionID = sessionID;
    }
    const reportSessionID = sessionID || renderedSessionID;
    const hasSession = Boolean(reportSessionID);
    htmlReportLink.hidden = !hasSession;
    jsonReportLink.hidden = !hasSession;
    if (!hasSession) {
      htmlReportLink.removeAttribute("href");
      jsonReportLink.removeAttribute("href");
      return;
    }
    const encodedID = encodeURIComponent(reportSessionID);
    htmlReportLink.href = `/api/diagnoses/${encodedID}/report.html`;
    jsonReportLink.href = `/api/diagnoses/${encodedID}/report.json`;
  }

  function renderNetworkContext(context) {
    networkContext.replaceChildren();
    const available = context && (context.requested_identity || context.selected_destination_address || context.network_scope || context.effective_route || (context.provenance && context.provenance.length) || (context.evidence_ids && context.evidence_ids.length));
    networkContextPanel.hidden = !available;
    if (!available) {
      return;
    }
    const fields = [
      [t("network.scope"), enumText("scope", context.network_scope, sourceText(context.network_scope_label || context.network_scope))],
      [t("network.requestedIdentity"), context.requested_identity],
      [t("network.selectedDestination"), context.selected_destination_address],
      [t("network.sourceInterface"), context.selected_source_interface],
      [t("network.sourceAddress"), context.selected_source_address],
      [t("network.route"), enumText("route", context.effective_route, sourceText(context.effective_route_label || context.effective_route))],
      [t("network.routePrefix"), context.route_prefix],
      [t("network.nextHop"), context.next_hop],
      [t("network.gateway"), context.gateway || t("network.gatewayNA")],
      [t("network.routeMetric"), context.route_metric],
      [t("network.certainty"), enumText("certainty", context.certainty, context.certainty)],
      [t("network.provenance"), listText(context.provenance)],
      [t("network.evidence"), referenceValue(context.evidence_ids)],
    ];
    fields.push([t("network.vpn"), booleanText(context.vpn_or_tunnel_involvement)]);
    fields.push([t("network.virtualAdapter"), booleanText(context.virtual_adapter_involvement)]);
    fields.push([t("network.ambiguous"), booleanText(context.route_selection_ambiguous)]);
    if (context.neighbor) {
      fields.push([t("network.neighbor"), enumText("neighbor", context.neighbor.observation, context.neighbor.observation)]);
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
        item.appendChild(semanticValueElement(label, value, "context-value", "code"));
      }
      networkContext.appendChild(item);
    }
    if (context.competing_routes && context.competing_routes.length) {
      const note = element("p", "section-note context-note", quantity("network.competingOne", "network.competingMany", context.competing_routes.length));
      networkContext.appendChild(note);
    }
  }

  function diagnosisDetailText(overall) {
    const stateKeys = {
      clear: "diagnosis.clear",
      finding: "diagnosis.findingState",
      incomplete: "diagnosis.incomplete",
      unknown: "diagnosis.unavailable",
    };
    const state = stateKeys[overall.diagnosis_state] ? t(stateKeys[overall.diagnosis_state]) : text(overall.diagnosis_state);
    const destination = overall.destination && overall.destination.status
      ? t("diagnosis.destination", { value: destinationStateText(overall.destination.status, overall.destination.label) })
      : "";
    return t("diagnosis.detail", { state, destination });
  }

  function diagnosisLabelText(overall, findings) {
    if (overall.diagnosis_state === "clear") {
      return t("diagnosis.clear");
    }
    if (overall.diagnosis_state === "finding") {
      const count = Array.isArray(findings) ? findings.length : 0;
      return quantity("diagnosis.findingsOne", "diagnosis.findingsMany", count);
    }
    if (overall.diagnosis_state === "incomplete") {
      return t("diagnosis.incomplete");
    }
    if (overall.diagnosis_state === "unknown") {
      return t("diagnosis.unavailable");
    }
    return sourceText(overall.diagnosis_label) || text(overall.diagnosis_label || overall.diagnosis_state);
  }

  function renderTargetDetails(target) {
    reportTarget.replaceChildren();
    if (!target) {
      reportTarget.appendChild(element("div", "target-detail", t("common.targetUnavailable")));
      return;
    }
    const service = target.service || {};
    const fields = [
      [t("target.label"), target.requested_identity || t("common.identityUnavailable")],
      [t("target.service"), serviceText(service.id || service.label) || protocolText(target.application_protocol) || t("common.notSpecified")],
      [t("target.transport"), transportText(target.transport_protocol) || t("common.notSpecified")],
      [t("target.port"), target.port || t("common.notSpecified")],
    ];
    if (target.resource) {
      fields.push([t("target.resource"), target.resource]);
    }
    for (const [label, value] of fields) {
      const row = element("div", "target-detail");
      row.appendChild(element("span", "target-detail-label", label));
      row.appendChild(semanticValueElement(label, value, "target-detail-value"));
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
    evidenceHeading.textContent = `${t("evidence.inspector")} · ${text(id)}`;
  }

  function clearPathSelection() {
    pathSelection.replaceChildren();
    pathSelection.hidden = true;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();
    closeEvents();
    activeSessionID = "";
    reportSection.hidden = true;
    clearPathSelection();
    pathGraphCount.textContent = t("path.awaitingReport");
    pathGraphDescription.textContent = t("path.waiting");
    setPathGraphState("loading");
    button.disabled = true;
    currentSessionState = "starting";
    button.textContent = t("target.starting");
    cancelButton.hidden = true;
    setProgress([{ state: "started" }, { state: "running" }], "session.starting", "starting", "neutral");

    try {
      const response = await fetch("/api/diagnoses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(composer.serialize(composerState)),
      });
      const snapshot = await readResponse(response);
      activeSessionID = text(snapshot.id);
      setSessionState(snapshot.state || "running");
      button.textContent = t("target.running");
      openEvents(activeSessionID);
    } catch (err) {
      currentSessionState = "error";
      setProgress([{ state: "error" }], "session.requestFailed", "error", "negative");
      showError(err instanceof Error ? err.message : t("session.requestError"));
      button.disabled = false;
      button.textContent = t("target.diagnoseArrow");
    }
  });

  browserCaptureStart.addEventListener("click", async () => {
    clearBrowserCaptureError();
    clearBrowserCapturePoll();
    browserCaptureStart.disabled = true;
    activeCaptureSnapshot = { state: "starting", unique_destination_count: 0, unique_address_count: 0, observation_count: 0, failure_count: 0, destinations: [] };
    renderBrowserCapture(activeCaptureSnapshot);
    browserCaptureState.className = toneClass("badge", "neutral");
    try {
      const response = await fetch("/api/browser-captures", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ browser: browserCaptureBrowser.value }),
      });
      const snapshot = await readResponse(response);
      activeCaptureID = text(snapshot.id);
      renderBrowserCapture(snapshot);
      void pollBrowserCapture();
    } catch (err) {
      browserCaptureStart.disabled = false;
      browserCaptureBrowser.disabled = false;
      activeCaptureSnapshot = { ...(activeCaptureSnapshot || {}), state: "error" };
      renderBrowserCapture(activeCaptureSnapshot);
      showBrowserCaptureError(err instanceof Error ? err.message : t("browser.requestError"));
    }
  });

  browserCaptureStop.addEventListener("click", async () => {
    if (!activeCaptureID) {
      return;
    }
    clearBrowserCaptureError();
    browserCaptureStop.disabled = true;
    try {
      const response = await fetch(`/api/browser-captures/${encodeURIComponent(activeCaptureID)}`, { method: "DELETE" });
      const snapshot = await readResponse(response);
      renderBrowserCapture(snapshot);
      void pollBrowserCapture();
    } catch (err) {
      browserCaptureStop.disabled = false;
      showBrowserCaptureError(err instanceof Error ? err.message : t("browser.stopError"));
    }
  });

  browserCaptureCopy.addEventListener("click", async () => {
    if (!activeCaptureID) {
      return;
    }
    clearBrowserCaptureError();
    try {
      const response = await fetch(`/api/browser-captures/${encodeURIComponent(activeCaptureID)}/fqdns.txt`, { cache: "no-store" });
      const fqdnList = await response.text();
      if (!response.ok) {
        throw new Error(t("browser.loadFQDNError"));
      }
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        throw new Error(t("browser.clipboardUnavailable"));
      }
      await navigator.clipboard.writeText(fqdnList);
      browserCaptureCopy.textContent = t("browser.copiedFQDNs");
      setTimeout(() => { browserCaptureCopy.textContent = t("browser.copyFQDNs"); }, 1500);
    } catch (err) {
      showBrowserCaptureError(err instanceof Error ? err.message : t("browser.copyError"));
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
      showError(err instanceof Error ? err.message : t("session.cancelError"));
      cancelButton.disabled = false;
    }
  });
})();
