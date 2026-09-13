(() => {
  "use strict";

  const form = document.querySelector("#diagnose-form");
  const targetInput = document.querySelector("#target");
  const diagnoseButton = form.querySelector("button");
  const cancelButton = document.querySelector("#cancel-button");
  const error = document.querySelector("#error");
  const sessionSection = document.querySelector("#session");
  const sessionState = document.querySelector("#session-state");
  const sessionID = document.querySelector("#session-id");
  const sessionTarget = document.querySelector("#session-target");
  const progress = document.querySelector("#progress");
  const reportSection = document.querySelector("#report");
  const overallStatus = document.querySelector("#overall-status");
  const reportTarget = document.querySelector("#report-target");
  const probes = document.querySelector("#probes");
  const findings = document.querySelector("#findings");
  const evidence = document.querySelector("#evidence");
  const canonicalJSON = document.querySelector("#canonical-json");

  let activeID = "";
  let eventSource = null;
  const probeItems = new Map();

  function text(value) {
    return value === undefined || value === null ? "" : String(value);
  }

  function targetText(target) {
    if (target?.url) {
      return text(target.url);
    }
    const host = text(target?.host);
    if (!host) {
      return "";
    }
    const port = Number(target?.port || 0);
    const formattedHost = host.includes(":") ? `[${host}]` : host;
    return port > 0 ? `${formattedHost}:${port}` : formattedHost;
  }

  function jsonText(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch (_) {
      return text(value);
    }
  }

  function showError(message) {
    error.textContent = text(message);
    error.hidden = false;
  }

  function clearError() {
    error.textContent = "";
    error.hidden = true;
  }

  function setSessionState(value) {
    sessionState.textContent = text(value);
    const cancellable = value === "running" || value === "cancelling";
    cancelButton.hidden = !cancellable;
    cancelButton.disabled = value === "cancelling";
  }

  function renderSession(snapshot) {
    activeID = text(snapshot.id);
    sessionID.textContent = activeID;
    sessionTarget.textContent = targetText(snapshot.target);
    setSessionState(snapshot.state);
    sessionSection.hidden = false;
    if (snapshot.report) {
      renderReport(snapshot.report);
    }
  }

  function addEmptyMessage(container) {
    const item = document.createElement("li");
    item.textContent = "(none)";
    container.appendChild(item);
  }

  function renderProgress(name, value) {
    const key = text(name);
    if (!key) {
      return;
    }
    let item = probeItems.get(key);
    if (!item) {
      item = document.createElement("li");
      item.dataset.probeName = key;
      progress.appendChild(item);
      probeItems.set(key, item);
    }
    item.textContent = `${key}: ${text(value)}`;
  }

  function renderProbe(probe, index) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = `${index + 1}. ${text(probe.name)}: ${text(probe.status)}`;
    item.appendChild(title);

    const interpretation = document.createElement("div");
    interpretation.textContent = `failure_reason=${text(probe.interpretation?.failure_reason)}; layer=${text(probe.interpretation?.layer)}; fault_domain=${text(probe.interpretation?.fault_domain)}`;
    item.appendChild(interpretation);
    probes.appendChild(item);
  }

  function renderFinding(finding) {
    const item = document.createElement("li");
    const references = [];
    if (finding.probe_names?.length) {
      references.push(`probes=${finding.probe_names.join(",")}`);
    }
    if (finding.evidence_ids?.length) {
      references.push(`evidence=${finding.evidence_ids.join(",")}`);
    }
    item.textContent = [
      `failure_reason=${text(finding.failure_reason)}`,
      `layer=${text(finding.layer)}`,
      `fault_domain=${text(finding.fault_domain)}`,
      ...references,
    ].join("; ");
    findings.appendChild(item);
  }

  function renderEvidence(probe) {
    for (const item of probe.evidence || []) {
      const card = document.createElement("section");
      card.className = "evidence-card";

      const heading = document.createElement("strong");
      heading.textContent = `${text(probe.name)} / ${text(item.id)} (${text(item.kind)})`;
      card.appendChild(heading);

      if (item.source) {
        const source = document.createElement("div");
        source.textContent = `source=${text(item.source)}`;
        card.appendChild(source);
      }

      const raw = document.createElement("pre");
      // textContent is intentional: raw evidence is never interpreted as HTML.
      raw.textContent = jsonText(item.raw);
      card.appendChild(raw);
      evidence.appendChild(card);
    }
  }

  function renderReport(report) {
    overallStatus.textContent = text(report.status);
    reportTarget.textContent = targetText(report.target);
    probes.replaceChildren();
    findings.replaceChildren();
    evidence.replaceChildren();

    for (const [index, probe] of (report.probes || []).entries()) {
      renderProbe(probe, index);
      renderEvidence(probe);
    }
    if (!report.probes?.length) {
      addEmptyMessage(probes);
    }
    for (const finding of report.findings || []) {
      renderFinding(finding);
    }
    if (!report.findings?.length) {
      addEmptyMessage(findings);
    }
    if (!evidence.children.length) {
      const empty = document.createElement("p");
      empty.textContent = "(none)";
      evidence.appendChild(empty);
    }
    canonicalJSON.textContent = jsonText(report);
    reportSection.hidden = false;
  }

  function closeEvents() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  }

  function finishSession(state, report) {
    setSessionState(state);
    if (report) {
      renderReport(report);
    }
    diagnoseButton.disabled = false;
    diagnoseButton.textContent = "Diagnose";
    if (state !== "running" && state !== "cancelling") {
      activeID = "";
    }
  }

  function handleEvent(event) {
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
        break;
      case "probe_started":
        renderProgress(body.probe_name, "running");
        break;
      case "probe_completed":
      case "result_updated":
        renderProgress(body.probe_name || body.result?.name, body.result?.status);
        break;
      case "finding_updated":
        break;
      case "diagnosis_completed":
        finishSession("completed", body.report);
        closeEvents();
        break;
      case "diagnosis_cancelled":
        finishSession("cancelled", body.report);
        closeEvents();
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
      eventSource.addEventListener(eventType, handleEvent);
    }
    eventSource.onerror = () => {
      if (eventSource && eventSource.readyState === EventSource.CLOSED && activeID) {
        showError("progress stream closed before the session completed");
      }
    };
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

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();
    closeEvents();
    activeID = "";
    probeItems.clear();
    progress.replaceChildren();
    reportSection.hidden = true;
    diagnoseButton.disabled = true;
    diagnoseButton.textContent = "Starting…";

    try {
      const response = await fetch("/api/diagnoses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: targetInput.value }),
      });
      const snapshot = await readResponse(response);
      renderSession(snapshot);
      diagnoseButton.textContent = "Running…";
      openEvents(snapshot.id);
    } catch (err) {
      showError(err instanceof Error ? err.message : "diagnosis request failed");
      diagnoseButton.disabled = false;
      diagnoseButton.textContent = "Diagnose";
    }
  });

  cancelButton.addEventListener("click", async () => {
    if (!activeID) {
      return;
    }
    clearError();
    cancelButton.disabled = true;
    setSessionState("cancelling");
    try {
      const response = await fetch(`/api/diagnoses/${encodeURIComponent(activeID)}`, {
        method: "DELETE",
      });
      const snapshot = await readResponse(response);
      renderSession(snapshot);
    } catch (err) {
      showError(err instanceof Error ? err.message : "cancel request failed");
      cancelButton.disabled = false;
    }
  });
})();
