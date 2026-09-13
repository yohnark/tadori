(() => {
  "use strict";

  const form = document.querySelector("#diagnose-form");
  const targetInput = document.querySelector("#target");
  const button = form.querySelector("button");
  const error = document.querySelector("#error");
  const reportSection = document.querySelector("#report");
  const status = document.querySelector("#overall-status");
  const reportTarget = document.querySelector("#report-target");
  const probes = document.querySelector("#probes");
  const findings = document.querySelector("#findings");
  const evidence = document.querySelector("#evidence");
  const canonicalJSON = document.querySelector("#canonical-json");

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

  function addEmptyMessage(container) {
    const item = document.createElement("li");
    item.textContent = "(none)";
    container.appendChild(item);
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
    status.textContent = text(report.status);
    reportTarget.textContent = text(report.target?.url || report.target?.host);
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

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    reportSection.hidden = true;
    button.disabled = true;
    button.textContent = "Running…";

    try {
      const response = await fetch("/api/diagnose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: targetInput.value }),
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error || `request failed (${response.status})`);
      }
      renderReport(body);
    } catch (err) {
      error.textContent = err instanceof Error ? err.message : "diagnose request failed";
      error.hidden = false;
    } finally {
      button.disabled = false;
      button.textContent = "Diagnose";
    }
  });
})();
