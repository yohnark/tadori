"use strict";

(() => {
  const OPAQUE_VALUE_LIMIT = 56;

  function text(value) {
    return value === undefined || value === null ? "" : String(value);
  }

  function semanticKind(label, value) {
    const normalizedLabel = text(label).toLowerCase();
    const normalizedValue = text(value);

    if (/\b(raw|json|code)\b/.test(normalizedLabel)) {
      return "raw";
    }
    if (/\b(sha-?256|serial|fingerprint|evidence|identifier|opaque|\bid\b)/.test(normalizedLabel)) {
      return "opaque";
    }
    if (/\b(certificate|subject|issuer)\b/.test(normalizedLabel)) {
      return "certificate";
    }
    if (/\b(url|uri|resource)\b/.test(normalizedLabel) || /^[a-z][a-z0-9+.-]*:\/\//i.test(normalizedValue)) {
      return "url";
    }
    if (/\b(host(?:name)?|endpoint|address|resolver|gateway|interface|route|server name|next hop|destination|target)\b/.test(normalizedLabel)) {
      return "endpoint";
    }
    if (/\b(failure|limitation(?:s)?|reason|detail|provenance|policy|path|message|note)\b/.test(normalizedLabel)) {
      return "prose";
    }
    return "semantic";
  }

  function truncateOpaque(value, limit = OPAQUE_VALUE_LIMIT) {
    const fullText = text(value);
    const safeLimit = Math.max(5, Math.floor(Number(limit) || OPAQUE_VALUE_LIMIT));
    if (fullText.length <= safeLimit) {
      return fullText;
    }
    const headLength = Math.ceil((safeLimit - 1) / 2);
    const tailLength = safeLimit - 1 - headLength;
    return `${fullText.slice(0, headLength)}…${fullText.slice(-tailLength)}`;
  }

  function describeSemanticValue(label, value) {
    const fullText = text(value);
    const kind = semanticKind(label, fullText);
    const truncated = kind === "opaque" && fullText.length > OPAQUE_VALUE_LIMIT;
    return {
      kind,
      text: truncated ? truncateOpaque(fullText) : fullText,
      fullText,
      truncated,
      copyable: kind === "opaque" && fullText !== "not observed" && fullText !== "not available",
    };
  }

  const api = Object.freeze({
    OPAQUE_VALUE_LIMIT,
    semanticKind,
    truncateOpaque,
    describeSemanticValue,
  });

  globalThis.TadoriWorkbenchDisplay = api;
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
})();
