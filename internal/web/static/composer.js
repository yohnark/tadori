(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.TadoriTargetComposer = factory();
  }
})(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  // These are UI identifiers and defaults mirrored from the backend service
  // profiles. They are not a target parser; ParseTarget remains authoritative.
  const PROVENANCE = Object.freeze({
    DEFAULT: "default",
    TARGET: "target",
    MANUAL: "manual",
    RESET: "reset",
  });

  const EVENT = Object.freeze({
    TARGET_CHANGED: "target_changed",
    SERVICE_CHANGED: "service_changed",
    PORT_CHANGED: "port_changed",
  });

  const SERVICE_PROFILES = Object.freeze({
    http: Object.freeze({ id: "http", defaultPort: 80 }),
    https: Object.freeze({ id: "https", defaultPort: 443 }),
    smb: Object.freeze({ id: "smb", defaultPort: 445 }),
    rdp: Object.freeze({ id: "rdp", defaultPort: 3389 }),
    ssh: Object.freeze({ id: "ssh", defaultPort: 22 }),
    dns: Object.freeze({ id: "dns", defaultPort: 53 }),
    custom_tcp: Object.freeze({ id: "custom_tcp", defaultPort: null }),
    custom_tls: Object.freeze({ id: "custom_tls", defaultPort: null }),
  });

  const SERVICE_ALIASES = Object.freeze({
    file: "smb",
    filesharing: "smb",
    "file-sharing": "smb",
    tcp: "custom_tcp",
    "custom-tcp": "custom_tcp",
    tls: "custom_tls",
    "custom-tls": "custom_tls",
  });

  const SCHEME_SERVICES = Object.freeze({
    http: "http",
    https: "https",
    smb: "smb",
    rdp: "rdp",
    ssh: "ssh",
    dns: "dns",
    tcp: "custom_tcp",
    tls: "custom_tls",
  });

  const DEFAULT_SERVICE = "http";

  function own(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
  }

  function normalizeService(value) {
    const candidate = String(value === undefined || value === null ? "" : value)
      .trim()
      .toLowerCase();
    const normalized = SERVICE_ALIASES[candidate] || candidate;
    return own(SERVICE_PROFILES, normalized) ? normalized : null;
  }

  function profileFor(service) {
    const normalized = normalizeService(service) || DEFAULT_SERVICE;
    return SERVICE_PROFILES[normalized];
  }

  function normalizePort(value) {
    if (value === undefined || value === null || String(value).trim() === "") {
      return null;
    }
    const text = String(value).trim();
    if (!/^\d+$/.test(text)) {
      return null;
    }
    const port = Number(text);
    return Number.isSafeInteger(port) && port >= 1 && port <= 65535 ? port : null;
  }

  function copyField(field) {
    return {
      value: field.value === undefined ? null : field.value,
      provenance: field.provenance,
      resetBy: field.resetBy || null,
      raw: field.raw === undefined || field.raw === null ? "" : String(field.raw),
    };
  }

  function field(value, provenance, raw, resetBy) {
    return {
      value: value === undefined ? null : value,
      provenance,
      resetBy: resetBy || null,
      raw: raw === undefined || raw === null ? value === null || value === undefined ? "" : String(value) : String(raw),
    };
  }

  function defaultPort(service) {
    return profileFor(service).defaultPort;
  }

  function parseAuthorityPort(authority) {
    const withoutUser = authority.slice(authority.lastIndexOf("@") + 1);
    if (withoutUser.startsWith("[")) {
      const closeBracket = withoutUser.indexOf("]");
      if (closeBracket >= 0) {
        return normalizePort(withoutUser.slice(closeBracket + 1).replace(/^:/, ""));
      }
      return null;
    }
    const match = /:(\d+)$/.exec(withoutUser);
    return match ? normalizePort(match[1]) : null;
  }

  function parseURLPort(input, schemeMatch) {
    const authorityAndPath = input.slice(schemeMatch[0].length);
    const authority = authorityAndPath.split(/[/?#]/, 1)[0];
    return parseAuthorityPort(authority);
  }

  function parseBareEndpointPort(input) {
    if (input.startsWith("[") && input.endsWith("]")) {
      return null;
    }
    const bracketed = /^\[[^\]]+\]:(\d+)$/.exec(input);
    if (bracketed) {
      return normalizePort(bracketed[1]);
    }
    const hostPort = /^[^:/\\]+:(\d+)$/.exec(input);
    return hostPort ? normalizePort(hostPort[1]) : null;
  }

  /**
   * Classifies only the syntax needed to preserve UI provenance. It does not
   * validate, canonicalize, resolve, or otherwise replace model.ParseTarget.
   */
  function inferTargetSyntax(value) {
    const input = String(value === undefined || value === null ? "" : value);
    const syntax = {
      kind: "plain",
      service: null,
      explicitPort: null,
      input,
    };
    if (input === "") {
      return syntax;
    }
    if (input.startsWith("\\")) {
      return { kind: "unc", service: "smb", explicitPort: null, input };
    }

    const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(input);
    if (schemeMatch) {
      const scheme = schemeMatch[1].toLowerCase();
      return {
        kind: "url",
        service: SCHEME_SERVICES[scheme] || null,
        explicitPort: parseURLPort(input, schemeMatch),
        input,
      };
    }

    const barePort = parseBareEndpointPort(input);
    if (barePort !== null) {
      syntax.kind = "endpoint";
      syntax.explicitPort = barePort;
    }
    return syntax;
  }

  function initialService(options) {
    const requested = options && (options.defaultService || options.service);
    return normalizeService(requested) || DEFAULT_SERVICE;
  }

  function initialState(options) {
    const settings = options || {};
    const service = initialService(settings);
    const target = settings.target === undefined || settings.target === null ? "" : String(settings.target);
    return {
      target,
      defaults: { service },
      service: field(service, PROVENANCE.DEFAULT),
      port: field(defaultPort(service), PROVENANCE.DEFAULT),
      syntax: inferTargetSyntax(target),
      conflicts: [],
      validationErrors: [],
      revision: 0,
    };
  }

  function serviceConflict(service, syntax) {
    if (service.provenance !== PROVENANCE.MANUAL || !syntax.service || service.value === syntax.service) {
      return null;
    }
    return {
      field: "service",
      explicit: service.value,
      targetDerived: syntax.service,
      message: `Selected service ${service.value} conflicts with target service ${syntax.service}`,
    };
  }

  function portConflict(port, syntax) {
    if (port.provenance !== PROVENANCE.MANUAL || port.value === null || syntax.explicitPort === null || port.value === syntax.explicitPort) {
      return null;
    }
    return {
      field: "port",
      explicit: port.value,
      targetDerived: syntax.explicitPort,
      message: `Selected port ${port.value} conflicts with target port ${syntax.explicitPort}`,
    };
  }

  function validationErrors(state) {
    const errors = [];
    if (state.port.provenance === PROVENANCE.MANUAL && state.port.raw && state.port.value === null) {
      errors.push("Port must be between 1 and 65535");
    }
    return errors;
  }

  function finalize(state, target, service, port) {
    const syntax = inferTargetSyntax(target);
    const conflicts = [];
    const serviceError = serviceConflict(service, syntax);
    const portError = portConflict(port, syntax);
    if (serviceError) {
      conflicts.push(serviceError);
    }
    if (portError) {
      conflicts.push(portError);
    }
    const next = {
      target,
      defaults: { service: state.defaults.service },
      service: copyField(service),
      port: copyField(port),
      syntax,
      conflicts,
      validationErrors: [],
      revision: state.revision + 1,
    };
    next.validationErrors = validationErrors(next);
    return next;
  }

  function resetService(state) {
    const service = state.defaults.service;
    return field(service, PROVENANCE.RESET, service, "target");
  }

  function applyTargetChange(state, value) {
    const target = String(value === undefined || value === null ? "" : value);
    const nextSyntax = inferTargetSyntax(target);
    const previousSyntax = state.syntax || inferTargetSyntax(state.target);
    let service = copyField(state.service);
    let port = copyField(state.port);
    const previousService = service.value;

    if (service.provenance !== PROVENANCE.MANUAL) {
      if (nextSyntax.service) {
        service = field(nextSyntax.service, PROVENANCE.TARGET);
      } else if (previousSyntax.service || service.provenance === PROVENANCE.TARGET) {
        service = resetService(state);
      }
    }
    const serviceChanged = previousService !== service.value;

    if (port.provenance !== PROVENANCE.MANUAL) {
      if (nextSyntax.explicitPort !== null) {
        port = field(nextSyntax.explicitPort, PROVENANCE.TARGET);
      } else if (previousSyntax.explicitPort !== null || port.provenance === PROVENANCE.TARGET) {
        const targetServiceChanged = nextSyntax.service && nextSyntax.service !== previousSyntax.service;
        const provenance = targetServiceChanged ? PROVENANCE.DEFAULT : PROVENANCE.RESET;
        port = field(defaultPort(service.value), provenance, defaultPort(service.value), provenance === PROVENANCE.RESET ? "target" : null);
      } else if (serviceChanged) {
        const provenance = !nextSyntax.service && (previousSyntax.service || state.service.provenance === PROVENANCE.TARGET)
          ? PROVENANCE.RESET
          : PROVENANCE.DEFAULT;
        port = field(defaultPort(service.value), provenance, defaultPort(service.value), provenance === PROVENANCE.RESET ? "target" : null);
      }
    }

    return finalize(state, target, service, port);
  }

  function applyServiceChange(state, requestedService) {
    const service = normalizeService(requestedService);
    if (!service) {
      throw new Error(`Unknown service profile: ${requestedService}`);
    }
    const nextService = field(service, PROVENANCE.MANUAL, service);
    let nextPort = copyField(state.port);
    if (nextPort.provenance === PROVENANCE.DEFAULT || nextPort.provenance === PROVENANCE.RESET) {
      const port = defaultPort(service);
      nextPort = field(port, PROVENANCE.DEFAULT, port);
    }
    return finalize(state, state.target, nextService, nextPort);
  }

  function applyPortChange(state, value) {
    const raw = value === undefined || value === null ? "" : String(value);
    return finalize(state, state.target, state.service, field(normalizePort(raw), PROVENANCE.MANUAL, raw));
  }

  function transition(state, event) {
    if (!state || !event || !event.type) {
      throw new Error("composer transition requires state and event");
    }
    switch (event.type) {
      case EVENT.TARGET_CHANGED:
        return applyTargetChange(state, event.value);
      case EVENT.SERVICE_CHANGED:
        return applyServiceChange(state, event.value);
      case EVENT.PORT_CHANGED:
        return applyPortChange(state, event.value);
      default:
        throw new Error(`Unknown composer event: ${event.type}`);
    }
  }

  function withInitialTarget(options) {
    const state = initialState(options);
    if (state.target === "") {
      return finalize(state, "", state.service, state.port);
    }
    return applyTargetChange(state, state.target);
  }

  function serialize(state) {
    if (!state || !state.service || !state.port) {
      throw new Error("composer serialization requires state");
    }
    const target = { input: state.target };
    if (state.service.provenance === PROVENANCE.MANUAL && state.service.value) {
      target.service = state.service.value;
    }
    if (state.port.provenance === PROVENANCE.MANUAL && state.port.value !== null) {
      target.port = state.port.value;
    }
    return { target };
  }

  function snapshot(state) {
    return {
      target: state.target,
      service: copyField(state.service),
      port: copyField(state.port),
      syntax: { ...state.syntax },
      conflicts: state.conflicts.map((conflict) => ({ ...conflict })),
      validationErrors: state.validationErrors.slice(),
      revision: state.revision,
    };
  }

  return Object.freeze({
    DEFAULT_SERVICE,
    EVENT,
    PROVENANCE,
    SERVICE_PROFILES,
    createState: withInitialTarget,
    inferTargetSyntax,
    normalizePort,
    normalizeService,
    serialize,
    snapshot,
    transition,
  });
});
