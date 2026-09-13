"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const Composer = require("./composer.js");

const {
  EVENT,
  PROVENANCE,
  createState,
  inferTargetSyntax,
  normalizePort,
  normalizeService,
  serialize,
  snapshot,
  transition,
} = Composer;

function target(state, value) {
  return transition(state, { type: EVENT.TARGET_CHANGED, value });
}

function service(state, value) {
  return transition(state, { type: EVENT.SERVICE_CHANGED, value });
}

function port(state, value) {
  return transition(state, { type: EVENT.PORT_CHANGED, value });
}

function fields(state) {
  return {
    service: [state.service.value, state.service.provenance],
    port: [state.port.value, state.port.provenance],
  };
}

test("service profiles expose stable defaults, including required custom ports", () => {
  assert.deepEqual(Composer.SERVICE_PROFILES, {
    http: { id: "http", defaultPort: 80 },
    https: { id: "https", defaultPort: 443 },
    smb: { id: "smb", defaultPort: 445 },
    rdp: { id: "rdp", defaultPort: 3389 },
    ssh: { id: "ssh", defaultPort: 22 },
    dns: { id: "dns", defaultPort: 53 },
    custom_tcp: { id: "custom_tcp", defaultPort: null },
    custom_tls: { id: "custom_tls", defaultPort: null },
  });
  assert.equal(normalizeService("file-sharing"), "smb");
  assert.equal(normalizeService("tcp"), "custom_tcp");
  assert.equal(normalizeService("not-a-service"), null);
});

test("port normalization accepts only backend-compatible explicit ports", () => {
  assert.equal(normalizePort("1"), 1);
  assert.equal(normalizePort("65535"), 65535);
  assert.equal(normalizePort(8443), 8443);
  assert.equal(normalizePort(""), null);
  assert.equal(normalizePort("0"), null);
  assert.equal(normalizePort("65536"), null);
  assert.equal(normalizePort("8443.5"), null);
  assert.equal(normalizePort("8443x"), null);
});

test("syntax inference reports provenance hints without canonicalizing identity", () => {
  assert.deepEqual(inferTargetSyntax("https://example.com:8443/path"), {
    kind: "url",
    service: "https",
    explicitPort: 8443,
    input: "https://example.com:8443/path",
  });
  assert.deepEqual(inferTargetSyntax("https://example.com"), {
    kind: "url",
    service: "https",
    explicitPort: null,
    input: "https://example.com",
  });
  assert.deepEqual(inferTargetSyntax("\\\\fileserver\\share"), {
    kind: "unc",
    service: "smb",
    explicitPort: null,
    input: "\\\\fileserver\\share",
  });
  assert.deepEqual(inferTargetSyntax("192.0.2.10:9443"), {
    kind: "endpoint",
    service: null,
    explicitPort: 9443,
    input: "192.0.2.10:9443",
  });
  assert.deepEqual(inferTargetSyntax("[2001:db8::10]:9443"), {
    kind: "endpoint",
    service: null,
    explicitPort: 9443,
    input: "[2001:db8::10]:9443",
  });
  assert.deepEqual(inferTargetSyntax("https://example.com:bad"), {
    kind: "url",
    service: "https",
    explicitPort: null,
    input: "https://example.com:bad",
  });
  assert.equal(inferTargetSyntax("javascript:alert(1)").service, null);
});

test("initial state keeps profile defaults out of the request", () => {
  const state = createState({ service: "http" });
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [80, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), { target: { input: "" } });
  assert.deepEqual(state.conflicts, []);
  assert.deepEqual(state.validationErrors, []);
});

test("initial target is reduced through the same transition used by input events", () => {
  const state = createState({ target: "https://example.com:8443" });
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.TARGET],
    port: [8443, PROVENANCE.TARGET],
  });
  assert.deepEqual(serialize(state), { target: { input: "https://example.com:8443" } });
  assert.equal(state.revision, 1);
});

test("URL explicit port to URL default port clears the stale target-derived override", () => {
  let state = createState();
  state = target(state, "https://example.com:8443");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.TARGET],
    port: [8443, PROVENANCE.TARGET],
  });

  state = target(state, "https://example.com");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.TARGET],
    port: [443, PROVENANCE.RESET],
  });
  assert.equal(state.port.resetBy, "target");
  assert.deepEqual(serialize(state), { target: { input: "https://example.com" } });
});

test("URL default port transitions as a default rather than an explicit override", () => {
  let state = createState();
  state = target(state, "https://example.com");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.TARGET],
    port: [443, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), { target: { input: "https://example.com" } });
});

test("URL default port to manual port serializes only the user override", () => {
  let state = target(createState(), "https://example.com");
  state = port(state, "9443");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.TARGET],
    port: [9443, PROVENANCE.MANUAL],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "https://example.com", port: 9443 },
  });
});

test("manual port survives a service change", () => {
  let state = createState();
  state = port(state, "1445");
  state = service(state, "smb");
  assert.deepEqual(fields(state), {
    service: ["smb", PROVENANCE.MANUAL],
    port: [1445, PROVENANCE.MANUAL],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "", service: "smb", port: 1445 },
  });
});

test("service change updates a default-derived port", () => {
  let state = createState();
  state = service(state, "ssh");
  assert.deepEqual(fields(state), {
    service: ["ssh", PROVENANCE.MANUAL],
    port: [22, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), { target: { input: "", service: "ssh" } });
});

test("service change preserves an explicit target-derived port", () => {
  let state = target(createState(), "https://example.com:8443");
  state = service(state, "https");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.MANUAL],
    port: [8443, PROVENANCE.TARGET],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "https://example.com:8443", service: "https" },
  });
});

test("manual service is not silently overwritten by target syntax", () => {
  let state = createState();
  state = service(state, "http");
  state = target(state, "https://example.com");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.MANUAL],
    port: [80, PROVENANCE.DEFAULT],
  });
  assert.equal(state.conflicts.length, 1);
  assert.deepEqual(state.conflicts[0], {
    field: "service",
    explicit: "http",
    targetDerived: "https",
    message: "Selected service http conflicts with target service https",
  });
  assert.deepEqual(serialize(state), {
    target: { input: "https://example.com", service: "http" },
  });
});

test("manual port conflict is retained for backend validation visibility", () => {
  let state = target(createState(), "https://example.com:8443");
  state = port(state, "9443");
  assert.equal(state.conflicts.length, 1);
  assert.equal(state.conflicts[0].field, "port");
  assert.deepEqual(serialize(state), {
    target: { input: "https://example.com:8443", port: 9443 },
  });
});

test("UNC inference yields SMB but a later hostname edit resets target-derived intent", () => {
  let state = target(createState(), "\\\\fileserver\\share");
  assert.deepEqual(fields(state), {
    service: ["smb", PROVENANCE.TARGET],
    port: [445, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), { target: { input: "\\\\fileserver\\share" } });

  state = target(state, "fileserver");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.RESET],
    port: [80, PROVENANCE.RESET],
  });
  assert.deepEqual(serialize(state), { target: { input: "fileserver" } });
});

test("explicit SMB selection survives a UNC-to-hostname edit", () => {
  let state = target(createState(), "\\\\fileserver\\share");
  state = service(state, "smb");
  state = target(state, "fileserver");
  assert.deepEqual(fields(state), {
    service: ["smb", PROVENANCE.MANUAL],
    port: [445, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "fileserver", service: "smb" },
  });
});

test("host and IPv4 edits keep an explicit service selector usable", () => {
  let state = createState();
  state = service(state, "https");
  state = target(state, "example.com");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.MANUAL],
    port: [443, PROVENANCE.DEFAULT],
  });
  state = target(state, "192.0.2.10");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.MANUAL],
    port: [443, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "192.0.2.10", service: "https" },
  });
});

test("IPv4 explicit target ports are target-derived and clear on a later edit", () => {
  let state = target(createState(), "192.0.2.10:9443");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [9443, PROVENANCE.TARGET],
  });
  state = target(state, "192.0.2.10");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [80, PROVENANCE.RESET],
  });
  assert.deepEqual(serialize(state), { target: { input: "192.0.2.10" } });
});

test("IPv6 explicit target ports are target-derived without changing service", () => {
  let state = target(createState(), "[2001:db8::10]:9443");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [9443, PROVENANCE.TARGET],
  });
  state = target(state, "[2001:db8::10]");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [80, PROVENANCE.RESET],
  });
});

test("manual IPv6 service and port intent remains explicit across target edits", () => {
  let state = service(createState(), "custom_tls");
  state = port(state, "9443");
  state = target(state, "[2001:db8::10]");
  assert.deepEqual(fields(state), {
    service: ["custom_tls", PROVENANCE.MANUAL],
    port: [9443, PROVENANCE.MANUAL],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "[2001:db8::10]", service: "custom_tls", port: 9443 },
  });
});

test("custom TCP requires a manual port and serializes it", () => {
  let state = service(createState(), "custom_tcp");
  assert.deepEqual(fields(state), {
    service: ["custom_tcp", PROVENANCE.MANUAL],
    port: [null, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(serialize(state), { target: { input: "", service: "custom_tcp" } });
  state = port(state, "12345");
  assert.deepEqual(fields(state), {
    service: ["custom_tcp", PROVENANCE.MANUAL],
    port: [12345, PROVENANCE.MANUAL],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "", service: "custom_tcp", port: 12345 },
  });
});

test("custom TLS can be inferred from a target and does not invent a port", () => {
  let state = target(createState(), "tls://example.com:443");
  assert.deepEqual(fields(state), {
    service: ["custom_tls", PROVENANCE.TARGET],
    port: [443, PROVENANCE.TARGET],
  });
  assert.deepEqual(serialize(state), { target: { input: "tls://example.com:443" } });
  state = target(state, "tls://example.com");
  assert.deepEqual(fields(state), {
    service: ["custom_tls", PROVENANCE.TARGET],
    port: [null, PROVENANCE.RESET],
  });
  assert.deepEqual(serialize(state), { target: { input: "tls://example.com" } });
});

test("clearing a manual port keeps the manual provenance and exposes invalid input", () => {
  let state = port(createState(), "8443");
  state = port(state, "");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [null, PROVENANCE.MANUAL],
  });
  assert.deepEqual(state.validationErrors, []);
  assert.deepEqual(serialize(state), { target: { input: "" } });
  state = port(state, "0");
  assert.deepEqual(state.validationErrors, ["Port must be between 1 and 65535"]);
  assert.deepEqual(serialize(state), { target: { input: "", } });
});

test("manual blank port is not overwritten by a service change", () => {
  let state = port(createState(), "");
  state = service(state, "custom_tcp");
  assert.deepEqual(fields(state), {
    service: ["custom_tcp", PROVENANCE.MANUAL],
    port: [null, PROVENANCE.MANUAL],
  });
  assert.deepEqual(serialize(state), { target: { input: "", service: "custom_tcp" } });
});

test("repeated target edits never retain a previous explicit target port", () => {
  const values = [
    "https://example.com:8443",
    "https://example.com",
    "https://example.com:9443",
    "https://example.com",
    "example.com",
    "192.0.2.10:10443",
    "192.0.2.10",
    "[2001:db8::10]:11443",
    "[2001:db8::10]",
  ];
  let state = createState();
  for (const value of values) {
    state = target(state, value);
    const syntax = inferTargetSyntax(value);
    if (syntax.explicitPort === null) {
      assert.notEqual(state.port.provenance, PROVENANCE.TARGET, value);
      assert.equal(state.port.value, Composer.SERVICE_PROFILES[state.service.value].defaultPort, value);
      assert.deepEqual(serialize(state), { target: { input: value } }, value);
    } else {
      assert.equal(state.port.value, syntax.explicitPort, value);
      assert.equal(state.port.provenance, PROVENANCE.TARGET, value);
    }
  }
});

test("target-derived values are replaced by later target-derived values", () => {
  let state = target(createState(), "https://one.example:8443");
  state = target(state, "http://two.example:8080");
  assert.deepEqual(fields(state), {
    service: ["http", PROVENANCE.TARGET],
    port: [8080, PROVENANCE.TARGET],
  });
  state = target(state, "smb://fileserver/share");
  assert.deepEqual(fields(state), {
    service: ["smb", PROVENANCE.TARGET],
    port: [445, PROVENANCE.DEFAULT],
  });
});

test("target syntax can change service while preserving a manual port", () => {
  let state = port(createState(), "1234");
  state = target(state, "https://example.com");
  assert.deepEqual(fields(state), {
    service: ["https", PROVENANCE.TARGET],
    port: [1234, PROVENANCE.MANUAL],
  });
  assert.deepEqual(serialize(state), {
    target: { input: "https://example.com", port: 1234 },
  });
});

test("manual service and port are both retained through an incompatible URL", () => {
  let state = service(createState(), "ssh");
  state = port(state, "2222");
  state = target(state, "https://example.com:443");
  assert.deepEqual(fields(state), {
    service: ["ssh", PROVENANCE.MANUAL],
    port: [2222, PROVENANCE.MANUAL],
  });
  assert.deepEqual(state.conflicts.map((item) => item.field), ["service", "port"]);
  assert.deepEqual(serialize(state), {
    target: { input: "https://example.com:443", service: "ssh", port: 2222 },
  });
});

test("reset provenance is replaced by manual intent when the user edits the field", () => {
  let state = target(createState(), "https://example.com:8443");
  state = target(state, "example.com");
  assert.equal(state.service.provenance, PROVENANCE.RESET);
  assert.equal(state.port.provenance, PROVENANCE.RESET);
  state = service(state, "https");
  state = port(state, "9443");
  assert.equal(state.service.provenance, PROVENANCE.MANUAL);
  assert.equal(state.port.provenance, PROVENANCE.MANUAL);
  assert.deepEqual(serialize(state), {
    target: { input: "example.com", service: "https", port: 9443 },
  });
});

test("snapshot is detached and cannot mutate future transitions", () => {
  const state = target(createState(), "https://example.com:8443");
  const copy = snapshot(state);
  copy.service.value = "ssh";
  copy.port.value = 22;
  copy.conflicts.push({ field: "test" });
  assert.equal(state.service.value, "https");
  assert.equal(state.port.value, 8443);
  assert.deepEqual(state.conflicts, []);
});

test("transitions are immutable and revisions are deterministic", () => {
  const initial = createState();
  const next = target(initial, "https://example.com:8443");
  assert.equal(initial.target, "");
  assert.equal(initial.revision, 1);
  assert.equal(next.revision, 2);
  assert.deepEqual(fields(initial), {
    service: ["http", PROVENANCE.DEFAULT],
    port: [80, PROVENANCE.DEFAULT],
  });
  assert.deepEqual(fields(next), {
    service: ["https", PROVENANCE.TARGET],
    port: [8443, PROVENANCE.TARGET],
  });
});

test("the same event sequence serializes identically on every run", () => {
  const events = [
    { type: EVENT.TARGET_CHANGED, value: "https://example.com:8443" },
    { type: EVENT.TARGET_CHANGED, value: "https://example.com" },
    { type: EVENT.SERVICE_CHANGED, value: "https" },
    { type: EVENT.PORT_CHANGED, value: "9443" },
    { type: EVENT.TARGET_CHANGED, value: "[2001:db8::5]" },
    { type: EVENT.SERVICE_CHANGED, value: "custom_tls" },
  ];

  function run() {
    return events.reduce((state, event) => transition(state, event), createState());
  }

  const first = run();
  const second = run();
  assert.deepEqual(first, second);
  assert.deepEqual(serialize(first), {
    target: { input: "[2001:db8::5]", service: "custom_tls", port: 9443 },
  });
});

