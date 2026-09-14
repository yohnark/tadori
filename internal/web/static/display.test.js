"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const Display = require("./display.js");

test("semantic endpoint values stay complete and wrap-friendly", () => {
  const values = [
    ["Hostname", "diagnostic-gateway.eu-west-1.example.internal"],
    ["Connected endpoint", "diagnostic-gateway.eu-west-1.example.internal:8443"],
    ["IP endpoint", "2001:db8:1234:5678:90ab:cdef:1234:5678:65535"],
  ];
  for (const [label, value] of values) {
    const descriptor = Display.describeSemanticValue(label, value);
    assert.equal(descriptor.kind, "endpoint");
    assert.equal(descriptor.text, value);
    assert.equal(descriptor.truncated, false);
  }
});

test("URLs and certificate subject/issuer values remain readable strings", () => {
  const url = "https://diagnostic-gateway.example.internal:8443/health/check?source=operator-console&attempt=20260914";
  const subject = "CN=diagnostic-gateway.example.internal,OU=Network Operations,O=Example Corporation,L=Tokyo,C=JP";
  const issuer = "CN=Example Enterprise Issuing CA 04,OU=Certificate Services,O=Example Corporation,L=Tokyo,C=JP";
  assert.equal(Display.describeSemanticValue("URL", url).kind, "url");
  assert.equal(Display.describeSemanticValue("Certificate subject", subject).kind, "certificate");
  assert.equal(Display.describeSemanticValue("Certificate issuer", issuer).kind, "certificate");
  assert.equal(Display.describeSemanticValue("URL", url).text, url);
  assert.equal(Display.describeSemanticValue("Certificate subject", subject).text, subject);
  assert.equal(Display.describeSemanticValue("Certificate issuer", issuer).text, issuer);
});

test("opaque evidence IDs use deterministic middle truncation with copy access", () => {
  const id = "tls-certificate-20260914T123456789Z-" + "a".repeat(96);
  const first = Display.describeSemanticValue("Evidence ID", id);
  const second = Display.describeSemanticValue("Evidence ID", id);
  assert.deepEqual(first, second);
  assert.equal(first.kind, "opaque");
  assert.equal(first.copyable, true);
  assert.equal(first.truncated, true);
  assert.equal(first.text.length, Display.OPAQUE_VALUE_LIMIT);
  assert.equal(first.text.slice(0, 18), id.slice(0, 18));
  assert.match(first.text, /a$/);
  assert.equal(first.fullText, id);
});

test("long failure and limitation prose plus raw JSON stay intact", () => {
  const prose = "The enterprise proxy returned a limitation explaining that the selected route could not expose the intermediate responder metadata before the bounded observation window ended.";
  const json = JSON.stringify({
    evidence_id: "packet-flow-" + "x".repeat(90),
    limitation: prose,
  });
  assert.equal(Display.describeSemanticValue("Limitations", prose).kind, "prose");
  assert.equal(Display.describeSemanticValue("Raw evidence JSON", json).kind, "raw");
  assert.equal(Display.describeSemanticValue("Limitations", prose).text, prose);
  assert.equal(Display.describeSemanticValue("Raw evidence JSON", json).text, json);
});
