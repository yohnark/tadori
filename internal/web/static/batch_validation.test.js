"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const staticRoot = __dirname;
const index = fs.readFileSync(path.join(staticRoot, "index.html"), "utf8");
const style = fs.readFileSync(path.join(staticRoot, "style.css"), "utf8");
const app = fs.readFileSync(path.join(staticRoot, "app.js"), "utf8");

function includesAll(source, fragments) {
  return fragments.every((fragment) => source.includes(fragment));
}

test("browser capture exposes all, failed-only, and manual validation actions", () => {
  assert.equal(includesAll(index, [
    'id="browser-capture-validate-all"',
    'id="browser-capture-validate-failed"',
    'id="browser-capture-validate-selected"',
    'id="browser-validation-panel"',
  ]), true);
  assert.match(app, /startBrowserValidation\("failed_only", \[\]\)/);
  assert.match(app, /startBrowserValidation\("selected", Array\.from\(selectedCaptureDestinations\)\)/);
});

test("validation table keeps capture and active observations separate", () => {
  assert.equal(includesAll(index, [
    "Capture",
    "Validation",
    "DNS",
    "TCP",
    "TLS / app",
    "Failure boundary",
    "Export Failed Identities",
  ]), true);
  assert.equal(includesAll(app, [
    "result.capture_outcome",
    "result.validation_outcome",
    "result.failure_boundary",
    "/api/browser-capture-validations/",
    "/failed.txt",
  ]), true);
  assert.match(style, /\.browser-validation-table[\s\S]*?validation-negative/);
});

test("endpoint reports are linked only when an active canonical report exists", () => {
  const rendererStart = app.indexOf("function renderBrowserValidation");
  const rendererEnd = app.indexOf("function clearBrowserValidationPoll", rendererStart);
  assert.ok(rendererStart >= 0);
  assert.ok(rendererEnd > rendererStart);
  const renderer = app.slice(rendererStart, rendererEnd);
  assert.match(renderer, /result\.report && activeValidationID/);
  assert.match(renderer, /\/endpoints\/\$\{encodeURIComponent\(result\.id\)\}\/report\.json/);
});
