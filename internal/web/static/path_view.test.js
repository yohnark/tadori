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

test("Observed Path has a stable graph/table workbench contract", () => {
  assert.equal(includesAll(index, [
    'id="observed-path-panel"',
    'class="path-view-switch"',
    'data-path-view="graph"',
    'data-path-view="table"',
    'id="path-graph-view"',
    'id="path-table-view"',
    'role="tablist"',
  ]), true);
});

test("Observed Path graph shell reserves each future layout concern", () => {
  assert.equal(includesAll(index, [
    "Probe vantage",
    "TTL responder slots",
    "one or more responders at a TTL",
    "No response interval",
    "not a packet-loss claim",
    "Confirmation slot",
    "Node selection → Evidence inspector",
  ]), true);
  assert.equal(includesAll(style, [
    ".path-graph-viewport",
    ".graph-scaffold-track",
    ".graph-scaffold-column",
    ".graph-scaffold-gap",
    ".path-graph-reservation",
  ]), true);
});

test("graph states are deliberate and the canonical table remains the fallback", () => {
  assert.equal(includesAll(index, [
    'id="path-graph-loading"',
    'id="path-graph-empty"',
    'id="path-graph-unsupported"',
    'id="path-graph-reserved"',
    'id="path-empty"',
  ]), true);
  assert.equal(includesAll(app, [
    "setPathGraphState(\"loading\")",
    "setPathGraphState(\"empty\")",
    "setPathGraphState(\"unsupported\")",
    "setPathGraphState(\"reserved\")",
    "paths.replaceChildren()",
  ]), true);
});

test("graph renderer does not define a second path-data projection", () => {
  const rendererStart = app.indexOf("function renderPathGraph");
  const rendererEnd = app.indexOf("function renderResponder", rendererStart);
  assert.ok(rendererStart >= 0);
  assert.ok(rendererEnd > rendererStart);
  const renderer = app.slice(rendererStart, rendererEnd);
  assert.match(renderer, /view\.paths/);
  assert.doesNotMatch(renderer, /createElement\([^)]+node/);
  assert.doesNotMatch(renderer, /\.hops/);
  assert.doesNotMatch(renderer, /\.responders/);
});

test("graph renderer consumes the backend graph projection and supports semantic selection", () => {
  assert.equal(includesAll(app, [
    "pathGraphContent",
    "renderGraphLane",
    "renderGraphNode",
    "selectGraphNode",
    "graph.groups",
    "graph.nodes",
    "graph.edges",
    "pathSelection",
    "Destination confirmed",
    "Limitations",
  ]), true);
});

test("narrow screens expose the table fallback affordance", () => {
  assert.match(index, /Narrow-screen fallback:/);
  assert.match(index, /Open Table view/);
  assert.match(style, /\.path-mobile-fallback\s*\{[\s\S]*?display: block;/);
  assert.match(style, /\.path-graph-viewport\s*\{[\s\S]*?overflow-x: auto;/);
});

test("copy keeps observed visibility distinct from physical topology", () => {
  assert.match(index, /responder\/path visibility, not physical topology/);
  assert.match(index, /not physical topology or inferred device identity/);
  assert.match(index, /Canonical graph elements focus retained evidence and semantic details here/);
});
