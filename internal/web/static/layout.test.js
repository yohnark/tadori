"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const staticRoot = __dirname;
const index = fs.readFileSync(path.join(staticRoot, "index.html"), "utf8");
const style = fs.readFileSync(path.join(staticRoot, "style.css"), "utf8");
const app = fs.readFileSync(path.join(staticRoot, "app.js"), "utf8");

test("workbench keeps the page as the primary scroll container", () => {
  assert.match(index, /display\.js/);
  assert.match(style, /\.workbench-grid\s*\{[\s\S]*?minmax\(320px, 360px\)/);
  assert.match(style, /\.workbench-inspector\s*\{[\s\S]*?position: sticky;[\s\S]*?align-self: start;/);
  assert.doesNotMatch(style, /\.workbench-inspector\s*\{[\s\S]*?overflow:\s*auto/);
  assert.match(style, /\.observation-table\s*\{[\s\S]*?overflow: visible;/);
  assert.match(style, /\.observation-grid\s*\{[\s\S]*?table-layout: fixed;/);
});

test("semantic values and raw JSON use separate overflow policies", () => {
  assert.match(app, /describeSemanticValue\(label, value\)/);
  assert.match(app, /copyValueButton\(evidenceID, "Copy evidence ID"\)/);
  assert.match(app, /renderCertificateTable\(securityObservation, observation\.certificates\)/);
  assert.match(style, /\.semantic-opaque \.semantic-value-text\s*\{[\s\S]*?text-overflow: ellipsis;[\s\S]*?white-space: nowrap;/);
  assert.match(style, /\.raw-evidence,[\s\S]*?#canonical-json\s*\{[\s\S]*?overflow-x: auto;[\s\S]*?white-space: pre-wrap;/);
});
