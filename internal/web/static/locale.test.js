"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const Locale = require("./locale.js");

test("locale selection normalizes supported and unsupported values deterministically", () => {
  assert.equal(Locale.normalizeLocale("ja-JP"), "ja");
  assert.equal(Locale.normalizeLocale("JA"), "ja");
  assert.equal(Locale.normalizeLocale("en-US"), "en");
  assert.equal(Locale.normalizeLocale("fr"), "en");
  assert.equal(Locale.normalizeLocale(null), "en");
});
test("locale resources translate presentation strings without changing values", () => {
  const japanese = Locale.createTranslator("ja");
  assert.equal(japanese("target.diagnose"), "診断");
  assert.equal(japanese("destination.reason", { value: "tcp_timeout" }), "理由: tcp_timeout");
  assert.equal(japanese("enum.failure.tcp_timeout"), "TCP タイムアウト");
  assert.equal(japanese("destination.reason", { value: "203.0.113.7" }), "理由: 203.0.113.7");
});

test("missing locale keys fall back to English and unknown source text stays unchanged", () => {
  const japanese = Locale.createTranslator("ja");
  assert.equal(japanese("target.diagnose"), "診断");
  assert.equal(japanese("does.not.exist"), "does.not.exist");
  assert.equal(Locale.translateSource("unrecognized evidence text", "ja"), "unrecognized evidence text");
  assert.equal(Locale.translateSource("TCP connection was refused.", "ja"), "TCP 接続が拒否されました。");
});
