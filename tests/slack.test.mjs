// Slack scheme tests: the `v0:{ts}:{body}` base string (version INSIDE the
// signed string), the v0= header prefix, and the 5-minute replay window.
import assert from "node:assert/strict";
import test from "node:test";
import { verify, signRequest } from "../dist/index.js";
import { NOW, PAYLOAD, finding, refHmacHex, slackHeaders } from "./helpers.mjs";

const SECRET = "8f742231b10e8888abcd99yyyzzz85a5";

test("a correctly signed request verifies", () => {
  const report = verify({
    provider: "slack",
    secret: SECRET,
    payload: PAYLOAD,
    headers: slackHeaders(SECRET, PAYLOAD),
    now: NOW + 30,
  });
  assert.equal(report.ok, true);
});

test("the base string is v0:{timestamp}:{body}", () => {
  const report = verify({
    provider: "slack",
    secret: SECRET,
    payload: PAYLOAD,
    headers: slackHeaders(SECRET, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.canonical.value, `v0:${NOW}:${PAYLOAD}`);
  assert.equal(report.expected.value, refHmacHex(SECRET, `v0:${NOW}:${PAYLOAD}`));
});

test("a missing timestamp header is its own finding", () => {
  const report = verify({
    provider: "slack",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "x-slack-signature": `v0=${"a".repeat(64)}` },
    now: NOW,
  });
  assert.equal(report.ok, false);
  const f = finding(report, "header-missing");
  assert.match(f.message, /X-Slack-Request-Timestamp/);
});

test("a signature without the v0= prefix is scheme-mismatch", () => {
  const good = refHmacHex(SECRET, `v0:${NOW}:${PAYLOAD}`);
  const report = verify({
    provider: "slack",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "x-slack-request-timestamp": String(NOW), "x-slack-signature": good },
    now: NOW,
  });
  assert.equal(report.ok, false);
  assert.ok(finding(report, "scheme-mismatch"));
});

test("a replayed request outside the window fails with timestamp-skew", () => {
  const report = verify({
    provider: "slack",
    secret: SECRET,
    payload: PAYLOAD,
    headers: slackHeaders(SECRET, PAYLOAD, NOW - 3600),
    now: NOW,
  });
  assert.equal(report.ok, false);
  const f = finding(report, "timestamp-skew");
  assert.match(f.message, /3600s in the past/);
});

test("a non-numeric timestamp is timestamp-invalid", () => {
  const report = verify({
    provider: "slack",
    secret: SECRET,
    payload: PAYLOAD,
    headers: {
      "x-slack-request-timestamp": "2023-11-14T22:13:20Z",
      "x-slack-signature": `v0=${"a".repeat(64)}`,
    },
    now: NOW,
  });
  assert.equal(report.ok, false);
  const f = finding(report, "timestamp-invalid");
  assert.match(f.fix, /epoch seconds/);
});

test("signRequest round-trips through verify", () => {
  const signed = signRequest({ provider: "slack", secret: SECRET, payload: PAYLOAD, timestamp: NOW });
  const headers = Object.fromEntries(signed.headers.map((h) => [h.name, h.value]));
  const report = verify({ provider: "slack", secret: SECRET, payload: PAYLOAD, headers, now: NOW + 10 });
  assert.equal(report.ok, true);
});
