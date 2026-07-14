// GitHub scheme tests: HMAC over the bare body, `sha256=` prefix handling,
// the legacy SHA-1 header, and the absence of any timestamp in the scheme.
import assert from "node:assert/strict";
import test from "node:test";
import { verify, signRequest, github } from "../dist/index.js";
import { NOW, PAYLOAD, finding, githubHeaders, refHmacHex } from "./helpers.mjs";

const SECRET = "octocat-webhook-secret";

test("a correctly signed request verifies", () => {
  const report = verify({
    provider: "github",
    secret: SECRET,
    payload: PAYLOAD,
    headers: githubHeaders(SECRET, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.ok, true);
  assert.equal(report.timestamp, null, "the GitHub scheme has no timestamp");
});

test("the canonical string is exactly the raw body", () => {
  const report = verify({
    provider: "github",
    secret: SECRET,
    payload: PAYLOAD,
    headers: githubHeaders(SECRET, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.canonical.value, PAYLOAD);
  assert.equal(report.expected.value, refHmacHex(SECRET, PAYLOAD));
});

test("header names are case-insensitive", () => {
  const value = `sha256=${refHmacHex(SECRET, PAYLOAD)}`;
  const report = verify({
    provider: "github",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "X-HUB-SIGNATURE-256": value },
    now: NOW,
  });
  assert.equal(report.ok, true);
});

test("a bare digest without sha256= fails with scheme-mismatch but names the real cause", () => {
  const report = verify({
    provider: "github",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "x-hub-signature-256": refHmacHex(SECRET, PAYLOAD) },
    now: NOW,
  });
  assert.equal(report.ok, false);
  const f = finding(report, "scheme-mismatch");
  assert.match(f.message, /without the sha256= prefix/);
  // The digest itself is right, so no secret-mismatch noise should appear.
  assert.equal(finding(report, "secret-mismatch"), undefined);
});

test("only the legacy SHA-1 header present: diagnosed as algorithm-mismatch", () => {
  const report = verify({
    provider: "github",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "x-hub-signature": `sha1=${refHmacHex(SECRET, PAYLOAD, "sha1")}` },
    now: NOW,
  });
  assert.equal(report.ok, false);
  assert.ok(finding(report, "header-missing"));
  assert.ok(finding(report, "scheme-mismatch"));
  const f = finding(report, "algorithm-mismatch");
  assert.match(f.message, /HMAC-SHA1/);
});

test("a wrong secret fails with secret-mismatch as the verdict", () => {
  const report = verify({
    provider: "github",
    secret: "the-wrong-secret",
    payload: PAYLOAD,
    headers: githubHeaders(SECRET, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.ok, false);
  assert.ok(finding(report, "secret-mismatch"));
});

test("signRequest emits both modern and legacy headers", () => {
  const signed = signRequest({ provider: "github", secret: SECRET, payload: PAYLOAD, timestamp: NOW });
  const names = signed.headers.map((h) => h.name);
  assert.deepEqual(names, ["X-Hub-Signature-256", "X-Hub-Signature"]);
  assert.match(signed.headers[0].value, /^sha256=[0-9a-f]{64}$/);
  assert.match(signed.headers[1].value, /^sha1=[0-9a-f]{40}$/);
  // Provider metadata matches the published scheme.
  assert.equal(github.toleranceSeconds, null);
  assert.equal(github.signatureHeader, "X-Hub-Signature-256");
});
