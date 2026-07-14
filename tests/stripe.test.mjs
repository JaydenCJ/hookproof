// Stripe scheme tests: canonical string `{t}.{body}`, verbatim whsec_ key,
// hex v1 signatures, multiple v1 elements during secret rolls, the v0
// legacy element, and the replay window.
import assert from "node:assert/strict";
import test from "node:test";
import { verify, signRequest, stripe } from "../dist/index.js";
import { NOW, PAYLOAD, finding, findingIds, refHmacHex, stripeHeader } from "./helpers.mjs";

const SECRET = "whsec_c2lnbmluZ19zZWNyZXQ";

test("a correctly signed request verifies", () => {
  const report = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: stripeHeader(SECRET, PAYLOAD),
    now: NOW + 5,
  });
  assert.equal(report.ok, true);
  assert.equal(report.signatureMatch, true);
  assert.deepEqual(findingIds(report), []);
});

test("the canonical string is the raw timestamp, a dot, the raw body", () => {
  const report = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: stripeHeader(SECRET, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.canonical.value, `${NOW}.${PAYLOAD}`);
  assert.equal(report.expected.value, refHmacHex(SECRET, `${NOW}.${PAYLOAD}`));
  assert.equal(report.expected.encoding, "hex");
});

test("any one of several v1 elements matching passes (secret roll), even uppercase hex", () => {
  // The whsec_ prefix is part of the key material — a stripped-prefix MAC differs.
  assert.notEqual(
    refHmacHex(SECRET, `${NOW}.${PAYLOAD}`),
    refHmacHex(SECRET.slice("whsec_".length), `${NOW}.${PAYLOAD}`),
  );
  const good = refHmacHex(SECRET, `${NOW}.${PAYLOAD}`);
  const stale = "0".repeat(64);
  const rolled = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "stripe-signature": `t=${NOW},v1=${stale},v1=${good}` },
    now: NOW,
  });
  assert.equal(rolled.ok, true);
  // Hex comparison is case-insensitive, like the providers' own SDKs.
  const upper = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "stripe-signature": `t=${NOW},v1=${good.toUpperCase()}` },
    now: NOW,
  });
  assert.equal(upper.ok, true);
});

test("a v0-only header fails with scheme-mismatch, not a bare boolean", () => {
  const report = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "stripe-signature": `t=${NOW},v0=${"a".repeat(64)}` },
    now: NOW,
  });
  assert.equal(report.ok, false);
  const f = finding(report, "scheme-mismatch");
  assert.ok(f, "expected a scheme-mismatch finding");
  assert.match(f.message, /v0/);
});

test("a missing t= element or a missing header is a structural finding", () => {
  const noTimestamp = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { "stripe-signature": `v1=${"a".repeat(64)}` },
    now: NOW,
  });
  assert.equal(noTimestamp.ok, false);
  assert.ok(finding(noTimestamp, "header-malformed"));
  assert.equal(noTimestamp.canonical, null, "no canonical string without a timestamp");
  const noHeader = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: {},
    now: NOW,
  });
  assert.equal(noHeader.ok, false);
  assert.equal(finding(noHeader, "header-missing").severity, "error");
});

test("an old timestamp fails with timestamp-skew even when the MAC is valid", () => {
  const report = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: stripeHeader(SECRET, PAYLOAD, NOW - 1000),
    now: NOW,
  });
  assert.equal(report.ok, false);
  assert.equal(report.signatureMatch, true, "the MAC itself is correct");
  const f = finding(report, "timestamp-skew");
  assert.match(f.message, /cryptographically valid/);
  assert.match(f.message, /1000s in the past/);
});

test("toleranceSeconds widens the replay window", () => {
  const report = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: stripeHeader(SECRET, PAYLOAD, NOW - 1000),
    now: NOW,
    toleranceSeconds: 2000,
  });
  assert.equal(report.ok, true);
});

test("signRequest emits a header that verify round-trips", () => {
  const signed = signRequest({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    timestamp: NOW,
  });
  assert.equal(signed.headers.length, 1);
  assert.equal(signed.headers[0].name, "Stripe-Signature");
  assert.equal(signed.canonical, `${NOW}.${PAYLOAD}`);
  const report = verify({
    provider: "stripe",
    secret: SECRET,
    payload: PAYLOAD,
    headers: { [signed.headers[0].name]: signed.headers[0].value },
    now: NOW + 60,
  });
  assert.equal(report.ok, true);
  // Provider metadata matches the published scheme.
  assert.equal(stripe.algorithm, "sha256");
  assert.equal(stripe.encoding, "hex");
  assert.equal(stripe.toleranceSeconds, 300);
});
