// Svix + Standard Webhooks scheme tests. The two share one implementation
// (only header names differ), so both are exercised here: base64-decoded
// whsec_ keys, `{id}.{ts}.{body}` canonical strings, space-separated
// multi-signature headers, and the v1a asymmetric tokens that must be
// ignored rather than break verification.
import assert from "node:assert/strict";
import test from "node:test";
import { verify, signRequest, svix, standard } from "../dist/index.js";
import { NOW, PAYLOAD, finding, svixHeaders, svixSecret } from "./helpers.mjs";

const KEY_TEXT = "supersecretkeymaterial";
const SECRET = svixSecret(KEY_TEXT);

test("a correctly signed svix request verifies", () => {
  const report = verify({
    provider: "svix",
    secret: SECRET,
    payload: PAYLOAD,
    headers: svixHeaders(KEY_TEXT, PAYLOAD),
    now: NOW + 5,
  });
  assert.equal(report.ok, true);
  assert.equal(report.expected.encoding, "base64");
});

test("the canonical string is {id}.{timestamp}.{body}", () => {
  const report = verify({
    provider: "svix",
    secret: SECRET,
    payload: PAYLOAD,
    headers: svixHeaders(KEY_TEXT, PAYLOAD, { id: "msg_2b9Xkd" }),
    now: NOW,
  });
  assert.equal(report.canonical.value, `msg_2b9Xkd.${NOW}.${PAYLOAD}`);
});

test("the key is the DECODED bytes: literal-string keys produce a different MAC", () => {
  // Sign with the literal secret string as key — the classic bug.
  const headers = svixHeaders(SECRET, PAYLOAD);
  const report = verify({
    provider: "svix",
    secret: SECRET,
    payload: PAYLOAD,
    headers,
    now: NOW,
  });
  assert.equal(report.ok, false);
  const f = finding(report, "secret-encoding");
  assert.match(f.message, /LITERAL secret string/);
});

test("a secret without the whsec_ prefix still decodes", () => {
  const bare = SECRET.slice("whsec_".length);
  const report = verify({
    provider: "svix",
    secret: bare,
    payload: PAYLOAD,
    headers: svixHeaders(KEY_TEXT, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.ok, true);
});

test("a secret that is not base64 at all is secret-encoding", () => {
  const report = verify({
    provider: "svix",
    secret: "whsec_!!!not-base64!!!",
    payload: PAYLOAD,
    headers: svixHeaders(KEY_TEXT, PAYLOAD),
    now: NOW,
  });
  assert.equal(report.ok, false);
  assert.ok(finding(report, "secret-encoding"));
});

test("any matching signature in a space-separated list passes (key rotation)", () => {
  const headers = svixHeaders(KEY_TEXT, PAYLOAD);
  headers["svix-signature"] = `v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= ${headers["svix-signature"]}`;
  const report = verify({ provider: "svix", secret: SECRET, payload: PAYLOAD, headers, now: NOW });
  assert.equal(report.ok, true);
});

test("v1a asymmetric tokens are ignored, not fatal — unless they are all there is", () => {
  const headers = svixHeaders(KEY_TEXT, PAYLOAD);
  headers["svix-signature"] = `v1a,dGhpcyBpcyBub3QgYW4gaG1hYw== ${headers["svix-signature"]}`;
  const mixed = verify({ provider: "svix", secret: SECRET, payload: PAYLOAD, headers, now: NOW });
  assert.equal(mixed.ok, true);
  assert.equal(finding(mixed, "scheme-mismatch").severity, "info", "ignored token surfaced as info");
  const onlyV1a = { ...svixHeaders(KEY_TEXT, PAYLOAD), "svix-signature": "v1a,dGhpcyBpcyBub3QgYW4gaG1hYw==" };
  const report = verify({ provider: "svix", secret: SECRET, payload: PAYLOAD, headers: onlyV1a, now: NOW });
  assert.equal(report.ok, false);
  assert.ok(finding(report, "header-malformed"));
});

test("a missing svix-id makes the canonical string impossible and is reported", () => {
  const headers = svixHeaders(KEY_TEXT, PAYLOAD);
  delete headers["svix-id"];
  const report = verify({ provider: "svix", secret: SECRET, payload: PAYLOAD, headers, now: NOW });
  assert.equal(report.ok, false);
  assert.equal(report.canonical, null);
  assert.match(finding(report, "header-missing").message, /svix-id/);
});

test("signRequest defaults the message id to msg_<timestamp>", () => {
  const signed = signRequest({ provider: "svix", secret: SECRET, payload: PAYLOAD, timestamp: NOW });
  assert.equal(signed.headers[0].value, `msg_${NOW}`);
  assert.match(signed.headers[2].value, /^v1,[A-Za-z0-9+/]+=*$/);
});

test("standard webhooks: same scheme under webhook-* header names, sign → verify round-trip", () => {
  const headers = svixHeaders(KEY_TEXT, PAYLOAD, { prefix: "webhook" });
  const report = verify({
    provider: "standard",
    secret: SECRET,
    payload: PAYLOAD,
    headers,
    now: NOW + 5,
  });
  assert.equal(report.ok, true);
  assert.equal(report.canonical.value, `msg_42.${NOW}.${PAYLOAD}`);
  const signed = signRequest({
    provider: "standard",
    secret: SECRET,
    payload: PAYLOAD,
    timestamp: NOW,
    id: "msg_std1",
  });
  const roundHeaders = Object.fromEntries(signed.headers.map((h) => [h.name, h.value]));
  assert.ok(roundHeaders["webhook-signature"]);
  const round = verify({ provider: "standard", secret: SECRET, payload: PAYLOAD, headers: roundHeaders, now: NOW });
  assert.equal(round.ok, true);
});

test("svix and standard signatures are interchangeable byte-for-byte", () => {
  // Same id, timestamp, payload, secret → identical MAC under both names.
  const a = signRequest({ provider: "svix", secret: SECRET, payload: PAYLOAD, timestamp: NOW, id: "msg_x" });
  const b = signRequest({ provider: "standard", secret: SECRET, payload: PAYLOAD, timestamp: NOW, id: "msg_x" });
  assert.equal(a.headers[2].value, b.headers[2].value);
  // The two providers differ only in header names, not in the scheme.
  assert.equal(svix.signatureHeader, "svix-signature");
  assert.equal(standard.signatureHeader, "webhook-signature");
  assert.equal(svix.scheme, standard.scheme);
});
