// Diagnosis-engine tests. Each test constructs a request that fails strict
// verification for ONE specific reason and asserts the engine names exactly
// that root cause — these are the scenarios the tool exists for.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { verify, payloadVariants } from "../dist/index.js";
import { NOW, PAYLOAD, finding, findingIds, refHmacHex, stripeHeader, svixHeaders, svixSecret } from "./helpers.mjs";

const SECRET = "whsec_ZGlhZ25vc2lzX3NlY3JldA";

function verifyStripe(payload, headers, secret = SECRET, extra = {}) {
  return verify({ provider: "stripe", secret, payload, headers, now: NOW, ...extra });
}

test("trailing newline stripped from the payload → payload-newline", () => {
  const signedBody = PAYLOAD + "\n"; // sender signed WITH the newline
  const report = verifyStripe(PAYLOAD, stripeHeader(SECRET, signedBody));
  assert.equal(report.ok, false);
  const f = finding(report, "payload-newline");
  assert.match(f.message, /trailing newline appended/);
});

test("trailing newline added to the payload → payload-newline (other direction)", () => {
  const report = verifyStripe(PAYLOAD + "\n", stripeHeader(SECRET, PAYLOAD));
  const f = finding(report, "payload-newline");
  assert.match(f.message, /removed/);
});

test("CRLF capture of an LF body → payload-crlf", () => {
  const lfBody = '{"a":1}\n{"b":2}\n';
  const crlfBody = lfBody.replace(/\n/g, "\r\n");
  const report = verifyStripe(crlfBody, stripeHeader(SECRET, lfBody));
  assert.ok(finding(report, "payload-crlf"));
});

test("LF capture of a CRLF body → payload-crlf (other direction)", () => {
  const crlfBody = "line1\r\nline2\r\n";
  const lfBody = crlfBody.replace(/\r\n/g, "\n");
  const report = verifyStripe(lfBody, stripeHeader(SECRET, crlfBody));
  const f = finding(report, "payload-crlf");
  assert.match(f.message, /LF to CRLF/);
});

test("UTF-8 BOM prepended by an editor → payload-bom", () => {
  const report = verifyStripe("\ufeff" + PAYLOAD, stripeHeader(SECRET, PAYLOAD));
  assert.ok(finding(report, "payload-bom"));
});

test("pretty-printed JSON body → payload-reserialized", () => {
  const pretty = JSON.stringify(JSON.parse(PAYLOAD), null, 2);
  const report = verifyStripe(pretty, stripeHeader(SECRET, PAYLOAD));
  const f = finding(report, "payload-reserialized");
  assert.match(f.fix, /RAW request bytes/);
});

test("secret with a trailing newline from .env → secret-whitespace", () => {
  const report = verifyStripe(PAYLOAD, stripeHeader(SECRET, PAYLOAD), SECRET + "\n");
  assert.ok(finding(report, "secret-whitespace"));
});

test("signer stripped the whsec_ prefix → secret-prefix", () => {
  const stripped = SECRET.slice("whsec_".length);
  const report = verifyStripe(PAYLOAD, stripeHeader(stripped, PAYLOAD));
  const f = finding(report, "secret-prefix");
  assert.match(f.message, /whsec_ prefix stripped/);
});

test("verifier missing the whsec_ prefix → secret-prefix (other direction)", () => {
  const report = verifyStripe(PAYLOAD, stripeHeader(SECRET, PAYLOAD), SECRET.slice("whsec_".length));
  const f = finding(report, "secret-prefix");
  assert.match(f.message, /whsec_ prepended/);
});

test("base64(url)-encoded signature where hex is expected → encoding-mismatch", () => {
  const mac = createHmac("sha256", SECRET).update(`${NOW}.${PAYLOAD}`, "utf8").digest("base64");
  const report = verifyStripe(PAYLOAD, { "stripe-signature": `t=${NOW},v1=${mac}` });
  assert.equal(report.ok, false);
  const f = finding(report, "encoding-mismatch");
  assert.match(f.message, /base64-encoded/);
  assert.match(f.message, /lowercase hex/);
  const urlMac = createHmac("sha256", SECRET).update(`${NOW}.${PAYLOAD}`, "utf8").digest("base64url");
  const urlReport = verifyStripe(PAYLOAD, { "stripe-signature": `t=${NOW},v1=${urlMac}` });
  // digest("base64url") may contain no -/_ for some MACs; accept either dialect name.
  assert.match(finding(urlReport, "encoding-mismatch").message, /base64(url)?-encoded/);
});

test("SHA-512 where SHA-256 is expected → algorithm-mismatch plus a length warning", () => {
  const mac = createHmac("sha512", SECRET).update(`${NOW}.${PAYLOAD}`, "utf8").digest("hex");
  const report = verifyStripe(PAYLOAD, { "stripe-signature": `t=${NOW},v1=${mac}` });
  assert.ok(finding(report, "algorithm-mismatch"));
  const len = finding(report, "signature-length");
  assert.match(len.message, /64 bytes/);
});

test("truncated or garbage signature values are named as such", () => {
  const good = refHmacHex(SECRET, `${NOW}.${PAYLOAD}`);
  const report = verifyStripe(PAYLOAD, { "stripe-signature": `t=${NOW},v1=${good.slice(0, 32)}` });
  const f = finding(report, "signature-truncated");
  assert.match(f.message, /32-character prefix/);
  const garbage = verifyStripe(PAYLOAD, { "stripe-signature": `t=${NOW},v1=%%%not-a-mac%%%` });
  assert.ok(finding(garbage, "signature-undecodable"));
});

test("combined failure: newline AND wrong encoding are BOTH reported", () => {
  const mac = createHmac("sha256", SECRET).update(`${NOW}.${PAYLOAD}\n`, "utf8").digest("base64");
  const report = verifyStripe(PAYLOAD, { "stripe-signature": `t=${NOW},v1=${mac}` });
  const ids = findingIds(report);
  assert.ok(ids.includes("payload-newline"), `missing payload-newline in ${ids}`);
  assert.ok(ids.includes("encoding-mismatch"), `missing encoding-mismatch in ${ids}`);
});

test("wrong provider with the right secret → wrong-provider names the fix", () => {
  const headers = svixHeaders("sharedkeymaterial", PAYLOAD);
  const report = verify({
    provider: "stripe",
    secret: svixSecret("sharedkeymaterial"),
    payload: PAYLOAD,
    headers,
    now: NOW,
  });
  const f = finding(report, "wrong-provider");
  assert.match(f.fix, /--provider svix/);
});

test("no transform matching → the fallback verdict is secret-mismatch alone", () => {
  const report = verifyStripe(PAYLOAD, stripeHeader("whsec_completely_other", PAYLOAD));
  const errors = report.findings.filter((f) => f.severity === "error");
  assert.equal(errors.length, 1);
  assert.equal(errors[0].id, "secret-mismatch");
});

test("diagnose: false suppresses the diagnosis pass", () => {
  const report = verifyStripe(PAYLOAD + "\n", stripeHeader(SECRET, PAYLOAD), SECRET, { diagnose: false });
  assert.equal(report.ok, false);
  assert.deepEqual(findingIds(report), []);
});

test("payloadVariants proposes the minimal transform set and never duplicates", () => {
  const variants = payloadVariants('{"a": 1}\r\n');
  const values = variants.map((v) => v.value);
  assert.equal(new Set(values).size, values.length, "variants must be unique");
  assert.equal(variants[0].finding, null, "first variant is the original");
  assert.ok(values.includes('{"a": 1}\r\n'.replace(/\r\n/g, "\n")));
  assert.ok(values.includes('{"a":1}'), "compact JSON re-serialization included");
});

test("diagnosis is deterministic: identical inputs give identical findings", () => {
  const run = () =>
    JSON.stringify(verifyStripe(PAYLOAD + "\n", stripeHeader(SECRET, PAYLOAD)).findings);
  assert.equal(run(), run());
});
