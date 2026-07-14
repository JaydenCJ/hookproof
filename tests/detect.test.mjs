// Provider auto-detection tests: the signature header anchors detection,
// companion headers upgrade confidence, and ambiguous bags stay honest.
import assert from "node:assert/strict";
import test from "node:test";
import { detectProviders } from "../dist/index.js";
import { PAYLOAD, githubHeaders, slackHeaders, stripeHeader, svixHeaders } from "./helpers.mjs";

test("each provider's own headers are detected as certain", () => {
  const cases = [
    ["stripe", stripeHeader("whsec_x", PAYLOAD)],
    ["github", githubHeaders("s", PAYLOAD)],
    ["slack", slackHeaders("s", PAYLOAD)],
    ["svix", svixHeaders("k", PAYLOAD)],
    ["standard", svixHeaders("k", PAYLOAD, { prefix: "webhook" })],
  ];
  for (const [expected, headers] of cases) {
    const detections = detectProviders(headers);
    assert.equal(detections[0]?.provider, expected, `expected ${expected}`);
    assert.equal(detections[0]?.confidence, "certain");
  }
  // Detection is purely header-name based; values are not inspected.
  assert.equal(detectProviders({ "stripe-signature": "utterly wrong value" })[0].provider, "stripe");
});

test("unrelated headers detect nothing", () => {
  assert.deepEqual(detectProviders({ "content-type": "application/json", host: "example.test" }), []);
});

test("slack signature without its timestamp header is only likely", () => {
  const detections = detectProviders({ "x-slack-signature": "v0=abc" });
  assert.equal(detections[0].provider, "slack");
  assert.equal(detections[0].confidence, "likely");
  assert.deepEqual(detections[0].missing, ["x-slack-request-timestamp"]);
});

test("the legacy x-hub-signature header alone still identifies GitHub", () => {
  const detections = detectProviders({ "x-hub-signature": "sha1=abc" });
  assert.equal(detections[0].provider, "github");
  assert.equal(detections[0].confidence, "likely");
});

test("multiple schemes in one bag are all reported, most complete first", () => {
  const headers = { ...stripeHeader("whsec_x", PAYLOAD), "x-slack-signature": "v0=abc" };
  const detections = detectProviders(headers);
  assert.equal(detections.length, 2);
  assert.equal(detections[0].provider, "stripe");
  assert.equal(detections[0].confidence, "certain");
  assert.equal(detections[1].provider, "slack");
});
