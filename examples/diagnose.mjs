// Library-API example: simulate the three most common webhook-verification
// failures and let the diagnosis engine name each root cause. Runs offline
// and deterministically (fixed clock, fixed secret). From the repo root:
//
//   npm run build && node examples/diagnose.mjs
//
import { createHmac } from "node:crypto";
import { verify, renderReport } from "../dist/index.js";

const NOW = 1700000000;
const SECRET = "whsec_ZXhhbXBsZV9zZWNyZXQ";
const BODY = '{"id":"evt_1","object":"event","type":"invoice.paid"}';

// What Stripe actually sends: HMAC-SHA256 over `${t}.${body}`, hex, in v1=.
function stripeHeaders(body, t = NOW, secret = SECRET) {
  const mac = createHmac("sha256", secret).update(`${t}.${body}`).digest("hex");
  return { "Stripe-Signature": `t=${t},v1=${mac}` };
}

function show(title, options) {
  console.log(`=== ${title}`);
  console.log(renderReport(verify({ provider: "stripe", now: NOW, ...options })));
}

// 1. Your framework parsed and re-serialized the JSON body before you
//    verified it — the single most common Stripe integration bug.
const pretty = JSON.stringify(JSON.parse(BODY), null, 2);
show("body re-serialized by middleware", {
  secret: SECRET,
  payload: pretty,
  headers: stripeHeaders(BODY),
});

// 2. A replayed delivery from an hour ago: the MAC is valid, the clock is not.
show("stale replay (signature valid, timestamp not)", {
  secret: SECRET,
  payload: BODY,
  headers: stripeHeaders(BODY, NOW - 3600),
});

// 3. The signing side hex-encoded correctly but you compared against base64.
const b64 = createHmac("sha256", SECRET).update(`${NOW}.${BODY}`).digest("base64");
show("signature re-encoded as base64", {
  secret: SECRET,
  payload: BODY,
  headers: { "Stripe-Signature": `t=${NOW},v1=${b64}` },
});
