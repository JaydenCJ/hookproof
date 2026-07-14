// Shared test helpers. Reference MACs are computed here with node:crypto +
// Buffer — a codepath fully independent of the hand-rolled codecs in
// src/encoding.ts — so a passing test cross-checks two implementations
// against each other. Everything is offline and deterministic: fixed
// payloads, fixed secrets, fixed clocks injected via --now / options.now.
import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const CLI = join(ROOT, "dist", "cli.js");

/** Fixed test clock (2023-11-14T22:13:20Z) used everywhere a "now" is needed. */
export const NOW = 1700000000;

export const PAYLOAD = '{"id":"evt_1","type":"charge.succeeded","amount":1999}';

/** Reference HMAC via Buffer/node:crypto (independent of src/encoding.ts). */
export function refHmacHex(secret, message, algorithm = "sha256") {
  return createHmac(algorithm, secret).update(message, "utf8").digest("hex");
}

export function refHmacBase64(secret, message, algorithm = "sha256") {
  return createHmac(algorithm, secret).update(message, "utf8").digest("base64");
}

/** Build a valid Stripe-Signature header for (secret, payload, t). */
export function stripeHeader(secret, payload, t = NOW) {
  return { "stripe-signature": `t=${t},v1=${refHmacHex(secret, `${t}.${payload}`)}` };
}

/** Build valid GitHub signature headers. */
export function githubHeaders(secret, payload) {
  return {
    "x-hub-signature-256": `sha256=${refHmacHex(secret, payload)}`,
    "x-hub-signature": `sha1=${refHmacHex(secret, payload, "sha1")}`,
  };
}

/** Build valid Slack headers. */
export function slackHeaders(secret, payload, t = NOW) {
  return {
    "x-slack-request-timestamp": String(t),
    "x-slack-signature": `v0=${refHmacHex(secret, `v0:${t}:${payload}`)}`,
  };
}

/** A Svix-family secret whose key bytes are `keyText` (ASCII). */
export function svixSecret(keyText) {
  return `whsec_${Buffer.from(keyText, "utf8").toString("base64")}`;
}

/** Build valid Svix-family headers for a given header prefix. */
export function svixHeaders(keyText, payload, { prefix = "svix", id = "msg_42", t = NOW } = {}) {
  const mac = createHmac("sha256", Buffer.from(keyText, "utf8"))
    .update(`${id}.${t}.${payload}`, "utf8")
    .digest("base64");
  return {
    [`${prefix}-id`]: id,
    [`${prefix}-timestamp`]: String(t),
    [`${prefix}-signature`]: `v1,${mac}`,
  };
}

/** Find the first finding with the given id, or undefined. */
export function finding(report, id) {
  return report.findings.find((f) => f.id === id);
}

/** Assert-style helper: list of finding ids in order. */
export function findingIds(report) {
  return report.findings.map((f) => f.id);
}

/**
 * Run the compiled CLI. Returns { stdout, stderr, code }; never throws on
 * non-zero exit so tests can assert failure paths.
 */
export function runCli(args, { input = "" } = {}) {
  try {
    const stdout = execFileSync("node", [CLI, ...args], { input, encoding: "utf8" });
    return { stdout, stderr: "", code: 0 };
  } catch (err) {
    return {
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? "",
      code: err.status ?? 1,
    };
  }
}
