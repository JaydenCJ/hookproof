/**
 * Slack request signatures.
 *
 * Headers:   X-Slack-Signature: v0=<hex>
 *            X-Slack-Request-Timestamp: <unix>
 * Canonical: `v0:${timestamp}:${body}` — note the version PREFIX inside the
 *            signed string, unlike Stripe/Svix where the version only labels
 *            the header element.
 * MAC:       HMAC-SHA256, lowercase hex, prefixed `v0=`.
 * Secret:    the app's Signing Secret (hex-looking string), used verbatim.
 * Replay:    Slack documents a 5 minute window.
 */

import { hmacString } from "../hmac.js";
import { bytesToHex } from "../encoding.js";
import type { Extraction, ProviderSpec } from "../types.js";
import { missingHeader, rawSecretKey, schemeMismatch } from "./common.js";

export const slack: ProviderSpec = {
  id: "slack",
  label: "Slack",
  signatureHeader: "X-Slack-Signature",
  timestampHeader: "X-Slack-Request-Timestamp",
  algorithm: "sha256",
  encoding: "hex",
  scheme: "HMAC-SHA256 over `v0:{ts}:{body}`, hex after `v0=`",
  toleranceSeconds: 300,
  secretHint: "the app's Signing Secret from the app config page, used verbatim",

  extract(headers): Extraction {
    const raw = headers["x-slack-signature"];
    const ts = headers["x-slack-request-timestamp"];
    const out: Extraction = { signatures: [], ignored: [], problems: [] };
    if (ts !== undefined) out.timestampRaw = ts;
    else out.problems.push(missingHeader("X-Slack-Request-Timestamp", "Slack"));
    if (raw === undefined) {
      out.problems.push(missingHeader("X-Slack-Signature", "Slack"));
      return out;
    }
    out.rawHeader = raw;
    if (raw.startsWith("v0=")) {
      out.signatures.push(raw.slice(3));
    } else {
      out.signatures.push(raw);
      out.problems.push(
        schemeMismatch(
          'X-Slack-Signature does not start with "v0="',
          'Slack sends "v0=<hex>", and the same "v0" also opens the signed base string',
        ),
      );
    }
    return out;
  },

  canonical(payload, parts) {
    return `v0:${parts.timestampRaw ?? ""}:${payload}`;
  },

  keyBytes: rawSecretKey,

  formatSignature(value) {
    return `v0=${value}`;
  },

  sign(input) {
    const canonical = `v0:${input.timestamp}:${input.payload}`;
    const key = rawSecretKey(input.secret);
    if ("error" in key) throw new Error(key.error.message);
    const mac = bytesToHex(hmacString("sha256", key.bytes, canonical));
    return {
      provider: "slack",
      headers: [
        { name: "X-Slack-Request-Timestamp", value: String(input.timestamp) },
        { name: "X-Slack-Signature", value: `v0=${mac}` },
      ],
      canonical,
    };
  },
};
