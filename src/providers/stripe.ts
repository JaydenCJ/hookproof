/**
 * Stripe webhook signatures.
 *
 * Header:    Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>][,v0=<hex>]
 * Canonical: `${t}.${body}` — the raw timestamp string, a dot, the raw body.
 * MAC:       HMAC-SHA256, lowercase hex.
 * Secret:    the endpoint's `whsec_…` string, used VERBATIM as the key
 *            (the prefix is part of the key material — a common trap).
 * Replay:    Stripe's SDKs default to a 300 s tolerance.
 */

import { hmacString } from "../hmac.js";
import { bytesToHex } from "../encoding.js";
import type { Extraction, ProviderSpec } from "../types.js";
import { malformedHeader, missingHeader, rawSecretKey, schemeMismatch } from "./common.js";

export const stripe: ProviderSpec = {
  id: "stripe",
  label: "Stripe",
  signatureHeader: "Stripe-Signature",
  algorithm: "sha256",
  encoding: "hex",
  scheme: "HMAC-SHA256 over `{t}.{body}`, hex in `v1=`",
  toleranceSeconds: 300,
  secretHint: "the endpoint's whsec_… string, used verbatim (keep the prefix)",

  extract(headers): Extraction {
    const raw = headers["stripe-signature"];
    if (raw === undefined) {
      return { signatures: [], ignored: [], problems: [missingHeader("Stripe-Signature", "Stripe")] };
    }
    const out: Extraction = { signatures: [], rawHeader: raw, ignored: [], problems: [] };
    for (const part of raw.split(",")) {
      const item = part.trim();
      if (item === "") continue;
      const eq = item.indexOf("=");
      if (eq <= 0) {
        out.problems.push(
          malformedHeader("Stripe-Signature", `element "${item}" is not a key=value pair`),
        );
        continue;
      }
      const key = item.slice(0, eq);
      const value = item.slice(eq + 1);
      if (key === "t") out.timestampRaw = value;
      else if (key === "v1") out.signatures.push(value);
      else out.ignored.push(item);
    }
    if (out.timestampRaw === undefined) {
      out.problems.push(
        malformedHeader(
          "Stripe-Signature",
          "no t= timestamp element",
          "the canonical string is `{t}.{body}` — without t= nothing can be verified",
        ),
      );
    }
    if (out.signatures.length === 0) {
      const v0 = out.ignored.some((item) => item.startsWith("v0="));
      out.problems.push(
        v0
          ? schemeMismatch(
              "Stripe-Signature carries only a v0= signature, no v1=",
              "v0 is signed with a different (legacy test) secret; live verification uses the v1 element",
            )
          : malformedHeader("Stripe-Signature", "no v1= signature element"),
      );
    }
    return out;
  },

  canonical(payload, parts) {
    return `${parts.timestampRaw ?? ""}.${payload}`;
  },

  keyBytes: rawSecretKey,

  formatSignature(value) {
    return `v1=${value}`;
  },

  sign(input) {
    const canonical = `${input.timestamp}.${input.payload}`;
    const key = rawSecretKey(input.secret);
    if ("error" in key) throw new Error(key.error.message);
    const mac = bytesToHex(hmacString("sha256", key.bytes, canonical));
    return {
      provider: "stripe",
      headers: [{ name: "Stripe-Signature", value: `t=${input.timestamp},v1=${mac}` }],
      canonical,
    };
  },
};
