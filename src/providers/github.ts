/**
 * GitHub webhook signatures.
 *
 * Header:    X-Hub-Signature-256: sha256=<hex>
 * Canonical: the raw request body, nothing else (no timestamp in the scheme).
 * MAC:       HMAC-SHA256, lowercase hex, prefixed `sha256=`.
 * Legacy:    X-Hub-Signature: sha1=<hex> is still delivered alongside; it is
 *            NOT accepted here, but its presence is diagnosed when the
 *            modern header is missing.
 * Secret:    the webhook secret string, used verbatim.
 */

import { hmacString } from "../hmac.js";
import { bytesToHex, hexToBytes } from "../encoding.js";
import type { Extraction, ProviderSpec } from "../types.js";
import { missingHeader, rawSecretKey, schemeMismatch } from "./common.js";

export const github: ProviderSpec = {
  id: "github",
  label: "GitHub",
  signatureHeader: "X-Hub-Signature-256",
  algorithm: "sha256",
  encoding: "hex",
  scheme: "HMAC-SHA256 over the raw body, hex after `sha256=`",
  toleranceSeconds: null,
  secretHint: "the webhook's secret string, used verbatim",

  extract(headers): Extraction {
    const raw = headers["x-hub-signature-256"];
    if (raw === undefined) {
      const legacy = headers["x-hub-signature"];
      const problems = [missingHeader("X-Hub-Signature-256", "GitHub")];
      const out: Extraction = { signatures: [], ignored: [], problems };
      if (legacy !== undefined) {
        // Surface the legacy value so the diagnosis engine can prove it is
        // the SHA-1 MAC of the same body ("algorithm-mismatch").
        out.signatures.push(legacy.startsWith("sha1=") ? legacy.slice(5) : legacy);
        out.rawHeader = legacy;
        problems.push(
          schemeMismatch(
            "only the legacy X-Hub-Signature (HMAC-SHA1) header is present",
            "read X-Hub-Signature-256 instead; SHA-1 verification is deprecated by GitHub",
          ),
        );
      }
      return out;
    }
    const out: Extraction = { signatures: [], rawHeader: raw, ignored: [], problems: [] };
    if (raw.startsWith("sha256=")) {
      out.signatures.push(raw.slice("sha256=".length));
    } else if (hexToBytes(raw) !== null) {
      out.signatures.push(raw);
      out.problems.push(
        schemeMismatch(
          "X-Hub-Signature-256 is a bare digest without the sha256= prefix",
          'GitHub always sends "sha256=<hex>"; if you generated this value yourself, prepend the prefix',
        ),
      );
    } else {
      out.signatures.push(raw);
      out.problems.push(
        schemeMismatch(
          `X-Hub-Signature-256 starts with "${raw.slice(0, Math.min(raw.length, 12))}" instead of "sha256="`,
          'expected the exact form "sha256=<64 hex chars>"',
        ),
      );
    }
    return out;
  },

  canonical(payload) {
    return payload;
  },

  keyBytes: rawSecretKey,

  formatSignature(value) {
    return `sha256=${value}`;
  },

  sign(input) {
    const key = rawSecretKey(input.secret);
    if ("error" in key) throw new Error(key.error.message);
    const sha256 = bytesToHex(hmacString("sha256", key.bytes, input.payload));
    const sha1 = bytesToHex(hmacString("sha1", key.bytes, input.payload));
    return {
      provider: "github",
      headers: [
        { name: "X-Hub-Signature-256", value: `sha256=${sha256}` },
        { name: "X-Hub-Signature", value: `sha1=${sha1}` },
      ],
      canonical: input.payload,
    };
  },
};
