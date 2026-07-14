/**
 * The Svix scheme, which the Standard Webhooks specification adopted
 * verbatim — only the header names differ. Both providers are generated
 * from this factory.
 *
 * Headers:   <prefix>-id: msg_…            (message id)
 *            <prefix>-timestamp: <unix>
 *            <prefix>-signature: v1,<base64> [v1,<base64> …]  (space-separated)
 * Canonical: `${id}.${timestamp}.${body}`
 * MAC:       HMAC-SHA256, STANDARD base64 (with padding) after `v1,`.
 * Secret:    `whsec_` + base64 — the key is the DECODED bytes of the part
 *            after the prefix, not the literal string (the other common trap).
 * Replay:    both ecosystems recommend a 5 minute window.
 */

import { hmacString } from "../hmac.js";
import { base64ToBytes, bytesToBase64 } from "../encoding.js";
import type { Extraction, Finding, ProviderId, ProviderSpec, SignInput, SignedRequest } from "../types.js";
import { malformedHeader, missingHeader } from "./common.js";

const SECRET_PREFIX = "whsec_";

/** Decode a Svix-family secret into key bytes: strip `whsec_`, base64-decode. */
export function svixKeyBytes(secret: string): { bytes: Uint8Array } | { error: Finding } {
  const body = secret.startsWith(SECRET_PREFIX) ? secret.slice(SECRET_PREFIX.length) : secret;
  const bytes = base64ToBytes(body);
  if (bytes === null || bytes.length === 0) {
    return {
      error: {
        id: "secret-encoding",
        severity: "error",
        message: `the secret does not base64-decode (expected "whsec_" + base64)`,
        fix: "copy the endpoint secret exactly as issued; the key is the decoded bytes after whsec_",
      },
    };
  }
  return { bytes };
}

export function makeSvixLike(id: ProviderId, label: string, headerPrefix: string): ProviderSpec {
  const sigHeader = `${headerPrefix}-signature`;
  const tsHeader = `${headerPrefix}-timestamp`;
  const idHeader = `${headerPrefix}-id`;

  return {
    id,
    label,
    // Svix-family headers are conventionally lower-case, so the display
    // casing is the wire casing.
    signatureHeader: sigHeader,
    timestampHeader: tsHeader,
    idHeader,
    algorithm: "sha256",
    encoding: "base64",
    scheme: "HMAC-SHA256 over `{id}.{ts}.{body}`, base64 after `v1,`",
    toleranceSeconds: 300,
    secretHint: `whsec_ + base64; the key is the DECODED bytes after the prefix`,

    extract(headers): Extraction {
      const out: Extraction = { signatures: [], ignored: [], problems: [] };
      const raw = headers[sigHeader];
      const ts = headers[tsHeader];
      const msgId = headers[idHeader];
      if (msgId !== undefined) out.id = msgId;
      else out.problems.push(missingHeader(idHeader, label));
      if (ts !== undefined) out.timestampRaw = ts;
      else out.problems.push(missingHeader(tsHeader, label));
      if (raw === undefined) {
        out.problems.push(missingHeader(sigHeader, label));
        return out;
      }
      out.rawHeader = raw;
      for (const token of raw.split(/\s+/)) {
        if (token === "") continue;
        const comma = token.indexOf(",");
        if (comma <= 0) {
          out.problems.push(
            malformedHeader(
              sigHeader,
              `token "${token}" has no version prefix`,
              'each space-separated token is "v1,<base64>"',
            ),
          );
          continue;
        }
        const version = token.slice(0, comma);
        const value = token.slice(comma + 1);
        if (version === "v1") out.signatures.push(value);
        else out.ignored.push(token); // e.g. v1a (asymmetric) — not verifiable with an HMAC secret.
      }
      if (out.signatures.length === 0 && out.ignored.length > 0) {
        out.problems.push(
          malformedHeader(
            sigHeader,
            `only non-v1 tokens present (${out.ignored.join(" ")})`,
            "symmetric verification uses the v1,<base64> tokens; v1a is the asymmetric scheme",
          ),
        );
      }
      return out;
    },

    canonical(payload, parts) {
      return `${parts.id ?? ""}.${parts.timestampRaw ?? ""}.${payload}`;
    },

    keyBytes: svixKeyBytes,

    formatSignature(value) {
      return `v1,${value}`;
    },

    sign(input: SignInput): SignedRequest {
      const key = svixKeyBytes(input.secret);
      if ("error" in key) throw new Error(key.error.message);
      const msgId = input.id ?? `msg_${input.timestamp}`;
      const canonical = `${msgId}.${input.timestamp}.${input.payload}`;
      const mac = bytesToBase64(hmacString("sha256", key.bytes, canonical));
      return {
        provider: id,
        headers: [
          { name: idHeader, value: msgId },
          { name: tsHeader, value: String(input.timestamp) },
          { name: sigHeader, value: `v1,${mac}` },
        ],
        canonical,
      };
    },
  };
}
