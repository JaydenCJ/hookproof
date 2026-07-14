/**
 * The diagnosis engine. After a strict FAIL, it searches a bounded matrix of
 * "forgiving" interpretations — payload transforms, secret interpretations,
 * alternate digest algorithms, alternate signature encodings — and reports
 * the SMALLEST set of changes that makes the MAC match. A match under a
 * transform is proof of the root cause: if appending "\n" to the payload
 * verifies, the sender signed a body your stack later stripped a newline
 * from; nothing else could produce those 32 bytes.
 *
 * The matrix is small (≤ ~8 payload × 5 secret × 3 algorithm variants) and
 * every candidate is a single HMAC, so diagnosis costs microseconds.
 */

import { base64ToBytes, bytesToBase64, bytesToHex, classifySignature, constantTimeEqual, utf8Bytes } from "./encoding.js";
import { hmacString } from "./hmac.js";
import { PROVIDERS } from "./providers/index.js";
import { signatureEquals, checkTimestamp } from "./verify.js";
import type { Extraction, Finding, HeaderBag, HmacAlgorithm, ProviderSpec } from "./types.js";
import { DIGEST_BYTES } from "./types.js";

export interface DiagnoseContext {
  spec: ProviderSpec;
  payload: string;
  secret: string;
  headers: HeaderBag;
  extraction: Extraction;
  /** The strictly expected signature string, when it was computable. */
  expected: string | null;
  /** True when the strict pass already matched (failure was timestamp/structure). */
  signatureMatch: boolean;
  now: number;
  toleranceSeconds: number;
}

interface Variant<T> {
  value: T;
  /** null = the unmodified original. */
  finding: Finding | null;
}

const BOM = "\ufeff";

/** Payload interpretations worth testing, most specific first. */
export function payloadVariants(payload: string): Array<Variant<string>> {
  const variants: Array<Variant<string>> = [{ value: payload, finding: null }];
  const push = (value: string, finding: Finding) => {
    if (value !== payload && !variants.some((v) => v.value === value)) {
      variants.push({ value, finding });
    }
  };

  if (payload.endsWith("\n")) {
    push(payload.replace(/\n+$/, ""), {
      id: "payload-newline",
      severity: "error",
      message: "verifies once the trailing newline is removed — your captured payload has a \\n that was not part of the signed body",
      fix: "capture the body byte-exact; echo, editors and some templating add a final newline (use printf %s or --payload file)",
    });
  } else {
    push(payload + "\n", {
      id: "payload-newline",
      severity: "error",
      message: "verifies with a trailing newline appended — the signed body ended in \\n and something stripped it",
      fix: "read the raw request stream; many body parsers and .trim() calls eat trailing whitespace",
    });
  }
  if (payload.includes("\r\n")) {
    push(payload.replace(/\r\n/g, "\n"), {
      id: "payload-crlf",
      severity: "error",
      message: "verifies after converting CRLF to LF — the signed body used \\n line endings but your capture has \\r\\n",
      fix: "a proxy, Windows editor or git autocrlf rewrote the line endings; keep the body binary-safe end to end",
    });
  } else if (payload.includes("\n")) {
    push(payload.replace(/\n/g, "\r\n"), {
      id: "payload-crlf",
      severity: "error",
      message: "verifies after converting LF to CRLF — the signed body used \\r\\n line endings but your capture has \\n",
      fix: "something normalized line endings in transit; keep the body binary-safe end to end",
    });
  }
  if (payload.startsWith(BOM)) {
    push(payload.slice(BOM.length), {
      id: "payload-bom",
      severity: "error",
      message: "verifies once the UTF-8 BOM is stripped — your capture gained a byte-order mark the signed body never had",
      fix: "save payload files as UTF-8 without BOM; some editors and PowerShell redirects add one",
    });
  }
  const trimmed = payload.trim();
  if (trimmed !== payload) {
    push(trimmed, {
      id: "payload-whitespace",
      severity: "error",
      message: "verifies after trimming surrounding whitespace — the capture gained leading/trailing whitespace",
      fix: "pass the body byte-exact; shell quoting and heredocs are common culprits",
    });
  }
  // Re-serialized JSON: the classic body-parser failure. If the payload is
  // JSON whose compact form differs, the sender most likely signed the
  // compact form and middleware re-serialized (pretty-printed, re-ordered
  // whitespace) before your handler saw it.
  try {
    const compact: string = JSON.stringify(JSON.parse(payload));
    if (typeof compact === "string") {
      push(compact, {
        id: "payload-reserialized",
        severity: "error",
        message: "verifies against the compact re-serialization of your JSON — the body was parsed and re-serialized before verification",
        fix: "verify against the RAW request bytes (e.g. express.raw() / request.body before JSON parsing), never JSON.stringify(req.body)",
      });
    }
  } catch {
    // Not JSON — nothing to try.
  }
  return variants;
}

/** Secret interpretations worth testing for a given provider family. */
export function secretVariants(spec: ProviderSpec, secret: string): Array<Variant<Uint8Array>> {
  const variants: Array<Variant<Uint8Array>> = [];
  const seen = new Set<string>();
  const push = (bytes: Uint8Array | null, finding: Finding | null) => {
    if (bytes === null || bytes.length === 0) return;
    const key = bytesToHex(bytes);
    if (seen.has(key)) return;
    seen.add(key);
    variants.push({ value: bytes, finding });
  };

  const strict = spec.keyBytes(secret);
  push("bytes" in strict ? strict.bytes : null, null);

  const trimmed = secret.trim();
  if (trimmed !== secret) {
    const k = spec.keyBytes(trimmed);
    push("bytes" in k ? k.bytes : null, {
      id: "secret-whitespace",
      severity: "error",
      message: "verifies after trimming whitespace from the secret — the configured value has stray spaces or a newline",
      fix: "re-copy the secret; check .env quoting and trailing newlines from `echo`",
    });
  }

  const hasPrefix = trimmed.startsWith("whsec_");
  const afterPrefix = hasPrefix ? trimmed.slice("whsec_".length) : trimmed;

  if (spec.encoding === "base64") {
    // Svix family: the correct key is base64-decoded. The common mistakes are
    // using the literal string (with or without prefix) as ASCII key material.
    push(utf8Bytes(trimmed), {
      id: "secret-encoding",
      severity: "error",
      message: "verifies when the LITERAL secret string is used as the key — the sender did not base64-decode it",
      fix: `${spec.label} keys are the decoded bytes after whsec_; align both sides on the decoded form`,
    });
    if (hasPrefix) {
      push(utf8Bytes(afterPrefix), {
        id: "secret-encoding",
        severity: "error",
        message: "verifies when the part after whsec_ is used as a literal ASCII key instead of being base64-decoded",
        fix: "base64-decode the portion after whsec_ before HMACing",
      });
    }
  } else {
    // Verbatim-secret providers: the common mistakes are stripping the
    // prefix (Stripe) or base64-decoding a secret that is really literal.
    if (hasPrefix) {
      push(utf8Bytes(afterPrefix), {
        id: "secret-prefix",
        severity: "error",
        message: "verifies with the whsec_ prefix stripped — the signer used the secret without its prefix",
        fix: `${spec.label} uses the full secret string verbatim; make both sides agree on including the prefix`,
      });
      const decoded = base64ToBytes(afterPrefix);
      if (decoded !== null && decoded.length >= 16) {
        push(decoded, {
          id: "secret-encoding",
          severity: "error",
          message: "verifies with the base64-decoded bytes after whsec_ as the key — a Svix-style decode was applied to a verbatim secret",
          fix: `${spec.label} secrets are raw strings, not base64; remove the decode step`,
        });
      }
    } else {
      push(utf8Bytes(`whsec_${trimmed}`), {
        id: "secret-prefix",
        severity: "error",
        message: "verifies with whsec_ prepended — the signer's key includes the prefix your configuration dropped",
        fix: "store the secret exactly as issued, prefix included",
      });
      const decoded = base64ToBytes(trimmed);
      if (decoded !== null && decoded.length >= 16) {
        push(decoded, {
          id: "secret-encoding",
          severity: "error",
          message: "verifies with the base64-decoded secret bytes as the key — the signer decoded the secret before HMACing",
          fix: "use the same key form (decoded bytes vs literal string) on both sides",
        });
      }
    }
  }
  return variants;
}

/** Structural findings about the provided signature strings themselves. */
function signatureShapeFindings(spec: ProviderSpec, expected: string | null, provided: string[]): Finding[] {
  const findings: Finding[] = [];
  const want = DIGEST_BYTES[spec.algorithm];
  for (const sig of provided) {
    const { kind, bytes } = classifySignature(sig);
    if (kind === "unknown") {
      findings.push({
        id: "signature-undecodable",
        severity: "error",
        message: `provided signature "${sig.slice(0, 24)}${sig.length > 24 ? "…" : ""}" is neither hex nor base64`,
        fix: "check for URL-encoding (%3D), quoting artifacts, or a truncated copy-paste",
      });
      continue;
    }
    if (
      expected !== null &&
      sig.length >= 16 &&
      sig.length < expected.length &&
      (spec.encoding === "hex"
        ? expected.toLowerCase().startsWith(sig.toLowerCase())
        : expected.startsWith(sig))
    ) {
      findings.push({
        id: "signature-truncated",
        severity: "error",
        message: `provided signature is a ${sig.length}-character prefix of the correct value (${expected.length} characters)`,
        fix: "the header value was cut off — check log line limits, column widths and copy-paste",
      });
      continue;
    }
    if (bytes !== null && bytes.length !== want) {
      findings.push({
        id: "signature-length",
        severity: "warn",
        message: `provided signature decodes to ${bytes.length} bytes; HMAC-${spec.algorithm.toUpperCase()} digests are ${want} bytes`,
        fix: "a different hash function or a corrupted value — the length alone rules out a plain secret mismatch",
      });
    }
  }
  return findings;
}

/** Does any other provider's scheme fully verify this request? */
function crossProviderFindings(ctx: DiagnoseContext): Finding[] {
  const findings: Finding[] = [];
  for (const other of PROVIDERS) {
    if (other.id === ctx.spec.id) continue;
    const extraction = other.extract(ctx.headers);
    if (extraction.signatures.length === 0) continue;
    if (extraction.problems.some((p) => p.severity === "error")) continue;
    const key = other.keyBytes(ctx.secret);
    if ("error" in key) continue;
    const canonical = other.canonical(ctx.payload, {
      ...(extraction.timestampRaw !== undefined ? { timestampRaw: extraction.timestampRaw } : {}),
      ...(extraction.id !== undefined ? { id: extraction.id } : {}),
    });
    const mac = hmacString(other.algorithm, key.bytes, canonical);
    const expected = other.encoding === "hex" ? bytesToHex(mac) : bytesToBase64(mac);
    const match = extraction.signatures.some((sig) => signatureEquals(other, expected, sig));
    if (!match) continue;
    let timestampOk = true;
    if (other.toleranceSeconds !== null && extraction.timestampRaw !== undefined) {
      const check = checkTimestamp(extraction.timestampRaw, ctx.now, other.toleranceSeconds);
      timestampOk = check !== null && check.withinTolerance;
    }
    findings.push({
      id: "wrong-provider",
      severity: "error",
      message: `the request verifies cleanly under the ${other.label} scheme${timestampOk ? "" : " (signature only; its timestamp is outside tolerance)"} — provider "${ctx.spec.id}" was the wrong choice`,
      fix: `re-run with --provider ${other.id}`,
    });
  }
  // Extraction produced nothing for the selected provider, but another
  // scheme's headers are sitting right there. Only hint when no full
  // cross-provider proof was already found above.
  if (ctx.extraction.signatures.length === 0 && findings.length === 0) {
    for (const other of PROVIDERS) {
      if (other.id === ctx.spec.id) continue;
      if (ctx.headers[other.signatureHeader.toLowerCase()] !== undefined) {
        findings.push({
          id: "wrong-provider",
          severity: "warn",
          message: `no ${ctx.spec.signatureHeader} header, but ${other.signatureHeader} is present — this looks like a ${other.label} delivery`,
          fix: `try --provider ${other.id}`,
        });
      }
    }
  }
  return findings;
}

/**
 * Run the full diagnosis. Returns findings ordered: signature shape,
 * minimal-transform match (the root cause), cross-provider, then the
 * fallback verdict when nothing explains the mismatch.
 */
export function diagnose(ctx: DiagnoseContext): Finding[] {
  const findings: Finding[] = [];
  const provided = ctx.extraction.signatures;

  findings.push(...signatureShapeFindings(ctx.spec, ctx.expected, provided));

  // The transform search only makes sense when a signature exists to match
  // against and the strict pass did not already match it. A truncated or
  // undecodable signature is already a complete explanation.
  let explained =
    ctx.signatureMatch ||
    findings.some((f) => f.id === "signature-truncated" || f.id === "signature-undecodable");
  if (provided.length > 0 && !ctx.signatureMatch) {
    const match = searchTransforms(ctx, provided);
    if (match !== null) {
      findings.push(...match);
      explained = true;
    }
  }

  findings.push(...crossProviderFindings(ctx));
  if (findings.some((f) => f.id === "wrong-provider")) explained = true;

  const structural = ctx.extraction.problems.some((p) => p.severity === "error");
  if (!explained && !structural && provided.length > 0) {
    findings.push({
      id: "secret-mismatch",
      severity: "error",
      message: "no payload, secret or encoding transform explains the mismatch — the secret is almost certainly not the one that signed this request",
      fix: "confirm the secret matches THIS endpoint (each endpoint has its own), the right environment (test vs live), and was not rotated",
    });
  }
  return findings;
}

/**
 * Enumerate (secret × payload × algorithm) candidates ordered by how many
 * dimensions differ from the strict interpretation, and return the findings
 * of the first (i.e. minimal) combination whose MAC matches a provided
 * signature — comparing raw digest bytes so encoding differences on the
 * provided side are detected in the same pass.
 */
function searchTransforms(ctx: DiagnoseContext, provided: string[]): Finding[] | null {
  const parts = {
    ...(ctx.extraction.timestampRaw !== undefined ? { timestampRaw: ctx.extraction.timestampRaw } : {}),
    ...(ctx.extraction.id !== undefined ? { id: ctx.extraction.id } : {}),
  };
  const secrets = secretVariants(ctx.spec, ctx.secret);
  const payloads = payloadVariants(ctx.payload);
  const algorithms: Array<Variant<HmacAlgorithm>> = (["sha256", "sha1", "sha512"] as const).map(
    (algorithm) =>
      algorithm === ctx.spec.algorithm
        ? { value: algorithm, finding: null }
        : {
            value: algorithm,
            finding: {
              id: "algorithm-mismatch",
              severity: "error",
              message: `verifies under HMAC-${algorithm.toUpperCase()} — the signer used ${algorithm}, not the scheme's ${ctx.spec.algorithm}`,
              fix: `switch the signing side to HMAC-${ctx.spec.algorithm.toUpperCase()} (or read the matching header)`,
            },
          },
    );

  const decodedProvided = provided.map((sig) => ({ sig, ...classifySignature(sig) }));

  interface Combo {
    changes: number;
    secret: Variant<Uint8Array>;
    payload: Variant<string>;
    algorithm: Variant<HmacAlgorithm>;
  }
  const combos: Combo[] = [];
  for (const s of secrets) {
    for (const p of payloads) {
      for (const a of algorithms) {
        const changes = (s.finding ? 1 : 0) + (p.finding ? 1 : 0) + (a.finding ? 1 : 0);
        combos.push({ changes, secret: s, payload: p, algorithm: a });
      }
    }
  }
  combos.sort((a, b) => a.changes - b.changes);

  for (const combo of combos) {
    const canonical = ctx.spec.canonical(combo.payload.value, parts);
    const mac = hmacString(combo.algorithm.value, combo.secret.value, canonical);
    for (const { sig, kind, bytes } of decodedProvided) {
      const byteMatch = bytes !== null && constantTimeEqual(mac, bytes);
      if (!byteMatch) continue;
      const findings: Finding[] = [];
      if (combo.secret.finding) findings.push(combo.secret.finding);
      if (combo.payload.finding) findings.push(combo.payload.finding);
      if (combo.algorithm.finding) findings.push(combo.algorithm.finding);
      // Same digest bytes but a different string than the scheme emits →
      // the sender (or a copy step) re-encoded the signature.
      const strictString = ctx.spec.encoding === "hex" ? bytesToHex(mac) : bytesToBase64(mac);
      if (!signatureEquals(ctx.spec, strictString, sig)) {
        findings.push({
          id: "encoding-mismatch",
          severity: "error",
          message: `the digest bytes are correct but arrived ${kind}-encoded; ${ctx.spec.label} emits ${ctx.spec.encoding === "hex" ? "lowercase hex" : "standard base64"}`,
          fix: `re-encode the digest as ${ctx.spec.encoding === "hex" ? "hex" : "base64 (standard alphabet, with padding)"} when generating signatures`,
        });
      }
      if (findings.length > 0) return findings;
      // changes === 0 and strict-equal string: the strict pass would have
      // caught it; nothing to report from here.
      return null;
    }
  }
  return null;
}
