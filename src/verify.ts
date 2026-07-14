/**
 * The strict verification pass. This is deliberately as unforgiving as the
 * provider's own SDK: exact header shape, exact encoding, timestamp inside
 * the tolerance window. Anything looser would defeat the purpose — the
 * diagnosis engine (diagnose.ts) is where the forgiving interpretations
 * live, and it only runs after a strict FAIL.
 */

import { constantTimeEqualString, utf8Bytes } from "./encoding.js";
import { encodeMac, hmacString } from "./hmac.js";
import { normalizeHeaders } from "./headers.js";
import { diagnose } from "./diagnose.js";
import { getProvider } from "./providers/index.js";
import type {
  Extraction,
  Finding,
  ProviderSpec,
  TimestampCheck,
  VerifyOptions,
  VerifyReport,
} from "./types.js";

/** Strict comparison in the provider's own encoding. Hex is case-insensitive
 * (RFC 4648 treats hex digits as case-insensitive and providers' SDKs
 * lowercase both sides); base64 must match exactly. Constant-time either way. */
export function signatureEquals(spec: ProviderSpec, expected: string, provided: string): boolean {
  if (spec.encoding === "hex") {
    return constantTimeEqualString(expected.toLowerCase(), provided.toLowerCase());
  }
  return constantTimeEqualString(expected, provided);
}

/** Parse a scheme timestamp and evaluate it against the replay window. */
export function checkTimestamp(
  raw: string,
  now: number,
  toleranceSeconds: number,
): TimestampCheck | null {
  if (!/^\d{1,12}$/.test(raw.trim())) return null;
  const parsed = Number(raw.trim());
  const skewSeconds = parsed - now;
  return {
    raw,
    parsed,
    now,
    skewSeconds,
    toleranceSeconds,
    withinTolerance: Math.abs(skewSeconds) <= toleranceSeconds,
  };
}

function describeSkew(check: TimestampCheck): Finding {
  const abs = Math.abs(check.skewSeconds);
  const direction =
    check.skewSeconds < 0
      ? `${abs}s in the past — an old delivery being replayed, a stuck queue, or your server clock running fast`
      : `${abs}s in the future — the sender's clock (or yours) is skewed`;
  return {
    id: "timestamp-skew",
    severity: "error",
    message: `timestamp ${check.parsed} is ${direction} (tolerance ${check.toleranceSeconds}s)`,
    fix: "sync clocks via NTP; for replayed test payloads pass an explicit verification time (--now) or raise --tolerance",
  };
}

/** Deduplicate findings by id + message, preserving first-seen order. */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.id}\u0000${finding.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}

/**
 * Verify a webhook request and explain the result. Never throws on bad
 * input — every problem becomes a finding in the report. Unknown provider
 * ids are the one programming error that does throw.
 */
export function verify(options: VerifyOptions): VerifyReport {
  const spec = getProvider(options.provider);
  if (spec === null) {
    throw new Error(`unknown provider "${options.provider}"`);
  }
  const headers = normalizeHeaders(options.headers);
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const tolerance = options.toleranceSeconds ?? spec.toleranceSeconds ?? 0;

  const extraction: Extraction = spec.extract(headers);
  const findings: Finding[] = [...extraction.problems];

  // Key material.
  const key = spec.keyBytes(options.secret);
  let expected: VerifyReport["expected"] = null;
  let canonical: VerifyReport["canonical"] = null;
  if ("error" in key) {
    findings.push(key.error);
  }

  // Canonical string + expected signature (only when the scheme's inputs exist).
  const haveParts =
    (spec.timestampHeader === undefined || extraction.timestampRaw !== undefined) &&
    (spec.idHeader === undefined || extraction.id !== undefined) &&
    (spec.id !== "stripe" || extraction.timestampRaw !== undefined);
  if (haveParts) {
    const value = spec.canonical(options.payload, {
      ...(extraction.timestampRaw !== undefined ? { timestampRaw: extraction.timestampRaw } : {}),
      ...(extraction.id !== undefined ? { id: extraction.id } : {}),
    });
    canonical = { value, bytes: utf8Bytes(value).length };
    if ("bytes" in key) {
      expected = {
        value: encodeMac(hmacString(spec.algorithm, key.bytes, value), spec.encoding),
        algorithm: spec.algorithm,
        encoding: spec.encoding,
      };
    }
  }

  // Strict signature comparison against every candidate.
  let signatureMatch = false;
  if (expected !== null) {
    for (const provided of extraction.signatures) {
      if (signatureEquals(spec, expected.value, provided)) signatureMatch = true;
    }
  }

  // Replay window.
  let timestamp: TimestampCheck | null = null;
  let timestampOk = true;
  if (spec.toleranceSeconds !== null && extraction.timestampRaw !== undefined) {
    timestamp = checkTimestamp(extraction.timestampRaw, now, tolerance);
    if (timestamp === null) {
      timestampOk = false;
      findings.push({
        id: "timestamp-invalid",
        severity: "error",
        message: `timestamp "${extraction.timestampRaw}" is not a Unix epoch-seconds integer`,
        fix: "the scheme timestamps are epoch seconds (not milliseconds, not ISO 8601)",
      });
    } else if (!timestamp.withinTolerance) {
      timestampOk = false;
      const skew = describeSkew(timestamp);
      if (signatureMatch) {
        skew.message = `signature is cryptographically valid, but ${skew.message}`;
      }
      findings.push(skew);
    }
  }

  const structuralError = extraction.problems.some((p) => p.severity === "error");
  const ok = signatureMatch && timestampOk && !structuralError && !("error" in key);

  if (!ok && options.diagnose !== false) {
    findings.push(
      ...diagnose({
        spec,
        payload: options.payload,
        secret: options.secret,
        headers,
        extraction,
        expected: expected?.value ?? null,
        signatureMatch,
        now,
        toleranceSeconds: tolerance,
      }),
    );
  }

  if (ok && extraction.ignored.length > 0) {
    findings.push({
      id: "scheme-mismatch",
      severity: "info",
      message: `ignored non-scheme signature elements: ${extraction.ignored.join(" ")}`,
    });
  }

  return {
    ok,
    provider: spec.id,
    providerLabel: spec.label,
    canonical,
    expected,
    provided: extraction.signatures,
    signatureMatch,
    timestamp,
    payloadBytes: utf8Bytes(options.payload).length,
    findings: dedupeFindings(findings),
  };
}
