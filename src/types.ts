/**
 * Shared types for the whole verification pipeline. Everything downstream —
 * providers, the verifier, the diagnosis engine, the reporters — speaks in
 * these shapes, so the CLI and the library API stay byte-identical in what
 * they can express.
 */

/** Providers supported in 0.1.0. */
export type ProviderId = "stripe" | "github" | "slack" | "svix" | "standard";

/** HMAC hash functions used by the supported schemes. */
export type HmacAlgorithm = "sha1" | "sha256" | "sha512";

/** How a provider serializes the MAC into its header. */
export type SignatureEncoding = "hex" | "base64";

/** Digest sizes in bytes, used for length diagnostics. */
export const DIGEST_BYTES: Record<HmacAlgorithm, number> = {
  sha1: 20,
  sha256: 32,
  sha512: 64,
};

/** Header names lower-cased to values (HTTP header names are case-insensitive). */
export type HeaderBag = Record<string, string>;

/** Severity of a diagnostic finding. `error` findings block a PASS. */
export type Severity = "error" | "warn" | "info";

/**
 * One diagnostic finding. `id` is a stable machine-readable code (documented
 * in the README finding catalog); `message` states what was observed;
 * `fix` states the concrete corrective action when one is known.
 */
export interface Finding {
  id: string;
  severity: Severity;
  message: string;
  fix?: string;
}

/** What a provider managed to pull out of the request headers. */
export interface Extraction {
  /** Candidate signature values with any scheme prefix (`v1=`, `sha256=`) stripped. */
  signatures: string[];
  /** The raw signature header value, for display. */
  rawHeader?: string;
  /** Raw timestamp string from the scheme's timestamp field, if any. */
  timestampRaw?: string;
  /** Message id (Svix / Standard Webhooks), if the scheme has one. */
  id?: string;
  /** Signature entries present but not part of the current scheme (v0, v1a, …). */
  ignored: string[];
  /** Structural problems observed while extracting. */
  problems: Finding[];
}

/** Fields a provider needs besides the payload to build its canonical string. */
export interface CanonicalParts {
  timestampRaw?: string;
  id?: string;
}

/** Input to a provider's `sign`. */
export interface SignInput {
  secret: string;
  payload: string;
  /** Unix epoch seconds. */
  timestamp: number;
  /** Message id for Svix-family schemes; defaults to `msg_<timestamp>`. */
  id?: string;
}

/** A fully signed request: headers ready to paste, plus the string that was MACed. */
export interface SignedRequest {
  provider: ProviderId;
  headers: Array<{ name: string; value: string }>;
  canonical: string;
}

/** Static description + behavior of one webhook signature scheme. */
export interface ProviderSpec {
  id: ProviderId;
  label: string;
  /** Display casing of the signature header, e.g. "Stripe-Signature". */
  signatureHeader: string;
  timestampHeader?: string;
  idHeader?: string;
  algorithm: HmacAlgorithm;
  encoding: SignatureEncoding;
  /** Human summary of the canonical string, for `providers` output and reports. */
  scheme: string;
  /** Default replay tolerance in seconds; null = the scheme has no timestamp. */
  toleranceSeconds: number | null;
  /** What the secret should look like, for error messages. */
  secretHint: string;
  extract(headers: HeaderBag): Extraction;
  canonical(payload: string, parts: CanonicalParts): string;
  /** Turn the configured secret into HMAC key bytes, or explain why it can't be. */
  keyBytes(secret: string): { bytes: Uint8Array } | { error: Finding };
  /** Format a bare signature value the way the provider's header carries it. */
  formatSignature(value: string): string;
  sign(input: SignInput): SignedRequest;
}

/** Result of the timestamp / replay-window check. */
export interface TimestampCheck {
  raw: string;
  parsed: number;
  now: number;
  /** parsed - now; negative = the webhook timestamp is in the past. */
  skewSeconds: number;
  toleranceSeconds: number;
  withinTolerance: boolean;
}

/** Options accepted by `verify`. */
export interface VerifyOptions {
  provider: ProviderId;
  secret: string;
  /** The raw request body, byte-exact as received. */
  payload: string;
  headers: HeaderBag;
  /** Override the provider's default replay tolerance (seconds). */
  toleranceSeconds?: number;
  /** Clock used for skew checks, Unix epoch seconds. Defaults to the real time. */
  now?: number;
  /** Set false to skip the diagnosis pass on failure. Default true. */
  diagnose?: boolean;
}

/** The full verification report — the library's main return value. */
export interface VerifyReport {
  ok: boolean;
  provider: ProviderId;
  providerLabel: string;
  /** The exact string the MAC is computed over, plus its UTF-8 byte length. */
  canonical: { value: string; bytes: number } | null;
  /** What the verifier computed from the secret + payload. */
  expected: { value: string; algorithm: HmacAlgorithm; encoding: SignatureEncoding } | null;
  /** Candidate signature values found in the headers. */
  provided: string[];
  /** True when at least one provided signature strictly matches `expected`. */
  signatureMatch: boolean;
  timestamp: TimestampCheck | null;
  payloadBytes: number;
  findings: Finding[];
}

/** Result of provider auto-detection over a header bag. */
export interface Detection {
  provider: ProviderId;
  label: string;
  /** Which of the scheme's headers were present (lower-cased). */
  matched: string[];
  /** Which were expected but absent. */
  missing: string[];
  /** "certain" = every header of the scheme is present. */
  confidence: "certain" | "likely";
}
