/**
 * hookproof — verify and generate webhook signatures for Stripe, GitHub,
 * Slack, Svix and Standard Webhooks, with diagnosis-first failure reports.
 *
 * Public API surface. Everything exported here is covered by semver.
 */

export { VERSION } from "./version.js";
export { verify, signatureEquals, checkTimestamp } from "./verify.js";
export { signRequest } from "./sign.js";
export type { SignRequestOptions } from "./sign.js";
export { diagnose, payloadVariants, secretVariants } from "./diagnose.js";
export type { DiagnoseContext } from "./diagnose.js";
export { detectProviders } from "./detect.js";
export { PROVIDERS, getProvider, providerIds, stripe, github, slack, svix, standard } from "./providers/index.js";
export { normalizeHeaders, parseHeaderBlock, parseHeaderLine } from "./headers.js";
export {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  classifySignature,
  constantTimeEqual,
  constantTimeEqualString,
  utf8Bytes,
} from "./encoding.js";
export { hmac, hmacString, encodeMac } from "./hmac.js";
export { renderReport, renderSigned, renderDetections, renderProviders } from "./report.js";
export { previewString, escapeVisible, shortToken } from "./preview.js";
export type {
  ProviderId,
  ProviderSpec,
  HmacAlgorithm,
  SignatureEncoding,
  HeaderBag,
  Finding,
  Severity,
  Extraction,
  CanonicalParts,
  SignInput,
  SignedRequest,
  TimestampCheck,
  VerifyOptions,
  VerifyReport,
  Detection,
} from "./types.js";
export { DIGEST_BYTES } from "./types.js";
