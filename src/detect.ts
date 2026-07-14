/**
 * Provider auto-detection from a header bag. Each scheme has a distinctive
 * signature header, so presence of that header is the anchor; companion
 * headers (timestamp, id) upgrade the confidence to "certain".
 */

import { PROVIDERS } from "./providers/index.js";
import type { Detection, HeaderBag, ProviderSpec } from "./types.js";

function schemeHeaders(spec: ProviderSpec): string[] {
  const names = [spec.signatureHeader];
  if (spec.timestampHeader !== undefined) names.push(spec.timestampHeader);
  if (spec.idHeader !== undefined) names.push(spec.idHeader);
  return names.map((n) => n.toLowerCase());
}

/**
 * Return every provider whose signature header is present, most complete
 * match first. Empty result = no known scheme in the headers.
 */
export function detectProviders(headers: HeaderBag): Detection[] {
  const detections: Detection[] = [];
  for (const spec of PROVIDERS) {
    const names = schemeHeaders(spec);
    const matched = names.filter((n) => headers[n] !== undefined);
    const missing = names.filter((n) => headers[n] === undefined);
    const sigPresent =
      headers[spec.signatureHeader.toLowerCase()] !== undefined ||
      // GitHub's legacy header still identifies the provider.
      (spec.id === "github" && headers["x-hub-signature"] !== undefined);
    if (!sigPresent) continue;
    if (spec.id === "github" && matched.length === 0) matched.push("x-hub-signature");
    detections.push({
      provider: spec.id,
      label: spec.label,
      matched,
      missing,
      confidence: missing.length === 0 ? "certain" : "likely",
    });
  }
  detections.sort((a, b) => {
    if (a.confidence !== b.confidence) return a.confidence === "certain" ? -1 : 1;
    return b.matched.length - a.matched.length;
  });
  return detections;
}
