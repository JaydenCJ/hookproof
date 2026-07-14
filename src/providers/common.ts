/**
 * Helpers shared by the provider implementations: finding constructors for
 * the structural problems every scheme can have, and the raw-UTF-8 secret
 * interpretation used by Stripe, GitHub and Slack.
 */

import { utf8Bytes } from "../encoding.js";
import type { Finding } from "../types.js";

/** `header-missing` finding for a required header. */
export function missingHeader(name: string, provider: string): Finding {
  return {
    id: "header-missing",
    severity: "error",
    message: `required header ${name} is not present`,
    fix: `${provider} sends ${name} on every delivery — check the header name and that your framework exposes raw request headers`,
  };
}

/** `header-malformed` finding with a scheme-specific explanation. */
export function malformedHeader(name: string, detail: string, fix?: string): Finding {
  const finding: Finding = {
    id: "header-malformed",
    severity: "error",
    message: `${name} did not parse: ${detail}`,
  };
  if (fix !== undefined) finding.fix = fix;
  return finding;
}

/** `scheme-mismatch` finding: a signature exists, but under the wrong scheme label. */
export function schemeMismatch(message: string, fix: string): Finding {
  return { id: "scheme-mismatch", severity: "error", message, fix };
}

/** Secrets used verbatim as ASCII/UTF-8 key material (Stripe, GitHub, Slack). */
export function rawSecretKey(secret: string): { bytes: Uint8Array } | { error: Finding } {
  if (secret.length === 0) {
    return {
      error: {
        id: "secret-mismatch",
        severity: "error",
        message: "the secret is empty",
        fix: "pass the signing secret via --secret or --secret-file",
      },
    };
  }
  return { bytes: utf8Bytes(secret) };
}
