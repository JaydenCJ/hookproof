/**
 * Thin wrapper over node:crypto HMAC plus the two serializations the
 * supported providers use. Keeping this the only module that touches
 * node:crypto makes the rest of the pipeline pure and unit-testable
 * against fixed vectors.
 */

import { createHmac } from "node:crypto";
import { bytesToBase64, bytesToHex, utf8Bytes } from "./encoding.js";
import type { HmacAlgorithm, SignatureEncoding } from "./types.js";

/** Compute HMAC(key, message) and return the raw digest bytes. */
export function hmac(algorithm: HmacAlgorithm, key: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac(algorithm, key).update(message).digest());
}

/** HMAC over a UTF-8 string message. */
export function hmacString(algorithm: HmacAlgorithm, key: Uint8Array, message: string): Uint8Array {
  return hmac(algorithm, key, utf8Bytes(message));
}

/** Serialize a MAC the way a provider's header carries it. */
export function encodeMac(mac: Uint8Array, encoding: SignatureEncoding): string {
  return encoding === "hex" ? bytesToHex(mac) : bytesToBase64(mac);
}
