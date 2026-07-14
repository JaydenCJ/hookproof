/**
 * Byte/string codecs. Every supported scheme is "HMAC, then encode", and most
 * real-world verification failures are on the encode side — so the codecs are
 * written to *classify* as well as convert: given an unknown signature string
 * we want to know every plausible byte interpretation of it.
 *
 * Implemented over Uint8Array with no Buffer dependency so the module stays
 * pure and trivially portable.
 */

const HEX_CHARS = "0123456789abcdef";
const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** UTF-8 encode a string. */
export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Lowercase hex encoding. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    out += HEX_CHARS.charAt((b >> 4) & 0xf) + HEX_CHARS.charAt(b & 0xf);
  }
  return out;
}

/** Hex decode (case-insensitive). Returns null when the input is not hex. */
export function hexToBytes(text: string): Uint8Array | null {
  if (text.length === 0 || text.length % 2 !== 0) return null;
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = HEX_CHARS.indexOf(text.charAt(i * 2).toLowerCase());
    const lo = HEX_CHARS.indexOf(text.charAt(i * 2 + 1).toLowerCase());
    if (hi < 0 || lo < 0) return null;
    out[i] = hi * 16 + lo;
  }
  return out;
}

/** Base64 encode, standard or URL-safe alphabet, with or without padding. */
export function bytesToBase64(bytes: Uint8Array, alphabet: "std" | "url" = "std", pad = true): string {
  const table = alphabet === "std" ? B64_STD : B64_URL;
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : null;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : null;
    out += table.charAt(b0 >> 2);
    out += table.charAt(((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4));
    out += b1 === null ? (pad ? "=" : "") : table.charAt(((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6));
    out += b2 === null ? (pad ? "=" : "") : table.charAt(b2 & 0x3f);
  }
  return out;
}

/**
 * Base64 decode accepting BOTH alphabets and optional padding — signature
 * strings in the wild mix all four combinations, and for diagnosis we care
 * about the bytes, not the dialect. Returns null on any invalid character.
 */
export function base64ToBytes(text: string): Uint8Array | null {
  if (text.length === 0) return null;
  const padMatch = /=+$/.exec(text);
  const padLen = padMatch ? padMatch[0].length : 0;
  if (padLen > 2) return null;
  const body = text.slice(0, text.length - padLen);
  if (body.length % 4 === 1) return null;
  if (padLen > 0 && (body.length + padLen) % 4 !== 0) return null;
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const ch of body) {
    let v = B64_STD.indexOf(ch);
    if (v < 0) v = ch === "-" ? 62 : ch === "_" ? 63 : -1;
    if (v < 0) return null;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

/** How a signature string appears to be encoded. */
export type SignatureKind = "hex" | "base64" | "base64url" | "unknown";

/**
 * Classify a signature string and return its byte interpretation. Hex wins
 * over base64 when both parse (every even-length hex string is also valid
 * base64, but no real scheme base64-encodes into pure hex characters).
 */
export function classifySignature(text: string): { kind: SignatureKind; bytes: Uint8Array | null } {
  const hex = hexToBytes(text);
  if (hex !== null) return { kind: "hex", bytes: hex };
  const b64 = base64ToBytes(text);
  if (b64 !== null) {
    return { kind: /[-_]/.test(text) ? "base64url" : "base64", bytes: b64 };
  }
  return { kind: "unknown", bytes: null };
}

/**
 * Constant-time byte comparison. Folds over the longer input so unequal
 * lengths do not short-circuit; the length difference itself is mixed into
 * the accumulator.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/** Constant-time comparison of two strings via their UTF-8 bytes. */
export function constantTimeEqualString(a: string, b: string): boolean {
  return constantTimeEqual(utf8Bytes(a), utf8Bytes(b));
}
