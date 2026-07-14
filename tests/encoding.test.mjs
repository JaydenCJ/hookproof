// Codec tests. The hand-rolled hex/base64 codecs are cross-checked against
// Buffer, and the classifier is probed with the ambiguous cases that matter
// for diagnosis (hex-that-is-also-base64, url-safe alphabets, padding).
import assert from "node:assert/strict";
import test from "node:test";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  classifySignature,
  constantTimeEqual,
  constantTimeEqualString,
  hexToBytes,
  utf8Bytes,
} from "../dist/encoding.js";

const VECTORS = [
  new Uint8Array([]),
  new Uint8Array([0]),
  new Uint8Array([0xff]),
  new Uint8Array([1, 2, 3]),
  new Uint8Array([250, 251, 252, 253]),
  new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 37) % 256)),
  new Uint8Array(Array.from({ length: 33 }, (_, i) => 255 - i)),
];

test("bytesToHex matches Buffer for every vector", () => {
  for (const v of VECTORS) {
    assert.equal(bytesToHex(v), Buffer.from(v).toString("hex"));
  }
});

test("hexToBytes round-trips, is case-insensitive, and rejects non-hex input", () => {
  for (const v of VECTORS.filter((v) => v.length > 0)) {
    const hex = Buffer.from(v).toString("hex");
    assert.deepEqual(hexToBytes(hex), v);
    assert.deepEqual(hexToBytes(hex.toUpperCase()), v);
  }
  assert.equal(hexToBytes(""), null);
  assert.equal(hexToBytes("abc"), null, "odd length");
  assert.equal(hexToBytes("zz"), null);
  assert.equal(hexToBytes("0x11"), null);
});

test("bytesToBase64 matches Buffer for both alphabets", () => {
  for (const v of VECTORS.filter((v) => v.length > 0)) {
    assert.equal(bytesToBase64(v), Buffer.from(v).toString("base64"));
    assert.equal(bytesToBase64(v, "url", false), Buffer.from(v).toString("base64url"));
  }
});

test("base64ToBytes decodes every dialect and rejects invalid input", () => {
  const bytes = new Uint8Array([251, 239, 190, 0, 1]);
  const std = Buffer.from(bytes).toString("base64");
  const url = Buffer.from(bytes).toString("base64url");
  assert.deepEqual(base64ToBytes(std), bytes);
  assert.deepEqual(base64ToBytes(std.replace(/=+$/, "")), bytes, "unpadded");
  assert.deepEqual(base64ToBytes(url), bytes, "url-safe alphabet");
  assert.equal(base64ToBytes(""), null);
  assert.equal(base64ToBytes("a"), null); // 6 bits is not a byte
  assert.equal(base64ToBytes("ab==="), null); // 3 pad chars never valid
  assert.equal(base64ToBytes("a b c"), null); // whitespace is not tolerated
  assert.equal(base64ToBytes("abc$"), null);
});

test("classifySignature prefers hex when the string is valid hex", () => {
  // 64 hex chars are ALSO valid base64; real schemes never base64-encode
  // into pure hex, so hex must win the tie.
  const hex = "a".repeat(64);
  const c = classifySignature(hex);
  assert.equal(c.kind, "hex");
  assert.equal(c.bytes.length, 32);
});

test("classifySignature identifies base64 and base64url dialects", () => {
  const bytes = new Uint8Array(Array.from({ length: 32 }, (_, i) => 0xfb - i));
  const std = Buffer.from(bytes).toString("base64");
  const url = Buffer.from(bytes).toString("base64url");
  assert.equal(classifySignature(std).kind, "base64");
  assert.equal(classifySignature(url).kind, /[-_]/.test(url) ? "base64url" : "base64");
  assert.deepEqual(classifySignature(std).bytes, bytes);
});

test("classifySignature returns unknown for garbage", () => {
  const c = classifySignature("not a signature!!");
  assert.equal(c.kind, "unknown");
  assert.equal(c.bytes, null);
});

test("constantTimeEqual compares bytes correctly including length differences", () => {
  const a = new Uint8Array([1, 2, 3]);
  assert.equal(constantTimeEqual(a, new Uint8Array([1, 2, 3])), true);
  assert.equal(constantTimeEqual(a, new Uint8Array([1, 2, 4])), false);
  assert.equal(constantTimeEqual(a, new Uint8Array([1, 2])), false);
  assert.equal(constantTimeEqual(new Uint8Array([]), new Uint8Array([])), true);
});

test("constantTimeEqualString compares via UTF-8 bytes (multibyte included)", () => {
  assert.equal(constantTimeEqualString("abc", "abc"), true);
  assert.equal(constantTimeEqualString("abc", "abd"), false);
  assert.equal(constantTimeEqualString("abc", "abc "), false);
  assert.deepEqual(utf8Bytes("é"), new Uint8Array([0xc3, 0xa9]));
  assert.equal(utf8Bytes("").length, 0);
});
