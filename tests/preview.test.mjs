// Preview rendering tests: the report must make invisible bytes visible —
// a diagnosis that hides the trailing \n it is complaining about is useless.
import assert from "node:assert/strict";
import test from "node:test";
import { escapeVisible, previewString, shortToken } from "../dist/index.js";

test("escapeVisible makes newlines, tabs, CR and BOM visible", () => {
  assert.equal(escapeVisible("a\nb"), "a\\nb");
  assert.equal(escapeVisible("a\r\nb"), "a\\r\\nb");
  assert.equal(escapeVisible("a\tb"), "a\\tb");
  assert.equal(escapeVisible("\ufeff" + "x"), "\\ufeffx");
  assert.equal(escapeVisible('say "hi"'), 'say \\"hi\\"');
  assert.equal(escapeVisible("a\x00b"), "a\\x00b");
  assert.equal(escapeVisible("日本語 ok"), "日本語 ok", "printable unicode is left alone");
});

test("previewString quotes short strings verbatim", () => {
  assert.equal(previewString("abc"), '"abc"');
});

test("previewString truncates the middle so head and tail both survive", () => {
  const long = "HEAD" + "x".repeat(200) + "TAIL\n";
  const p = previewString(long, 40);
  assert.ok(p.startsWith('"HEAD'));
  assert.ok(p.endsWith('TAIL\\n"'), `tail (with visible \\n) must survive: ${p}`);
  assert.ok(p.includes("…"));
  assert.ok(p.length <= 44);
});

test("shortToken keeps short tokens and middle-truncates long ones", () => {
  assert.equal(shortToken("abcdef"), "abcdef");
  const t = shortToken("a".repeat(30) + "b".repeat(30), 21);
  assert.equal(t.length, 21);
  assert.ok(t.startsWith("aaa"));
  assert.ok(t.endsWith("bbb"));
  assert.ok(t.includes("…"));
});
