// Header parsing tests: case-insensitivity, header blocks pasted from
// terminals (including curl -v transcripts), and the --header flag format.
import assert from "node:assert/strict";
import test from "node:test";
import { normalizeHeaders, parseHeaderBlock, parseHeaderLine } from "../dist/index.js";

test("normalizeHeaders lower-cases names and trims values", () => {
  const bag = normalizeHeaders({ "Stripe-Signature": "  t=1,v1=a  ", HOST: "example.test" });
  assert.deepEqual(bag, { "stripe-signature": "t=1,v1=a", host: "example.test" });
});

test("normalizeHeaders lets later duplicates win", () => {
  const bag = normalizeHeaders([
    ["X-Test", "first"],
    ["x-test", "second"],
  ]);
  assert.equal(bag["x-test"], "second");
});

test("parseHeaderBlock reads Name: value lines, skips blanks, keeps value colons", () => {
  const bag = parseHeaderBlock("Stripe-Signature: t=1,v1=a\n\nContent-Type: application/json\nX-Note: a:b:c\n");
  assert.equal(bag["stripe-signature"], "t=1,v1=a");
  assert.equal(bag["content-type"], "application/json");
  assert.equal(bag["x-note"], "a:b:c");
});

test("parseHeaderBlock skips HTTP request/status lines and curl -v arrows", () => {
  const bag = parseHeaderBlock("POST /hook HTTP/1.1\nHost: example.test\nHTTP/1.1 200 OK\nX-A: 1\n");
  assert.equal(bag["host"], "example.test");
  assert.equal(bag["x-a"], "1");
  assert.equal(Object.keys(bag).length, 2);
  const curl = parseHeaderBlock("> POST /hook HTTP/1.1\n> svix-id: msg_1\n< HTTP/1.1 200 OK\n< X-B: 2\n");
  assert.equal(curl["svix-id"], "msg_1");
  assert.equal(curl["x-b"], "2");
});

test("parseHeaderLine parses one flag value and rejects malformed input", () => {
  assert.deepEqual(parseHeaderLine("X-A: hello"), ["X-A", "hello"]);
  assert.deepEqual(parseHeaderLine("X-A:no-space"), ["X-A", "no-space"]);
  assert.equal(parseHeaderLine("no colon here"), null);
  assert.equal(parseHeaderLine(": empty name"), null);
});
