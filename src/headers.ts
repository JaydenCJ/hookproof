/**
 * Header handling. HTTP header names are case-insensitive, so everything
 * internal works on a lower-cased bag; the parsers here accept the formats
 * people actually paste into a terminal — `curl -v` output, raw request
 * dumps, and `Name: value` lines.
 */

import type { HeaderBag } from "./types.js";

/** Lower-case names and trim values. Later duplicates win. */
export function normalizeHeaders(input: Record<string, string> | Array<[string, string]>): HeaderBag {
  const entries = Array.isArray(input) ? input : Object.entries(input);
  const bag: HeaderBag = {};
  for (const [name, value] of entries) {
    bag[name.trim().toLowerCase()] = value.trim();
  }
  return bag;
}

/**
 * Parse a raw header block: one `Name: value` per line. Tolerates and skips
 * an HTTP request/status line, blank lines, and the `> ` / `< ` prefixes
 * that `curl -v` puts in front of each header.
 */
export function parseHeaderBlock(text: string): HeaderBag {
  const entries: Array<[string, string]> = [];
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (line.startsWith("> ") || line.startsWith("< ")) line = line.slice(2).trim();
    if (line === "" || line === ">" || line === "<") continue;
    // Request line ("POST /hook HTTP/1.1") or status line ("HTTP/1.1 200 OK").
    if (/^[A-Z]+ \S+ HTTP\//.test(line) || /^HTTP\//.test(line)) continue;
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    entries.push([line.slice(0, colon), line.slice(colon + 1)]);
  }
  return normalizeHeaders(entries);
}

/** Parse a single `Name: value` string (the CLI's --header flag). */
export function parseHeaderLine(text: string): [string, string] | null {
  const colon = text.indexOf(":");
  if (colon <= 0) return null;
  const name = text.slice(0, colon).trim();
  if (name === "") return null;
  return [name, text.slice(colon + 1).trim()];
}
