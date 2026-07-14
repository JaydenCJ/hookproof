/**
 * Safe single-line previews of payloads and canonical strings. Invisible
 * bytes are the whole point: a diagnosis that prints "\n" and "﻿"
 * escapes visibly is how a user finally *sees* the trailing newline or BOM
 * that broke their MAC.
 */

/** Escape a string so every byte is visible on one line. */
export function escapeVisible(text: string): string {
  let out = "";
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code === 0xfeff) out += "\\ufeff";
    else if (code < 0x20 || code === 0x7f) out += "\\x" + code.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out;
}

/**
 * Quote and escape `text`, truncating the middle when the escaped form is
 * longer than `max` characters so both the head (scheme fields) and the
 * tail (trailing newlines!) stay visible.
 */
export function previewString(text: string, max = 96): string {
  const escaped = escapeVisible(text);
  if (escaped.length <= max) return `"${escaped}"`;
  const head = Math.ceil((max - 1) * 0.7);
  const tail = max - 1 - head;
  return `"${escaped.slice(0, head)}…${escaped.slice(escaped.length - tail)}"`;
}

/** Shorten a signature-like token for display: head…tail. */
export function shortToken(text: string, max = 40): string {
  if (text.length <= max) return text;
  const head = Math.ceil((max - 1) / 2);
  const tail = max - 1 - head;
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`;
}
