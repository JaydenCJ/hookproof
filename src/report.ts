/**
 * Human-readable rendering of reports. Plain text, no ANSI color, stable
 * layout — the output is meant to be pasted into issues and CI logs, and
 * the finding ids are greppable (`hookproof verify … | grep payload-`).
 */

import { PROVIDERS } from "./providers/index.js";
import { previewString, shortToken } from "./preview.js";
import type { Detection, Finding, SignedRequest, VerifyReport } from "./types.js";

const SEVERITY_MARK: Record<Finding["severity"], string> = {
  error: "x",
  warn: "!",
  info: "i",
};

function line(label: string, value: string): string {
  return `  ${label.padEnd(10)} ${value}`;
}

function renderFinding(finding: Finding): string {
  let out = `  ${SEVERITY_MARK[finding.severity]} ${finding.id} — ${finding.message}`;
  if (finding.fix !== undefined) out += `\n      fix: ${finding.fix}`;
  return out;
}

/** Render a verification report as aligned plain text. */
export function renderReport(report: VerifyReport): string {
  const out: string[] = [];
  out.push(
    report.ok
      ? `PASS  ${report.provider} — signature verified`
      : `FAIL  ${report.provider} — signature did not verify`,
  );
  out.push(line("payload", `${report.payloadBytes} bytes`));
  if (report.canonical !== null) {
    out.push(line("canonical", `${previewString(report.canonical.value)} (${report.canonical.bytes} bytes)`));
  }
  if (report.timestamp !== null) {
    const t = report.timestamp;
    const sign = t.skewSeconds >= 0 ? "+" : "-";
    out.push(
      line(
        "timestamp",
        `${t.parsed} · skew ${sign}${Math.abs(t.skewSeconds)}s of ${t.toleranceSeconds}s tolerance · ${t.withinTolerance ? "ok" : "EXCEEDED"}`,
      ),
    );
  }
  if (report.expected !== null) {
    out.push(
      line(
        "expected",
        `${shortToken(report.expected.value)} (${report.expected.algorithm} · ${report.expected.encoding})`,
      ),
    );
  }
  for (const provided of report.provided) {
    out.push(line("provided", shortToken(provided)));
  }
  if (report.provided.length === 0) {
    out.push(line("provided", "(no signature found)"));
  }
  if (report.findings.length > 0) {
    out.push("");
    out.push(`  findings (${report.findings.length})`);
    for (const finding of report.findings) {
      out.push(renderFinding(finding));
    }
  }
  return out.join("\n") + "\n";
}

/** Render a signed request as paste-ready header lines. */
export function renderSigned(signed: SignedRequest): string {
  const out = signed.headers.map((h) => `${h.name}: ${h.value}`);
  return out.join("\n") + "\n";
}

/** Render detection results. */
export function renderDetections(detections: Detection[]): string {
  if (detections.length === 0) {
    return "no known webhook signature scheme detected in these headers\n";
  }
  const out: string[] = [];
  for (const d of detections) {
    let text = `${d.provider.padEnd(9)} ${d.confidence.padEnd(8)} matched: ${d.matched.join(", ")}`;
    if (d.missing.length > 0) text += ` · missing: ${d.missing.join(", ")}`;
    out.push(text);
  }
  return out.join("\n") + "\n";
}

/** Render the provider reference table for `hookproof providers`. */
export function renderProviders(): string {
  const out: string[] = [];
  for (const spec of PROVIDERS) {
    out.push(`${spec.id.padEnd(9)} ${spec.label}`);
    out.push(`          header:    ${spec.signatureHeader}`);
    if (spec.timestampHeader !== undefined) out.push(`          timestamp: ${spec.timestampHeader}`);
    if (spec.idHeader !== undefined) out.push(`          id:        ${spec.idHeader}`);
    out.push(`          scheme:    ${spec.scheme}`);
    out.push(`          secret:    ${spec.secretHint}`);
    out.push(
      `          replay:    ${spec.toleranceSeconds === null ? "no timestamp in the scheme" : `${spec.toleranceSeconds}s default tolerance`}`,
    );
  }
  return out.join("\n") + "\n";
}
