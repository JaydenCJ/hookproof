/**
 * The hookproof CLI. Four commands — verify, sign, detect, providers — over
 * the library API. Reads the payload from a file or stdin, headers from
 * repeatable --header flags or a pasted header block, and never touches the
 * network. Exit codes: 0 success/verified, 1 verification failed, 2 usage
 * or input error.
 */

import { readFileSync } from "node:fs";
import { detectProviders } from "./detect.js";
import { normalizeHeaders, parseHeaderBlock, parseHeaderLine } from "./headers.js";
import { getProvider, providerIds, PROVIDERS } from "./providers/index.js";
import { renderDetections, renderProviders, renderReport, renderSigned } from "./report.js";
import { signRequest } from "./sign.js";
import { verify } from "./verify.js";
import { VERSION } from "./version.js";
import type { HeaderBag, ProviderId, VerifyOptions } from "./types.js";

const USAGE = `hookproof ${VERSION} — explainable webhook signature verification

Usage:
  hookproof verify [--provider <id>] --secret <secret> [--payload <file>]
                   (--header "Name: value")... [--headers <file>] [options]
  hookproof sign   --provider <id> --secret <secret> [--payload <file>]
                   [--timestamp <epoch>] [--id <msg id>] [--json]
  hookproof detect (--header "Name: value")... | --headers <file> [--json]
  hookproof providers [--json]

Providers: ${providerIds().join(" | ")}

Options:
  --payload <file>     request body file; "-" or omitted reads stdin
  --header "N: v"      add one request header (repeatable)
  --headers <file>     raw header block ("Name: value" lines; curl -v ok)
  --secret <secret>    signing secret
  --secret-file <f>    read the secret from a file (trailing newline trimmed)
  --provider <id>      scheme; verify auto-detects from headers when omitted
  --tolerance <secs>   override the scheme's replay tolerance
  --now <epoch>        clock for skew checks (default: current time)
  --timestamp <epoch>  sign: signing timestamp (default: current time)
  --id <id>            sign: message id for svix/standard
  --json               machine-readable output
  --no-diagnose        verify: plain pass/fail, skip the diagnosis pass
  --help, --version

Exit codes: 0 ok, 1 verification failed, 2 usage or input error.
`;

class UsageError extends Error {}

interface ParsedArgs {
  command: string | null;
  flags: Map<string, string>;
  headers: string[];
  booleans: Set<string>;
}

const VALUE_FLAGS = new Set([
  "--payload",
  "--headers",
  "--secret",
  "--secret-file",
  "--provider",
  "--tolerance",
  "--now",
  "--timestamp",
  "--id",
]);
const BOOLEAN_FLAGS = new Set(["--json", "--no-diagnose", "--help", "--version"]);

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { command: null, flags: new Map(), headers: [], booleans: new Set() };
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i] ?? "";
    if (arg === "--header") {
      const value = argv[i + 1];
      if (value === undefined) throw new UsageError("--header needs a value");
      parsed.headers.push(value);
      i += 2;
    } else if (VALUE_FLAGS.has(arg)) {
      const value = argv[i + 1];
      if (value === undefined) throw new UsageError(`${arg} needs a value`);
      parsed.flags.set(arg, value);
      i += 2;
    } else if (BOOLEAN_FLAGS.has(arg)) {
      parsed.booleans.add(arg);
      i += 1;
    } else if (arg.startsWith("-") && arg !== "-") {
      throw new UsageError(`unknown flag ${arg}`);
    } else if (parsed.command === null) {
      parsed.command = arg;
      i += 1;
    } else {
      throw new UsageError(`unexpected argument "${arg}"`);
    }
  }
  return parsed;
}

function readPayload(parsed: ParsedArgs): string {
  const path = parsed.flags.get("--payload");
  if (path === undefined || path === "-") return readFileSync(0, "utf8");
  return readFileSync(path, "utf8");
}

function readSecret(parsed: ParsedArgs): string {
  const inline = parsed.flags.get("--secret");
  if (inline !== undefined) return inline;
  const path = parsed.flags.get("--secret-file");
  if (path !== undefined) return readFileSync(path, "utf8").replace(/\r?\n$/, "");
  throw new UsageError("a secret is required (--secret or --secret-file)");
}

function readHeaders(parsed: ParsedArgs): HeaderBag {
  const entries: Array<[string, string]> = [];
  const file = parsed.flags.get("--headers");
  let fromFile: HeaderBag = {};
  if (file !== undefined) fromFile = parseHeaderBlock(readFileSync(file, "utf8"));
  for (const raw of parsed.headers) {
    const entry = parseHeaderLine(raw);
    if (entry === null) throw new UsageError(`--header "${raw}" is not a "Name: value" pair`);
    entries.push(entry);
  }
  return { ...fromFile, ...normalizeHeaders(entries) };
}

function readEpoch(parsed: ParsedArgs, flag: string): number | undefined {
  const raw = parsed.flags.get(flag);
  if (raw === undefined) return undefined;
  if (!/^\d+$/.test(raw)) throw new UsageError(`${flag} must be Unix epoch seconds, got "${raw}"`);
  return Number(raw);
}

function resolveProvider(parsed: ParsedArgs, headers: HeaderBag | null): ProviderId {
  const flag = parsed.flags.get("--provider");
  if (flag !== undefined) {
    const spec = getProvider(flag);
    if (spec === null) {
      throw new UsageError(`unknown provider "${flag}" (expected ${providerIds().join(", ")})`);
    }
    return spec.id;
  }
  if (headers === null) throw new UsageError("--provider is required for this command");
  const detections = detectProviders(headers);
  const first = detections[0];
  if (first === undefined) {
    throw new UsageError(
      "--provider not given and no known signature header found; pass --provider or add headers",
    );
  }
  const certain = detections.filter((d) => d.confidence === "certain");
  if (certain.length > 1) {
    throw new UsageError(
      `headers match several schemes (${certain.map((d) => d.provider).join(", ")}); pass --provider`,
    );
  }
  return first.provider;
}

function cmdVerify(parsed: ParsedArgs): number {
  const headers = readHeaders(parsed);
  const provider = resolveProvider(parsed, headers);
  const tolerance = readEpoch(parsed, "--tolerance");
  const now = readEpoch(parsed, "--now");
  const options: VerifyOptions = {
    provider,
    secret: readSecret(parsed),
    payload: readPayload(parsed),
    headers,
    ...(tolerance !== undefined ? { toleranceSeconds: tolerance } : {}),
    ...(now !== undefined ? { now } : {}),
    ...(parsed.booleans.has("--no-diagnose") ? { diagnose: false } : {}),
  };
  const report = verify(options);
  process.stdout.write(
    parsed.booleans.has("--json") ? JSON.stringify(report, null, 2) + "\n" : renderReport(report),
  );
  return report.ok ? 0 : 1;
}

function cmdSign(parsed: ParsedArgs): number {
  const flag = parsed.flags.get("--provider");
  if (flag === undefined) throw new UsageError("sign requires --provider");
  const spec = getProvider(flag);
  if (spec === null) {
    throw new UsageError(`unknown provider "${flag}" (expected ${providerIds().join(", ")})`);
  }
  const timestamp = readEpoch(parsed, "--timestamp");
  const id = parsed.flags.get("--id");
  let signed;
  try {
    signed = signRequest({
      provider: spec.id,
      secret: readSecret(parsed),
      payload: readPayload(parsed),
      ...(timestamp !== undefined ? { timestamp } : {}),
      ...(id !== undefined ? { id } : {}),
    });
  } catch (err) {
    throw new UsageError(err instanceof Error ? err.message : String(err));
  }
  process.stdout.write(
    parsed.booleans.has("--json") ? JSON.stringify(signed, null, 2) + "\n" : renderSigned(signed),
  );
  return 0;
}

function cmdProviders(parsed: ParsedArgs): number {
  if (parsed.booleans.has("--json")) {
    const specs = PROVIDERS.map((p) => ({
      id: p.id,
      label: p.label,
      signatureHeader: p.signatureHeader,
      ...(p.timestampHeader !== undefined ? { timestampHeader: p.timestampHeader } : {}),
      ...(p.idHeader !== undefined ? { idHeader: p.idHeader } : {}),
      algorithm: p.algorithm,
      encoding: p.encoding,
      scheme: p.scheme,
      toleranceSeconds: p.toleranceSeconds,
      secretHint: p.secretHint,
    }));
    process.stdout.write(JSON.stringify(specs, null, 2) + "\n");
    return 0;
  }
  process.stdout.write(renderProviders());
  return 0;
}

function cmdDetect(parsed: ParsedArgs): number {
  const headers = readHeaders(parsed);
  if (Object.keys(headers).length === 0) {
    throw new UsageError("detect needs headers (--header or --headers <file>)");
  }
  const detections = detectProviders(headers);
  process.stdout.write(
    parsed.booleans.has("--json")
      ? JSON.stringify(detections, null, 2) + "\n"
      : renderDetections(detections),
  );
  return detections.length > 0 ? 0 : 1;
}

/** Entry point, exported for tests. Returns the process exit code. */
export function main(argv: string[]): number {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`hookproof: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  if (parsed.booleans.has("--version")) {
    process.stdout.write(VERSION + "\n");
    return 0;
  }
  if (parsed.booleans.has("--help") || parsed.command === null) {
    process.stdout.write(USAGE);
    return 0;
  }
  try {
    switch (parsed.command) {
      case "verify":
        return cmdVerify(parsed);
      case "sign":
        return cmdSign(parsed);
      case "detect":
        return cmdDetect(parsed);
      case "providers":
        return cmdProviders(parsed);
      default:
        throw new UsageError(`unknown command "${parsed.command}" (try --help)`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`hookproof: ${err.message}\n`);
      return 2;
    }
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`hookproof: ${message}\n`);
    return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
