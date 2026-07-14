// End-to-end CLI tests against the compiled dist/cli.js: real argv, real
// stdin, real exit codes. These prove the whole pipeline — header parsing,
// verification, diagnosis, rendering — is reachable from a shell.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { NOW, PAYLOAD, ROOT, refHmacHex, runCli } from "./helpers.mjs";

const SECRET = "whsec_Y2xpX3Rlc3Rfc2VjcmV0";
const DIR = mkdtempSync(join(tmpdir(), "hookproof-cli-"));
const PAYLOAD_FILE = join(DIR, "payload.json");
writeFileSync(PAYLOAD_FILE, PAYLOAD);
test.after(() => rmSync(DIR, { recursive: true, force: true }));

function stripeHeaderArg(secret = SECRET, t = NOW, payload = PAYLOAD) {
  return `Stripe-Signature: t=${t},v1=${refHmacHex(secret, `${t}.${payload}`)}`;
}

test("--version matches package.json", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const { stdout, code } = runCli(["--version"]);
  assert.equal(code, 0);
  assert.equal(stdout.trim(), pkg.version);
});

test("--help (and bare invocation) documents commands, providers and exit codes", () => {
  const { stdout, code } = runCli(["--help"]);
  assert.equal(code, 0);
  for (const word of ["verify", "sign", "detect", "providers", "stripe", "Exit codes"]) {
    assert.ok(stdout.includes(word), `help missing ${word}`);
  }
  assert.equal(runCli([]).code, 0);
});

test("verify: a valid request exits 0 and prints PASS", () => {
  const { stdout, code } = runCli([
    "verify",
    "--provider", "stripe",
    "--secret", SECRET,
    "--payload", PAYLOAD_FILE,
    "--header", stripeHeaderArg(),
    "--now", String(NOW + 10),
  ]);
  assert.equal(code, 0);
  assert.match(stdout, /^PASS {2}stripe/);
  assert.match(stdout, /canonical/);
});

test("verify: a tampered payload exits 1 and explains itself", () => {
  const { stdout, code } = runCli([
    "verify",
    "--provider", "stripe",
    "--secret", "whsec_the_wrong_secret",
    "--payload", PAYLOAD_FILE,
    "--header", stripeHeaderArg(),
    "--now", String(NOW),
  ]);
  assert.equal(code, 1);
  assert.match(stdout, /^FAIL {2}stripe/);
  assert.match(stdout, /findings/);
  assert.match(stdout, /secret-mismatch/);
});

test("verify: reads stdin when --payload is omitted and auto-detects the provider", () => {
  const { stdout, code } = runCli(
    ["verify", "--secret", SECRET, "--header", stripeHeaderArg(), "--now", String(NOW)],
    { input: PAYLOAD },
  );
  assert.equal(code, 0);
  assert.match(stdout, /PASS {2}stripe/);
});

test("verify: --json emits a machine-readable report with findings", () => {
  const { stdout, code } = runCli(
    [
      "verify",
      "--provider", "stripe",
      "--secret", SECRET,
      "--header", `Stripe-Signature: t=${NOW},v1=${refHmacHex(SECRET, `${NOW}.${PAYLOAD}\n`)}`,
      "--now", String(NOW),
      "--json",
    ],
    { input: PAYLOAD },
  );
  assert.equal(code, 1);
  const report = JSON.parse(stdout);
  assert.equal(report.ok, false);
  assert.equal(report.provider, "stripe");
  assert.ok(report.findings.some((f) => f.id === "payload-newline"));
});

test("verify: --tolerance rescues an old-but-genuine test replay", () => {
  const old = runCli(
    ["verify", "--secret", SECRET, "--header", stripeHeaderArg(SECRET, NOW - 9000), "--now", String(NOW)],
    { input: PAYLOAD },
  );
  assert.equal(old.code, 1);
  assert.match(old.stdout, /timestamp-skew/);
  const rescued = runCli(
    [
      "verify",
      "--secret", SECRET,
      "--header", stripeHeaderArg(SECRET, NOW - 9000),
      "--now", String(NOW),
      "--tolerance", "10000",
    ],
    { input: PAYLOAD },
  );
  assert.equal(rescued.code, 0);
});

test("verify: --no-diagnose keeps the report plain", () => {
  const { stdout, code } = runCli(
    [
      "verify",
      "--provider", "stripe",
      "--secret", "whsec_wrong",
      "--header", stripeHeaderArg(),
      "--now", String(NOW),
      "--no-diagnose",
    ],
    { input: PAYLOAD },
  );
  assert.equal(code, 1);
  assert.ok(!stdout.includes("findings"), "no findings section expected");
});

test("sign → verify round-trips for every provider via --headers file", () => {
  for (const provider of ["stripe", "github", "slack", "svix", "standard"]) {
    const secret = provider === "svix" || provider === "standard" ? "whsec_a2V5bWF0ZXJpYWw=" : SECRET;
    const signed = runCli(
      ["sign", "--provider", provider, "--secret", secret, "--payload", PAYLOAD_FILE, "--timestamp", String(NOW), "--id", "msg_rt"],
    );
    assert.equal(signed.code, 0, `${provider} sign failed: ${signed.stderr}`);
    const headersFile = join(DIR, `${provider}-headers.txt`);
    writeFileSync(headersFile, signed.stdout);
    const verified = runCli(
      ["verify", "--provider", provider, "--secret", secret, "--payload", PAYLOAD_FILE, "--headers", headersFile, "--now", String(NOW)],
    );
    assert.equal(verified.code, 0, `${provider} round-trip failed:\n${verified.stdout}`);
  }
});

test("sign: --json includes the canonical string", () => {
  const { stdout, code } = runCli(
    ["sign", "--provider", "slack", "--secret", "sekrit", "--payload", PAYLOAD_FILE, "--timestamp", String(NOW), "--json"],
  );
  assert.equal(code, 0);
  const signed = JSON.parse(stdout);
  assert.equal(signed.canonical, `v0:${NOW}:${PAYLOAD}`);
});

test("sign: a svix secret that is not base64 exits 2 with a diagnostic", () => {
  const { code, stderr } = runCli(
    ["sign", "--provider", "svix", "--secret", "not base64 at all", "--payload", PAYLOAD_FILE],
  );
  assert.equal(code, 2);
  assert.match(stderr, /^hookproof: /);
});

test("detect: names the scheme from a header block file, exits 1 on nothing", () => {
  const headersFile = join(DIR, "detect-headers.txt");
  writeFileSync(headersFile, "svix-id: msg_1\nsvix-timestamp: 1700000000\nsvix-signature: v1,abc\n");
  const { stdout, code } = runCli(["detect", "--headers", headersFile]);
  assert.equal(code, 0);
  assert.match(stdout, /svix\s+certain/);
  const nothing = runCli(["detect", "--header", "Content-Type: application/json"]);
  assert.equal(nothing.code, 1);
  assert.match(nothing.stdout, /no known webhook signature scheme/);
});

test("usage errors exit 2 with a hookproof: prefix on stderr", () => {
  const cases = [
    ["frobnicate"],
    ["verify", "--provider", "nope", "--secret", "s", "--header", "X: y"],
    ["verify", "--secret", "s"], // no headers to detect from
    ["sign", "--secret", "s"], // sign requires --provider
    ["verify", "--provider", "stripe", "--header", "X: y"], // no secret
    ["verify", "--provider", "stripe", "--secret", "s", "--now", "yesterday"],
    ["--bogus-flag"],
  ];
  for (const args of cases) {
    const { code, stderr } = runCli(args, { input: "" });
    assert.equal(code, 2, `expected exit 2 for: ${args.join(" ")}`);
    assert.match(stderr, /^hookproof: /);
  }
});

test("verify: --secret-file trims a single trailing newline only", () => {
  const secretFile = join(DIR, "secret.txt");
  writeFileSync(secretFile, SECRET + "\n");
  const { code } = runCli(
    ["verify", "--provider", "stripe", "--secret-file", secretFile, "--header", stripeHeaderArg(), "--now", String(NOW)],
    { input: PAYLOAD },
  );
  assert.equal(code, 0);
});

test("providers: lists all five schemes with their headers", () => {
  const { stdout, code } = runCli(["providers"]);
  assert.equal(code, 0);
  for (const name of ["Stripe-Signature", "X-Hub-Signature-256", "X-Slack-Signature", "svix-signature", "webhook-signature"]) {
    assert.ok(stdout.includes(name), `providers output missing ${name}`);
  }
});

test("providers: --json emits the machine-readable scheme reference", () => {
  const { stdout, code } = runCli(["providers", "--json"]);
  assert.equal(code, 0);
  const specs = JSON.parse(stdout);
  assert.equal(specs.length, 5);
  const stripe = specs.find((s) => s.id === "stripe");
  assert.equal(stripe.signatureHeader, "Stripe-Signature");
  assert.equal(stripe.algorithm, "sha256");
  assert.equal(stripe.toleranceSeconds, 300);
  const github = specs.find((s) => s.id === "github");
  assert.equal(github.toleranceSeconds, null, "GitHub's scheme has no timestamp");
});
