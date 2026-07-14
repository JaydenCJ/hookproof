#!/usr/bin/env bash
# Smoke test for hookproof: exercises the real CLI end to end — sign,
# verify, diagnose, detect — across providers. No network, idempotent,
# runs from a clean checkout (after `npm install`). Prints "SMOKE OK".
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$(pwd)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $1" >&2
  exit 1
}

NOW=1700000000
SECRET="whsec_c21va2Vfc2VjcmV0"
SVIX_SECRET="whsec_$(printf '%s' 'smoke-key-material' | base64)"

# 1. Build (idempotent).
npm run build >/dev/null 2>&1 || fail "npm run build failed"
CLI="node $ROOT/dist/cli.js"
echo "[smoke] build ok"

# 2. --version matches package.json; --help documents the surface.
PKG_VERSION="$(node -p "require('$ROOT/package.json').version")"
CLI_VERSION="$($CLI --version)"
[ "$CLI_VERSION" = "$PKG_VERSION" ] || fail "--version mismatch: $CLI_VERSION != $PKG_VERSION"
HELP="$($CLI --help)"
for word in verify sign detect providers stripe svix "Exit codes"; do
  echo "$HELP" | grep -q -- "$word" || fail "--help missing $word"
done
echo "[smoke] --help/--version ok ($CLI_VERSION)"

# 3. providers lists all five schemes.
PROV="$($CLI providers)"
for name in Stripe-Signature X-Hub-Signature-256 X-Slack-Signature svix-signature webhook-signature; do
  echo "$PROV" | grep -q "$name" || fail "providers missing $name"
done
echo "[smoke] providers ok (5 schemes)"

# 4. Stripe: sign → verify round-trip with a fixed clock.
printf '%s' '{"id":"evt_smoke","type":"charge.succeeded"}' > "$WORKDIR/body.json"
HEADER="$($CLI sign --provider stripe --secret "$SECRET" --payload "$WORKDIR/body.json" --timestamp "$NOW")"
$CLI verify --provider stripe --secret "$SECRET" --payload "$WORKDIR/body.json" \
  --header "$HEADER" --now "$NOW" > "$WORKDIR/pass.txt" || fail "stripe round-trip did not verify"
grep -q "^PASS  stripe" "$WORKDIR/pass.txt" || fail "expected PASS output"
grep -q "canonical" "$WORKDIR/pass.txt" || fail "report must show the canonical string"
echo "[smoke] stripe sign → verify ok"

# 5. Diagnosis: a stripped trailing newline is named, exit code is 1.
printf '%s\n' '{"id":"evt_smoke","type":"charge.succeeded"}' > "$WORKDIR/body-nl.json"
HEADER_NL="$($CLI sign --provider stripe --secret "$SECRET" --payload "$WORKDIR/body-nl.json" --timestamp "$NOW")"
set +e
$CLI verify --provider stripe --secret "$SECRET" --payload "$WORKDIR/body.json" \
  --header "$HEADER_NL" --now "$NOW" > "$WORKDIR/fail.txt"; code=$?
set -e
[ "$code" -eq 1 ] || fail "verification failure should exit 1, got $code"
grep -q "payload-newline" "$WORKDIR/fail.txt" || fail "diagnosis must name payload-newline"
echo "[smoke] diagnosis ok (payload-newline, exit 1)"

# 6. Diagnosis: base64 signature where hex is expected.
B64SIG="$(node -e 'const{createHmac}=require("node:crypto");const fs=require("node:fs");
const body=fs.readFileSync(process.argv[1],"utf8");
process.stdout.write(createHmac("sha256","whsec_c21va2Vfc2VjcmV0").update("1700000000."+body).digest("base64"));' "$WORKDIR/body.json")"
set +e
$CLI verify --provider stripe --secret "$SECRET" --payload "$WORKDIR/body.json" \
  --header "Stripe-Signature: t=$NOW,v1=$B64SIG" --now "$NOW" > "$WORKDIR/enc.txt"; code=$?
set -e
[ "$code" -eq 1 ] || fail "encoding mismatch should exit 1"
grep -q "encoding-mismatch" "$WORKDIR/enc.txt" || fail "diagnosis must name encoding-mismatch"
echo "[smoke] diagnosis ok (encoding-mismatch)"

# 7. Svix: sign to a headers file, detect it, verify with auto-detection.
$CLI sign --provider svix --secret "$SVIX_SECRET" --payload "$WORKDIR/body.json" \
  --timestamp "$NOW" --id msg_smoke > "$WORKDIR/svix-headers.txt"
$CLI detect --headers "$WORKDIR/svix-headers.txt" | grep -q "svix.*certain" || fail "detect must name svix"
$CLI verify --secret "$SVIX_SECRET" --payload "$WORKDIR/body.json" \
  --headers "$WORKDIR/svix-headers.txt" --now "$NOW" | grep -q "^PASS  svix" || fail "svix auto-detected verify failed"
echo "[smoke] svix detect + verify ok"

# 8. Wrong provider is diagnosed with the fix.
$CLI sign --provider github --secret gh-secret --payload "$WORKDIR/body.json" > "$WORKDIR/gh-headers.txt"
set +e
$CLI verify --provider slack --secret gh-secret --payload "$WORKDIR/body.json" \
  --headers "$WORKDIR/gh-headers.txt" --now "$NOW" > "$WORKDIR/wrong.txt"; code=$?
set -e
[ "$code" -eq 1 ] || fail "wrong provider should exit 1"
grep -q -- "--provider github" "$WORKDIR/wrong.txt" || fail "diagnosis must suggest --provider github"
echo "[smoke] wrong-provider diagnosis ok"

# 9. --json is machine-readable and carries the findings.
$CLI verify --provider stripe --secret "$SECRET" --payload "$WORKDIR/body.json" \
  --header "$HEADER_NL" --now "$NOW" --json > "$WORKDIR/report.json" || true
node -e 'const r=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
if (r.ok !== false) throw new Error("ok should be false");
if (!r.findings.some(f=>f.id==="payload-newline")) throw new Error("missing finding");
if (!r.canonical || !r.expected) throw new Error("missing canonical/expected");' "$WORKDIR/report.json" \
  || fail "--json report malformed"
echo "[smoke] --json ok"

# 10. Usage errors exit 2 with a diagnostic on stderr.
set +e
$CLI frobnicate </dev/null >/dev/null 2>"$WORKDIR/err"; code=$?
set -e
[ "$code" -eq 2 ] || fail "unknown command should exit 2, got $code"
grep -q "^hookproof: " "$WORKDIR/err" || fail "usage error must print a diagnostic"
echo "[smoke] usage errors ok (exit 2)"

# 11. The bundled example runs and diagnoses its scenarios.
node "$ROOT/examples/diagnose.mjs" > "$WORKDIR/example.txt" || fail "examples/diagnose.mjs failed"
grep -q "payload-reserialized" "$WORKDIR/example.txt" || fail "example output missing diagnosis"
echo "[smoke] example ok"

echo "SMOKE OK"
