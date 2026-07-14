# Contributing to hookproof

Issues, discussions and pull requests are all welcome — this project aims to
stay a small, exact tool: five schemes implemented faithfully, zero runtime
dependencies, and a diagnosis engine that never guesses.

## Getting started

Requirements: Node.js >= 22.13 (for the stable `node:test` runner).

```bash
git clone https://github.com/JaydenCJ/hookproof.git
cd hookproof
npm install            # installs typescript, the only devDependency
npm run build          # compile TypeScript to dist/
npm test               # build + 90 node:test tests
bash scripts/smoke.sh  # end-to-end CLI check
```

`scripts/smoke.sh` drives the compiled CLI through sign → verify round-trips,
three diagnosis scenarios, provider detection, JSON output and the exit-code
contract, and must print `SMOKE OK`.

## Before you open a pull request

1. `npx tsc -p tsconfig.json --noEmit` — the tree must type-check clean
   (strict mode plus `noUncheckedIndexedAccess` is enforced).
2. `npm test` — all tests must pass.
3. `bash scripts/smoke.sh` — must print `SMOKE OK`.
4. Add tests for behavior changes; keep logic in pure, unit-testable modules
   (providers, codecs and the diagnosis engine all take plain strings and
   header bags — never sockets, streams or clocks; time is an injected
   parameter).
5. A new provider needs: a `ProviderSpec` in `src/providers/`, reference
   vectors computed with an independent implementation in its test file, a
   row in `docs/providers.md`, and README table updates.

## Ground rules

- **No runtime dependencies.** The zero-dependency install is a core
  feature; adding one needs justification in the PR and will usually be
  declined.
- No network calls, ever — hookproof reads strings and prints strings.
  Secrets stay in memory and are never echoed back in full by any code path.
- Scheme fidelity over convenience: the strict verification pass must match
  the provider's own SDK byte-for-byte. Forgiving interpretations belong
  exclusively in the diagnosis engine, clearly labelled as findings.
- Finding ids (`payload-newline`, `encoding-mismatch`, …) are stable API:
  scripts grep for them. Renaming one is a breaking change.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include: `hookproof --version` output, the provider, the `--json`
report (redact the secret and signature values — the finding ids and
structure are what matter), and if possible a self-contained repro built
with `hookproof sign` and a throwaway secret.

## Security

Do not open public issues for security problems; use GitHub private
vulnerability reporting on this repository instead. Note that hookproof is a
diagnostic tool: run it with production secrets only on machines you trust,
and prefer `--secret-file` over `--secret` to keep secrets out of shell
history.
