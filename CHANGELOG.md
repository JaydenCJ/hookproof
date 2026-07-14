# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-13

### Added

- Faithful implementations of five webhook signature schemes: Stripe
  (`Stripe-Signature`, `{t}.{body}`, hex), GitHub (`X-Hub-Signature-256`,
  raw body, hex, plus the legacy SHA-1 header), Slack (`X-Slack-Signature`,
  `v0:{ts}:{body}`), Svix (`svix-*`, `{id}.{ts}.{body}`, base64,
  base64-decoded `whsec_` keys) and Standard Webhooks (`webhook-*`, same
  scheme as Svix).
- A strict verification pass that mirrors each provider's own SDK:
  constant-time comparison, exact encodings, replay-window enforcement with
  per-scheme default tolerances and an injectable clock (`--now`) for
  deterministic verification of captured requests.
- The diagnosis engine: on failure, a bounded search over payload transforms
  (trailing newline, CRLF/LF, UTF-8 BOM, surrounding whitespace, re-serialized
  JSON), secret interpretations (whitespace, `whsec_` prefix handling,
  base64-decoded vs literal keys) and digest algorithms (SHA-1/256/512)
  reports the minimal change that makes the MAC match — plus signature-shape
  checks (truncation, wrong length, undecodable values), cross-provider
  verification ("this request is actually a valid GitHub delivery"), and an
  honest `secret-mismatch` fallback when nothing else explains it.
- 20 stable, greppable finding ids with severity, observation and a concrete
  fix on every finding.
- Reports that show their work: the exact canonical string with invisible
  bytes escaped (`\n`, `\r`, `\ufeff`), payload byte counts, timestamp skew
  against tolerance, and expected vs provided signatures.
- Signature generation (`hookproof sign`) for all five schemes — mint valid
  headers for any payload/secret/timestamp to test endpoints offline
  (GitHub signing emits both the SHA-256 and legacy SHA-1 headers).
- Provider auto-detection from headers (`hookproof detect` and provider-less
  `verify`), with certain/likely confidence and missing-header listing.
- A four-command CLI (`verify`, `sign`, `detect`, `providers`) reading
  payloads from files or stdin and headers from repeatable `--header` flags
  or pasted header blocks (curl -v transcripts accepted); `--json` output on
  every command; exit codes 0/1/2.
- A typed library API exporting the verifier, signer, diagnosis engine,
  provider registry, header parsers and codecs.
- Zero runtime dependencies: hand-rolled hex/base64/base64url codecs
  (cross-checked against Buffer in the test suite) and `node:crypto` HMAC.
- Scheme reference in `docs/providers.md`; a runnable diagnosis example in
  `examples/`; test suite: 90 node:test tests plus an end-to-end
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/hookproof/releases/tag/v0.1.0
