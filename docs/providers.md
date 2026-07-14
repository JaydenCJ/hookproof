# Scheme reference

The exact wire formats hookproof implements, and the finding catalog the
diagnosis engine reports against them. This file is the contract: the strict
verification pass in `src/verify.ts` + `src/providers/` must match this
document, and this document must match the providers' published behavior.

## The five schemes

### Stripe

```
Stripe-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>][,v0=<hex>]
```

- Canonical string: `{t}.{body}` — the raw `t=` value, one dot, the raw body.
- MAC: HMAC-SHA256, lowercase hex, in one or more `v1=` elements (multiple
  during secret rolls; any one matching passes).
- Secret: the endpoint's `whsec_…` string used **verbatim** — the prefix is
  part of the key material.
- `v0=` elements belong to a legacy test scheme and are ignored (a v0-only
  header is diagnosed, not silently failed).
- Replay tolerance: 300 s default.

### GitHub

```
X-Hub-Signature-256: sha256=<hex>
X-Hub-Signature: sha1=<hex>          (legacy, still delivered)
```

- Canonical string: the raw body, nothing else. **No timestamp exists in the
  scheme** — replay protection must come from the `X-GitHub-Delivery` id on
  your side.
- Secret: the webhook secret string, verbatim.
- hookproof verifies the SHA-256 header only; a delivery carrying only the
  legacy header is diagnosed (`scheme-mismatch` + `algorithm-mismatch`).

### Slack

```
X-Slack-Signature: v0=<hex>
X-Slack-Request-Timestamp: <unix seconds>
```

- Canonical string: `v0:{timestamp}:{body}` — note the version prefix lives
  **inside** the signed string, unlike every other scheme here.
- Secret: the app's Signing Secret, verbatim.
- Replay tolerance: 300 s (Slack documents "about five minutes").

### Svix and Standard Webhooks

```
svix-id: msg_…              webhook-id: msg_…
svix-timestamp: <unix>      webhook-timestamp: <unix>
svix-signature: v1,<base64> webhook-signature: v1,<base64> [v1,<base64> …]
```

- One scheme, two header prefixes — the Standard Webhooks specification
  adopted Svix's format. Signatures produced under one prefix verify under
  the other byte-for-byte.
- Canonical string: `{id}.{timestamp}.{body}`.
- MAC: HMAC-SHA256, **standard base64 with padding**, after `v1,`. The
  signature header is a space-separated list; any matching `v1` passes.
  `v1a,` tokens are the asymmetric scheme and are skipped.
- Secret: `whsec_` + base64. The key is the **decoded bytes** of the portion
  after the prefix — not the literal string.
- Replay tolerance: 300 s recommended by both ecosystems.

## Verification semantics

The strict pass mirrors the providers' own SDKs:

1. Extract signature / timestamp / id from the (case-insensitively matched)
   headers; structural problems become findings immediately.
2. Derive key bytes from the secret per the scheme.
3. Build the canonical string and compute the expected MAC.
4. Compare constant-time in the scheme's encoding — hex case-insensitively,
   base64 exactly.
5. Check the timestamp against `now ± tolerance` (injectable `now`).

`ok` requires all of: a signature match, a timestamp inside tolerance (when
the scheme has one), no structural errors, and usable key material. Anything
less is a FAIL with findings — never a bare boolean.

## Finding catalog

Ids are stable API; scripts may grep for them. Severity `error` blocks PASS.

| Id | Detects |
| --- | --- |
| `header-missing` | a required scheme header is absent |
| `header-malformed` | the signature header does not parse per scheme |
| `scheme-mismatch` | a signature exists under the wrong scheme label (v0-only, bare digest, sha1-only, v1a-only) |
| `timestamp-invalid` | the timestamp is not epoch seconds |
| `timestamp-skew` | outside the replay window (reports direction and magnitude; notes when the MAC itself is valid) |
| `signature-undecodable` | the value is neither hex nor any base64 dialect |
| `signature-length` | decodes to the wrong byte count for the algorithm |
| `signature-truncated` | the value is a prefix of the correct signature |
| `encoding-mismatch` | correct digest bytes, wrong serialization (base64 vs hex vs base64url) |
| `algorithm-mismatch` | the MAC matches under SHA-1 or SHA-512 instead of the scheme's algorithm |
| `payload-newline` | a trailing newline was added to or stripped from the signed body |
| `payload-crlf` | line endings were rewritten (CRLF↔LF) in transit |
| `payload-bom` | the capture gained a UTF-8 byte-order mark |
| `payload-whitespace` | surrounding whitespace was added to the body |
| `payload-reserialized` | the MAC matches the compact re-serialization of the JSON body |
| `secret-whitespace` | the secret verifies after trimming stray whitespace |
| `secret-prefix` | the `whsec_` prefix was wrongly included or stripped |
| `secret-encoding` | key material was base64-decoded where it should be literal, or vice versa |
| `wrong-provider` | the request verifies cleanly under a different provider's scheme |
| `secret-mismatch` | fallback verdict: nothing above explains it — the secret is wrong |

## How diagnosis stays honest

Every finding of the transform search is *proof*, not heuristics: the engine
recomputes the HMAC under the candidate interpretation and reports it only on
a byte-exact digest match. With a 256-bit MAC, a transform that matches did
happen on the signing side. Candidates are ordered by how many dimensions
differ from the strict interpretation, so the report always names the
minimal explanation; when several dimensions are wrong at once (say, a
stripped newline *and* a base64-encoded digest) each contributing finding is
listed. The search is bounded (≤ ~8 payload × 5 secret × 3 algorithm
variants per signature) and costs microseconds.

## Limitations in 0.1.0

- Payloads are treated as UTF-8 text; binary bodies (invalid UTF-8) are out
  of scope until a `--payload-base64` input lands.
- Svix `v1a` (asymmetric ed25519) signatures are recognized and skipped, not
  verified.
- No HTTP listener: hookproof inspects captured requests, it does not proxy.
