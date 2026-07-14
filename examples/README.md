# hookproof examples

Runnable demonstrations of the diagnosis engine. Everything is offline and
deterministic; run from the repository root after `npm install && npm run build`.

## diagnose.mjs

```bash
node examples/diagnose.mjs
```

Simulates the three failures that account for most "signature verification
failed" hours: a JSON body re-serialized by middleware, a replayed delivery
with a stale timestamp, and a digest re-encoded as base64 where hex was
expected — and prints the full diagnosis report for each, naming the root
cause and the fix.

## Shell one-liners

The CLI covers the same ground from a pipe. A few to try:

```bash
# Mint valid Stripe headers for a fixture body (great for endpoint tests).
printf '%s' '{"id":"evt_1"}' \
  | node dist/cli.js sign --provider stripe --secret whsec_test --timestamp 1700000000

# Verify it back, pinning the clock so the replay check is deterministic.
printf '%s' '{"id":"evt_1"}' \
  | node dist/cli.js verify --secret whsec_test --now 1700000005 \
      --header "$(printf '%s' '{"id":"evt_1"}' \
        | node dist/cli.js sign --provider stripe --secret whsec_test --timestamp 1700000000)"

# Which scheme is this? Paste any header block (curl -v output works too).
node dist/cli.js detect --header "svix-id: msg_1" \
  --header "svix-timestamp: 1700000000" --header "svix-signature: v1,abc"

# The full scheme reference table.
node dist/cli.js providers
```
