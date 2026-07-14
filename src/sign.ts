/**
 * Signature generation — the other half of the tool. Being able to mint a
 * correct header for any scheme is what makes endpoints testable offline:
 * sign a fixture, POST it at your handler, and you have a deterministic
 * integration test with no provider dashboard involved.
 */

import { getProvider } from "./providers/index.js";
import type { ProviderId, SignedRequest } from "./types.js";

export interface SignRequestOptions {
  provider: ProviderId;
  secret: string;
  payload: string;
  /** Unix epoch seconds. Defaults to the current time. */
  timestamp?: number;
  /** Message id for Svix-family schemes. Defaults to `msg_<timestamp>`. */
  id?: string;
}

/**
 * Produce ready-to-send headers for a payload. Throws Error when the
 * provider id is unknown or the secret is unusable for the scheme
 * (e.g. a Svix secret that does not base64-decode).
 */
export function signRequest(options: SignRequestOptions): SignedRequest {
  const spec = getProvider(options.provider);
  if (spec === null) {
    throw new Error(`unknown provider "${options.provider}"`);
  }
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  return spec.sign({
    secret: options.secret,
    payload: options.payload,
    timestamp,
    ...(options.id !== undefined ? { id: options.id } : {}),
  });
}
