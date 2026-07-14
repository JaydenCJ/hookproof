/**
 * Provider registry. Order matters only for display; lookups are by id.
 */

import type { ProviderId, ProviderSpec } from "../types.js";
import { stripe } from "./stripe.js";
import { github } from "./github.js";
import { slack } from "./slack.js";
import { makeSvixLike } from "./svixlike.js";

export const svix = makeSvixLike("svix", "Svix", "svix");
export const standard = makeSvixLike("standard", "Standard Webhooks", "webhook");
export { stripe, github, slack };

export const PROVIDERS: readonly ProviderSpec[] = [stripe, github, slack, svix, standard];

const BY_ID = new Map<ProviderId, ProviderSpec>(PROVIDERS.map((p) => [p.id, p]));

/** Look up a provider by id; returns null for unknown ids. */
export function getProvider(id: string): ProviderSpec | null {
  return BY_ID.get(id as ProviderId) ?? null;
}

/** All provider ids, for usage messages. */
export function providerIds(): string[] {
  return PROVIDERS.map((p) => p.id);
}
