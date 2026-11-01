import type { ListAuditQuery } from "./types";

/**
 * TanStack Query keys.
 *
 * Keys are arrays built through these factories rather than written inline, so an invalidation can
 * never miss a variant by typo. The hierarchy is deliberate: invalidating `['audit', org]` clears
 * every audit page and filter for that org without touching another org's cache.
 */
export const queryKeys = {
  session: () => ["session"] as const,

  organizations: () => ["organizations"] as const,

  clients: () => ["clients"] as const,

  members: (org: string) => ["members", org] as const,

  agents: (org: string) => ["agents", org] as const,
  agent: (org: string, agentId: string) => ["agents", org, agentId] as const,

  grants: (org: string) => ["grants", org] as const,

  audit: (org: string, query: ListAuditQuery = {}) => ["audit", org, normalize(query)] as const,
  auditVerify: (org: string) => ["audit", org, "verify"] as const,
};

/** Drop undefined members so `{}` and `{limit: undefined}` are the same cache entry. */
function normalize(query: ListAuditQuery): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) out[key] = value;
  }
  return out;
}
