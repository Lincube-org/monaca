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

  resources: () => ["resources"] as const,

  accounts: (query: string) => ["accounts", query] as const,

  tenantRoles: () => ["tenant-roles"] as const,

  accountSessions: (accountId: string) => ["account-sessions", accountId] as const,

  accountSecurity: (accountId: string) => ["account-security", accountId] as const,

  connectors: () => ["connectors"] as const,

  ssoConnectors: () => ["sso-connectors"] as const,

  signInExperience: () => ["sign-in-experience"] as const,

  webhooks: () => ["webhooks"] as const,
  webhookDeliveries: (webhookId: string) => ["webhooks", webhookId, "deliveries"] as const,

  members: (org: string) => ["members", org] as const,

  orgEmailDomains: (org: string) => ["org-email-domains", org] as const,

  orgInvitations: (org: string) => ["org-invitations", org] as const,

  orgRoles: (org: string) => ["org-roles", org] as const,
  memberRoles: (org: string, accountId: string) => ["member-roles", org, accountId] as const,

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
