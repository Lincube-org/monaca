/**
 * Audit event shapes and presentation helpers.
 *
 * These mirror docs/contracts/m0.md §8.1 exactly: the stored form is the event plus `seq`,
 * `prev_hash` and `hash`, and the API list item carries all of them. Field names are the wire
 * names (`snake_case`) on purpose — a rename here would silently desynchronize the console from
 * the JSON Schema in `spec/events/`.
 */

export type AuditDecision = "allow" | "deny" | "info";

export type AuditSubjectType =
  | "account"
  | "org"
  | "agent"
  | "agent_key"
  | "grant"
  | "client"
  | "tool"
  | "session"
  | "tenant";

export interface AuditActor {
  type: AuditSubjectType;
  id: string;
}

export interface AuditSubject {
  type: AuditSubjectType;
  /** A typed id (`acc_…`), or a bare tool name such as `list_notes`. */
  id: string;
}

export interface AuditEvent {
  seq: number;
  id: string;
  at: string;
  action: string;
  actor_chain: AuditActor[];
  subject: AuditSubject;
  decision: AuditDecision;
  grant_id: string | null;
  jti: string | null;
  payload: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditChainHead {
  seq: number;
  hash: string;
}

export interface AuditIntegrity {
  valid: boolean;
  checked: number;
  head: AuditChainHead;
  first_broken: {
    seq: number;
    expected: string;
    actual: string;
    reason: "hash_mismatch" | "prev_hash_mismatch" | "seq_gap" | "head_mismatch";
  } | null;
}

/**
 * The M0 action set (§8.1), kept in the same order as `M0_ACTIONS` in `monaca-server`.
 * Anything outside it is shown verbatim but flagged as unexpected.
 */
export const M0_ACTIONS = [
  "account.created",
  "org.created",
  "org.archived",
  "org.reactivated",
  "org.member.added",
  "org.member.role_changed",
  "org.member.removed",
  "org.member.roles_changed",
  "org.domain.added",
  "org.domain.removed",
  "org.invitation.created",
  "org.invitation.revoked",
  "org.role.created",
  "org.role.updated",
  "org.role.deleted",
  "agent.created",
  "agent.key.registered",
  "agent.key.revoked",
  "grant.created",
  "grant.revoked",
  "agent.token.requested",
  "agent.token.issued",
  "agent.token.denied",
  "tool.invoked",
  "tool.denied",
  "interaction.sign_in.succeeded",
  "interaction.sign_in.failed",
  "connector.created",
  "connector.deleted",
  "sso_connector.created",
  "sso_connector.deleted",
  "client.created",
  "client.updated",
  "client.secret_rotated",
  "client.deleted",
  "account.deleted",
  "account.suspended",
  "account.reactivated",
  "account.security_changed",
  "role.created",
  "role.deleted",
  "session.logout",
  "session.revoked",
  "session.revoked_all",
  "sign_in_experience.updated",
  "resource.created",
  "resource.updated",
  "resource.deleted",
  "webhook.created",
  "webhook.updated",
  "webhook.deleted",
  "webhook.secret_rotated",
] as const;

export function isKnownAction(action: string): boolean {
  return (M0_ACTIONS as readonly string[]).includes(action);
}

/**
 * The actions a tenant webhook may subscribe to (§6.2), kept in the same order as
 * `WEBHOOK_EVENTS` in `monaca-server`.
 *
 * It is a subset of [`M0_ACTIONS`]: actions written straight into an org schema inside a business
 * transaction are not delivered by the tenant audit helpers yet, so the console must not offer
 * them.
 */
export const WEBHOOK_EVENTS = [
  "account.created",
  "account.deleted",
  "account.suspended",
  "account.reactivated",
  "account.security_changed",
  "client.created",
  "client.updated",
  "client.secret_rotated",
  "client.deleted",
  "connector.created",
  "connector.deleted",
  "sso_connector.created",
  "sso_connector.deleted",
  "interaction.sign_in.succeeded",
  "interaction.sign_in.failed",
  "org.created",
  "org.archived",
  "org.reactivated",
  "org.domain.added",
  "org.domain.removed",
  "org.invitation.created",
  "org.invitation.revoked",
  "resource.created",
  "resource.updated",
  "resource.deleted",
  "role.created",
  "role.deleted",
  "session.logout",
  "session.revoked",
  "session.revoked_all",
  "sign_in_experience.updated",
  "webhook.created",
  "webhook.updated",
  "webhook.deleted",
  "webhook.secret_rotated",
] as const;

export function isKnownWebhookEvent(action: string): boolean {
  return (WEBHOOK_EVENTS as readonly string[]).includes(action);
}

export function truncateHash(hash: string, head = 12): string {
  return hash.length > head ? `${hash.slice(0, head)}…` : hash;
}

/** `2026-01-01T00:10:00.000Z` → `00:10:00.000`, with the date shown only when it is not today. */
export function formatEventTime(at: string, now: Date = new Date()): { time: string; date: string | null } {
  const parsed = new Date(at);
  if (Number.isNaN(parsed.getTime())) return { time: at, date: null };

  const time = parsed.toISOString().slice(11, 23);
  const sameDay =
    parsed.getUTCFullYear() === now.getUTCFullYear() &&
    parsed.getUTCMonth() === now.getUTCMonth() &&
    parsed.getUTCDate() === now.getUTCDate();
  return { time, date: sameDay ? null : parsed.toISOString().slice(0, 10) };
}

/** Human-readable label for a typed id: the id itself, shortened to `prefix_…suffix4`. */
export function shortId(id: string): string {
  const match = /^([a-z]+)_(.+)$/.exec(id);
  if (!match) return id;
  const [, prefix, suffix] = match;
  return suffix && suffix.length > 6 ? `${prefix}_…${suffix.slice(-4)}` : id;
}

/** The subject label shown next to the action; a tool name is a bare string, not a typed id. */
export function subjectLabel(subject: AuditSubject): string {
  return subject.type === "tool" ? subject.id : shortId(subject.id);
}
