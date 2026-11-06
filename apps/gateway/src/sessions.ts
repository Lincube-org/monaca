/**
 * BFF sessions and login tickets, in memory (contract §9: "Access and refresh tokens live in
 * gateway memory (M0) and are never sent to the browser").
 *
 * The browser only ever holds an opaque session id in an HttpOnly cookie. TTL is enforced
 * lazily on read plus a periodic sweep, so an abandoned session cannot outlive its TTL even if
 * nobody ever looks at it again.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface BffTokens {
  accessToken: string;
  refreshToken?: string;
  /** Epoch milliseconds at which the access token expires. */
  expiresAt: number;
}

export interface BffOrg {
  readonly slug: string;
  readonly role: string;
}

/** The management tier `/v1/me` reports; the console uses it to hide write controls. */
export type ManagementTier = "none" | "read" | "write" | "full";

/** A tenant role as `/v1/me` returns it. */
export interface BffRole {
  readonly id: string;
  readonly name: string;
  readonly permissions: readonly string[];
}

export interface BffSession {
  readonly id: string;
  readonly tenant: string;
  readonly accountId: string;
  readonly email: string;
  readonly orgs: readonly BffOrg[];
  readonly management: ManagementTier;
  readonly roles: readonly BffRole[];
  readonly isTenantAdmin: boolean;
  readonly createdAt: number;
  touchedAt: number;
  tokens: BffTokens;
}

export interface LoginTicket {
  readonly state: string;
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly nonce: string;
  readonly createdAt: number;
}

const TICKET_TTL_MS = 10 * 60 * 1000; // login tickets are short-lived; the interaction itself is 600 s (§2.2)
const SWEEP_INTERVAL_MS = 60 * 1000;

function base64url(buffer: Buffer): string {
  return buffer.toString("base64url");
}

/** S256 PKCE challenge from a high-entropy verifier (RFC 7636). */
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export class SessionStore {
  readonly #sessions = new Map<string, BffSession>();
  readonly #tickets = new Map<string, LoginTicket>();
  readonly #ttlMs: number;
  #sweeper: ReturnType<typeof setInterval> | undefined;

  constructor(ttlSecs: number) {
    this.#ttlMs = ttlSecs * 1000;
  }

  /** A fresh login ticket; the `state` doubles as its map key. */
  createTicket(): LoginTicket {
    const state = base64url(randomBytes(24));
    const codeVerifier = base64url(randomBytes(32));
    const ticket: LoginTicket = {
      state,
      codeVerifier,
      codeChallenge: pkceChallenge(codeVerifier),
      nonce: base64url(randomBytes(16)),
      createdAt: Date.now(),
    };
    this.#tickets.set(state, ticket);
    return ticket;
  }

  /** Consumes the ticket for `state`; unknown or expired states yield `undefined`. */
  consumeTicket(state: string | null): LoginTicket | undefined {
    if (state === null) return undefined;
    const ticket = this.#tickets.get(state);
    if (ticket === undefined) return undefined;
    this.#tickets.delete(state);
    if (Date.now() - ticket.createdAt > TICKET_TTL_MS) return undefined;
    return ticket;
  }

  createSession(input: {
    tenant: string;
    accountId: string;
    email: string;
    orgs: readonly BffOrg[];
    management: ManagementTier;
    roles: readonly BffRole[];
    isTenantAdmin: boolean;
    tokens: BffTokens;
  }): BffSession {
    const now = Date.now();
    const session: BffSession = {
      id: base64url(randomBytes(24)),
      tenant: input.tenant,
      accountId: input.accountId,
      email: input.email,
      management: input.management,
      roles: input.roles,
      isTenantAdmin: input.isTenantAdmin,
      orgs: input.orgs,
      createdAt: now,
      touchedAt: now,
      tokens: input.tokens,
    };
    this.#sessions.set(session.id, session);
    return session;
  }

  /** The live session for an id, or `undefined` when unknown or past its TTL. */
  get(id: string | undefined): BffSession | undefined {
    if (id === undefined) return undefined;
    const session = this.#sessions.get(id);
    if (session === undefined) return undefined;
    // `>=` so a TTL of 0 means "born expired"; at exactly the TTL age the session is gone.
    if (Date.now() - session.touchedAt >= this.#ttlMs) {
      this.#sessions.delete(id);
      return undefined;
    }
    session.touchedAt = Date.now();
    return session;
  }

  destroy(id: string | undefined): void {
    if (id === undefined) return;
    this.#sessions.delete(id);
  }

  /** Drop expired tickets and sessions; runs on a timer and on demand. */
  sweep(): void {
    const now = Date.now();
    for (const [state, ticket] of this.#tickets) {
      if (now - ticket.createdAt > TICKET_TTL_MS) this.#tickets.delete(state);
    }
    for (const [id, session] of this.#sessions) {
      if (now - session.touchedAt >= this.#ttlMs) this.#sessions.delete(id);
    }
  }

  startSweep(): void {
    this.#sweeper ??= setInterval(() => this.sweep(), SWEEP_INTERVAL_MS).unref();
  }

  stopSweep(): void {
    if (this.#sweeper !== undefined) clearInterval(this.#sweeper);
    this.#sweeper = undefined;
  }

  get size(): number {
    return this.#sessions.size;
  }
}

// ---------------------------------------------------------------------------
// cookie helpers
// ---------------------------------------------------------------------------

export interface CookieOptions {
  readonly name: string;
  readonly value: string;
  readonly maxAgeSecs: number;
  readonly secure: boolean;
}

export function serializeSessionCookie(options: CookieOptions): string {
  const parts = [
    `${options.name}=${options.value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.max(0, Math.floor(options.maxAgeSecs))}`,
  ];
  if (options.secure) parts.push("Secure");
  return parts.join("; ");
}

export function clearSessionCookie(name: string, secure: boolean): string {
  const parts = [`${name}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

/** Reads a cookie value out of a `Cookie` header without pulling in a parser. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (header === undefined) return undefined;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    return part.slice(separator + 1).trim();
  }
  return undefined;
}

/**
 * Constant-time comparison for the internal secret the gateway sends upstream. The server
 * performs the authoritative check (§6.3); this keeps the gateway's own copy honest.
 */
export function secretsMatch(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
