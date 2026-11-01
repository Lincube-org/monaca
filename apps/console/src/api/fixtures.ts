import { GENESIS_HASH, chainHash } from "@/lib/jcs";
import { newId, typedId, uuidv7 } from "@/lib/typed-id";

import type {
  Account,
  AccountSession,
  Agent,
  AgentKey,
  ApiResource,
  AuditActor,
  AuditEvent,
  AuditIntegrity,
  Client,
  Connector,
  Grant,
  Member,
  OrgRole,
  OrgRoleDetail,
  SignInExperience,
  SsoConnector,
  TenantRole,
} from "./types";

/**
 * The seeded tenant.
 *
 * Everything here is derived from docs/contracts/m0.md §5.7's bootstrap rows: tenant `demo`, org
 * `acme` as its default org, and the admin account at `admin@demo.localhost`. The extra members,
 * agents and grants are fixtures the pages need to look like a working product rather than an
 * empty shell.
 *
 * The audit trail is not hand-written. It is built by appending through the same
 * `chainHash(prev, event)` the server uses (§8.2), so the fixtures' chain really does verify and
 * the Audit page is exercising the real thing. A fabricated `hash` column would make the page a
 * lie the moment anyone clicked "verify".
 */

export const TENANT = "demo";
export const DEFAULT_ORG = "acme";

/** A fixed RNG so fixtures are identical on every reload and screenshots are reproducible. */
function mulberry32(seed: number): () => number {
  let state = seed;
  return () => {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(0x5ca1ab1e);

function pick<T>(items: readonly T[]): T {
  const item = items[Math.floor(rand() * items.length)];
  if (item === undefined) throw new Error("pick from an empty list");
  return item;
}

const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;

/** Fixture time base. Events are spread backwards from "now" so the timeline always looks live. */
const BASE = Date.now();

function at(minutesAgo: number): string {
  return new Date(BASE - minutesAgo * MINUTE_MS).toISOString();
}

// ---------------------------------------------------------------------------------------------
// Accounts and membership
// ---------------------------------------------------------------------------------------------

export function seedAccounts(): Account[] {
  return [
    {
      id: newId("acc", BASE - 900 * HOUR_MS),
      email: "admin@demo.localhost",
      display_name: "Demo Admin",
      state: "active",
      created_at: at(900 * 60),
    },
    {
      id: newId("acc", BASE - 720 * HOUR_MS),
      email: "wei.zhang@demo.localhost",
      display_name: "Wei Zhang",
      state: "active",
      created_at: at(720 * 60),
    },
    {
      id: newId("acc", BASE - 500 * HOUR_MS),
      email: "priya.raman@demo.localhost",
      display_name: "Priya Raman",
      state: "active",
      created_at: at(500 * 60),
    },
    {
      id: newId("acc", BASE - 200 * HOUR_MS),
      email: "sam.oduya@demo.localhost",
      display_name: "Sam Oduya",
      state: "active",
      created_at: at(200 * 60),
    },
    {
      id: newId("acc", BASE - 40 * HOUR_MS),
      email: "intern@demo.localhost",
      display_name: "Ravi Menon",
      state: "disabled",
      created_at: at(40 * 60),
    },
  ];
}

export function seedMembers(accounts: readonly Account[]): Member[] {
  const roles: OrgRole[] = ["owner", "admin", "admin", "member", "member"];
  return accounts.map((account, index) => ({
    account_id: account.id,
    email: account.email,
    role: roles[index] ?? "member",
  }));
}

// ---------------------------------------------------------------------------------------------
// Sign-in sessions
// ---------------------------------------------------------------------------------------------

interface SessionSpec {
  account: number;
  client: number | null;
  /** Minutes ago the session was issued. */
  issued: number;
  /** Minutes ago an authorize request last reused it. */
  lastSeen: number;
  /** Session lifetime in minutes, measured from issuance. */
  ttl: number;
  userAgent: string | null;
}

/**
 * Live sessions on a few seeded accounts.
 *
 * The shapes are the ones an administrator actually investigates: one user with a current browser
 * plus an older service session, one user whose only session is stale, and a suspended user with
 * none — suspension revokes sessions, so a fixture that kept them would contradict the console.
 */
export function buildSessions(
  accounts: readonly Account[],
  clients: readonly Client[],
): AccountSession[] {
  const specs: SessionSpec[] = [
    {
      account: 0,
      client: 0,
      issued: 3 * 24 * 60,
      lastSeen: 20,
      ttl: 30 * 24 * 60,
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    },
    {
      account: 0,
      client: 1,
      issued: 26 * 60,
      lastSeen: 110,
      ttl: 30 * 24 * 60,
      userAgent: "monaca-notes/1.4 (+https://notes.demo.localhost)",
    },
    {
      account: 1,
      client: 0,
      issued: 12 * 24 * 60,
      lastSeen: 12 * 60,
      ttl: 30 * 24 * 60,
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    },
    {
      account: 3,
      client: 2,
      issued: 6 * 60,
      lastSeen: 6 * 60,
      ttl: 30 * 24 * 60,
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/133.0 Safari/537.36",
    },
  ];

  return specs.map((spec) => {
    const account = accounts[spec.account];
    const client = spec.client === null ? null : clients[spec.client]?.id ?? null;
    if (!account) throw new Error(`fixture session names a missing account: ${spec.account}`);
    return {
      id: newId("ses"),
      account_id: account.id,
      client_id: client,
      issued_at: at(spec.issued),
      expires_at: at(spec.issued - spec.ttl),
      last_seen_at: at(spec.lastSeen),
      user_agent: spec.userAgent,
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Organization email domains
// ---------------------------------------------------------------------------------------------

/** A domain entry as the mock stores it; the wire shape drops `org`. */
export interface SeededEmailDomain {
  org: string;
  domain: string;
  created_at: string;
}

/**
 * The demo tenant's own domain.
 *
 * Every seeded account is at `demo.localhost`, so this is the one domain that would admit the demo
 * directory just in time at sign-in — registered the way an admin would have registered it.
 */
export function seedEmailDomains(): SeededEmailDomain[] {
  return [{ org: DEFAULT_ORG, domain: "demo.localhost", created_at: at(895 * 60) }];
}

// ---------------------------------------------------------------------------------------------
// Organization invitations
// ---------------------------------------------------------------------------------------------

export interface SeededOrgInvitation {
  org: string;
  id: string;
  email: string;
  role: OrgRole;
  invited_by: string | null;
  created_at: string;
  expires_at: string;
}

/** A timestamp `days` after the fixture base, so seeded expiry looks live on every reload. */
function expiresIn(days: number): string {
  return new Date(BASE + days * 24 * HOUR_MS).toISOString();
}

/**
 * One pending invitation, so the Members page has the state an administrator actually sees between
 * sending an invitation and the invitee's next sign-in.
 */
export function seedOrgInvitations(): SeededOrgInvitation[] {
  return [
    {
      org: DEFAULT_ORG,
      id: newId("inv", BASE - 180 * 60_000),
      email: "new-teammate@demo.localhost",
      role: "member",
      invited_by: null,
      created_at: at(180 * 60),
      expires_at: expiresIn(4),
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Tenant roles
// ---------------------------------------------------------------------------------------------

/**
 * Roles that apply in every organization, as opposed to the org roles below.
 *
 * Two shapes an administrator distinguishes: a read-only role for people (and agents) who inspect
 * work, and one that may also change it. The names are what the id_token's `roles` claim carries.
 */
export function seedTenantRoles(): TenantRole[] {
  return [
    {
      id: newId("rol", BASE - 340 * HOUR_MS),
      name: "viewer",
      description: "Read-only access to the tenant's tools.",
      permissions: ["tools:read"],
      created_at: at(340 * 60),
    },
    {
      id: newId("rol", BASE - 280 * HOUR_MS),
      name: "contributor",
      description: "Read and write access to the tenant's tools.",
      permissions: ["tools:read", "tools:write"],
      created_at: at(280 * 60),
    },
  ];
}

/** Which seeded account holds which seeded tenant role, by account index. */
export function seedAccountRoleIndexes(): Record<number, number[]> {
  return { 0: [1], 1: [0], 4: [0] };
}

// ---------------------------------------------------------------------------------------------
// Organization roles
// ---------------------------------------------------------------------------------------------

/**
 * Roles defined inside the demo org.
 *
 * Names and scope sets are deliberately operational rather than decorative: `support` can read
 * tools, `release-manager` can also write, and `auditor` is read-only — the three shapes an
 * administrator distinguishes when reading a role table.
 */
export function seedOrgRoles(): OrgRoleDetail[] {
  return [
    {
      id: newId("rol", BASE - 300 * HOUR_MS),
      name: "support",
      description: "Read tool results and ticket data during the support rotation.",
      scopes: ["tools:read"],
      created_at: at(300 * 60),
    },
    {
      id: newId("rol", BASE - 240 * HOUR_MS),
      name: "release-manager",
      description: "Read and write build and release data.",
      scopes: ["tools:read", "tools:write"],
      created_at: at(240 * 60),
    },
    {
      id: newId("rol", BASE - 120 * HOUR_MS),
      name: "auditor",
      description: "Read-only access for compliance reviews.",
      scopes: ["tools:read"],
      created_at: at(120 * 60),
    },
  ];
}

/**
 * Which seeded account holds which seeded role, by account index.
 *
 * Kept out of the account fixture so the two concerns stay separate: an account exists whether or
 * not it has been granted anything.
 */
export function seedMemberRoleIndexes(): Record<number, number[]> {
  return { 1: [0], 2: [1], 3: [2] };
}

// ---------------------------------------------------------------------------------------------
// API resources
// ---------------------------------------------------------------------------------------------

/**
 * The same indicator the seeded grants point at, plus a second audience.
 *
 * A grant without a registered resource could not have been issued a custom scope by `authorize`,
 * so the demo tenant registers the resource its grants name.
 */
export function seedResources(): ApiResource[] {
  return [
    {
      id: newId("res", BASE - 700 * HOUR_MS),
      name: "Demo MCP server",
      identifier: DEMO_RESOURCE,
      scopes: ["tools:read", "tools:write"],
      created_at: at(700 * 60),
    },
    {
      id: newId("res", BASE - 420 * HOUR_MS),
      name: "Notes API",
      identifier: "https://api.demo.localhost",
      scopes: ["notes:read", "notes:write"],
      created_at: at(420 * 60),
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Social connectors
// ---------------------------------------------------------------------------------------------

/**
 * Two providers with the shapes a real tenant registers: GitHub's non-OIDC userinfo endpoint and
 * Google's OIDC discovery equivalents. No secret is part of the fixture because the API never
 * returns one.
 */
export function seedConnectors(): Connector[] {
  return [
    {
      connector_id: "github",
      display_name: "GitHub",
      authorize_url: "https://github.com/login/oauth/authorize",
      token_url: "https://github.com/login/oauth/access_token",
      userinfo_url: "https://api.github.com/user",
      client_id: "demo-github-client",
      scopes: ["read:user", "user:email"],
      created_at: at(600 * 60),
    },
    {
      connector_id: "google",
      display_name: "Google",
      authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
      client_id: "demo-google-client",
      scopes: ["openid", "profile", "email"],
      created_at: at(360 * 60),
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Enterprise SSO
// ---------------------------------------------------------------------------------------------

/**
 * One federated identity provider.
 *
 * The demo tenant's accounts are at `demo.localhost`, so the seeded connector owns a separate
 * partner domain: the sign-in page routes any address there to the provider instead of the password
 * form, and the demo directory keeps its ordinary sign-in.
 */
export function seedSsoConnectors(): SsoConnector[] {
  return [
    {
      connector_id: "partner-oidc",
      display_name: "Partner OIDC",
      issuer: "https://idp.partner.example",
      authorize_url: "https://idp.partner.example/oauth2/authorize",
      token_url: "https://idp.partner.example/oauth2/token",
      userinfo_url: "https://idp.partner.example/oauth2/userinfo",
      client_id: "demo-partner-client",
      scopes: ["openid", "profile", "email"],
      email_domains: ["partner.example"],
      created_at: at(300 * 60),
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Sign-in experience
// ---------------------------------------------------------------------------------------------

/**
 * The hosted sign-in switches as the migration seeds them: every method on.
 *
 * `updated_at` is the tenant's provisioning time, not "now" — a freshly provisioned tenant has not
 * been configured yet, and the page should be able to say how long the switches have stood.
 */
export function seedSignInExperience(): SignInExperience {
  return {
    sign_up_enabled: true,
    password_sign_in_enabled: true,
    email_code_sign_in_enabled: true,
    updated_at: at(900 * 60),
  };
}

// ---------------------------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------------------------

/**
 * The tenant's applications.
 *
 * Three shapes an administrator actually meets: a first-party browser app (public, PKCE only), a
 * server-side integration (confidential, secret held by the backend) and a partner app the consent
 * screen must annotate as third-party. Together they exercise every column the page renders.
 */
export function seedClients(): Client[] {
  return [
    {
      id: newId("cli", BASE - 880 * HOUR_MS),
      client_id: "admin-console",
      name: "Admin console",
      kind: "public",
      token_auth_method: "none",
      scopes: ["openid", "profile", "email"],
      redirect_uris: ["https://console.demo.localhost/callback"],
      post_logout_redirect_uris: ["https://console.demo.localhost/"],
      is_third_party: false,
      created_at: at(880 * 60),
    },
    {
      id: newId("cli", BASE - 640 * HOUR_MS),
      client_id: "notes-service",
      name: "Notes service",
      kind: "confidential",
      token_auth_method: "client_secret_basic",
      scopes: ["openid", "tools:read"],
      redirect_uris: ["https://notes.demo.localhost/oauth/callback"],
      post_logout_redirect_uris: [],
      is_third_party: false,
      created_at: at(640 * 60),
    },
    {
      id: newId("cli", BASE - 120 * HOUR_MS),
      client_id: "partner-portal",
      name: "Partner portal",
      kind: "public",
      token_auth_method: "none",
      scopes: ["openid", "profile"],
      redirect_uris: ["https://partner.example.com/sso/callback"],
      post_logout_redirect_uris: ["https://partner.example.com/signed-out"],
      is_third_party: true,
      created_at: at(120 * 60),
    },
  ];
}

// ---------------------------------------------------------------------------------------------
// Agents and keys
// ---------------------------------------------------------------------------------------------

export interface SeedAgent {
  agent: Agent;
  /** The owner account's index into `accounts`; resolved by the caller. */
  ownerIndex: number;
}

export function seedAgentSpecs(): { name: string; description: string; ownerIndex: number }[] {
  return [
    { name: "ci-bot", description: "Runs the release pipeline and reads build notes.", ownerIndex: 1 },
    { name: "release-bot", description: "Tags releases and writes changelog entries.", ownerIndex: 0 },
    { name: "support-copilot", description: "Summarises tickets for the support rotation.", ownerIndex: 2 },
    { name: "notes-indexer", description: "Keeps the demo note store indexed.", ownerIndex: 3 },
  ];
}

/**
 * A registered key. The `fingerprint` here is a fixture value, not a real thumbprint of a real key
 * — the console computes real ones when it generates a pair. Marked so nobody mistakes it for one.
 */
export function seedKeys(agentIndex: number, createdAt: string): AgentKey[] {
  const keys: AgentKey[] = [
    {
      id: newId("akey", BASE - (agentIndex + 1) * 30 * HOUR_MS),
      kid: `k${agentIndex + 1}`,
      fingerprint: syntheticFingerprint(agentIndex * 2),
      created_at: createdAt,
      revoked_at: null,
    },
  ];
  // One agent carries a rotated-out key so the revoked state is visible in the UI.
  if (agentIndex === 1) {
    keys.push({
      id: newId("akey", BASE - (agentIndex + 1) * 30 * HOUR_MS - 1000),
      kid: "k1-old",
      fingerprint: syntheticFingerprint(agentIndex * 2 + 1),
      created_at: at(700 * 60),
      revoked_at: at(60 * 60),
    });
  }
  return keys;
}

function syntheticFingerprint(seed: number): string {
  const local = mulberry32(0xf00d + seed);
  let out = "";
  for (let index = 0; index < 64; index += 1) out += Math.floor(local() * 16).toString(16);
  return out;
}

export function buildAgents(accounts: readonly Account[]): Agent[] {
  return seedAgentSpecs().map((spec, index) => {
    const createdAt = at((spec.ownerIndex + 1) * 40 * 60 - index * 17);
    const owner = accounts[spec.ownerIndex];
    if (!owner) throw new Error(`fixture agent ${spec.name} has no owner account`);
    return {
      id: newId("agt", BASE - (index + 1) * 20 * HOUR_MS),
      org: DEFAULT_ORG,
      name: spec.name,
      description: spec.description,
      owner_account_id: owner.id,
      state: index === 3 ? "disabled" : "active",
      keys: seedKeys(index, createdAt),
      created_at: createdAt,
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------------------------

export const DEMO_RESOURCE = "http://localhost:8080/mcp/demo";

export function buildGrants(agents: readonly Agent[], accounts: readonly Account[]): Grant[] {
  const createdBy = accounts[0];
  if (!createdBy) throw new Error("fixture grants need an admin account");

  const specs: { agent: number; scopes: string[]; expires: number | null; revoked: boolean }[] = [
    { agent: 0, scopes: ["tools:read", "tools:write"], expires: null, revoked: false },
    { agent: 1, scopes: ["tools:read"], expires: null, revoked: false },
    { agent: 2, scopes: ["tools:read"], expires: 72 * 60, revoked: false },
    { agent: 3, scopes: ["tools:read"], expires: null, revoked: true },
    { agent: 0, scopes: ["tools:write"], expires: -1, revoked: false },
  ];

  return specs.map((spec, index) => {
    const agent = agents[spec.agent];
    if (!agent) throw new Error(`fixture grant ${index} names a missing agent`);
    return {
      id: newId("grt", BASE - (index + 1) * 10 * HOUR_MS),
      org: DEFAULT_ORG,
      agent_id: agent.id,
      account_id: agent.owner_account_id,
      scopes: spec.scopes,
      resource: DEMO_RESOURCE,
      constraints: {},
      expires_at: spec.expires === null ? null : at(-spec.expires),
      revoked_at: spec.revoked ? at(90) : null,
      created_by: createdBy.id,
      created_at: at((index + 1) * 10 * 60),
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------------------------

export interface AuditHead {
  seq: number;
  hash: string;
}

export interface AuditLog {
  events: AuditEvent[];
  head: AuditHead;
}

export interface AuditSeed {
  id: string;
  at: string;
  action: string;
  actor_chain: AuditActor[];
  subject: { type: AuditEvent["subject"]["type"]; id: string };
  decision: AuditEvent["decision"];
  grant_id: string | null;
  jti: string | null;
  payload: Record<string, unknown>;
}

/**
 * Append an event to a chain, computing `seq`, `prev_hash` and `hash` exactly as §8.3 describes.
 * The three chain fields are excluded from the canonical bytes (§8.2), which is why the hashed
 * object is built explicitly rather than by stripping keys off the stored row.
 */
export async function appendToChain(log: AuditLog, seed: AuditSeed): Promise<AuditEvent> {
  const seq = log.head.seq + 1;
  const event: AuditEvent = {
    seq,
    id: seed.id,
    at: seed.at,
    action: seed.action,
    actor_chain: seed.actor_chain,
    subject: seed.subject,
    decision: seed.decision,
    grant_id: seed.grant_id,
    jti: seed.jti,
    payload: seed.payload,
    prev_hash: log.head.hash,
    hash: "",
  };

  event.hash = await chainHash(event.prev_hash, {
    id: event.id,
    at: event.at,
    action: event.action,
    actor_chain: event.actor_chain,
    subject: event.subject,
    decision: event.decision,
    grant_id: event.grant_id,
    jti: event.jti,
    payload: event.payload,
  });

  log.events.push(event);
  log.head = { seq, hash: event.hash };
  return event;
}

/** Rebuild the chain from scratch and check every link — the console-side mirror of §8.4. */
export async function verifyLog(log: AuditLog): Promise<AuditIntegrity> {
  let prev = GENESIS_HASH;
  let checked = 0;

  for (const event of log.events) {
    if (event.prev_hash !== prev) {
      return {
        valid: false,
        checked,
        head: log.head,
        first_broken: { seq: event.seq, expected: prev, actual: event.prev_hash, reason: "prev_hash_mismatch" },
      };
    }
    const expected = await chainHash(prev, {
      id: event.id,
      at: event.at,
      action: event.action,
      actor_chain: event.actor_chain,
      subject: event.subject,
      decision: event.decision,
      grant_id: event.grant_id,
      jti: event.jti,
      payload: event.payload,
    });
    if (expected !== event.hash) {
      return {
        valid: false,
        checked,
        head: log.head,
        first_broken: { seq: event.seq, expected, actual: event.hash, reason: "hash_mismatch" },
      };
    }
    prev = event.hash;
    checked += 1;
  }

  const valid = checked === log.events.length && prev === log.head.hash;
  return {
    valid,
    checked,
    head: log.head,
    first_broken: valid
      ? null
      : { seq: log.head.seq, expected: prev, actual: log.head.hash, reason: "head_mismatch" },
  };
}

/**
 * The narrative as data, before any hashing.
 *
 * Split out from `buildAuditLog` so a caller that only needs counts or a summary does not pay for
 * 130 sha256 over canonical JSON. `buildAuditLog` is the only thing that turns these into a chain.
 */
export function auditSeeds(
  accounts: readonly Account[],
  agents: readonly Agent[],
  grants: readonly Grant[],
): AuditSeed[] {
  const seeds: AuditSeed[] = [];
  const append = (seed: Omit<AuditSeed, "id">): void => {
    seeds.push({ id: newId("evt"), ...seed });
  };

  const admin = accounts[0];
  const ciBot = agents[0];
  const releaseBot = agents[1];
  const copilot = agents[2];
  const indexer = agents[3];
  const grant = grants[0];
  if (!admin || !ciBot || !releaseBot || !copilot || !indexer || !grant) {
    throw new Error("audit fixture is missing a seed row");
  }

  const accountActor = (id: string): AuditActor => ({ type: "account", id });
  const agentActor = (id: string): AuditActor => ({ type: "agent", id });

  // --- The documented lifecycle, in order. -------------------------------------------------
  append({
    at: at(1500),
    action: "account.created",
    actor_chain: [accountActor(admin.id)],
    subject: { type: "account", id: admin.id },
    decision: "info",
    grant_id: null,
    jti: null,
    payload: { email: admin.email },
  });
  append({
    at: at(1440),
    action: "org.member.added",
    actor_chain: [accountActor(admin.id)],
    subject: { type: "org", id: typedId("org", uuidv7(BASE - 900 * HOUR_MS)) },
    decision: "info",
    grant_id: null,
    jti: null,
    payload: { member: accounts[1]?.id ?? admin.id, role: "admin" },
  });
  append({
    at: at(1300),
    action: "agent.created",
    actor_chain: [accountActor(ciBot.owner_account_id)],
    subject: { type: "agent", id: ciBot.id },
    decision: "info",
    grant_id: null,
    jti: null,
    payload: { name: ciBot.name },
  });
  append({
    at: at(1298),
    action: "agent.key.registered",
    actor_chain: [accountActor(ciBot.owner_account_id)],
    subject: { type: "agent_key", id: ciBot.keys[0]?.id ?? ciBot.id },
    decision: "info",
    grant_id: null,
    jti: null,
    payload: { kid: ciBot.keys[0]?.kid ?? "k1", alg: "ES256" },
  });
  append({
    at: at(1290),
    action: "grant.created",
    actor_chain: [accountActor(grant.created_by)],
    subject: { type: "grant", id: grant.id },
    decision: "info",
    grant_id: grant.id,
    jti: null,
    payload: { scopes: grant.scopes, resource: grant.resource, agent_id: grant.agent_id },
  });

  // --- Routine traffic over the last day. --------------------------------------------------
  // Sized for the demo, not for volume. Every link costs a canonicalize plus a digest, and under
  // Bun `crypto.subtle.digest` is ~15 ms per call (a browser is ~0.05 ms), so the fixture is kept to
  // roughly forty events: enough to make the timeline and the counters look like a working product,
  // small enough that a test suite importing this module does not spend ten seconds asleep.
  const scopes = ["tools:read", "tools:write"] as const;
  const tools = ["list_notes", "delete_note"] as const;
  const agentPool = [ciBot, releaseBot, copilot, indexer];

  for (let step = 0; step < 11; step += 1) {
    const minutesAgo = 1100 - step * 90 - Math.floor(rand() * 30);
    const agent = pick(agentPool);
    const actor = grants.find((candidate) => candidate.agent_id === agent.id) ?? grant;
    const scope = pick(scopes);
    const tool = pick(tools);
    const jti = uuidv7(BASE - minutesAgo * MINUTE_MS);

    const deniedByScope = scope === "tools:read" && tool === "delete_note";
    const deniedByGrant = agent.state === "disabled" || actor.revoked_at !== null;

    append({
      at: at(minutesAgo),
      action: "agent.token.requested",
      actor_chain: [accountActor(agent.owner_account_id), agentActor(agent.id)],
      subject: { type: "agent", id: agent.id },
      decision: deniedByGrant ? "deny" : "info",
      grant_id: actor.id,
      jti,
      payload: { requested_scope: [scope], resource: DEMO_RESOURCE },
    });

    if (deniedByGrant) {
      append({
        at: at(minutesAgo - 1),
        action: "agent.token.denied",
        actor_chain: [accountActor(agent.owner_account_id), agentActor(agent.id)],
        subject: { type: "grant", id: actor.id },
        decision: "deny",
        grant_id: actor.id,
        jti,
        payload: { reason: agent.state === "disabled" ? "agent_disabled" : "grant_revoked" },
      });
      continue;
    }

    append({
      at: at(minutesAgo - 1),
      action: "agent.token.issued",
      actor_chain: [accountActor(agent.owner_account_id), agentActor(agent.id)],
      subject: { type: "grant", id: actor.id },
      decision: "allow",
      grant_id: actor.id,
      jti,
      payload: { scope: [scope], aud: DEMO_RESOURCE, exp_secs: 300 },
    });

    append({
      at: at(minutesAgo - 2),
      action: deniedByScope ? "tool.denied" : "tool.invoked",
      actor_chain: [accountActor(agent.owner_account_id), agentActor(agent.id)],
      subject: { type: "tool", id: tool },
      decision: deniedByScope ? "deny" : "allow",
      grant_id: actor.id,
      jti,
      payload: deniedByScope
        ? { required_scope: "tools:write", held_scope: [scope] }
        : { result: "ok", rows: 1 + Math.floor(rand() * 12) },
    });
  }

  // --- Sign-in traffic. --------------------------------------------------------------------
  for (let step = 0; step < 6; step += 1) {
    const account = pick(accounts);
    const failed = rand() < 0.25;
    append({
      at: at(640 - step * 110 - Math.floor(rand() * 20)),
      action: failed ? "interaction.sign_in.failed" : "interaction.sign_in.succeeded",
      actor_chain: [accountActor(account.id)],
      subject: { type: "session", id: newId("ses") },
      decision: failed ? "deny" : "info",
      grant_id: null,
      jti: null,
      payload: failed ? { reason: "invalid_credentials" } : { client_id: "monaca-console" },
    });
  }

  // Oldest first: the chain is appended in order, and `listAudit` reverses for display.
  return seeds.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

/**
 * Turn the seeds into a real hash chain (§8.3).
 *
 * The seeded chain must satisfy the same verifier the UI exposes; a fixture that failed its own
 * check would train the reader to ignore the verdict.
 */
export async function buildAuditLog(
  accounts: readonly Account[],
  agents: readonly Agent[],
  grants: readonly Grant[],
): Promise<AuditLog> {
  const log: AuditLog = { events: [], head: { seq: 0, hash: GENESIS_HASH } };
  for (const seed of auditSeeds(accounts, agents, grants)) await appendToChain(log, seed);

  const report = await verifyLog(log);
  if (!report.valid) {
    throw new Error(`fixture audit chain does not verify: ${JSON.stringify(report.first_broken)}`);
  }
  return log;
}
