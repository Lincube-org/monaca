import { newId } from "@/lib/typed-id";
import { jwkThumbprintHex, publicEcJwk } from "@monaca/ui";

import { ApiError, type MonacaApi } from "./contract";
import {
  DEFAULT_ORG,
  TENANT,
  appendToChain,
  buildAgents,
  buildAuditLog,
  buildGrants,
  seedAccounts,
  seedMembers,
  verifyLog,
  type AuditLog,
} from "./fixtures";
import type {
  AddMemberRequest,
  Agent,
  AuditEvent,
  AuditIntegrity,
  CreateAgentRequest,
  CreateGrantRequest,
  CreateOrganizationRequest,
  Grant,
  ListAuditQuery,
  Member,
  Organization,
  Page,
  RegisterAgentKeyRequest,
  SessionInfo,
  UpdateOrganizationRequest,
} from "./types";

/**
 * Stage-0 mock layer.
 *
 * It implements `MonacaApi` exactly, so swapping `VITE_USE_MOCKS` moves every page from fixtures to
 * the gateway with no page-level change. Two rules keep it honest rather than merely convenient:
 *
 * - **State lives in the store, not in the response.** Creating an agent really appends to the
 *   agent list and to the audit chain, so a page that lists after writing sees its own write, and
 *   the Audit page shows `agent.created` for the agent the user just made. A mock that returns a
 *   fabricated object and forgets it hides exactly the bugs this layer exists to surface.
 * - **Server rules are enforced where a page could observe them.** The RFC 7638 fingerprint and the
 *   private-key rejection (§6.2, `MONACA_PRIVATE_KEY_SUBMITTED`) are checked here, so the register
 *   flow exercises the real validation before a server exists to do it.
 *
 * Latency is simulated: without it, loading and pending states are dead code in development and
 * only ever run for the first time against a real server.
 */

class MockStore {
  private accounts = seedAccounts();
  private organizations: Organization[] = seedOrganizations();
  private members: Member[] = seedMembers(this.accounts);
  private agents: Agent[] = buildAgents(this.accounts);
  private grants: Grant[] = buildGrants(this.agents, this.accounts);
  private log: AuditLog | null = null;
  /**
   * The fixture is a ~130-link hash chain, and every link costs a canonicalize plus a sha256, so it
   * must be built exactly once per tab. One store instance is created at module scope and this
   * promise is created in its constructor; `auditSeeds` is available separately for a caller that
   * needs the narrative without paying for the hashing.
   */
  private readonly ready: Promise<void>;

  constructor() {
    this.ready = buildAuditLog(this.accounts, this.agents, this.grants).then((log) => {
      this.log = log;
    });
  }

  private async audit(): Promise<AuditLog> {
    await this.ready;
    if (!this.log) throw new Error("mock audit log failed to build");
    return this.log;
  }

  session(): SessionInfo {
    const admin = this.accounts[0];
    if (!admin) throw new Error("mock store has no accounts");
    return {
      authenticated: true,
      account_id: admin.id,
      email: admin.email,
      tenant: TENANT,
      orgs: [{ slug: DEFAULT_ORG, role: "owner" }],
    };
  }

  listOrganizations(): Page<Organization> {
    return { items: this.organizations.map((org) => ({ ...org })), next: null };
  }

  async createOrganization(body: CreateOrganizationRequest): Promise<Organization> {
    const slug = body.slug.trim();
    // §6.2's slug rule, enforced here so the console never learns it from a 400 in production.
    if (!/^[a-z0-9][a-z0-9-]{1,30}$/.test(slug)) {
      throw new ApiError("A slug is 2–31 lowercase letters, digits or dashes", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (this.organizations.some((org) => org.slug === slug)) {
      throw new ApiError(`An organization with the slug ${slug} already exists`, {
        status: 409,
        code: "MONACA_ORG_EXISTS",
      });
    }

    const org: Organization = {
      id: newId("org"),
      slug,
      state: "active",
      is_default: false,
      created_at: new Date().toISOString(),
    };
    this.organizations = [...this.organizations, org];
    await this.append({
      action: "org.created",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: org.id,
      decision: "info",
      payload: { slug: org.slug, is_default: org.is_default },
    });
    return { ...org };
  }

  async updateOrganization(
    organizationId: string,
    body: UpdateOrganizationRequest,
  ): Promise<Organization> {
    const index = this.organizations.findIndex(
      (candidate) => candidate.id === organizationId || candidate.slug === organizationId,
    );
    const org = this.organizations[index];
    if (!org) {
      throw new ApiError("No such organization in this tenant", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    if (org.state === body.state) return { ...org };
    if (body.state === "archived" && org.is_default) {
      throw new ApiError("The tenant's default organization cannot be archived", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    const updated: Organization = { ...org, state: body.state };
    this.organizations = [
      ...this.organizations.slice(0, index),
      updated,
      ...this.organizations.slice(index + 1),
    ];
    await this.append({
      action: body.state === "archived" ? "org.archived" : "org.reactivated",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: org.id,
      decision: "info",
      payload: { slug: org.slug, state: body.state },
    });
    return { ...updated };
  }

  listMembers(): Page<Member> {
    return { items: [...this.members], next: null };
  }

  async addMember(body: AddMemberRequest): Promise<Member> {
    const account = this.accounts.find((candidate) => candidate.id === body.account_id);
    if (!account) {
      throw new ApiError("No account with that id exists in this tenant", {
        status: 404,
        code: "MONACA_ACCOUNT_NOT_FOUND",
      });
    }
    if (this.members.some((member) => member.account_id === body.account_id)) {
      throw new ApiError("That account is already a member of this organization", {
        status: 409,
        code: "MONACA_MEMBER_EXISTS",
      });
    }
    const member: Member = { account_id: account.id, email: account.email, role: body.role };
    this.members = [...this.members, member];
    await this.append({
      action: "org.member.added",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: account.id,
      decision: "info",
      payload: { role: body.role, org: DEFAULT_ORG },
    });
    return member;
  }

  listAgents(): Page<Agent> {
    return { items: this.agents.map(cloneAgent), next: null };
  }

  async createAgent(body: CreateAgentRequest): Promise<Agent> {
    if (this.agents.some((agent) => agent.name === body.name)) {
      throw new ApiError(`An agent named ${body.name} already exists`, {
        status: 409,
        code: "MONACA_AGENT_NAME_TAKEN",
      });
    }
    if (!this.members.some((member) => member.account_id === body.owner_account_id)) {
      throw new ApiError("The owner account is not a member of this organization", {
        status: 400,
        code: "MONACA_OWNER_NOT_MEMBER",
      });
    }

    const agent: Agent = {
      id: newId("agt"),
      org: DEFAULT_ORG,
      name: body.name,
      description: body.description,
      owner_account_id: body.owner_account_id,
      state: "active",
      keys: [],
      created_at: new Date().toISOString(),
    };
    this.agents = [...this.agents, agent];
    await this.append({
      action: "agent.created",
      actor: this.session().account_id,
      subjectType: "agent",
      subjectId: agent.id,
      decision: "info",
      payload: { name: agent.name, owner_account_id: agent.owner_account_id },
    });
    return cloneAgent(agent);
  }

  async registerAgentKey(agentId: string, body: RegisterAgentKeyRequest): Promise<Agent> {
    const index = this.agents.findIndex((agent) => agent.id === agentId);
    const agent = this.agents[index];
    if (!agent) {
      throw new ApiError("No such agent in this organization", { status: 404, code: "MONACA_AGENT_NOT_FOUND" });
    }

    // §6.2: a JWK carrying a private component is rejected outright, so a careless client can never
    // leak a private key into the database. Enforced here too — the console must never be the thing
    // that discovers this rule in production.
    if ("d" in body.public_jwk && body.public_jwk.d) {
      throw new ApiError("The submitted JWK contains a private key", {
        status: 400,
        code: "MONACA_PRIVATE_KEY_SUBMITTED",
      });
    }
    if (body.public_jwk.kty !== "EC" || body.public_jwk.crv !== "P-256") {
      throw new ApiError("The public key must be an EC P-256 key", {
        status: 400,
        code: "MONACA_INVALID_PUBLIC_KEY",
      });
    }
    if (agent.keys.some((key) => key.kid === body.kid && key.revoked_at === null)) {
      throw new ApiError(`Key id ${body.kid} is already registered for this agent`, {
        status: 409,
        code: "MONACA_KEY_ID_TAKEN",
      });
    }

    const publicJwk = publicEcJwk(body.public_jwk);
    const fingerprint = await jwkThumbprintHex(publicJwk);
    const key = {
      id: newId("akey"),
      kid: body.kid,
      fingerprint,
      created_at: new Date().toISOString(),
      revoked_at: null,
    };
    const updated: Agent = { ...agent, keys: [...agent.keys, key] };
    this.agents = [...this.agents.slice(0, index), updated, ...this.agents.slice(index + 1)];

    await this.append({
      action: "agent.key.registered",
      actor: this.session().account_id,
      subjectType: "agent_key",
      subjectId: key.id,
      decision: "info",
      payload: { agent_id: agent.id, kid: key.kid, alg: body.alg, fingerprint },
      grantId: null,
    });
    return cloneAgent(updated);
  }

  async revokeAgentKey(agentId: string, keyId: string): Promise<void> {
    const index = this.agents.findIndex((agent) => agent.id === agentId);
    const agent = this.agents[index];
    if (!agent) {
      throw new ApiError("No such agent in this organization", { status: 404, code: "MONACA_AGENT_NOT_FOUND" });
    }
    const keyIndex = agent.keys.findIndex((key) => key.id === keyId);
    const key = agent.keys[keyIndex];
    if (!key) {
      throw new ApiError("No such key for this agent", { status: 404, code: "MONACA_KEY_NOT_FOUND" });
    }
    if (key.revoked_at !== null) return; // idempotent, as a DELETE should be

    const keys = [...agent.keys];
    keys[keyIndex] = { ...key, revoked_at: new Date().toISOString() };
    const updated: Agent = { ...agent, keys };
    this.agents = [...this.agents.slice(0, index), updated, ...this.agents.slice(index + 1)];

    await this.append({
      action: "agent.key.revoked",
      actor: this.session().account_id,
      subjectType: "agent_key",
      subjectId: key.id,
      decision: "info",
      payload: { agent_id: agent.id, kid: key.kid },
      grantId: null,
    });
  }

  listGrants(): Page<Grant> {
    return { items: this.grants.map((grant) => ({ ...grant })), next: null };
  }

  async createGrant(body: CreateGrantRequest): Promise<Grant> {
    const agent = this.agents.find((candidate) => candidate.id === body.agent_id);
    if (!agent) {
      throw new ApiError("No such agent in this organization", { status: 404, code: "MONACA_AGENT_NOT_FOUND" });
    }
    if (!this.members.some((member) => member.account_id === body.account_id)) {
      throw new ApiError("The delegating account is not a member of this organization", {
        status: 400,
        code: "MONACA_DELEGATOR_NOT_MEMBER",
      });
    }

    const grant: Grant = {
      id: newId("grt"),
      org: DEFAULT_ORG,
      agent_id: body.agent_id,
      account_id: body.account_id,
      scopes: [...body.scopes],
      resource: body.resource,
      constraints: {},
      expires_at: body.expires_at,
      revoked_at: null,
      created_by: this.session().account_id,
      created_at: new Date().toISOString(),
    };
    this.grants = [...this.grants, grant];
    await this.append({
      action: "grant.created",
      actor: grant.created_by,
      subjectType: "grant",
      subjectId: grant.id,
      decision: "info",
      payload: { scopes: grant.scopes, resource: grant.resource, agent_id: grant.agent_id },
      grantId: grant.id,
    });
    return { ...grant };
  }

  async revokeGrant(grantId: string): Promise<void> {
    const index = this.grants.findIndex((grant) => grant.id === grantId);
    const grant = this.grants[index];
    if (!grant) {
      throw new ApiError("No such grant in this organization", { status: 404, code: "MONACA_GRANT_NOT_FOUND" });
    }
    if (grant.revoked_at !== null) return;

    const updated: Grant = { ...grant, revoked_at: new Date().toISOString() };
    this.grants = [...this.grants.slice(0, index), updated, ...this.grants.slice(index + 1)];
    await this.append({
      action: "grant.revoked",
      actor: this.session().account_id,
      subjectType: "grant",
      subjectId: grant.id,
      decision: "info",
      payload: { agent_id: grant.agent_id },
      grantId: grant.id,
    });
  }

  async listAudit(params: ListAuditQuery = {}): Promise<Page<AuditEvent>> {
    const log = await this.audit();
    // Newest first, as the API orders it (`audit_events_at_idx` is DESC).
    let items = [...log.events].reverse();

    if (params.grant_id) items = items.filter((event) => event.grant_id === params.grant_id);
    if (params.jti) items = items.filter((event) => event.jti === params.jti);
    if (params.action) items = items.filter((event) => event.action === params.action);
    if (params.before !== undefined) items = items.filter((event) => event.seq < params.before!);

    const limit = Math.min(params.limit ?? 50, 200);
    const page = items.slice(0, limit);
    const next = items.length > limit ? String(page.at(-1)?.seq ?? 0) : null;
    return { items: page.map((event) => ({ ...event })), next };
  }

  async verifyAudit(): Promise<AuditIntegrity> {
    const log = await this.audit();
    return verifyLog(log);
  }

  /** Append to the chain, so every mock write is visible on the Audit page immediately. */
  private async append(seed: {
    action: string;
    actor: string;
    subjectType: AuditEvent["subject"]["type"];
    subjectId: string;
    decision: AuditEvent["decision"];
    payload: Record<string, unknown>;
    grantId?: string | null;
  }): Promise<void> {
    const log = await this.audit();
    await appendToChain(log, {
      id: newId("evt"),
      at: new Date().toISOString(),
      action: seed.action,
      actor_chain: [{ type: "account", id: seed.actor }],
      subject: { type: seed.subjectType, id: seed.subjectId },
      decision: seed.decision,
      grant_id: seed.grantId ?? null,
      jti: null,
      payload: seed.payload,
    });
  }
}

function cloneAgent(agent: Agent): Agent {
  return { ...agent, keys: agent.keys.map((key) => ({ ...key })) };
}

/** The tenant starts with the single default org the session signs into. */
function seedOrganizations(): Organization[] {
  return [
    {
      id: newId("org"),
      slug: DEFAULT_ORG,
      state: "active",
      is_default: true,
      created_at: new Date().toISOString(),
    },
  ];
}

/** One store per tab. Module scope, so navigating between pages keeps writes. */
const store = new MockStore();

export const mockApi: MonacaApi = {
  async getSession() {
    await delay();
    return store.session();
  },
  async listOrganizations() {
    await delay();
    return store.listOrganizations();
  },
  async createOrganization(body) {
    await delay();
    return store.createOrganization(body);
  },
  async updateOrganization(organizationId, body) {
    await delay();
    return store.updateOrganization(organizationId, body);
  },
  async listMembers() {
    await delay();
    return store.listMembers();
  },
  async addMember(_org, body) {
    await delay();
    return store.addMember(body);
  },
  async listAgents() {
    await delay();
    return store.listAgents();
  },
  async createAgent(_org, body) {
    await delay();
    return store.createAgent(body);
  },
  async registerAgentKey(_org, agentId, body) {
    await delay();
    return store.registerAgentKey(agentId, body);
  },
  async revokeAgentKey(_org, agentId, keyId) {
    await delay();
    return store.revokeAgentKey(agentId, keyId);
  },
  async listGrants() {
    await delay();
    return store.listGrants();
  },
  async createGrant(_org, body) {
    await delay();
    return store.createGrant(body);
  },
  async revokeGrant(_org, grantId) {
    await delay();
    return store.revokeGrant(grantId);
  },
  async listAudit(_org, query) {
    await delay();
    return store.listAudit(query);
  },
  async verifyAudit() {
    // Verification is real work: 100+ sha256 over canonical JSON. A little longer than the
    // other calls, but not so long that the button feels broken.
    await delay(420);
    return store.verifyAudit();
  },
};

/**
 * Simulated latency. Without it, loading and pending states are dead code in development and only
 * ever execute for the first time against a real server.
 *
 * Tests set it to 0 through `setMockLatency`: a suite that spends twenty seconds asleep is a suite
 * nobody runs.
 */
let latencyMs = 180;

export function setMockLatency(ms: number): void {
  latencyMs = ms;
}

function delay(ms = latencyMs): Promise<void> {
  return ms === 0 ? Promise.resolve() : new Promise((resolve) => setTimeout(resolve, ms));
}
