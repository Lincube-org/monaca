import { newId } from "@/lib/typed-id";
import { jwkThumbprintHex, isKnownWebhookEvent, publicEcJwk } from "@monaca/ui";

import { ApiError, type MonacaApi } from "./contract";
import {
  DEFAULT_ORG,
  TENANT,
  appendToChain,
  buildAgents,
  buildAuditLog,
  buildGrants,
  buildSessions,
  seedAccounts,
  seedAccountRoleIndexes,
  seedClients,
  seedConnectors,
  seedEmailDomains,
  seedMemberRoleIndexes,
  seedMembers,
  seedOrgInvitations,
  seedOrgRoles,
  seedResources,
  seedSignInExperience,
  seedSsoConnectors,
  seedTenantRoles,
  verifyLog,
  type AuditLog,
  type SeededEmailDomain,
  type SeededOrgInvitation,
} from "./fixtures";
import type {
  AccountRole,
  AccountSecurity,
  AccountSession,
  AccountWithRoles,
  AddMemberRequest,
  AddOrgEmailDomainRequest,
  Agent,
  ApiResource,
  AssignOrgRoleRequest,
  AuditEvent,
  AuditIntegrity,
  Client,
  ClientSecret,
  Connector,
  CreateAccountRequest,
  CreateAgentRequest,
  CreateApiResourceRequest,
  CreateClientRequest,
  CreateConnectorRequest,
  CreateGrantRequest,
  CreateOrganizationRequest,
  CreateOrgInvitationRequest,
  CreateOrgRoleRequest,
  CreateSsoConnectorRequest,
  CreateTenantRoleRequest,
  CreateWebhookRequest,
  CreatedClient,
  CreatedWebhook,
  Grant,
  ListAccountsQuery,
  ListAuditQuery,
  Member,
  Organization,
  OrganizationEmailDomain,
  OrganizationInvitation,
  OrgRoleDetail,
  Page,
  RegisterAgentKeyRequest,
  RevokedSessions,
  SessionInfo,
  SignInExperience,
  SsoConnector,
  TenantRole,
  UpdateAccountRequest,
  UpdateApiResourceRequest,
  UpdateClientRequest,
  UpdateOrganizationRequest,
  UpdateOrgRoleRequest,
  UpdateSignInExperienceRequest,
  UpdateWebhookRequest,
  Webhook,
  WebhookDelivery,
  WebhookSecret,
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
  private clients: Client[] = seedClients();
  /** Live sign-in sessions; a revoked or expired one is not kept. */
  private sessions: AccountSession[] = buildSessions(this.accounts, this.clients);
  /**
   * Plaintext secrets for confidential clients, keyed by row id.
   *
   * A real server keeps only an argon2 hash and can never answer "was this the old secret?" — the
   * console never asks either. The map exists so the mock can model the one rule a page observes:
   * a rotation replaces the secret, and the previous value stops being valid.
   */
  private clientSecrets = new Map<string, string>();
  private resources: ApiResource[] = seedResources();
  private connectors: Connector[] = seedConnectors();
  private ssoConnectors: SsoConnector[] = seedSsoConnectors();
  private experience: SignInExperience = seedSignInExperience();
  /**
   * Webhook subscriptions. The signing key is kept in memory only so a rotation can return a new
   * one — the real server seals it and never lists it, which the page honours by hiding it.
   */
  private webhooks: (Webhook & { secret: string })[] = [];
  /** Delivery rows carry their subscription privately; the API shape does not. */
  private webhookDeliveries: (WebhookDelivery & { webhook_id: string })[] = [];
  private members: Member[] = seedMembers(this.accounts);
  private emailDomains: SeededEmailDomain[] = seedEmailDomains();
  private invitations: SeededOrgInvitation[] = seedOrgInvitations();
  private tenantRoles: TenantRole[] = seedTenantRoles();
  /** account id → the tenant role ids it holds. A role may be held by many accounts. */
  private accountRoles = new Map<string, Set<string>>();
  private orgRoles: OrgRoleDetail[] = seedOrgRoles();
  /** account id → role ids held in this org. A role may be held by many members. */
  private memberRoles = new Map<string, Set<string>>();
  private agents: Agent[] = buildAgents(this.accounts);
  private grants: Grant[] = buildGrants(this.agents, this.accounts);
  /** Enrolled second factors per account; absent means nothing enrolled. */
  private accountSecurity = new Map<string, AccountSecurity>();
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
    this.seedMemberRoles();
    this.seedAccountRoles();
    this.seedAccountSecurity();
  }

  /**
   * One account starts with an authenticator and a passkey, so the security dialog has a state other
   * than "nothing enrolled" without an account having to run a WebAuthn ceremony in the mock.
   */
  private seedAccountSecurity(): void {
    const account = this.accounts[1];
    if (!account) return;
    this.accountSecurity.set(account.id, {
      account_id: account.id,
      mfa: { totp: true, backup_codes: 4 },
      passkeys: [
        {
          id: newId("pky"),
          name: "Laptop",
          created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
          last_used_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
        },
      ],
      trusted_devices: 1,
    });
  }

  private seedMemberRoles(): void {
    const indexes = seedMemberRoleIndexes();
    for (const [accountIndex, roleIndexes] of Object.entries(indexes)) {
      const account = this.accounts[Number(accountIndex)];
      if (!account) continue;
      const ids = roleIndexes
        .map((index) => this.orgRoles[index]?.id)
        .filter((id): id is string => id !== undefined);
      if (ids.length > 0) this.memberRoles.set(account.id, new Set(ids));
    }
  }

  private seedAccountRoles(): void {
    const indexes = seedAccountRoleIndexes();
    for (const [accountIndex, roleIndexes] of Object.entries(indexes)) {
      const account = this.accounts[Number(accountIndex)];
      if (!account) continue;
      const ids = roleIndexes
        .map((index) => this.tenantRoles[index]?.id)
        .filter((id): id is string => id !== undefined);
      if (ids.length > 0) this.accountRoles.set(account.id, new Set(ids));
    }
  }

  /** The tenant roles an account holds, by name — the shape `AccountWithRoles.roles` carries. */
  private rolesFor(accountId: string): AccountRole[] {
    const ids = this.accountRoles.get(accountId);
    if (!ids) return [];
    return this.tenantRoles
      .filter((role) => ids.has(role.id))
      .sort((left, right) => left.name.localeCompare(right.name))
      .map((role) => ({ id: role.id, name: role.name }));
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

  listClients(): Page<Client> {
    return { items: this.clients.map((client) => cloneClient(client)), next: null };
  }

  async createClient(body: CreateClientRequest): Promise<CreatedClient> {
    const clientId = body.client_id.trim();
    if (!validClientId(clientId)) {
      throw new ApiError(
        "client_id must be 2-32 characters of lowercase letters, digits or `-`, not starting or ending with `-`",
        { status: 400, code: "MONACA_INVALID_REQUEST" },
      );
    }
    const name = body.name.trim();
    if (name.length === 0 || name.length > 80) {
      throw new ApiError("name must be 1-80 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (body.kind !== "public" && body.kind !== "confidential") {
      throw new ApiError("kind must be `public` or `confidential`", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    // §6.2: the protocol id names the application in every authorize URL, so it is unique per
    // tenant and a second row with the same value is an honest conflict, not a silent overwrite.
    if (this.clients.some((client) => client.client_id === clientId)) {
      throw new ApiError(`An application with the client_id ${clientId} already exists`, {
        status: 409,
        code: "MONACA_CLIENT_EXISTS",
      });
    }

    const scopes = normaliseScopes(body.scopes);
    const redirectUris = normaliseUris(body.redirect_uris, "redirect_uris");
    const postLogout = normaliseUris(body.post_logout_redirect_uris, "post_logout_redirect_uris");

    const client: Client = {
      id: newId("cli"),
      client_id: clientId,
      name,
      kind: body.kind,
      token_auth_method: body.kind === "confidential" ? "client_secret_basic" : "none",
      scopes,
      redirect_uris: redirectUris,
      post_logout_redirect_uris: postLogout,
      is_third_party: body.is_third_party,
      created_at: new Date().toISOString(),
    };
    this.clients = [...this.clients, client];

    // The secret exists only in this response: a later list never carries it, exactly as §6.2 says.
    let secret: string | undefined;
    if (body.kind === "confidential") {
      secret = generateClientSecret();
      this.clientSecrets.set(client.id, secret);
    }

    await this.append({
      action: "client.created",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: {
        client_id: client.client_id,
        name: client.name,
        kind: client.kind,
        is_third_party: client.is_third_party,
      },
    });

    return secret === undefined ? cloneClient(client) : { ...cloneClient(client), client_secret: secret };
  }

  async updateClient(clientId: string, body: UpdateClientRequest): Promise<Client> {
    const index = this.clients.findIndex(
      (candidate) => candidate.id === clientId || candidate.client_id === clientId,
    );
    const client = this.clients[index];
    if (!client) {
      throw new ApiError(`client ${clientId} not found`, { status: 404, code: "MONACA_NOT_FOUND" });
    }

    let name = client.name;
    if (body.name !== undefined) {
      name = body.name.trim();
      if (name.length === 0 || name.length > 80) {
        throw new ApiError("name must be 1-80 characters", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }
    const scopes = body.scopes === undefined ? client.scopes : normaliseScopes(body.scopes);
    const redirectUris =
      body.redirect_uris === undefined
        ? client.redirect_uris
        : normaliseUris(body.redirect_uris, "redirect_uris");
    const postLogout =
      body.post_logout_redirect_uris === undefined
        ? client.post_logout_redirect_uris
        : normaliseUris(body.post_logout_redirect_uris, "post_logout_redirect_uris");

    const updated: Client = {
      ...client,
      name,
      scopes,
      redirect_uris: redirectUris,
      post_logout_redirect_uris: postLogout,
    };
    this.clients = [...this.clients.slice(0, index), updated, ...this.clients.slice(index + 1)];

    await this.append({
      action: "client.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { client_id: updated.client_id },
    });
    return cloneClient(updated);
  }

  async rotateClientSecret(clientId: string): Promise<ClientSecret> {
    const index = this.clients.findIndex(
      (candidate) => candidate.id === clientId || candidate.client_id === clientId,
    );
    const client = this.clients[index];
    if (!client) {
      throw new ApiError(`client ${clientId} not found`, { status: 404, code: "MONACA_NOT_FOUND" });
    }
    if (client.kind !== "confidential") {
      throw new ApiError("a public client has no secret to rotate", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    // Overwriting the map entry is the whole invalidation: the previous secret is no longer stored
    // anywhere, so there is nothing left for a later authentication to match.
    const secret = generateClientSecret();
    this.clientSecrets.set(client.id, secret);

    await this.append({
      action: "client.secret_rotated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { client_id: client.client_id },
    });
    return { client_id: client.client_id, client_secret: secret };
  }

  async deleteClient(clientId: string): Promise<void> {
    const index = this.clients.findIndex(
      (candidate) => candidate.id === clientId || candidate.client_id === clientId,
    );
    const client = this.clients[index];
    if (!client) {
      throw new ApiError(`client ${clientId} not found`, { status: 404, code: "MONACA_NOT_FOUND" });
    }

    this.clients = [...this.clients.slice(0, index), ...this.clients.slice(index + 1)];
    this.clientSecrets.delete(client.id);

    await this.append({
      action: "client.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { client_id: client.client_id },
    });
  }

  listResources(): Page<ApiResource> {
    // The server orders by identifier, and the console should not invent a different order.
    const items = [...this.resources]
      .sort((left, right) => left.identifier.localeCompare(right.identifier))
      .map(cloneResource);
    return { items, next: null };
  }

  async createResource(body: CreateApiResourceRequest): Promise<ApiResource> {
    const name = body.name.trim();
    if (name.length === 0 || name.length > 80) {
      throw new ApiError("name must be 1-80 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const identifier = body.identifier.trim();
    if (!/^https?:\/\/[^\s]+$/.test(identifier)) {
      throw new ApiError("identifier must be an absolute http(s) URL", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    // The indicator is the audience an application asks for; two rows publishing it would make
    // "which scopes does this audience define" ambiguous.
    if (this.resources.some((resource) => resource.identifier === identifier)) {
      throw new ApiError(`A resource with the identifier ${identifier} already exists`, {
        status: 409,
        code: "MONACA_RESOURCE_EXISTS",
      });
    }

    const resource: ApiResource = {
      id: newId("res"),
      name,
      identifier,
      scopes: normaliseScopes(body.scopes),
      created_at: new Date().toISOString(),
    };
    this.resources = [...this.resources, resource];

    await this.append({
      action: "resource.created",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { identifier: resource.identifier, scopes: resource.scopes },
    });
    return cloneResource(resource);
  }

  async updateResource(resourceId: string, body: UpdateApiResourceRequest): Promise<ApiResource> {
    if (body.name === undefined && body.scopes === undefined) {
      throw new ApiError("at least one field must be present", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const resource = this.requireResource(resourceId);

    let name = resource.name;
    if (body.name !== undefined) {
      name = body.name.trim();
      if (name.length === 0 || name.length > 80) {
        throw new ApiError("name must be 1-80 characters", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }

    const updated: ApiResource = {
      ...resource,
      name,
      scopes: body.scopes === undefined ? resource.scopes : normaliseScopes(body.scopes),
    };
    const index = this.resources.findIndex((candidate) => candidate.id === resource.id);
    this.resources = [
      ...this.resources.slice(0, index),
      updated,
      ...this.resources.slice(index + 1),
    ];

    await this.append({
      action: "resource.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { identifier: updated.identifier, scopes: updated.scopes },
    });
    return cloneResource(updated);
  }

  async deleteResource(resourceId: string): Promise<void> {
    const resource = this.requireResource(resourceId);
    this.resources = this.resources.filter((candidate) => candidate.id !== resource.id);

    await this.append({
      action: "resource.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { identifier: resource.identifier },
    });
  }

  private requireResource(resourceId: string): ApiResource {
    if (!/^res_[0-9abcdefghjkmnpqrstvwxyz]{26}$/.test(resourceId)) {
      throw new ApiError("not a resource id", { status: 400, code: "MONACA_INVALID_REQUEST" });
    }
    const resource = this.resources.find((candidate) => candidate.id === resourceId);
    if (!resource) {
      throw new ApiError("resource not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    return resource;
  }

  listAccounts(params: ListAccountsQuery = {}): Page<AccountWithRoles> {
    const needle = params.query?.trim().toLowerCase() ?? "";
    const limit = Math.min(Math.max(params.limit ?? 50, 1), 200);
    // Newest first, matching `ORDER BY created_at DESC, id DESC`.
    const items = [...this.accounts]
      .sort((left, right) => right.created_at.localeCompare(left.created_at))
      .filter(
        (account) =>
          needle.length === 0 ||
          account.email.toLowerCase().includes(needle) ||
          account.display_name.toLowerCase().includes(needle),
      )
      .slice(0, limit)
      .map((account) => ({ ...account, roles: this.rolesFor(account.id) }));
    return { items, next: null };
  }

  async createAccount(body: CreateAccountRequest): Promise<AccountWithRoles> {
    const email = body.email.trim();
    if (email.length === 0 || !email.includes("@")) {
      throw new ApiError("email must be an address", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (this.accounts.some((account) => account.email === email)) {
      throw new ApiError(`email is already taken`, { status: 409, code: "MONACA_EMAIL_TAKEN" });
    }

    const account = {
      id: newId("acc"),
      email,
      display_name: body.display_name.trim(),
      state: "active" as const,
      created_at: new Date().toISOString(),
    };
    this.accounts = [...this.accounts, account];

    await this.append({
      action: "account.created",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: account.id,
      decision: "info",
      payload: { email: account.email },
    });
    return { ...account, roles: [] };
  }

  async updateAccount(accountId: string, body: UpdateAccountRequest): Promise<AccountWithRoles> {
    parseAccountId(accountId);
    if (body.state !== "active" && body.state !== "disabled") {
      throw new ApiError("state must be `active` or `disabled`", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const index = this.accounts.findIndex((account) => account.id === accountId);
    const account = this.accounts[index];
    if (!account) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    if (account.state === body.state) return { ...account, roles: this.rolesFor(account.id) };
    if (body.state === "disabled") {
      // Suspension revokes every live session; "suspended" has to mean signed out everywhere.
      this.sessions = this.sessions.filter((session) => session.account_id !== account.id);
    }

    const updated = { ...account, state: body.state };
    this.accounts = [...this.accounts.slice(0, index), updated, ...this.accounts.slice(index + 1)];

    await this.append({
      action: body.state === "disabled" ? "account.suspended" : "account.reactivated",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: account.id,
      decision: "info",
      payload: { email: account.email },
    });
    return { ...updated, roles: this.rolesFor(account.id) };
  }

  listTenantRoles(): Page<TenantRole> {
    // Ordered by name, as `tenant.roles` is, so a new role lands where a reader looks for it.
    const items = [...this.tenantRoles]
      .sort((left, right) => left.name.localeCompare(right.name))
      .map(cloneTenantRole);
    return { items, next: null };
  }

  async createTenantRole(body: CreateTenantRoleRequest): Promise<TenantRole> {
    const name = body.name.trim();
    if (name.length === 0 || name.length > 80) {
      throw new ApiError("name must be 1-80 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const permissions = normaliseScopes(body.permissions);
    if (this.tenantRoles.some((role) => role.name === name)) {
      throw new ApiError("role is already taken", {
        status: 409,
        code: "MONACA_ROLE_EXISTS",
      });
    }

    const role: TenantRole = {
      id: newId("rol"),
      name,
      description: body.description.trim(),
      permissions,
      created_at: new Date().toISOString(),
    };
    this.tenantRoles = [...this.tenantRoles, role];

    await this.append({
      action: "role.created",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { name: role.name },
    });
    return cloneTenantRole(role);
  }

  async deleteTenantRole(roleId: string): Promise<void> {
    parseRoleId(roleId);
    const index = this.tenantRoles.findIndex((role) => role.id === roleId);
    const role = this.tenantRoles[index];
    if (!role) {
      throw new ApiError("role not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    this.tenantRoles = [
      ...this.tenantRoles.slice(0, index),
      ...this.tenantRoles.slice(index + 1),
    ];
    // Deleting the role drops every assignment of it, exactly as the server's cascade does.
    for (const [accountId, ids] of this.accountRoles) {
      if (ids.delete(roleId) && ids.size === 0) this.accountRoles.delete(accountId);
    }

    await this.append({
      action: "role.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { name: role.name },
    });
  }

  async assignAccountRole(accountId: string, roleId: string): Promise<void> {
    parseAccountId(accountId);
    parseRoleId(roleId);
    if (!this.accounts.some((account) => account.id === accountId)) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    if (!this.tenantRoles.some((role) => role.id === roleId)) {
      throw new ApiError("role not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    // Repeating an assignment is a success, not a second row.
    const ids = this.accountRoles.get(accountId) ?? new Set<string>();
    ids.add(roleId);
    this.accountRoles.set(accountId, ids);
  }

  async unassignAccountRole(accountId: string, roleId: string): Promise<void> {
    parseAccountId(accountId);
    parseRoleId(roleId);
    const ids = this.accountRoles.get(accountId);
    if (!ids?.delete(roleId)) {
      throw new ApiError("role assignment not found", {
        status: 404,
        code: "MONACA_NOT_FOUND",
      });
    }
    if (ids.size === 0) this.accountRoles.delete(accountId);
  }

  listAccountSessions(accountId: string): Page<AccountSession> {
    parseAccountId(accountId);
    if (!this.accounts.some((account) => account.id === accountId)) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const now = Date.now();
    // Newest activity first, as the server orders by `last_seen_at DESC`.
    const items = this.sessions
      .filter(
        (session) => session.account_id === accountId && Date.parse(session.expires_at) > now,
      )
      .sort((left, right) => Date.parse(right.last_seen_at) - Date.parse(left.last_seen_at))
      .map((session) => ({ ...session }));
    return { items, next: null };
  }

  async revokeAccountSession(accountId: string, sessionId: string): Promise<void> {
    parseAccountId(accountId);
    parseSessionId(sessionId);
    // A session may only be revoked through the account it belongs to.
    const index = this.sessions.findIndex(
      (session) => session.id === sessionId && session.account_id === accountId,
    );
    if (index < 0) {
      throw new ApiError("session not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    this.sessions = [...this.sessions.slice(0, index), ...this.sessions.slice(index + 1)];
    await this.append({
      action: "session.revoked",
      actor: this.session().account_id,
      subjectType: "session",
      subjectId: sessionId,
      decision: "deny",
      payload: { account_id: accountId },
    });
  }

  async revokeAccountSessions(accountId: string): Promise<RevokedSessions> {
    parseAccountId(accountId);
    if (!this.accounts.some((account) => account.id === accountId)) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    const revoked = this.sessions.filter((session) => session.account_id === accountId).length;
    this.sessions = this.sessions.filter((session) => session.account_id !== accountId);
    await this.append({
      action: "session.revoked_all",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: accountId,
      decision: "deny",
      payload: { revoked },
    });
    return { revoked };
  }

  getAccountSecurity(accountId: string): AccountSecurity {
    parseAccountId(accountId);
    if (!this.accounts.some((account) => account.id === accountId)) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const stored = this.accountSecurity.get(accountId);
    return stored
      ? cloneAccountSecurity(stored)
      : {
          account_id: accountId,
          mfa: { totp: false, backup_codes: 0 },
          passkeys: [],
          trusted_devices: 0,
        };
  }

  async resetAccountMfa(accountId: string): Promise<void> {
    parseAccountId(accountId);
    if (!this.accounts.some((account) => account.id === accountId)) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    this.accountSecurity.set(accountId, {
      ...(this.accountSecurity.get(accountId) ?? {
        account_id: accountId,
        passkeys: [],
        trusted_devices: 0,
      }),
      mfa: { totp: false, backup_codes: 0 },
    });
    await this.append({
      action: "account.security_changed",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: accountId,
      decision: "deny",
      payload: { account_id: accountId, kind: "mfa_reset" },
    });
  }

  async deleteAccountPasskey(accountId: string, passkeyId: string): Promise<void> {
    parseAccountId(accountId);
    if (!this.accounts.some((account) => account.id === accountId)) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const stored = this.accountSecurity.get(accountId);
    const index = stored?.passkeys.findIndex((passkey) => passkey.id === passkeyId) ?? -1;
    if (!stored || index < 0) {
      throw new ApiError("passkey not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    this.accountSecurity.set(accountId, {
      ...stored,
      passkeys: [...stored.passkeys.slice(0, index), ...stored.passkeys.slice(index + 1)],
    });
    await this.append({
      action: "account.security_changed",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: accountId,
      decision: "deny",
      payload: { account_id: accountId, kind: "passkey_removed", passkey: passkeyId },
    });
  }

  listConnectors(): Page<Connector> {
    const items = [...this.connectors]
      .sort((left, right) => left.connector_id.localeCompare(right.connector_id))
      .map(cloneConnector);
    return { items, next: null };
  }

  async createConnector(body: CreateConnectorRequest): Promise<Connector> {
    // The slug is lowercased before validation, exactly as `check_connector_id` does.
    const connectorId = body.connector_id.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{1,31}$/.test(connectorId)) {
      throw new ApiError("connector_id must be 2-32 lowercase letters, digits or hyphens", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const displayName = body.display_name.trim();
    if (displayName.length === 0) {
      throw new ApiError("display_name must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    for (const [field, url] of [
      ["authorize_url", body.authorize_url.trim()],
      ["token_url", body.token_url.trim()],
      ["userinfo_url", body.userinfo_url.trim()],
    ] as const) {
      if (!/^https?:\/\/[^\s]+$/.test(url)) {
        throw new ApiError(`${field} must be an absolute http(s) URL`, {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }
    if (body.client_id.trim().length === 0 || body.client_secret.length === 0) {
      throw new ApiError("client_id and client_secret must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (this.connectors.some((connector) => connector.connector_id === connectorId)) {
      throw new ApiError("connector is already taken", {
        status: 409,
        code: "MONACA_CONNECTOR_EXISTS",
      });
    }

    const scopes: string[] = [];
    for (const scope of body.scopes) {
      const trimmed = scope.trim();
      if (trimmed.length === 0 || /\s/.test(trimmed)) {
        throw new ApiError("each scope must be a single non-empty token", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      if (!scopes.includes(trimmed)) scopes.push(trimmed);
    }

    const connector: Connector = {
      connector_id: connectorId,
      display_name: displayName,
      authorize_url: body.authorize_url.trim(),
      token_url: body.token_url.trim(),
      userinfo_url: body.userinfo_url.trim(),
      client_id: body.client_id.trim(),
      scopes,
      created_at: new Date().toISOString(),
    };
    this.connectors = [...this.connectors, connector];

    await this.append({
      action: "connector.created",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { connector_id: connector.connector_id },
    });
    return cloneConnector(connector);
  }

  async deleteConnector(connectorId: string): Promise<void> {
    const index = this.connectors.findIndex((connector) => connector.connector_id === connectorId);
    const connector = this.connectors[index];
    if (!connector) {
      throw new ApiError("connector not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    this.connectors = [...this.connectors.slice(0, index), ...this.connectors.slice(index + 1)];

    await this.append({
      action: "connector.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { connector_id: connector.connector_id },
    });
  }

  listSsoConnectors(): Page<SsoConnector> {
    return { items: this.ssoConnectors.map(cloneSsoConnector), next: null };
  }

  async createSsoConnector(body: CreateSsoConnectorRequest): Promise<SsoConnector> {
    const connectorId = body.connector_id.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{1,31}$/.test(connectorId)) {
      throw new ApiError("connector_id must be 2-32 lowercase letters, digits or hyphens", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const displayName = body.display_name.trim();
    if (displayName.length === 0) {
      throw new ApiError("display_name must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    for (const [field, url] of [
      ["issuer", body.issuer],
      ["authorize_url", body.authorize_url],
      ["token_url", body.token_url],
      ["userinfo_url", body.userinfo_url],
    ] as const) {
      if (!/^https?:\/\/[^\s]+$/.test(url.trim())) {
        throw new ApiError(`${field} must be an absolute http(s) URL`, {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }
    if (body.client_id.trim().length === 0 || body.client_secret.length === 0) {
      throw new ApiError("client_id and client_secret must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    const domains: string[] = [];
    for (const raw of body.email_domains) {
      const domain = normaliseDomain(raw);
      if (domain === null) {
        throw new ApiError("email_domains must be DNS names of lowercase letters, digits, `-` and `.`", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      if (!domains.includes(domain)) domains.push(domain);
    }
    if (domains.length === 0) {
      throw new ApiError("email_domains must name at least one domain", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    if (this.ssoConnectors.some((connector) => connector.connector_id === connectorId)) {
      throw new ApiError("SSO connector is already taken", {
        status: 409,
        code: "MONACA_SSO_CONNECTOR_EXISTS",
      });
    }
    const claimed = this.ssoConnectors.find((connector) =>
      connector.email_domains.some((domain) => domains.includes(domain)),
    );
    if (claimed) {
      throw new ApiError("an SSO connector already owns that email domain", {
        status: 409,
        code: "MONACA_SSO_DOMAIN_TAKEN",
      });
    }

    const scopes: string[] = [];
    for (const scope of body.scopes ?? []) {
      const trimmed = scope.trim();
      if (trimmed.length === 0 || /\s/.test(trimmed)) {
        throw new ApiError("each scope must be a single non-empty token", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      if (!scopes.includes(trimmed)) scopes.push(trimmed);
    }
    if (scopes.length === 0) scopes.push("openid", "profile", "email");

    const connector: SsoConnector = {
      connector_id: connectorId,
      display_name: displayName,
      issuer: body.issuer.trim(),
      authorize_url: body.authorize_url.trim(),
      token_url: body.token_url.trim(),
      userinfo_url: body.userinfo_url.trim(),
      client_id: body.client_id.trim(),
      scopes,
      email_domains: domains,
      created_at: new Date().toISOString(),
    };
    this.ssoConnectors = [...this.ssoConnectors, connector];

    await this.append({
      action: "sso_connector.created",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { connector_id: connector.connector_id, email_domains: connector.email_domains },
    });
    return cloneSsoConnector(connector);
  }

  async deleteSsoConnector(connectorId: string): Promise<void> {
    const index = this.ssoConnectors.findIndex(
      (connector) => connector.connector_id === connectorId,
    );
    const connector = this.ssoConnectors[index];
    if (!connector) {
      throw new ApiError("SSO connector not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    this.ssoConnectors = [
      ...this.ssoConnectors.slice(0, index),
      ...this.ssoConnectors.slice(index + 1),
    ];
    await this.append({
      action: "sso_connector.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { connector_id: connector.connector_id },
    });
  }

  getSignInExperience(): SignInExperience {
    return { ...this.experience };
  }

  async updateSignInExperience(body: UpdateSignInExperienceRequest): Promise<SignInExperience> {
    // §6.2: an empty patch is a mistake, not a no-op — it says the caller meant to change something.
    if (
      body.sign_up_enabled === undefined &&
      body.password_sign_in_enabled === undefined &&
      body.email_code_sign_in_enabled === undefined &&
      body.mfa_enabled === undefined &&
      body.mfa_policy === undefined &&
      body.password_min_length === undefined
    ) {
      throw new ApiError("at least one switch must be present", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (body.mfa_policy !== undefined && !["user_controlled", "mandatory"].includes(body.mfa_policy)) {
      throw new ApiError("mfa_policy must be user_controlled or mandatory", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (
      body.password_min_length !== undefined &&
      !(body.password_min_length >= 8 && body.password_min_length <= 64)
    ) {
      throw new ApiError("password_min_length must be between 8 and 64", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    const password = body.password_sign_in_enabled ?? this.experience.password_sign_in_enabled;
    const emailCode = body.email_code_sign_in_enabled ?? this.experience.email_code_sign_in_enabled;
    // Checked against the *resulting* state, so a one-field patch cannot silently leave no method on.
    if (!password && !emailCode) {
      throw new ApiError("password sign-in or email code sign-in must stay enabled", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const mfaEnabled = body.mfa_enabled ?? this.experience.mfa_enabled;
    const mfaPolicy = body.mfa_policy ?? this.experience.mfa_policy;
    if (!mfaEnabled && mfaPolicy === "mandatory") {
      throw new ApiError("mfa_policy cannot be mandatory while MFA is disabled", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    const updated: SignInExperience = {
      sign_up_enabled: body.sign_up_enabled ?? this.experience.sign_up_enabled,
      password_sign_in_enabled: password,
      email_code_sign_in_enabled: emailCode,
      mfa_enabled: mfaEnabled,
      mfa_policy: mfaPolicy,
      password_min_length:
        body.password_min_length ?? this.experience.password_min_length,
      updated_at: new Date().toISOString(),
    };
    this.experience = updated;

    await this.append({
      action: "sign_in_experience.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: {
        sign_up_enabled: updated.sign_up_enabled,
        password_sign_in_enabled: updated.password_sign_in_enabled,
        email_code_sign_in_enabled: updated.email_code_sign_in_enabled,
        mfa_enabled: updated.mfa_enabled,
        mfa_policy: updated.mfa_policy,
        password_min_length: updated.password_min_length,
      },
    });
    return { ...updated };
  }

  listWebhooks(): Page<Webhook> {
    return {
      items: this.webhooks.map(({ secret: _secret, ...row }) => ({
        ...row,
        events: [...row.events],
      })),
      next: null,
    };
  }

  async createWebhook(body: CreateWebhookRequest): Promise<CreatedWebhook> {
    const url = checkWebhookUrl(body.url);
    const events = checkWebhookEvents(body.events);
    const now = new Date().toISOString();
    const row = {
      id: newId("whk"),
      url,
      events,
      enabled: true,
      secret: newWebhookSecret(),
      created_at: now,
      updated_at: now,
    };
    this.webhooks = [...this.webhooks, row];

    await this.append({
      action: "webhook.created",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { webhook_id: row.id, url: row.url, events: row.events },
    });
    return { ...row, events: [...row.events] };
  }

  async updateWebhook(webhookId: string, body: UpdateWebhookRequest): Promise<Webhook> {
    parseWebhookId(webhookId);
    if (body.url === undefined && body.events === undefined && body.enabled === undefined) {
      throw new ApiError("at least one field must be present", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const index = this.webhooks.findIndex((row) => row.id === webhookId);
    if (index === -1) {
      throw new ApiError("webhook not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const current = this.webhooks[index]!;
    const url = body.url === undefined ? current.url : checkWebhookUrl(body.url);
    const events = body.events === undefined ? current.events : checkWebhookEvents(body.events);
    const updated = {
      ...current,
      url,
      events,
      enabled: body.enabled ?? current.enabled,
      updated_at: new Date().toISOString(),
    };
    this.webhooks = this.webhooks.map((row, at) => (at === index ? updated : row));

    await this.append({
      action: "webhook.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: {
        webhook_id: updated.id,
        url: updated.url,
        events: updated.events,
        enabled: updated.enabled,
      },
    });
    const { secret: _secret, ...row } = updated;
    return { ...row, events: [...row.events] };
  }

  async rotateWebhookSecret(webhookId: string): Promise<WebhookSecret> {
    parseWebhookId(webhookId);
    const index = this.webhooks.findIndex((row) => row.id === webhookId);
    if (index === -1) {
      throw new ApiError("webhook not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const secret = newWebhookSecret();
    this.webhooks = this.webhooks.map((row, at) =>
      at === index ? { ...row, secret, updated_at: new Date().toISOString() } : row,
    );

    await this.append({
      action: "webhook.secret_rotated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { webhook_id: webhookId },
    });
    return { id: webhookId, secret };
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    parseWebhookId(webhookId);
    if (!this.webhooks.some((row) => row.id === webhookId)) {
      throw new ApiError("webhook not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    this.webhooks = this.webhooks.filter((row) => row.id !== webhookId);
    this.webhookDeliveries = this.webhookDeliveries.filter((row) => row.webhook_id !== webhookId);

    await this.append({
      action: "webhook.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { webhook_id: webhookId },
    });
  }

  listWebhookDeliveries(webhookId: string): Page<WebhookDelivery> {
    parseWebhookId(webhookId);
    if (!this.webhooks.some((row) => row.id === webhookId)) {
      throw new ApiError("webhook not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const items = this.webhookDeliveries
      .filter((row) => row.webhook_id === webhookId)
      .slice()
      .sort((left, right) => right.created_at.localeCompare(left.created_at))
      .map(({ webhook_id: _hook, ...row }) => ({ ...row }));
    return { items, next: null };
  }

  /**
   * The mock never makes an outbound HTTP call, so it records what the server's dispatcher would:
   * one delivery for each enabled subscription that names the appended action.
   */
  private recordWebhookDeliveries(action: string): void {
    for (const hook of this.webhooks) {
      if (!hook.enabled || !hook.events.includes(action)) continue;
      this.webhookDeliveries.push({
        id: newId("dlv"),
        webhook_id: hook.id,
        event: action,
        status_code: 200,
        success: true,
        attempts: 1,
        error: null,
        created_at: new Date().toISOString(),
      });
    }
  }

  listMembers(): Page<Member> {
    return { items: [...this.members], next: null };
  }

  private orgBySlug(slug: string): Organization {
    const org = this.organizations.find((candidate) => candidate.slug === slug);
    if (!org) {
      throw new ApiError("organization not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    return org;
  }

  listOrgEmailDomains(org: string): Page<OrganizationEmailDomain> {
    const row = this.orgBySlug(org);
    const items = this.emailDomains
      .filter((entry) => entry.org === row.slug)
      // Oldest first, as `org_email_domains` orders by `created_at`.
      .slice()
      .sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at))
      .map((entry) => ({ domain: entry.domain, created_at: entry.created_at }));
    return { items, next: null };
  }

  async addOrgEmailDomain(
    org: string,
    body: AddOrgEmailDomainRequest,
  ): Promise<OrganizationEmailDomain> {
    const row = this.orgBySlug(org);
    const domain = normaliseDomain(body.domain);
    if (domain === null) {
      throw new ApiError("domain must be a DNS name of lowercase letters, digits, `-` and `.`", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    // One org per domain in the tenant: two orgs claiming the same address would split a sign-in.
    if (this.emailDomains.some((entry) => entry.domain === domain)) {
      throw new ApiError("email domain is already taken", {
        status: 409,
        code: "MONACA_DOMAIN_EXISTS",
      });
    }

    const created_at = new Date().toISOString();
    this.emailDomains = [...this.emailDomains, { org: row.slug, domain, created_at }];
    await this.append({
      action: "org.domain.added",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: row.id,
      decision: "allow",
      payload: { org: row.slug, domain },
    });
    return { domain, created_at };
  }

  async removeOrgEmailDomain(org: string, rawDomain: string): Promise<void> {
    const row = this.orgBySlug(org);
    const domain = normaliseDomain(rawDomain);
    if (domain === null) {
      throw new ApiError("domain must be a DNS name of lowercase letters, digits, `-` and `.`", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    const index = this.emailDomains.findIndex(
      (entry) => entry.org === row.slug && entry.domain === domain,
    );
    if (index < 0) {
      throw new ApiError("domain not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }

    this.emailDomains = [
      ...this.emailDomains.slice(0, index),
      ...this.emailDomains.slice(index + 1),
    ];
    await this.append({
      action: "org.domain.removed",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: row.id,
      decision: "allow",
      payload: { org: row.slug, domain },
    });
  }

  listOrgInvitations(org: string): Page<OrganizationInvitation> {
    const row = this.orgBySlug(org);
    const now = Date.now();
    const items = this.invitations
      .filter((entry) => entry.org === row.slug && Date.parse(entry.expires_at) > now)
      // Oldest first, as `organization_invitations` orders by `created_at`.
      .slice()
      .sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at))
      .map(({ id, email, role, invited_by, created_at, expires_at }) => ({
        id,
        email,
        role,
        invited_by,
        created_at,
        expires_at,
      }));
    return { items, next: null };
  }

  async createOrgInvitation(
    org: string,
    body: CreateOrgInvitationRequest,
  ): Promise<OrganizationInvitation> {
    const row = this.orgBySlug(org);
    const email = normaliseEmail(body.email);
    if (email === null) {
      throw new ApiError("email must be a single address without whitespace", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const role = body.role ?? "member";
    const days = body.expires_in_days ?? 7;
    if (!Number.isInteger(days) || days < 1 || days > 90) {
      throw new ApiError("expires_in_days must be between 1 and 90", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    const now = Date.now();
    if (
      this.invitations.some(
        (entry) =>
          entry.org === row.slug && entry.email === email && Date.parse(entry.expires_at) > now,
      )
    ) {
      throw new ApiError("an invitation for that address is already pending", {
        status: 409,
        code: "MONACA_INVITATION_EXISTS",
      });
    }

    const invitation: SeededOrgInvitation = {
      org: row.slug,
      id: newId("inv"),
      email,
      role,
      invited_by: this.session().account_id,
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + days * 24 * 60 * 60 * 1000).toISOString(),
    };
    this.invitations = [...this.invitations, invitation];
    await this.append({
      action: "org.invitation.created",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: row.id,
      decision: "allow",
      payload: { org: row.slug, email, role, expires_at: invitation.expires_at },
    });
    return {
      id: invitation.id,
      email: invitation.email,
      role: invitation.role,
      invited_by: invitation.invited_by,
      created_at: invitation.created_at,
      expires_at: invitation.expires_at,
    };
  }

  async revokeOrgInvitation(org: string, invitationId: string): Promise<void> {
    const row = this.orgBySlug(org);
    const index = this.invitations.findIndex(
      (entry) => entry.org === row.slug && entry.id === invitationId,
    );
    if (index < 0) {
      throw new ApiError("invitation not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const removed = this.invitations[index] as SeededOrgInvitation;
    this.invitations = [
      ...this.invitations.slice(0, index),
      ...this.invitations.slice(index + 1),
    ];
    await this.append({
      action: "org.invitation.revoked",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: row.id,
      decision: "deny",
      payload: { org: row.slug, email: removed.email, invitation: removed.id },
    });
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

  listOrgRoles(): Page<OrgRoleDetail> {
    return { items: this.orgRoles.map(cloneRole), next: null };
  }

  async createOrgRole(body: CreateOrgRoleRequest): Promise<OrgRoleDetail> {
    const name = body.name.trim();
    if (name.length === 0 || name.length > 80) {
      throw new ApiError("name must be 1-80 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    // A role name is unique inside its org, and the schema's unique index is what says so.
    if (this.orgRoles.some((role) => role.name === name)) {
      throw new ApiError(`A role named ${name} already exists`, {
        status: 409,
        code: "MONACA_ORG_ROLE_EXISTS",
      });
    }

    const role: OrgRoleDetail = {
      id: newId("rol"),
      name,
      description: body.description.trim(),
      scopes: normaliseScopes(body.scopes),
      created_at: new Date().toISOString(),
    };
    this.orgRoles = [...this.orgRoles, role];

    await this.append({
      action: "org.role.created",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: DEFAULT_ORG,
      decision: "info",
      payload: { org: DEFAULT_ORG, role: role.name, scopes: role.scopes },
    });
    return cloneRole(role);
  }

  async updateOrgRole(roleId: string, body: UpdateOrgRoleRequest): Promise<OrgRoleDetail> {
    if (body.name === undefined && body.description === undefined && body.scopes === undefined) {
      throw new ApiError("at least one field must be present", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const role = this.requireRole(roleId);

    let name = role.name;
    if (body.name !== undefined) {
      name = body.name.trim();
      if (name.length === 0 || name.length > 80) {
        throw new ApiError("name must be 1-80 characters", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      if (this.orgRoles.some((candidate) => candidate.id !== role.id && candidate.name === name)) {
        throw new ApiError(`A role named ${name} already exists`, {
          status: 409,
          code: "MONACA_ORG_ROLE_EXISTS",
        });
      }
    }

    const updated: OrgRoleDetail = {
      ...role,
      name,
      description: body.description === undefined ? role.description : body.description.trim(),
      scopes: body.scopes === undefined ? role.scopes : normaliseScopes(body.scopes),
    };
    this.replaceRole(updated);

    await this.append({
      action: "org.role.updated",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: DEFAULT_ORG,
      decision: "info",
      payload: { org: DEFAULT_ORG, role: updated.name, scopes: updated.scopes },
    });
    return cloneRole(updated);
  }

  async deleteOrgRole(roleId: string): Promise<void> {
    const role = this.requireRole(roleId);
    this.orgRoles = this.orgRoles.filter((candidate) => candidate.id !== role.id);
    // Every assignment goes with the role, so no member keeps a dangling reference.
    for (const [accountId, ids] of this.memberRoles) {
      if (!ids.has(role.id)) continue;
      ids.delete(role.id);
      if (ids.size === 0) this.memberRoles.delete(accountId);
    }

    await this.append({
      action: "org.role.deleted",
      actor: this.session().account_id,
      subjectType: "org",
      subjectId: DEFAULT_ORG,
      decision: "info",
      payload: { org: DEFAULT_ORG, role: role.name },
    });
  }

  listMemberRoles(accountId: string): Page<OrgRoleDetail> {
    this.requireMember(accountId);
    const ids = this.memberRoles.get(accountId) ?? new Set<string>();
    const items = [...ids]
      .map((id) => this.orgRoles.find((role) => role.id === id))
      .filter((role): role is OrgRoleDetail => role !== undefined);
    return { items: items.map(cloneRole), next: null };
  }

  async assignMemberRole(accountId: string, body: AssignOrgRoleRequest): Promise<void> {
    this.requireMember(accountId);
    const role = this.requireRole(body.role_id);

    const before = this.roleNamesOf(accountId);
    const ids = new Set(this.memberRoles.get(accountId) ?? []);
    if (ids.has(role.id)) return; // idempotent: repeating an assignment is a no-op, as the server says
    ids.add(role.id);
    this.memberRoles.set(accountId, ids);

    await this.appendRolesChanged(accountId, before, this.roleNamesOf(accountId));
  }

  async unassignMemberRole(accountId: string, roleId: string): Promise<void> {
    this.requireMember(accountId);
    parseRoleId(roleId);

    const ids = new Set(this.memberRoles.get(accountId) ?? []);
    if (!ids.has(roleId)) {
      throw new ApiError("role assignment not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const before = this.roleNamesOf(accountId);
    ids.delete(roleId);
    if (ids.size === 0) this.memberRoles.delete(accountId);
    else this.memberRoles.set(accountId, ids);

    await this.appendRolesChanged(accountId, before, this.roleNamesOf(accountId));
  }

  private requireMember(accountId: string): void {
    if (!this.members.some((member) => member.account_id === accountId)) {
      throw new ApiError("member not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
  }

  private requireRole(roleId: string): OrgRoleDetail {
    parseRoleId(roleId);
    const role = this.orgRoles.find((candidate) => candidate.id === roleId);
    if (!role) {
      throw new ApiError("role not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    return role;
  }

  private replaceRole(role: OrgRoleDetail): void {
    const index = this.orgRoles.findIndex((candidate) => candidate.id === role.id);
    this.orgRoles = [...this.orgRoles.slice(0, index), role, ...this.orgRoles.slice(index + 1)];
  }

  private roleNamesOf(accountId: string): string[] {
    const ids = this.memberRoles.get(accountId) ?? new Set<string>();
    return [...ids]
      .map((id) => this.orgRoles.find((role) => role.id === id)?.name)
      .filter((name): name is string => name !== undefined);
  }

  private async appendRolesChanged(accountId: string, from: string[], to: string[]): Promise<void> {
    await this.append({
      action: "org.member.roles_changed",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: accountId,
      decision: "info",
      payload: { org: DEFAULT_ORG, from, to },
    });
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
    this.recordWebhookDeliveries(seed.action);
  }
}

function cloneAgent(agent: Agent): Agent {
  return { ...agent, keys: agent.keys.map((key) => ({ ...key })) };
}

function cloneClient(client: Client): Client {
  return {
    ...client,
    scopes: [...client.scopes],
    redirect_uris: [...client.redirect_uris],
    post_logout_redirect_uris: [...client.post_logout_redirect_uris],
  };
}

function cloneRole(role: OrgRoleDetail): OrgRoleDetail {
  return { ...role, scopes: [...role.scopes] };
}

function cloneTenantRole(role: TenantRole): TenantRole {
  return { ...role, permissions: [...role.permissions] };
}

function cloneResource(resource: ApiResource): ApiResource {
  return { ...resource, scopes: [...resource.scopes] };
}

function cloneConnector(connector: Connector): Connector {
  return { ...connector, scopes: [...connector.scopes] };
}

function cloneSsoConnector(connector: SsoConnector): SsoConnector {
  return {
    ...connector,
    scopes: [...connector.scopes],
    email_domains: [...connector.email_domains],
  };
}

/** The server's `WebhookId::parse`: a typed `whk_…` id, nothing else. */
function parseWebhookId(webhookId: string): void {
  if (!/^whk_[0-9abcdefghjkmnpqrstvwxyz]{26}$/.test(webhookId)) {
    throw new ApiError("not a webhook id", { status: 400, code: "MONACA_INVALID_REQUEST" });
  }
}

/** An absolute http(s) endpoint — the same rule `is_absolute_http_url` enforces server-side. */
function checkWebhookUrl(raw: string): string {
  const url = raw.trim();
  if (!/^https?:\/\/[^\s]+$/.test(url)) {
    throw new ApiError("url must be an absolute http(s) URL", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  return url;
}

/** Trim, de-duplicate, and refuse anything outside §6.2's catalog. */
function checkWebhookEvents(raw: string[]): string[] {
  const events: string[] = [];
  for (const value of raw) {
    const event = value.trim();
    if (!isKnownWebhookEvent(event)) {
      throw new ApiError(`\`${event}\` is not a subscribable event`, {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (!events.includes(event)) events.push(event);
  }
  if (events.length === 0) {
    throw new ApiError("events must name at least one audit action", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  return events;
}

/** `whsec_` plus 64 hex characters — the shape the real server generates. */
function newWebhookSecret(): string {
  const half = () => crypto.randomUUID().replaceAll("-", "");
  return `whsec_${half()}${half()}`;
}

function cloneAccountSecurity(security: AccountSecurity): AccountSecurity {
  return {
    ...security,
    mfa: { ...security.mfa },
    passkeys: security.passkeys.map((passkey) => ({ ...passkey })),
  };
}

/** The server's `RoleId::parse`: a typed `rol_…` id, nothing else. */
function parseRoleId(roleId: string): void {
  if (!/^rol_[0-9abcdefghjkmnpqrstvwxyz]{26}$/.test(roleId)) {
    throw new ApiError("not a role id", { status: 400, code: "MONACA_INVALID_REQUEST" });
  }
}

/** The server's `AccountId::parse`: a typed `acc_…` id, nothing else. */
function parseAccountId(accountId: string): void {
  if (!/^acc_[0-9abcdefghjkmnpqrstvwxyz]{26}$/.test(accountId)) {
    throw new ApiError("not an account id", { status: 400, code: "MONACA_INVALID_REQUEST" });
  }
}

/** The server's `SessionId::parse`: a typed `ses_…` id, nothing else. */
function parseSessionId(sessionId: string): void {
  if (!/^ses_[0-9abcdefghjkmnpqrstvwxyz]{26}$/.test(sessionId)) {
    throw new ApiError("not a session id", { status: 400, code: "MONACA_INVALID_REQUEST" });
  }
}

/** The §6.2 protocol-id rule, identical to the server's `valid_client_id`. */
function validClientId(value: string): boolean {
  return (
    value.length >= 2 &&
    value.length <= 32 &&
    /^[a-z0-9-]+$/.test(value) &&
    !value.startsWith("-") &&
    !value.endsWith("-")
  );
}

/** The scope grammar: `a` or `a:b`, lowercase, dots and dashes allowed inside a segment. */
function normaliseScopes(raw: readonly string[]): string[] {
  const scopes: string[] = [];
  for (const scope of raw) {
    const trimmed = scope.trim();
    if (!/^[a-z][a-z0-9_.-]*(:[a-z][a-z0-9_.-]*)*$/.test(trimmed)) {
      throw new ApiError("scopes must match the scope grammar", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (!scopes.includes(trimmed)) scopes.push(trimmed);
  }
  return scopes;
}

/** Absolute http(s) URLs, de-duplicated in first-seen order — the server's `normalise_uris`. */
function normaliseUris(raw: readonly string[], field: string): string[] {
  const uris: string[] = [];
  for (const uri of raw) {
    const trimmed = uri.trim();
    if (!/^https?:\/\/[^\s]+$/.test(trimmed)) {
      throw new ApiError(`${field} must be absolute http(s) URLs`, {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (!uris.includes(trimmed)) uris.push(trimmed);
  }
  return uris;
}

/** The server's `normalise_domain`: trim, lowercase, and accept only a plain DNS name. */
function normaliseDomain(raw: string): string | null {
  const domain = raw.trim().toLowerCase();
  if (domain.length < 2 || domain.length > 100) return null;
  const labels = domain.split(".");
  const valid = labels.every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      [...label].every(
        (char) => (char >= "a" && char <= "z") || (char >= "0" && char <= "9") || char === "-",
      ),
  );
  return valid ? domain : null;
}

/** The server's invitation email rule: trim, lowercase, and one `local@domain`. */
function normaliseEmail(raw: string): string | null {
  const email = raw.trim().toLowerCase();
  if (email.split("@").length !== 2 || /\s/.test(email)) return null;
  const [local, domain] = email.split("@");
  return local !== undefined && domain !== undefined && local.length > 0 && domain.length > 0
    ? email
    : null;
}

/** A 256-bit base64url secret, the shape the server's `generate_client_secret` produces. */
function generateClientSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
  async listClients() {
    await delay();
    return store.listClients();
  },
  async createClient(body) {
    await delay();
    return store.createClient(body);
  },
  async updateClient(clientId, body) {
    await delay();
    return store.updateClient(clientId, body);
  },
  async rotateClientSecret(clientId) {
    await delay();
    return store.rotateClientSecret(clientId);
  },
  async deleteClient(clientId) {
    await delay();
    return store.deleteClient(clientId);
  },
  async listResources() {
    await delay();
    return store.listResources();
  },
  async createResource(body) {
    await delay();
    return store.createResource(body);
  },
  async updateResource(resourceId, body) {
    await delay();
    return store.updateResource(resourceId, body);
  },
  async deleteResource(resourceId) {
    await delay();
    return store.deleteResource(resourceId);
  },
  async listAccounts(query) {
    await delay();
    return store.listAccounts(query);
  },
  async createAccount(body) {
    await delay();
    return store.createAccount(body);
  },
  async updateAccount(accountId, body) {
    await delay();
    return store.updateAccount(accountId, body);
  },
  async listTenantRoles() {
    await delay();
    return store.listTenantRoles();
  },
  async createTenantRole(body) {
    await delay();
    return store.createTenantRole(body);
  },
  async deleteTenantRole(roleId) {
    await delay();
    return store.deleteTenantRole(roleId);
  },
  async assignAccountRole(accountId, roleId) {
    await delay();
    return store.assignAccountRole(accountId, roleId);
  },
  async unassignAccountRole(accountId, roleId) {
    await delay();
    return store.unassignAccountRole(accountId, roleId);
  },
  async listAccountSessions(accountId) {
    await delay();
    return store.listAccountSessions(accountId);
  },
  async revokeAccountSession(accountId, sessionId) {
    await delay();
    return store.revokeAccountSession(accountId, sessionId);
  },
  async revokeAccountSessions(accountId) {
    await delay();
    return store.revokeAccountSessions(accountId);
  },
  async getAccountSecurity(accountId) {
    await delay();
    return store.getAccountSecurity(accountId);
  },
  async resetAccountMfa(accountId) {
    await delay();
    return store.resetAccountMfa(accountId);
  },
  async deleteAccountPasskey(accountId, passkeyId) {
    await delay();
    return store.deleteAccountPasskey(accountId, passkeyId);
  },
  async listConnectors() {
    await delay();
    return store.listConnectors();
  },
  async createConnector(body) {
    await delay();
    return store.createConnector(body);
  },
  async deleteConnector(connectorId) {
    await delay();
    return store.deleteConnector(connectorId);
  },
  async listSsoConnectors() {
    await delay();
    return store.listSsoConnectors();
  },
  async createSsoConnector(body) {
    await delay();
    return store.createSsoConnector(body);
  },
  async deleteSsoConnector(connectorId) {
    await delay();
    return store.deleteSsoConnector(connectorId);
  },
  async getSignInExperience() {
    await delay();
    return store.getSignInExperience();
  },
  async updateSignInExperience(body) {
    await delay();
    return store.updateSignInExperience(body);
  },
  async listWebhooks() {
    await delay();
    return store.listWebhooks();
  },
  async createWebhook(body) {
    await delay();
    return store.createWebhook(body);
  },
  async updateWebhook(webhookId, body) {
    await delay();
    return store.updateWebhook(webhookId, body);
  },
  async rotateWebhookSecret(webhookId) {
    await delay();
    return store.rotateWebhookSecret(webhookId);
  },
  async deleteWebhook(webhookId) {
    await delay();
    return store.deleteWebhook(webhookId);
  },
  async listWebhookDeliveries(webhookId) {
    await delay();
    return store.listWebhookDeliveries(webhookId);
  },
  async listMembers() {
    await delay();
    return store.listMembers();
  },
  async listOrgEmailDomains(org) {
    await delay();
    return store.listOrgEmailDomains(org);
  },
  async addOrgEmailDomain(org, body) {
    await delay();
    return store.addOrgEmailDomain(org, body);
  },
  async removeOrgEmailDomain(org, domain) {
    await delay();
    return store.removeOrgEmailDomain(org, domain);
  },
  async listOrgInvitations(org) {
    await delay();
    return store.listOrgInvitations(org);
  },
  async createOrgInvitation(org, body) {
    await delay();
    return store.createOrgInvitation(org, body);
  },
  async revokeOrgInvitation(org, invitationId) {
    await delay();
    return store.revokeOrgInvitation(org, invitationId);
  },
  async addMember(_org, body) {
    await delay();
    return store.addMember(body);
  },
  async listOrgRoles() {
    await delay();
    return store.listOrgRoles();
  },
  async createOrgRole(_org, body) {
    await delay();
    return store.createOrgRole(body);
  },
  async updateOrgRole(_org, roleId, body) {
    await delay();
    return store.updateOrgRole(roleId, body);
  },
  async deleteOrgRole(_org, roleId) {
    await delay();
    return store.deleteOrgRole(roleId);
  },
  async listMemberRoles(_org, accountId) {
    await delay();
    return store.listMemberRoles(accountId);
  },
  async assignMemberRole(_org, accountId, body) {
    await delay();
    return store.assignMemberRole(accountId, body);
  },
  async unassignMemberRole(_org, accountId, roleId) {
    await delay();
    return store.unassignMemberRole(accountId, roleId);
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
