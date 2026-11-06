// The pure helpers, not the barrel: the mock is loaded by `bun test`, and the barrel drags every
// Vue SFC into a process that never renders one.
import { isKnownWebhookEvent } from "@monaca/ui/components/domain/audit.ts";
import { jwkThumbprintHex, publicEcJwk } from "@monaca/ui/lib/thumbprint.ts";

import { unknownPlaceholder } from "@/lib/placeholders";
import { newId } from "@/lib/typed-id";

import { ApiError, type MonacaApi } from "./contract";
import {
  DEFAULT_ORG,
  EMAIL_TEMPLATE_DEFAULTS,
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
  seedEmailTemplates,
  seedMemberRoleIndexes,
  seedMembers,
  seedOrgInvitations,
  seedOrgRoles,
  seedResources,
  seedSignInCopy,
  seedSignInExperience,
  seedSsoConnectors,
  seedTenantRoles,
  verifyLog,
  type AuditLog,
  type SeededEmailDomain,
  type SeededOrgInvitation,
} from "./fixtures";
import type {
  AccountDeletion,
  AccountRole,
  AccountDetail,
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
  Branding,
  BrandingPatch,
  Client,
  ClientSecret,
  Connector,
  CreateAccountRequest,
  CreateAgentRequest,
  CreateApiResourceRequest,
  CreateClientRequest,
  CreateConnectorRequest,
  UpdateConnectorRequest,
  CreateGrantRequest,
  CreateOrganizationRequest,
  CreateOrgInvitationRequest,
  CreateOrgRoleRequest,
  CreateSsoConnectorRequest,
  CreateTenantRoleRequest,
  CreateWebhookRequest,
  CreatedClient,
  CreatedWebhook,
  CaptchaPatch,
  DeliveryConnector,
  EmailTemplate,
  Grant,
  ListAccountsQuery,
  ListAuditQuery,
  Member,
  MessageTemplate,
  Organization,
  OrganizationEmailDomain,
  OrganizationInvitation,
  OrgRoleDetail,
  Page,
  RateLimits,
  RegisterAgentKeyRequest,
  RevokedSessions,
  SessionInfo,
  SignInCopy,
  SignInExperience,
  SsoConnector,
  Tenant,
  TenantRole,
  UpdateAccountRequest,
  UpdateApiResourceRequest,
  UpdateClientRequest,
  UpdateDeliveryConnectorRequest,
  UpdateEmailTemplateRequest,
  UpdateMessageTemplateRequest,
  UpdateOrganizationRequest,
  UpdateOrgRoleRequest,
  UpdateRateLimitsRequest,
  UpdateSignInCopyRequest,
  UpdateSignInExperienceRequest,
  UpdateTenantRequest,
  UpdateTenantRoleRequest,
  UpdateUsageRequest,
  UpdateWebhookRequest,
  Usage,
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
  /** Tenant and client gate overrides; the four defaults are built into the document. */
  private rateLimitItems: RateLimits["items"] = [];
  /** The tenant's language and custom copy; only the default is listed until one is added. */
  private signInCopy: SignInCopy = seedSignInCopy();
  /** One row per mail purpose; a default is what the server would send without a tenant override. */
  private emailTemplates: EmailTemplate[] = seedEmailTemplates();
  /** The optional hosted-page look; absent values fall back to the built-in style. */
  private branding: Branding = {
    display_name: null,
    logo_url: null,
    dark_logo_url: null,
    favicon_url: null,
    primary_color: null,
    terms_url: null,
    privacy_url: null,
    support_email: null,
    website_url: null,
    custom_css: null,
  };
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
  /** The tenant lifecycle state the console can archive/reactivate. */
  private tenantState: Tenant["state"] = "active";
  private usageQuota: number | null = null;
  private usageLogins = 3;
  private deliveryConnectors: Record<"email" | "sms", DeliveryConnector> = {
    email: {
      channel: "email",
      configured: false,
      provider: null,
      endpoint: null,
      from_address: null,
      from_name: null,
      secret_set: false,
      enabled: false,
      updated_at: null,
    },
    sms: {
      channel: "sms",
      configured: false,
      provider: null,
      endpoint: null,
      from_address: null,
      from_name: null,
      secret_set: false,
      enabled: false,
      updated_at: null,
    },
  };
  private messageTemplates: MessageTemplate[] = [];
  /** account id → the tenant role ids it holds. A role may be held by many accounts. */
  private accountRoles = new Map<string, Set<string>>();
  /** account id → its lowercase sign-in username, when one is set. */
  private accountUsernames = new Map<string, string>();
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
    this.seedMessageTemplates();
  }

  /** The mock's message catalogue: the English email rows plus one SMS verification purpose. */
  private seedMessageTemplates(): void {
    for (const template of this.emailTemplates) {
      this.messageTemplates.push({
        purpose: template.purpose,
        channel: "email",
        locale: "en",
        subject: template.subject,
        body: template.body,
        variables: [...template.variables],
        customized: template.customized,
        updated_at: template.updated_at,
      });
    }
    this.messageTemplates.push({
      purpose: "sms_verification",
      channel: "sms",
      locale: "en",
      subject: null,
      body: "Your {{tenant}} code is {{code}}.",
      variables: ["tenant", "code", "expires_in"],
      customized: false,
      updated_at: null,
    });
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
      management: "full",
      roles: this.tenantRoles
        .filter((role) => this.accountRoles.get(admin.id)?.has(role.id) === true)
        .map((role) => ({ id: role.id, name: role.name, permissions: [...role.permissions] })),
      is_tenant_admin: true,
    };
  }

  getTenant(): Tenant {
    return {
      id: `ten_${TENANT}`,
      slug: TENANT,
      state: this.tenantState,
      issuer: `http://localhost:8080/t/${TENANT}`,
    };
  }

  async updateTenant(body: UpdateTenantRequest): Promise<Tenant> {
    if (body.state !== "active" && body.state !== "archived") {
      throw new ApiError("state must be active or archived", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (this.tenantState !== body.state) {
      const action = body.state === "archived" ? "tenant.archived" : "tenant.reactivated";
      const from = this.tenantState;
      this.tenantState = body.state;
      await this.append({
        action,
        actor: this.session().account_id,
        subjectType: "tenant",
        subjectId: TENANT,
        decision: "allow",
        payload: { from, to: body.state },
      });
    }
    return this.getTenant();
  }

  getUsage(): Usage {
    const total = this.accounts.length;
    return {
      users: {
        total,
        quota: this.usageQuota,
        remaining: this.usageQuota === null ? null : Math.max(this.usageQuota - total, 0),
        enforcement: "reject",
      },
      daily: {
        date: new Date().toISOString().slice(0, 10),
        active_accounts: Math.min(total, 3),
        logins: this.usageLogins,
        timezone: "UTC",
      },
      updated_at: new Date().toISOString(),
    };
  }

  updateUsage(body: UpdateUsageRequest): Usage {
    if (body.max_accounts !== null && (!Number.isInteger(body.max_accounts) || body.max_accounts < 0)) {
      throw new ApiError("max_accounts must be a non-negative integer or null", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    this.usageQuota = body.max_accounts;
    return this.getUsage();
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
    const corsAllowedOrigins = normaliseOrigins(body.cors_allowed_origins ?? []);

    const client: Client = {
      id: newId("cli"),
      client_id: clientId,
      name,
      kind: body.kind,
      token_auth_method: body.kind === "confidential" ? "client_secret_basic" : "none",
      scopes,
      redirect_uris: redirectUris,
      post_logout_redirect_uris: postLogout,
      cors_allowed_origins: corsAllowedOrigins,
      custom_css: null,
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
    const corsAllowedOrigins =
      body.cors_allowed_origins === undefined
        ? client.cors_allowed_origins
        : normaliseOrigins(body.cors_allowed_origins);

    // §6.2: an empty string clears the application's style; an absent field leaves it alone.
    let customCss = client.custom_css;
    if (body.custom_css !== undefined) {
      const trimmed = body.custom_css.trim();
      if ([...trimmed].length > 20_000) {
        throw new ApiError("custom_css must be at most 20000 characters", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      customCss = trimmed === "" ? null : trimmed;
    }

    const updated: Client = {
      ...client,
      name,
      scopes,
      redirect_uris: redirectUris,
      post_logout_redirect_uris: postLogout,
      cors_allowed_origins: corsAllowedOrigins,
      custom_css: customCss,
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
      avatar_url: null,
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

  getAccount(accountId: string): AccountDetail {
    parseAccountId(accountId);
    const account = this.accounts.find((candidate) => candidate.id === accountId);
    if (!account) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    return {
      ...account,
      roles: this.rolesFor(account.id),
      username: this.accountUsernames.get(account.id) ?? null,
    };
  }

  async updateAccount(accountId: string, body: UpdateAccountRequest): Promise<AccountDetail> {
    parseAccountId(accountId);
    if (
      body.state === undefined &&
      body.display_name === undefined &&
      body.username === undefined &&
      body.avatar_url === undefined
    ) {
      throw new ApiError(
        "nothing to update; send `state`, `display_name`, `username` and/or `avatar_url`",
        {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        },
      );
    }
    if (body.state !== undefined && body.state !== "active" && body.state !== "disabled") {
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

    const displayName = body.display_name?.trim();
    if (displayName !== undefined && (displayName.length === 0 || displayName.length > 80)) {
      throw new ApiError("display_name must be 1-80 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    let username: string | undefined;
    if (body.username !== undefined) {
      username = body.username.trim().toLowerCase();
      if (!/^[a-z0-9_-]{3,32}$/.test(username)) {
        throw new ApiError("username is 3-32 letters, digits, `_` or `-`", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      const held = [...this.accountUsernames.entries()].find(
        ([other, value]) => value === username && other !== account.id,
      );
      if (held !== undefined) {
        throw new ApiError("username is already taken", {
          status: 409,
          code: "MONACA_USERNAME_TAKEN",
        });
      }
    }
    let avatarUrl: string | null | undefined;
    if (body.avatar_url !== undefined) {
      const trimmed = body.avatar_url.trim();
      if (
        trimmed !== "" &&
        (!/^https?:\/\/[^\s]+$/.test(trimmed) || [...trimmed].length > 2048)
      ) {
        throw new ApiError("avatar_url must be an absolute http(s) URL or empty", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      avatarUrl = trimmed === "" ? null : trimmed;
    }

    if (body.state !== undefined && account.state !== body.state) {
      if (body.state === "disabled") {
        // Suspension revokes every live session; "suspended" has to mean signed out everywhere.
        this.sessions = this.sessions.filter((session) => session.account_id !== account.id);
      }
    }

    const updated = {
      ...account,
      state: body.state ?? account.state,
      display_name: displayName ?? account.display_name,
      avatar_url: avatarUrl === undefined ? account.avatar_url : avatarUrl,
    };
    this.accounts = [...this.accounts.slice(0, index), updated, ...this.accounts.slice(index + 1)];

    if (body.state !== undefined && account.state !== body.state) {
      await this.append({
        action: body.state === "disabled" ? "account.suspended" : "account.reactivated",
        actor: this.session().account_id,
        subjectType: "account",
        subjectId: account.id,
        decision: "info",
        payload: { email: account.email },
      });
    }
    const changed: string[] = [];
    const profile: Record<string, unknown> = { email: account.email };
    if (displayName !== undefined && displayName !== account.display_name) {
      changed.push("display_name");
      profile["display_name"] = displayName;
    }
    if (username !== undefined && username !== this.accountUsernames.get(account.id)) {
      this.accountUsernames.set(account.id, username);
      changed.push("username");
      profile["username"] = username;
    }
    if (avatarUrl !== undefined && avatarUrl !== account.avatar_url) {
      changed.push("avatar_url");
      profile["avatar_url"] = avatarUrl;
    }
    if (changed.length > 0) {
      await this.append({
        action: "account.updated",
        actor: this.session().account_id,
        subjectType: "account",
        subjectId: account.id,
        decision: "allow",
        payload: { ...profile, fields: changed },
      });
    }

    return {
      ...updated,
      roles: this.rolesFor(account.id),
      username: this.accountUsernames.get(account.id) ?? null,
    };
  }

  async deleteAccount(accountId: string, confirm?: string): Promise<AccountDeletion> {
    parseAccountId(accountId);
    const account = this.accounts.find((candidate) => candidate.id === accountId);
    if (!account) {
      throw new ApiError("account not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const sessions = this.sessions.filter((session) => session.account_id === accountId).length;
    const result: AccountDeletion = {
      account_id: account.id,
      email: account.email,
      state: account.state,
      sessions,
      refresh_tokens: sessions * 2,
    };
    if (confirm === undefined) {
      return { ...result, dry_run: true, confirmation: `repeat DELETE with ?confirm=${account.email}` };
    }
    if (confirm.trim().toLowerCase() !== account.email.toLowerCase()) {
      throw new ApiError("the confirmation does not name this account", {
        status: 400,
        code: "MONACA_CONFIRMATION_REQUIRED",
      });
    }
    this.accounts = this.accounts.filter((candidate) => candidate.id !== accountId);
    this.sessions = this.sessions.filter((session) => session.account_id !== accountId);
    this.members = this.members.filter((member) => member.account_id !== accountId);
    this.accountRoles.delete(accountId);
    this.accountUsernames.delete(accountId);
    this.accountSecurity.delete(accountId);
    await this.append({
      action: "account.deleted",
      actor: this.session().account_id,
      subjectType: "account",
      subjectId: accountId,
      decision: "allow",
      payload: { email: account.email },
    });
    return result;
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

  async updateTenantRole(roleId: string, body: UpdateTenantRoleRequest): Promise<TenantRole> {
    parseRoleId(roleId);
    const role = this.tenantRoles.find((candidate) => candidate.id === roleId);
    if (!role) {
      throw new ApiError("role not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    if (body.name === undefined && body.description === undefined && body.permissions === undefined) {
      throw new ApiError("nothing to update", { status: 400, code: "MONACA_INVALID_REQUEST" });
    }
    const before = cloneTenantRole(role);
    if (body.name !== undefined) role.name = body.name.trim();
    if (body.description !== undefined) role.description = body.description.trim();
    if (body.permissions !== undefined) role.permissions = [...new Set(body.permissions)];
    role.updated_at = new Date().toISOString();
    await this.append({
      action: "role.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { id: role.id, from: before, to: cloneTenantRole(role) },
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
    const provider = body.provider ?? "generic";
    if (!["generic", "github", "google"].includes(provider)) {
      throw new ApiError("provider must be generic, github or google", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const linkPolicy = body.link_policy ?? "confirm_link";
    if (!["auto_link_verified_email", "confirm_link", "create_new_only"].includes(linkPolicy)) {
      throw new ApiError(
        "link_policy must be auto_link_verified_email, confirm_link or create_new_only",
        { status: 400, code: "MONACA_INVALID_REQUEST" },
      );
    }
    const preset = provider === "github"
      ? {
          authorize_url: "https://github.com/login/oauth/authorize",
          token_url: "https://github.com/login/oauth/access_token",
          userinfo_url: "https://api.github.com/user",
          scopes: ["read:user", "user:email"],
        }
      : provider === "google"
        ? {
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
            scopes: ["openid", "email", "profile"],
          }
        : null;
    if (preset === null) {
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
    for (const scope of preset?.scopes ?? body.scopes) {
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
      provider,
      display_name: displayName,
      enabled: body.enabled ?? true,
      link_policy: linkPolicy,
      authorize_url: preset?.authorize_url ?? body.authorize_url.trim(),
      token_url: preset?.token_url ?? body.token_url.trim(),
      userinfo_url: preset?.userinfo_url ?? body.userinfo_url.trim(),
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
      payload: {
        connector_id: connector.connector_id,
        provider: connector.provider,
        link_policy: connector.link_policy,
      },
    });
    return cloneConnector(connector);
  }

  async updateConnector(
    connectorId: string,
    body: UpdateConnectorRequest,
  ): Promise<Connector> {
    const index = this.connectors.findIndex((connector) => connector.connector_id === connectorId);
    const connector = this.connectors[index];
    if (!connector) {
      throw new ApiError("connector not found", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const displayName = body.display_name?.trim();
    if (displayName !== undefined && displayName.length === 0) {
      throw new ApiError("display_name must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (body.client_id !== undefined && body.client_id.trim().length === 0) {
      throw new ApiError("client_id must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (body.client_secret !== undefined && body.client_secret.length === 0) {
      throw new ApiError("client_secret must not be empty", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (connector.provider !== "generic" && body.scopes !== undefined) {
      throw new ApiError("a built-in provider owns its scopes", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (
      body.link_policy !== undefined &&
      !["auto_link_verified_email", "confirm_link", "create_new_only"].includes(body.link_policy)
    ) {
      throw new ApiError(
        "link_policy must be auto_link_verified_email, confirm_link or create_new_only",
        { status: 400, code: "MONACA_INVALID_REQUEST" },
      );
    }
    const updated: Connector = {
      ...connector,
      ...(displayName === undefined ? {} : { display_name: displayName }),
      ...(body.client_id === undefined ? {} : { client_id: body.client_id.trim() }),
      ...(body.scopes === undefined ? {} : { scopes: [...body.scopes] }),
      ...(body.enabled === undefined ? {} : { enabled: body.enabled }),
      ...(body.link_policy === undefined ? {} : { link_policy: body.link_policy }),
    };
    this.connectors = this.connectors.map((row, at) => (at === index ? updated : row));
    await this.append({
      action: "connector.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: {
        connector_id: updated.connector_id,
        provider: updated.provider,
        enabled: updated.enabled,
        link_policy: updated.link_policy,
      },
    });
    return cloneConnector(updated);
  }

  getDeliveryConnector(channel: "email" | "sms"): DeliveryConnector {
    return { ...this.deliveryConnectors[channel] };
  }

  async updateDeliveryConnector(
    channel: "email" | "sms",
    body: UpdateDeliveryConnectorRequest,
  ): Promise<DeliveryConnector> {
    if (body.provider.trim() === "" || body.endpoint.trim() === "" || body.from_address.trim() === "") {
      throw new ApiError("provider, endpoint and from_address are required", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const current = this.deliveryConnectors[channel];
    const next: DeliveryConnector = {
      channel,
      configured: true,
      provider: body.provider.trim(),
      endpoint: body.endpoint.trim(),
      from_address: body.from_address.trim(),
      from_name: body.from_name?.trim() || null,
      secret_set: body.secret === undefined ? current.secret_set : body.secret.trim() !== "",
      enabled: body.enabled ?? true,
      updated_at: new Date().toISOString(),
    };
    this.deliveryConnectors[channel] = next;
    await this.append({
      action: channel === "email" ? "email_connector.updated" : "sms_connector.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { channel, provider: next.provider, enabled: next.enabled },
    });
    return { ...next };
  }

  async deleteDeliveryConnector(channel: "email" | "sms"): Promise<void> {
    this.deliveryConnectors[channel] = {
      channel,
      configured: false,
      provider: null,
      endpoint: null,
      from_address: null,
      from_name: null,
      secret_set: false,
      enabled: false,
      updated_at: null,
    };
    await this.append({
      action: channel === "email" ? "email_connector.deleted" : "sms_connector.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { channel },
    });
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
    return {
      ...this.experience,
      captcha: { ...this.experience.captcha },
      branding: { ...this.experience.branding },
    };
  }

  getRateLimits(): RateLimits {
    return {
      defaults: [
        { endpoint: "authorize", limit: 600, window_secs: 60 },
        { endpoint: "token", limit: 600, window_secs: 60 },
        { endpoint: "userinfo", limit: 1200, window_secs: 60 },
        { endpoint: "management", limit: 600, window_secs: 60 },
      ],
      items: this.rateLimitItems.map((item) => ({ ...item })),
      ip: { limit: 600, window_secs: 60, scope: "per address (IPv6: /64), per server instance" },
      status: [],
    };
  }

  async updateRateLimits(body: UpdateRateLimitsRequest): Promise<RateLimits> {
    this.rateLimitItems = body.items.map((item) => ({
      endpoint: item.endpoint,
      client_id: item.client_id ?? null,
      limit: item.limit,
      window_secs: item.window_secs,
    }));
    return this.getRateLimits();
  }

  async updateSignInExperience(body: UpdateSignInExperienceRequest): Promise<SignInExperience> {
    // §6.2: an empty patch is a mistake, not a no-op — it says the caller meant to change something.
    if (
      body.sign_up_enabled === undefined &&
      body.password_sign_in_enabled === undefined &&
      body.email_code_sign_in_enabled === undefined &&
      body.passkey_sign_in_enabled === undefined &&
      body.single_sign_on_enabled === undefined &&
      body.mfa_enabled === undefined &&
      body.mfa_policy === undefined &&
      body.mfa_trusted_devices_enabled === undefined &&
      body.mfa_trusted_device_ttl_days === undefined &&
      body.password_min_length === undefined &&
      body.password_min_character_types === undefined &&
      body.password_reject_user_info === undefined &&
      body.password_reject_repetition_and_sequence === undefined &&
      body.password_rejected_words === undefined &&
      body.session_ttl_secs === undefined &&
      body.refresh_token_ttl_secs === undefined &&
      body.sign_up_identifiers === undefined &&
      body.sign_up_email_verification_required === undefined &&
      body.username_case_sensitive === undefined &&
      body.username_min_length === undefined &&
      body.username_max_length === undefined &&
      body.username_allowed_punctuation === undefined &&
      body.username_allow_email_local_part === undefined &&
      body.username_preserve_case === undefined &&
      body.username_reserved_words === undefined &&
      body.sign_up_profile_fields === undefined &&
      (body.captcha === undefined || captchaPatchIsEmpty(body.captcha)) &&
      body.login_lockout_threshold === undefined &&
      body.login_lockout_duration_secs === undefined &&
      (body.branding === undefined || brandingPatchIsEmpty(body.branding))
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
    if (
      body.password_min_character_types !== undefined &&
      !(body.password_min_character_types >= 1 && body.password_min_character_types <= 4)
    ) {
      throw new ApiError("password_min_character_types must be between 1 and 4", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (
      body.mfa_trusted_device_ttl_days !== undefined &&
      !(body.mfa_trusted_device_ttl_days >= 1 && body.mfa_trusted_device_ttl_days <= 365)
    ) {
      throw new ApiError("mfa_trusted_device_ttl_days must be between 1 and 365", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (body.sign_up_identifiers !== undefined) {
      const identifiers = body.sign_up_identifiers;
      if (
        identifiers.length === 0 ||
        !identifiers.includes("email") ||
        identifiers.some((identifier) => identifier !== "email" && identifier !== "username")
      ) {
        throw new ApiError(
          "sign_up_identifiers must be a non-empty subset of email, username that contains email",
          { status: 400, code: "MONACA_INVALID_REQUEST" },
        );
      }
    }
    if (body.username_allowed_punctuation !== undefined) {
      const allowed = body.username_allowed_punctuation;
      if (
        allowed.length > 3 ||
        allowed.some(
          (punctuation, index) =>
            !["_", "-", "."].includes(punctuation) || allowed.slice(0, index).includes(punctuation),
        )
      ) {
        throw new ApiError(
          "username_allowed_punctuation may only contain a unique subset of _, - and .",
          { status: 400, code: "MONACA_INVALID_REQUEST" },
        );
      }
    }
    if (
      body.sign_up_profile_fields !== undefined &&
      body.sign_up_profile_fields.some((field) => field !== "name" && field !== "avatar")
    ) {
      throw new ApiError("sign_up_profile_fields may only name name or avatar", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (body.captcha !== undefined) {
      const captcha = body.captcha;
      if (
        captcha.provider !== undefined &&
        captcha.provider !== "turnstile" &&
        captcha.provider !== "recaptcha" &&
        captcha.provider !== "hcaptcha" &&
        captcha.provider !== "cap"
      ) {
        throw new ApiError("captcha.provider must be turnstile, recaptcha, hcaptcha or cap", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      if (captcha.site_key !== undefined && captcha.site_key.trim().length > 200) {
        throw new ApiError("captcha.site_key must be at most 200 characters", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      if (captcha.base_url !== undefined && captcha.base_url.trim() !== "") {
        const url = captcha.base_url.trim();
        const authority = url.split("://")[1]?.split(/[/?#]/)[0] ?? "";
        if (!/^https?:\/\/[^\s]+$/.test(url) || authority.includes("@") || url.length > 500) {
          throw new ApiError(
            "captcha.base_url must be an absolute http(s) URL of at most 500 characters without credentials",
            { status: 400, code: "MONACA_INVALID_REQUEST" },
          );
        }
      }
      if (captcha.secret !== undefined && captcha.secret.trim().length > 500) {
        throw new ApiError("captcha.secret must be at most 500 characters", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }
    for (const [field, value, min, max] of [
      ["login_lockout_threshold", body.login_lockout_threshold, 0, 100],
      ["login_lockout_duration_secs", body.login_lockout_duration_secs, 30, 86_400],
    ] as const) {
      if (value !== undefined && !(value >= min && value <= max)) {
        throw new ApiError(`${field} must be between ${min} and ${max}`, {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }
    const usernameMin = body.username_min_length ?? this.experience.username_min_length;
    const usernameMax = body.username_max_length ?? this.experience.username_max_length;
    if (usernameMin < 3 || usernameMax > 32 || usernameMin > usernameMax) {
      throw new ApiError("username lengths must be 3–32 characters and min must not exceed max", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const usernameCaseSensitive =
      body.username_case_sensitive ?? this.experience.username_case_sensitive;
    const usernamePreserveCase =
      body.username_preserve_case ?? this.experience.username_preserve_case;
    if (usernameCaseSensitive && usernamePreserveCase) {
      throw new ApiError("username_preserve_case requires username_case_sensitive to be false", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const usernameReservedWords =
      body.username_reserved_words === undefined
        ? undefined
        : normaliseUsernameReservedWords(body.username_reserved_words);
    const rejectedWords =
      body.password_rejected_words === undefined
        ? undefined
        : normaliseRejectedWords(body.password_rejected_words);
    if (body.branding !== undefined) checkBrandingPatch(body.branding);
    for (const [field, value, min, max] of [
      ["session_ttl_secs", body.session_ttl_secs, 3_600, 7_776_000],
      ["refresh_token_ttl_secs", body.refresh_token_ttl_secs, 3_600, 31_536_000],
    ] as const) {
      if (value !== undefined && !(value >= min && value <= max)) {
        throw new ApiError(`${field} must be between ${min} and ${max}`, {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
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
    // Enabling a challenge without both halves of the provider configuration would strand every
    // gated visitor; the resulting state is checked before the write.
    const captcha: SignInExperience["captcha"] = {
      ...this.experience.captcha,
      ...(body.captcha?.enabled === undefined ? {} : { enabled: body.captcha.enabled }),
      ...(body.captcha?.provider === undefined ? {} : { provider: body.captcha.provider }),
      ...(body.captcha?.site_key === undefined
        ? {}
        : { site_key: body.captcha.site_key.trim() || null }),
      ...(body.captcha?.base_url === undefined
        ? {}
        : { base_url: body.captcha.base_url.trim() || null }),
      ...(body.captcha?.secret === undefined
        ? {}
        : { secret_set: body.captcha.secret.trim().length > 0 }),
      ...(body.captcha?.on_sign_in === undefined ? {} : { on_sign_in: body.captcha.on_sign_in }),
      ...(body.captcha?.on_sign_up === undefined ? {} : { on_sign_up: body.captcha.on_sign_up }),
      ...(body.captcha?.on_password_reset === undefined
        ? {}
        : { on_password_reset: body.captcha.on_password_reset }),
    };
    if (captcha.enabled && (captcha.site_key === null || !captcha.secret_set)) {
      throw new ApiError("captcha.enabled requires a site key and a secret", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (captcha.enabled && captcha.provider === "cap" && captcha.base_url === null) {
      throw new ApiError("captcha.enabled with cap requires a base URL", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    if (body.branding !== undefined) {
      this.branding = {
        ...this.branding,
        ...normaliseBrandingPatch(body.branding),
      };
    }

    const updated: SignInExperience = {
      sign_up_enabled: body.sign_up_enabled ?? this.experience.sign_up_enabled,
      password_sign_in_enabled: password,
      email_code_sign_in_enabled: emailCode,
      passkey_sign_in_enabled:
        body.passkey_sign_in_enabled ?? this.experience.passkey_sign_in_enabled,
      single_sign_on_enabled:
        body.single_sign_on_enabled ?? this.experience.single_sign_on_enabled,
      mfa_enabled: mfaEnabled,
      mfa_policy: mfaPolicy,
      mfa_trusted_devices_enabled:
        body.mfa_trusted_devices_enabled ?? this.experience.mfa_trusted_devices_enabled,
      mfa_trusted_device_ttl_days:
        body.mfa_trusted_device_ttl_days ?? this.experience.mfa_trusted_device_ttl_days,
      password_min_length:
        body.password_min_length ?? this.experience.password_min_length,
      password_min_character_types:
        body.password_min_character_types ?? this.experience.password_min_character_types,
      password_reject_user_info:
        body.password_reject_user_info ?? this.experience.password_reject_user_info,
      password_reject_repetition_and_sequence:
        body.password_reject_repetition_and_sequence ??
        this.experience.password_reject_repetition_and_sequence,
      password_rejected_words:
        rejectedWords ?? this.experience.password_rejected_words,
      session_ttl_secs: body.session_ttl_secs ?? this.experience.session_ttl_secs,
      refresh_token_ttl_secs:
        body.refresh_token_ttl_secs ?? this.experience.refresh_token_ttl_secs,
      sign_up_identifiers:
        body.sign_up_identifiers ?? this.experience.sign_up_identifiers,
      sign_up_email_verification_required:
        body.sign_up_email_verification_required ??
        this.experience.sign_up_email_verification_required,
      username_case_sensitive: usernameCaseSensitive,
      username_min_length: usernameMin,
      username_max_length: usernameMax,
      username_allowed_punctuation:
        body.username_allowed_punctuation === undefined
          ? [...this.experience.username_allowed_punctuation]
          : [...body.username_allowed_punctuation],
      username_allow_email_local_part:
        body.username_allow_email_local_part ??
        this.experience.username_allow_email_local_part,
      username_preserve_case: usernamePreserveCase,
      username_reserved_words:
        usernameReservedWords ?? [...this.experience.username_reserved_words],
      sign_up_profile_fields:
        body.sign_up_profile_fields ?? this.experience.sign_up_profile_fields,
      captcha,
      login_lockout_threshold:
        body.login_lockout_threshold ?? this.experience.login_lockout_threshold,
      login_lockout_duration_secs:
        body.login_lockout_duration_secs ?? this.experience.login_lockout_duration_secs,
      branding: { ...this.branding },
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
        passkey_sign_in_enabled: updated.passkey_sign_in_enabled,
        single_sign_on_enabled: updated.single_sign_on_enabled,
        mfa_enabled: updated.mfa_enabled,
        mfa_policy: updated.mfa_policy,
        mfa_trusted_devices_enabled: updated.mfa_trusted_devices_enabled,
        mfa_trusted_device_ttl_days: updated.mfa_trusted_device_ttl_days,
        password_min_length: updated.password_min_length,
        password_min_character_types: updated.password_min_character_types,
        password_reject_user_info: updated.password_reject_user_info,
        password_reject_repetition_and_sequence:
          updated.password_reject_repetition_and_sequence,
        password_rejected_words: updated.password_rejected_words,
        session_ttl_secs: updated.session_ttl_secs,
        refresh_token_ttl_secs: updated.refresh_token_ttl_secs,
        sign_up_identifiers: updated.sign_up_identifiers,
        sign_up_email_verification_required: updated.sign_up_email_verification_required,
        username_case_sensitive: updated.username_case_sensitive,
        username_min_length: updated.username_min_length,
        username_max_length: updated.username_max_length,
        username_allowed_punctuation: updated.username_allowed_punctuation,
        username_allow_email_local_part: updated.username_allow_email_local_part,
        username_preserve_case: updated.username_preserve_case,
        username_reserved_words: updated.username_reserved_words,
        sign_up_profile_fields: updated.sign_up_profile_fields,
        captcha: { ...updated.captcha },
        login_lockout_threshold: updated.login_lockout_threshold,
        login_lockout_duration_secs: updated.login_lockout_duration_secs,
        branding: { ...updated.branding },
      },
    });
    return { ...updated, branding: { ...updated.branding } };
  }

  getSignInCopy(): SignInCopy {
    return {
      default_language: this.signInCopy.default_language,
      languages: this.signInCopy.languages.map((entry) => ({
        language: entry.language,
        phrases: { ...entry.phrases },
      })),
    };
  }

  /** The complete replacement set for one language; an emptied set removes the language. */
  async updateSignInCopy(body: UpdateSignInCopyRequest): Promise<SignInCopy> {
    if (body.default_language === undefined && body.phrases === undefined) {
      throw new ApiError("at least one of default_language or phrases must be present", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    const defaultLanguage =
      body.default_language === undefined ? null : normaliseLanguage(body.default_language);
    if (body.default_language !== undefined && defaultLanguage === null) {
      throw new ApiError("default_language must be a BCP 47 language tag", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }

    let editedLanguage: string | null = null;
    let phraseCount: number | null = null;
    const stored = new Map<string, Map<string, string>>(
      this.signInCopy.languages.map((entry) => [
        entry.language,
        new Map(Object.entries(entry.phrases)),
      ]),
    );
    if (body.phrases !== undefined) {
      if (body.language === undefined) {
        throw new ApiError("language is required when phrases are present", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      const language = normaliseLanguage(body.language);
      if (language === null) {
        throw new ApiError("language must be a BCP 47 language tag", {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      const entries = Object.entries(body.phrases);
      if (entries.length > MAX_PHRASES) {
        throw new ApiError(`at most ${MAX_PHRASES} phrases may be stored for one language`, {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
      const phrases = new Map<string, string>();
      for (const [rawKey, rawValue] of entries) {
        const key = rawKey.trim();
        if (!validPhraseKey(key)) {
          throw new ApiError("phrase keys must be dotted camelCase segments, such as signIn.title", {
            status: 400,
            code: "MONACA_INVALID_REQUEST",
          });
        }
        const value = (rawValue ?? "").trim();
        if (value.length === 0) continue;
        if (value.length > MAX_PHRASE_CHARS) {
          throw new ApiError(`phrase values must be at most ${MAX_PHRASE_CHARS} characters`, {
            status: 400,
            code: "MONACA_INVALID_REQUEST",
          });
        }
        phrases.set(key, value);
      }
      stored.set(language, phrases);
      editedLanguage = language;
      phraseCount = phrases.size;
    }

    const nextDefault = defaultLanguage ?? this.signInCopy.default_language;
    // The default is always listed even with no overrides; another language only when it has copy.
    const languages = [...stored.entries()]
      .filter(([language, phrases]) => language === nextDefault || phrases.size > 0)
      .map(([language, phrases]) => ({
        language,
        phrases: Object.fromEntries(phrases),
      }))
      .sort((left, right) => (left.language < right.language ? -1 : 1));
    if (!languages.some((entry) => entry.language === nextDefault)) {
      languages.push({ language: nextDefault, phrases: {} });
      languages.sort((left, right) => (left.language < right.language ? -1 : 1));
    }
    this.signInCopy = { default_language: nextDefault, languages };

    await this.append({
      action: "sign_in_copy.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: {
        default_language: nextDefault,
        language: editedLanguage,
        phrase_count: phraseCount,
      },
    });
    return this.getSignInCopy();
  }

  listEmailTemplates(): Page<EmailTemplate> {
    return { items: this.emailTemplates.map(copyEmailTemplate), next: null };
  }

  async updateEmailTemplate(
    purpose: string,
    body: UpdateEmailTemplateRequest,
  ): Promise<EmailTemplate> {
    const template = this.emailTemplates.find((row) => row.purpose === purpose);
    if (!template) {
      throw new ApiError("unknown mail purpose", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    const subject = body.subject.trim();
    const copy = body.body.trim();
    if (subject.length === 0 || [...subject].length > 200) {
      throw new ApiError("subject must be 1–200 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (copy.length === 0 || [...copy].length > 10_000) {
      throw new ApiError("body must be 1–10000 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    for (const [field, text] of [
      ["subject", subject],
      ["body", copy],
    ] as const) {
      const unknown = unknownPlaceholder(text, template.variables);
      if (unknown !== undefined) {
        throw new ApiError(`${field}: unknown placeholder {{${unknown}}}`, {
          status: 400,
          code: "MONACA_INVALID_REQUEST",
        });
      }
    }

    template.subject = subject;
    template.body = copy;
    template.customized = true;
    template.updated_at = new Date().toISOString();
    await this.append({
      action: "email_template.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { purpose, subject, body: copy },
    });
    return copyEmailTemplate(template);
  }

  listMessageTemplates(channel?: "email" | "sms"): Page<MessageTemplate> {
    const items = [...this.messageTemplates]
      .filter((row) => channel === undefined || row.channel === channel)
      .sort(
        (left, right) =>
          left.purpose.localeCompare(right.purpose) || left.locale.localeCompare(right.locale),
      )
      .map(cloneMessageTemplate);
    return { items, next: null };
  }

  async updateMessageTemplate(
    purpose: string,
    locale: string,
    body: UpdateMessageTemplateRequest,
  ): Promise<MessageTemplate> {
    const template = this.messageTemplates.find(
      (row) => row.purpose === purpose && row.locale === locale,
    );
    if (!template) {
      throw new ApiError("unknown message template", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    template.subject = body.subject;
    template.body = body.body;
    template.customized = true;
    template.updated_at = new Date().toISOString();
    await this.append({
      action: "message_template.updated",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { purpose, locale, subject: body.subject, body: body.body },
    });
    return cloneMessageTemplate(template);
  }

  async deleteMessageTemplate(purpose: string, locale: string): Promise<void> {
    const template = this.messageTemplates.find(
      (row) => row.purpose === purpose && row.locale === locale,
    );
    if (!template) {
      throw new ApiError("unknown message template", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    template.customized = false;
    template.updated_at = null;
    await this.append({
      action: "message_template.deleted",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { purpose, locale },
    });
  }

  async restoreMessageTemplate(purpose: string, locale: string): Promise<MessageTemplate> {
    const template = this.messageTemplates.find(
      (row) => row.purpose === purpose && row.locale === locale,
    );
    if (!template) {
      throw new ApiError("unknown message template", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    template.customized = false;
    template.updated_at = null;
    await this.append({
      action: "message_template.restored",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "allow",
      payload: { purpose, locale },
    });
    return cloneMessageTemplate(template);
  }

  async resetEmailTemplate(purpose: string): Promise<void> {
    const index = this.emailTemplates.findIndex((row) => row.purpose === purpose);
    const template = this.emailTemplates[index];
    if (!template) {
      throw new ApiError("unknown mail purpose", { status: 404, code: "MONACA_NOT_FOUND" });
    }
    // A default purpose has nothing to drop; resetting it is already the requested state.
    if (!template.customized) return;
    const fallback = EMAIL_TEMPLATE_DEFAULTS.find((row) => row.purpose === purpose);
    if (fallback) {
      this.emailTemplates[index] = { ...fallback, variables: [...fallback.variables] };
    }
    await this.append({
      action: "email_template.reset",
      actor: this.session().account_id,
      subjectType: "tenant",
      subjectId: TENANT,
      decision: "info",
      payload: { purpose },
    });
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
    cors_allowed_origins: [...client.cors_allowed_origins],
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

/** Lowercase, trim and de-duplicate reserved usernames; each must be 3–64 characters. */
function normaliseUsernameReservedWords(words: string[]): string[] {
  if (words.length > 100) {
    throw new ApiError("username_reserved_words must list at most 100 words", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  const normalised: string[] = [];
  for (const word of words) {
    const value = word.trim().toLowerCase();
    if (value.length < 3 || value.length > 64) {
      throw new ApiError("each reserved username must be 3-64 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (!normalised.includes(value)) normalised.push(value);
  }
  return normalised;
}

/** Lowercase, de-duplicate and bound the rejected-word list, exactly like the server. */
function normaliseRejectedWords(words: string[]): string[] {
  if (words.length > 100) {
    throw new ApiError("password_rejected_words must list at most 100 words", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  const out: string[] = [];
  for (const word of words) {
    const normalised = word.trim().toLowerCase();
    if ([...normalised].length < 3 || [...normalised].length > 64) {
      throw new ApiError("each rejected word must be 3-64 characters", {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
    if (!out.includes(normalised)) out.push(normalised);
  }
  return out;
}

/** An empty branding object says nothing, which the server treats as an empty patch. */
function brandingPatchIsEmpty(patch: BrandingPatch): boolean {
  return Object.values(patch).every((value) => value === undefined);
}

function captchaPatchIsEmpty(patch: CaptchaPatch): boolean {
  return Object.values(patch).every((value) => value === undefined);
}

/** Non-empty values must be usable by the hosted page; an empty string clears a field. */
function checkBrandingPatch(patch: BrandingPatch): void {
  if (patch.display_name !== undefined && patch.display_name.trim().length > 64) {
    throw new ApiError("display_name must be at most 64 characters", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  for (const [field, value] of [
    ["logo_url", patch.logo_url],
    ["dark_logo_url", patch.dark_logo_url],
    ["favicon_url", patch.favicon_url],
    ["terms_url", patch.terms_url],
    ["privacy_url", patch.privacy_url],
    ["website_url", patch.website_url],
  ] as const) {
    if (value !== undefined && value.trim() !== "" && !/^https?:\/\/[^\s]+$/.test(value.trim())) {
      throw new ApiError(`${field} must be an absolute http(s) URL or empty`, {
        status: 400,
        code: "MONACA_INVALID_REQUEST",
      });
    }
  }
  if (
    patch.support_email !== undefined &&
    patch.support_email.trim() !== "" &&
    (!patch.support_email.includes("@") || /\s/.test(patch.support_email.trim()))
  ) {
    throw new ApiError("support_email must be an address or empty", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  if (
    patch.primary_color !== undefined &&
    patch.primary_color.trim() !== "" &&
    !/^#[0-9a-fA-F]{6}$/.test(patch.primary_color.trim())
  ) {
    throw new ApiError("primary_color must be `#rrggbb` or empty", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  if (patch.custom_css !== undefined && [...patch.custom_css.trim()].length > 20_000) {
    throw new ApiError("custom_css must be at most 20000 characters", {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
}

/** Trim what was sent; an empty string becomes `null`, the stored form of "unset". */
function normaliseBrandingPatch(patch: BrandingPatch): Partial<Branding> {
  const out: Partial<Branding> = {};
  for (const key of [
    "display_name",
    "logo_url",
    "dark_logo_url",
    "favicon_url",
    "primary_color",
    "terms_url",
    "privacy_url",
    "support_email",
    "website_url",
    "custom_css",
  ] as const) {
    const value = patch[key];
    if (value !== undefined) out[key] = value.trim() === "" ? null : value.trim();
  }
  return out;
}

function copyEmailTemplate(template: EmailTemplate): EmailTemplate {
  return { ...template, variables: [...template.variables] };
}

function cloneMessageTemplate(template: MessageTemplate): MessageTemplate {
  return { ...template, variables: [...template.variables] };
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

/** One application's origin cap — the server's `MAX_CORS_ORIGINS`, mirrored by schema 38. */
const MAX_CORS_ORIGINS = 32;

/**
 * Canonicalize one CORS origin to `scheme://host[:port]`, or `null` when it is not an origin —
 * the server's `normalise_origin`. `new URL` does the serialization (lowercased host, default
 * port omitted); the checks refuse what an origin is not: a path, query, fragment, userinfo or
 * wildcard.
 */
function normaliseOrigin(raw: string): string | null {
  const trimmed = raw.trim();
  if (!/^https?:\/\//.test(trimmed)) return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    return null;
  }
  return url.origin;
}

function normaliseOrigins(raw: readonly string[]): string[] {
  if (raw.length > MAX_CORS_ORIGINS) {
    throw new ApiError(`cors_allowed_origins accepts at most ${MAX_CORS_ORIGINS} origins`, {
      status: 400,
      code: "MONACA_INVALID_REQUEST",
    });
  }
  const origins: string[] = [];
  for (const origin of raw) {
    const normalized = normaliseOrigin(origin);
    if (normalized === null || normalized.length > 255) {
      throw new ApiError(
        "cors_allowed_origins must be origins of the form https://app.example.com — no path, query, fragment, userinfo or wildcard",
        { status: 400, code: "MONACA_INVALID_REQUEST" },
      );
    }
    if (!origins.includes(normalized)) origins.push(normalized);
  }
  return origins;
}

/** One language's override cap and longest value — the server's `MAX_PHRASES`/`MAX_PHRASE_CHARS`. */
const MAX_PHRASES = 200;
const MAX_PHRASE_CHARS = 500;

/**
 * A lowercased BCP 47-shaped tag: a 2–3 letter primary subtag, then 1–8 alphanumeric subtags —
 * the server's `normalise_language` and schema 39's column check.
 */
function normaliseLanguage(raw: string): string | null {
  const language = raw.trim().toLowerCase();
  if (language.length < 2 || language.length > 35) return null;
  const [primary, ...subtags] = language.split("-");
  if (primary === undefined || !/^[a-z]{2,3}$/.test(primary)) return null;
  if (subtags.some((subtag) => !/^[a-z0-9]{1,8}$/.test(subtag))) return null;
  return language;
}

/** A dotted key of 2–4 camelCase segments — the server's `valid_phrase_key`. */
function validPhraseKey(key: string): boolean {
  if (key.length < 3 || key.length > 100) return false;
  return /^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*){1,3}$/.test(key);
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
  async getTenant() {
    await delay();
    return store.getTenant();
  },
  async updateTenant(body) {
    await delay();
    return store.updateTenant(body);
  },
  async getUsage() {
    await delay();
    return store.getUsage();
  },
  async updateUsage(body) {
    await delay();
    return store.updateUsage(body);
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
  async getAccount(accountId) {
    await delay();
    return store.getAccount(accountId);
  },
  async updateAccount(accountId, body) {
    await delay();
    return store.updateAccount(accountId, body);
  },
  async deleteAccount(accountId, confirm) {
    await delay();
    return store.deleteAccount(accountId, confirm);
  },
  async listTenantRoles() {
    await delay();
    return store.listTenantRoles();
  },
  async createTenantRole(body) {
    await delay();
    return store.createTenantRole(body);
  },
  async updateTenantRole(roleId, body) {
    await delay();
    return store.updateTenantRole(roleId, body);
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
  async updateConnector(connectorId, body) {
    await delay();
    return store.updateConnector(connectorId, body);
  },
  async deleteConnector(connectorId) {
    await delay();
    return store.deleteConnector(connectorId);
  },
  async getDeliveryConnector(channel) {
    await delay();
    return store.getDeliveryConnector(channel);
  },
  async updateDeliveryConnector(channel, body) {
    await delay();
    return store.updateDeliveryConnector(channel, body);
  },
  async deleteDeliveryConnector(channel) {
    await delay();
    return store.deleteDeliveryConnector(channel);
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
  async getRateLimits() {
    await delay();
    return store.getRateLimits();
  },
  async updateRateLimits(body) {
    await delay();
    return store.updateRateLimits(body);
  },
  async updateSignInExperience(body) {
    await delay();
    return store.updateSignInExperience(body);
  },
  async getSignInCopy() {
    await delay();
    return store.getSignInCopy();
  },
  async updateSignInCopy(body) {
    await delay();
    return store.updateSignInCopy(body);
  },
  async listEmailTemplates() {
    await delay();
    return store.listEmailTemplates();
  },
  async updateEmailTemplate(purpose, body) {
    await delay();
    return store.updateEmailTemplate(purpose, body);
  },
  async resetEmailTemplate(purpose) {
    await delay();
    return store.resetEmailTemplate(purpose);
  },
  async listMessageTemplates(channel) {
    await delay();
    return store.listMessageTemplates(channel);
  },
  async updateMessageTemplate(purpose, locale, body) {
    await delay();
    return store.updateMessageTemplate(purpose, locale, body);
  },
  async deleteMessageTemplate(purpose, locale) {
    await delay();
    return store.deleteMessageTemplate(purpose, locale);
  },
  async restoreMessageTemplate(purpose, locale) {
    await delay();
    return store.restoreMessageTemplate(purpose, locale);
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
