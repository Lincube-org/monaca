import type {
  AccountWithRoles,
  AccountDetail,
  AccountSession,
  AccountSecurity,
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
  UpdateConnectorRequest,
  CreateTenantRoleRequest,
  CreateWebhookRequest,
  CreatedClient,
  CreatedWebhook,
  EmailTemplate,
  Grant,
  ListAccountsQuery,
  ListAuditQuery,
  Member,
  Organization,
  OrganizationEmailDomain,
  OrganizationInvitation,
  OrgRoleDetail,
  Page,
  ProblemDetails,
  RegisterAgentKeyRequest,
  RevokedSessions,
  SessionInfo,
  SignInCopy,
  SignInExperience,
  SsoConnector,
  TenantRole,
  UpdateAccountRequest,
  UpdateApiResourceRequest,
  UpdateClientRequest,
  UpdateEmailTemplateRequest,
  UpdateOrganizationRequest,
  UpdateOrgRoleRequest,
  UpdateSignInCopyRequest,
  UpdateSignInExperienceRequest,
  UpdateWebhookRequest,
  Webhook,
  WebhookDelivery,
  WebhookSecret,
} from "./types";

/**
 * The management API, as the pages see it.
 *
 * One interface, two implementations (`client.ts` for the gateway, `mock.ts` for stage 0). Pages
 * depend on this and never on either — that is the whole point: when the server lands, the only
 * change is which object `api` is bound to.
 *
 * Paths are relative on purpose. The BFF rewrites `/bff/api/*` to `{MONACA_SERVER_URL}/v1/*` and
 * attaches the session's bearer token, so the browser never holds a token and never learns the
 * server's address (§9). `org` is an org **slug**, not an id — `/v1` has no `/t/{tenant}` prefix
 * because the tenant comes from the token's `tid` (§6.2).
 */
export interface MonacaApi {
  getSession(): Promise<SessionInfo>;

  /**
   * Organizations are tenant-level: unlike the pages below they are not scoped to the org switcher,
   * because this is the page that defines the orgs the switcher offers.
   */
  listOrganizations(): Promise<Page<Organization>>;
  createOrganization(body: CreateOrganizationRequest): Promise<Organization>;
  updateOrganization(organizationId: string, body: UpdateOrganizationRequest): Promise<Organization>;

  /**
   * Applications are tenant-level for the same reason organizations are: one `client_id` namespace
   * serves the whole tenant, and an org switcher must never appear to scope who can sign in.
   */
  listClients(): Promise<Page<Client>>;
  createClient(body: CreateClientRequest): Promise<CreatedClient>;
  updateClient(clientId: string, body: UpdateClientRequest): Promise<Client>;
  rotateClientSecret(clientId: string): Promise<ClientSecret>;
  deleteClient(clientId: string): Promise<void>;

  /**
   * API resources are tenant-level: the identifier is an audience the whole tenant's applications
   * may request, and its scopes are published once for all of them.
   */
  listResources(): Promise<Page<ApiResource>>;
  createResource(body: CreateApiResourceRequest): Promise<ApiResource>;
  updateResource(resourceId: string, body: UpdateApiResourceRequest): Promise<ApiResource>;
  deleteResource(resourceId: string): Promise<void>;

  /** The tenant-wide account directory; organization membership is a separate concept. */
  listAccounts(query?: ListAccountsQuery): Promise<Page<AccountWithRoles>>;
  createAccount(body: CreateAccountRequest): Promise<AccountWithRoles>;
  /** The detail read, which also names the sign-in username for the edit form. */
  getAccount(accountId: string): Promise<AccountDetail>;
  updateAccount(accountId: string, body: UpdateAccountRequest): Promise<AccountDetail>;

  /**
   * Tenant roles are what an account holds everywhere; organization roles are per-org and live
   * under `/orgs/{org}/roles`. A role is immutable once created, and deleting it also drops every
   * assignment.
   */
  listTenantRoles(): Promise<Page<TenantRole>>;
  createTenantRole(body: CreateTenantRoleRequest): Promise<TenantRole>;
  deleteTenantRole(roleId: string): Promise<void>;
  assignAccountRole(accountId: string, roleId: string): Promise<void>;
  unassignAccountRole(accountId: string, roleId: string): Promise<void>;

  /**
   * The account's live sign-in sessions. Revoking one signs that browser out; revoking all of them
   * is the tenant-wide "sign out everywhere" lever, and both append to the audit chain.
   */
  listAccountSessions(accountId: string): Promise<Page<AccountSession>>;
  revokeAccountSession(accountId: string, sessionId: string): Promise<void>;
  revokeAccountSessions(accountId: string): Promise<RevokedSessions>;

  /**
   * The account's enrolled second factors. An administrator may read the metadata and reset the
   * authenticator, but never a secret; passkeys are removed one at a time.
   */
  getAccountSecurity(accountId: string): Promise<AccountSecurity>;
  resetAccountMfa(accountId: string): Promise<void>;
  deleteAccountPasskey(accountId: string, passkeyId: string): Promise<void>;

  /** Social sign-in providers, tenant-level; deleting one also drops every identity it linked. */
  listConnectors(): Promise<Page<Connector>>;
  createConnector(body: CreateConnectorRequest): Promise<Connector>;
  updateConnector(connectorId: string, body: UpdateConnectorRequest): Promise<Connector>;
  deleteConnector(connectorId: string): Promise<void>;

  /**
   * Enterprise SSO identity providers, tenant-level like social connectors. A connector owns the
   * email domains whose sign-ins it federates, and its client secret is never returned.
   */
  listSsoConnectors(): Promise<Page<SsoConnector>>;
  createSsoConnector(body: CreateSsoConnectorRequest): Promise<SsoConnector>;
  deleteSsoConnector(connectorId: string): Promise<void>;

  /**
   * The hosted sign-in switches — the one tenant-level screen that changes what every application's
   * sign-in page offers. The public page reads the same values without a token.
   */
  getSignInExperience(): Promise<SignInExperience>;
  updateSignInExperience(body: UpdateSignInExperienceRequest): Promise<SignInExperience>;

  /**
   * The hosted page's language and custom copy. A phrase is addressed by the same dotted key the
   * page renders; an unknown key is stored but never shown. A patch replaces one language's whole
   * set, so omitted keys are deletions.
   */
  getSignInCopy(): Promise<SignInCopy>;
  updateSignInCopy(body: UpdateSignInCopyRequest): Promise<SignInCopy>;

  /**
   * The copy every outbox mail renders. A purpose without a tenant row answers the built-in
   * default with `customized: false`; resetting drops the row and restores that default.
   */
  listEmailTemplates(): Promise<Page<EmailTemplate>>;
  updateEmailTemplate(purpose: string, body: UpdateEmailTemplateRequest): Promise<EmailTemplate>;
  resetEmailTemplate(purpose: string): Promise<void>;

  /**
   * Outbound webhook subscriptions, tenant-level like the sign-in switches: one endpoint may
   * receive the events of the whole tenant. The signing key is returned once on creation and
   * again on rotation — a list never echoes it.
   */
  listWebhooks(): Promise<Page<Webhook>>;
  createWebhook(body: CreateWebhookRequest): Promise<CreatedWebhook>;
  updateWebhook(webhookId: string, body: UpdateWebhookRequest): Promise<Webhook>;
  rotateWebhookSecret(webhookId: string): Promise<WebhookSecret>;
  deleteWebhook(webhookId: string): Promise<void>;
  listWebhookDeliveries(webhookId: string): Promise<Page<WebhookDelivery>>;

  listMembers(org: string): Promise<Page<Member>>;
  addMember(org: string, body: AddMemberRequest): Promise<Member>;

  /**
   * The domains whose accounts join the org at sign-in, without an explicit membership.
   *
   * Organization-scoped like the member list: the same domain may not be registered to two orgs in
   * one tenant, and removing one stops future joins without touching existing members.
   */
  listOrgEmailDomains(org: string): Promise<Page<OrganizationEmailDomain>>;
  addOrgEmailDomain(org: string, body: AddOrgEmailDomainRequest): Promise<OrganizationEmailDomain>;
  removeOrgEmailDomain(org: string, domain: string): Promise<void>;

  /**
   * Pending invitations, which admit one address with one role at sign-in.
   *
   * Listing returns only live invitations: an accepted or expired one disappears from the page
   * without deleting the record that acceptance happened.
   */
  listOrgInvitations(org: string): Promise<Page<OrganizationInvitation>>;
  createOrgInvitation(org: string, body: CreateOrgInvitationRequest): Promise<OrganizationInvitation>;
  revokeOrgInvitation(org: string, invitationId: string): Promise<void>;

  /**
   * Org roles are scoped to the org in the path; the same member may hold different roles, and so
   * different scopes, in each organization. The membership rank is a separate concept.
   */
  listOrgRoles(org: string): Promise<Page<OrgRoleDetail>>;
  createOrgRole(org: string, body: CreateOrgRoleRequest): Promise<OrgRoleDetail>;
  updateOrgRole(org: string, roleId: string, body: UpdateOrgRoleRequest): Promise<OrgRoleDetail>;
  deleteOrgRole(org: string, roleId: string): Promise<void>;

  listMemberRoles(org: string, accountId: string): Promise<Page<OrgRoleDetail>>;
  assignMemberRole(org: string, accountId: string, body: AssignOrgRoleRequest): Promise<void>;
  unassignMemberRole(org: string, accountId: string, roleId: string): Promise<void>;

  listAgents(org: string): Promise<Page<Agent>>;
  createAgent(org: string, body: CreateAgentRequest): Promise<Agent>;
  registerAgentKey(org: string, agentId: string, body: RegisterAgentKeyRequest): Promise<Agent>;
  revokeAgentKey(org: string, agentId: string, keyId: string): Promise<void>;

  listGrants(org: string): Promise<Page<Grant>>;
  createGrant(org: string, body: CreateGrantRequest): Promise<Grant>;
  revokeGrant(org: string, grantId: string): Promise<void>;

  listAudit(org: string, query?: ListAuditQuery): Promise<Page<AuditEvent>>;
  verifyAudit(org: string, from?: number, to?: number): Promise<AuditIntegrity>;
}

/**
 * An error carrying the server's problem+json, so a page can show `title` and branch on
 * `monaca_error_code` without re-parsing a response.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly problem: ProblemDetails | undefined;

  constructor(message: string, options: { status: number; problem?: ProblemDetails; code?: string }) {
    super(message);
    this.name = "ApiError";
    this.status = options.status;
    this.problem = options.problem;
    this.code = options.code ?? options.problem?.monaca_error_code;
  }

  /** A 401 means the BFF session is gone; the console should offer a sign-in, not a retry. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }
}

/** Narrow an unknown throwable to something with a user-safe message. */
export function describeError(error: unknown): { title: string; detail?: string; code?: string } {
  if (error instanceof ApiError) {
    return { title: error.problem?.title ?? error.message, detail: error.problem?.detail, code: error.code };
  }
  if (error instanceof Error) return { title: error.message };
  return { title: String(error) };
}
