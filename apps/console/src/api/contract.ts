import type {
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
  CreateOrgRoleRequest,
  CreateTenantRoleRequest,
  CreatedClient,
  Grant,
  ListAccountsQuery,
  ListAuditQuery,
  Member,
  Organization,
  OrganizationEmailDomain,
  OrgRoleDetail,
  Page,
  ProblemDetails,
  RegisterAgentKeyRequest,
  SessionInfo,
  SignInExperience,
  TenantRole,
  UpdateAccountRequest,
  UpdateApiResourceRequest,
  UpdateClientRequest,
  UpdateOrganizationRequest,
  UpdateOrgRoleRequest,
  UpdateSignInExperienceRequest,
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
  updateAccount(accountId: string, body: UpdateAccountRequest): Promise<AccountWithRoles>;

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

  /** Social sign-in providers, tenant-level; deleting one also drops every identity it linked. */
  listConnectors(): Promise<Page<Connector>>;
  createConnector(body: CreateConnectorRequest): Promise<Connector>;
  deleteConnector(connectorId: string): Promise<void>;

  /**
   * The hosted sign-in switches — the one tenant-level screen that changes what every application's
   * sign-in page offers. The public page reads the same values without a token.
   */
  getSignInExperience(): Promise<SignInExperience>;
  updateSignInExperience(body: UpdateSignInExperienceRequest): Promise<SignInExperience>;

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
