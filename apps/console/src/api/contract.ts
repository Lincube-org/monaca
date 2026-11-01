import type {
  AddMemberRequest,
  Agent,
  AssignOrgRoleRequest,
  AuditEvent,
  AuditIntegrity,
  Client,
  ClientSecret,
  CreateAgentRequest,
  CreateClientRequest,
  CreateGrantRequest,
  CreateOrganizationRequest,
  CreateOrgRoleRequest,
  CreatedClient,
  Grant,
  ListAuditQuery,
  Member,
  Organization,
  OrgRoleDetail,
  Page,
  ProblemDetails,
  RegisterAgentKeyRequest,
  SessionInfo,
  UpdateClientRequest,
  UpdateOrganizationRequest,
  UpdateOrgRoleRequest,
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

  listMembers(org: string): Promise<Page<Member>>;
  addMember(org: string, body: AddMemberRequest): Promise<Member>;

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
