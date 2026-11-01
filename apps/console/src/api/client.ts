import { ApiError, type MonacaApi } from "./contract";
import type {
  AccountWithRoles,
  AddMemberRequest,
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
  CreatedClient,
  Grant,
  ListAccountsQuery,
  ListAuditQuery,
  Member,
  Organization,
  OrgRoleDetail,
  Page,
  ProblemDetails,
  RegisterAgentKeyRequest,
  SessionInfo,
  UpdateAccountRequest,
  UpdateApiResourceRequest,
  UpdateClientRequest,
  UpdateOrganizationRequest,
  UpdateOrgRoleRequest,
} from "./types";

/**
 * The real client: `/bff/api/*` on the gateway (docs/contracts/m0.md §9).
 *
 * Every call carries the session cookie and nothing else. The BFF holds the access token, refreshes
 * it when it has under 30 s left, and attaches it — so a browser token never exists and there is
 * nothing here to leak. A 401 means the session is gone, which is why `ApiError.isUnauthenticated`
 * exists: the shell turns that into a sign-in prompt rather than a retry button.
 */
const BFF_PREFIX = "/bff/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BFF_PREFIX}${path}`, {
      ...init,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...init?.headers,
      },
    });
  } catch (cause) {
    // A transport failure is not an HTTP status; say so plainly instead of inventing a 0.
    throw new ApiError("The gateway is unreachable", {
      status: 0,
      problem: { type: "about:blank", title: "The gateway is unreachable", status: 0, detail: String(cause) },
    });
  }

  if (response.status === 204) return undefined as T;

  if (!response.ok) {
    const problem = await readProblem(response);
    throw new ApiError(problem.title, { status: response.status, problem });
  }

  return (await response.json()) as T;
}

async function readProblem(response: Response): Promise<ProblemDetails> {
  const fallback: ProblemDetails = {
    type: "about:blank",
    title: response.statusText || `Request failed with ${response.status}`,
    status: response.status,
  };
  try {
    const body = (await response.json()) as Partial<ProblemDetails>;
    return { ...fallback, ...body };
  } catch {
    // A non-JSON error body (a proxy's HTML error page, most often) keeps the status and title.
    return fallback;
  }
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded.length > 0 ? `?${encoded}` : "";
}

export const httpApi: MonacaApi = {
  getSession(): Promise<SessionInfo> {
    return request<SessionInfo>("/session");
  },

  listOrganizations(): Promise<Page<Organization>> {
    return request<Page<Organization>>("/orgs");
  },

  createOrganization(body: CreateOrganizationRequest): Promise<Organization> {
    return request<Organization>("/orgs", { method: "POST", body: JSON.stringify(body) });
  },

  updateOrganization(organizationId: string, body: UpdateOrganizationRequest): Promise<Organization> {
    return request<Organization>(`/orgs/${encodeURIComponent(organizationId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  },

  listClients(): Promise<Page<Client>> {
    return request<Page<Client>>("/clients");
  },

  createClient(body: CreateClientRequest): Promise<CreatedClient> {
    return request<CreatedClient>("/clients", { method: "POST", body: JSON.stringify(body) });
  },

  updateClient(clientId: string, body: UpdateClientRequest): Promise<Client> {
    return request<Client>(`/clients/${encodeURIComponent(clientId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  },

  rotateClientSecret(clientId: string): Promise<ClientSecret> {
    return request<ClientSecret>(`/clients/${encodeURIComponent(clientId)}/secret`, { method: "POST" });
  },

  deleteClient(clientId: string): Promise<void> {
    return request<void>(`/clients/${encodeURIComponent(clientId)}`, { method: "DELETE" });
  },

  listResources(): Promise<Page<ApiResource>> {
    return request<Page<ApiResource>>("/resources");
  },

  createResource(body: CreateApiResourceRequest): Promise<ApiResource> {
    return request<ApiResource>("/resources", { method: "POST", body: JSON.stringify(body) });
  },

  updateResource(resourceId: string, body: UpdateApiResourceRequest): Promise<ApiResource> {
    return request<ApiResource>(`/resources/${encodeURIComponent(resourceId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  },

  deleteResource(resourceId: string): Promise<void> {
    return request<void>(`/resources/${encodeURIComponent(resourceId)}`, { method: "DELETE" });
  },

  listAccounts(params: ListAccountsQuery = {}): Promise<Page<AccountWithRoles>> {
    return request<Page<AccountWithRoles>>(
      `/accounts${query({ query: params.query, limit: params.limit })}`,
    );
  },

  createAccount(body: CreateAccountRequest): Promise<AccountWithRoles> {
    return request<AccountWithRoles>("/accounts", { method: "POST", body: JSON.stringify(body) });
  },

  updateAccount(accountId: string, body: UpdateAccountRequest): Promise<AccountWithRoles> {
    return request<AccountWithRoles>(`/accounts/${encodeURIComponent(accountId)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  },

  listConnectors(): Promise<Page<Connector>> {
    return request<Page<Connector>>("/connectors");
  },

  createConnector(body: CreateConnectorRequest): Promise<Connector> {
    return request<Connector>("/connectors", { method: "POST", body: JSON.stringify(body) });
  },

  deleteConnector(connectorId: string): Promise<void> {
    return request<void>(`/connectors/${encodeURIComponent(connectorId)}`, { method: "DELETE" });
  },

  listMembers(org: string): Promise<Page<Member>> {
    return request<Page<Member>>(`/orgs/${encodeURIComponent(org)}/members`);
  },

  addMember(org: string, body: AddMemberRequest): Promise<Member> {
    return request<Member>(`/orgs/${encodeURIComponent(org)}/members`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  listOrgRoles(org: string): Promise<Page<OrgRoleDetail>> {
    return request<Page<OrgRoleDetail>>(`/orgs/${encodeURIComponent(org)}/roles`);
  },

  createOrgRole(org: string, body: CreateOrgRoleRequest): Promise<OrgRoleDetail> {
    return request<OrgRoleDetail>(`/orgs/${encodeURIComponent(org)}/roles`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  updateOrgRole(org: string, roleId: string, body: UpdateOrgRoleRequest): Promise<OrgRoleDetail> {
    return request<OrgRoleDetail>(
      `/orgs/${encodeURIComponent(org)}/roles/${encodeURIComponent(roleId)}`,
      { method: "PATCH", body: JSON.stringify(body) },
    );
  },

  deleteOrgRole(org: string, roleId: string): Promise<void> {
    return request<void>(`/orgs/${encodeURIComponent(org)}/roles/${encodeURIComponent(roleId)}`, {
      method: "DELETE",
    });
  },

  listMemberRoles(org: string, accountId: string): Promise<Page<OrgRoleDetail>> {
    return request<Page<OrgRoleDetail>>(
      `/orgs/${encodeURIComponent(org)}/members/${encodeURIComponent(accountId)}/roles`,
    );
  },

  assignMemberRole(org: string, accountId: string, body: AssignOrgRoleRequest): Promise<void> {
    return request<void>(
      `/orgs/${encodeURIComponent(org)}/members/${encodeURIComponent(accountId)}/roles`,
      { method: "POST", body: JSON.stringify(body) },
    );
  },

  unassignMemberRole(org: string, accountId: string, roleId: string): Promise<void> {
    return request<void>(
      `/orgs/${encodeURIComponent(org)}/members/${encodeURIComponent(accountId)}/roles/${encodeURIComponent(roleId)}`,
      { method: "DELETE" },
    );
  },

  listAgents(org: string): Promise<Page<Agent>> {
    return request<Page<Agent>>(`/orgs/${encodeURIComponent(org)}/agents`);
  },

  createAgent(org: string, body: CreateAgentRequest): Promise<Agent> {
    return request<Agent>(`/orgs/${encodeURIComponent(org)}/agents`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  registerAgentKey(org: string, agentId: string, body: RegisterAgentKeyRequest): Promise<Agent> {
    // The server answers with the created key object (§6.2); the page needs the agent, so this
    // re-reads the agent. One extra round trip on a rare action buys a consistent shape.
    return request<unknown>(
      `/orgs/${encodeURIComponent(org)}/agents/${encodeURIComponent(agentId)}/keys`,
      { method: "POST", body: JSON.stringify(body) },
    ).then(() => request<Agent>(`/orgs/${encodeURIComponent(org)}/agents/${encodeURIComponent(agentId)}`));
  },

  revokeAgentKey(org: string, agentId: string, keyId: string): Promise<void> {
    return request<void>(
      `/orgs/${encodeURIComponent(org)}/agents/${encodeURIComponent(agentId)}/keys/${encodeURIComponent(keyId)}`,
      { method: "DELETE" },
    );
  },

  listGrants(org: string): Promise<Page<Grant>> {
    return request<Page<Grant>>(`/orgs/${encodeURIComponent(org)}/grants`);
  },

  createGrant(org: string, body: CreateGrantRequest): Promise<Grant> {
    return request<Grant>(`/orgs/${encodeURIComponent(org)}/grants`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  revokeGrant(org: string, grantId: string): Promise<void> {
    return request<void>(`/orgs/${encodeURIComponent(org)}/grants/${encodeURIComponent(grantId)}`, {
      method: "DELETE",
    });
  },

  listAudit(org: string, params: ListAuditQuery = {}): Promise<Page<AuditEvent>> {
    return request<Page<AuditEvent>>(
      `/orgs/${encodeURIComponent(org)}/audit${query({
        limit: params.limit,
        before: params.before,
        grant_id: params.grant_id,
        jti: params.jti,
        action: params.action,
      })}`,
    );
  },

  verifyAudit(org: string, from?: number, to?: number): Promise<AuditIntegrity> {
    return request<AuditIntegrity>(
      `/orgs/${encodeURIComponent(org)}/audit/verify${query({ from, to })}`,
    );
  },
};
