import { ApiError, type MonacaApi } from "./contract";
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
  ProblemDetails,
  RegisterAgentKeyRequest,
  SessionInfo,
  UpdateOrganizationRequest,
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

  listMembers(org: string): Promise<Page<Member>> {
    return request<Page<Member>>(`/orgs/${encodeURIComponent(org)}/members`);
  },

  addMember(org: string, body: AddMemberRequest): Promise<Member> {
    return request<Member>(`/orgs/${encodeURIComponent(org)}/members`, {
      method: "POST",
      body: JSON.stringify(body),
    });
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
