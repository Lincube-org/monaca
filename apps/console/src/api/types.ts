/**
 * Wire types for the management API, transcribed from docs/contracts/m0.md §6.2 and §8.1.
 *
 * Names are the wire names (`snake_case`) deliberately: this layer's job is to describe what
 * crosses the socket, not to be idiomatic TypeScript. A camelCase view model belongs in the page
 * that needs one, so a contract change lands here as one obvious edit instead of a silent
 * translation mismatch.
 *
 * The console never talks to `/v1` directly — the BFF rewrites `/bff/api/*` to `/v1/*` and attaches
 * the session's bearer token, so these calls carry a cookie, not a token.
 */

/** Every list endpoint returns this envelope (§6.2); pass `?cursor=<next>` for the next page. */
export interface Page<T> {
  items: T[];
  next: string | null;
}

export interface Account {
  id: string;
  email: string;
  display_name: string;
  state: "active" | "disabled";
  created_at: string;
}

export interface Member {
  account_id: string;
  email: string;
  role: OrgRole;
}

/** An organization row (§6.2). Archived orgs stay listed; their slug stops resolving. */
export interface Organization {
  id: string;
  slug: string;
  state: "active" | "archived";
  is_default: boolean;
  created_at: string;
}

export type OrgRole = "owner" | "admin" | "member";

/**
 * An application — the protocol `client_id`, its credentials policy and where it may redirect.
 *
 * The secret is never part of this object: the server stores an argon2 hash and reveals the
 * plaintext exactly once, in the response to a create or a rotate (§6.2).
 */
export interface Client {
  id: string;
  client_id: string;
  name: string;
  kind: ClientKind;
  token_auth_method: "none" | "client_secret_basic";
  scopes: string[];
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  is_third_party: boolean;
  created_at: string;
}

export type ClientKind = "public" | "confidential";

/** A create response for a confidential client carries the new secret exactly once. */
export type CreatedClient = Client & { client_secret?: string };

/** The answer to a rotation; the previous secret stops authenticating at once. */
export interface ClientSecret {
  client_id: string;
  client_secret: string;
}

export interface AgentKey {
  id: string;
  kid: string;
  /** Lowercase hex sha256 of the canonical public JWK (RFC 7638). */
  fingerprint: string;
  created_at: string;
  revoked_at: string | null;
}

export interface Agent {
  id: string;
  org: string;
  name: string;
  description: string;
  owner_account_id: string;
  state: "active" | "disabled";
  keys: AgentKey[];
  created_at: string;
}

export interface Grant {
  id: string;
  org: string;
  agent_id: string;
  account_id: string;
  scopes: string[];
  resource: string;
  constraints: Record<string, unknown>;
  expires_at: string | null;
  revoked_at: string | null;
  created_by: string;
  created_at: string;
}

/** Audit list items are §8.1 plus the three chain fields (§5.7). */
export type {
  AuditActor,
  AuditChainHead,
  AuditEvent,
  AuditIntegrity,
  AuditSubject,
  AuditSubjectType,
} from "@monaca/ui";

export interface SessionInfo {
  authenticated: boolean;
  account_id: string;
  email: string;
  tenant: string;
  orgs: { slug: string; role: OrgRole }[];
}

// ---------------------------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------------------------

export interface CreateAgentRequest {
  name: string;
  description: string;
  owner_account_id: string;
}

export interface RegisterAgentKeyRequest {
  public_jwk: JsonWebKey;
  alg: "ES256";
  kid: string;
}

export interface CreateGrantRequest {
  agent_id: string;
  account_id: string;
  scopes: string[];
  resource: string;
  expires_at: string | null;
}

export interface AddMemberRequest {
  account_id: string;
  role: OrgRole;
}

export interface CreateOrganizationRequest {
  slug: string;
}

export interface UpdateOrganizationRequest {
  state: "active" | "archived";
}

export interface CreateClientRequest {
  client_id: string;
  name: string;
  kind: ClientKind;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: string[];
  is_third_party: boolean;
}

/** Absent fields are left alone; a supplied array replaces the stored set. */
export interface UpdateClientRequest {
  name?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  scopes?: string[];
}

export interface ListAuditQuery {
  limit?: number;
  before?: number;
  grant_id?: string;
  jti?: string;
  action?: string;
}

/**
 * RFC 9457 problem+json, the shape of every non-token error (§6.1). `monaca_error_code` is the
 * stable machine code; `title` is the only part safe to show a user unmodified.
 */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  monaca_error_code?: string;
}
