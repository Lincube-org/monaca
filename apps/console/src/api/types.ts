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

/** A tenant-role reference carried by an account row; the role itself is `/v1/roles`. */
export interface AccountRole {
  id: string;
  name: string;
}

/**
 * An account as `/v1/accounts` returns it: the identity plus the tenant roles it holds.
 *
 * Org membership and org roles are separate — this list is the tenant-wide directory, not one
 * organization's members.
 */
export interface AccountWithRoles extends Account {
  roles: AccountRole[];
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
 * A named set of scopes defined inside one organization (§6.2).
 *
 * Distinct from the membership rank in `Member.role`: an org role grants scopes only while signing
 * into the org that defines it, and a member may hold any number of them. Deleting a role removes
 * every assignment of it.
 */
export interface OrgRoleDetail {
  id: string;
  name: string;
  description: string;
  scopes: string[];
  created_at: string;
}

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

/**
 * An API resource — an absolute `http(s)` indicator plus the scope names it publishes (§6.2).
 *
 * `authorize` refuses any non-standard scope a registered resource does not define, so this row is
 * what makes a custom scope requestable at all.
 */
export interface ApiResource {
  id: string;
  name: string;
  identifier: string;
  scopes: string[];
  created_at: string;
}

/**
 * A social sign-in provider (§6.2).
 *
 * The client secret is sealed at rest and never part of this object; the endpoints and the client
 * id are what the sign-in flow needs, and the sign-in page shows only the id and the display name.
 */
export interface Connector {
  connector_id: string;
  display_name: string;
  authorize_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  scopes: string[];
  created_at: string;
}

/**
 * The tenant's hosted sign-in switches (§6.2).
 *
 * The public page reads the same three booleans from `/t/{tenant}/sign-in-experience`; `updated_at`
 * is only on the management read. The server refuses a state where both password sign-in and email
 * codes are off, because that would leave no way to sign in at all.
 */
export interface SignInExperience {
  sign_up_enabled: boolean;
  password_sign_in_enabled: boolean;
  email_code_sign_in_enabled: boolean;
  updated_at: string;
}

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

export interface CreateOrgRoleRequest {
  name: string;
  description: string;
  scopes: string[];
}

/** Absent fields keep their value; a supplied array replaces the stored set. */
export interface UpdateOrgRoleRequest {
  name?: string;
  description?: string;
  scopes?: string[];
}

export interface AssignOrgRoleRequest {
  role_id: string;
}

export interface CreateApiResourceRequest {
  name: string;
  identifier: string;
  scopes: string[];
}

/** The identifier is fixed at registration; only the name and scopes may change. */
export interface UpdateApiResourceRequest {
  name?: string;
  scopes?: string[];
}

/**
 * Absent switches keep their value, so a page sends only what the user changed.
 *
 * The server rejects an empty patch, and any patch whose result turns both first-factor methods off.
 */
export interface UpdateSignInExperienceRequest {
  sign_up_enabled?: boolean;
  password_sign_in_enabled?: boolean;
  email_code_sign_in_enabled?: boolean;
}

export interface CreateConnectorRequest {
  connector_id: string;
  display_name: string;
  authorize_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
}

export interface ListAccountsQuery {
  /** Case-insensitive substring of the email or display name. */
  query?: string;
  limit?: number;
}

export interface CreateAccountRequest {
  email: string;
  display_name: string;
  password: string;
}

export interface UpdateAccountRequest {
  state: "active" | "disabled";
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
