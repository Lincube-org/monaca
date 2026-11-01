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
 * A live sign-in session of an account (§6.2).
 *
 * `issued_at` is the authentication instant the id_token's `auth_time` mirrors, and `last_seen_at`
 * is when an authorize request last reused the session. Revoking one signs that browser out; the
 * listing endpoint only returns sessions that are neither revoked nor expired.
 */
export interface AccountSession {
  id: string;
  account_id: string;
  /** The client that established the session, when the server knows it. */
  client_id: string | null;
  issued_at: string;
  expires_at: string;
  last_seen_at: string;
  user_agent: string | null;
}

/** The answer to revoking every live session of an account. */
export interface RevokedSessions {
  revoked: number;
}

/** One enrolled passkey, as the account-security read reports it. */
export interface AccountPasskey {
  id: string;
  name: string | null;
  created_at: string;
  last_used_at: string | null;
}

/** The account's enrolled factors (§6.2). Secrets are never part of this object. */
export interface AccountSecurity {
  account_id: string;
  mfa: { totp: boolean; backup_codes: number };
  passkeys: AccountPasskey[];
  trusted_devices: number;
}

/**
 * A tenant role (§6.2) — a named permission set an account holds in every organization.
 *
 * Distinct from an organization role: this one is tenant-wide, its name is what the id_token's
 * `roles` claim carries, and it is immutable after creation (create, list and delete only).
 */
export interface TenantRole {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  created_at: string;
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

/** The detail shape, which also names the sign-in username (the list omits it). */
export interface AccountDetail extends AccountWithRoles {
  username: string | null;
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
 * An email domain registered to an organization (§6.2).
 *
 * An account whose primary email is at the domain joins the org automatically at sign-in. Domains
 * are stored lowercased and belong to at most one org in the tenant; removing one does not revoke
 * the memberships it already created.
 */
export interface OrganizationEmailDomain {
  domain: string;
  created_at: string;
}

/**
 * A pending invitation to join an organization (§6.2).
 *
 * There is no token to share: acceptance is the invited address's account signing in to the org,
 * and it joins with the role carried here. Accepted and expired invitations are not listed.
 */
export interface OrganizationInvitation {
  id: string;
  email: string;
  role: OrgRole;
  invited_by: string | null;
  created_at: string;
  expires_at: string;
}

/**
 * A tenant-level enterprise SSO connector (§6.2).
 *
 * The secret is never part of this object. A connector owns one or more email domains and routes
 * their sign-ins to its identity provider; deleting it also drops its pending sign-in states.
 */
export interface SsoConnector {
  connector_id: string;
  display_name: string;
  issuer: string;
  authorize_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  scopes: string[];
  email_domains: string[];
  created_at: string;
}

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
  /** Application CSS for the hosted page; `null` falls back to the tenant's. */
  custom_css: string | null;
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

/** The optional hosted-page look; `null` means the built-in style (§6.2). */
export interface Branding {
  display_name: string | null;
  logo_url: string | null;
  primary_color: string | null;
  terms_url: string | null;
  privacy_url: string | null;
  /** CSS appended after the built-in stylesheet; `null` keeps the built-in look. */
  custom_css: string | null;
}

/**
 * The tenant's hosted sign-in switches (§6.2).
 *
 * The public page reads the same booleans from `/t/{tenant}/sign-in-experience`; `updated_at`
 * is only on the management read. The server refuses a state where both password sign-in and email
 * codes are off, because that would leave no way to sign in at all, and a mandatory MFA policy with
 * MFA disabled, because that would demand an enrollment no page offers.
 */
export interface SignInExperience {
  sign_up_enabled: boolean;
  password_sign_in_enabled: boolean;
  email_code_sign_in_enabled: boolean;
  mfa_enabled: boolean;
  mfa_policy: "user_controlled" | "mandatory";
  /** The shortest password every entrance accepts, 8–64 characters. */
  password_min_length: number;
  /** How many character classes a password must use, 1–4. */
  password_min_character_types: number;
  /** Whether a password may not contain the account's email local part or username. */
  password_reject_user_info: boolean;
  /** Whether a password may not repeat a character or follow a sequence four times. */
  password_reject_repetition_and_sequence: boolean;
  /** Lowercased words a password may not contain. */
  password_rejected_words: string[];
  /** How long a browser session stays signed in, in seconds (3600–7776000). */
  session_ttl_secs: number;
  /** How long a refresh token stays usable, in seconds (3600–31536000). */
  refresh_token_ttl_secs: number;
  branding: Branding;
  updated_at: string;
}

/** A create response for a confidential client carries the new secret exactly once. */
export type CreatedClient = Client & { client_secret?: string };

/**
 * A tenant webhook subscription (§6.2).
 *
 * The signing key is deliberately absent: it is returned once on creation and once on rotation,
 * never by a list.
 */
export interface Webhook {
  /** `whk_…`. */
  id: string;
  url: string;
  events: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

/** A creation response carries the signing key the receiver must verify with. */
export type CreatedWebhook = Webhook & { secret: string };

/** The answer to a rotation; the previous key stops verifying at once. */
export interface WebhookSecret {
  id: string;
  secret: string;
}

/** The outcome of one delivery, after the last attempt (§6.2). */
export interface WebhookDelivery {
  /** `dlv_…`. */
  id: string;
  event: string;
  status_code: number | null;
  success: boolean;
  attempts: number;
  error: string | null;
  created_at: string;
}

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

/** A DNS name; the server lowercases it and rejects malformed values with a 400. */
export interface AddOrgEmailDomainRequest {
  domain: string;
}

/** `role` defaults to `member`; `expires_in_days` defaults to 7 and must be 1–90. */
export interface CreateOrgInvitationRequest {
  email: string;
  role?: OrgRole;
  expires_in_days?: number;
}

/** Empty `scopes` defaults to `openid profile email`; `email_domains` must name at least one. */
export interface CreateSsoConnectorRequest {
  connector_id: string;
  display_name: string;
  issuer: string;
  authorize_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  client_secret: string;
  scopes?: string[];
  email_domains: string[];
}

/** `permissions` is the wire name for the role's scope set; duplicates are dropped. */
export interface CreateTenantRoleRequest {
  name: string;
  description: string;
  permissions: string[];
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

/** A branding patch: absent fields keep their value, an empty string clears one. */
export interface BrandingPatch {
  display_name?: string;
  logo_url?: string;
  primary_color?: string;
  terms_url?: string;
  privacy_url?: string;
  custom_css?: string;
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
  mfa_enabled?: boolean;
  mfa_policy?: "user_controlled" | "mandatory";
  password_min_length?: number;
  password_min_character_types?: number;
  password_reject_user_info?: boolean;
  password_reject_repetition_and_sequence?: boolean;
  password_rejected_words?: string[];
  session_ttl_secs?: number;
  refresh_token_ttl_secs?: number;
  branding?: BrandingPatch;
}

/** An absolute http(s) endpoint and a non-empty set of subscribable actions. */
export interface CreateWebhookRequest {
  url: string;
  events: string[];
}

export interface UpdateWebhookRequest {
  url?: string;
  events?: string[];
  enabled?: boolean;
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

/** Any subset may be sent: `state` suspends/reactivates; profile fields edit the account. */
export interface UpdateAccountRequest {
  state?: "active" | "disabled";
  display_name?: string;
  username?: string;
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
  /** Application CSS; an empty string clears it. */
  custom_css?: string;
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
