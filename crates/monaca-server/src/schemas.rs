//! Typed views for the curated `/v1` operations in `spec/openapi.json`.
//!
//! These are the response shapes the handlers actually build; the OpenAPI annotations name them,
//! and the SDK is generated from the same document. Only the operations a third party automates
//! are here on purpose — the rest keep their `SURFACE` summary until a consumer needs them.

use serde::Serialize;

/// A role reference embedded in an account row.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleRef {
    /// The `role_…` id.
    pub id: String,
    /// The role name.
    pub name: String,
}

/// `GET /v1/accounts` row and the `GET`/`PATCH` shapes.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AccountView {
    /// The `acc_…` id.
    pub id: String,
    /// The primary email.
    pub email: String,
    /// The display name.
    pub display_name: String,
    /// An absolute avatar URL, or `null`.
    pub avatar_url: Option<String>,
    /// `active` or `disabled`.
    pub state: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Roles assigned to the account.
    pub roles: Vec<RoleRef>,
}

/// The account detail shape; it also carries the sign-in username.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AccountDetailView {
    /// The `acc_…` id.
    pub id: String,
    /// The primary email.
    pub email: String,
    /// The display name.
    pub display_name: String,
    /// An absolute avatar URL, or `null`.
    pub avatar_url: Option<String>,
    /// `active` or `disabled`.
    pub state: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Roles assigned to the account.
    pub roles: Vec<RoleRef>,
    /// The sign-in username, or `null`.
    pub username: Option<String>,
}

/// `GET /v1/accounts`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AccountList {
    /// The matched accounts.
    pub items: Vec<AccountView>,
    /// Cursor for the next page; always `null` in M0.
    pub next: Option<String>,
}

/// `GET /v1/clients` row and the `GET`/`PATCH` shapes.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ClientView {
    /// The `cli_…` row id.
    pub id: String,
    /// The protocol client id used in authorize URLs.
    pub client_id: String,
    /// The application name.
    pub name: String,
    /// `public` or `confidential`.
    pub kind: String,
    /// `none` or `client_secret_basic`.
    pub token_auth_method: String,
    /// Scopes the application may request.
    pub scopes: Vec<String>,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// RP-initiated-logout targets.
    pub post_logout_redirect_uris: Vec<String>,
    /// Browser origins allowed to call the protocol endpoints.
    pub cors_allowed_origins: Vec<String>,
    /// Application CSS, or `null`.
    pub custom_css: Option<String>,
    /// Whether the consent screen is mandatory.
    pub is_third_party: bool,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `POST /v1/clients`; the secret appears only for a confidential client and only here.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreatedClientView {
    /// The `cli_…` row id.
    pub id: String,
    /// The protocol client id.
    pub client_id: String,
    /// The application name.
    pub name: String,
    /// `public` or `confidential`.
    pub kind: String,
    /// `none` or `client_secret_basic`.
    pub token_auth_method: String,
    /// Scopes the application may request.
    pub scopes: Vec<String>,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// RP-initiated-logout targets.
    pub post_logout_redirect_uris: Vec<String>,
    /// Browser origins allowed to call the protocol endpoints.
    pub cors_allowed_origins: Vec<String>,
    /// Application CSS, or `null`.
    pub custom_css: Option<String>,
    /// Whether the consent screen is mandatory.
    pub is_third_party: bool,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// The plaintext secret, returned once; absent for a public client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl CreatedClientView {
    /// The created row plus the one-time secret, in the same field order as the JSON it replaces.
    pub fn from_view(client: ClientView, client_secret: Option<String>) -> Self {
        Self {
            id: client.id,
            client_id: client.client_id,
            name: client.name,
            kind: client.kind,
            token_auth_method: client.token_auth_method,
            scopes: client.scopes,
            redirect_uris: client.redirect_uris,
            post_logout_redirect_uris: client.post_logout_redirect_uris,
            cors_allowed_origins: client.cors_allowed_origins,
            custom_css: client.custom_css,
            is_third_party: client.is_third_party,
            created_at: client.created_at,
            client_secret,
        }
    }
}

/// `GET /v1/clients`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ClientList {
    /// The applications.
    pub items: Vec<ClientView>,
    /// Cursor for the next page; always `null` in M0.
    pub next: Option<String>,
}

/// `GET /v1/clients/{client}/secret`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ClientSecretView {
    /// The protocol client id.
    pub client_id: String,
    /// The new plaintext secret, returned once.
    pub client_secret: String,
}

/// `GET /v1/orgs` row.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OrgView {
    /// The `org_…` id.
    pub id: String,
    /// The org slug.
    pub slug: String,
    /// `active` or `archived`.
    pub state: String,
    /// Whether this is the tenant's default org.
    pub is_default: bool,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /v1/orgs`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OrgList {
    /// The orgs.
    pub items: Vec<OrgView>,
    /// Cursor for the next page; always `null` in M0.
    pub next: Option<String>,
}

/// `GET /v1/roles` row.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleView {
    /// The `role_…` id.
    pub id: String,
    /// The role name.
    pub name: String,
    /// A free-form description.
    pub description: String,
    /// Permission scopes the role grants.
    pub permissions: Vec<String>,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 time of the last name, description or permission change.
    pub updated_at: String,
}

/// `GET /v1/roles`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleList {
    /// The roles.
    pub items: Vec<RoleView>,
    /// Cursor for the next page; always `null` in M0.
    pub next: Option<String>,
}

/// `GET /v1/connectors` row.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConnectorView {
    /// The connector slug.
    pub connector_id: String,
    /// `generic`, `github` or `google`.
    pub provider: String,
    /// The name shown on the sign-in page.
    pub display_name: String,
    /// Whether the connector is offered.
    pub enabled: bool,
    /// `auto_link_verified_email`, `confirm_link` or `create_new_only`.
    pub link_policy: String,
    /// The provider authorization endpoint.
    pub authorize_url: String,
    /// The provider token endpoint.
    pub token_url: String,
    /// The provider userinfo endpoint.
    pub userinfo_url: String,
    /// The provider client id.
    pub client_id: String,
    /// The scopes sent to the provider.
    pub scopes: Vec<String>,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /v1/connectors`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ConnectorList {
    /// The connectors.
    pub items: Vec<ConnectorView>,
    /// Cursor for the next page; always `null` in M0.
    pub next: Option<String>,
}

/// One user session in `GET /v1/accounts/{id}/sessions`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionView {
    /// The `ses_…` id.
    pub id: String,
    /// The owning account.
    pub account_id: String,
    /// The client the session was created for, or `null`.
    pub client_id: Option<String>,
    /// RFC 3339 issue time.
    pub issued_at: String,
    /// RFC 3339 expiry time.
    pub expires_at: String,
    /// RFC 3339 last-seen time.
    pub last_seen_at: String,
    /// The browser user agent, or `null`.
    pub user_agent: Option<String>,
}

/// `GET /v1/accounts/{id}/sessions`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionList {
    /// The active sessions.
    pub items: Vec<SessionView>,
    /// Cursor for the next page; always `null` in M0.
    pub next: Option<String>,
}

/// `DELETE /v1/accounts/{id}/sessions`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RevokedSessionsView {
    /// How many sessions were revoked.
    pub revoked: u64,
    /// How many live refresh tokens were revoked with them.
    pub refresh_revoked: u64,
}
