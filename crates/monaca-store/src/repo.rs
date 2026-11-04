//! Row types and the queries the HTTP layer needs.
//!
//! Every tenant-level query is fully qualified (`tenant.accounts`) and every org-level query is
//! unqualified, because it runs inside [`crate::Store::begin_org`] with the org schema first on
//! the search_path (§5.1). The dynamic `{schema}` fragments below are built only from rows the
//! provisioner created and are validated before use.

use monaca_audit::{
    AuditActorType, AuditDecision, AuditEvent, AuditSubject, ChainFields, ChainHead, StoredEvent,
    VerifyReport, chain_hash, verify_chain,
};
use monaca_types::{AccountId, AgentId, GrantId, OrgId, RoleId, TypedId, WebhookId};
use serde_json::Value;
use sqlx::{FromRow, PgConnection};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provision::{OrgRow, TenantRow};
use crate::{Store, StoreError, q, quote_ident};

/// An account in `tenant.accounts`.
#[derive(Debug, Clone, FromRow)]
pub struct AccountRow {
    /// `accounts.id`.
    pub id: Uuid,
    /// Primary email, as entered.
    pub primary_email: String,
    /// Display name.
    pub display_name: String,
    /// An absolute http(s) avatar URL; absent keeps the built-in mark.
    pub avatar_url: Option<String>,
    /// `active` | `disabled`.
    pub state: String,
    /// Whether the account may be granted `monaca:admin`.
    pub is_tenant_admin: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

impl AccountRow {
    /// The account's typed id.
    pub fn account_id(&self) -> AccountId {
        AccountId::from_uuid(self.id)
    }
}

/// The tenant's hosted sign-in switches (§6.1 sign-in experience).
#[derive(Debug, Clone, FromRow)]
pub struct SignInExperienceRow {
    /// Whether self-service registration is offered.
    pub sign_up_enabled: bool,
    /// Whether the password form is offered.
    pub password_sign_in_enabled: bool,
    /// Whether emailed sign-in codes and links are offered.
    pub email_code_sign_in_enabled: bool,
    /// Whether passwordless passkey sign-in is offered.
    pub passkey_sign_in_enabled: bool,
    /// Whether enterprise SSO connectors are reachable from the hosted page.
    pub single_sign_on_enabled: bool,
    /// Whether second factors are used at sign-in at all.
    pub mfa_enabled: bool,
    /// `user_controlled` (an enrolled factor is challenged) | `mandatory` (everyone must enroll).
    pub mfa_policy: String,
    /// Whether a browser may be remembered past the second factor.
    pub mfa_trusted_devices_enabled: bool,
    /// How long a remembered browser keeps its trust, in days (1–365).
    pub mfa_trusted_device_ttl_days: i32,
    /// The shortest password every entrance accepts, in characters.
    pub password_min_length: i32,
    /// How many character classes (lowercase, uppercase, digits, symbols) a password must use.
    pub password_min_character_types: i32,
    /// Whether a password may not contain the account's own email local part or username.
    pub password_reject_user_info: bool,
    /// Whether a password may not repeat a character or follow a sequence for a run of four.
    pub password_reject_repetition_and_sequence: bool,
    /// Lowercased words a password may not contain.
    pub password_rejected_words: Vec<String>,
    /// How long a browser session stays signed in, in seconds.
    pub session_ttl_secs: i32,
    /// How long a refresh token stays usable, in seconds.
    pub refresh_token_ttl_secs: i32,
    /// The identifiers a new account may claim at sign-up (`email`, `username`).
    pub sign_up_identifiers: Vec<String>,
    /// Whether an address must be proved with an emailed code before the account exists.
    pub sign_up_email_verification_required: bool,
    /// Whether usernames keep their case and are compared exactly.
    pub username_case_sensitive: bool,
    /// The shortest accepted username, in characters.
    pub username_min_length: i32,
    /// The longest accepted username, in characters.
    pub username_max_length: i32,
    /// The punctuation characters allowed beside ASCII letters and digits (`_`, `-`, `.`).
    pub username_allowed_punctuation: Vec<String>,
    /// Whether a username may equal its account's email local part.
    pub username_allow_email_local_part: bool,
    /// Whether the typed case is kept in `display_value` while `value` stays lowercased.
    pub username_preserve_case: bool,
    /// Lowercased whole usernames the tenant refuses, at most 100.
    pub username_reserved_words: Vec<String>,
    /// The profile fields the sign-up form collects (`name`, `avatar`).
    pub sign_up_profile_fields: Vec<String>,
    /// The default language tag the hosted page announces and negotiates against.
    pub language: String,
    /// Whether a CAPTCHA challenge gates the entrances named below.
    pub captcha_enabled: bool,
    /// `turnstile` | `recaptcha` | `hcaptcha` | `cap`.
    pub captcha_provider: String,
    /// The provider's public site key; `null` until one is saved.
    pub captcha_site_key: Option<String>,
    /// The Cap instance's public base URL; `null` unless the provider is `cap`.
    pub captcha_cap_base_url: Option<String>,
    /// The provider's secret, sealed with the tenant DEK — never returned by any endpoint.
    pub captcha_secret_enc: Option<Vec<u8>>,
    /// Whether password sign-in demands a token.
    pub captcha_on_sign_in: bool,
    /// Whether sign-up demands a token.
    pub captcha_on_sign_up: bool,
    /// Whether password-reset code requests demand a token.
    pub captcha_on_password_reset: bool,
    /// Consecutive wrong passwords before the identifier is refused; zero disables the check.
    pub login_lockout_threshold: i32,
    /// How long a locked identifier stays refused, in seconds.
    pub login_lockout_duration_secs: i32,
    /// When the switches last changed.
    pub updated_at: OffsetDateTime,
}

/// One tenant override of a hosted-page phrase (§6.1 sign-in experience).
#[derive(Debug, Clone, FromRow)]
pub struct SignInPhraseRow {
    /// The lowercased BCP 47 tag the override belongs to.
    pub language: String,
    /// The dotted key the hosted page renders, such as `signIn.title`.
    pub phrase_key: String,
    /// The replacement text.
    pub value: String,
}

/// The failure counter for one normalised sign-in identifier (§6.1 lockout).
#[derive(Debug, Clone, FromRow)]
pub struct LoginFailureRow {
    /// Wrong passwords recorded since the last success or expiry.
    pub failures: i32,
    /// When the identifier may try again; `null` while it is still counting.
    pub locked_until: Option<OffsetDateTime>,
}

/// The CAPTCHA and lockout switches a `PATCH /v1/sign-in-experience` may change.
///
/// The nullable columns are double options: `None` keeps the column, `Some(None)` clears it and
/// `Some(Some(value))` writes it. That is how a write-only secret can be removed without an
/// empty-string sentinel reaching the cipher.
#[derive(Debug, Clone, Default)]
pub struct SignInGuardrailsPatch {
    /// Whether CAPTCHA is enforced.
    pub captcha_enabled: Option<bool>,
    /// `turnstile` | `recaptcha` | `hcaptcha` | `cap`.
    pub captcha_provider: Option<String>,
    /// The public site key.
    pub captcha_site_key: Option<Option<String>>,
    /// The Cap instance's public base URL.
    pub captcha_cap_base_url: Option<Option<String>>,
    /// The sealed provider secret.
    pub captcha_secret_enc: Option<Option<Vec<u8>>>,
    /// Whether password sign-in demands a token.
    pub captcha_on_sign_in: Option<bool>,
    /// Whether sign-up demands a token.
    pub captcha_on_sign_up: Option<bool>,
    /// Whether password-reset code requests demand a token.
    pub captcha_on_password_reset: Option<bool>,
    /// Wrong passwords before a lock; zero disables the lockout.
    pub login_lockout_threshold: Option<i32>,
    /// How long a lock lasts, in seconds.
    pub login_lockout_duration_secs: Option<i32>,
}

impl SignInGuardrailsPatch {
    /// Whether the patch names any field.
    pub fn is_empty(&self) -> bool {
        self.captcha_enabled.is_none()
            && self.captcha_provider.is_none()
            && self.captcha_site_key.is_none()
            && self.captcha_cap_base_url.is_none()
            && self.captcha_secret_enc.is_none()
            && self.captcha_on_sign_in.is_none()
            && self.captcha_on_sign_up.is_none()
            && self.captcha_on_password_reset.is_none()
            && self.login_lockout_threshold.is_none()
            && self.login_lockout_duration_secs.is_none()
    }
}

/// A tenant's optional hosted-page branding (§6.1, §6.2).
#[derive(Debug, Clone, FromRow)]
pub struct BrandingRow {
    /// A name shown instead of the tenant slug.
    pub display_name: Option<String>,
    /// An absolute http(s) logo URL.
    pub logo_url: Option<String>,
    /// An absolute http(s) logo URL used when the page is in dark mode.
    pub dark_logo_url: Option<String>,
    /// An absolute http(s) favicon URL.
    pub favicon_url: Option<String>,
    /// A `#rrggbb` primary colour.
    pub primary_color: Option<String>,
    /// Terms-of-service link.
    pub terms_url: Option<String>,
    /// Privacy-policy link.
    pub privacy_url: Option<String>,
    /// An address visitors can write to for help.
    pub support_email: Option<String>,
    /// The tenant's own website, linked from the hosted page.
    pub website_url: Option<String>,
    /// Tenant CSS appended after the built-in stylesheet.
    pub custom_css: Option<String>,
    /// When a branding field last changed.
    pub updated_at: OffsetDateTime,
}

/// A social (OAuth2) connector in `tenant.social_connectors` (§6.1).
#[derive(Debug, Clone, FromRow)]
pub struct SocialConnectorRow {
    /// Row id.
    pub id: Uuid,
    /// The slug the protocol and the page use, unique within the tenant.
    pub connector_id: String,
    /// `generic` | `github` | `google`; built-ins own the endpoints and field mapping.
    pub provider: String,
    /// Human-readable name shown on the sign-in page.
    pub display_name: String,
    /// Whether the connector is offered publicly and may complete a round-trip.
    pub enabled: bool,
    /// `auto_link_verified_email` | `confirm_link` | `create_new_only`.
    pub link_policy: String,
    /// The provider's authorization endpoint.
    pub authorize_url: String,
    /// The provider's token endpoint.
    pub token_url: String,
    /// The provider's userinfo endpoint.
    pub userinfo_url: String,
    /// The client id the tenant registered at the provider.
    pub client_id: String,
    /// The client secret, sealed by the caller (§5.6) — the store never sees plaintext.
    pub client_secret_enc: Vec<u8>,
    /// Scopes requested at the provider.
    pub scopes: Vec<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

/// One provider account linked to a Monaca account, joined with its connector's display name.
#[derive(Debug, Clone, FromRow)]
pub struct SocialIdentityRow {
    /// The connector slug.
    pub connector: String,
    /// The connector's display name.
    pub display_name: String,
    /// The provider's stable subject for this account.
    pub subject: String,
    /// The address the provider asserted when the link was created.
    pub email_at_link: Option<String>,
    /// When the identity was linked.
    pub linked_at: OffsetDateTime,
}

/// A pending social `state`, as the callback reads it (§6.1).
#[derive(Debug, Clone, FromRow)]
pub struct SocialStateRow {
    /// The connector the state was minted for.
    pub connector: String,
    /// `sign_in` | `link`.
    pub purpose: String,
    /// The interaction a sign-in state completes.
    pub interaction_id: Option<String>,
    /// The account a link state attaches to.
    pub account_id: Option<Uuid>,
    /// The sealed PKCE verifier minted with the state.
    pub code_verifier_enc: Option<Vec<u8>>,
    /// The OIDC nonce minted with the state, when the provider uses one.
    pub nonce: Option<String>,
}

/// A pending "link this provider identity to the account that owns the email" confirmation.
#[derive(Debug, Clone, FromRow)]
pub struct SocialLinkRequestRow {
    /// The opaque token handed to the hosted page.
    pub id: Uuid,
    /// The connector the provider identity belongs to.
    pub connector: String,
    /// The provider's stable subject.
    pub subject: String,
    /// The verified address the provider asserted.
    pub email: String,
    /// The existing account that owns the address.
    pub account_id: Uuid,
    /// The interaction the confirmed sign-in completes.
    pub interaction_id: String,
    /// When the confirmation expires.
    pub expires_at: OffsetDateTime,
}

/// An enterprise SSO (OIDC) connector in `tenant.sso_connectors` (§6.1).
#[derive(Debug, Clone, FromRow)]
pub struct SsoConnectorRow {
    /// Row id.
    pub id: Uuid,
    /// The slug the protocol and the page use, unique within the tenant.
    pub connector_id: String,
    /// Human-readable name shown on the sign-in page.
    pub display_name: String,
    /// The provider's issuer identifier, recorded for display and id_token validation.
    pub issuer: String,
    /// The provider's authorization endpoint.
    pub authorize_url: String,
    /// The provider's token endpoint.
    pub token_url: String,
    /// The provider's userinfo endpoint.
    pub userinfo_url: String,
    /// The client id the tenant registered at the provider.
    pub client_id: String,
    /// The client secret, sealed by the caller (§5.6) — the store never sees plaintext.
    pub client_secret_enc: Vec<u8>,
    /// Scopes requested at the provider.
    pub scopes: Vec<String>,
    /// The lowercased email domains whose sign-ins route here.
    pub email_domains: Vec<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

/// A pending enterprise SSO `state`, as the callback reads it (§6.1).
#[derive(Debug, Clone, FromRow)]
pub struct SsoStateRow {
    /// The connector the state was minted for.
    pub connector: String,
    /// The interaction the provider is authenticating for.
    pub interaction_id: String,
}

/// A tenant webhook subscription in `tenant.webhooks` (§6.2).
#[derive(Debug, Clone, FromRow)]
pub struct WebhookRow {
    /// Row id.
    pub id: Uuid,
    /// Absolute http(s) endpoint the deliveries are posted to.
    pub url: String,
    /// Audit action names this subscription receives.
    pub events: Vec<String>,
    /// The HMAC signing key, sealed by the caller (§5.6) — the store never sees plaintext.
    pub secret_enc: Vec<u8>,
    /// Whether deliveries are attempted at all.
    pub enabled: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// When the row last changed.
    pub updated_at: OffsetDateTime,
}

/// One delivery attempt summary in `tenant.webhook_deliveries` (§6.2).
#[derive(Debug, Clone, FromRow)]
pub struct WebhookDeliveryRow {
    /// Row id.
    pub id: Uuid,
    /// The subscription the event was sent to.
    pub webhook_id: Uuid,
    /// The audit action that fired the delivery.
    pub event: String,
    /// The last HTTP status the endpoint answered, if it answered.
    pub status_code: Option<i32>,
    /// Whether the endpoint accepted the event (any 2xx).
    pub success: bool,
    /// How many attempts the delivery took.
    pub attempts: i32,
    /// The last failure, when the endpoint refused or could not be reached.
    pub error: Option<String>,
    /// When the delivery finished.
    pub created_at: OffsetDateTime,
}

/// An RBAC role in `tenant.roles` (§6.2).
#[derive(Debug, Clone, FromRow)]
pub struct RoleRow {
    /// Row id; its typed form is the `rol_…` id the API uses.
    pub id: Uuid,
    /// The unique, human-readable name.
    pub name: String,
    /// Free-form description.
    pub description: String,
    /// The permission scopes the role grants.
    pub permissions: Vec<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

/// An arbitrary role in an org schema's `roles` table (§5.7).
///
/// Distinct from [`RoleRow`]: tenant roles grant scopes tenant-wide, organization roles grant them
/// only while signing into that organization.
#[derive(Debug, Clone, FromRow)]
pub struct OrgRoleRow {
    /// Row id; its typed form is the `rol_…` id the API uses.
    pub id: Uuid,
    /// The unique, human-readable name.
    pub name: String,
    /// Free-form description.
    pub description: String,
    /// The scopes this role grants within the org.
    pub scopes: Vec<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

impl OrgRoleRow {
    /// The role's typed id.
    pub fn role_id(&self) -> RoleId {
        RoleId::from_uuid(self.id)
    }
}

/// A registered API resource in `tenant.api_resources` (§6.2).
#[derive(Debug, Clone, FromRow)]
pub struct ApiResourceRow {
    /// Row id; its typed form is the `res_…` id the API uses.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// The resource indicator (an absolute `http(s)` URL).
    pub identifier: String,
    /// The scopes this resource defines.
    pub scopes: Vec<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

impl ApiResourceRow {
    /// The resource's typed id.
    pub fn resource_id(&self) -> monaca_types::ResourceId {
        monaca_types::ResourceId::from_uuid(self.id)
    }
}

/// A pending invitation to join an organization, in `tenant.organization_invitations` (§5.6).
#[derive(Debug, Clone, FromRow)]
pub struct OrgInvitationRow {
    /// Row id; its typed form is the `inv_…` id the API uses.
    pub id: Uuid,
    /// The invited address, lowercased.
    pub email: String,
    /// The role the account receives when the invitation is accepted.
    pub role: String,
    /// The administrator who issued it; `NULL` after that account is deleted.
    pub invited_by: Option<Uuid>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// The moment the invitation stops admitting its address.
    pub expires_at: OffsetDateTime,
}

impl OrgInvitationRow {
    /// The invitation's typed id.
    pub fn invitation_id(&self) -> monaca_types::OrgInvitationId {
        monaca_types::OrgInvitationId::from_uuid(self.id)
    }
}

impl RoleRow {
    /// The role's typed id.
    pub fn role_id(&self) -> monaca_types::RoleId {
        monaca_types::RoleId::from_uuid(self.id)
    }
}

/// A browser remembered past the second factor (§6.1).
#[derive(Debug, Clone, FromRow)]
pub struct TrustedDeviceRow {
    /// Row id; its typed form is the `mfd_…` id the account centre revokes.
    pub id: Uuid,
    /// The account the remembered browser signs in.
    pub account_id: Uuid,
    /// SHA-256 hex of the cookie value, never the value itself.
    pub token_hash: String,
    /// The browser's user agent, as the request carried it.
    pub user_agent: Option<String>,
    /// When the browser was remembered.
    pub created_at: OffsetDateTime,
    /// When it last skipped the second factor.
    pub last_used_at: Option<OffsetDateTime>,
    /// When the trust expires, whether or not it was revoked.
    pub expires_at: OffsetDateTime,
}

/// One recorded third-party approval in `tenant.consents`.
#[derive(Debug, Clone, FromRow)]
pub struct ConsentRow {
    /// The account that approved the application.
    pub account_id: Uuid,
    /// The client's row id.
    pub client_id: Uuid,
    /// The scopes the account approved.
    pub scopes: Vec<String>,
    /// `remember` or `one_shot`.
    pub kind: String,
    /// The `int_…` consent screen that recorded this row, when known.
    pub interaction_id: Option<String>,
    /// When the approval was first recorded.
    pub granted_at: OffsetDateTime,
    /// When the scopes were last refreshed.
    pub updated_at: OffsetDateTime,
}

/// A consent joined with the client it names, as the account centre lists it.
#[derive(Debug, Clone, FromRow)]
pub struct AuthorizedAppRow {
    /// The protocol `client_id` the application is known by.
    pub client_id: String,
    /// The application's display name.
    pub name: String,
    /// The scopes the account approved.
    pub scopes: Vec<String>,
    /// `remember` or `one_shot`.
    pub kind: String,
    /// When the approval was first recorded.
    pub granted_at: OffsetDateTime,
    /// When the approval was last refreshed.
    pub updated_at: OffsetDateTime,
}

/// One purpose's customised mail copy; a missing row means the built-in default.
#[derive(Debug, Clone, FromRow)]
pub struct EmailTemplateRow {
    /// The mail purpose the copy applies to.
    pub purpose: String,
    /// The subject line, with `{{variable}}` placeholders already allowed by the server.
    pub subject: String,
    /// The plain-text body.
    pub body: String,
    /// When the copy was last written.
    pub updated_at: OffsetDateTime,
}

/// The tenant's outbound mail route in `tenant.email_connector` (§6.3).
#[derive(Debug, Clone, FromRow)]
pub struct EmailConnectorRow {
    /// The delivery mechanism. `http` is the only provider; SMTP is a later increment.
    pub provider: String,
    /// The absolute http(s) endpoint each mail is posted to.
    pub endpoint: String,
    /// The envelope sender, e.g. `no-reply@example.com`.
    pub from_address: String,
    /// An optional display name for the sender.
    pub from_name: Option<String>,
    /// The bearer token, sealed by the caller — the store never sees plaintext.
    pub secret_enc: Option<Vec<u8>>,
    /// Whether delivery is attempted at all.
    pub enabled: bool,
    /// When the route last changed.
    pub updated_at: OffsetDateTime,
}

/// One claimable outbox mail row (§6.3).
#[derive(Debug, Clone, FromRow)]
pub struct OutboxMailRow {
    /// `outbox.id`, also sent to the provider so a retry can be de-duplicated.
    pub id: Uuid,
    /// The rendered mail payload.
    pub payload: Value,
    /// How many delivery attempts this row has now seen, including this claim.
    pub attempts: i32,
}

/// A client in `tenant.clients`.
#[derive(Debug, Clone, FromRow)]
pub struct ClientRow {
    /// Row id (`cli_…`).
    pub id: Uuid,
    /// The protocol `client_id`.
    pub client_id: String,
    /// Human-readable name.
    pub name: String,
    /// `public` | `confidential`.
    pub kind: String,
    /// argon2 PHC string; `NULL` for public clients.
    pub secret_hash: Option<String>,
    /// One of the four token endpoint auth methods.
    pub token_auth_method: String,
    /// Registered public keys for `private_key_jwt`.
    pub jwks: Option<Value>,
    /// Application-specific CSS for the hosted page; falls back to the tenant's.
    pub custom_css: Option<String>,
    /// Browser origins allowed to read this application's protocol responses.
    pub cors_allowed_origins: Vec<String>,
    /// Scopes this client may ask for.
    pub scopes: Vec<String>,
    /// A third-party application must show a consent screen.
    pub is_third_party: bool,
    /// When the application was registered.
    pub created_at: OffsetDateTime,
}

/// One signing key row.
#[derive(Debug, Clone, FromRow)]
pub struct SigningKeyRow {
    /// Row id; its typed form is the JWS `kid`.
    pub id: Uuid,
    /// Sealed PKCS#8 DER.
    pub private_enc: Vec<u8>,
    /// Public JWK, served verbatim.
    pub public_jwk: Value,
}

/// An authorization code, as stored.
#[derive(Debug, Clone, FromRow)]
pub struct AuthCodeRow {
    /// SHA-256 hex of the code.
    pub code_hash: String,
    /// Client row id.
    pub client_id: Uuid,
    /// Account row id.
    pub account_id: Uuid,
    /// Organization row id.
    pub org_id: Uuid,
    /// The redirect URI the code is bound to.
    pub redirect_uri: String,
    /// Granted scopes.
    pub scope: Vec<String>,
    /// PKCE S256 challenge.
    pub code_challenge: String,
    /// `nonce` to echo into the id_token.
    pub nonce: Option<String>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// The BFF session that signed in, when any.
    pub session_id: Option<Uuid>,
    /// DPoP key thumbprint the code is bound to, when the authorize request supplied `dpop_jkt`.
    pub dpop_jkt: Option<String>,
    /// When the user authenticated, echoed as the id_token's `auth_time`.
    pub auth_time: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// When it was redeemed.
    pub consumed_at: Option<OffsetDateTime>,
}

/// A refresh token, as stored.
#[derive(Debug, Clone, FromRow)]
pub struct RefreshRow {
    /// Row id.
    pub id: Uuid,
    /// SHA-256 hex of the token.
    pub token_hash: String,
    /// Client row id.
    pub client_id: Uuid,
    /// Account row id.
    pub account_id: Uuid,
    /// Organization row id.
    pub org_id: Uuid,
    /// Scope.
    pub scope: Vec<String>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
    /// The token this one replaced.
    pub rotated_from: Option<Uuid>,
    /// The rotation family; every descendant shares it.
    pub family_id: Option<Uuid>,
    /// DPoP key thumbprint this refresh token is bound to, if any.
    pub dpop_jkt: Option<String>,
    /// The original authentication instant, for the refreshed id_token.
    pub auth_time: OffsetDateTime,
    /// Issuance time, reported by introspection as `iat`.
    pub created_at: OffsetDateTime,
}

/// A stored pushed authorization request (RFC 9126).
#[derive(Debug, Clone, FromRow)]
pub struct ParRow {
    /// The client row the request was pushed for.
    pub client_id: Uuid,
    /// The validated authorize parameters.
    pub params: Value,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// When it was redeemed.
    pub consumed_at: Option<OffsetDateTime>,
}

/// A short-lived email verification code in `tenant.verification_codes`.
///
/// Only the SHA-256 hex of the code is stored; the row is single-use through `consumed_at`, and
/// `attempts` is the brute-force guard.
#[derive(Debug, Clone, FromRow)]
pub struct VerificationRow {
    /// Row id.
    pub id: Uuid,
    /// `sign_up` | `sign_in` | `password_reset`.
    pub purpose: String,
    /// The normalised (trimmed, lowercase) email address.
    pub identifier: String,
    /// SHA-256 hex of the code.
    pub code_hash: String,
    /// Failed verification attempts so far.
    pub attempts: i32,
    /// When the code stops being accepted.
    pub expires_at: OffsetDateTime,
    /// When it was successfully redeemed.
    pub consumed_at: Option<OffsetDateTime>,
    /// When it was issued.
    pub created_at: OffsetDateTime,
}

/// A sign-in session in `tenant.sessions`.
///
/// `issued_at` is the authentication instant (`auth_time`); `last_seen_at` is the last time an
/// authorize request reused the session, which is what `prompt`/`max_age` mean. The `ip` column
/// exists in the schema but is not read here: sqlx needs the `ipnetwork` feature to decode `inet`.
#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    /// Row id, carried as `ses_…` on the API and inside the SSO cookie.
    pub id: Uuid,
    /// The account that signed in.
    pub account_id: Uuid,
    /// The client that established the session, when known.
    pub client_id: Option<Uuid>,
    /// The authentication instant.
    pub issued_at: OffsetDateTime,
    /// When the session stops being usable.
    pub expires_at: OffsetDateTime,
    /// Revocation instant (`logout`, an admin revoke, or an account disable).
    pub revoked_at: Option<OffsetDateTime>,
    /// Last authorize request that reused it.
    pub last_seen_at: OffsetDateTime,
    /// The browser's `User-Agent`, for the sessions list.
    pub user_agent: Option<String>,
}

impl SessionRow {
    /// The session's typed id.
    pub fn session_id(&self) -> monaca_types::SessionId {
        monaca_types::SessionId::from_uuid(self.id)
    }

    /// Whether the row can still authenticate an authorize request at `now`.
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A WebAuthn credential in `tenant.credentials` with `kind = 'passkey'`.
///
/// `secret_enc` is the COSE public key sealed by the caller, like every other credential blob;
/// `credential_id` is the raw (not base64url) id the authenticator chose.
#[derive(Debug, Clone, FromRow)]
pub struct PasskeyRow {
    /// Row id, exposed as `pky_…`.
    pub id: Uuid,
    /// The account the passkey belongs to.
    pub account_id: Uuid,
    /// Raw credential id reported as `rawId` by the browser.
    pub credential_id: Vec<u8>,
    /// Sealed COSE public key.
    pub secret_enc: Vec<u8>,
    /// The last accepted signature counter; `0` means the authenticator does not count.
    pub sign_count: i64,
    /// Transport hints (`usb`, `nfc`, `ble`, `internal`, `hybrid`).
    pub transports: Vec<String>,
    /// User-chosen label.
    pub name: Option<String>,
    /// The authenticator's model id, when it reported one.
    pub aaguid: Option<Uuid>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last successful assertion.
    pub last_used_at: Option<OffsetDateTime>,
}

impl PasskeyRow {
    /// The passkey's typed id.
    pub fn passkey_id(&self) -> monaca_types::PasskeyId {
        monaca_types::PasskeyId::from_uuid(self.id)
    }
}

/// An agent row.
#[derive(Debug, Clone, FromRow)]
pub struct AgentRow {
    /// `agents.id`.
    pub id: Uuid,
    /// Unique within the org.
    pub name: String,
    /// Free-form description.
    pub description: String,
    /// The account the agent acts for.
    pub owner_account_id: Uuid,
    /// `active` | `disabled`.
    pub state: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

impl AgentRow {
    /// The agent's typed id.
    pub fn agent_id(&self) -> AgentId {
        AgentId::from_uuid(self.id)
    }
}

/// An agent key row.
#[derive(Debug, Clone, FromRow)]
pub struct AgentKeyRow {
    /// `agent_keys.id`.
    pub id: Uuid,
    /// Owning agent.
    pub agent_id: Uuid,
    /// The registered public JWK.
    pub public_jwk: Value,
    /// Client-chosen key id.
    pub kid: String,
    /// SHA-256 hex of the canonical JWK (RFC 7638).
    pub fingerprint: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
}

/// A grant row.
#[derive(Debug, Clone, FromRow)]
pub struct GrantRow {
    /// `grants.id`.
    pub id: Uuid,
    /// The agent the grant is for.
    pub agent_id: Uuid,
    /// The delegating account.
    pub account_id: Uuid,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// The only `aud` this grant authorizes.
    pub resource: String,
    /// Extra constraints (unused in M0).
    pub constraints: Value,
    /// Expiry, if any.
    pub expires_at: Option<OffsetDateTime>,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Who created it (`acc_…` or `cli_…`).
    pub created_by: Uuid,
}

impl GrantRow {
    /// The grant's typed id.
    pub fn grant_id(&self) -> GrantId {
        GrantId::from_uuid(self.id)
    }
}

/// A stored audit row, chain fields included.
#[derive(Debug, Clone, FromRow)]
pub struct AuditRow {
    /// Identity sequence, 1-based per chain.
    pub seq: i64,
    /// `evt_…`.
    pub id: Uuid,
    /// Event time.
    pub at: OffsetDateTime,
    /// Dotted verb.
    pub action: String,
    /// Actor chain JSON.
    pub actor_chain: Value,
    /// Subject type.
    pub subject_type: String,
    /// Subject id, when it is a UUID.
    pub subject_id: Option<Uuid>,
    /// The exact `subject.id` string as hashed.
    pub subject_ref: Option<String>,
    /// `allow` | `deny` | `info`.
    pub decision: String,
    /// Grant the action was authorized by.
    pub grant_id: Option<Uuid>,
    /// Token `jti`.
    pub jti: Option<Uuid>,
    /// Event payload.
    pub payload: Value,
    /// Previous digest.
    pub prev_hash: Vec<u8>,
    /// This row's digest.
    pub hash: Vec<u8>,
}

fn subject_uuid(id: Option<&str>) -> Option<Uuid> {
    let raw = id?;
    let (_, suffix) = raw.split_once('_')?;
    monaca_types::decode_suffix(suffix).ok()
}

/// Map PostgreSQL `unique_violation` (23505) to the "already taken" answer (§6.1).
///
/// The unique indexes are the authority on uniqueness, so the constraint — not a prior SELECT — is
/// what decides; this keeps two concurrent claims from both succeeding. `entity` names the value
/// the caller tried to claim, e.g. `username` or `email`.
pub(crate) fn unique_conflict(err: sqlx::Error, entity: &'static str) -> StoreError {
    if let sqlx::Error::Database(ref db) = err
        && db.code().as_deref() == Some("23505")
    {
        return StoreError::AlreadyExists { entity };
    }
    StoreError::Database(err.to_string())
}

/// One configured rate-limit layer (§6.2).
#[derive(Debug, Clone, FromRow)]
pub struct RateLimitRow {
    /// Row id.
    pub id: Uuid,
    /// `authorize` | `token` | `userinfo` | `management`.
    pub endpoint: String,
    /// The protocol client id for a per-client layer; `None` for the tenant-wide layer.
    pub client_id: Option<String>,
    /// Requests allowed per window.
    pub limit_count: i32,
    /// Window length in seconds.
    pub window_secs: i32,
}

impl Store {
    // ---------------------------------------------------------------- accounts

    /// Create an account with its identifiers and an optional password, atomically.
    ///
    /// The email row is always written; `username` is a second sign-in identifier and is stored
    /// lowercased, matching the case-insensitive unique index from schema version 7.
    pub async fn create_account(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        email: &str,
        display_name: &str,
        password_phc: Option<&str>,
        is_tenant_admin: bool,
        username: Option<&str>,
        username_display: Option<&str>,
    ) -> Result<AccountRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        let row = sqlx::query_as::<_, AccountRow>(
            "INSERT INTO tenant.accounts (id, primary_email, display_name, state, is_tenant_admin)
             VALUES ($1,$2,$3,'active',$4)
             RETURNING id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at",
        )
        .bind(account_id.uuid())
        .bind(email)
        .bind(display_name)
        .bind(is_tenant_admin)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO tenant.account_identifiers (id, account_id, kind, value, verified_at)
             VALUES ($1,$2,'email',$3,now())",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(email)
        .execute(&mut *tx)
        .await?;

        if let Some(username) = username {
            sqlx::query(
                "INSERT INTO tenant.account_identifiers (id, account_id, kind, value, display_value)
                 VALUES ($1,$2,'username',$3,$4)",
            )
            .bind(Uuid::now_v7())
            .bind(account_id.uuid())
            .bind(username)
            .bind(username_display)
            .execute(&mut *tx)
            .await
            .map_err(|err| unique_conflict(err, "username"))?;
        }

        if let Some(phc) = password_phc {
            sqlx::query(
                "INSERT INTO tenant.credentials (id, account_id, kind, secret_enc)
                 VALUES ($1,$2,'password',$3)",
            )
            .bind(Uuid::now_v7())
            .bind(account_id.uuid())
            .bind(phc.as_bytes())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(row)
    }

    /// An account by id.
    pub async fn account_by_id(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Option<AccountRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, AccountRow>(
            "SELECT id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at
             FROM tenant.accounts WHERE id = $1",
        )
        .bind(account_id.uuid())
        .fetch_optional(&pool)
        .await?)
    }

    /// Accounts newest first, optionally filtered by a case-insensitive substring of the email or
    /// display name. `limit` is bounded by the caller.
    pub async fn accounts(
        &self,
        tenant: &TenantRow,
        query: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AccountRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        // A literal `%` or `_` in the search box must not turn into a wildcard.
        let pattern = query.map(|value| {
            format!(
                "%{}%",
                value
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        });
        Ok(sqlx::query_as::<_, AccountRow>(
            "SELECT id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at
             FROM tenant.accounts
             WHERE $1::text IS NULL OR primary_email ILIKE $1 OR display_name ILIKE $1
             ORDER BY created_at DESC, id DESC
             LIMIT $2",
        )
        .bind(pattern.as_deref())
        .bind(limit)
        .fetch_all(&pool)
        .await?)
    }

    /// Change an account's state; false when the row does not exist.
    pub async fn set_account_state(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        state: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result =
            sqlx::query("UPDATE tenant.accounts SET state = $2, updated_at = now() WHERE id = $1")
                .bind(account_id.uuid())
                .bind(state)
                .execute(&pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The tenant's hosted sign-in switches. The migration seeds the row, so this never creates
    /// one; a missing row is a provisioning bug and surfaces as a database error.
    pub async fn sign_in_experience(
        &self,
        tenant: &TenantRow,
    ) -> Result<SignInExperienceRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SignInExperienceRow>(
            "SELECT sign_up_enabled, password_sign_in_enabled, email_code_sign_in_enabled,
                    passkey_sign_in_enabled, single_sign_on_enabled, mfa_enabled, mfa_policy,
                    mfa_trusted_devices_enabled, mfa_trusted_device_ttl_days,
                    password_min_length, password_min_character_types, password_reject_user_info,
                    password_reject_repetition_and_sequence, password_rejected_words,
                    session_ttl_secs, refresh_token_ttl_secs, sign_up_identifiers,
                    sign_up_email_verification_required, username_case_sensitive,
                    username_min_length, username_max_length, username_allowed_punctuation,
                    username_allow_email_local_part, username_preserve_case,
                    username_reserved_words, sign_up_profile_fields, language,
                    captcha_enabled, captcha_provider, captcha_site_key, captcha_cap_base_url,
                    captcha_secret_enc, captcha_on_sign_in, captcha_on_sign_up,
                    captcha_on_password_reset,
                    login_lockout_threshold, login_lockout_duration_secs, updated_at
             FROM tenant.sign_in_experience WHERE singleton",
        )
        .fetch_one(&pool)
        .await?)
    }

    /// Change only the switches the caller named; the others keep their value.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_sign_in_experience(
        &self,
        tenant: &TenantRow,
        sign_up_enabled: Option<bool>,
        password_sign_in_enabled: Option<bool>,
        email_code_sign_in_enabled: Option<bool>,
        passkey_sign_in_enabled: Option<bool>,
        mfa_enabled: Option<bool>,
        mfa_policy: Option<&str>,
        password_min_length: Option<i32>,
        password_min_character_types: Option<i32>,
        password_reject_user_info: Option<bool>,
        password_reject_repetition_and_sequence: Option<bool>,
        password_rejected_words: Option<Vec<String>>,
        session_ttl_secs: Option<i32>,
        refresh_token_ttl_secs: Option<i32>,
        mfa_trusted_devices_enabled: Option<bool>,
        mfa_trusted_device_ttl_days: Option<i32>,
        single_sign_on_enabled: Option<bool>,
        sign_up_identifiers: Option<Vec<String>>,
        sign_up_email_verification_required: Option<bool>,
        username_case_sensitive: Option<bool>,
        username_min_length: Option<i32>,
        username_max_length: Option<i32>,
        username_allowed_punctuation: Option<Vec<String>>,
        username_allow_email_local_part: Option<bool>,
        username_preserve_case: Option<bool>,
        username_reserved_words: Option<Vec<String>>,
        sign_up_profile_fields: Option<Vec<String>>,
    ) -> Result<SignInExperienceRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SignInExperienceRow>(
            "UPDATE tenant.sign_in_experience
             SET sign_up_enabled = COALESCE($1, sign_up_enabled),
                 password_sign_in_enabled = COALESCE($2, password_sign_in_enabled),
                 email_code_sign_in_enabled = COALESCE($3, email_code_sign_in_enabled),
                 passkey_sign_in_enabled = COALESCE($4, passkey_sign_in_enabled),
                 mfa_enabled = COALESCE($5, mfa_enabled),
                 mfa_policy = COALESCE($6, mfa_policy),
                 password_min_length = COALESCE($7, password_min_length),
                 password_min_character_types = COALESCE($8, password_min_character_types),
                 password_reject_user_info = COALESCE($9, password_reject_user_info),
                 password_reject_repetition_and_sequence =
                   COALESCE($10, password_reject_repetition_and_sequence),
                 password_rejected_words = COALESCE($11, password_rejected_words),
                 session_ttl_secs = COALESCE($12, session_ttl_secs),
                 refresh_token_ttl_secs = COALESCE($13, refresh_token_ttl_secs),
                 mfa_trusted_devices_enabled = COALESCE($14, mfa_trusted_devices_enabled),
                 mfa_trusted_device_ttl_days = COALESCE($15, mfa_trusted_device_ttl_days),
                 single_sign_on_enabled = COALESCE($16, single_sign_on_enabled),
                 sign_up_identifiers = COALESCE($17, sign_up_identifiers),
                 sign_up_email_verification_required =
                   COALESCE($18, sign_up_email_verification_required),
                 username_case_sensitive = COALESCE($19, username_case_sensitive),
                 username_min_length = COALESCE($20, username_min_length),
                 username_max_length = COALESCE($21, username_max_length),
                 username_allowed_punctuation =
                   COALESCE($23, username_allowed_punctuation),
                 username_allow_email_local_part =
                   COALESCE($24, username_allow_email_local_part),
                 username_preserve_case = COALESCE($25, username_preserve_case),
                 username_reserved_words = COALESCE($26, username_reserved_words),
                 sign_up_profile_fields = COALESCE($22, sign_up_profile_fields),
                 updated_at = now()
             WHERE singleton
             RETURNING sign_up_enabled, password_sign_in_enabled, email_code_sign_in_enabled,
                       passkey_sign_in_enabled, single_sign_on_enabled, mfa_enabled, mfa_policy,
                       mfa_trusted_devices_enabled, mfa_trusted_device_ttl_days,
                       password_min_length, password_min_character_types,
                       password_reject_user_info, password_reject_repetition_and_sequence,
                       password_rejected_words, session_ttl_secs, refresh_token_ttl_secs,
                       sign_up_identifiers, sign_up_email_verification_required,
                       username_case_sensitive, username_min_length, username_max_length,
                       username_allowed_punctuation, username_allow_email_local_part,
                       username_preserve_case, username_reserved_words, sign_up_profile_fields,
                       language, captcha_enabled, captcha_provider, captcha_site_key,
                       captcha_cap_base_url, captcha_secret_enc, captcha_on_sign_in,
                       captcha_on_sign_up,
                       captcha_on_password_reset, login_lockout_threshold,
                       login_lockout_duration_secs, updated_at",
        )
        .bind(sign_up_enabled)
        .bind(password_sign_in_enabled)
        .bind(email_code_sign_in_enabled)
        .bind(passkey_sign_in_enabled)
        .bind(mfa_enabled)
        .bind(mfa_policy)
        .bind(password_min_length)
        .bind(password_min_character_types)
        .bind(password_reject_user_info)
        .bind(password_reject_repetition_and_sequence)
        .bind(password_rejected_words)
        .bind(session_ttl_secs)
        .bind(refresh_token_ttl_secs)
        .bind(mfa_trusted_devices_enabled)
        .bind(mfa_trusted_device_ttl_days)
        .bind(single_sign_on_enabled)
        .bind(sign_up_identifiers)
        .bind(sign_up_email_verification_required)
        .bind(username_case_sensitive)
        .bind(username_min_length)
        .bind(username_max_length)
        .bind(sign_up_profile_fields)
        .bind(username_allowed_punctuation)
        .bind(username_allow_email_local_part)
        .bind(username_preserve_case)
        .bind(username_reserved_words)
        .fetch_one(&pool)
        .await?)
    }

    /// Change only the CAPTCHA and lockout settings the caller named; the others keep their value.
    pub async fn update_sign_in_guardrails(
        &self,
        tenant: &TenantRow,
        patch: &SignInGuardrailsPatch,
    ) -> Result<SignInExperienceRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SignInExperienceRow>(
            "UPDATE tenant.sign_in_experience
             SET captcha_enabled = COALESCE($1, captcha_enabled),
                 captcha_provider = COALESCE($2, captcha_provider),
                 captcha_site_key = CASE WHEN $3 THEN $4 ELSE captcha_site_key END,
                 captcha_cap_base_url = CASE WHEN $5 THEN $6 ELSE captcha_cap_base_url END,
                 captcha_secret_enc = CASE WHEN $7 THEN $8 ELSE captcha_secret_enc END,
                 captcha_on_sign_in = COALESCE($9, captcha_on_sign_in),
                 captcha_on_sign_up = COALESCE($10, captcha_on_sign_up),
                 captcha_on_password_reset = COALESCE($11, captcha_on_password_reset),
                 login_lockout_threshold = COALESCE($12, login_lockout_threshold),
                 login_lockout_duration_secs = COALESCE($13, login_lockout_duration_secs),
                 updated_at = now()
             WHERE singleton
             RETURNING sign_up_enabled, password_sign_in_enabled, email_code_sign_in_enabled,
                       passkey_sign_in_enabled, single_sign_on_enabled, mfa_enabled, mfa_policy,
                       mfa_trusted_devices_enabled, mfa_trusted_device_ttl_days,
                       password_min_length, password_min_character_types,
                       password_reject_user_info, password_reject_repetition_and_sequence,
                       password_rejected_words, session_ttl_secs, refresh_token_ttl_secs,
                       sign_up_identifiers, sign_up_email_verification_required,
                       username_case_sensitive, username_min_length, username_max_length,
                       username_allowed_punctuation, username_allow_email_local_part,
                       username_preserve_case, username_reserved_words, sign_up_profile_fields,
                       language, captcha_enabled, captcha_provider, captcha_site_key,
                       captcha_cap_base_url, captcha_secret_enc, captcha_on_sign_in,
                       captcha_on_sign_up,
                       captcha_on_password_reset, login_lockout_threshold,
                       login_lockout_duration_secs, updated_at",
        )
        .bind(patch.captcha_enabled)
        .bind(patch.captcha_provider.as_deref())
        .bind(patch.captcha_site_key.is_some())
        .bind(patch.captcha_site_key.clone().flatten())
        .bind(patch.captcha_cap_base_url.is_some())
        .bind(patch.captcha_cap_base_url.clone().flatten())
        .bind(patch.captcha_secret_enc.is_some())
        .bind(patch.captcha_secret_enc.clone().flatten())
        .bind(patch.captcha_on_sign_in)
        .bind(patch.captcha_on_sign_up)
        .bind(patch.captcha_on_password_reset)
        .bind(patch.login_lockout_threshold)
        .bind(patch.login_lockout_duration_secs)
        .fetch_one(&pool)
        .await?)
    }

    /// Every phrase override the tenant stored, across languages, in a stable order.
    pub async fn sign_in_phrases(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<SignInPhraseRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SignInPhraseRow>(
            "SELECT language, phrase_key, value FROM tenant.sign_in_phrases
             ORDER BY language, phrase_key",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Replace one language's overrides and, when named, the tenant's default language — together.
    ///
    /// One transaction because the two writes are one administrative intent: a default language
    /// pointing at a half-written phrase set is worse than either write alone. An empty `entries`
    /// removes the language.
    pub async fn update_sign_in_copy(
        &self,
        tenant: &TenantRow,
        default_language: Option<&str>,
        phrases: Option<(&str, &[(String, String)])>,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        if let Some(language) = default_language {
            sqlx::query(
                "UPDATE tenant.sign_in_experience
                 SET language = $1, updated_at = now()
                 WHERE singleton",
            )
            .bind(language)
            .execute(&mut *tx)
            .await?;
        }
        if let Some((language, entries)) = phrases {
            sqlx::query("DELETE FROM tenant.sign_in_phrases WHERE language = $1")
                .bind(language)
                .execute(&mut *tx)
                .await?;
            for (key, value) in entries {
                sqlx::query(
                    "INSERT INTO tenant.sign_in_phrases (language, phrase_key, value, updated_at)
                     VALUES ($1, $2, $3, now())",
                )
                .bind(language)
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The failure counter for one normalised sign-in identifier, when one exists.
    pub async fn login_failure(
        &self,
        tenant: &TenantRow,
        identifier_key: &str,
    ) -> Result<Option<LoginFailureRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, LoginFailureRow>(
            "SELECT failures, locked_until FROM tenant.login_failures
             WHERE identifier_key = $1",
        )
        .bind(identifier_key)
        .fetch_optional(&pool)
        .await?)
    }

    /// Count one wrong password and lock the identifier when it reaches the threshold.
    pub async fn record_login_failure(
        &self,
        tenant: &TenantRow,
        identifier_key: &str,
        threshold: i32,
        duration_secs: i32,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.login_failures (identifier_key, failures, locked_until)
             VALUES ($1, 1,
                     CASE WHEN $2 <= 1
                          THEN now() + make_interval(secs => $3::double precision) END)
             ON CONFLICT (identifier_key) DO UPDATE
             SET failures = tenant.login_failures.failures + 1,
                 locked_until =
                   CASE WHEN tenant.login_failures.failures + 1 >= $2
                        THEN now() + make_interval(secs => $3::double precision)
                        ELSE tenant.login_failures.locked_until END,
                 updated_at = now()",
        )
        .bind(identifier_key)
        .bind(threshold)
        .bind(duration_secs)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Forget an identifier's failures — after a success, or once a lock has expired.
    pub async fn clear_login_failures(
        &self,
        tenant: &TenantRow,
        identifier_key: &str,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("DELETE FROM tenant.login_failures WHERE identifier_key = $1")
            .bind(identifier_key)
            .execute(&pool)
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------- branding

    /// The tenant's optional hosted-page branding. The migration seeds the row.
    pub async fn branding(&self, tenant: &TenantRow) -> Result<BrandingRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, BrandingRow>(
            "SELECT display_name, logo_url, dark_logo_url, favicon_url, primary_color, terms_url,
                    privacy_url, support_email, website_url, custom_css, updated_at
             FROM tenant.branding WHERE singleton",
        )
        .fetch_one(&pool)
        .await?)
    }

    /// Change only the fields the caller named; `None` keeps the current value and `Some("")`
    /// clears it, so an administrator can remove a logo or a legal link without a second endpoint.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_branding(
        &self,
        tenant: &TenantRow,
        display_name: Option<&str>,
        logo_url: Option<&str>,
        dark_logo_url: Option<&str>,
        favicon_url: Option<&str>,
        primary_color: Option<&str>,
        terms_url: Option<&str>,
        privacy_url: Option<&str>,
        support_email: Option<&str>,
        website_url: Option<&str>,
        custom_css: Option<&str>,
    ) -> Result<BrandingRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, BrandingRow>(
            "UPDATE tenant.branding
             SET display_name = CASE WHEN $1 IS NULL THEN display_name
                                     WHEN $1 = '' THEN NULL ELSE $1 END,
                 logo_url = CASE WHEN $2 IS NULL THEN logo_url
                                 WHEN $2 = '' THEN NULL ELSE $2 END,
                 dark_logo_url = CASE WHEN $3 IS NULL THEN dark_logo_url
                                      WHEN $3 = '' THEN NULL ELSE $3 END,
                 favicon_url = CASE WHEN $4 IS NULL THEN favicon_url
                                    WHEN $4 = '' THEN NULL ELSE $4 END,
                 primary_color = CASE WHEN $5 IS NULL THEN primary_color
                                      WHEN $5 = '' THEN NULL ELSE $5 END,
                 terms_url = CASE WHEN $6 IS NULL THEN terms_url
                                  WHEN $6 = '' THEN NULL ELSE $6 END,
                 privacy_url = CASE WHEN $7 IS NULL THEN privacy_url
                                    WHEN $7 = '' THEN NULL ELSE $7 END,
                 support_email = CASE WHEN $8 IS NULL THEN support_email
                                      WHEN $8 = '' THEN NULL ELSE $8 END,
                 website_url = CASE WHEN $9 IS NULL THEN website_url
                                    WHEN $9 = '' THEN NULL ELSE $9 END,
                 custom_css = CASE WHEN $10 IS NULL THEN custom_css
                                   WHEN $10 = '' THEN NULL ELSE $10 END,
                 updated_at = now()
             WHERE singleton
             RETURNING display_name, logo_url, dark_logo_url, favicon_url, primary_color,
                       terms_url, privacy_url, support_email, website_url, custom_css, updated_at",
        )
        .bind(display_name)
        .bind(logo_url)
        .bind(dark_logo_url)
        .bind(favicon_url)
        .bind(primary_color)
        .bind(terms_url)
        .bind(privacy_url)
        .bind(support_email)
        .bind(website_url)
        .bind(custom_css)
        .fetch_one(&pool)
        .await?)
    }

    // ------------------------------------------------------------ email templates

    /// Every purpose the tenant customised. Purposes without a row use the built-in default.
    pub async fn email_templates(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<EmailTemplateRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, EmailTemplateRow>(
            "SELECT purpose, subject, body, updated_at
             FROM tenant.email_templates ORDER BY purpose",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// One purpose's customised copy, or `None` when the default applies.
    pub async fn email_template(
        &self,
        tenant: &TenantRow,
        purpose: &str,
    ) -> Result<Option<EmailTemplateRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, EmailTemplateRow>(
            "SELECT purpose, subject, body, updated_at
             FROM tenant.email_templates WHERE purpose = $1",
        )
        .bind(purpose)
        .fetch_optional(&pool)
        .await?)
    }

    /// Replace one purpose's copy; the next mail for that purpose renders it.
    pub async fn upsert_email_template(
        &self,
        tenant: &TenantRow,
        purpose: &str,
        subject: &str,
        body: &str,
    ) -> Result<EmailTemplateRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, EmailTemplateRow>(
            "INSERT INTO tenant.email_templates (purpose, subject, body)
             VALUES ($1,$2,$3)
             ON CONFLICT (purpose) DO UPDATE
             SET subject = EXCLUDED.subject, body = EXCLUDED.body, updated_at = now()
             RETURNING purpose, subject, body, updated_at",
        )
        .bind(purpose)
        .bind(subject)
        .bind(body)
        .fetch_one(&pool)
        .await?)
    }

    /// Drop the customisation so the built-in default applies again; `false` when none existed.
    pub async fn delete_email_template(
        &self,
        tenant: &TenantRow,
        purpose: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.email_templates WHERE purpose = $1")
            .bind(purpose)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ------------------------------------------------------------ email connector

    /// The tenant's outbound mail route, or `None` while nothing is configured.
    pub async fn email_connector(
        &self,
        tenant: &TenantRow,
    ) -> Result<Option<EmailConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, EmailConnectorRow>(
            "SELECT provider, endpoint, from_address, from_name, secret_enc, enabled, updated_at
             FROM tenant.email_connector WHERE singleton",
        )
        .fetch_optional(&pool)
        .await?)
    }

    /// Create or replace the route. When `set_secret` is false the stored secret is preserved, so
    /// an endpoint change cannot silently drop authentication; `enabled=None` also preserves it.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_email_connector(
        &self,
        tenant: &TenantRow,
        provider: &str,
        endpoint: &str,
        from_address: &str,
        from_name: Option<&str>,
        secret_enc: Option<&[u8]>,
        set_secret: bool,
        enabled: Option<bool>,
    ) -> Result<EmailConnectorRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, EmailConnectorRow>(
            "INSERT INTO tenant.email_connector
               (singleton, provider, endpoint, from_address, from_name, secret_enc, enabled)
             VALUES (true, $1, $2, $3, $4, $5, COALESCE($6, true))
             ON CONFLICT (singleton) DO UPDATE
             SET provider = EXCLUDED.provider,
                 endpoint = EXCLUDED.endpoint,
                 from_address = EXCLUDED.from_address,
                 from_name = EXCLUDED.from_name,
                 secret_enc = CASE WHEN $7 THEN EXCLUDED.secret_enc
                                   ELSE tenant.email_connector.secret_enc END,
                 enabled = COALESCE($6, tenant.email_connector.enabled),
                 updated_at = now()
             RETURNING provider, endpoint, from_address, from_name, secret_enc, enabled, updated_at",
        )
        .bind(provider)
        .bind(endpoint)
        .bind(from_address)
        .bind(from_name)
        .bind(secret_enc.map(<[u8]>::to_vec))
        .bind(enabled)
        .bind(set_secret)
        .fetch_one(&pool)
        .await?)
    }

    /// Remove the route; `false` when there was none. Mail stays in the outbox either way.
    pub async fn delete_email_connector(&self, tenant: &TenantRow) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.email_connector WHERE singleton")
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ------------------------------------------------------------------ webhooks

    /// Every webhook the tenant configured, oldest first.
    pub async fn webhooks(&self, tenant: &TenantRow) -> Result<Vec<WebhookRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, WebhookRow>(
            "SELECT id, url, events, secret_enc, enabled, created_at, updated_at
             FROM tenant.webhooks ORDER BY created_at, id",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// One webhook by its typed id.
    pub async fn webhook(
        &self,
        tenant: &TenantRow,
        id: WebhookId,
    ) -> Result<Option<WebhookRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, WebhookRow>(
            "SELECT id, url, events, secret_enc, enabled, created_at, updated_at
             FROM tenant.webhooks WHERE id = $1",
        )
        .bind(id.uuid())
        .fetch_optional(&pool)
        .await?)
    }

    /// The enabled subscriptions that name `action`.
    ///
    /// Takes the database name rather than a [`TenantRow`] because delivery is triggered from the
    /// audit helpers, including org-chain ones where only the tenant context is in scope.
    pub async fn webhooks_for_event(
        &self,
        db_name: &str,
        action: &str,
    ) -> Result<Vec<WebhookRow>, StoreError> {
        let pool = self.tenant_pool(db_name).await?;
        Ok(sqlx::query_as::<_, WebhookRow>(
            "SELECT id, url, events, secret_enc, enabled, created_at, updated_at
             FROM tenant.webhooks
             WHERE enabled AND $1 = ANY(events)
             ORDER BY created_at, id",
        )
        .bind(action)
        .fetch_all(&pool)
        .await?)
    }

    /// Register a webhook. The caller seals the signing key.
    pub async fn create_webhook(
        &self,
        tenant: &TenantRow,
        url: &str,
        events: &[String],
        secret_enc: &[u8],
    ) -> Result<WebhookRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, WebhookRow>(
            "INSERT INTO tenant.webhooks (id, url, events, secret_enc)
             VALUES ($1,$2,$3,$4)
             RETURNING id, url, events, secret_enc, enabled, created_at, updated_at",
        )
        .bind(WebhookId::new().uuid())
        .bind(url)
        .bind(events)
        .bind(secret_enc)
        .fetch_one(&pool)
        .await?)
    }

    /// Change only the fields the caller named; `None` leaves each value alone.
    pub async fn update_webhook(
        &self,
        tenant: &TenantRow,
        id: WebhookId,
        url: Option<&str>,
        events: Option<&[String]>,
        enabled: Option<bool>,
    ) -> Result<Option<WebhookRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, WebhookRow>(
            "UPDATE tenant.webhooks
             SET url = COALESCE($2, url),
                 events = COALESCE($3, events),
                 enabled = COALESCE($4, enabled),
                 updated_at = now()
             WHERE id = $1
             RETURNING id, url, events, secret_enc, enabled, created_at, updated_at",
        )
        .bind(id.uuid())
        .bind(url)
        .bind(events)
        .bind(enabled)
        .fetch_optional(&pool)
        .await?)
    }

    /// Replace a webhook's sealed signing key; `None` when the row does not exist.
    pub async fn set_webhook_secret(
        &self,
        tenant: &TenantRow,
        id: WebhookId,
        secret_enc: &[u8],
    ) -> Result<Option<WebhookRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, WebhookRow>(
            "UPDATE tenant.webhooks SET secret_enc = $2, updated_at = now()
             WHERE id = $1
             RETURNING id, url, events, secret_enc, enabled, created_at, updated_at",
        )
        .bind(id.uuid())
        .bind(secret_enc)
        .fetch_optional(&pool)
        .await?)
    }

    /// Delete a webhook and its delivery history; false when it did not exist.
    pub async fn delete_webhook(
        &self,
        tenant: &TenantRow,
        id: WebhookId,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.webhooks WHERE id = $1")
            .bind(id.uuid())
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record the outcome of one delivery, after its last attempt.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_webhook_delivery(
        &self,
        db_name: &str,
        webhook_id: Uuid,
        event: &str,
        status_code: Option<i32>,
        success: bool,
        attempts: i32,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.webhook_deliveries
                (id, webhook_id, event, status_code, success, attempts, error)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(Uuid::now_v7())
        .bind(webhook_id)
        .bind(event)
        .bind(status_code)
        .bind(success)
        .bind(attempts)
        .bind(error)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// The most recent deliveries of one webhook, newest first.
    pub async fn webhook_deliveries(
        &self,
        tenant: &TenantRow,
        webhook_id: WebhookId,
        limit: i64,
    ) -> Result<Vec<WebhookDeliveryRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, WebhookDeliveryRow>(
            "SELECT id, webhook_id, event, status_code, success, attempts, error, created_at
             FROM tenant.webhook_deliveries
             WHERE webhook_id = $1
             ORDER BY created_at DESC, id DESC
             LIMIT $2",
        )
        .bind(webhook_id.uuid())
        .bind(limit)
        .fetch_all(&pool)
        .await?)
    }

    /// An account and its password PHC string, by email (case-insensitive).
    pub async fn account_by_email(
        &self,
        tenant: &TenantRow,
        email: &str,
    ) -> Result<Option<(AccountRow, Option<String>)>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let account = sqlx::query_as::<_, AccountRow>(
            "SELECT id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at
             FROM tenant.accounts WHERE lower(primary_email) = lower($1)",
        )
        .bind(email)
        .fetch_optional(&pool)
        .await?;

        let Some(account) = account else {
            return Ok(None);
        };

        let secret: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT secret_enc FROM tenant.credentials
             WHERE account_id = $1 AND kind = 'password' LIMIT 1",
        )
        .bind(account.id)
        .fetch_optional(&pool)
        .await?;

        let phc = secret.and_then(|(bytes,)| String::from_utf8(bytes).ok());
        Ok(Some((account, phc)))
    }

    /// An account and its password PHC string, by sign-in identifier (§6.1).
    ///
    /// The identifier is either an email address or a username. Emails are compared
    /// case-insensitively; a username follows the tenant's policy, which `case_sensitive` carries.
    /// An email always wins: a username may not contain `@` (§6.1), so the two namespaces can only
    /// overlap through data written outside this API, and the email is the safer interpretation.
    pub async fn account_by_identifier(
        &self,
        tenant: &TenantRow,
        identifier: &str,
        case_sensitive: bool,
    ) -> Result<Option<(AccountRow, Option<String>)>, StoreError> {
        if let Some(account) = self.account_by_email(tenant, identifier).await? {
            return Ok(Some(account));
        }
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let account = sqlx::query_as::<_, AccountRow>(
            "SELECT a.id, a.primary_email, a.display_name, a.avatar_url, a.state,
                    a.is_tenant_admin, a.created_at
             FROM tenant.accounts a
             JOIN tenant.account_identifiers i ON i.account_id = a.id
             WHERE i.kind = 'username'
               AND (($2 AND i.value = $1) OR (NOT $2 AND lower(i.value) = lower($1)))
             LIMIT 1",
        )
        .bind(identifier)
        .bind(case_sensitive)
        .fetch_optional(&pool)
        .await?;

        let Some(account) = account else {
            return Ok(None);
        };

        let secret: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT secret_enc FROM tenant.credentials
             WHERE account_id = $1 AND kind = 'password' LIMIT 1",
        )
        .bind(account.id)
        .fetch_optional(&pool)
        .await?;

        let phc = secret.and_then(|(bytes,)| String::from_utf8(bytes).ok());
        Ok(Some((account, phc)))
    }

    /// The account's username, if one was set: the preserved display form when the tenant keeps
    /// case, otherwise the normalised identifier.
    pub async fn account_username(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Option<String>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, (String,)>(
            "SELECT COALESCE(display_value, value) FROM tenant.account_identifiers
             WHERE account_id = $1 AND kind = 'username' LIMIT 1",
        )
        .bind(account_id.uuid())
        .fetch_optional(&pool)
        .await?
        .map(|(value,)| value))
    }

    /// Set or replace the account's username, rejecting one another account already holds.
    ///
    /// Callers pass an already-normalised (lowercased, syntactically valid) username; the unique
    /// index is the authority, so a race between two accounts yields `AlreadyExists` rather than a
    /// duplicate row. `display` keeps the typed case for presentation and is `None` when the
    /// tenant folds the name.
    pub async fn set_username(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        username: &str,
        display: Option<&str>,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        let existing: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM tenant.account_identifiers
             WHERE account_id = $1 AND kind = 'username' LIMIT 1",
        )
        .bind(account_id.uuid())
        .fetch_optional(&mut *tx)
        .await?;

        match existing {
            Some((id,)) => {
                sqlx::query(
                    "UPDATE tenant.account_identifiers
                     SET value = $2, display_value = $3 WHERE id = $1",
                )
                .bind(id)
                .bind(username)
                .bind(display)
                .execute(&mut *tx)
                .await
                .map_err(|err| unique_conflict(err, "username"))?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO tenant.account_identifiers
                       (id, account_id, kind, value, display_value)
                     VALUES ($1,$2,'username',$3,$4)",
                )
                .bind(Uuid::now_v7())
                .bind(account_id.uuid())
                .bind(username)
                .bind(display)
                .execute(&mut *tx)
                .await
                .map_err(|err| unique_conflict(err, "username"))?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    /// Replace the account's primary email, in `accounts` and in its email identifier (§6.1).
    ///
    /// Both writes share one transaction so sign-in never sees the old address after the new one is
    /// recorded. The case-insensitive unique index is the authority: a race for an address that just
    /// became free yields `AlreadyExists { entity: "email" }`.
    pub async fn update_primary_email(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        email: &str,
    ) -> Result<AccountRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        let account = sqlx::query_as::<_, AccountRow>(
            "UPDATE tenant.accounts SET primary_email = $2, updated_at = now()
             WHERE id = $1
             RETURNING id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at",
        )
        .bind(account_id.uuid())
        .bind(email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| unique_conflict(err, "email"))?;

        sqlx::query(
            "UPDATE tenant.account_identifiers SET value = $2, verified_at = now()
             WHERE account_id = $1 AND kind = 'email'",
        )
        .bind(account_id.uuid())
        .bind(email)
        .execute(&mut *tx)
        .await
        .map_err(|err| unique_conflict(err, "email"))?;

        tx.commit().await?;
        Ok(account)
    }

    /// Every social connector the tenant configured.
    pub async fn social_connectors(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<SocialConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialConnectorRow>(
            "SELECT id, connector_id, provider, display_name, enabled, link_policy,
                    authorize_url, token_url, userinfo_url, client_id, client_secret_enc, scopes,
                    created_at
             FROM tenant.social_connectors ORDER BY connector_id",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// One connector by its slug.
    pub async fn social_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
    ) -> Result<Option<SocialConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialConnectorRow>(
            "SELECT id, connector_id, provider, display_name, enabled, link_policy,
                    authorize_url, token_url, userinfo_url, client_id, client_secret_enc, scopes,
                    created_at
             FROM tenant.social_connectors WHERE connector_id = $1",
        )
        .bind(connector_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Register a connector; a slug another row holds is `AlreadyExists { entity: "connector" }`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_social_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
        provider: &str,
        display_name: &str,
        enabled: bool,
        link_policy: &str,
        authorize_url: &str,
        token_url: &str,
        userinfo_url: &str,
        client_id: &str,
        client_secret_enc: &[u8],
        scopes: &[String],
    ) -> Result<SocialConnectorRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, SocialConnectorRow>(
            "INSERT INTO tenant.social_connectors
                (id, connector_id, provider, display_name, enabled, link_policy, authorize_url,
                 token_url, userinfo_url, client_id, client_secret_enc, scopes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             RETURNING id, connector_id, provider, display_name, enabled, link_policy,
                       authorize_url, token_url, userinfo_url, client_id, client_secret_enc, scopes,
                       created_at",
        )
        .bind(Uuid::now_v7())
        .bind(connector_id)
        .bind(provider)
        .bind(display_name)
        .bind(enabled)
        .bind(link_policy)
        .bind(authorize_url)
        .bind(token_url)
        .bind(userinfo_url)
        .bind(client_id)
        .bind(client_secret_enc)
        .bind(scopes)
        .fetch_one(&pool)
        .await
        .map_err(|err| unique_conflict(err, "connector"))
    }

    /// Change the writable half of a connector; absent fields keep their value.
    pub async fn update_social_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
        display_name: Option<&str>,
        client_id: Option<&str>,
        client_secret_enc: Option<&[u8]>,
        scopes: Option<&[String]>,
        enabled: Option<bool>,
        link_policy: Option<&str>,
    ) -> Result<Option<SocialConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialConnectorRow>(
            "UPDATE tenant.social_connectors
             SET display_name = COALESCE($2, display_name),
                 client_id = COALESCE($3, client_id),
                 client_secret_enc = COALESCE($4, client_secret_enc),
                 scopes = COALESCE($5, scopes),
                 enabled = COALESCE($6, enabled),
                 link_policy = COALESCE($7, link_policy)
             WHERE connector_id = $1
             RETURNING id, connector_id, provider, display_name, enabled, link_policy,
                       authorize_url, token_url, userinfo_url, client_id, client_secret_enc, scopes,
                       created_at",
        )
        .bind(connector_id)
        .bind(display_name)
        .bind(client_id)
        .bind(client_secret_enc)
        .bind(scopes)
        .bind(enabled)
        .bind(link_policy)
        .fetch_optional(&pool)
        .await?)
    }

    /// Delete a connector, and with it every identity that used it; false when it did not exist.
    pub async fn delete_social_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.social_connectors WHERE connector_id = $1")
            .bind(connector_id)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The account a provider subject is linked to.
    pub async fn social_identity_account(
        &self,
        tenant: &TenantRow,
        connector: &str,
        subject: &str,
    ) -> Result<Option<AccountRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, AccountRow>(
            "SELECT a.id, a.primary_email, a.display_name, a.avatar_url, a.state,
                    a.is_tenant_admin, a.created_at
             FROM tenant.accounts a
             JOIN tenant.account_social_identities i ON i.account_id = a.id
             WHERE i.connector = $1 AND i.subject = $2
             LIMIT 1",
        )
        .bind(connector)
        .bind(subject)
        .fetch_optional(&pool)
        .await?)
    }

    /// Link a provider subject to an account.
    ///
    /// The unique constraints are the authority: a subject another account already claimed, or a
    /// second provider for the same account, is `AlreadyExists { entity: "social identity" }`.
    pub async fn link_social_identity(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        connector: &str,
        subject: &str,
        email_at_link: Option<&str>,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.account_social_identities
                (id, account_id, connector, subject, email_at_link)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(connector)
        .bind(subject)
        .bind(email_at_link)
        .execute(&pool)
        .await
        .map_err(|err| unique_conflict(err, "social identity"))?;
        Ok(())
    }

    /// Remove one link; false when the account was not connected to that connector.
    pub async fn unlink_social_identity(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        connector: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "DELETE FROM tenant.account_social_identities
             WHERE account_id = $1 AND connector = $2",
        )
        .bind(account_id.uuid())
        .bind(connector)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The account's linked providers, with the display names the account page shows.
    pub async fn social_identities(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Vec<SocialIdentityRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialIdentityRow>(
            "SELECT i.connector, c.display_name, i.subject, i.email_at_link, i.created_at AS linked_at
             FROM tenant.account_social_identities i
             JOIN tenant.social_connectors c ON c.connector_id = i.connector
             WHERE i.account_id = $1
             ORDER BY i.connector",
        )
        .bind(account_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Mint a single-use `state` the provider will echo back; returns the uuid to send.
    pub async fn insert_social_state(
        &self,
        tenant: &TenantRow,
        connector: &str,
        purpose: &str,
        interaction_id: Option<&str>,
        account_id: Option<Uuid>,
        code_verifier_enc: Option<&[u8]>,
        nonce: Option<&str>,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant.social_states
                (id, connector, purpose, interaction_id, account_id, code_verifier_enc, nonce,
                 expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(connector)
        .bind(purpose)
        .bind(interaction_id)
        .bind(account_id)
        .bind(code_verifier_enc)
        .bind(nonce)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(id)
    }

    /// Redeem a `state`: only an unconsumed, unexpired row is returned, and it is consumed in the
    /// same statement so two callbacks cannot both proceed.
    pub async fn take_social_state(
        &self,
        tenant: &TenantRow,
        state_id: Uuid,
    ) -> Result<Option<SocialStateRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialStateRow>(
            "UPDATE tenant.social_states SET consumed_at = now()
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
             RETURNING connector, purpose, interaction_id, account_id, code_verifier_enc, nonce",
        )
        .bind(state_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Mint a pending link confirmation; returns the opaque token the page presents.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_social_link_request(
        &self,
        tenant: &TenantRow,
        connector: &str,
        subject: &str,
        email: &str,
        account_id: Uuid,
        interaction_id: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant.social_link_requests
                (id, connector, subject, email, account_id, interaction_id, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(connector)
        .bind(subject)
        .bind(email)
        .bind(account_id)
        .bind(interaction_id)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(id)
    }

    /// Read a link confirmation without consuming it, for the page's prompt.
    pub async fn social_link_request(
        &self,
        tenant: &TenantRow,
        token: Uuid,
    ) -> Result<Option<SocialLinkRequestRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialLinkRequestRow>(
            "SELECT id, connector, subject, email, account_id, interaction_id, expires_at
             FROM tenant.social_link_requests
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()",
        )
        .bind(token)
        .fetch_optional(&pool)
        .await?)
    }

    /// Redeem a link confirmation once.
    pub async fn take_social_link_request(
        &self,
        tenant: &TenantRow,
        token: Uuid,
    ) -> Result<Option<SocialLinkRequestRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SocialLinkRequestRow>(
            "UPDATE tenant.social_link_requests SET consumed_at = now()
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
             RETURNING id, connector, subject, email, account_id, interaction_id, expires_at",
        )
        .bind(token)
        .fetch_optional(&pool)
        .await?)
    }

    // ------------------------------------------------------------- enterprise SSO

    /// Every SSO connector the tenant configured, ordered by slug.
    pub async fn sso_connectors(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<SsoConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SsoConnectorRow>(
            "SELECT id, connector_id, display_name, issuer, authorize_url, token_url, userinfo_url,
                    client_id, client_secret_enc, scopes, email_domains, created_at
             FROM tenant.sso_connectors ORDER BY connector_id",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// One SSO connector by its slug.
    pub async fn sso_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
    ) -> Result<Option<SsoConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SsoConnectorRow>(
            "SELECT id, connector_id, display_name, issuer, authorize_url, token_url, userinfo_url,
                    client_id, client_secret_enc, scopes, email_domains, created_at
             FROM tenant.sso_connectors WHERE connector_id = $1",
        )
        .bind(connector_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// The connector that owns `domain` — the routing lookup of §6.1.
    pub async fn sso_connector_for_domain(
        &self,
        tenant: &TenantRow,
        domain: &str,
    ) -> Result<Option<SsoConnectorRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SsoConnectorRow>(
            "SELECT id, connector_id, display_name, issuer, authorize_url, token_url, userinfo_url,
                    client_id, client_secret_enc, scopes, email_domains, created_at
             FROM tenant.sso_connectors WHERE $1 = ANY(email_domains) LIMIT 1",
        )
        .bind(domain)
        .fetch_optional(&pool)
        .await?)
    }

    /// Register an SSO connector; a slug another row holds is `AlreadyExists { entity: "sso
    /// connector" }`, and a domain another connector owns is `AlreadyExists { entity: "sso email
    /// domain" }`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sso_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
        display_name: &str,
        issuer: &str,
        authorize_url: &str,
        token_url: &str,
        userinfo_url: &str,
        client_id: &str,
        client_secret_enc: &[u8],
        scopes: &[String],
        email_domains: &[String],
    ) -> Result<SsoConnectorRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        // The slug is checked before the domains so re-posting an existing connector reports the
        // connector, even when its body also repeats the domains that connector already owns.
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT connector_id FROM tenant.sso_connectors WHERE connector_id = $1",
        )
        .bind(connector_id)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_some() {
            return Err(StoreError::AlreadyExists {
                entity: "sso connector",
            });
        }
        let taken: Option<(String,)> = sqlx::query_as(
            "SELECT connector_id FROM tenant.sso_connectors
             WHERE email_domains && $1 LIMIT 1",
        )
        .bind(email_domains)
        .fetch_optional(&mut *tx)
        .await?;
        if taken.is_some() {
            return Err(StoreError::AlreadyExists {
                entity: "sso email domain",
            });
        }
        let row = sqlx::query_as::<_, SsoConnectorRow>(
            "INSERT INTO tenant.sso_connectors
                (id, connector_id, display_name, issuer, authorize_url, token_url, userinfo_url,
                 client_id, client_secret_enc, scopes, email_domains)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             RETURNING id, connector_id, display_name, issuer, authorize_url, token_url,
                       userinfo_url, client_id, client_secret_enc, scopes, email_domains, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(connector_id)
        .bind(display_name)
        .bind(issuer)
        .bind(authorize_url)
        .bind(token_url)
        .bind(userinfo_url)
        .bind(client_id)
        .bind(client_secret_enc)
        .bind(scopes)
        .bind(email_domains)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| unique_conflict(err, "sso connector"))?;
        tx.commit().await?;
        Ok(row)
    }

    /// Delete an SSO connector and its pending states; false when it did not exist.
    pub async fn delete_sso_connector(
        &self,
        tenant: &TenantRow,
        connector_id: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.sso_connectors WHERE connector_id = $1")
            .bind(connector_id)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Mint a single-use SSO `state` bound to an interaction; returns the uuid to send.
    pub async fn insert_sso_state(
        &self,
        tenant: &TenantRow,
        connector: &str,
        interaction_id: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant.sso_states (id, connector, interaction_id, expires_at)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(id)
        .bind(connector)
        .bind(interaction_id)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(id)
    }

    /// Redeem an SSO `state`: only an unconsumed, unexpired row is returned, and it is consumed in
    /// the same statement so two callbacks cannot both proceed.
    pub async fn take_sso_state(
        &self,
        tenant: &TenantRow,
        state_id: Uuid,
    ) -> Result<Option<SsoStateRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SsoStateRow>(
            "UPDATE tenant.sso_states SET consumed_at = now()
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
             RETURNING connector, interaction_id",
        )
        .bind(state_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Record a browser this account chose to trust past the second factor.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_trusted_device(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        token_hash: &str,
        user_agent: Option<&str>,
        expires_at: OffsetDateTime,
    ) -> Result<TrustedDeviceRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, TrustedDeviceRow>(
            "INSERT INTO tenant.mfa_trusted_devices
                (id, account_id, token_hash, user_agent, expires_at)
             VALUES ($1,$2,$3,$4,$5)
             RETURNING id, account_id, token_hash, user_agent, created_at, last_used_at, expires_at",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(token_hash)
        .bind(user_agent)
        .bind(expires_at)
        .fetch_one(&pool)
        .await?)
    }

    /// The live trust a cookie value names, if any.
    pub async fn trusted_device(
        &self,
        tenant: &TenantRow,
        token_hash: &str,
    ) -> Result<Option<TrustedDeviceRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, TrustedDeviceRow>(
            "SELECT id, account_id, token_hash, user_agent, created_at, last_used_at, expires_at
             FROM tenant.mfa_trusted_devices
             WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
             LIMIT 1",
        )
        .bind(token_hash)
        .fetch_optional(&pool)
        .await?)
    }

    /// Record that a trusted browser just used its trust.
    pub async fn touch_trusted_device(
        &self,
        tenant: &TenantRow,
        device_id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("UPDATE tenant.mfa_trusted_devices SET last_used_at = $2 WHERE id = $1")
            .bind(device_id)
            .bind(at)
            .execute(&pool)
            .await?;
        Ok(())
    }

    /// The account's live trusted browsers, newest first.
    pub async fn trusted_devices(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Vec<TrustedDeviceRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, TrustedDeviceRow>(
            "SELECT id, account_id, token_hash, user_agent, created_at, last_used_at, expires_at
             FROM tenant.mfa_trusted_devices
             WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now()
             ORDER BY created_at DESC",
        )
        .bind(account_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Revoke one trusted browser; false when it is not the account's own live trust.
    pub async fn revoke_trusted_device(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        device_id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.mfa_trusted_devices SET revoked_at = now()
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .bind(account_id.uuid())
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete an account and everything that depends on it (§6.1).
    ///
    /// Order matters: the account is disabled and its tokens revoked first, so a failure partway
    /// through leaves it unable to sign in rather than half-deleted but still usable. Each org then
    /// drops the grants the account delegated, the agents it owned (their keys, grants and
    /// delegations cascade) and its membership; the last step deletes the tenant row, which cascades
    /// the identifiers, credentials, backup codes, social identities, trusted devices and tokens.
    /// Audit rows are never removed: the chains are history, not account data.
    pub async fn delete_account(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        {
            let mut tx = pool.begin().await?;
            let found = sqlx::query(
                "UPDATE tenant.accounts SET state = 'disabled', updated_at = now()
                 WHERE id = $1
                 RETURNING id",
            )
            .bind(account_id.uuid())
            .fetch_optional(&mut *tx)
            .await?;
            if found.is_none() {
                tx.rollback().await?;
                return Ok(false);
            }
            sqlx::query(
                "UPDATE tenant.sessions SET revoked_at = now()
                 WHERE account_id = $1 AND revoked_at IS NULL",
            )
            .bind(account_id.uuid())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE tenant.refresh_tokens SET revoked_at = now()
                 WHERE account_id = $1 AND revoked_at IS NULL",
            )
            .bind(account_id.uuid())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        for org in self.orgs(tenant).await? {
            let org_ctx = org.ctx(tenant);
            let mut tx = self.begin_org(&org_ctx).await?;
            sqlx::query("DELETE FROM grants WHERE account_id = $1")
                .bind(account_id.uuid())
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM agents WHERE owner_account_id = $1")
                .bind(account_id.uuid())
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM members WHERE account_id = $1")
                .bind(account_id.uuid())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }

        sqlx::query("DELETE FROM tenant.accounts WHERE id = $1")
            .bind(account_id.uuid())
            .execute(&pool)
            .await?;
        Ok(true)
    }

    /// Every role the tenant defined, by name.
    pub async fn roles(&self, tenant: &TenantRow) -> Result<Vec<RoleRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, RoleRow>(
            "SELECT id, name, description, permissions, created_at
             FROM tenant.roles ORDER BY name",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// One role by its typed uuid.
    pub async fn role_by_id(
        &self,
        tenant: &TenantRow,
        role_id: Uuid,
    ) -> Result<Option<RoleRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, RoleRow>(
            "SELECT id, name, description, permissions, created_at
             FROM tenant.roles WHERE id = $1",
        )
        .bind(role_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Create a role; a name another row holds is `AlreadyExists { entity: "role" }`.
    pub async fn create_role(
        &self,
        tenant: &TenantRow,
        name: &str,
        description: &str,
        permissions: &[String],
    ) -> Result<RoleRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, RoleRow>(
            "INSERT INTO tenant.roles (id, name, description, permissions)
             VALUES ($1,$2,$3,$4)
             RETURNING id, name, description, permissions, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(name)
        .bind(description)
        .bind(permissions)
        .fetch_one(&pool)
        .await
        .map_err(|err| unique_conflict(err, "role"))
    }

    /// Delete a role, and with it every assignment; false when it did not exist.
    pub async fn delete_role(&self, tenant: &TenantRow, role_id: Uuid) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.roles WHERE id = $1")
            .bind(role_id)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Assign a role to an account; the primary key makes a second assignment a no-op the caller
    /// treats as success.
    pub async fn assign_role(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        role_id: Uuid,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.account_roles (account_id, role_id) VALUES ($1,$2)
             ON CONFLICT DO NOTHING",
        )
        .bind(account_id.uuid())
        .bind(role_id)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Remove one assignment; false when the account did not hold the role.
    pub async fn unassign_role(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        role_id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result =
            sqlx::query("DELETE FROM tenant.account_roles WHERE account_id = $1 AND role_id = $2")
                .bind(account_id.uuid())
                .bind(role_id)
                .execute(&pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The roles an account holds, by name.
    pub async fn account_roles(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Vec<RoleRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, RoleRow>(
            "SELECT r.id, r.name, r.description, r.permissions, r.created_at
             FROM tenant.roles r
             JOIN tenant.account_roles a ON a.role_id = r.id
             WHERE a.account_id = $1
             ORDER BY r.name",
        )
        .bind(account_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Replace the account's password with a new argon2id PHC string.
    ///
    /// One password row per account is the invariant the sign-in path relies on, so the old row is
    /// deleted rather than appended to. `credentials.kind` is checked, not merely assumed, so a
    /// future passkey row can never be overwritten by this call.
    pub async fn set_password(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        phc: &str,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM tenant.credentials WHERE account_id = $1 AND kind = 'password'")
            .bind(account_id.uuid())
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO tenant.credentials (id, account_id, kind, secret_enc)
             VALUES ($1,$2,'password',$3)",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(phc.as_bytes())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Replace an account's display name, returning the row as it now stands.
    pub async fn update_display_name(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        display_name: &str,
    ) -> Result<AccountRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, AccountRow>(
            "UPDATE tenant.accounts SET display_name = $2, updated_at = now()
             WHERE id = $1
             RETURNING id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at",
        )
        .bind(account_id.uuid())
        .bind(display_name)
        .fetch_one(&pool)
        .await?)
    }

    /// Replace an account's avatar URL; `None` clears it, returning the row as it now stands.
    pub async fn update_avatar_url(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        avatar_url: Option<&str>,
    ) -> Result<AccountRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, AccountRow>(
            "UPDATE tenant.accounts SET avatar_url = $2, updated_at = now()
             WHERE id = $1
             RETURNING id, primary_email, display_name, avatar_url, state, is_tenant_admin, created_at",
        )
        .bind(account_id.uuid())
        .bind(avatar_url)
        .fetch_one(&pool)
        .await?)
    }

    /// The account's envelope-encrypted TOTP secret, or `None` when MFA is not enrolled.
    ///
    /// The blob is sealed by the caller: the store has no key provider and must never see plaintext
    /// authenticator secrets (§5.6 `credentials.secret_enc`).
    pub async fn totp_secret(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT secret_enc FROM tenant.credentials
             WHERE account_id = $1 AND kind = 'totp' LIMIT 1",
        )
        .bind(account_id.uuid())
        .fetch_optional(&pool)
        .await?
        .map(|(bytes,)| bytes))
    }

    /// Replace the account's TOTP credential with a freshly sealed secret.
    ///
    /// One TOTP row per account, for the same reason as [`Store::set_password`]: the sign-in path
    /// reads it without having to pick a winner, and a re-enrollment must not leave the old
    /// authenticator working.
    pub async fn set_totp_secret(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        sealed: &[u8],
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM tenant.credentials WHERE account_id = $1 AND kind = 'totp'")
            .bind(account_id.uuid())
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO tenant.credentials (id, account_id, kind, secret_enc)
             VALUES ($1,$2,'totp',$3)",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(sealed)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Remove the account's TOTP credential. `true` when one existed.
    pub async fn delete_totp_secret(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result =
            sqlx::query("DELETE FROM tenant.credentials WHERE account_id = $1 AND kind = 'totp'")
                .bind(account_id.uuid())
                .execute(&pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    // ------------------------------------------------------------ MFA backup codes

    /// Replace every backup code of an account with the supplied digests, in one transaction.
    ///
    /// Regenerating is a full replacement of the previous set rather than an append: the account
    /// asked for a fresh sheet and the old one must stop working.
    pub async fn replace_backup_codes(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        code_hashes: &[String],
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM tenant.backup_codes WHERE account_id = $1")
            .bind(account_id.uuid())
            .execute(&mut *tx)
            .await?;

        for code_hash in code_hashes {
            sqlx::query(
                "INSERT INTO tenant.backup_codes (id, account_id, code_hash)
                 VALUES ($1,$2,$3)",
            )
            .bind(Uuid::now_v7())
            .bind(account_id.uuid())
            .bind(code_hash)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// How many backup codes of an account are still unused.
    pub async fn backup_code_count(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<i64, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let (count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM tenant.backup_codes
             WHERE account_id = $1 AND used_at IS NULL",
        )
        .bind(account_id.uuid())
        .fetch_one(&pool)
        .await?;
        Ok(count)
    }

    /// Burn one backup code. `true` when it existed and had not been used yet.
    ///
    /// The update *is* the check: two racing requests can only succeed when they update different
    /// rows, because the second one no longer finds `used_at IS NULL`.
    pub async fn consume_backup_code(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        code_hash: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.backup_codes SET used_at = now()
             WHERE account_id = $1 AND code_hash = $2 AND used_at IS NULL",
        )
        .bind(account_id.uuid())
        .bind(code_hash)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Remove every backup code of an account. `true` when at least one was deleted.
    pub async fn delete_backup_codes(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.backup_codes WHERE account_id = $1")
            .bind(account_id.uuid())
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record a successful TOTP use, so an operator can see the factor is live.
    pub async fn touch_totp(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "UPDATE tenant.credentials SET last_used_at = $2
             WHERE account_id = $1 AND kind = 'totp'",
        )
        .bind(account_id.uuid())
        .bind(at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    // ------------------------------------------------------------ WebAuthn passkeys

    /// Every passkey of an account, oldest first.
    pub async fn passkeys(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Vec<PasskeyRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, PasskeyRow>(
            "SELECT id, account_id, credential_id, secret_enc, sign_count, transports, name,
                    aaguid, created_at, last_used_at
             FROM tenant.credentials
             WHERE account_id = $1 AND kind = 'passkey'
             ORDER BY created_at",
        )
        .bind(account_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// The passkey that owns a credential id, for the assertion ceremonies.
    ///
    /// The lookup is tenant-wide because the browser sends only the id: the account is discovered
    /// from the row, never from a value the client chose.
    pub async fn passkey_by_credential_id(
        &self,
        tenant: &TenantRow,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, PasskeyRow>(
            "SELECT id, account_id, credential_id, secret_enc, sign_count, transports, name,
                    aaguid, created_at, last_used_at
             FROM tenant.credentials
             WHERE kind = 'passkey' AND credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Store a new passkey. The caller seals the COSE public key before calling.
    ///
    /// A duplicate credential id is rejected by the unique index, which is what keeps one
    /// authenticator from being enrolled for two accounts.
    #[expect(
        clippy::too_many_arguments,
        reason = "a passkey insert carries exactly the WebAuthn fields; a struct would only move them"
    )]
    pub async fn insert_passkey(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        credential_id: &[u8],
        sealed: &[u8],
        sign_count: i64,
        transports: &[String],
        name: Option<&str>,
        aaguid: Option<Uuid>,
    ) -> Result<PasskeyRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, PasskeyRow>(
            "INSERT INTO tenant.credentials
                (id, account_id, kind, secret_enc, credential_id, sign_count, transports, name, aaguid)
             VALUES ($1,$2,'passkey',$3,$4,$5,$6,$7,$8)
             RETURNING id, account_id, credential_id, secret_enc, sign_count, transports, name,
                       aaguid, created_at, last_used_at",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(sealed)
        .bind(credential_id)
        .bind(sign_count)
        .bind(transports.to_vec())
        .bind(name)
        .bind(aaguid)
        .fetch_one(&pool)
        .await?)
    }

    /// Rename a passkey, scoped to its owner. `None` when the id is not this account's.
    pub async fn rename_passkey(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        passkey_id: Uuid,
        name: &str,
    ) -> Result<Option<PasskeyRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, PasskeyRow>(
            "UPDATE tenant.credentials SET name = $3
             WHERE id = $1 AND account_id = $2 AND kind = 'passkey'
             RETURNING id, account_id, credential_id, secret_enc, sign_count, transports, name,
                       aaguid, created_at, last_used_at",
        )
        .bind(passkey_id)
        .bind(account_id.uuid())
        .bind(name)
        .fetch_optional(&pool)
        .await?)
    }

    /// Delete a passkey, scoped to its owner. `true` when one was removed.
    pub async fn delete_passkey(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        passkey_id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "DELETE FROM tenant.credentials
             WHERE id = $1 AND account_id = $2 AND kind = 'passkey'",
        )
        .bind(passkey_id)
        .bind(account_id.uuid())
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record a successful assertion: the new counter and the use time.
    pub async fn record_passkey_use(
        &self,
        tenant: &TenantRow,
        passkey_id: Uuid,
        sign_count: i64,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "UPDATE tenant.credentials SET sign_count = $2, last_used_at = $3
             WHERE id = $1 AND kind = 'passkey'",
        )
        .bind(passkey_id)
        .bind(sign_count)
        .bind(at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// The account's role in an org, or `None` when it is not a member.
    pub async fn org_member_role(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
    ) -> Result<Option<String>, StoreError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT role FROM members WHERE account_id = $1")
                .bind(account_id.uuid())
                .fetch_optional(&mut *conn)
                .await?;
        Ok(row.map(|(role,)| role))
    }

    /// Add (or re-role) a member.
    pub async fn org_member_add(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
        role: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO members (account_id, role) VALUES ($1,$2)
             ON CONFLICT (account_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(account_id.uuid())
        .bind(role)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// Change a member's role; `false` when the account is not a member.
    pub async fn org_member_set_role(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
        role: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE members SET role = $2 WHERE account_id = $1")
            .bind(account_id.uuid())
            .bind(role)
            .execute(&mut *conn)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Remove a member; `false` when the account is not a member.
    pub async fn org_member_remove(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM members WHERE account_id = $1")
            .bind(account_id.uuid())
            .execute(&mut *conn)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Members with their email, ordered by creation.
    pub async fn org_members(
        &self,
        conn: &mut PgConnection,
    ) -> Result<Vec<(Uuid, String, String)>, StoreError> {
        Ok(sqlx::query_as(
            "SELECT m.account_id, a.primary_email, m.role
             FROM members m JOIN tenant.accounts a ON a.id = m.account_id
             ORDER BY m.created_at",
        )
        .fetch_all(&mut *conn)
        .await?)
    }

    // ------------------------------------------------------------ organizations

    /// Apply the org migration set to every organization of a tenant — `monaca-server migrate`.
    ///
    /// A fresh org runs the whole set inside its provisioning transaction; this replays it on the
    /// orgs that already exist, which is how a later org migration (the role tables, say) reaches
    /// schemas provisioned before it. The per-org ledger decides which files actually run.
    pub async fn migrate_orgs(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<(String, crate::MigrationReport)>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut reports = Vec::new();
        for org in self.all_orgs(tenant).await? {
            let mut tx = pool.begin().await?;
            let report =
                crate::migrate::apply_org(&mut *tx, &org.schema_name, &tenant.short, "").await?;
            tx.commit().await?;
            reports.push((org.slug, report));
        }
        Ok(reports)
    }

    /// The organization with `slug` in `tenant`, active only.
    pub async fn org_by_slug(&self, tenant: &TenantRow, slug: &str) -> Result<OrgRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, state, is_default, created_at
             FROM tenant.organizations WHERE slug = $1 AND state = 'active'",
        )
        .bind(slug)
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| StoreError::UnknownOrg(slug.to_owned()))
    }

    /// The organization with `slug` in any state — the management API's view (§6.2).
    ///
    /// The operational lookups keep using [`Store::org_by_slug`]; this one exists so an archived
    /// org stays addressable for the `GET`/`PATCH` that reports and reverses the archive.
    pub async fn org_by_slug_any(
        &self,
        tenant: &TenantRow,
        slug: &str,
    ) -> Result<OrgRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, state, is_default, created_at
             FROM tenant.organizations WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| StoreError::UnknownOrg(slug.to_owned()))
    }

    /// The organization with `id`, whatever its state.
    pub async fn org_by_id(&self, tenant: &TenantRow, id: OrgId) -> Result<OrgRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, state, is_default, created_at
             FROM tenant.organizations WHERE id = $1",
        )
        .bind(id.uuid())
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| StoreError::NotFound {
            entity: "org",
            id: id.to_typed_string(),
        })
    }

    /// Every active org in the tenant, oldest first.
    pub async fn orgs(&self, tenant: &TenantRow) -> Result<Vec<OrgRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, state, is_default, created_at
             FROM tenant.organizations WHERE state = 'active' ORDER BY created_at",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Every org in the tenant, archived included, oldest first — the management listing.
    pub async fn all_orgs(&self, tenant: &TenantRow) -> Result<Vec<OrgRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, state, is_default, created_at
             FROM tenant.organizations ORDER BY created_at",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Move an org to `state`; `false` when no row matched.
    ///
    /// The `organizations` CHECK constraint rejects anything but `active` / `archived`; the
    /// server validates the same set first so a bad value is a 400 rather than a 500.
    pub async fn set_org_state(
        &self,
        tenant: &TenantRow,
        id: OrgId,
        state: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("UPDATE tenant.organizations SET state = $2 WHERE id = $1")
            .bind(id.uuid())
            .bind(state)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Every email domain registered to an org, oldest first.
    pub async fn org_email_domains(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
    ) -> Result<Vec<(String, OffsetDateTime)>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as(
            "SELECT domain, created_at FROM tenant.organization_email_domains
             WHERE org_id = $1 ORDER BY created_at",
        )
        .bind(org_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Register `domain` for an org; a domain another org holds is
    /// `AlreadyExists { entity: "email domain" }`.
    pub async fn add_org_email_domain(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        domain: &str,
    ) -> Result<OffsetDateTime, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_scalar(
            "INSERT INTO tenant.organization_email_domains (org_id, domain)
             VALUES ($1,$2) RETURNING created_at",
        )
        .bind(org_id.uuid())
        .bind(domain)
        .fetch_one(&pool)
        .await
        .map_err(|err| unique_conflict(err, "email domain"))
    }

    /// Remove a domain from an org; `false` when it was not registered there.
    pub async fn remove_org_email_domain(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        domain: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "DELETE FROM tenant.organization_email_domains WHERE org_id = $1 AND domain = $2",
        )
        .bind(org_id.uuid())
        .bind(domain)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Whether `domain` is registered to `org_id` — the just-in-time predicate (§6.2).
    pub async fn has_org_email_domain(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        domain: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM tenant.organization_email_domains
             WHERE org_id = $1 AND domain = $2)",
        )
        .bind(org_id.uuid())
        .bind(domain)
        .fetch_one(&pool)
        .await?)
    }

    // ------------------------------------------------------- organization invitations

    /// The invitations that still admit their address, oldest first.
    ///
    /// Accepted and expired rows stay for the record but are not listed: the management view is
    /// the set of invitations an administrator can still revoke (§6.2).
    pub async fn org_invitations(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
    ) -> Result<Vec<OrgInvitationRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, OrgInvitationRow>(
            "SELECT id, email, role, invited_by, created_at, expires_at
             FROM tenant.organization_invitations
             WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > now()
             ORDER BY created_at",
        )
        .bind(org_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Invite `email` to join an org with `role`; a live invitation for the same address is
    /// `AlreadyExists { entity: "invitation" }`.
    ///
    /// An expired row for the same pair is removed first, so re-inviting after the expiry date is
    /// the natural retry rather than a conflict the administrator has to clean up by hand.
    pub async fn create_org_invitation(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        id: Uuid,
        email: &str,
        role: &str,
        invited_by: Option<Uuid>,
        expires_at: OffsetDateTime,
    ) -> Result<OrgInvitationRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        sqlx::query(
            "DELETE FROM tenant.organization_invitations
             WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL AND expires_at <= now()",
        )
        .bind(org_id.uuid())
        .bind(email)
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query_as::<_, OrgInvitationRow>(
            "INSERT INTO tenant.organization_invitations
                (id, org_id, email, role, invited_by, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)
             RETURNING id, email, role, invited_by, created_at, expires_at",
        )
        .bind(id)
        .bind(org_id.uuid())
        .bind(email)
        .bind(role)
        .bind(invited_by)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| unique_conflict(err, "invitation"))?;
        tx.commit().await?;
        Ok(row)
    }

    /// Revoke a pending invitation, returning its address; `None` when it is already accepted,
    /// expired past the cleanup window or simply not there.
    pub async fn revoke_org_invitation(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        id: Uuid,
    ) -> Result<Option<String>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let removed: Option<(String,)> = sqlx::query_as(
            "DELETE FROM tenant.organization_invitations
             WHERE id = $1 AND org_id = $2 AND accepted_at IS NULL
             RETURNING email",
        )
        .bind(id)
        .bind(org_id.uuid())
        .fetch_optional(&pool)
        .await?;
        Ok(removed.map(|(email,)| email))
    }

    /// The live invitation for `email` in an org — the acceptance predicate of sign-in (§6.2).
    pub async fn pending_org_invitation(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        email: &str,
    ) -> Result<Option<(Uuid, String)>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as(
            "SELECT id, role FROM tenant.organization_invitations
             WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL AND expires_at > now()
             ORDER BY created_at LIMIT 1",
        )
        .bind(org_id.uuid())
        .bind(email)
        .fetch_optional(&pool)
        .await?)
    }

    /// Mark an invitation accepted; `false` when another sign-in consumed it first.
    ///
    /// Deliberately a tenant-level write: the org role that owns a sign-in transaction has no
    /// privileges on `tenant.organization_invitations`, so acceptance runs after the membership
    /// transaction commits. A missed acceptance leaves a pending row pointing at a member, which
    /// the list hides only when the row expires — the membership itself is already correct.
    pub async fn accept_org_invitation(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.organization_invitations SET accepted_at = now()
             WHERE id = $1 AND accepted_at IS NULL",
        )
        .bind(id)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // --------------------------------------------------------- organization roles

    /// Every role defined in the org, oldest first.
    pub async fn org_roles(&self, conn: &mut PgConnection) -> Result<Vec<OrgRoleRow>, StoreError> {
        Ok(sqlx::query_as::<_, OrgRoleRow>(
            "SELECT id, name, description, scopes, created_at FROM roles ORDER BY created_at",
        )
        .fetch_all(&mut *conn)
        .await?)
    }

    /// One org role by its row id.
    pub async fn org_role_by_id(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
    ) -> Result<Option<OrgRoleRow>, StoreError> {
        Ok(sqlx::query_as::<_, OrgRoleRow>(
            "SELECT id, name, description, scopes, created_at FROM roles WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?)
    }

    /// Define an org role; a name another role holds is `AlreadyExists { entity: "org role" }`.
    pub async fn create_org_role(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
        name: &str,
        description: &str,
        scopes: &[String],
    ) -> Result<OrgRoleRow, StoreError> {
        sqlx::query_as::<_, OrgRoleRow>(
            "INSERT INTO roles (id, name, description, scopes) VALUES ($1,$2,$3,$4)
             RETURNING id, name, description, scopes, created_at",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(scopes)
        .fetch_one(&mut *conn)
        .await
        .map_err(|err| unique_conflict(err, "org role"))
    }

    /// Replace the supplied fields of an org role; `None` keeps the current value.
    pub async fn update_org_role(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        scopes: Option<&[String]>,
    ) -> Result<Option<OrgRoleRow>, StoreError> {
        sqlx::query_as::<_, OrgRoleRow>(
            "UPDATE roles SET name = COALESCE($2, name),
                    description = COALESCE($3, description),
                    scopes = COALESCE($4, scopes)
             WHERE id = $1
             RETURNING id, name, description, scopes, created_at",
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(scopes)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|err| unique_conflict(err, "org role"))
    }

    /// Delete an org role and every assignment of it; `false` when it does not exist.
    pub async fn delete_org_role(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The org roles assigned to a member, oldest assignment first.
    pub async fn org_member_roles(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
    ) -> Result<Vec<OrgRoleRow>, StoreError> {
        Ok(sqlx::query_as::<_, OrgRoleRow>(
            "SELECT r.id, r.name, r.description, r.scopes, r.created_at
             FROM member_roles m JOIN roles r ON r.id = m.role_id
             WHERE m.account_id = $1 ORDER BY m.created_at",
        )
        .bind(account_id.uuid())
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Assign an org role; `false` when the member already held it.
    pub async fn assign_org_role(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
        role_id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "INSERT INTO member_roles (account_id, role_id) VALUES ($1,$2)
             ON CONFLICT (account_id, role_id) DO NOTHING",
        )
        .bind(account_id.uuid())
        .bind(role_id)
        .execute(&mut *conn)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Remove an assignment; `false` when the member did not hold it.
    pub async fn unassign_org_role(
        &self,
        conn: &mut PgConnection,
        account_id: AccountId,
        role_id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM member_roles WHERE account_id = $1 AND role_id = $2")
            .bind(account_id.uuid())
            .bind(role_id)
            .execute(&mut *conn)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The org role names a member holds — the `org_roles` claim of their id_token (§7.3).
    pub async fn org_role_names(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        account_id: AccountId,
    ) -> Result<Vec<String>, StoreError> {
        let org = self.org_by_id(tenant, org_id).await?;
        let mut tx = self.begin_org(&org.ctx(tenant)).await?;
        let roles = self.org_member_roles(&mut *tx, account_id).await?;
        tx.rollback().await?;
        Ok(roles.into_iter().map(|role| role.name).collect())
    }

    /// Every scope granted by the org roles a member holds in that org (§6.2).
    pub async fn org_role_scopes(
        &self,
        tenant: &TenantRow,
        org_id: OrgId,
        account_id: AccountId,
    ) -> Result<Vec<String>, StoreError> {
        let org = self.org_by_id(tenant, org_id).await?;
        let mut tx = self.begin_org(&org.ctx(tenant)).await?;
        let roles = self.org_member_roles(&mut *tx, account_id).await?;
        tx.rollback().await?;
        let mut scopes: Vec<String> = Vec::new();
        for scope in roles.iter().flat_map(|role| role.scopes.iter()) {
            if !scopes.iter().any(|existing| existing == scope) {
                scopes.push(scope.clone());
            }
        }
        Ok(scopes)
    }

    /// The account's default org: `is_default` if it is a member, else its oldest membership.
    pub async fn org_for_account(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Option<OrgRow>, StoreError> {
        for org in self.orgs(tenant).await? {
            let mut tx = self.begin_org(&org.ctx(tenant)).await?;
            let role = self.org_member_role(&mut *tx, account_id).await?;
            tx.rollback().await?;
            if role.is_some() {
                return Ok(Some(org));
            }
        }
        Ok(None)
    }

    /// The org an agent lives in, from the tenant-wide directory.
    pub async fn org_of_agent(
        &self,
        tenant: &TenantRow,
        agent_id: AgentId,
    ) -> Result<Option<OrgRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, OrgRow>(
            "SELECT o.id, o.slug, o.schema_name, o.role_name, o.state, o.is_default, o.created_at
             FROM tenant.agent_directory d
             JOIN tenant.organizations o ON o.id = d.org_id
             WHERE d.agent_id = $1",
        )
        .bind(agent_id.uuid())
        .fetch_optional(&pool)
        .await?)
    }

    // ------------------------------------------------------------------ resources

    /// Every registered API resource, by identifier.
    pub async fn api_resources(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<ApiResourceRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ApiResourceRow>(
            "SELECT id, name, identifier, scopes, created_at
             FROM tenant.api_resources ORDER BY identifier",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// One API resource by its row id.
    pub async fn api_resource_by_id(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<Option<ApiResourceRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ApiResourceRow>(
            "SELECT id, name, identifier, scopes, created_at
             FROM tenant.api_resources WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// One API resource by its indicator.
    pub async fn api_resource_by_identifier(
        &self,
        tenant: &TenantRow,
        identifier: &str,
    ) -> Result<Option<ApiResourceRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ApiResourceRow>(
            "SELECT id, name, identifier, scopes, created_at
             FROM tenant.api_resources WHERE identifier = $1",
        )
        .bind(identifier)
        .fetch_optional(&pool)
        .await?)
    }

    /// Register a resource; an identifier another row holds is
    /// `AlreadyExists { entity: "api resource" }`.
    pub async fn create_api_resource(
        &self,
        tenant: &TenantRow,
        name: &str,
        identifier: &str,
        scopes: &[String],
    ) -> Result<ApiResourceRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, ApiResourceRow>(
            "INSERT INTO tenant.api_resources (id, name, identifier, scopes)
             VALUES ($1,$2,$3,$4)
             RETURNING id, name, identifier, scopes, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(name)
        .bind(identifier)
        .bind(scopes)
        .fetch_one(&pool)
        .await
        .map_err(|err| unique_conflict(err, "api resource"))
    }

    /// Replace the editable fields of a resource; `None` leaves the current value.
    pub async fn update_api_resource(
        &self,
        tenant: &TenantRow,
        id: Uuid,
        name: Option<&str>,
        scopes: Option<&[String]>,
    ) -> Result<Option<ApiResourceRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ApiResourceRow>(
            "UPDATE tenant.api_resources
             SET name = COALESCE($2, name), scopes = COALESCE($3, scopes)
             WHERE id = $1
             RETURNING id, name, identifier, scopes, created_at",
        )
        .bind(id)
        .bind(name)
        .bind(scopes)
        .fetch_optional(&pool)
        .await?)
    }

    /// Delete a resource; false when it did not exist.
    pub async fn delete_api_resource(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.api_resources WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ------------------------------------------------------------------ clients

    /// A client by its protocol `client_id`.
    pub async fn client_by_client_id(
        &self,
        tenant: &TenantRow,
        client_id: &str,
    ) -> Result<Option<ClientRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ClientRow>(
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, custom_css,
                    cors_allowed_origins, scopes, is_third_party, created_at
             FROM tenant.clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// A client by row id.
    pub async fn client_by_id(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<Option<ClientRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ClientRow>(
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, custom_css,
                    cors_allowed_origins, scopes, is_third_party, created_at
             FROM tenant.clients WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&pool)
        .await?)
    }

    /// The redirect URIs registered for a client row.
    pub async fn client_redirect_uris(
        &self,
        tenant: &TenantRow,
        client_row_id: Uuid,
    ) -> Result<Vec<String>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT redirect_uri FROM tenant.redirect_uris WHERE client_id = $1")
                .bind(client_row_id)
                .fetch_all(&pool)
                .await?;
        Ok(rows.into_iter().map(|(uri,)| uri).collect())
    }

    /// The RP-initiated-logout targets registered for a client row.
    pub async fn client_post_logout_uris(
        &self,
        tenant: &TenantRow,
        client_row_id: Uuid,
    ) -> Result<Vec<String>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(Vec<String>,)> =
            sqlx::query_as("SELECT post_logout_redirect_uris FROM tenant.clients WHERE id = $1")
                .bind(client_row_id)
                .fetch_optional(&pool)
                .await?;
        Ok(row.map(|(uris,)| uris).unwrap_or_default())
    }

    /// Create a client and its redirect URIs, atomically.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_client(
        &self,
        tenant: &TenantRow,
        client_id: &str,
        name: &str,
        kind: &str,
        secret_phc: Option<&str>,
        token_auth_method: &str,
        jwks: Option<&Value>,
        scopes: &[String],
        redirect_uris: &[String],
        post_logout_redirect_uris: &[String],
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO tenant.clients
               (id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes,
                post_logout_redirect_uris)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (client_id) DO UPDATE SET name = EXCLUDED.name,
               post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(client_id)
        .bind(name)
        .bind(kind)
        .bind(secret_phc)
        .bind(token_auth_method)
        .bind(jwks)
        .bind(scopes)
        .bind(post_logout_redirect_uris)
        .fetch_one(&mut *tx)
        .await?;

        for uri in redirect_uris {
            sqlx::query(
                "INSERT INTO tenant.redirect_uris (client_id, redirect_uri) VALUES ($1,$2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(uri)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(id)
    }

    /// Every client in the tenant, ordered by protocol id.
    pub async fn clients(&self, tenant: &TenantRow) -> Result<Vec<ClientRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ClientRow>(
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, custom_css,
                    cors_allowed_origins, scopes, is_third_party, created_at
             FROM tenant.clients ORDER BY client_id",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Insert a client and its redirect URIs, atomically; a `client_id` another row holds is
    /// `AlreadyExists { entity: "client" }`.
    ///
    /// Unlike [`Store::create_client`] — which upserts so seeding is idempotent — this refuses a
    /// duplicate, because an administrator naming an application must get an honest conflict.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_client(
        &self,
        tenant: &TenantRow,
        client_id: &str,
        name: &str,
        kind: &str,
        secret_phc: Option<&str>,
        token_auth_method: &str,
        scopes: &[String],
        redirect_uris: &[String],
        post_logout_redirect_uris: &[String],
        cors_allowed_origins: &[String],
        is_third_party: bool,
    ) -> Result<ClientRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        let row = sqlx::query_as::<_, ClientRow>(
            "INSERT INTO tenant.clients
               (id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes,
                post_logout_redirect_uris, cors_allowed_origins, is_third_party)
             VALUES ($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,$10)
             RETURNING id, client_id, name, kind, secret_hash, token_auth_method, jwks, custom_css,
                       cors_allowed_origins, scopes, is_third_party, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(client_id)
        .bind(name)
        .bind(kind)
        .bind(secret_phc)
        .bind(token_auth_method)
        .bind(scopes)
        .bind(post_logout_redirect_uris)
        .bind(cors_allowed_origins)
        .bind(is_third_party)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| unique_conflict(err, "client"))?;

        for uri in redirect_uris {
            sqlx::query(
                "INSERT INTO tenant.redirect_uris (client_id, redirect_uri) VALUES ($1,$2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(row.id)
            .bind(uri)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(row)
    }

    /// Replace the editable fields of a client; false when the row does not exist.
    ///
    /// The protocol id, the kind and the secret are immutable here. A `None` list is left alone;
    /// a `Some` list replaces the stored set wholesale (including an empty one).
    pub async fn update_client(
        &self,
        tenant: &TenantRow,
        id: Uuid,
        name: Option<&str>,
        scopes: Option<&[String]>,
        redirect_uris: Option<&[String]>,
        post_logout_redirect_uris: Option<&[String]>,
        cors_allowed_origins: Option<&[String]>,
        custom_css: Option<&str>,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        let result = sqlx::query(
            "UPDATE tenant.clients
             SET name = COALESCE($2, name),
                 scopes = COALESCE($3, scopes),
                 post_logout_redirect_uris = COALESCE($4, post_logout_redirect_uris),
                 cors_allowed_origins = COALESCE($5, cors_allowed_origins),
                 custom_css = CASE WHEN $6 IS NULL THEN custom_css
                                   WHEN $6 = '' THEN NULL ELSE $6 END
             WHERE id = $1",
        )
        .bind(id)
        .bind(name)
        .bind(scopes)
        .bind(post_logout_redirect_uris)
        .bind(cors_allowed_origins)
        .bind(custom_css)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }

        if let Some(uris) = redirect_uris {
            sqlx::query("DELETE FROM tenant.redirect_uris WHERE client_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            for uri in uris {
                sqlx::query(
                    "INSERT INTO tenant.redirect_uris (client_id, redirect_uri) VALUES ($1,$2)
                     ON CONFLICT DO NOTHING",
                )
                .bind(id)
                .bind(uri)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(true)
    }

    /// Replace a client's secret hash; false when the row does not exist.
    pub async fn set_client_secret(
        &self,
        tenant: &TenantRow,
        id: Uuid,
        secret_phc: &str,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("UPDATE tenant.clients SET secret_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(secret_phc)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete a client; its codes, refresh tokens and redirect URIs cascade.
    pub async fn delete_client(&self, tenant: &TenantRow, id: Uuid) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query("DELETE FROM tenant.clients WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Every origin any application of the tenant registered for CORS, de-duplicated.
    ///
    /// A preflight request carries no `client_id`, so the browser's gate has to be decided from
    /// the tenant's whole application set; the union is that set.
    pub async fn tenant_cors_origins(&self, tenant: &TenantRow) -> Result<Vec<String>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT origin
             FROM tenant.clients
             CROSS JOIN LATERAL unnest(cors_allowed_origins) AS o(origin)
             ORDER BY origin",
        )
        .fetch_all(&pool)
        .await?;
        Ok(rows.into_iter().map(|(origin,)| origin).collect())
    }

    // ---------------------------------------------------------------- consent grants

    /// The account's *remembered* approval for a client, if any.
    ///
    /// A one-shot row is deliberately invisible here: it is listed and revocable, but it never
    /// covers a later authorize request.
    pub async fn consent(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        client_row_id: Uuid,
    ) -> Result<Option<ConsentRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ConsentRow>(
            "SELECT account_id, client_id, scopes, kind, interaction_id, granted_at, updated_at
             FROM tenant.consents
             WHERE account_id = $1 AND client_id = $2 AND kind = 'remember'",
        )
        .bind(account_id.uuid())
        .bind(client_row_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Every approval (remembered and one-shot) the account holds for one client.
    pub async fn consents_for_client(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        client_row_id: Uuid,
    ) -> Result<Vec<ConsentRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ConsentRow>(
            "SELECT account_id, client_id, scopes, kind, interaction_id, granted_at, updated_at
             FROM tenant.consents WHERE account_id = $1 AND client_id = $2
             ORDER BY granted_at",
        )
        .bind(account_id.uuid())
        .bind(client_row_id)
        .fetch_all(&pool)
        .await?)
    }

    /// Record or refresh an approval; approving again keeps the original `granted_at`.
    ///
    /// Remembering supersedes a pending one-shot row for the same client, because the remembered
    /// scopes now cover everything that row listed.
    pub async fn upsert_consent(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        client_row_id: Uuid,
        scopes: &[String],
        kind: &str,
        interaction_id: Option<&str>,
    ) -> Result<ConsentRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        let row = sqlx::query_as::<_, ConsentRow>(
            "INSERT INTO tenant.consents (account_id, client_id, scopes, kind, interaction_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (account_id, client_id, kind)
             DO UPDATE SET scopes = EXCLUDED.scopes,
                           interaction_id = EXCLUDED.interaction_id,
                           updated_at = now()
             RETURNING account_id, client_id, scopes, kind, interaction_id, granted_at, updated_at",
        )
        .bind(account_id.uuid())
        .bind(client_row_id)
        .bind(scopes)
        .bind(kind)
        .bind(interaction_id)
        .fetch_one(&mut *tx)
        .await?;
        if kind == "remember" {
            sqlx::query(
                "DELETE FROM tenant.consents
                 WHERE account_id = $1 AND client_id = $2 AND kind = 'one_shot'",
            )
            .bind(account_id.uuid())
            .bind(client_row_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(row)
    }

    /// Third-party applications this account approved, most recently used first.
    pub async fn authorized_apps(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Vec<AuthorizedAppRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, AuthorizedAppRow>(
            "SELECT c.client_id, c.name, g.scopes, g.kind, g.granted_at, g.updated_at
             FROM tenant.consents g
             JOIN tenant.clients c ON c.id = g.client_id
             WHERE g.account_id = $1
             ORDER BY g.updated_at DESC, c.name, g.kind",
        )
        .bind(account_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Remove every approval for one client; false when the account held none.
    pub async fn revoke_consent(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        client_row_id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result =
            sqlx::query("DELETE FROM tenant.consents WHERE account_id = $1 AND client_id = $2")
                .bind(account_id.uuid())
                .bind(client_row_id)
                .execute(&pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    // ---------------------------------------------------------------- sessions

    /// Insert a sign-in session. The row id is the cookie value's source of truth.
    pub async fn insert_session(
        &self,
        tenant: &TenantRow,
        session_id: Uuid,
        account_id: Uuid,
        client_row_id: Option<Uuid>,
        expires_at: OffsetDateTime,
        user_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.sessions
               (id, account_id, client_id, expires_at, last_seen_at, user_agent)
             VALUES ($1,$2,$3,$4,now(),$5)",
        )
        .bind(session_id)
        .bind(account_id)
        .bind(client_row_id)
        .bind(expires_at)
        .bind(user_agent)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// A session by id, revoked or not. The caller decides whether it is still usable.
    pub async fn session_by_id(
        &self,
        tenant: &TenantRow,
        session_id: Uuid,
    ) -> Result<Option<SessionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SessionRow>(
            "SELECT id, account_id, client_id, issued_at, expires_at, revoked_at,
                    last_seen_at, user_agent
             FROM tenant.sessions WHERE id = $1",
        )
        .bind(session_id)
        .fetch_optional(&pool)
        .await?)
    }

    /// Record that a session authenticated an authorize request.
    pub async fn touch_session(
        &self,
        tenant: &TenantRow,
        session_id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("UPDATE tenant.sessions SET last_seen_at = $2 WHERE id = $1")
            .bind(session_id)
            .bind(at)
            .execute(&pool)
            .await?;
        Ok(())
    }

    /// Every session of an account that is not revoked and not expired.
    pub async fn list_sessions(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Vec<SessionRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SessionRow>(
            "SELECT id, account_id, client_id, issued_at, expires_at, revoked_at,
                    last_seen_at, user_agent
             FROM tenant.sessions
             WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now()
             ORDER BY last_seen_at DESC",
        )
        .bind(account_id.uuid())
        .fetch_all(&pool)
        .await?)
    }

    /// Revoke one session. Returns whether a live session was actually revoked.
    pub async fn revoke_session(
        &self,
        tenant: &TenantRow,
        session_id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.sessions SET revoked_at = now()
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Revoke every live session of an account. Returns how many were revoked.
    pub async fn revoke_account_sessions(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<u64, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.sessions SET revoked_at = now()
             WHERE account_id = $1 AND revoked_at IS NULL",
        )
        .bind(account_id.uuid())
        .execute(&pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every live session of an account except `keep` — the browser making the change.
    pub async fn revoke_other_sessions(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        keep: Uuid,
    ) -> Result<u64, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.sessions SET revoked_at = now()
             WHERE account_id = $1 AND id <> $2 AND revoked_at IS NULL",
        )
        .bind(account_id.uuid())
        .bind(keep)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ------------------------------------------------------- verification codes

    /// Issue a verification code, retiring every earlier live code for the same purpose and
    /// address in one transaction — an old code stops working the moment a new one is sent.
    pub async fn insert_verification_code(
        &self,
        tenant: &TenantRow,
        purpose: &str,
        identifier: &str,
        code_hash: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        sqlx::query(
            "UPDATE tenant.verification_codes SET consumed_at = now()
             WHERE purpose = $1 AND identifier = $2 AND consumed_at IS NULL",
        )
        .bind(purpose)
        .bind(identifier)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO tenant.verification_codes (id, purpose, identifier, code_hash, expires_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::now_v7())
        .bind(purpose)
        .bind(identifier)
        .bind(code_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// The newest unconsumed code for a purpose and address, expired or not.
    pub async fn verification_code_latest(
        &self,
        tenant: &TenantRow,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, VerificationRow>(
            "SELECT id, purpose, identifier, code_hash, attempts, expires_at, consumed_at, created_at
             FROM tenant.verification_codes
             WHERE purpose = $1 AND identifier = $2 AND consumed_at IS NULL
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(purpose)
        .bind(identifier)
        .fetch_optional(&pool)
        .await?)
    }

    /// A live code or link token looked up by its hash alone (§6.1 sign-in links).
    ///
    /// A link carries only the token, not the address, so the row found here supplies the
    /// identifier the link signs in. `code_hash` is a 256-bit secret for a link, which is why no
    /// attempt counter is consulted on this path.
    pub async fn verification_code_by_hash(
        &self,
        tenant: &TenantRow,
        purpose: &str,
        code_hash: &str,
    ) -> Result<Option<VerificationRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, VerificationRow>(
            "SELECT id, purpose, identifier, code_hash, attempts, expires_at, consumed_at, created_at
             FROM tenant.verification_codes
             WHERE purpose = $1 AND code_hash = $2 AND consumed_at IS NULL
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(purpose)
        .bind(code_hash)
        .fetch_optional(&pool)
        .await?)
    }

    /// Count one failed attempt against a live code and return the new total.
    ///
    /// Returns `None` when the code was already consumed, which makes the caller's answer the
    /// same as an unknown code.
    pub async fn verification_code_attempt(
        &self,
        tenant: &TenantRow,
        code_id: Uuid,
    ) -> Result<Option<i32>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(i32,)> = sqlx::query_as(
            "UPDATE tenant.verification_codes SET attempts = attempts + 1
             WHERE id = $1 AND consumed_at IS NULL
             RETURNING attempts",
        )
        .bind(code_id)
        .fetch_optional(&pool)
        .await?;
        Ok(row.map(|(attempts,)| attempts))
    }

    /// Redeem a code. Returns whether this call was the one that consumed it.
    pub async fn consume_verification_code(
        &self,
        tenant: &TenantRow,
        code_id: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.verification_codes SET consumed_at = now()
             WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(code_id)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    // ------------------------------------------------------------- signing keys

    /// Every non-retired signing key for the tenant, newest first.
    pub async fn signing_keys(&self, tenant: &TenantRow) -> Result<Vec<SigningKeyRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, SigningKeyRow>(
            "SELECT id, private_enc, public_jwk FROM tenant.signing_keys
             WHERE retired_at IS NULL ORDER BY created_at DESC",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Insert a signing key.
    pub async fn insert_signing_key(
        &self,
        tenant: &TenantRow,
        id: Uuid,
        private_enc: &[u8],
        public_jwk: &Value,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.signing_keys (id, private_enc, public_jwk)
             VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(private_enc)
        .bind(public_jwk)
        .execute(&pool)
        .await?;
        Ok(())
    }

    // -------------------------------------------------------------- auth codes

    /// Store an authorization code (only its hash).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_auth_code(
        &self,
        tenant: &TenantRow,
        code_hash: &str,
        client_row_id: Uuid,
        account_id: Uuid,
        org_id: Uuid,
        redirect_uri: &str,
        scope: &[String],
        code_challenge: &str,
        nonce: Option<&str>,
        resource: Option<&str>,
        session_id: Option<Uuid>,
        dpop_jkt: Option<&str>,
        auth_time: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.auth_codes
               (id, code_hash, client_id, account_id, org_id, redirect_uri, scope,
                code_challenge, nonce, resource, session_id, dpop_jkt, auth_time, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(Uuid::now_v7())
        .bind(code_hash)
        .bind(client_row_id)
        .bind(account_id)
        .bind(org_id)
        .bind(redirect_uri)
        .bind(scope)
        .bind(code_challenge)
        .bind(nonce)
        .bind(resource)
        .bind(session_id)
        .bind(dpop_jkt)
        .bind(auth_time)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Atomically consume an authorization code: `UPDATE … WHERE consumed_at IS NULL RETURNING`.
    pub async fn take_auth_code(
        &self,
        tenant: &TenantRow,
        code_hash: &str,
    ) -> Result<Option<AuthCodeRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, AuthCodeRow>(
            "UPDATE tenant.auth_codes SET consumed_at = now()
             WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
             RETURNING code_hash, client_id, account_id, org_id, redirect_uri, scope,
                       code_challenge, nonce, resource, session_id, dpop_jkt, auth_time,
                       expires_at, consumed_at",
        )
        .bind(code_hash)
        .fetch_optional(&pool)
        .await?)
    }

    // ---------------------------------------------------------- refresh tokens

    /// Store a refresh token (only its hash).
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_refresh_token(
        &self,
        tenant: &TenantRow,
        token_hash: &str,
        client_row_id: Uuid,
        account_id: Uuid,
        org_id: Uuid,
        scope: &[String],
        resource: Option<&str>,
        rotated_from: Option<Uuid>,
        family_id: Uuid,
        dpop_jkt: Option<&str>,
        auth_time: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant.refresh_tokens
               (id, token_hash, client_id, account_id, org_id, scope, resource, rotated_from,
                family_id, dpop_jkt, auth_time, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(id)
        .bind(token_hash)
        .bind(client_row_id)
        .bind(account_id)
        .bind(org_id)
        .bind(scope)
        .bind(resource)
        .bind(rotated_from)
        .bind(family_id)
        .bind(dpop_jkt)
        .bind(auth_time)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(id)
    }

    /// A refresh token by hash. Revoked rows are returned so reuse can be detected.
    pub async fn refresh_by_hash(
        &self,
        tenant: &TenantRow,
        token_hash: &str,
    ) -> Result<Option<RefreshRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, RefreshRow>(
            "SELECT id, token_hash, client_id, account_id, org_id, scope, resource,
                    expires_at, revoked_at, rotated_from, family_id, dpop_jkt, auth_time,
                    created_at
             FROM tenant.refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&pool)
        .await?)
    }

    /// Revoke one refresh token.
    pub async fn revoke_refresh_token(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("UPDATE tenant.refresh_tokens SET revoked_at = now() WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await?;
        Ok(())
    }

    /// Revoke every live refresh token of an account — suspension must end renewal, not just
    /// the next sign-in.
    pub async fn revoke_account_refresh_tokens(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<u64, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.refresh_tokens SET revoked_at = now()
             WHERE account_id = $1 AND revoked_at IS NULL",
        )
        .bind(account_id.uuid())
        .execute(&pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every live refresh token an account holds for one client, so withdrawing an
    /// application's approval also ends the renewal it was relying on.
    pub async fn revoke_account_client_refresh_tokens(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        client_row_id: Uuid,
    ) -> Result<u64, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let result = sqlx::query(
            "UPDATE tenant.refresh_tokens SET revoked_at = now()
             WHERE account_id = $1 AND client_id = $2 AND revoked_at IS NULL",
        )
        .bind(account_id.uuid())
        .bind(client_row_id)
        .execute(&pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revoke every live refresh token in a rotation family (reuse detection, RFC 6749 §10.4).
    ///
    /// A family is created when the authorization code is exchanged and every rotated token
    /// carries the same `family_id`, so one statement kills the whole chain. Legacy rows with a
    /// `NULL` family fall back to their own id.
    pub async fn revoke_refresh_family(
        &self,
        tenant: &TenantRow,
        family_id: Uuid,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "WITH RECURSIVE family AS (
                SELECT id FROM tenant.refresh_tokens
                WHERE id = $1 OR family_id = $1
                UNION ALL
                SELECT t.id FROM tenant.refresh_tokens t JOIN family f ON t.rotated_from = f.id
             )
             UPDATE tenant.refresh_tokens SET revoked_at = now()
             WHERE id IN (SELECT id FROM family) AND revoked_at IS NULL",
        )
        .bind(family_id)
        .execute(&pool)
        .await?;
        Ok(())
    }

    // -------------------------------------------------- protocol support tables

    /// Remember a DPoP proof's `jti` until its freshness window ends.
    ///
    /// Returns `false` when the `jti` was already seen — a replay, which the caller must reject.
    pub async fn dpop_replay_add(
        &self,
        tenant: &TenantRow,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let inserted = sqlx::query(
            "INSERT INTO tenant.dpop_replays (jti, expires_at) VALUES ($1,$2)
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&pool)
        .await?
        .rows_affected();
        sqlx::query("DELETE FROM tenant.dpop_replays WHERE expires_at < now()")
            .execute(&pool)
            .await?;
        Ok(inserted == 1)
    }

    /// Record a revoked access-token `jti` until the token would have expired.
    pub async fn revoke_access_token(
        &self,
        tenant: &TenantRow,
        jti: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.revoked_access_tokens (jti, expires_at) VALUES ($1,$2)
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Whether `jti` was revoked and has not yet reached its expiry.
    pub async fn access_token_revoked(
        &self,
        tenant: &TenantRow,
        jti: Uuid,
    ) -> Result<bool, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1::bigint FROM tenant.revoked_access_tokens
             WHERE jti = $1 AND expires_at > now()",
        )
        .bind(jti)
        .fetch_optional(&pool)
        .await?;
        Ok(row.is_some())
    }

    /// Store a pushed authorization request (RFC 9126), keyed by the hash of its `request_uri`.
    #[allow(clippy::too_many_arguments)]
    pub async fn par_insert(
        &self,
        tenant: &TenantRow,
        request_uri_hash: &str,
        client_row_id: Uuid,
        params: &Value,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.par_requests
               (id, request_uri_hash, client_id, params, expires_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::now_v7())
        .bind(request_uri_hash)
        .bind(client_row_id)
        .bind(params)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(())
    }

    /// Atomically consume a pushed authorization request.
    pub async fn par_take(
        &self,
        tenant: &TenantRow,
        request_uri_hash: &str,
    ) -> Result<Option<ParRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, ParRow>(
            "UPDATE tenant.par_requests SET consumed_at = now()
             WHERE request_uri_hash = $1 AND consumed_at IS NULL AND expires_at > now()
             RETURNING client_id, params, expires_at, consumed_at",
        )
        .bind(request_uri_hash)
        .fetch_optional(&pool)
        .await?)
    }

    // ------------------------------------------------------------------- agents

    /// Create an agent, its directory row and its first key — one transaction.
    pub async fn create_agent(
        &self,
        org: &monaca_types::OrgCtx,
        agent_id: AgentId,
        name: &str,
        description: &str,
        owner_account_id: AccountId,
    ) -> Result<AgentRow, StoreError> {
        let mut tx = self.begin_org(org).await?;
        let row = sqlx::query_as::<_, AgentRow>(
            "INSERT INTO agents (id, name, description, owner_account_id, state)
             VALUES ($1,$2,$3,$4,'active')
             RETURNING id, name, description, owner_account_id, state, created_at",
        )
        .bind(agent_id.uuid())
        .bind(name)
        .bind(description)
        .bind(owner_account_id.uuid())
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO tenant.agent_directory (agent_id, org_id) VALUES ($1,$2)
             ON CONFLICT (agent_id) DO NOTHING",
        )
        .bind(agent_id.uuid())
        .bind(org.org_id.uuid())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row)
    }

    /// Agents in the org, oldest first.
    pub async fn agents(&self, conn: &mut PgConnection) -> Result<Vec<AgentRow>, StoreError> {
        Ok(sqlx::query_as::<_, AgentRow>(
            "SELECT id, name, description, owner_account_id, state, created_at
             FROM agents ORDER BY created_at",
        )
        .fetch_all(&mut *conn)
        .await?)
    }

    /// One agent by id.
    pub async fn agent(
        &self,
        conn: &mut PgConnection,
        agent_id: AgentId,
    ) -> Result<Option<AgentRow>, StoreError> {
        Ok(sqlx::query_as::<_, AgentRow>(
            "SELECT id, name, description, owner_account_id, state, created_at
             FROM agents WHERE id = $1",
        )
        .bind(agent_id.uuid())
        .fetch_optional(&mut *conn)
        .await?)
    }

    /// Keys of one agent, newest first.
    pub async fn agent_keys(
        &self,
        conn: &mut PgConnection,
        agent_id: AgentId,
    ) -> Result<Vec<AgentKeyRow>, StoreError> {
        Ok(sqlx::query_as::<_, AgentKeyRow>(
            "SELECT id, agent_id, public_jwk, kid, fingerprint, created_at, revoked_at
             FROM agent_keys WHERE agent_id = $1 ORDER BY created_at DESC",
        )
        .bind(agent_id.uuid())
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Register a public key for an agent.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_agent_key(
        &self,
        conn: &mut PgConnection,
        key_id: Uuid,
        agent_id: AgentId,
        public_jwk: &Value,
        kid: &str,
        fingerprint: &str,
    ) -> Result<AgentKeyRow, StoreError> {
        Ok(sqlx::query_as::<_, AgentKeyRow>(
            "INSERT INTO agent_keys (id, agent_id, public_jwk, kid, fingerprint)
             VALUES ($1,$2,$3,$4,$5)
             RETURNING id, agent_id, public_jwk, kid, fingerprint, created_at, revoked_at",
        )
        .bind(key_id)
        .bind(agent_id.uuid())
        .bind(public_jwk)
        .bind(kid)
        .bind(fingerprint)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Revoke one agent key.
    pub async fn revoke_agent_key(
        &self,
        conn: &mut PgConnection,
        agent_id: AgentId,
        key_id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE agent_keys SET revoked_at = now()
             WHERE id = $1 AND agent_id = $2 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .bind(agent_id.uuid())
        .execute(&mut *conn)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ------------------------------------------------------------------- grants

    /// Create a grant.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_grant(
        &self,
        conn: &mut PgConnection,
        grant_id: GrantId,
        agent_id: AgentId,
        account_id: AccountId,
        scopes: &[String],
        resource: &str,
        constraints: &Value,
        expires_at: Option<OffsetDateTime>,
        created_by: Uuid,
    ) -> Result<GrantRow, StoreError> {
        Ok(sqlx::query_as::<_, GrantRow>(
            "INSERT INTO grants
               (id, agent_id, account_id, scopes, resource, constraints, expires_at, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             RETURNING id, agent_id, account_id, scopes, resource, constraints,
                       expires_at, revoked_at, created_at, created_by",
        )
        .bind(grant_id.uuid())
        .bind(agent_id.uuid())
        .bind(account_id.uuid())
        .bind(scopes)
        .bind(resource)
        .bind(constraints)
        .bind(expires_at)
        .bind(created_by)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Grants in the org, oldest first.
    pub async fn grants(&self, conn: &mut PgConnection) -> Result<Vec<GrantRow>, StoreError> {
        Ok(sqlx::query_as::<_, GrantRow>(
            "SELECT id, agent_id, account_id, scopes, resource, constraints,
                    expires_at, revoked_at, created_at, created_by
             FROM grants ORDER BY created_at",
        )
        .fetch_all(&mut *conn)
        .await?)
    }

    /// One grant by id.
    pub async fn grant(
        &self,
        conn: &mut PgConnection,
        grant_id: GrantId,
    ) -> Result<Option<GrantRow>, StoreError> {
        Ok(sqlx::query_as::<_, GrantRow>(
            "SELECT id, agent_id, account_id, scopes, resource, constraints,
                    expires_at, revoked_at, created_at, created_by
             FROM grants WHERE id = $1",
        )
        .bind(grant_id.uuid())
        .fetch_optional(&mut *conn)
        .await?)
    }

    /// Revoke a grant.
    pub async fn revoke_grant(
        &self,
        conn: &mut PgConnection,
        grant_id: GrantId,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(grant_id.uuid())
        .execute(&mut *conn)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // --------------------------------------------------------------- rate limits

    /// Every configured rate-limit row for the tenant.
    pub async fn rate_limits(&self, tenant: &TenantRow) -> Result<Vec<RateLimitRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, RateLimitRow>(
            "SELECT id, endpoint, client_id, limit_count, window_secs
             FROM tenant.rate_limits ORDER BY endpoint, client_id NULLS FIRST",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Count one request in a shared fixed window, returning `(count, window_start)`.
    ///
    /// The upsert is one atomic statement, so every server instance increments the same row. A
    /// window that has elapsed is reset in place, which keeps the table bounded by the number of
    /// distinct bucket keys rather than by request volume.
    pub async fn rate_limit_hit(
        &self,
        tenant: &TenantRow,
        bucket_key: &str,
        window_secs: u32,
        now: OffsetDateTime,
    ) -> Result<(i64, OffsetDateTime), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: (i64, OffsetDateTime) = sqlx::query_as(
            "INSERT INTO tenant.rate_limit_counters (bucket_key, window_start, count)
             VALUES ($1,$2,1)
             ON CONFLICT (bucket_key) DO UPDATE SET
               count = CASE
                 WHEN rate_limit_counters.window_start + make_interval(secs => $3::double precision) <= $2
                 THEN 1 ELSE rate_limit_counters.count + 1 END,
               window_start = CASE
                 WHEN rate_limit_counters.window_start + make_interval(secs => $3::double precision) <= $2
                 THEN $2 ELSE rate_limit_counters.window_start END
             RETURNING count, window_start",
        )
        .bind(bucket_key)
        .bind(now)
        .bind(window_secs as i32)
        .fetch_one(&pool)
        .await?;
        Ok(row)
    }

    /// The tenant's live fixed-window counters, for the management status view.
    pub async fn rate_limit_counters(
        &self,
        tenant: &TenantRow,
    ) -> Result<Vec<(String, i64, OffsetDateTime)>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, (String, i64, OffsetDateTime)>(
            "SELECT bucket_key, count, window_start
             FROM tenant.rate_limit_counters ORDER BY bucket_key",
        )
        .fetch_all(&pool)
        .await?)
    }

    /// Clear a tenant's shared counters. A configuration write starts every window fresh, so a
    /// lowered limit applies to the next request instead of inheriting an earlier count.
    pub async fn reset_rate_limit_counters(&self, tenant: &TenantRow) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query("DELETE FROM tenant.rate_limit_counters")
            .execute(&pool)
            .await?;
        Ok(())
    }

    /// Replace the tenant's whole rate-limit configuration.
    ///
    /// The caller validates every entry first; the delete-and-insert is one transaction so a
    /// reader never sees a half-replaced set.
    pub async fn replace_rate_limits(
        &self,
        tenant: &TenantRow,
        rows: &[(String, Option<String>, i32, i32)],
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM tenant.rate_limits")
            .execute(&mut *tx)
            .await?;
        for (endpoint, client_id, limit_count, window_secs) in rows {
            sqlx::query(
                "INSERT INTO tenant.rate_limits
                   (id, endpoint, client_id, limit_count, window_secs)
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(Uuid::now_v7())
            .bind(endpoint)
            .bind(client_id)
            .bind(limit_count)
            .bind(window_secs)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    // -------------------------------------------------------------------- audit

    /// Append an event to `{schema}`'s chain — §8.3.
    ///
    /// Caller supplies the transaction so the audit row commits with the business write.
    pub async fn audit_append(
        &self,
        conn: &mut PgConnection,
        schema: &str,
        event: &AuditEvent,
    ) -> Result<ChainFields, StoreError> {
        let schema = quote_ident(schema);
        event
            .validate()
            .map_err(|err| StoreError::Database(format!("invalid audit event: {err}")))?;

        // PostgreSQL's `timestamptz` keeps microseconds and the event is hashed before storage, so
        // a nanosecond-precision `at` would never round-trip. §8.1 asks for millisecond precision,
        // so the event is normalized *before* hashing and the stored row is that same value.
        let event = &{
            let mut normalized = event.clone();
            if let Ok(at) = normalized
                .at
                .replace_nanosecond(u32::from(normalized.at.millisecond()) * 1_000_000)
            {
                normalized.at = at;
            }
            normalized
        };

        let (_head_seq, prev): (i64, Vec<u8>) = sqlx::query_as(q(format!(
            "SELECT seq, hash FROM {schema}.audit_chain_head WHERE singleton FOR UPDATE"
        )))
        .fetch_one(&mut *conn)
        .await?;

        let prev_hash: [u8; 32] = prev.try_into().map_err(|bytes: Vec<u8>| {
            StoreError::Database(format!("chain head hash is {} bytes", bytes.len()))
        })?;

        let hash = chain_hash(&prev_hash, event)
            .map_err(|err| StoreError::Database(format!("audit hash: {err}")))?;

        let subject_id = subject_uuid(event.subject.id.as_deref());
        let actor_chain = serde_json::to_value(&event.actor_chain)
            .map_err(|err| StoreError::Database(format!("actor_chain: {err}")))?;

        let (stored_seq,): (i64,) = sqlx::query_as(q(format!(
            "INSERT INTO {schema}.audit_events
               (id, at, action, actor_chain, subject_type, subject_id, subject_ref, decision,
                grant_id, jti, payload, prev_hash, hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             RETURNING seq"
        )))
        .bind(event.id.uuid())
        .bind(event.at)
        .bind(&event.action)
        .bind(actor_chain)
        .bind(subject_type_str(event.subject.subject_type))
        .bind(subject_id)
        .bind(event.subject.id.as_deref())
        .bind(decision_str(event.decision))
        .bind(event.grant_id.map(|id| id.uuid()))
        .bind(event.jti)
        .bind(&event.payload)
        .bind(prev_hash.as_slice())
        .bind(hash.as_slice())
        .fetch_one(&mut *conn)
        .await?;

        sqlx::query(q(format!(
            "UPDATE {schema}.audit_chain_head
             SET seq = $1, hash = $2, updated_at = now() WHERE singleton"
        )))
        .bind(stored_seq)
        .bind(hash.as_slice())
        .execute(&mut *conn)
        .await?;

        Ok(ChainFields {
            seq: stored_seq,
            prev_hash,
            hash,
        })
    }

    /// The chain head.
    pub async fn audit_head(
        &self,
        conn: &mut PgConnection,
        schema: &str,
    ) -> Result<ChainHead, StoreError> {
        let schema = quote_ident(schema);
        let (seq, hash): (i64, Vec<u8>) = sqlx::query_as(q(format!(
            "SELECT seq, hash FROM {schema}.audit_chain_head WHERE singleton"
        )))
        .fetch_one(&mut *conn)
        .await?;
        let hash: [u8; 32] = hash.try_into().map_err(|bytes: Vec<u8>| {
            StoreError::Database(format!("chain head hash is {} bytes", bytes.len()))
        })?;
        Ok(ChainHead { seq, hash })
    }

    /// Newest events first, with the §6.2 filters.
    pub async fn audit_list(
        &self,
        conn: &mut PgConnection,
        schema: &str,
        limit: i64,
        before: Option<i64>,
        grant_id: Option<Uuid>,
        jti: Option<Uuid>,
        action: Option<&str>,
    ) -> Result<Vec<AuditRow>, StoreError> {
        let schema = quote_ident(schema);
        Ok(sqlx::query_as::<_, AuditRow>(q(format!(
            "SELECT seq, id, at, action, actor_chain, subject_type, subject_id, subject_ref,
                    decision, grant_id, jti, payload, prev_hash, hash
             FROM {schema}.audit_events
             WHERE ($1::bigint IS NULL OR seq < $1)
               AND ($2::uuid IS NULL OR grant_id = $2)
               AND ($3::uuid IS NULL OR jti = $3)
               AND ($4::text IS NULL OR action = $4)
             ORDER BY seq DESC
             LIMIT $5"
        )))
        .bind(before)
        .bind(grant_id)
        .bind(jti)
        .bind(action)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// The stored rows needed to verify `[from, to]`, ascending.
    pub async fn audit_rows(
        &self,
        conn: &mut PgConnection,
        schema: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<AuditRow>, StoreError> {
        let schema = quote_ident(schema);
        Ok(sqlx::query_as::<_, AuditRow>(q(format!(
            "SELECT seq, id, at, action, actor_chain, subject_type, subject_id, subject_ref,
                    decision, grant_id, jti, payload, prev_hash, hash
             FROM {schema}.audit_events
             WHERE seq >= $1 AND seq <= $2 ORDER BY seq"
        )))
        .bind(from)
        .bind(to)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Verify a range — §8.4.
    pub async fn audit_verify(
        &self,
        conn: &mut PgConnection,
        schema: &str,
        from: i64,
        to: Option<i64>,
    ) -> Result<VerifyReport, StoreError> {
        let head = self.audit_head(conn, schema).await?;
        let to = to.unwrap_or(head.seq);
        let rows = self.audit_rows(conn, schema, from, to).await?;

        let stored: Vec<StoredEvent> = rows
            .iter()
            .map(|row| {
                let event = AuditEvent {
                    id: monaca_types::EventId::from_uuid(row.id),
                    at: row.at,
                    action: row.action.clone(),
                    actor_chain: serde_json::from_value(row.actor_chain.clone())
                        .unwrap_or_default(),
                    subject: AuditSubject {
                        subject_type: subject_type_from_str(&row.subject_type),
                        id: row.subject_ref.clone(),
                    },
                    decision: decision_from_str(&row.decision),
                    grant_id: row.grant_id.map(GrantId::from_uuid),
                    jti: row.jti,
                    payload: row.payload.clone(),
                };
                let chain = ChainFields {
                    seq: row.seq,
                    prev_hash: to_array(&row.prev_hash),
                    hash: to_array(&row.hash),
                };
                StoredEvent::new(event, chain)
            })
            .collect();

        Ok(verify_chain(&stored, head, from))
    }

    /// The newest dev mail row addressed to `to`, optionally filtered by `purpose`.
    ///
    /// This is the M0 stand-in for a real mail delivery: the server writes `mail.verification` to
    /// the outbox and `GET /internal/mail` reads it back, so the acceptance script can finish a
    /// verification flow without an SMTP transport. A production relay consumes the same rows.
    pub async fn outbox_mail_latest(
        &self,
        tenant: &TenantRow,
        to: &str,
        purpose: Option<&str>,
    ) -> Result<Option<Value>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let row: Option<(Value,)> = sqlx::query_as(
            "SELECT payload FROM tenant.outbox
             WHERE topic = 'mail.verification'
               AND lower(payload->>'to') = lower($1)
               AND ($2::text IS NULL OR payload->>'purpose' = $2)
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(to)
        .bind(purpose)
        .fetch_optional(&pool)
        .await?;
        Ok(row.map(|(payload,)| payload))
    }

    /// Insert an outbox row.
    pub async fn outbox_append(
        &self,
        conn: &mut PgConnection,
        topic: &str,
        payload: &Value,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO outbox (id, topic, payload) VALUES ($1,$2,$3)")
            .bind(Uuid::now_v7())
            .bind(topic)
            .bind(payload)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Claim up to `limit` unpublished mail rows for delivery, counting this attempt.
    ///
    /// `SKIP LOCKED` keeps two server processes from sending the same row at once; a row that
    /// reaches `max_attempts` is excluded from later claims, which is how a permanently failing
    /// endpoint stops costing requests while the row stays visible to `/internal/mail`.
    pub async fn outbox_claim_mail(
        &self,
        tenant: &TenantRow,
        limit: i64,
        max_attempts: i32,
    ) -> Result<Vec<OutboxMailRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, OutboxMailRow>(
            "WITH claimed AS (
               SELECT id FROM tenant.outbox
               WHERE topic = 'mail.verification'
                 AND published_at IS NULL
                 AND attempts < $2
               ORDER BY created_at
               LIMIT $1
               FOR UPDATE SKIP LOCKED
             )
             UPDATE tenant.outbox AS o
             SET attempts = o.attempts + 1
             FROM claimed
             WHERE o.id = claimed.id
             RETURNING o.id, o.payload, o.attempts",
        )
        .bind(limit)
        .bind(max_attempts)
        .fetch_all(&pool)
        .await?)
    }

    /// Mark a claimed row published once the provider answered 2xx.
    pub async fn outbox_mark_published(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "UPDATE tenant.outbox SET published_at = now()
             WHERE id = $1 AND published_at IS NULL",
        )
        .bind(id)
        .execute(&pool)
        .await?;
        Ok(())
    }
}

fn to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn subject_type_str(value: AuditActorType) -> &'static str {
    match value {
        AuditActorType::Account => "account",
        AuditActorType::Org => "org",
        AuditActorType::Agent => "agent",
        AuditActorType::AgentKey => "agent_key",
        AuditActorType::Grant => "grant",
        AuditActorType::Client => "client",
        AuditActorType::Tool => "tool",
        AuditActorType::Session => "session",
        AuditActorType::Tenant => "tenant",
    }
}

fn subject_type_from_str(value: &str) -> AuditActorType {
    match value {
        "account" => AuditActorType::Account,
        "org" => AuditActorType::Org,
        "agent" => AuditActorType::Agent,
        "agent_key" => AuditActorType::AgentKey,
        "grant" => AuditActorType::Grant,
        "client" => AuditActorType::Client,
        "tool" => AuditActorType::Tool,
        "session" => AuditActorType::Session,
        _ => AuditActorType::Tenant,
    }
}

fn decision_str(value: AuditDecision) -> &'static str {
    value.as_str()
}

fn decision_from_str(value: &str) -> AuditDecision {
    match value {
        "deny" => AuditDecision::Deny,
        "info" => AuditDecision::Info,
        _ => AuditDecision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_ids_only_become_uuids_when_they_carry_a_typed_suffix() {
        let id = AccountId::new();
        assert_eq!(subject_uuid(Some(&id.to_typed_string())), Some(id.uuid()));
        assert_eq!(subject_uuid(Some("list_notes")), None);
        assert_eq!(subject_uuid(None), None);
    }

    #[test]
    fn a_short_byte_array_is_zero_padded_not_panicking() {
        assert_eq!(to_array(&[1, 2]), {
            let mut out = [0u8; 32];
            out[0] = 1;
            out[1] = 2;
            out
        });
    }

    #[test]
    fn decision_strings_round_trip() {
        for decision in [
            AuditDecision::Allow,
            AuditDecision::Deny,
            AuditDecision::Info,
        ] {
            assert_eq!(decision_from_str(decision_str(decision)), decision);
        }
    }

    #[test]
    fn subject_types_round_trip() {
        for kind in [
            AuditActorType::Account,
            AuditActorType::Org,
            AuditActorType::Agent,
            AuditActorType::AgentKey,
            AuditActorType::Grant,
            AuditActorType::Client,
            AuditActorType::Tool,
            AuditActorType::Session,
            AuditActorType::Tenant,
        ] {
            assert_eq!(subject_type_from_str(subject_type_str(kind)), kind);
        }
    }
}
