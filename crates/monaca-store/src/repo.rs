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
use monaca_types::{AccountId, AgentId, GrantId, OrgId, TypedId};
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

/// A social (OAuth2) connector in `tenant.social_connectors` (§6.1).
#[derive(Debug, Clone, FromRow)]
pub struct SocialConnectorRow {
    /// Row id.
    pub id: Uuid,
    /// The slug the protocol and the page use, unique within the tenant.
    pub connector_id: String,
    /// Human-readable name shown on the sign-in page.
    pub display_name: String,
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
    /// Scopes this client may ask for.
    pub scopes: Vec<String>,
    /// A third-party application must show a consent screen.
    pub is_third_party: bool,
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
fn unique_conflict(err: sqlx::Error, entity: &'static str) -> StoreError {
    if let sqlx::Error::Database(ref db) = err
        && db.code().as_deref() == Some("23505")
    {
        return StoreError::AlreadyExists { entity };
    }
    StoreError::Database(err.to_string())
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
    ) -> Result<AccountRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        let row = sqlx::query_as::<_, AccountRow>(
            "INSERT INTO tenant.accounts (id, primary_email, display_name, state, is_tenant_admin)
             VALUES ($1,$2,$3,'active',$4)
             RETURNING id, primary_email, display_name, state, is_tenant_admin, created_at",
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
                "INSERT INTO tenant.account_identifiers (id, account_id, kind, value)
                 VALUES ($1,$2,'username',$3)",
            )
            .bind(Uuid::now_v7())
            .bind(account_id.uuid())
            .bind(username)
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
            "SELECT id, primary_email, display_name, state, is_tenant_admin, created_at
             FROM tenant.accounts WHERE id = $1",
        )
        .bind(account_id.uuid())
        .fetch_optional(&pool)
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
            "SELECT id, primary_email, display_name, state, is_tenant_admin, created_at
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
    /// The identifier is either an email address or a username, both matched case-insensitively.
    /// An email always wins: a username may not contain `@` (§6.1), so the two namespaces can only
    /// overlap through data written outside this API, and the email is the safer interpretation.
    pub async fn account_by_identifier(
        &self,
        tenant: &TenantRow,
        identifier: &str,
    ) -> Result<Option<(AccountRow, Option<String>)>, StoreError> {
        if let Some(account) = self.account_by_email(tenant, identifier).await? {
            return Ok(Some(account));
        }
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let account = sqlx::query_as::<_, AccountRow>(
            "SELECT a.id, a.primary_email, a.display_name, a.state, a.is_tenant_admin, a.created_at
             FROM tenant.accounts a
             JOIN tenant.account_identifiers i ON i.account_id = a.id
             WHERE i.kind = 'username' AND lower(i.value) = lower($1)
             LIMIT 1",
        )
        .bind(identifier)
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

    /// The account's username, if one was set.
    pub async fn account_username(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
    ) -> Result<Option<String>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, (String,)>(
            "SELECT value FROM tenant.account_identifiers
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
    /// duplicate row.
    pub async fn set_username(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        username: &str,
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
                sqlx::query("UPDATE tenant.account_identifiers SET value = $2 WHERE id = $1")
                    .bind(id)
                    .bind(username)
                    .execute(&mut *tx)
                    .await
                    .map_err(|err| unique_conflict(err, "username"))?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO tenant.account_identifiers (id, account_id, kind, value)
                     VALUES ($1,$2,'username',$3)",
                )
                .bind(Uuid::now_v7())
                .bind(account_id.uuid())
                .bind(username)
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
             RETURNING id, primary_email, display_name, state, is_tenant_admin, created_at",
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
            "SELECT id, connector_id, display_name, authorize_url, token_url, userinfo_url,
                    client_id, client_secret_enc, scopes, created_at
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
            "SELECT id, connector_id, display_name, authorize_url, token_url, userinfo_url,
                    client_id, client_secret_enc, scopes, created_at
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
        display_name: &str,
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
                (id, connector_id, display_name, authorize_url, token_url, userinfo_url,
                 client_id, client_secret_enc, scopes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING id, connector_id, display_name, authorize_url, token_url, userinfo_url,
                       client_id, client_secret_enc, scopes, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(connector_id)
        .bind(display_name)
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
            "SELECT a.id, a.primary_email, a.display_name, a.state, a.is_tenant_admin, a.created_at
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
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.account_social_identities (id, account_id, connector, subject)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(Uuid::now_v7())
        .bind(account_id.uuid())
        .bind(connector)
        .bind(subject)
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
            "SELECT i.connector, c.display_name, i.subject
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
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant.social_states
                (id, connector, purpose, interaction_id, account_id, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(connector)
        .bind(purpose)
        .bind(interaction_id)
        .bind(account_id)
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
             RETURNING connector, purpose, interaction_id, account_id",
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
             RETURNING id, primary_email, display_name, state, is_tenant_admin, created_at",
        )
        .bind(account_id.uuid())
        .bind(display_name)
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

    /// The organization with `slug` in `tenant`.
    pub async fn org_by_slug(&self, tenant: &TenantRow, slug: &str) -> Result<OrgRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, is_default
             FROM tenant.organizations WHERE slug = $1 AND state = 'active'",
        )
        .bind(slug)
        .fetch_optional(&pool)
        .await?
        .ok_or_else(|| StoreError::UnknownOrg(slug.to_owned()))
    }

    /// The organization with `id`.
    pub async fn org_by_id(&self, tenant: &TenantRow, id: OrgId) -> Result<OrgRow, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query_as::<_, OrgRow>(
            "SELECT id, slug, schema_name, role_name, is_default
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
            "SELECT id, slug, schema_name, role_name, is_default
             FROM tenant.organizations WHERE state = 'active' ORDER BY created_at",
        )
        .fetch_all(&pool)
        .await?)
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
            "SELECT o.id, o.slug, o.schema_name, o.role_name, o.is_default
             FROM tenant.agent_directory d
             JOIN tenant.organizations o ON o.id = d.org_id
             WHERE d.agent_id = $1",
        )
        .bind(agent_id.uuid())
        .fetch_optional(&pool)
        .await?)
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
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes,
                    is_third_party
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
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes,
                    is_third_party
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
