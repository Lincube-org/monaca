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

impl Store {
    // ---------------------------------------------------------------- accounts

    /// Create an account with its email identifier and an optional password, atomically.
    pub async fn create_account(
        &self,
        tenant: &TenantRow,
        account_id: AccountId,
        email: &str,
        display_name: &str,
        password_phc: Option<&str>,
        is_tenant_admin: bool,
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
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes
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
            "SELECT id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes
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

    /// Create a client and its redirect URIs, atomically.
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
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO tenant.clients
               (id, client_id, name, kind, secret_hash, token_auth_method, jwks, scopes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (client_id) DO UPDATE SET name = EXCLUDED.name
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
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "INSERT INTO tenant.auth_codes
               (id, code_hash, client_id, account_id, org_id, redirect_uri, scope,
                code_challenge, nonce, resource, session_id, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
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
                       code_challenge, nonce, resource, session_id, expires_at, consumed_at",
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
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant.refresh_tokens
               (id, token_hash, client_id, account_id, org_id, scope, resource, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(token_hash)
        .bind(client_row_id)
        .bind(account_id)
        .bind(org_id)
        .bind(scope)
        .bind(resource)
        .bind(expires_at)
        .execute(&pool)
        .await?;
        Ok(id)
    }

    /// A live refresh token by hash.
    pub async fn refresh_by_hash(
        &self,
        tenant: &TenantRow,
        token_hash: &str,
    ) -> Result<Option<RefreshRow>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        Ok(sqlx::query_as::<_, RefreshRow>(
            "SELECT id, token_hash, client_id, account_id, org_id, scope, resource,
                    expires_at, revoked_at, rotated_from
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

    /// Revoke every live refresh token descended from `id` (reuse detection, §11 M1).
    pub async fn revoke_refresh_family(
        &self,
        tenant: &TenantRow,
        id: Uuid,
    ) -> Result<(), StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        sqlx::query(
            "WITH RECURSIVE family AS (
                SELECT id FROM tenant.refresh_tokens WHERE id = $1
                UNION ALL
                SELECT t.id FROM tenant.refresh_tokens t JOIN family f ON t.rotated_from = f.id
             )
             UPDATE tenant.refresh_tokens SET revoked_at = now()
             WHERE id IN (SELECT id FROM family) AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&pool)
        .await?;
        Ok(())
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
