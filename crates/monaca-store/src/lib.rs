//! Persistence: migrations, provisioning, the org transaction boundary and the outbox.
//!
//! The two rules this crate exists to enforce:
//!
//! * **`tenant` is always written fully qualified; `org_<short>` is never written qualified.**
//!   [`OrgCtx`](monaca_types::OrgCtx) carries the schema and role names, and every org query runs
//!   inside [`Store::begin_org`] / [`Store::with_org_tx`], which sets `search_path` and
//!   `SET LOCAL ROLE` for the transaction. The role grants are the real boundary; `search_path` is
//!   defence in depth, so a wrong `search_path` still cannot read another org (§5.1).
//! * **`CREATE DATABASE` cannot run in a transaction**, so tenant provisioning is a resumable
//!   state machine whose state is the `tenants.state` column, and every step is idempotent (§5.4).
//! * **`monaca_app` is created `NOINHERIT`.** A plain `GRANT org_role TO monaca_app` defaults to
//!   `INHERIT TRUE`, which hands the login role the union of every org's privileges the moment the
//!   grant runs. The grants are the boundary only because the role never inherits.
//!
//! Identifiers that reach SQL as identifiers (database, schema, role) are never taken from user
//! input: the database name is `mt_<short>`, the schema `org_<oshort>` and the role
//! `t<tshort>_o<oshort>`, each validated against the contract's character class before use.

mod migrate;
mod provision;
mod repo;

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use monaca_types::{OrgCtx, OrgId, TenantId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;

pub use migrate::{MigrationReport, apply_control, apply_tenant};
pub use provision::{OrgRow, TenantRow};
pub use repo::{
    AccountRow, AgentKeyRow, AgentRow, AuditRow, AuthCodeRow, ClientRow, GrantRow, ParRow,
    RefreshRow, SessionRow, SigningKeyRow,
};

/// A storage failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The tenant is not registered in the control plane.
    #[error("unknown tenant `{0}`")]
    UnknownTenant(String),
    /// The organization is not registered in its tenant.
    #[error("unknown organization `{0}`")]
    UnknownOrg(String),
    /// A row the caller named does not exist.
    #[error("{entity} `{id}` was not found")]
    NotFound {
        /// The entity kind, e.g. `agent`.
        entity: &'static str,
        /// The typed id the caller asked for.
        id: String,
    },
    /// A migration's checksum does not match what was recorded, so the file changed after it ran.
    #[error("migration {version} checksum mismatch: recorded {recorded}, computed {computed}")]
    MigrationChecksum {
        /// The migration version.
        version: i64,
        /// The checksum in `_migrations`.
        recorded: String,
        /// The checksum of the file on disk.
        computed: String,
    },
    /// Provisioning stopped part-way; the saga row still says `provisioning`.
    #[error("tenant provisioning is incomplete at step {0}")]
    ProvisioningIncomplete(u8),
    /// A value that must be a SQL identifier is not one.
    #[error("refusing to use `{0}` as a SQL identifier")]
    BadIdentifier(String),
    /// The database driver reported an error.
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        StoreError::Database(err.to_string())
    }
}

/// The transaction boundary every org query runs inside — §5.1.
pub trait OrgTransaction {
    /// The error a transaction can fail with.
    type Error;

    /// Run `work` inside this org's transaction.
    ///
    /// The boxed future is what a closure generic over the connection's lifetime needs on stable
    /// Rust; handlers usually prefer [`Store::begin_org`], which returns the transaction and lets
    /// them write straight-line `await`s.
    fn with_org_tx<T, F>(
        &self,
        ctx: &OrgCtx,
        work: F,
    ) -> impl std::future::Future<Output = Result<T, Self::Error>>
    where
        F: for<'c> FnOnce(
            &'c mut sqlx::PgConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, Self::Error>> + Send + 'c>,
        >;
}

/// The M0 outbox topic names. A module writes to `outbox`; the relay that publishes it is M2.
pub mod topics {
    /// An audit event that must reach the chain.
    pub const AUDIT: &str = "audit";
    /// A tenant was provisioned or changed state.
    pub const TENANT: &str = "tenant";
    /// An agent or grant changed.
    pub const AGENT: &str = "agent";
}

/// How the store reaches PostgreSQL — §2.2.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Control-plane database, `MONACA_CONTROL_DATABASE_URL`.
    pub control_url: String,
    /// `CREATEDB`/`CREATEROLE` connection, `MONACA_ADMIN_DATABASE_URL`.
    pub admin_url: String,
    /// Connections per tenant pool.
    pub tenant_pool_size: u32,
    /// LRU cap on cached tenant pools (`MONACA_TENANT_POOL_CACHE`).
    pub tenant_pool_cache: usize,
    /// Whether org transactions `SET LOCAL ROLE` (`MONACA_ORG_ROLE_ENFORCEMENT`).
    pub org_role_enforcement: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            control_url: String::from("postgres://monaca:monaca@127.0.0.1:54329/monaca_control"),
            admin_url: String::from("postgres://monaca:monaca@127.0.0.1:54329/postgres"),
            tenant_pool_size: 5,
            tenant_pool_cache: 64,
            org_role_enforcement: true,
        }
    }
}

impl StoreConfig {
    /// Read the configuration from the environment, falling back to the dev defaults.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            control_url: env_string("MONACA_CONTROL_DATABASE_URL").unwrap_or(default.control_url),
            admin_url: env_string("MONACA_ADMIN_DATABASE_URL").unwrap_or(default.admin_url),
            tenant_pool_size: env_u32("MONACA_TENANT_POOL_SIZE")
                .unwrap_or(default.tenant_pool_size)
                .max(1),
            tenant_pool_cache: env_u32("MONACA_TENANT_POOL_CACHE")
                .unwrap_or(default.tenant_pool_cache as u32)
                .max(1) as usize,
            org_role_enforcement: env_bool("MONACA_ORG_ROLE_ENFORCEMENT", true),
        }
    }
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_u32(name: &str) -> Option<u32> {
    env_string(name)?.parse().ok()
}

fn env_bool(name: &str, default: bool) -> bool {
    match env_string(name) {
        Some(value) => !matches!(value.as_str(), "0" | "false" | "no" | "off"),
        None => default,
    }
}

/// The database handle: one control-plane pool, one provisioning pool, one pool per tenant.
pub struct Store {
    control: PgPool,
    admin: PgPool,
    config: StoreConfig,
    tenants: Mutex<HashMap<String, PgPool>>,
}

impl Store {
    /// Connect the control and provisioning pools and check they are usable.
    pub async fn connect(config: StoreConfig) -> Result<Self, StoreError> {
        let pool_options = |max: u32| {
            PgPoolOptions::new()
                .max_connections(max)
                .acquire_timeout(Duration::from_secs(10))
                .idle_timeout(Duration::from_secs(300))
        };

        let control = pool_options(config.tenant_pool_size.max(2))
            .connect(&config.control_url)
            .await?;
        let admin = pool_options(2).connect(&config.admin_url).await?;

        Ok(Self {
            control,
            admin,
            config,
            tenants: Mutex::new(HashMap::new()),
        })
    }

    /// The control-plane pool.
    pub fn control(&self) -> &PgPool {
        &self.control
    }

    /// The configuration this store was built with.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// The pool for one tenant database, created on first use and cached.
    pub async fn tenant_pool(&self, db_name: &str) -> Result<PgPool, StoreError> {
        validate_database_name(db_name)?;

        let mut pools = self.tenants.lock().await;
        if let Some(pool) = pools.get(db_name) {
            return Ok(pool.clone());
        }

        let options = PgConnectOptions::from_str(&self.config.control_url)
            .map_err(|err| StoreError::Database(format!("control URL: {err}")))?
            .database(db_name);
        let pool = PgPoolOptions::new()
            .max_connections(self.config.tenant_pool_size)
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .connect_with(options)
            .await?;

        // Evict the oldest entry when the cache is full. Pools are cheap to rebuild and the cap is
        // what keeps an unbounded tenant count from exhausting PostgreSQL's connection slots.
        while pools.len() >= self.config.tenant_pool_cache {
            if let Some(oldest) = pools.keys().next().cloned() {
                pools.remove(&oldest);
            } else {
                break;
            }
        }
        pools.insert(db_name.to_owned(), pool.clone());
        Ok(pool)
    }

    /// Open an org transaction: `BEGIN`, `search_path`, and (when enabled) `SET LOCAL ROLE`.
    ///
    /// The returned transaction is the only handle through which org queries run, so the two
    /// `SET LOCAL`s cannot be forgotten by a caller that has one.
    pub async fn begin_org(
        &self,
        ctx: &OrgCtx,
    ) -> Result<Transaction<'static, Postgres>, StoreError> {
        validate_schema_name(&ctx.schema_name)?;
        validate_role_name(&ctx.role_name)?;

        let pool = self.tenant_pool(&ctx.tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        sqlx::query(q(format!(
            "SET LOCAL search_path = {}, tenant",
            quote_ident(&ctx.schema_name)
        )))
        .execute(&mut *tx)
        .await?;

        if self.config.org_role_enforcement {
            sqlx::query(q(format!("SET LOCAL ROLE {}", quote_ident(&ctx.role_name))))
                .execute(&mut *tx)
                .await?;
        }

        Ok(tx)
    }

    /// Open a tenant-level transaction (`search_path = tenant`), for writes to the tenant chain
    /// and the tables that are deliberately not org-scoped.
    pub async fn begin_tenant(
        &self,
        tenant: &TenantRow,
    ) -> Result<Transaction<'static, Postgres>, StoreError> {
        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL search_path = tenant")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// The tenant row for an id.
    pub async fn tenant_by_id(&self, id: uuid::Uuid) -> Result<TenantRow, StoreError> {
        sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, short, db_name, issuer, state FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.control)
        .await?
        .ok_or_else(|| StoreError::UnknownTenant(id.to_string()))
    }

    /// Run `work` inside an org transaction, committing on success.
    pub async fn with_org_tx<T, F>(&self, ctx: &OrgCtx, work: F) -> Result<T, StoreError>
    where
        F: for<'c> FnOnce(
            &'c mut sqlx::PgConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, StoreError>> + Send + 'c>,
        >,
    {
        let mut tx = self.begin_org(ctx).await?;
        let result = work(&mut tx).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Register a tenant row without provisioning its database (used by tests and by the saga's
    /// first step). `cluster_id` names the cluster row the tenant lives on.
    pub async fn insert_tenant_row(
        &self,
        tenant_id: TenantId,
        slug: &str,
        short: &str,
        db_name: &str,
        issuer: &str,
        cluster_id: uuid::Uuid,
        state: &str,
    ) -> Result<TenantRow, StoreError> {
        sqlx::query(
            "INSERT INTO tenants (id, slug, short, cluster_id, db_name, issuer, state)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (slug) DO NOTHING",
        )
        .bind(tenant_id.uuid())
        .bind(slug)
        .bind(short)
        .bind(cluster_id)
        .bind(db_name)
        .bind(issuer)
        .bind(state)
        .execute(&self.control)
        .await?;

        self.tenant_by_slug(slug).await
    }

    /// Ensure a cluster row exists, returning its id.
    pub async fn ensure_cluster(
        &self,
        name: &str,
        admin_dsn_enc: &[u8],
        app_dsn_enc: &[u8],
    ) -> Result<uuid::Uuid, StoreError> {
        if let Some((id,)) =
            sqlx::query_as::<_, (uuid::Uuid,)>("SELECT id FROM clusters WHERE name = $1")
                .bind(name)
                .fetch_optional(&self.control)
                .await?
        {
            return Ok(id);
        }

        let id = uuid::Uuid::now_v7();
        sqlx::query(
            "INSERT INTO clusters (id, name, admin_dsn_enc, app_dsn_enc)
             VALUES ($1,$2,$3,$4) ON CONFLICT (name) DO NOTHING",
        )
        .bind(id)
        .bind(name)
        .bind(admin_dsn_enc)
        .bind(app_dsn_enc)
        .execute(&self.control)
        .await?;
        let (id,) = sqlx::query_as::<_, (uuid::Uuid,)>("SELECT id FROM clusters WHERE name = $1")
            .bind(name)
            .fetch_one(&self.control)
            .await?;
        Ok(id)
    }

    /// The tenant row for a slug.
    pub async fn tenant_by_slug(&self, slug: &str) -> Result<TenantRow, StoreError> {
        sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, short, db_name, issuer, state FROM tenants WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.control)
        .await?
        .ok_or_else(|| StoreError::UnknownTenant(slug.to_owned()))
    }

    /// Every registered tenant, ordered by slug.
    pub async fn tenants(&self) -> Result<Vec<TenantRow>, StoreError> {
        Ok(sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, short, db_name, issuer, state FROM tenants ORDER BY slug",
        )
        .fetch_all(&self.control)
        .await?)
    }

    /// Mark a fully provisioned tenant `active` — §5.4 step 5.
    pub async fn activate_tenant(&self, slug: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE tenants SET state = 'active', updated_at = now()
             WHERE slug = $1 AND state = 'provisioning'",
        )
        .bind(slug)
        .execute(&self.control)
        .await?;
        Ok(())
    }

    /// The provisioning pool, for `CREATE DATABASE`.
    pub(crate) fn admin(&self) -> &PgPool {
        &self.admin
    }
}

impl OrgTransaction for Store {
    type Error = StoreError;

    async fn with_org_tx<T, F>(&self, ctx: &OrgCtx, work: F) -> Result<T, Self::Error>
    where
        F: for<'c> FnOnce(
            &'c mut sqlx::PgConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, Self::Error>> + Send + 'c>,
        >,
    {
        Store::with_org_tx(self, ctx, work).await
    }
}

/// A tenant context from a row.
impl TenantRow {
    /// The request context for this tenant.
    pub fn ctx(&self) -> monaca_types::TenantCtx {
        monaca_types::TenantCtx::new(TenantId::from_uuid(self.id), &self.slug, &self.db_name)
    }
}

/// An org context from a row.
impl OrgRow {
    /// The request context for this organization.
    pub fn ctx(&self, tenant: &TenantRow) -> OrgCtx {
        OrgCtx::new(
            tenant.ctx(),
            OrgId::from_uuid(self.id),
            &self.slug,
            &self.schema_name,
            &self.role_name,
        )
    }
}

pub(crate) fn validate_database_name(name: &str) -> Result<(), StoreError> {
    let ok = name.len() >= 6
        && name.len() <= 13
        && name.starts_with("mt_")
        && name[3..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(StoreError::BadIdentifier(name.to_owned()))
    }
}

pub(crate) fn validate_schema_name(name: &str) -> Result<(), StoreError> {
    let ok = name.starts_with("org_")
        && name.len() >= 8
        && name.len() <= 14
        && name[4..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(StoreError::BadIdentifier(name.to_owned()))
    }
}

pub(crate) fn validate_role_name(name: &str) -> Result<(), StoreError> {
    let ok = name.len() >= 6
        && name.len() <= 26
        && name.starts_with('t')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if ok {
        Ok(())
    } else {
        Err(StoreError::BadIdentifier(name.to_owned()))
    }
}

/// Quote a validated identifier. The validators above restrict the character class to
/// `[a-z0-9_]`, so this is belt and braces rather than the only defence.
pub(crate) fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Mark a dynamically built statement as safe to execute.
///
/// Every call site has already interpolated only an identifier that passed
/// [`validate_schema_name`] / [`validate_database_name`] / [`validate_role_name`]; values are
/// always `bind` parameters. sqlx 0.9 requires the assertion to be explicit, which is exactly the
/// speed bump that keeps a future `format!` from quietly interpolating user input.
pub(crate) fn q(text: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_are_stable_strings() {
        assert_eq!(topics::AUDIT, "audit");
        assert_eq!(topics::TENANT, "tenant");
        assert_eq!(topics::AGENT, "agent");
    }

    #[test]
    fn errors_render_a_useful_message() {
        assert!(
            StoreError::UnknownTenant("demo".into())
                .to_string()
                .contains("demo")
        );
        let mismatch = StoreError::MigrationChecksum {
            version: 3,
            recorded: "aaa".into(),
            computed: "bbb".into(),
        };
        assert!(mismatch.to_string().contains("migration 3"));
    }

    #[test]
    fn identifiers_are_checked_before_they_reach_sql() {
        assert!(validate_database_name("mt_abcd").is_ok());
        assert!(validate_database_name("mt_ABCD").is_err());
        assert!(validate_database_name("mt_ab;drop").is_err());
        assert!(validate_schema_name("org_abcd").is_ok());
        assert!(validate_schema_name("org_ab-cd").is_err());
        assert!(validate_role_name("tabcd_oefgh").is_ok());
        assert!(validate_role_name("tabcd\"oefgh").is_err());
    }
}
