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

mod domains;
mod migrate;
mod provision;
mod repo;
mod runtime_state;
mod templates;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use monaca_types::{OrgCtx, OrgId, TenantId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::{Mutex, OnceCell};

pub use domains::{DomainRouteRow, TenantDomainRow};
pub use migrate::{MigrationReport, apply_control, apply_tenant};
pub use provision::{OrgRow, TenantRow};
pub use repo::{
    AccountLivenessRow, AccountRow, AgentKeyRow, AgentRow, ApiResourceRow, AuditFilter, AuditRow,
    AuthCodeRow, AuthorizedAppRow, BrandingRow, ClientRow, ConsentRow, DeliveryConnectorRow,
    GrantRow, LoginFailureRow, MessageTemplateRow, OrgInvitationRow, OrgRoleRow, OutboxMailRow,
    ParRow, PasskeyRow, RateLimitRow, RefreshRow, RoleRow, SamlConnectorRow, SamlStateRow,
    SessionRow, SignInExperienceRow, SignInGuardrailsPatch, SignInPhraseRow, SigningKeyRow,
    SocialConnectorRow, SocialIdentityRow, SocialStateRow, SsoConnectorRow, SsoStateRow,
    TrustedDeviceRow, UsageSummaryRow, VerificationRow, WebhookDeliveryRow, WebhookRow,
};
pub use runtime_state::InteractionRow;

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
    /// A conditional state transition matched no row, because another writer changed the state
    /// first or the row is not in a state that allows this transition.
    #[error("{entity} `{id}` is not in a state that allows this transition")]
    Conflict {
        /// The entity kind, e.g. `custom domain`.
        entity: &'static str,
        /// The identity the caller named.
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
    /// A unique value is already in use (e.g. a username taken by another account).
    #[error("{entity} is already taken")]
    AlreadyExists {
        /// The entity kind, e.g. `username`.
        entity: &'static str,
    },
    /// The tenant's account quota is exhausted; the creation was refused.
    #[error("the tenant's account quota is exhausted")]
    QuotaExceeded,
    /// A value that must be a SQL identifier is not one.
    #[error("refusing to use `{0}` as a SQL identifier")]
    BadIdentifier(String),
    /// Tenant pools have neither an app DSN nor the explicit superuser escape hatch.
    #[error(
        "MONACA_APP_DATABASE_URL is not set; tenant pools refuse to fall back to the control DSN \
         unless MONACA_ALLOW_SUPERUSER_TENANT_POOLS=1 is set explicitly"
    )]
    TenantPoolsNotConfigured,
    /// The app login named by `MONACA_APP_DATABASE_URL` cannot be used for tenant pools.
    #[error("MONACA_APP_DATABASE_URL: {0}")]
    TenantPoolRole(String),
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
    /// A dev mail message, read back by `GET /internal/mail`; a real relay consumes it later.
    pub const MAIL: &str = "mail.verification";
    /// An SMS message the mailer claims for the tenant's SMS connector.
    pub const SMS: &str = "sms.verification";
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
    /// Connections per pool in the mailer's cache (`MONACA_MAILER_POOL_SIZE`).
    pub mailer_pool_size: u32,
    /// LRU cap on the mailer's own tenant pools (`MONACA_MAILER_POOL_CACHE`).
    pub mailer_pool_cache: usize,
    /// Whether org transactions `SET LOCAL ROLE` (`MONACA_ORG_ROLE_ENFORCEMENT`).
    pub org_role_enforcement: bool,
    /// Least-privilege base DSN for tenant pools (`MONACA_APP_DATABASE_URL`). The per-tenant
    /// database name is substituted into this URL, so request-path connections use the
    /// `monaca_app` login rather than the control superuser. `serve` refuses to start without it
    /// unless [`Self::allow_control_db_user`] is set.
    pub app_url: Option<String>,
    /// The explicit escape hatch (`MONACA_ALLOW_SUPERUSER_TENANT_POOLS=1`): use `control_url` for
    /// tenant pools when no app DSN is configured. Administrative subcommands set this internally
    /// because migrations, bootstrap and rewrap need the owner connection.
    pub allow_control_db_user: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            control_url: String::from("postgres://monaca:monaca@127.0.0.1:54329/monaca_control"),
            admin_url: String::from("postgres://monaca:monaca@127.0.0.1:54329/postgres"),
            tenant_pool_size: 5,
            tenant_pool_cache: 64,
            mailer_pool_size: 1,
            // The poller's cache must exceed its working set by enough that a visit's three
            // lookups do not race an eviction; 128 was the smallest value that kept the 400-tenant
            // sweep to one pool open per tenant (docs/roadmap.md §Batch H).
            mailer_pool_cache: 128,
            org_role_enforcement: true,
            app_url: None,
            allow_control_db_user: false,
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
            mailer_pool_size: env_u32("MONACA_MAILER_POOL_SIZE")
                .unwrap_or(default.mailer_pool_size)
                .max(1),
            mailer_pool_cache: env_u32("MONACA_MAILER_POOL_CACHE")
                .unwrap_or(default.mailer_pool_cache as u32)
                .max(1) as usize,
            org_role_enforcement: env_bool("MONACA_ORG_ROLE_ENFORCEMENT", true),
            app_url: env_string("MONACA_APP_DATABASE_URL"),
            allow_control_db_user: env_bool("MONACA_ALLOW_SUPERUSER_TENANT_POOLS", false),
        }
    }

    /// Administrative mode: tenant pools use the control DSN regardless of `app_url`.
    ///
    /// `migrate`, `bootstrap`, `audit verify` and `rewap` must be able to read and write schemas
    /// the app login deliberately cannot. This is an internal switch, not an environment variable;
    /// `serve` never calls it.
    pub fn with_control_tenant_pools(mut self) -> Self {
        self.app_url = None;
        self.allow_control_db_user = true;
        self
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

/// Tenant-pool cache counters. Read by the server's `/metrics` handler (§6.4); never a source of
/// truth, so they are relaxed atomics that a long-lived process can update without contention.
#[derive(Debug, Default)]
pub struct PoolStats {
    hits: AtomicU64,
    misses: AtomicU64,
    lookup_nanos: AtomicU64,
    connect_nanos: AtomicU64,
}

/// A point-in-time copy of [`PoolStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStatsSnapshot {
    /// Lookups answered by an existing pool or an in-flight creation.
    pub hits: u64,
    /// Lookups that started a new pool; a concurrent waiter for the same key counts as a hit.
    pub misses: u64,
    /// Time spent in the cache lookup, including waiting for the map lock.
    pub lookup_nanos: u64,
    /// Time spent creating a pool and validating its first connection.
    pub connect_nanos: u64,
}

impl PoolStats {
    fn snapshot(&self) -> PoolStatsSnapshot {
        PoolStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            lookup_nanos: self.lookup_nanos.load(Ordering::Relaxed),
            connect_nanos: self.connect_nanos.load(Ordering::Relaxed),
        }
    }
}

/// One cached tenant pool plus the tick at which it was last used, for LRU eviction.
///
/// The pool is created through a per-entry [`OnceCell`], so concurrent misses for the same tenant
/// share one `connect` instead of serialising behind the map lock or opening a pool each. The
/// cell also keeps a failed attempt visible to the callers that were already waiting: they see the
/// same error, and only a later request starts a new attempt.
struct CachedPool {
    init: Arc<OnceCell<Result<PgPool, StoreError>>>,
    last_used: AtomicU64,
}

/// The database handle: one control-plane pool, one provisioning pool, one pool per tenant.
pub struct Store {
    control: PgPool,
    admin: PgPool,
    config: StoreConfig,
    /// Connections this cache may open per tenant pool. The request path and the mailer keep
    /// separate values so a sweep cannot resize or evict the working set of the other.
    tenant_pool_size: u32,
    /// LRU cap for this store's tenant-pool cache.
    tenant_pool_cache: usize,
    tenants: Mutex<HashMap<String, CachedPool>>,
    pool_tick: AtomicU64,
    stats: PoolStats,
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
            tenant_pool_size: config.tenant_pool_size,
            tenant_pool_cache: config.tenant_pool_cache,
            config,
            tenants: Mutex::new(HashMap::new()),
            pool_tick: AtomicU64::new(0),
            stats: PoolStats::default(),
        })
    }

    /// A second tenant-pool cache over the same control and provisioning connections.
    ///
    /// The mailer uses this so its sweep of every connector tenant cannot evict the pools the
    /// request path depends on. `pool_size` is usually 1: a tenant visit runs its queries one at a
    /// time, and a deeper pool would reserve connections it never uses.
    pub fn separate_tenant_cache(&self, pool_size: u32, cache: usize) -> Store {
        Store {
            control: self.control.clone(),
            admin: self.admin.clone(),
            config: self.config.clone(),
            tenant_pool_size: pool_size.max(1),
            tenant_pool_cache: cache.max(1),
            tenants: Mutex::new(HashMap::new()),
            pool_tick: AtomicU64::new(0),
            stats: PoolStats::default(),
        }
    }

    /// The control-plane pool.
    pub fn control(&self) -> &PgPool {
        &self.control
    }

    /// Tenant-pool cache counters for `/metrics` (§6.4).
    pub fn pool_stats(&self) -> PoolStatsSnapshot {
        self.stats.snapshot()
    }

    /// The configuration this store was built with.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// The pool for one tenant database, created on first use and cached.
    ///
    /// Only the map lookup and the insertion run under the map lock. A miss installs an empty
    /// [`OnceCell`] and connects outside the lock; another request for the same tenant that arrives
    /// while the connection is being established joins the same cell instead of opening a second
    /// pool. If that attempt fails, every waiter receives the same error and the entry is removed,
    /// so a retry is a new attempt rather than a burst of concurrent ones.
    pub async fn tenant_pool(&self, db_name: &str) -> Result<PgPool, StoreError> {
        validate_database_name(db_name)?;
        let base = match self.config.app_url.as_deref() {
            Some(app) => app.to_owned(),
            None if self.config.allow_control_db_user => self.config.control_url.clone(),
            None => return Err(StoreError::TenantPoolsNotConfigured),
        };
        self.cached_pool(db_name, || async move {
            let options = PgConnectOptions::from_str(&base)
                .map_err(|err| StoreError::Database(format!("tenant pool URL: {err}")))?
                .database(db_name);
            let connect_started = Instant::now();
            let connected = PgPoolOptions::new()
                .max_connections(self.tenant_pool_size)
                .acquire_timeout(Duration::from_secs(10))
                .idle_timeout(Duration::from_secs(300))
                .connect_with(options)
                .await;
            self.stats.connect_nanos.fetch_add(
                connect_started.elapsed().as_nanos() as u64,
                Ordering::Relaxed,
            );
            connected.map_err(StoreError::from)
        })
        .await
    }

    /// A one-shot pool for org provisioning inside one tenant database.
    ///
    /// `provision_org` runs DDL (`CREATE SCHEMA`, `CREATE ROLE`, the org migration set) that the
    /// request-path login deliberately cannot execute. The provisioning login (`admin_url`) created
    /// the tenant database and owns it. The pool is not cached: org creation is rare, and a
    /// privileged pool kept next to the least-privilege request pools would widen exactly the
    /// surface the app login is there to narrow.
    pub async fn provisioning_pool(&self, db_name: &str) -> Result<PgPool, StoreError> {
        validate_database_name(db_name)?;
        let options = PgConnectOptions::from_str(&self.config.admin_url)
            .map_err(|err| StoreError::Database(format!("provisioning URL: {err}")))?
            .database(db_name);
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .connect_with(options)
            .await
            .map_err(StoreError::from)
    }

    /// Prove the configured app login can serve tenant pools, and refuse the two unsafe shapes.
    ///
    /// `serve` calls this before it listens. A missing app DSN is already refused by
    /// [`Self::tenant_pool`]; this adds the checks a bad DSN cannot express: the login must exist,
    /// must not be a superuser, must not inherit privileges, and must be able to read the tenant
    /// schema of at least one active tenant. A deployment that skipped the app-role provisioning
    /// therefore fails at startup rather than serving until the first request.
    pub async fn verify_tenant_pool_role(&self) -> Result<(), StoreError> {
        let Some(app_url) = self.config.app_url.as_deref() else {
            return if self.config.allow_control_db_user {
                Ok(())
            } else {
                Err(StoreError::TenantPoolsNotConfigured)
            };
        };
        let options = PgConnectOptions::from_str(app_url)
            .map_err(|err| StoreError::TenantPoolRole(format!("the DSN is invalid: {err}")))?;
        let user = options.get_username();
        let attrs: Option<(bool, bool)> =
            sqlx::query_as("SELECT rolsuper, rolinherit FROM pg_roles WHERE rolname = $1")
                .bind(user)
                .fetch_optional(&self.admin)
                .await?;
        let (superuser, inherit) = attrs.ok_or_else(|| {
            StoreError::TenantPoolRole(format!(
                "role `{user}` does not exist; run `monaca-server bootstrap` with \
                 MONACA_APP_DB_PASSWORD before starting the server"
            ))
        })?;
        if superuser {
            return Err(StoreError::TenantPoolRole(format!(
                "role `{user}` is a superuser; MONACA_APP_DATABASE_URL must name a least-privilege \
                 login, not the control or admin DSN"
            )));
        }
        if inherit {
            return Err(StoreError::TenantPoolRole(format!(
                "role `{user}` inherits privileges; it must be NOINHERIT so org grants only apply \
                 inside `SET LOCAL ROLE`"
            )));
        }

        let Some(tenant) = self
            .tenants()
            .await?
            .into_iter()
            .find(|tenant| tenant.is_active())
        else {
            return Ok(());
        };
        let pool = self.tenant_pool(&tenant.db_name).await.map_err(|err| {
            StoreError::TenantPoolRole(format!(
                "tenant `{}` cannot be opened by `{user}`: {err}",
                tenant.slug
            ))
        })?;
        if let Err(err) = sqlx::query("SELECT 1 FROM tenant.accounts LIMIT 0")
            .execute(&pool)
            .await
        {
            return Err(StoreError::TenantPoolRole(format!(
                "tenant `{}` has no app-role grants: {err}",
                tenant.slug
            )));
        }
        Ok(())
    }

    /// The cache and single-flight mechanism behind [`Self::tenant_pool`].
    ///
    /// `connect` runs outside the map lock and only for the caller that installed the entry; every
    /// concurrent caller for the same key awaits that one attempt instead of starting its own.
    async fn cached_pool<F, Fut>(&self, db_name: &str, connect: F) -> Result<PgPool, StoreError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<PgPool, StoreError>>,
    {
        let tick = self.pool_tick.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let init = {
            let mut pools = self.tenants.lock().await;
            let lookup = started.elapsed();
            self.stats
                .lookup_nanos
                .fetch_add(lookup.as_nanos() as u64, Ordering::Relaxed);
            if let Some(entry) = pools.get(db_name) {
                entry.last_used.store(tick, Ordering::Relaxed);
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Arc::clone(&entry.init)
            } else {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                let init = Arc::new(OnceCell::new());

                // Evict the least recently used pool when the cache is full. A pool that is still
                // connecting is never chosen: removing it would let the next request start a
                // second pool for the same tenant, which is exactly what the cell prevents. If
                // every entry is connecting, the cap is exceeded briefly.
                if pools.len() >= self.tenant_pool_cache
                    && let Some(oldest) = pools
                        .iter()
                        .filter(|(_, entry)| entry.init.get().is_some())
                        .min_by_key(|(_, entry)| entry.last_used.load(Ordering::Relaxed))
                        .map(|(key, _)| key.clone())
                {
                    pools.remove(&oldest);
                }
                pools.insert(
                    db_name.to_owned(),
                    CachedPool {
                        init: Arc::clone(&init),
                        last_used: AtomicU64::new(tick),
                    },
                );
                init
            }
        };

        let result = init.get_or_init(connect).await;

        match result {
            Ok(pool) => Ok(pool.clone()),
            Err(err) => {
                // Drop only this attempt's entry: a concurrent caller may already have replaced
                // it after another failure, and removing that one would break its single flight.
                let mut pools = self.tenants.lock().await;
                if pools
                    .get(db_name)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.init, &init))
                {
                    pools.remove(db_name);
                }
                Err(err.clone())
            }
        }
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

    /// Active tenants whose database has at least one delivery connector, ordered by slug.
    ///
    /// The index is maintained by connector writes and reconciled by `migrate`; without it the
    /// mailer would open every active tenant database on every poll just to discover that most
    /// have no connector.
    pub async fn tenants_with_delivery_connector(&self) -> Result<Vec<TenantRow>, StoreError> {
        Ok(sqlx::query_as::<_, TenantRow>(
            "SELECT t.id, t.slug, t.short, t.db_name, t.issuer, t.state
             FROM tenants t
             JOIN tenant_delivery_connectors c ON c.tenant_id = t.id
             WHERE t.state = 'active'
             ORDER BY t.slug",
        )
        .fetch_all(&self.control)
        .await?)
    }

    /// Record that a tenant has a connector row. Called before the tenant-database write on the
    /// create path, so a failed index write cannot leave a connector that the mailer never sees.
    pub async fn mark_delivery_connector_present(
        &self,
        tenant: &TenantRow,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO tenant_delivery_connectors (tenant_id) VALUES ($1)
             ON CONFLICT (tenant_id) DO UPDATE SET updated_at = now()",
        )
        .bind(tenant.id)
        .execute(&self.control)
        .await?;
        Ok(())
    }

    /// Remove a tenant from the delivery-connector index.
    pub async fn forget_delivery_connector_index(
        &self,
        tenant: &TenantRow,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM tenant_delivery_connectors WHERE tenant_id = $1")
            .bind(tenant.id)
            .execute(&self.control)
            .await?;
        Ok(())
    }

    /// Make the index row match the tenant database. Called by `migrate`, which is the upgrade
    /// path for connectors that predate the index.
    pub async fn reconcile_delivery_connector_index(
        &self,
        tenant: &TenantRow,
    ) -> Result<(), StoreError> {
        if !self.delivery_connectors(tenant).await?.is_empty() {
            self.mark_delivery_connector_present(tenant).await
        } else {
            self.forget_delivery_connector_index(tenant).await
        }
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

/// A login role name that can be interpolated as an identifier (the app login, not an org role).
pub(crate) fn validate_login_role(name: &str) -> Result<(), StoreError> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
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

    /// A store whose pools are never opened: the cache tests below touch no database.
    fn test_store(tenant_pool_cache: usize) -> Store {
        let pool = || {
            PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://monaca:monaca@127.0.0.1:54329/monaca_control")
                .expect("a valid URL")
        };
        Store {
            control: pool(),
            admin: pool(),
            config: StoreConfig {
                tenant_pool_cache,
                ..StoreConfig::default()
            },
            tenant_pool_size: 5,
            tenant_pool_cache,
            tenants: Mutex::new(HashMap::new()),
            pool_tick: AtomicU64::new(0),
            stats: PoolStats::default(),
        }
    }

    fn lazy_pool(name: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(&format!("postgres://monaca:monaca@127.0.0.1:54329/{name}"))
            .expect("a valid URL")
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_connection_attempt() {
        use std::sync::atomic::AtomicUsize;

        let store = Arc::new(test_store(64));
        let calls = Arc::new(AtomicUsize::new(0));
        let (started, started_rx) = tokio::sync::oneshot::channel();

        let attempt = {
            let store = Arc::clone(&store);
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                store
                    .cached_pool("mt_shared", || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let _ = started.send(());
                        // Long enough that the second caller joins this cell, not a new one.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Ok(lazy_pool("mt_shared"))
                    })
                    .await
            })
        };
        started_rx.await.expect("the first attempt starts");

        // The second caller arrives while the first is still connecting.
        let joined = store
            .cached_pool("mt_shared", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(lazy_pool("mt_shared"))
            })
            .await
            .expect("the shared attempt succeeds");

        let first = attempt.await.expect("the task finishes").expect("succeeds");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one connect for two callers"
        );
        assert_eq!(
            store.pool_stats().misses,
            1,
            "the waiter counts as a hit, not a miss"
        );
        assert_eq!(
            first.connect_options().get_database(),
            joined.connect_options().get_database()
        );
    }

    #[tokio::test]
    async fn waiters_share_the_error_of_a_failed_attempt_and_the_entry_is_dropped() {
        let store = Arc::new(test_store(64));
        let (started, started_rx) = tokio::sync::oneshot::channel();

        let attempt = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                store
                    .cached_pool("mt_broken", || async move {
                        let _ = started.send(());
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Err(StoreError::UnknownTenant("mt_broken".into()))
                    })
                    .await
            })
        };
        started_rx.await.expect("the first attempt starts");

        let joined = store
            .cached_pool("mt_broken", || async {
                Err(StoreError::UnknownTenant(
                    "a second attempt must not run".into(),
                ))
            })
            .await;

        let first = attempt.await.expect("the task finishes");
        let expected = StoreError::UnknownTenant("mt_broken".into());
        assert_eq!(first.err(), Some(expected.clone()));
        assert_eq!(
            joined.err(),
            Some(expected),
            "the waiter sees the attempt's error"
        );

        // The failed entry is gone, so the next request is a fresh attempt.
        assert!(store.tenants.lock().await.is_empty());
    }

    #[tokio::test]
    async fn tenant_pools_refuse_the_control_dsn_without_the_escape_hatch() {
        let store = test_store(64);
        assert_eq!(
            store.tenant_pool("mt_hot").await.err(),
            Some(StoreError::TenantPoolsNotConfigured)
        );

        let allowed = StoreConfig::default().with_control_tenant_pools();
        assert!(allowed.app_url.is_none());
        assert!(allowed.allow_control_db_user);
    }

    #[tokio::test]
    async fn a_separate_cache_does_not_evict_the_request_path() {
        let store = test_store(1);
        let poller = store.separate_tenant_cache(1, 1);

        store
            .cached_pool("mt_hot", || async { Ok(lazy_pool("mt_hot")) })
            .await
            .expect("the hot pool opens");
        poller
            .cached_pool("mt_cold", || async { Ok(lazy_pool("mt_cold")) })
            .await
            .expect("the poller pool opens");

        // A one-entry poller cache has room only for `mt_cold`; the request-path entry is intact.
        assert!(store.tenants.lock().await.contains_key("mt_hot"));
        assert!(!poller.tenants.lock().await.contains_key("mt_hot"));
        assert!(poller.tenants.lock().await.contains_key("mt_cold"));
    }

    #[tokio::test]
    async fn a_later_request_retries_after_a_failure() {
        use std::sync::atomic::AtomicUsize;

        let store = test_store(64);
        let calls = Arc::new(AtomicUsize::new(0));
        let failure = store
            .cached_pool("mt_retry", || async {
                Err(StoreError::UnknownTenant("mt_retry".into()))
            })
            .await;
        assert!(failure.is_err());

        let retry = store
            .cached_pool("mt_retry", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(lazy_pool("mt_retry"))
            })
            .await;
        assert!(retry.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.pool_stats().misses, 2, "a retry is a new miss");
    }
}
