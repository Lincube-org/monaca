//! `monaca-server rewrap` — move sealed values from the retiring KEK to the current one.
//!
//! Rotation is a three-step procedure (§10.7):
//!
//! 1. restart with `MONACA_KEK` = the new key and `MONACA_KEK_PREVIOUS` = the old key; reads try
//!    the new key first and the old one second, while new writes use the new key;
//! 2. run this command, which opens every sealed value with either key and writes it back under
//!    the new one;
//! 3. restart without `MONACA_KEK_PREVIOUS`.
//!
//! Every row is migrated with a compare-and-swap on its current bytes, so a value the server
//! rewrote concurrently is skipped rather than overwritten. A value that opens with the current
//! key is skipped, which is what makes the command safe to run again after an interruption.

use std::sync::Arc;

use anyhow::Context;
use monaca_crypto::{KeyProvider, rewrap};
use monaca_store::{Store, StoreError, TenantRow};
use sqlx::{AssertSqlSafe, PgPool};

use crate::cli::RewrapArgs;

/// One sealed column and the column that identifies its row. An empty `key` means the table has a
/// single row (`singleton`), so the update addresses it directly.
struct SealedColumn {
    table: &'static str,
    key: &'static str,
    column: &'static str,
    /// Rows to touch. `None` means every row; `credentials` also holds argon2 password hashes
    /// and must be limited to the sealed kinds.
    filter: Option<&'static str>,
}

/// Every tenant-scoped column sealed with the tenant DEK.
///
/// Keep this list in step with the migrations: a new `_enc` column that this command does not
/// know about would stay unreadable after the old KEK is removed.
const TENANT_COLUMNS: &[SealedColumn] = &[
    SealedColumn {
        table: "tenant.signing_keys",
        key: "id",
        column: "private_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.credentials",
        key: "id",
        column: "secret_enc",
        filter: Some("kind IN ('totp','passkey')"),
    },
    SealedColumn {
        table: "tenant.totp_enrollments",
        key: "account_id",
        column: "secret_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.social_connectors",
        key: "connector_id",
        column: "client_secret_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.sso_connectors",
        key: "connector_id",
        column: "client_secret_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.delivery_connector",
        key: "",
        column: "secret_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.webhooks",
        key: "id",
        column: "secret_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.sign_in_experience",
        key: "",
        column: "captcha_secret_enc",
        filter: None,
    },
    SealedColumn {
        table: "tenant.social_states",
        key: "id",
        column: "code_verifier_enc",
        filter: None,
    },
];

/// The control-plane DSNs, sealed directly with the platform KEK rather than a tenant DEK.
const CLUSTER_COLUMNS: &[(&str, &str)] =
    &[("clusters", "admin_dsn_enc"), ("clusters", "app_dsn_enc")];

#[derive(Debug, Default)]
struct Counts {
    migrated: u64,
    skipped: u64,
    failed: u64,
}

impl Counts {
    fn merge(&mut self, other: Counts) {
        self.migrated += other.migrated;
        self.skipped += other.skipped;
        self.failed += other.failed;
    }
}

/// Run the command.
pub async fn run(args: RewrapArgs) -> anyhow::Result<()> {
    let state = crate::admin_state().await?;
    let deks = Arc::clone(&state.keys);
    let tenants = select_tenants(&state.store, args.tenant.as_deref()).await?;

    let mut total = Counts::default();
    for tenant in &tenants {
        let counts = rewrap_tenant(&state.store, tenant, deks.as_ref(), args.dry_run).await;
        total.merge(counts);
    }

    // The cluster DSNs are only written, never read at runtime, but leaving them under a removed
    // key would make the row unusable later. They are re-wrapped with the platform KEKs.
    let cluster = rewrap_clusters(
        state.store.control(),
        deks.platform_kek(),
        deks.previous_platform_kek(),
        args.dry_run,
    )
    .await;
    total.merge(cluster);

    let verb = if args.dry_run {
        "would re-wrap"
    } else {
        "re-wrapped"
    };
    println!(
        "rewrap: {verb} {} value(s), skipped {}, failed {}",
        total.migrated, total.skipped, total.failed
    );
    if total.failed > 0 {
        anyhow::bail!(
            "{} sealed value(s) could not be opened with the configured KEKs",
            total.failed
        );
    }
    Ok(())
}

async fn select_tenants(store: &Store, slug: Option<&str>) -> anyhow::Result<Vec<TenantRow>> {
    match slug {
        Some(slug) => Ok(vec![
            store
                .tenant_by_slug(slug)
                .await
                .with_context(|| format!("tenant `{slug}`"))?,
        ]),
        None => Ok(store.tenants().await?),
    }
}

async fn rewrap_tenant(
    store: &Store,
    tenant: &TenantRow,
    keys: &dyn KeyProvider,
    dry_run: bool,
) -> Counts {
    let deks = keys.tenant_deks(&tenant.tenant_id());
    if deks.len() < 2 {
        // No previous key is configured: every value either already opens with the current key
        // (skipped) or belongs to neither key (reported). There is nothing to migrate.
        tracing::warn!(
            tenant = %tenant.slug,
            "MONACA_KEK_PREVIOUS is not set; there is no retiring key to re-wrap from"
        );
    }
    let pool = match store.tenant_pool(&tenant.db_name).await {
        Ok(pool) => pool,
        Err(err) => {
            tracing::error!(tenant = %tenant.slug, %err, "could not open the tenant database");
            return Counts {
                failed: 1,
                ..Counts::default()
            };
        }
    };
    let mut counts = Counts::default();
    for column in TENANT_COLUMNS {
        let table = rewrap_column(&pool, column, &deks, dry_run).await;
        match table {
            Ok(table) => counts.merge(table),
            Err(err) => {
                tracing::error!(
                    tenant = %tenant.slug,
                    table = column.table,
                    column = column.column,
                    %err,
                    "could not re-wrap a sealed column"
                );
                counts.failed += 1;
            }
        }
    }
    println!(
        "  tenant {:<24} migrated {:>4}  skipped {:>4}  failed {:>2}",
        tenant.slug, counts.migrated, counts.skipped, counts.failed
    );
    counts
}

async fn rewrap_column(
    pool: &PgPool,
    column: &SealedColumn,
    deks: &[[u8; 32]],
    dry_run: bool,
) -> Result<Counts, StoreError> {
    let filter = column
        .filter
        .map(|filter| format!(" WHERE {filter}"))
        .unwrap_or_default();
    let select = if column.key.is_empty() {
        format!(
            "SELECT NULL::text AS row_key, {column} AS sealed FROM {table}{filter}",
            column = column.column,
            table = column.table
        )
    } else {
        format!(
            "SELECT {key}::text AS row_key, {column} AS sealed FROM {table}{filter}",
            key = column.key,
            column = column.column,
            table = column.table
        )
    };
    let rows: Vec<(Option<String>, Option<Vec<u8>>)> = sqlx::query_as(AssertSqlSafe(select))
        .fetch_all(pool)
        .await?;

    let mut counts = Counts::default();
    for (row_key, sealed) in rows {
        let Some(sealed) = sealed else {
            continue;
        };
        match rewrap(deks, &sealed) {
            Ok(None) => counts.skipped += 1,
            Ok(Some(rewrapped)) => {
                if dry_run {
                    counts.migrated += 1;
                    continue;
                }
                let rows = if column.key.is_empty() {
                    let update = format!(
                        "UPDATE {table} SET {column} = $1 WHERE {column} = $2",
                        table = column.table,
                        column = column.column
                    );
                    sqlx::query(AssertSqlSafe(update))
                        .bind(&rewrapped)
                        .bind(&sealed)
                        .execute(pool)
                        .await?
                        .rows_affected()
                } else {
                    let update = format!(
                        "UPDATE {table} SET {column} = $1
                         WHERE {key}::text = $2 AND {column} = $3",
                        table = column.table,
                        column = column.column,
                        key = column.key
                    );
                    sqlx::query(AssertSqlSafe(update))
                        .bind(&rewrapped)
                        .bind(row_key.as_deref().unwrap_or_default())
                        .bind(&sealed)
                        .execute(pool)
                        .await?
                        .rows_affected()
                };
                if rows == 1 {
                    counts.migrated += 1;
                } else {
                    // A concurrent writer replaced the value between the read and the update; it
                    // wrote under the current key, so there is nothing left to migrate here.
                    counts.skipped += 1;
                }
            }
            Err(err) => {
                tracing::error!(
                    table = column.table,
                    column = column.column,
                    row = row_key.as_deref().unwrap_or("(singleton)"),
                    %err,
                    "sealed value opens with no configured key"
                );
                counts.failed += 1;
            }
        }
    }
    Ok(counts)
}

async fn rewrap_clusters(
    control: &PgPool,
    current: &[u8; 32],
    previous: Option<[u8; 32]>,
    dry_run: bool,
) -> Counts {
    let Some(previous) = previous else {
        return Counts::default();
    };
    let deks = [*current, previous];
    let mut counts = Counts::default();
    for (table, column) in CLUSTER_COLUMNS {
        let select = format!("SELECT id::text AS row_key, {column} AS sealed FROM {table}");
        let rows: Result<Vec<(String, Vec<u8>)>, StoreError> =
            sqlx::query_as(AssertSqlSafe(select))
                .fetch_all(control)
                .await
                .map_err(StoreError::from);
        let rows = match rows {
            Ok(rows) => rows,
            Err(err) => {
                tracing::error!(table, column, %err, "could not read control-plane DSNs");
                counts.failed += 1;
                continue;
            }
        };
        for (row_key, sealed) in rows {
            match rewrap(&deks, &sealed) {
                Ok(None) => counts.skipped += 1,
                Ok(Some(rewrapped)) => {
                    if dry_run {
                        counts.migrated += 1;
                        continue;
                    }
                    let update = format!(
                        "UPDATE {table} SET {column} = $1 WHERE id::text = $2 AND {column} = $3"
                    );
                    match sqlx::query(AssertSqlSafe(update))
                        .bind(&rewrapped)
                        .bind(&row_key)
                        .bind(&sealed)
                        .execute(control)
                        .await
                    {
                        Ok(result) if result.rows_affected() == 1 => counts.migrated += 1,
                        Ok(_) => counts.skipped += 1,
                        Err(err) => {
                            tracing::error!(table, column, row = %row_key, %err, "could not update a cluster row");
                            counts.failed += 1;
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(table, column, row = %row_key, %err, "cluster DSN opens with no configured key");
                    counts.failed += 1;
                }
            }
        }
    }
    counts
}
