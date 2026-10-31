//! The three migration sets — control, tenant and org — and their ledgers.
//!
//! Each target keeps its own `_migrations` table, because a tenant database and each org schema
//! are provisioned at different times and must be able to say independently what has run. The
//! control plane keeps `migration_rollup`, a summary that a `monaca-server migrate` run can print
//! without opening every tenant database.
//!
//! Files are applied with `sqlx::raw_sql`, which runs a multi-statement script. Statements are
//! `IF NOT EXISTS` so a re-run after a crash is harmless; the ledger is what decides whether a
//! migration runs, and a checksum mismatch is a hard error (§4.1).

use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};

use crate::{StoreError, q};

/// What one migration run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Versions applied by this run, ascending.
    pub applied: Vec<i64>,
    /// Versions already recorded with the same checksum.
    pub skipped: usize,
}

impl MigrationReport {
    /// Whether this run changed anything.
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
    }
}

/// The control-plane set.
const CONTROL: &[(i64, &str, &str)] = &[(
    1,
    "control schema (§5.3)",
    include_str!("../migrations/control.sql"),
)];

/// The tenant set (§5.6). Applied to each tenant database after `CREATE DATABASE`.
const TENANT: &[(i64, &str, &str)] = &[
    (
        1,
        "tenant schema (§5.6)",
        include_str!("../migrations/tenant.sql"),
    ),
    (
        2,
        "protocol completeness: PAR, DPoP, refresh families, token revocation (M1)",
        include_str!("../migrations/tenant_2.sql"),
    ),
    (
        3,
        "sessions and RP-initiated logout (M1)",
        include_str!("../migrations/tenant_3.sql"),
    ),
    (
        4,
        "email verification codes: sign-up, passwordless sign-in and password reset (M1)",
        include_str!("../migrations/tenant_4.sql"),
    ),
    (
        5,
        "MFA backup codes (M1)",
        include_str!("../migrations/tenant_5.sql"),
    ),
    (
        6,
        "WebAuthn passkeys (M1)",
        include_str!("../migrations/tenant_6.sql"),
    ),
    (
        7,
        "case-insensitive usernames as a sign-in identifier (M1)",
        include_str!("../migrations/tenant_7.sql"),
    ),
    (
        8,
        "email change codes from the account centre (M1)",
        include_str!("../migrations/tenant_8.sql"),
    ),
    (
        9,
        "social (OAuth2) connectors and linked identities (M1)",
        include_str!("../migrations/tenant_9.sql"),
    ),
    (
        10,
        "trusted browsers that skip the second factor (M1)",
        include_str!("../migrations/tenant_10.sql"),
    ),
    (
        11,
        "self-service account deletion codes (M1)",
        include_str!("../migrations/tenant_11.sql"),
    ),
];

/// The org template (§5.7). Applied to a fresh `org_<oshort>` schema.
const ORG: &[(i64, &str, &str)] = &[(
    1,
    "org schema (§5.7)",
    include_str!("../migrations/org.sql"),
)];

/// Apply the control-plane set.
pub async fn apply_control(pool: &PgPool) -> Result<MigrationReport, StoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query(LEDGER).execute(&mut *tx).await?;

    let mut report = MigrationReport::default();
    for (version, description, sql) in CONTROL {
        if apply_one(&mut tx, *version, description, sql).await? {
            report.applied.push(*version);
            record_rollup(&mut tx, "control", *version, description, sql).await?;
        } else {
            report.skipped += 1;
        }
    }

    tx.commit().await?;
    Ok(report)
}

/// Apply the tenant set to one tenant database.
pub async fn apply_tenant(pool: &PgPool, _short: &str) -> Result<MigrationReport, StoreError> {
    let mut tx = pool.begin().await?;

    // `tenant` is the one schema whose name is fixed (§5.1), and it is always fully qualified in
    // application SQL. Inside the migration the search_path makes the DDL readable.
    sqlx::query("CREATE SCHEMA IF NOT EXISTS tenant")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL search_path = tenant")
        .execute(&mut *tx)
        .await?;
    sqlx::query(LEDGER).execute(&mut *tx).await?;

    let mut report = MigrationReport::default();
    for (version, description, sql) in TENANT {
        if apply_one(&mut tx, *version, description, sql).await? {
            report.applied.push(*version);
        } else {
            report.skipped += 1;
        }
    }

    tx.commit().await?;
    Ok(report)
}

/// Apply the org template inside an already-open provisioning transaction.
///
/// The caller has created the schema and is responsible for the role grants; this function only
/// creates the tables and records the ledger row.
pub async fn apply_org(
    tx: &mut PgConnection,
    schema: &str,
    _tenant_short: &str,
    _org_short: &str,
) -> Result<(), StoreError> {
    sqlx::query(q(format!(
        "CREATE SCHEMA IF NOT EXISTS {}",
        crate::quote_ident(schema)
    )))
    .execute(&mut *tx)
    .await?;
    sqlx::query(q(format!(
        "SET LOCAL search_path = {}",
        crate::quote_ident(schema)
    )))
    .execute(&mut *tx)
    .await?;
    sqlx::query(LEDGER).execute(&mut *tx).await?;

    // The control-plane `migration_rollup` lives in the control database, not here; the org's own
    // `_migrations` ledger is the authority for this schema. `monaca-server migrate` aggregates the
    // rollup from the control side.
    for (version, description, sql) in ORG {
        apply_one(tx, *version, description, sql).await?;
    }

    Ok(())
}

/// The per-target ledger. `_migrations` is unqualified because the search_path is set by the
/// caller; the control plane uses `public`.
const LEDGER: &str = "CREATE TABLE IF NOT EXISTS _migrations (
    version     bigint PRIMARY KEY,
    description text NOT NULL,
    checksum    text NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
)";

/// Apply one migration if it is not recorded. Returns whether it ran.
async fn apply_one(
    tx: &mut PgConnection,
    version: i64,
    description: &str,
    sql: &str,
) -> Result<bool, StoreError> {
    let checksum = checksum(sql);
    let recorded: Option<(String,)> =
        sqlx::query_as("SELECT checksum FROM _migrations WHERE version = $1")
            .bind(version)
            .fetch_optional(&mut *tx)
            .await?;

    if let Some((recorded,)) = recorded {
        if recorded != checksum {
            return Err(StoreError::MigrationChecksum {
                version,
                recorded,
                computed: checksum,
            });
        }
        return Ok(false);
    }

    sqlx::raw_sql(q(sql.to_owned())).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO _migrations (version, description, checksum) VALUES ($1,$2,$3)")
        .bind(version)
        .bind(description)
        .bind(&checksum)
        .execute(&mut *tx)
        .await?;
    Ok(true)
}

async fn record_rollup(
    tx: &mut PgConnection,
    target: &str,
    version: i64,
    description: &str,
    sql: &str,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO public.migration_rollup (target, version, description, checksum)
         VALUES ($1,$2,$3,$4) ON CONFLICT (target, version) DO NOTHING",
    )
    .bind(target)
    .bind(version)
    .bind(description)
    .bind(checksum(sql))
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Lowercase hex SHA-256 of a migration file.
fn checksum(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sets_are_numbered_from_one() {
        assert_eq!(CONTROL[0].0, 1);
        assert_eq!(TENANT[0].0, 1);
        assert_eq!(ORG[0].0, 1);
    }

    #[test]
    fn every_set_has_a_description() {
        for (_, description, _) in CONTROL.iter().chain(TENANT).chain(ORG) {
            assert!(!description.is_empty());
        }
    }

    #[test]
    fn the_tenant_set_does_not_create_the_schema() {
        // The migrator creates `tenant`; the file must not, or a future restore into a differently
        // named schema would silently create the wrong one.
        assert!(!TENANT[0].2.contains("CREATE SCHEMA"));
    }

    #[test]
    fn the_org_set_does_not_pick_its_own_schema() {
        let sql = ORG[0].2;
        assert!(!sql.contains("CREATE SCHEMA"));
        assert!(!sql.contains("SET search_path"));
    }

    #[test]
    fn a_checksum_is_stable_and_sensitive() {
        assert_eq!(checksum("a"), checksum("a"));
        assert_ne!(checksum("a"), checksum("b"));
        assert_eq!(checksum("a").len(), 64);
    }

    #[test]
    fn the_ledger_is_idempotent() {
        assert!(LEDGER.contains("IF NOT EXISTS"));
    }
}
