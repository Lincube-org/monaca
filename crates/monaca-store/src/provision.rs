//! Tenant and organization provisioning — §5.4 and §5.5.
//!
//! `CREATE DATABASE` cannot run inside a transaction, so tenant provisioning is a resumable state
//! machine whose progress is the `tenants.state` column. Every step tolerates having already run,
//! which is what makes a retry after a crash safe.
//!
//! Organization provisioning is a single transaction: schema, role, grants, the org migration set
//! and the directory row either all exist or none do.

use monaca_types::{OrgId, TenantId};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::repo::unique_conflict;
use crate::{Store, StoreError, q, quote_ident, validate_login_role};

/// A tenant as stored in the control plane.
#[derive(Debug, Clone, FromRow)]
pub struct TenantRow {
    /// `tenants.id`.
    pub id: Uuid,
    /// `tenants.slug`, e.g. `demo`.
    pub slug: String,
    /// `tenants.short`, the identifier fragment in `db_name`, schemas and roles.
    pub short: String,
    /// `mt_<short>`.
    pub db_name: String,
    /// `<public_base_url>/t/<slug>`.
    pub issuer: String,
    /// `provisioning` | `active` | `suspended`.
    pub state: String,
}

impl TenantRow {
    /// The tenant's typed id.
    pub fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.id)
    }

    /// Whether the tenant is ready to serve.
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }

    /// `Ok` only for `active`; otherwise the state that is refusing the request.
    pub fn serving(&self) -> Result<(), &str> {
        if self.is_active() {
            Ok(())
        } else {
            Err(self.state.as_str())
        }
    }
}

/// An organization as stored in its tenant's `tenant.organizations`.
#[derive(Debug, Clone, FromRow)]
pub struct OrgRow {
    /// `organizations.id`.
    pub id: Uuid,
    /// `organizations.slug`, e.g. `acme`.
    pub slug: String,
    /// `org_<oshort>`.
    pub schema_name: String,
    /// `t<tshort>_o<oshort>`.
    pub role_name: String,
    /// `active` | `archived` (§5.6).
    pub state: String,
    /// Whether this is the tenant's default org.
    pub is_default: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
}

impl OrgRow {
    /// The organization's typed id.
    pub fn org_id(&self) -> OrgId {
        OrgId::from_uuid(self.id)
    }

    /// Whether the org is serving traffic. An archived org keeps its schema and audit chain but
    /// is no longer addressable by slug, so `authorize` and the `/v1` sub-resources refuse it.
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
}

/// Derive a `short` from a UUIDv7: the **last** symbols of the TypeID suffix.
///
/// Never user input (§5.4). The tail matters: a v7's first symbols encode its timestamp, so two
/// tenants created in the same millisecond would share a prefix and collide on `tenants.short`.
/// The tail is the random part of the UUID, which is what a short id needs. The columns are
/// UNIQUE, so a collision is a loud error rather than a silent merge.
fn short_from_uuid(id: Uuid, len: usize) -> String {
    let suffix = monaca_types::encode_suffix(id);
    suffix[suffix.len() - len..].to_owned()
}

impl Store {
    /// Provision a tenant — §5.4. Idempotent at every step.
    ///
    /// `slug` is validated by the `tenants` CHECK constraint; `short`, `db_name` and `issuer` are
    /// derived here and never taken from the caller.
    pub async fn provision_tenant(
        &self,
        slug: &str,
        public_base_url: &str,
        cluster_id: Uuid,
    ) -> Result<TenantRow, StoreError> {
        // Step 1: the saga row. Re-read if it already exists.
        let tenant_id = TenantId::new();
        let short = short_from_uuid(tenant_id.uuid(), 8);
        let db_name = format!("mt_{short}");
        let issuer = format!("{}/t/{slug}", public_base_url.trim_end_matches('/'));

        sqlx::query(
            "INSERT INTO tenants (id, slug, short, cluster_id, db_name, issuer, state)
             VALUES ($1,$2,$3,$4,$5,$6,'provisioning')
             ON CONFLICT (slug) DO NOTHING",
        )
        .bind(tenant_id.uuid())
        .bind(slug)
        .bind(&short)
        .bind(cluster_id)
        .bind(&db_name)
        .bind(&issuer)
        .execute(self.control())
        .await?;

        let tenant = self.tenant_by_slug(slug).await?;
        if tenant.is_active() {
            return Ok(tenant);
        }

        // Step 2: the database. `CREATE DATABASE` is not transactional; "already exists" is the
        // idempotent case.
        if let Err(err) = sqlx::query(q(format!(
            "CREATE DATABASE {}",
            quote_ident(&tenant.db_name)
        )))
        .execute(self.admin())
        .await
        {
            match &err {
                sqlx::Error::Database(db) if db.code().as_deref() == Some("42P04") => {}
                _ => return Err(err.into()),
            }
        }

        // Step 3: the tenant migration set (which includes `tenant.organizations`).
        let pool = self.tenant_pool(&tenant.db_name).await?;
        crate::apply_tenant(&pool, &tenant.short).await?;

        // Step 5: active.
        self.activate_tenant(slug).await?;
        self.tenant_by_slug(slug).await
    }

    /// Move a tenant between serving states. `provisioning` is never a target.
    ///
    /// The caller (the `tenant` CLI) validates and prints the transition; this method enforces the
    /// state machine so a direct call cannot put a half-provisioned tenant into service.
    pub async fn set_tenant_state(
        &self,
        slug: &str,
        target: &str,
    ) -> Result<TenantRow, StoreError> {
        let tenant = self.tenant_by_slug(slug).await?;
        let allowed = match (tenant.state.as_str(), target) {
            ("active", "suspended") | ("active", "archived") => true,
            ("suspended", "active") | ("suspended", "archived") => true,
            ("archived", "active") => true,
            (state, target) if state == target => true,
            _ => false,
        };
        if !allowed {
            return Err(StoreError::Database(format!(
                "tenant `{slug}` cannot move from `{}` to `{target}`",
                tenant.state
            )));
        }
        sqlx::query("UPDATE tenants SET state = $2, updated_at = now() WHERE slug = $1")
            .bind(slug)
            .bind(target)
            .execute(self.control())
            .await?;
        self.tenant_by_slug(slug).await
    }

    /// Create or update the least-privilege login and grant it the request-path surface.
    ///
    /// `bootstrap` calls this for every tenant after the org roles exist. The login is `LOGIN
    /// NOINHERIT`; its org-role memberships therefore only take effect inside the request path's
    /// `SET LOCAL ROLE`. `PUBLIC` loses `CONNECT` on each tenant database, so a role that was not
    /// provisioned cannot open one even if it guesses the name.
    pub async fn provision_app_role(&self, user: &str, password: &str) -> Result<(), StoreError> {
        validate_login_role(user)?;
        if password.is_empty() {
            return Err(StoreError::TenantPoolRole(
                "MONACA_APP_DB_PASSWORD is empty".to_owned(),
            ));
        }
        let role = quote_ident(user);
        let password = password.replace('\'', "''");
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(user)
                .fetch_one(self.admin())
                .await?;
        let statement = if exists {
            format!("ALTER ROLE {role} LOGIN NOINHERIT PASSWORD '{password}'")
        } else {
            format!("CREATE ROLE {role} LOGIN NOINHERIT PASSWORD '{password}'")
        };
        sqlx::query(q(statement)).execute(self.admin()).await?;

        for tenant in self.tenants().await? {
            let database = quote_ident(&tenant.db_name);
            sqlx::query(q(format!(
                "REVOKE CONNECT ON DATABASE {database} FROM PUBLIC"
            )))
            .execute(self.admin())
            .await?;
            sqlx::query(q(format!("GRANT CONNECT ON DATABASE {database} TO {role}")))
                .execute(self.admin())
                .await?;

            let pool = self.tenant_pool(&tenant.db_name).await?;
            for statement in [
                format!("GRANT USAGE ON SCHEMA tenant TO {role}"),
                format!(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenant TO {role}"
                ),
                format!(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA tenant \
                     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"
                ),
            ] {
                sqlx::query(q(statement)).execute(&pool).await?;
            }

            let org_roles: Vec<(String,)> = sqlx::query_as(
                "SELECT rolname FROM pg_roles WHERE rolname ~ '^t[0-9a-z]+_o[0-9a-z]+$'",
            )
            .fetch_all(&pool)
            .await?;
            for (org_role,) in org_roles {
                let org_role = quote_ident(&org_role);
                sqlx::query(q(format!("GRANT {org_role} TO {role}")))
                    .execute(&pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Provision an organization in one transaction — §5.5.
    ///
    /// `org_id` is generated by the caller **before** the transaction, so a retried request
    /// derives the same schema and role names and the whole transaction is a no-op.
    pub async fn provision_org(
        &self,
        tenant: &TenantRow,
        slug: &str,
        org_id: OrgId,
        is_default: bool,
    ) -> Result<OrgRow, StoreError> {
        let oshort = short_from_uuid(org_id.uuid(), 8);
        let schema_name = format!("org_{oshort}");
        let role_name = format!("t{}_o{oshort}", tenant.short);
        let app_user = std::env::var("MONACA_APP_DB_USER").unwrap_or_else(|_| "monaca_app".into());

        let pool = self.tenant_pool(&tenant.db_name).await?;
        let mut tx = pool.begin().await?;

        sqlx::query(q(format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            quote_ident(&schema_name)
        )))
        .execute(&mut *tx)
        .await?;

        // A role is cluster-wide; it may already exist after a crashed attempt. Checking first
        // matters: a failed statement would abort this transaction and every later grant with it.
        let role_exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(&role_name)
                .fetch_one(&mut *tx)
                .await?;
        if !role_exists {
            sqlx::query(q(format!(
                "CREATE ROLE {} NOLOGIN",
                quote_ident(&role_name)
            )))
            .execute(&mut *tx)
            .await?;
        }

        for statement in [
            format!(
                "GRANT USAGE ON SCHEMA {} TO {}",
                quote_ident(&schema_name),
                quote_ident(&role_name)
            ),
            format!(
                "GRANT USAGE ON SCHEMA tenant TO {}",
                quote_ident(&role_name)
            ),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON tenant.accounts, tenant.account_identifiers,
                        tenant.credentials, tenant.sessions TO {}",
                quote_ident(&role_name)
            ),
            format!(
                "GRANT SELECT ON tenant.organizations TO {}",
                quote_ident(&role_name)
            ),
            format!(
                "GRANT SELECT, INSERT, DELETE ON tenant.agent_directory TO {}",
                quote_ident(&role_name)
            ),
            format!(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}",
                quote_ident(&schema_name),
                quote_ident(&role_name)
            ),
        ] {
            sqlx::query(q(statement)).execute(&mut *tx).await?;
        }

        // Step 4: the org migration set.
        crate::migrate::apply_org(&mut tx, &schema_name, &tenant.short, &oshort).await?;

        // After the tables exist, grant on all of them as well: `ALTER DEFAULT PRIVILEGES` covers
        // tables created after this point, not the ones just created.
        sqlx::query(q(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}",
            quote_ident(&schema_name),
            quote_ident(&role_name)
        )))
        .execute(&mut *tx)
        .await?;

        // Membership only. `monaca_app` is created NOINHERIT (§5.1), so this confers nothing until
        // `SET LOCAL ROLE` runs. Both grants are best-effort: a deployment may not have created
        // the app role yet, and a failed GRANT must not abort the provisioning transaction.
        let connect_user = current_user(&mut *tx).await?;
        for grantee in [app_user.as_str(), connect_user.as_str()] {
            let _ = try_exec(
                &mut *tx,
                format!(
                    "GRANT {} TO {}",
                    quote_ident(&role_name),
                    quote_ident(grantee)
                ),
            )
            .await;
        }

        sqlx::query(
            "INSERT INTO tenant.organizations (id, slug, schema_name, role_name, state, is_default)
             VALUES ($1,$2,$3,$4,'active',$5)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(org_id.uuid())
        .bind(slug)
        .bind(&schema_name)
        .bind(&role_name)
        .bind(is_default)
        .execute(&mut *tx)
        .await
        // A duplicate slug fails here, after the schema and role DDL: PostgreSQL aborts the
        // transaction, so the rollback removes both and the caller sees "already taken" — the
        // unique index in `tenant.organizations` is the authority, not a prior SELECT.
        .map_err(|err| unique_conflict(err, "organization"))?;

        tx.commit().await?;

        self.org_by_id(tenant, org_id).await
    }
}

/// The role the provisioning connection is running as.
async fn current_user(conn: &mut sqlx::PgConnection) -> Result<String, StoreError> {
    let (user,): (String,) = sqlx::query_as("SELECT current_user")
        .fetch_one(&mut *conn)
        .await?;
    Ok(user)
}

/// Run a statement that is allowed to fail without aborting the surrounding transaction.
///
/// PostgreSQL marks a transaction aborted on any error, so "best effort" needs a savepoint rather
/// than an ignored `Result`. This is how the two membership grants stay optional.
async fn try_exec(conn: &mut sqlx::PgConnection, sql: String) -> Result<(), StoreError> {
    sqlx::query("SAVEPOINT monaca_best_effort")
        .execute(&mut *conn)
        .await?;
    match sqlx::query(q(sql)).execute(&mut *conn).await {
        Ok(_) => {
            sqlx::query("RELEASE SAVEPOINT monaca_best_effort")
                .execute(&mut *conn)
                .await?;
        }
        Err(_) => {
            sqlx::query("ROLLBACK TO SAVEPOINT monaca_best_effort")
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_is_derived_from_the_uuid_and_honours_the_target_length() {
        let short = short_from_uuid(Uuid::now_v7(), 8);
        assert_eq!(short.len(), 8);
        assert!(
            short
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
            "got {short}"
        );
        assert!(!short.contains('i') && !short.contains('l') && !short.contains('u'));
    }

    #[test]
    fn the_role_name_matches_the_contract_pattern() {
        let tenant_short = "abcd1234";
        let oshort = "efgh5678";
        let role = format!("t{tenant_short}_o{oshort}");
        assert!(crate::validate_role_name(&role).is_ok());
    }

    #[test]
    fn the_schema_name_matches_the_contract_pattern() {
        let oshort = "efgh5678";
        let schema = format!("org_{oshort}");
        assert!(crate::validate_schema_name(&schema).is_ok());
    }
}
