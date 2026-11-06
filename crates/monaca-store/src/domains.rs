//! Custom tenant hostnames in the control plane — `docs/contracts/m0.md` §5.8.
//!
//! These rows are the only authority for "which tenant owns `login.example.com`". The host is
//! globally unique, so the INSERT is the cross-tenant claim lock. State changes are conditional
//! UPDATEs: a caller names the state it observed, and a concurrent change makes the statement
//! return no row instead of silently skipping a transition.

use monaca_types::{TenantId, TypedId};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provision::TenantRow;
use crate::repo::unique_conflict;
use crate::{Store, StoreError};

/// One custom hostname binding.
#[derive(Debug, Clone, FromRow)]
pub struct TenantDomainRow {
    /// `tenant_domains.id`.
    pub id: Uuid,
    /// The tenant that owns the host.
    pub tenant_id: Uuid,
    /// Lower-case hostname without a port.
    pub host: String,
    /// `pending` | `verified` | `active` | `degraded` | `revoked`.
    pub state: String,
    /// The one-time claim nonce published in the TXT record.
    pub nonce: String,
    /// The serving state a failed re-check interrupted.
    pub last_good_state: Option<String>,
    /// When DNS ownership was first proven.
    pub verified_at: Option<OffsetDateTime>,
    /// When DNS was last checked, successfully or not.
    pub last_checked_at: Option<OffsetDateTime>,
    /// Consecutive failed checks.
    pub check_failures: i32,
    /// When the binding was revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last transition time.
    pub updated_at: OffsetDateTime,
}

impl TenantDomainRow {
    /// Whether this binding serves requests. It is orthogonal to the tenant's own state; the
    /// cache builder applies [`TenantRow::serving`] to both before a host is routable.
    pub fn serves(&self) -> bool {
        matches!(self.state.as_str(), "verified" | "active")
    }

    /// The tenant this domain belongs to, as the typed id.
    pub fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }
}

/// A domain plus the tenant fields routing needs, from one join.
#[derive(Debug, Clone, FromRow)]
pub struct DomainRouteRow {
    /// Lower-case hostname.
    pub host: String,
    /// The binding state.
    pub domain_state: String,
    /// `tenants.id`.
    pub tenant_id: Uuid,
    /// `tenants.slug`.
    pub tenant_slug: String,
    /// `tenants.short`.
    pub tenant_short: String,
    /// `mt_<short>`.
    pub tenant_db_name: String,
    /// The canonical issuer; custom hosts never change it.
    pub tenant_issuer: String,
    /// `tenants.state`.
    pub tenant_state: String,
}

impl DomainRouteRow {
    /// The tenant row this route addresses.
    pub fn tenant(&self) -> TenantRow {
        TenantRow {
            id: self.tenant_id,
            slug: self.tenant_slug.clone(),
            short: self.tenant_short.clone(),
            db_name: self.tenant_db_name.clone(),
            issuer: self.tenant_issuer.clone(),
            state: self.tenant_state.clone(),
        }
    }
}

const COLUMNS: &str = "id, tenant_id, host, state, nonce, last_good_state, verified_at, \
                       last_checked_at, check_failures, revoked_at, created_at, updated_at";

impl Store {
    /// Every binding a tenant owns, oldest first.
    pub async fn tenant_domains(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<TenantDomainRow>, StoreError> {
        Ok(sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM tenant_domains WHERE tenant_id = $1 ORDER BY created_at, host"
        )))
        .bind(tenant.as_uuid())
        .fetch_all(&self.control)
        .await?)
    }

    /// One binding, scoped to its tenant so a caller cannot read another tenant's row.
    pub async fn tenant_domain(
        &self,
        tenant: TenantId,
        host: &str,
    ) -> Result<TenantDomainRow, StoreError> {
        sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM tenant_domains WHERE tenant_id = $1 AND host = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(host)
        .fetch_optional(&self.control)
        .await?
        .ok_or_else(|| StoreError::NotFound {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// Claim a host for a tenant. The UNIQUE(host) constraint refuses a host another tenant owns;
    /// `nonce` is the value the tenant must publish at `_monaca-verify.<host>`.
    pub async fn create_tenant_domain(
        &self,
        tenant: TenantId,
        host: &str,
        nonce: &str,
    ) -> Result<TenantDomainRow, StoreError> {
        sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "INSERT INTO tenant_domains (id, tenant_id, host, state, nonce)
             VALUES ($1, $2, $3, 'pending', $4) RETURNING {COLUMNS}"
        )))
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(host)
        .bind(nonce)
        .fetch_one(&self.control)
        .await
        .map_err(|err| unique_conflict(err, "custom domain"))
    }

    /// `pending -> verified`, after the TXT record matched. Only a pending row can be verified.
    pub async fn verify_tenant_domain(
        &self,
        tenant: TenantId,
        host: &str,
        at: OffsetDateTime,
    ) -> Result<TenantDomainRow, StoreError> {
        let updated = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "UPDATE tenant_domains
             SET state = 'verified', verified_at = $3, last_checked_at = $3, check_failures = 0,
                 last_good_state = NULL, updated_at = now()
             WHERE tenant_id = $1 AND host = $2 AND state = 'pending'
             RETURNING {COLUMNS}"
        )))
        .bind(tenant.as_uuid())
        .bind(host)
        .bind(at)
        .fetch_optional(&self.control)
        .await?;
        updated.ok_or_else(|| StoreError::Conflict {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// `verified -> active`. Activation is the explicit "this name is now live" action.
    pub async fn activate_tenant_domain(
        &self,
        tenant: TenantId,
        host: &str,
    ) -> Result<TenantDomainRow, StoreError> {
        let updated = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "UPDATE tenant_domains
             SET state = 'active', updated_at = now()
             WHERE tenant_id = $1 AND host = $2 AND state = 'verified'
             RETURNING {COLUMNS}"
        )))
        .bind(tenant.as_uuid())
        .bind(host)
        .fetch_optional(&self.control)
        .await?;
        updated.ok_or_else(|| StoreError::Conflict {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// Revoke from any non-revoked state. The row is kept; `renew` starts a fresh claim.
    pub async fn revoke_tenant_domain(
        &self,
        tenant: TenantId,
        host: &str,
        at: OffsetDateTime,
    ) -> Result<TenantDomainRow, StoreError> {
        let updated = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "UPDATE tenant_domains
             SET state = 'revoked', revoked_at = $3, last_good_state = NULL, updated_at = now()
             WHERE tenant_id = $1 AND host = $2 AND state <> 'revoked'
             RETURNING {COLUMNS}"
        )))
        .bind(tenant.as_uuid())
        .bind(host)
        .bind(at)
        .fetch_optional(&self.control)
        .await?;
        updated.ok_or_else(|| StoreError::Conflict {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// `revoked -> pending` with a fresh nonce, so the old published record can never re-claim it.
    pub async fn renew_tenant_domain(
        &self,
        tenant: TenantId,
        host: &str,
        nonce: &str,
    ) -> Result<TenantDomainRow, StoreError> {
        let updated = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "UPDATE tenant_domains
             SET state = 'pending', nonce = $3, verified_at = NULL, last_checked_at = NULL,
                 check_failures = 0, last_good_state = NULL, revoked_at = NULL, updated_at = now()
             WHERE tenant_id = $1 AND host = $2 AND state = 'revoked'
             RETURNING {COLUMNS}"
        )))
        .bind(tenant.as_uuid())
        .bind(host)
        .bind(nonce)
        .fetch_optional(&self.control)
        .await?;
        updated.ok_or_else(|| StoreError::Conflict {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// Record a successful DNS check. A degraded binding returns to the state the failure
    /// interrupted (`verified` or `active`); a healthy one only refreshes the timestamp.
    pub async fn domain_check_ok(
        &self,
        host: &str,
        at: OffsetDateTime,
    ) -> Result<TenantDomainRow, StoreError> {
        let updated = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "UPDATE tenant_domains
             SET state = COALESCE(last_good_state, state), last_good_state = NULL,
                 check_failures = 0, last_checked_at = $2,
                 verified_at = COALESCE(verified_at, $2), updated_at = now()
             WHERE host = $1 AND state IN ('verified','active','degraded')
             RETURNING {COLUMNS}"
        )))
        .bind(host)
        .bind(at)
        .fetch_optional(&self.control)
        .await?;
        updated.ok_or_else(|| StoreError::Conflict {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// Record a failed DNS check. A serving binding becomes `degraded` and stops serving; the
    /// tenant's `active` state is untouched. A pending or already degraded row only accumulates
    /// the failure count.
    pub async fn domain_check_failed(
        &self,
        host: &str,
        at: OffsetDateTime,
    ) -> Result<TenantDomainRow, StoreError> {
        let updated = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "UPDATE tenant_domains
             SET last_good_state = CASE WHEN state IN ('verified','active') THEN state
                                        ELSE last_good_state END,
                 state = CASE WHEN state IN ('verified','active') THEN 'degraded'
                              ELSE state END,
                 check_failures = check_failures + 1, last_checked_at = $2, updated_at = now()
             WHERE host = $1 AND state IN ('pending','verified','active','degraded')
             RETURNING {COLUMNS}"
        )))
        .bind(host)
        .bind(at)
        .fetch_optional(&self.control)
        .await?;
        updated.ok_or_else(|| StoreError::Conflict {
            entity: "custom domain",
            id: host.to_owned(),
        })
    }

    /// Every binding the host router may consult: a serving domain and a serving tenant. The
    /// tenant half uses the same [`TenantRow::serving`] gate as every path-based handler, so the
    /// two entry points cannot disagree.
    pub async fn serving_domain_routes(&self) -> Result<Vec<DomainRouteRow>, StoreError> {
        Ok(sqlx::query_as::<_, DomainRouteRow>(
            "SELECT d.host, d.state AS domain_state,
                    t.id AS tenant_id, t.slug AS tenant_slug, t.short AS tenant_short,
                    t.db_name AS tenant_db_name, t.issuer AS tenant_issuer,
                    t.state AS tenant_state
             FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id
             WHERE d.state IN ('verified','active')
             ORDER BY d.host",
        )
        .fetch_all(&self.control)
        .await?)
    }

    /// Every binding the daily re-check visits, with the tenant row its audit entries belong to.
    pub async fn domains_for_recheck(
        &self,
    ) -> Result<Vec<(TenantRow, TenantDomainRow)>, StoreError> {
        let tenants: std::collections::HashMap<Uuid, TenantRow> = self
            .tenants()
            .await?
            .into_iter()
            .map(|tenant| (tenant.id, tenant))
            .collect();
        let domains = sqlx::query_as::<_, TenantDomainRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM tenant_domains
             WHERE state IN ('verified','active','degraded')
             ORDER BY host"
        )))
        .fetch_all(&self.control)
        .await?;
        Ok(domains
            .into_iter()
            .filter_map(|domain| {
                tenants
                    .get(&domain.tenant_id)
                    .cloned()
                    .map(|tenant| (tenant, domain))
            })
            .collect())
    }
}
