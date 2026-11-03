//! `/internal/*` — §6.3.
//!
//! Shared-secret authenticated, never proxied by the gateway. This is the only interface through
//! which the Bun side writes core data.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::AuditEvent;
use monaca_store::topics;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, kinds};
use crate::state::AppState;

/// The internal write body — §6.3.
#[derive(Debug, Deserialize)]
pub struct AuditBody {
    /// Tenant slug.
    pub tenant: String,
    /// Org slug.
    pub org: String,
    /// The §8.1 event.
    pub event: AuditEvent,
}

fn require_secret(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = headers
        .get("x-monaca-internal-secret")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !const_eq(supplied.as_bytes(), state.config.internal_secret.as_bytes()) {
        return Err(ApiError::problem(
            kinds::UNAUTHORIZED,
            "internal authentication failed",
        ));
    }
    Ok(())
}

fn const_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// `POST /internal/audit`.
pub async fn append_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AuditBody>,
) -> Result<Response, ApiError> {
    require_secret(&state, &headers)?;
    let tenant = state.tenant(&body.tenant).await?;
    let org = state.store.org_by_slug(&tenant, &body.org).await?;
    let ctx = org.ctx(&tenant);

    let mut tx = state.store.begin_org(&ctx).await?;
    let chain = state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &body.event)
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "seq": chain.seq,
            "hash": monaca_audit::hash_hex(&chain.hash),
        })),
    )
        .into_response())
}

/// The query of `GET /internal/audit`.
#[derive(Debug, Deserialize)]
pub struct TenantAuditQuery {
    /// Tenant slug.
    pub tenant: String,
    /// Optional §8.1 action filter.
    pub action: Option<String>,
    /// Page size, clamped to 1–200.
    pub limit: Option<i64>,
    /// Return events older than this `seq`.
    pub before: Option<i64>,
}

/// `GET /internal/audit` — the tenant chain, for the dev walk-through.
///
/// §8.1 puts tenant-level writes (email templates, sign-in experience, copy) on the tenant chain,
/// which has no management-API reader. The acceptance script proves those writes land here; a
/// production deployment would surface the same rows through an admin view.
pub async fn tenant_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TenantAuditQuery>,
) -> Result<Json<Value>, ApiError> {
    require_secret(&state, &headers)?;
    let tenant = state.tenant(&query.tenant).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    let mut tx = state.store.begin_tenant(&tenant).await?;
    let rows = state
        .store
        .audit_list(
            &mut *tx,
            "tenant",
            limit,
            query.before,
            None,
            None,
            query.action.as_deref(),
        )
        .await?;
    let head = state.store.audit_head(&mut *tx, "tenant").await?;
    tx.rollback().await?;

    let next = if rows.len() as i64 == limit {
        rows.last().map(|row| row.seq)
    } else {
        None
    };
    let items: Vec<Value> = rows.iter().map(crate::management::audit_json).collect();
    Ok(Json(json!({
        "items": items,
        "next": next,
        "head": { "seq": head.seq, "hash": monaca_audit::hash_hex(&head.hash) },
    })))
}

/// `GET /internal/tenants/{slug}/jwks`.
pub async fn tenant_jwks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_secret(&state, &headers)?;
    let tenant = state.tenant(&slug).await?;
    Ok(Json(json!({ "keys": state.jwks(&tenant).await? })))
}

/// `GET /internal/tenants/{slug}/issuer`.
pub async fn tenant_issuer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_secret(&state, &headers)?;
    let tenant = state.tenant(&slug).await?;
    Ok(Json(json!({
        "issuer": tenant.issuer,
        "audiences": [state.config.management_audience()],
    })))
}

/// The query of `GET /internal/mail`.
#[derive(Debug, Deserialize)]
pub struct MailQuery {
    /// Tenant slug.
    pub tenant: String,
    /// The recipient address to look up.
    pub to: String,
    /// Optional `sign_up` | `sign_in` | `password_reset` filter.
    pub purpose: Option<String>,
}

/// `GET /internal/mail` — the newest dev mail addressed to an address.
///
/// §6.3: a production deployment would hand these rows to a relay; in M0 and the acceptance run
/// they are read back here, which is what lets `scripts/e2e/skeleton.ts` finish a verification
/// flow without an SMTP server.
pub async fn latest_mail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MailQuery>,
) -> Result<Json<Value>, ApiError> {
    require_secret(&state, &headers)?;
    let tenant = state.tenant(&query.tenant).await?;
    let payload = state
        .store
        .outbox_mail_latest(&tenant, &query.to, query.purpose.as_deref())
        .await?
        .ok_or_else(|| ApiError::problem(kinds::NOT_FOUND, "no mail for that address"))?;
    Ok(Json(json!({
        "to": query.to,
        "topic": topics::MAIL,
        "payload": payload,
    })))
}

/// `GET /internal/health`.
pub async fn health(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_secret(&state, &headers)?;
    sqlx::query("SELECT 1")
        .execute(state.store.control())
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "status": "ok", "db": "ok" })))
}
