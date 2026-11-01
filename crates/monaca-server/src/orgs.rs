//! Organizations — §5.5 and §6.2.
//!
//! Creating an organization is the provisioning transaction of §5.5: a schema, a role, the org
//! migration set and the directory row. Archiving keeps all of that — and the org's audit chain —
//! but removes the org from every operational lookup, so `authorize` and the `/v1/orgs/{org}/…`
//! sub-resources stop resolving it. That is the reversible substitute for a hard delete, which
//! would destroy the chain the tenant is required to keep.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::{OrgRow, TenantRow};
use monaca_types::{EventId, OrgId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// The body of `POST /v1/orgs`.
#[derive(Debug, Deserialize)]
pub struct CreateOrgBody {
    /// The org slug: lowercase, digits and `-`, 2–31 characters.
    pub slug: String,
}

/// The body of `PATCH /v1/orgs/{org}`.
#[derive(Debug, Deserialize)]
pub struct UpdateOrgBody {
    /// `active` | `archived`.
    pub state: Option<String>,
}

/// `POST /v1/orgs` — provision an organization.
pub async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateOrgBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let slug = body.slug.trim();
    if !valid_slug(slug) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "slug must be 2-31 characters of lowercase letters, digits or `-`",
        ));
    }

    // The id is minted before the transaction so a retried request derives the same schema and
    // role names; the slug's uniqueness is what decides, and a duplicate is a 409 (§5.5).
    let org = state
        .store
        .provision_org(&tenant, slug, OrgId::new(), false)
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "slug": org.slug, "is_default": org.is_default }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append org.created audit event");
    }

    Ok((StatusCode::CREATED, Json(org_json(&org))).into_response())
}

/// `GET /v1/orgs` — every org in the tenant, archived included.
pub async fn list_orgs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.all_orgs(&tenant).await?;
    let items: Vec<Value> = rows.iter().map(org_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `GET /v1/orgs/{org}` — a slug or an `org_…` id, in either state.
pub async fn get_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let row = load_org(&state, &tenant, &org).await?;
    Ok(Json(org_json(&row)))
}

/// `PATCH /v1/orgs/{org}` — archive or reactivate.
pub async fn update_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<UpdateOrgBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let Some(target) = body.state.as_deref() else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "state must be `active` or `archived`",
        ));
    };
    if !matches!(target, "active" | "archived") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "state must be `active` or `archived`",
        ));
    }

    let row = load_org(&state, &tenant, &org).await?;
    if row.state == target {
        // Idempotent: an archive of an archived org is the same answer, and writes no second event.
        return Ok(Json(org_json(&row)));
    }
    if row.is_default && target == "archived" {
        // The default org is the fallback for every flow that names none — client_credentials
        // tokens included — so it has to keep serving.
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the tenant's default organization cannot be archived",
        ));
    }
    if !state
        .store
        .set_org_state(&tenant, row.org_id(), target)
        .await?
    {
        return Err(ApiError::not_found("organization"));
    }

    let action = if target == "archived" {
        "org.archived"
    } else {
        "org.reactivated"
    };
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: action.into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(row.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "slug": row.slug, "state": target }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append {action} audit event");
    }

    let updated = state.store.org_by_id(&tenant, row.org_id()).await?;
    Ok(Json(org_json(&updated)))
}

/// Resolve `{org}`: a typed `org_…` id, or a slug, in either state.
///
/// The lifecycle endpoints accept the id so an archived org — which no longer resolves by slug in
/// the operational lookups — stays addressable for the `PATCH` that reverses the archive.
async fn load_org(state: &AppState, tenant: &TenantRow, raw: &str) -> Result<OrgRow, ApiError> {
    if raw.starts_with("org_") {
        let id = OrgId::parse(raw)
            .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an organization id"))?;
        Ok(state.store.org_by_id(tenant, id).await?)
    } else {
        Ok(state.store.org_by_slug_any(tenant, raw).await?)
    }
}

fn org_json(row: &OrgRow) -> Value {
    json!({
        "id": row.org_id().to_typed_string(),
        "slug": row.slug,
        "state": row.state,
        "is_default": row.is_default,
        "created_at": ts(row.created_at),
    })
}

/// The slug rule the `tenant.organizations` CHECK constraint fixes: lowercase, digits and `-`,
/// 2–31 characters, and never leading with `-`.
fn valid_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=31).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slug_rule_matches_the_ddl_check() {
        for good in ["acme", "team-1", "a1", "x-"] {
            assert!(valid_slug(good), "{good} must be a valid slug");
        }
        for bad in [
            "",
            "a",
            "Acme",
            "acme_team",
            "-acme",
            "acme team",
            &"x".repeat(32),
        ] {
            assert!(!valid_slug(bad), "{bad} must be rejected");
        }
    }
}
