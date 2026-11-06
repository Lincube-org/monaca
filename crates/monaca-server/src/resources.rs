//! API resources — §6.2.
//!
//! A resource is an absolute `http(s)` indicator plus the scope names it defines. The authorize
//! endpoint refuses any non-standard scope a registered resource does not define, so an
//! application can never be issued a permission the resource owner did not publish.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_oidc::is_absolute_http_url;
use monaca_store::ApiResourceRow;
use monaca_types::{EventId, ResourceId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::clients::normalise_scopes;
use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, authorize_admin_read, ts};
use crate::state::AppState;

/// The body of `POST /v1/resources`.
#[derive(Debug, Deserialize)]
pub struct CreateResourceBody {
    /// Human-readable name.
    pub name: String,
    /// The resource indicator; the value `resource` carries on authorize.
    pub identifier: String,
    /// The scopes this resource defines.
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// The body of `PATCH /v1/resources/{resource}`; absent fields keep their value.
#[derive(Debug, Deserialize)]
pub struct UpdateResourceBody {
    /// New display name.
    pub name: Option<String>,
    /// Replacement scope set (an empty array clears it).
    pub scopes: Option<Vec<String>>,
}

/// `POST /v1/resources` — register an API resource.
pub async fn create_resource(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateResourceBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "name must be 1-80 characters",
        ));
    }
    let identifier = body.identifier.trim();
    if !is_absolute_http_url(identifier) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "identifier must be an absolute http(s) URL",
        ));
    }
    let scopes = normalise_scopes(&body.scopes)?;

    let row = state
        .store
        .create_api_resource(&tenant, name, identifier, &scopes)
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "resource.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "identifier": row.identifier, "scopes": row.scopes }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append resource.created audit event");
    }

    Ok((StatusCode::CREATED, Json(resource_json(&row))).into_response())
}

/// `GET /v1/resources` — every registered resource.
pub async fn list_resources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let rows = state.store.api_resources(&tenant).await?;
    let items: Vec<Value> = rows.iter().map(resource_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `GET /v1/resources/{resource}`.
pub async fn get_resource(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(resource): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let row = load_resource(&state, &tenant, &resource).await?;
    Ok(Json(resource_json(&row)))
}

/// `PATCH /v1/resources/{resource}` — rename it or replace its scope set.
pub async fn update_resource(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(resource): Path<String>,
    Json(body): Json<UpdateResourceBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if body.name.is_none() && body.scopes.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one field must be present",
        ));
    }
    let row = load_resource(&state, &tenant, &resource).await?;

    let name = match body.name.as_deref().map(str::trim) {
        Some(name) if name.is_empty() || name.len() > 80 => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "name must be 1-80 characters",
            ));
        }
        Some(name) => Some(name.to_owned()),
        None => None,
    };
    let scopes = body.scopes.as_deref().map(normalise_scopes).transpose()?;

    let updated = state
        .store
        .update_api_resource(&tenant, row.id, name.as_deref(), scopes.as_deref())
        .await?
        .ok_or_else(|| ApiError::not_found("resource"))?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "resource.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "identifier": updated.identifier, "scopes": updated.scopes }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append resource.updated audit event");
    }

    Ok(Json(resource_json(&updated)))
}

/// `DELETE /v1/resources/{resource}`.
pub async fn delete_resource(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(resource): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let row = load_resource(&state, &tenant, &resource).await?;
    if !state.store.delete_api_resource(&tenant, row.id).await? {
        return Err(ApiError::not_found("resource"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "resource.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "identifier": row.identifier }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append resource.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Resolve a `res_…` path segment, 404 when it is missing.
async fn load_resource(
    state: &AppState,
    tenant: &monaca_store::TenantRow,
    resource: &str,
) -> Result<ApiResourceRow, ApiError> {
    let id = ResourceId::parse(resource)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a resource id"))?;
    state
        .store
        .api_resource_by_id(tenant, id.uuid())
        .await?
        .ok_or_else(|| ApiError::not_found("resource"))
}

fn resource_json(row: &ApiResourceRow) -> Value {
    json!({
        "id": row.resource_id().to_typed_string(),
        "name": row.name,
        "identifier": row.identifier,
        "scopes": row.scopes,
        "created_at": ts(row.created_at),
    })
}
