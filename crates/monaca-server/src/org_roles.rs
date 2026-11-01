//! Organization roles — §5.7 and §6.2.
//!
//! An org role is a named set of scopes, defined inside one organization. A member may hold any
//! number of them; the scopes they grant apply only while signing into that org, unlike the tenant
//! roles of `/v1/roles`, which apply everywhere. `members.role` stays the membership rank
//! (owner/admin/member) and is not a permission grant.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::OrgRoleRow;
use monaca_types::{AccountId, EventId, RoleId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::clients::normalise_scopes;
use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, parse_account, ts};
use crate::state::AppState;

/// The body of `POST /v1/orgs/{org}/roles`.
#[derive(Debug, Deserialize)]
pub struct CreateOrgRoleBody {
    /// Unique name within the org.
    pub name: String,
    /// Free-form description.
    #[serde(default)]
    pub description: String,
    /// The scopes this role grants inside the org.
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// The body of `PATCH /v1/orgs/{org}/roles/{role}`; absent fields keep their value.
#[derive(Debug, Deserialize)]
pub struct UpdateOrgRoleBody {
    /// New unique name.
    pub name: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// Replacement scope set (an empty array clears it).
    pub scopes: Option<Vec<String>>,
}

/// The body of `POST /v1/orgs/{org}/members/{account}/roles`.
#[derive(Debug, Deserialize)]
pub struct AssignOrgRoleBody {
    /// The `rol_…` id of a role defined in this org.
    pub role_id: String,
}

/// `POST /v1/orgs/{org}/roles` — define an org role.
pub async fn create_org_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<CreateOrgRoleBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "name must be 1-80 characters",
        ));
    }
    let scopes = normalise_scopes(&body.scopes)?;

    let mut tx = state.store.begin_org(&ctx).await?;
    let role = state
        .store
        .create_org_role(
            &mut *tx,
            RoleId::new().uuid(),
            name,
            body.description.trim(),
            &scopes,
        )
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.role.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "role": role.name, "scopes": role.scopes }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(role_json(&role))).into_response())
}

/// `GET /v1/orgs/{org}/roles` — every role defined in the org.
pub async fn list_org_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let mut tx = state.store.begin_org(&ctx).await?;
    let rows = state.store.org_roles(&mut *tx).await?;
    tx.rollback().await?;
    let items: Vec<Value> = rows.iter().map(role_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `PATCH /v1/orgs/{org}/roles/{role}` — rename it, describe it or replace its scopes.
pub async fn update_org_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, role)): Path<(String, String)>,
    Json(body): Json<UpdateOrgRoleBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let role_id = parse_role(&role)?;
    if body.name.is_none() && body.description.is_none() && body.scopes.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one field must be present",
        ));
    }
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

    let mut tx = state.store.begin_org(&ctx).await?;
    let Some(updated) = state
        .store
        .update_org_role(
            &mut *tx,
            role_id.uuid(),
            name.as_deref(),
            body.description.as_deref().map(str::trim),
            scopes.as_deref(),
        )
        .await?
    else {
        tx.rollback().await?;
        return Err(ApiError::not_found("role"));
    };
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.role.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "role": updated.name, "scopes": updated.scopes }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok(Json(role_json(&updated)))
}

/// `DELETE /v1/orgs/{org}/roles/{role}` — remove it and every assignment of it.
pub async fn delete_org_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, role)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let role_id = parse_role(&role)?;

    let mut tx = state.store.begin_org(&ctx).await?;
    let Some(row) = state.store.org_role_by_id(&mut *tx, role_id.uuid()).await? else {
        tx.rollback().await?;
        return Err(ApiError::not_found("role"));
    };
    if !state
        .store
        .delete_org_role(&mut *tx, role_id.uuid())
        .await?
    {
        tx.rollback().await?;
        return Err(ApiError::not_found("role"));
    }
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.role.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "role": row.name }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/orgs/{org}/members/{account}/roles`.
pub async fn list_member_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, account)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let account_id = parse_account(&account)?;

    let mut tx = state.store.begin_org(&ctx).await?;
    if state
        .store
        .org_member_role(&mut *tx, account_id)
        .await?
        .is_none()
    {
        tx.rollback().await?;
        return Err(ApiError::not_found("member"));
    }
    let rows = state.store.org_member_roles(&mut *tx, account_id).await?;
    tx.rollback().await?;

    let items: Vec<Value> = rows.iter().map(role_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/orgs/{org}/members/{account}/roles` — assign a role; repeating it is a no-op.
pub async fn assign_member_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, account)): Path<(String, String)>,
    Json(body): Json<AssignOrgRoleBody>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let account_id = parse_account(&account)?;
    let role_id = parse_role(&body.role_id)?;

    let mut tx = state.store.begin_org(&ctx).await?;
    if state
        .store
        .org_member_role(&mut *tx, account_id)
        .await?
        .is_none()
    {
        tx.rollback().await?;
        return Err(ApiError::not_found("member"));
    }
    let Some(role) = state.store.org_role_by_id(&mut *tx, role_id.uuid()).await? else {
        tx.rollback().await?;
        return Err(ApiError::not_found("role"));
    };
    let before = state.store.org_member_roles(&mut *tx, account_id).await?;
    let inserted = state
        .store
        .assign_org_role(&mut *tx, account_id, role_id.uuid())
        .await?;
    if inserted {
        let after = state.store.org_member_roles(&mut *tx, account_id).await?;
        let event = roles_changed_event(
            state.now(),
            admin.actor(),
            account_id,
            &org,
            &role_names(&before),
            &role_names(&after),
        );
        state
            .store
            .audit_append(&mut *tx, &ctx.schema_name, &event)
            .await?;
    }
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/orgs/{org}/members/{account}/roles/{role}` — remove an assignment.
pub async fn unassign_member_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, account, role)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let account_id = parse_account(&account)?;
    let role_id = parse_role(&role)?;

    let mut tx = state.store.begin_org(&ctx).await?;
    if state
        .store
        .org_member_role(&mut *tx, account_id)
        .await?
        .is_none()
    {
        tx.rollback().await?;
        return Err(ApiError::not_found("member"));
    }
    let before = state.store.org_member_roles(&mut *tx, account_id).await?;
    if !state
        .store
        .unassign_org_role(&mut *tx, account_id, role_id.uuid())
        .await?
    {
        tx.rollback().await?;
        return Err(ApiError::not_found("role assignment"));
    }
    let after = state.store.org_member_roles(&mut *tx, account_id).await?;
    let event = roles_changed_event(
        state.now(),
        admin.actor(),
        account_id,
        &org,
        &role_names(&before),
        &role_names(&after),
    );
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

fn parse_role(raw: &str) -> Result<RoleId, ApiError> {
    RoleId::parse(raw).map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a role id"))
}

fn role_names(roles: &[OrgRoleRow]) -> Vec<String> {
    roles.iter().map(|role| role.name.clone()).collect()
}

fn roles_changed_event(
    at: time::OffsetDateTime,
    actor: AuditActor,
    account_id: AccountId,
    org: &monaca_store::OrgRow,
    before: &[String],
    after: &[String],
) -> AuditEvent {
    AuditEvent {
        id: EventId::new(),
        at,
        action: "org.member.roles_changed".into(),
        actor_chain: vec![actor],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "from": before, "to": after }),
    }
}

fn role_json(role: &OrgRoleRow) -> Value {
    json!({
        "id": role.role_id().to_typed_string(),
        "name": role.name,
        "description": role.description,
        "scopes": role.scopes,
        "created_at": ts(role.created_at),
    })
}
