//! The `/v1` management API — §6.2.
//!
//! Every handler takes a bearer token whose `aud` is `{base}/v1`, whose `scope` contains
//! `monaca:admin`, and which carries no `act` claim (§6.2). A resource outside the caller's tenant
//! is a 404, never a 403.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::hash_password;
use monaca_oidc::{is_absolute_http_url, valid_scope};
use monaca_store::{
    AccountRow, AgentKeyRow, AgentRow, GrantRow, RoleRow, SessionRow, SignInExperienceRow,
    TenantRow,
};
use monaca_types::{
    AccountId, AgentId, AgentKeyId, EventId, GrantId, RoleId, SessionId, TenantId, TypedId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::state::AppState;

/// Who called the management API.
///
/// §6.2 allows two callers: a tenant admin's user token (`sub = acc_…`) and the seeded automation
/// client (`sub = cli_…`). Keeping both in one type is what lets a handler write the correct actor
/// into the audit chain without branching on the token's shape.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    /// `acc_…` or `cli_…`, exactly as the token carried it.
    pub subject: String,
    /// The account row, when the caller is a user.
    pub account_id: Option<AccountId>,
    /// The uuid written to `created_by`: the account's, or the client row's.
    pub actor_uuid: Uuid,
}

impl AdminPrincipal {
    /// The outer actor for the audit chain.
    pub fn actor(&self) -> AuditActor {
        match self.account_id {
            Some(account_id) => AuditActor::account(account_id),
            None => AuditActor {
                actor_type: AuditActorType::Client,
                id: self.subject.clone(),
            },
        }
    }
}

/// The query string of the audit list.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Page size, default 50, max 200.
    pub limit: Option<i64>,
    /// Return rows with `seq < before`.
    pub before: Option<i64>,
    /// Filter by grant.
    pub grant_id: Option<String>,
    /// Filter by token `jti`.
    pub jti: Option<Uuid>,
    /// Filter by action.
    pub action: Option<String>,
}

/// `POST /v1/accounts` body.
#[derive(Debug, Deserialize)]
pub struct CreateAccountBody {
    /// Primary email.
    pub email: String,
    /// Display name.
    pub display_name: String,
    /// Initial password.
    pub password: String,
}

/// `POST /v1/orgs/{org}/members` body.
#[derive(Debug, Deserialize)]
pub struct AddMemberBody {
    /// The account to add.
    pub account_id: String,
    /// `owner` | `admin` | `member`.
    pub role: String,
}

/// `PATCH /v1/orgs/{org}/members/{account}` body.
#[derive(Debug, Deserialize)]
pub struct UpdateMemberBody {
    /// `owner` | `admin` | `member`.
    pub role: String,
}

/// `POST /v1/orgs/{org}/agents` body.
#[derive(Debug, Deserialize)]
pub struct CreateAgentBody {
    /// Unique name within the org.
    pub name: String,
    /// Free-form description.
    #[serde(default)]
    pub description: String,
    /// The account the agent acts for.
    pub owner_account_id: String,
}

/// `POST /v1/orgs/{org}/agents/{agent}/keys` body.
#[derive(Debug, Deserialize)]
pub struct RegisterKeyBody {
    /// An EC P-256 public JWK. A `d` member is rejected.
    pub public_jwk: Value,
    /// Must be `ES256`.
    pub alg: Option<String>,
    /// Client-chosen key id.
    pub kid: String,
}

/// `POST /v1/orgs/{org}/grants` body.
#[derive(Debug, Deserialize)]
pub struct CreateGrantBody {
    /// The agent that will receive delegated tokens.
    pub agent_id: String,
    /// The delegating account.
    pub account_id: String,
    /// Non-empty scope set.
    pub scopes: Vec<String>,
    /// The only `aud` the grant authorizes.
    pub resource: String,
    /// Optional expiry.
    pub expires_at: Option<String>,
}

/// Resolve and verify the caller's bearer token.
pub async fn authorize_admin(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "a bearer token is required"))?;

    let (_, claims) = monaca_crypto::decode_unverified(token)
        .map_err(|_| ApiError::problem(kinds::UNAUTHORIZED, "the token is malformed"))?;

    let tid = claims
        .get("tid")
        .and_then(Value::as_str)
        .and_then(|raw| TenantId::parse(raw).ok())
        .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "the token has no tenant"))?;

    let tenant = state.store.tenant_by_id(tid.uuid()).await?;
    let jwks = state.jwks(&tenant).await?;
    let claims = monaca_crypto::verify_jws_with_audience(
        token,
        &jwks,
        "at+jwt",
        &state.config.management_audience(),
    )
    .map_err(|err| ApiError::problem(kinds::UNAUTHORIZED, err.to_string()))?;

    if claims.get("act").is_some() {
        return Err(ApiError::problem(
            kinds::INSUFFICIENT_SCOPE,
            "an agent token may not call the management API",
        ));
    }
    let scopes: Vec<String> = claims
        .get("scope")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if !scopes.iter().any(|scope| scope == "monaca:admin") {
        return Err(ApiError::problem(
            kinds::INSUFFICIENT_SCOPE,
            "the token lacks monaca:admin",
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // A user token must belong to an account that is still a tenant admin; `monaca:admin` is only
    // minted for one, but a demotion has to take effect before the token expires.
    if let Ok(account_id) = AccountId::parse(sub) {
        let account = state
            .store
            .account_by_id(&tenant, account_id)
            .await?
            .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "the account is gone"))?;
        if !account.is_tenant_admin {
            return Err(ApiError::problem(
                kinds::INSUFFICIENT_SCOPE,
                "the account is not a tenant admin",
            ));
        }
        return Ok((
            tenant,
            AdminPrincipal {
                subject: sub.to_owned(),
                account_id: Some(account_id),
                actor_uuid: account_id.uuid(),
            },
        ));
    }

    // The automation client (§6.2). Its scope was checked above and `monaca:admin` is only
    // registered on that seeded client, so the client id is the actor.
    let client_id = monaca_types::ClientId::parse(sub).map_err(|_| {
        ApiError::problem(kinds::UNAUTHORIZED, "the token subject is not a principal")
    })?;
    let client = state
        .store
        .client_by_id(&tenant, client_id.uuid())
        .await?
        .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "the client is gone"))?;
    Ok((
        tenant,
        AdminPrincipal {
            subject: sub.to_owned(),
            account_id: None,
            actor_uuid: client.id,
        },
    ))
}

/// The query string of `GET /v1/accounts`.
#[derive(Debug, Deserialize)]
pub struct AccountsQuery {
    /// Case-insensitive substring of the email or display name.
    pub query: Option<String>,
    /// Page size, default 50, max 200.
    pub limit: Option<i64>,
}

/// `GET /v1/accounts` — search the tenant's accounts (§6.2).
pub async fn list_accounts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AccountsQuery>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let needle = query
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let rows = state.store.accounts(&tenant, needle, limit).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let roles = state.store.account_roles(&tenant, row.account_id()).await?;
        items.push(account_json(row, &roles));
    }
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/accounts`.
pub async fn create_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateAccountBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if body.email.trim().is_empty() || !body.email.contains('@') {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "email must be an address",
        ));
    }
    let phc = hash_password(body.password.clone(), state.argon)
        .await
        .map_err(ApiError::internal)?;
    let account = state
        .store
        .create_account(
            &tenant,
            AccountId::new(),
            body.email.trim(),
            body.display_name.trim(),
            Some(&phc),
            false,
            None,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "email": account.primary_email }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append account.created audit event");
    }

    Ok((StatusCode::CREATED, Json(account_json(&account, &[]))).into_response())
}

/// `GET /v1/accounts/{id}`.
pub async fn get_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let id = AccountId::parse(&id)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    let account = state
        .store
        .account_by_id(&tenant, id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;
    let roles = state
        .store
        .account_roles(&tenant, account.account_id())
        .await?;
    Ok(Json(account_json(&account, &roles)))
}

/// The body of `PATCH /v1/accounts/{id}`.
#[derive(Debug, Deserialize)]
pub struct UpdateAccountBody {
    /// `active` | `disabled`.
    pub state: String,
}

/// `PATCH /v1/accounts/{id}` — suspend or reactivate an account (§6.2).
///
/// Suspension is immediate: every live session and refresh token is revoked with the state
/// change, so the browser is signed out and no new access token can be minted. Repeating the
/// current state is a no-op that answers with the unchanged account.
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateAccountBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    if !matches!(body.state.as_str(), "active" | "disabled") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "state must be `active` or `disabled`",
        ));
    }
    let account = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;

    if account.state != body.state {
        if !state
            .store
            .set_account_state(&tenant, account_id, &body.state)
            .await?
        {
            return Err(ApiError::not_found("account"));
        }
        if body.state == "disabled" {
            state
                .store
                .revoke_account_sessions(&tenant, account_id)
                .await?;
            state
                .store
                .revoke_account_refresh_tokens(&tenant, account_id)
                .await?;
        }

        let event = AuditEvent {
            id: EventId::new(),
            at: state.now(),
            action: if body.state == "disabled" {
                "account.suspended".into()
            } else {
                "account.reactivated".into()
            },
            actor_chain: vec![admin.actor()],
            subject: AuditSubject {
                subject_type: AuditActorType::Account,
                id: Some(account.account_id().to_typed_string()),
            },
            decision: AuditDecision::Allow,
            grant_id: None,
            jti: None,
            payload: json!({ "email": account.primary_email }),
        };
        if let Err(err) = state.audit_tenant(&tenant, &event).await {
            tracing::warn!(%err, "could not append the account state audit event");
        }
    }

    let updated = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;
    let roles = state.store.account_roles(&tenant, account_id).await?;
    Ok(Json(account_json(&updated, &roles)))
}

/// The body of `PATCH /v1/sign-in-experience`; absent fields keep their value.
#[derive(Debug, Deserialize)]
pub struct UpdateSignInExperienceBody {
    /// Whether self-service registration is offered.
    pub sign_up_enabled: Option<bool>,
    /// Whether the password form is offered.
    pub password_sign_in_enabled: Option<bool>,
    /// Whether emailed codes and links are offered.
    pub email_code_sign_in_enabled: Option<bool>,
}

/// `GET /v1/sign-in-experience` — the tenant's hosted sign-in switches (§6.2).
pub async fn get_sign_in_experience(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    Ok(Json(sign_in_experience_json(&experience)))
}

/// `PATCH /v1/sign-in-experience` — switch hosted sign-in methods on or off (§6.2).
///
/// At least one first-factor method — the password form or emailed codes — must stay enabled:
/// a tenant with neither has no way to sign in at all, which is a misconfiguration rather than a
/// choice. The resulting state is checked before the write, so a rejected patch changes nothing.
pub async fn update_sign_in_experience(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateSignInExperienceBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if body.sign_up_enabled.is_none()
        && body.password_sign_in_enabled.is_none()
        && body.email_code_sign_in_enabled.is_none()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one switch must be present",
        ));
    }

    let current = state.store.sign_in_experience(&tenant).await?;
    let password = body
        .password_sign_in_enabled
        .unwrap_or(current.password_sign_in_enabled);
    let email_code = body
        .email_code_sign_in_enabled
        .unwrap_or(current.email_code_sign_in_enabled);
    if !password && !email_code {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "password sign-in or email code sign-in must stay enabled",
        ));
    }

    let experience = state
        .store
        .update_sign_in_experience(
            &tenant,
            body.sign_up_enabled,
            body.password_sign_in_enabled,
            body.email_code_sign_in_enabled,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sign_in_experience.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "sign_up_enabled": experience.sign_up_enabled,
            "password_sign_in_enabled": experience.password_sign_in_enabled,
            "email_code_sign_in_enabled": experience.email_code_sign_in_enabled,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sign_in_experience.updated audit event");
    }

    Ok(Json(sign_in_experience_json(&experience)))
}

fn sign_in_experience_json(experience: &SignInExperienceRow) -> Value {
    json!({
        "sign_up_enabled": experience.sign_up_enabled,
        "password_sign_in_enabled": experience.password_sign_in_enabled,
        "email_code_sign_in_enabled": experience.email_code_sign_in_enabled,
        "updated_at": ts(experience.updated_at),
    })
}

/// The body of `POST /v1/roles`.
#[derive(Debug, Deserialize)]
pub struct CreateRoleBody {
    /// The unique name the id_token carries.
    pub name: String,
    /// Free-form description.
    #[serde(default)]
    pub description: String,
    /// Permission scopes the role grants.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// `POST /v1/roles` — define a role.
pub async fn create_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateRoleBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "name must be 1-80 characters",
        ));
    }
    let mut permissions: Vec<String> = Vec::new();
    for permission in &body.permissions {
        let permission = permission.trim();
        if !valid_scope(permission) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "permissions must match the scope grammar",
            ));
        }
        if !permissions.iter().any(|existing| existing == permission) {
            permissions.push(permission.to_owned());
        }
    }

    let role = state
        .store
        .create_role(&tenant, name, body.description.trim(), &permissions)
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "role.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "name": role.name }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append role.created audit event");
    }

    Ok((StatusCode::CREATED, Json(role_json(&role))).into_response())
}

/// `GET /v1/roles` — every role the tenant defined.
pub async fn list_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.roles(&tenant).await?;
    let items: Vec<Value> = rows.iter().map(role_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /v1/roles/{role}` — remove a role and every assignment of it.
pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    Path(role): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let role_id = RoleId::parse(&role)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a role id"))?;
    let Some(row) = state.store.role_by_id(&tenant, role_id.uuid()).await? else {
        return Err(ApiError::not_found("role"));
    };
    if !state.store.delete_role(&tenant, role_id.uuid()).await? {
        return Err(ApiError::not_found("role"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "role.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "name": row.name }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append role.deleted audit event");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/accounts/{id}/roles/{role}` — assign a role; repeating it is a no-op.
pub async fn assign_role(
    State(state): State<Arc<AppState>>,
    Path((account, role)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let account_id = AccountId::parse(&account)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    let role_id = RoleId::parse(&role)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a role id"))?;
    if state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("account"));
    }
    if state
        .store
        .role_by_id(&tenant, role_id.uuid())
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("role"));
    }
    state
        .store
        .assign_role(&tenant, account_id, role_id.uuid())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/accounts/{id}/roles/{role}` — remove an assignment.
pub async fn unassign_role(
    State(state): State<Arc<AppState>>,
    Path((account, role)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let account_id = AccountId::parse(&account)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    let role_id = RoleId::parse(&role)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a role id"))?;
    if !state
        .store
        .unassign_role(&tenant, account_id, role_id.uuid())
        .await?
    {
        return Err(ApiError::not_found("role assignment"));
    }
    Ok(StatusCode::NO_CONTENT)
}

fn role_json(role: &RoleRow) -> Value {
    json!({
        "id": role.role_id().to_typed_string(),
        "name": role.name,
        "description": role.description,
        "permissions": role.permissions,
        "created_at": ts(role.created_at),
    })
}

/// `GET /v1/accounts/{id}/sessions`.
pub async fn list_account_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;

    let sessions = state.store.list_sessions(&tenant, account_id).await?;
    let items: Vec<Value> = sessions.iter().map(session_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /v1/accounts/{id}/sessions/{session}`.
pub async fn revoke_account_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, session)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    let session_id = SessionId::parse(&session)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a session id"))?;

    // A session may only be revoked through the account it belongs to.
    let owned = state
        .store
        .session_by_id(&tenant, session_id.uuid())
        .await?
        .filter(|row| row.account_id == account_id.uuid())
        .ok_or_else(|| ApiError::not_found("session"))?;
    if !state.store.revoke_session(&tenant, owned.id).await? {
        return Err(ApiError::not_found("session"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "session.revoked".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Session,
            id: Some(session_id.to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({ "account_id": account_id.to_typed_string() }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append session.revoked audit event");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/accounts/{id}/sessions` — revoke every live session of the account.
pub async fn revoke_account_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;

    let revoked = state
        .store
        .revoke_account_sessions(&tenant, account_id)
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "session.revoked_all".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({ "revoked": revoked }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append session.revoked_all audit event");
    }
    Ok(Json(json!({ "revoked": revoked })))
}

pub(crate) fn parse_account(raw: &str) -> Result<AccountId, ApiError> {
    AccountId::parse(raw)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))
}

/// `POST /v1/orgs/{org}/members`.
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<AddMemberBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let account_id = AccountId::parse(&body.account_id)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    if !matches!(body.role.as_str(), "owner" | "admin" | "member") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "role must be owner, admin or member",
        ));
    }
    if state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("account"));
    }

    let mut tx = state.store.begin_org(&ctx).await?;
    state
        .store
        .org_member_add(&mut *tx, account_id, &body.role)
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.member.added".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "role": body.role }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "account_id": account_id.to_typed_string(),
            "org": org.org_id().to_typed_string(),
            "role": body.role,
        })),
    )
        .into_response())
}

/// `GET /v1/orgs/{org}/members`.
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let mut tx = state.store.begin_org(&ctx).await?;
    let members = state.store.org_members(&mut *tx).await?;
    tx.rollback().await?;

    let items: Vec<Value> = members
        .into_iter()
        .map(|(account_id, email, role)| {
            json!({ "account_id": AccountId::from_uuid(account_id).to_typed_string(), "email": email, "role": role })
        })
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `PATCH /v1/orgs/{org}/members/{account}` — change one member's role.
///
/// The role set is the same one `add_member` accepts (§6.2). Repeating the member's current role is
/// a no-op and writes no audit event, so a retried call cannot inflate the chain.
pub async fn update_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, account)): Path<(String, String)>,
    Json(body): Json<UpdateMemberBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let account_id = parse_account(&account)?;
    if !matches!(body.role.as_str(), "owner" | "admin" | "member") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "role must be owner, admin or member",
        ));
    }

    let mut tx = state.store.begin_org(&ctx).await?;
    let previous = state.store.org_member_role(&mut *tx, account_id).await?;
    let Some(previous) = previous else {
        tx.rollback().await?;
        return Err(ApiError::not_found("member"));
    };
    if previous != body.role {
        state
            .store
            .org_member_set_role(&mut *tx, account_id, &body.role)
            .await?;
        let event = AuditEvent {
            id: EventId::new(),
            at: state.now(),
            action: "org.member.role_changed".into(),
            actor_chain: vec![admin.actor()],
            subject: AuditSubject {
                subject_type: AuditActorType::Account,
                id: Some(account_id.to_typed_string()),
            },
            decision: AuditDecision::Allow,
            grant_id: None,
            jti: None,
            payload: json!({ "org": org.slug, "from": previous, "to": body.role }),
        };
        state
            .store
            .audit_append(&mut *tx, &ctx.schema_name, &event)
            .await?;
    }
    tx.commit().await?;

    Ok(Json(json!({
        "account_id": account_id.to_typed_string(),
        "org": org.org_id().to_typed_string(),
        "role": body.role,
    })))
}

/// `DELETE /v1/orgs/{org}/members/{account}` — remove a member, keeping the account.
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, account)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let account_id = parse_account(&account)?;

    let mut tx = state.store.begin_org(&ctx).await?;
    if !state.store.org_member_remove(&mut *tx, account_id).await? {
        tx.rollback().await?;
        return Err(ApiError::not_found("member"));
    }
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.member.removed".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/orgs/{org}/agents`.
pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let mut tx = state.store.begin_org(&ctx).await?;
    let agents = state.store.agents(&mut *tx).await?;
    let mut items = Vec::with_capacity(agents.len());
    for agent in agents {
        let keys = state.store.agent_keys(&mut *tx, agent.agent_id()).await?;
        items.push(agent_json(&org, &agent, &keys));
    }
    tx.rollback().await?;
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/orgs/{org}/agents`.
pub async fn create_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<CreateAgentBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let owner = AccountId::parse(&body.owner_account_id)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    if body.name.trim().is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "name is required",
        ));
    }

    let mut tx = state.store.begin_org(&ctx).await?;
    if state
        .store
        .org_member_role(&mut *tx, owner)
        .await?
        .is_none()
    {
        tx.rollback().await?;
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "owner_account_id is not a member of the org",
        ));
    }
    tx.rollback().await?;

    let agent = state
        .store
        .create_agent(
            &ctx,
            AgentId::new(),
            body.name.trim(),
            &body.description,
            owner,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "agent.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Agent,
            id: Some(agent.agent_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "name": agent.name, "owner_account_id": owner.to_typed_string() }),
    };
    if let Err(err) = state.audit_org(&ctx, &event).await {
        tracing::warn!(%err, "could not append agent.created audit event");
    }

    Ok((StatusCode::CREATED, Json(agent_json(&org, &agent, &[]))).into_response())
}

/// `POST /v1/orgs/{org}/agents/{agent}/keys`.
pub async fn register_agent_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, agent)): Path<(String, String)>,
    Json(body): Json<RegisterKeyBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let agent_id = AgentId::parse(&agent)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an agent id"))?;

    validate_public_jwk(&body.public_jwk)?;
    let fingerprint = jwk_thumbprint(&body.public_jwk)?;

    // Stamp the server-side `kid` into the stored JWK. The assertion's header names the key by
    // `kid`, and a client that exports a bare WebCrypto JWK has no reason to have put one there;
    // without this the key would be unreachable at verification time.
    let mut public_jwk = body.public_jwk.clone();
    let object = public_jwk
        .as_object_mut()
        .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "public_jwk must be an object"))?;
    object.insert("kid".to_owned(), Value::String(body.kid.clone()));
    object
        .entry("alg".to_owned())
        .or_insert_with(|| Value::String("ES256".to_owned()));
    object
        .entry("use".to_owned())
        .or_insert_with(|| Value::String("sig".to_owned()));

    let mut tx = state.store.begin_org(&ctx).await?;
    let exists = state.store.agent(&mut *tx, agent_id).await?;
    if exists.is_none() {
        tx.rollback().await?;
        return Err(ApiError::not_found("agent"));
    }
    let key = state
        .store
        .insert_agent_key(
            &mut *tx,
            AgentKeyId::new().uuid(),
            agent_id,
            &public_jwk,
            &body.kid,
            &fingerprint,
        )
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "agent.key.registered".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::AgentKey,
            id: Some(AgentKeyId::from_uuid(key.id).to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "agent_id": agent_id.to_typed_string(), "kid": body.kid }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": AgentKeyId::from_uuid(key.id).to_typed_string(),
            "kid": key.kid,
            "fingerprint": key.fingerprint,
            "created_at": ts(key.created_at),
        })),
    )
        .into_response())
}

/// `DELETE /v1/orgs/{org}/agents/{agent}/keys/{key}`.
pub async fn revoke_agent_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, agent, key)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let agent_id = AgentId::parse(&agent)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an agent id"))?;
    let key_id = AgentKeyId::parse(&key)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a key id"))?;

    let mut tx = state.store.begin_org(&ctx).await?;
    let revoked = state
        .store
        .revoke_agent_key(&mut *tx, agent_id, key_id.uuid())
        .await?;
    if !revoked {
        tx.rollback().await?;
        return Err(ApiError::not_found("agent key"));
    }
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "agent.key.revoked".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::AgentKey,
            id: Some(key_id.to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({ "agent_id": agent_id.to_typed_string() }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/orgs/{org}/grants`.
pub async fn list_grants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let mut tx = state.store.begin_org(&ctx).await?;
    let grants = state.store.grants(&mut *tx).await?;
    tx.rollback().await?;
    let items: Vec<Value> = grants.iter().map(|grant| grant_json(&org, grant)).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/orgs/{org}/grants`.
pub async fn create_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<CreateGrantBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);

    let agent_id = AgentId::parse(&body.agent_id)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an agent id"))?;
    let account_id = AccountId::parse(&body.account_id)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    if body.scopes.is_empty() || !body.scopes.iter().all(|scope| valid_scope(scope)) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "scopes must be non-empty and match the scope grammar",
        ));
    }
    if !is_absolute_http_url(&body.resource) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "resource must be an absolute http(s) URL",
        ));
    }
    let expires_at = match body.expires_at.as_deref() {
        Some(raw) => Some(OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| {
            ApiError::problem(kinds::INVALID_REQUEST, "expires_at is not RFC 3339")
        })?),
        None => None,
    };

    let mut tx = state.store.begin_org(&ctx).await?;
    if state.store.agent(&mut *tx, agent_id).await?.is_none() {
        tx.rollback().await?;
        return Err(ApiError::not_found("agent"));
    }
    if state
        .store
        .org_member_role(&mut *tx, account_id)
        .await?
        .is_none()
    {
        tx.rollback().await?;
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "account_id is not a member of the org",
        ));
    }

    let grant = state
        .store
        .create_grant(
            &mut *tx,
            GrantId::new(),
            agent_id,
            account_id,
            &body.scopes,
            &body.resource,
            &json!({}),
            expires_at,
            admin.actor_uuid,
        )
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "grant.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Grant,
            id: Some(grant.grant_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: Some(grant.grant_id()),
        jti: None,
        payload: json!({
            "agent_id": agent_id.to_typed_string(),
            "account_id": account_id.to_typed_string(),
            "scopes": grant.scopes,
            "resource": grant.resource,
        }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(grant_json(&org, &grant))).into_response())
}

/// `DELETE /v1/orgs/{org}/grants/{grant}`.
pub async fn revoke_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, grant)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let grant_id = GrantId::parse(&grant)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a grant id"))?;

    let mut tx = state.store.begin_org(&ctx).await?;
    let revoked = state.store.revoke_grant(&mut *tx, grant_id).await?;
    if !revoked {
        tx.rollback().await?;
        return Err(ApiError::not_found("grant"));
    }
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "grant.revoked".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Grant,
            id: Some(grant_id.to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: Some(grant_id),
        jti: None,
        payload: json!({ "org": org.slug }),
    };
    state
        .store
        .audit_append(&mut *tx, &ctx.schema_name, &event)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/orgs/{org}/audit`.
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let grant_id = match query.grant_id.as_deref() {
        Some(raw) => Some(
            GrantId::parse(raw)
                .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a grant id"))?
                .uuid(),
        ),
        None => None,
    };

    let mut tx = state.store.begin_org(&ctx).await?;
    let rows = state
        .store
        .audit_list(
            &mut *tx,
            &ctx.schema_name,
            limit,
            query.before,
            grant_id,
            query.jti,
            query.action.as_deref(),
        )
        .await?;
    let head = state.store.audit_head(&mut *tx, &ctx.schema_name).await?;
    tx.rollback().await?;

    let next = if rows.len() as i64 == limit {
        rows.last().map(|row| row.seq)
    } else {
        None
    };
    let items: Vec<Value> = rows.iter().map(audit_json).collect();
    Ok(Json(json!({
        "items": items,
        "next": next,
        "head": { "seq": head.seq, "hash": monaca_audit::hash_hex(&head.hash) },
    })))
}

/// `GET /v1/orgs/{org}/audit/verify`.
pub async fn verify_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Query(bounds): Query<AuditBounds>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let ctx = org.ctx(&tenant);
    let from = bounds.from.unwrap_or(1).max(1);

    let mut tx = state.store.begin_org(&ctx).await?;
    let report = state
        .store
        .audit_verify(&mut *tx, &ctx.schema_name, from, bounds.to)
        .await?;
    tx.rollback().await?;
    Ok(Json(report.to_json()))
}

/// The `from`/`to` bounds of the verify endpoint.
#[derive(Debug, Deserialize)]
pub struct AuditBounds {
    /// First `seq` to check.
    pub from: Option<i64>,
    /// Last `seq` to check.
    pub to: Option<i64>,
}

fn account_json(account: &AccountRow, roles: &[RoleRow]) -> Value {
    json!({
        "id": account.account_id().to_typed_string(),
        "email": account.primary_email,
        "display_name": account.display_name,
        "state": account.state,
        "created_at": ts(account.created_at),
        "roles": roles
            .iter()
            .map(|role| json!({ "id": role.role_id().to_typed_string(), "name": role.name }))
            .collect::<Vec<_>>(),
    })
}

fn session_json(session: &SessionRow) -> Value {
    json!({
        "id": session.session_id().to_typed_string(),
        "account_id": AccountId::from_uuid(session.account_id).to_typed_string(),
        "client_id": session
            .client_id
            .map(|id| monaca_types::ClientId::from_uuid(id).to_typed_string()),
        "issued_at": ts(session.issued_at),
        "expires_at": ts(session.expires_at),
        "last_seen_at": ts(session.last_seen_at),
        "user_agent": session.user_agent,
    })
}

fn agent_json(org: &monaca_store::OrgRow, agent: &AgentRow, keys: &[AgentKeyRow]) -> Value {
    let keys: Vec<Value> = keys
        .iter()
        .map(|key| {
            json!({
                "id": AgentKeyId::from_uuid(key.id).to_typed_string(),
                "kid": key.kid,
                "fingerprint": key.fingerprint,
                "created_at": ts(key.created_at),
                "revoked_at": key.revoked_at.map(ts),
            })
        })
        .collect();
    json!({
        "id": agent.agent_id().to_typed_string(),
        "org": org.slug,
        "name": agent.name,
        "description": agent.description,
        "owner_account_id": AccountId::from_uuid(agent.owner_account_id).to_typed_string(),
        "state": agent.state,
        "keys": keys,
        "created_at": ts(agent.created_at),
    })
}

fn grant_json(org: &monaca_store::OrgRow, grant: &GrantRow) -> Value {
    json!({
        "id": grant.grant_id().to_typed_string(),
        "org": org.slug,
        "agent_id": AgentId::from_uuid(grant.agent_id).to_typed_string(),
        "account_id": AccountId::from_uuid(grant.account_id).to_typed_string(),
        "scopes": grant.scopes,
        "resource": grant.resource,
        "constraints": grant.constraints,
        "expires_at": grant.expires_at.map(ts),
        "revoked_at": grant.revoked_at.map(ts),
        "created_by": AccountId::from_uuid(grant.created_by).to_typed_string(),
        "created_at": ts(grant.created_at),
    })
}

fn audit_json(row: &monaca_store::AuditRow) -> Value {
    // `subject_ref` is the exact string that was hashed; the uuid column exists for indexing and
    // for a future filter, not as the source of truth.
    let subject_id = row.subject_ref.clone();
    json!({
        "seq": row.seq,
        "id": EventId::from_uuid(row.id).to_typed_string(),
        "at": ts(row.at),
        "action": row.action,
        "actor_chain": row.actor_chain,
        "subject": { "type": row.subject_type, "id": subject_id },
        "decision": row.decision,
        "grant_id": row.grant_id.map(|id| GrantId::from_uuid(id).to_typed_string()),
        "jti": row.jti,
        "payload": row.payload,
        "prev_hash": hex::encode(&row.prev_hash),
        "hash": hex::encode(&row.hash),
    })
}

/// RFC 3339 UTC.
pub fn ts(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_else(|_| value.to_string())
}

/// Reject a JWK that is not a usable EC P-256 public key — §6.2.
fn validate_public_jwk(jwk: &Value) -> Result<(), ApiError> {
    if jwk.get("d").is_some() {
        return Err(ApiError::problem(
            kinds::PRIVATE_KEY_SUBMITTED,
            "a JWK with a private component is never accepted",
        ));
    }
    let field = |name: &str| jwk.get(name).and_then(Value::as_str).unwrap_or_default();
    if field("kty") != "EC"
        || field("crv") != "P-256"
        || field("x").is_empty()
        || field("y").is_empty()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "public_jwk must be an EC P-256 public key with x and y",
        ));
    }
    Ok(())
}

/// RFC 7638 thumbprint: SHA-256 hex of the canonical `{crv,kty,x,y}` object.
fn jwk_thumbprint(jwk: &Value) -> Result<String, ApiError> {
    let field = |name: &str| {
        jwk.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "JWK is missing a member"))
    };
    // JCS sorts members lexicographically; the required members are exactly these four.
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        field("crv")?,
        field("kty")?,
        field("x")?,
        field("y")?
    );
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}
