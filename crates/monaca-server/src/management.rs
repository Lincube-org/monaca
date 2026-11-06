//! The `/v1` management API — §6.2.
//!
//! Every handler takes a bearer token whose `aud` is `{base}/v1`, whose `scope` contains
//! `monaca:admin`, and which carries no `act` claim (§6.2). A resource outside the caller's tenant
//! is a 404, never a 403.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{hash_password, seal};
use monaca_oidc::{is_absolute_http_url, valid_scope};
use monaca_store::{
    AccountRow, AgentKeyRow, AgentRow, AuditFilter, BrandingRow, GrantRow, RateLimitRow, RoleRow,
    SessionRow, SignInExperienceRow, SignInGuardrailsPatch, TenantRow, UsageSummaryRow,
};
use monaca_types::{
    AccountId, AgentId, AgentKeyId, EventId, GrantId, PasskeyId, RoleId, SessionId, TenantId,
    TypedId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::schemas::{
    AccountDetailView, AccountList, AccountView, RoleList, RoleRef, RoleView, SessionList,
    SessionView,
};
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
    /// The strongest management tier the caller currently holds.
    pub access: ManagementAccess,
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

/// The query string of `GET /v1/audit` (§6.2).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct TenantAuditQuery {
    /// Page size, default 50; values above 200 are clamped to 200.
    pub limit: Option<i64>,
    /// Return rows with `seq < before`.
    pub before: Option<i64>,
    /// Exact action, such as `account.suspended`.
    pub action: Option<String>,
    /// Anchored action prefix, such as `account.` or `message_template.`.
    pub action_prefix: Option<String>,
    /// A typed actor id, such as `acc_…`, `cli_…` or `agt_…`.
    pub actor: Option<String>,
    /// The exact `subject.id` string.
    pub subject: Option<String>,
    /// Inclusive lower time bound, RFC 3339.
    pub from: Option<String>,
    /// Exclusive upper time bound, RFC 3339.
    pub to: Option<String>,
}

/// The account-count half of `GET /v1/usage` (§6.2).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UsageUsersView {
    /// Existing accounts, from the incremental counter.
    pub total: i64,
    /// The configured cap; `null` is unlimited.
    pub quota: Option<i64>,
    /// `quota - total`; `null` when unlimited.
    pub remaining: Option<i64>,
    /// Always `reject`: a creation past the cap is refused, not merely warned.
    pub enforcement: &'static str,
}

/// The UTC-day half of `GET /v1/usage`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UsageDailyView {
    /// The UTC date the counters cover.
    pub date: String,
    /// Distinct accounts that signed in that day.
    pub active_accounts: i64,
    /// Sign-ins recorded that day.
    pub logins: i64,
    /// `UTC`; the day boundary is not tenant-configurable.
    pub timezone: &'static str,
}

/// `GET /v1/usage` — the tenant's usage and quota from one snapshot.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UsageView {
    /// Accounts and their cap.
    pub users: UsageUsersView,
    /// Today's activity.
    pub daily: UsageDailyView,
    /// When the quota last changed.
    pub updated_at: String,
}

/// The body of `PATCH /v1/usage`; `{"max_accounts": null}` clears the cap.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateUsageBody {
    /// Absent means "nothing to update"; `null` clears, a number sets the cap.
    #[serde(default, deserialize_with = "deserialize_optional_cap")]
    pub max_accounts: Option<Option<i64>>,
}

/// Distinguish an absent `max_accounts` (`None`) from an explicit `null` (`Some(None)`) — plain
/// `Option<Option<i64>>` collapses both to `None`, which made clearing the cap a 400.
fn deserialize_optional_cap<'de, D>(deserializer: D) -> Result<Option<Option<i64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<i64>::deserialize(deserializer)?))
}

/// `POST /v1/accounts` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
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

/// How much of the management surface a caller may use (§6.2).
///
/// Ordered, so `access < required` is the refusal test. A tenant administrator and the seeded
/// automation client are `Full`. A tenant role can grant `management:read`, `management:write`,
/// or `monaca:admin` (full) without the account being a tenant administrator, which is how a
/// tenant delegates read-only or operator access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagementAccess {
    /// No management capability.
    None = 0,
    /// `GET`/`HEAD` on `/v1`.
    Read = 1,
    /// Ordinary mutations, and every read.
    Write = 2,
    /// Role administration, and every read/write.
    Full = 3,
}

impl ManagementAccess {
    /// Map the level `account_liveness` computed from the account's current roles.
    fn from_level(level: i32) -> Self {
        match level {
            3 => Self::Full,
            2 => Self::Write,
            1 => Self::Read,
            _ => Self::None,
        }
    }

    /// The permission a caller at this tier must hold.
    fn permission(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "management:read",
            Self::Write => "management:write",
            Self::Full => "monaca:admin",
        }
    }

    /// The wire name `/v1/me` reports.
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::Full => "full",
        }
    }
}

/// Resolve and verify the caller's bearer token, then require a management tier.
async fn authorize_management(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    required: ManagementAccess,
    allow_archived: bool,
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
    // A suspended or archived tenant keeps its data but must not answer `/v1`, even with a token
    // minted before the state changed.
    if !tenant.is_active() && !(allow_archived && tenant.state == "archived") {
        return Err(match tenant.state.as_str() {
            "suspended" => ApiError::problem(
                kinds::TENANT_SUSPENDED,
                "this tenant is suspended; contact its administrator",
            ),
            "archived" => ApiError::problem(
                kinds::TENANT_ARCHIVED,
                "this tenant is archived; contact its administrator",
            ),
            _ => ApiError::problem(kinds::UNAUTHORIZED, "the tenant is not active"),
        });
    }
    let jwks = state.jwks(&tenant).await?;
    let claims = monaca_crypto::verify_jws_with_audience(
        token,
        &jwks,
        "at+jwt",
        &state.config.management_audience(),
    )
    .map_err(|err| ApiError::problem(kinds::UNAUTHORIZED, err.to_string()))?;

    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .and_then(|raw| Uuid::parse_str(raw).ok());

    if claims.get("act").is_some() {
        return Err(ApiError::problem(
            kinds::INSUFFICIENT_SCOPE,
            "an agent token may not call the management API",
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    // A user token is only usable while its account is active, its `jti` is not revoked and the
    // session that minted it is still live. A disable or a session kick must stop the old token
    // from reaching `/v1`, not merely prevent the next sign-in. The three answers come from one
    // primary-key row, so the request does not pay for separate account and session lookups.
    if let Ok(account_id) = AccountId::parse(&sub) {
        let session_id = claims
            .get("sid")
            .and_then(Value::as_str)
            .and_then(|raw| Uuid::parse_str(raw).ok());
        let live = state
            .store
            .account_liveness(&tenant, account_id, session_id, jti)
            .await?
            .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "the account is gone"))?;
        if live.token_revoked {
            state.metrics.record_revoked("management");
            return Err(ApiError::problem(
                kinds::UNAUTHORIZED,
                "the token was revoked",
            ));
        }
        if live.state != "active" {
            return Err(ApiError::problem(
                kinds::UNAUTHORIZED,
                "the account is disabled",
            ));
        }
        if !live.session_live {
            return Err(ApiError::problem(
                kinds::UNAUTHORIZED,
                "the session was revoked",
            ));
        }
        // Roles are read per request, so assigning or removing one changes the next call rather
        // than waiting for a new token. A token scope is not the authority for a user token.
        let access = ManagementAccess::from_level(live.management_level);
        if access < required {
            return Err(ApiError::problem(
                kinds::INSUFFICIENT_SCOPE,
                format!(
                    "the account's roles do not grant `{}`",
                    required.permission()
                ),
            ));
        }
        state
            .enforce_rate_limit(&tenant, "management", None)
            .await?;
        return Ok((
            tenant,
            AdminPrincipal {
                subject: sub,
                account_id: Some(account_id),
                actor_uuid: account_id.uuid(),
                access,
            },
        ));
    }

    // Automation tokens have no account row; their `jti` is the only revocation state.
    if let Some(jti) = jti
        && state.store.access_token_revoked(&tenant, jti).await?
    {
        state.metrics.record_revoked("management");
        return Err(ApiError::problem(
            kinds::UNAUTHORIZED,
            "the token was revoked",
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

    // The automation client (§6.2). `monaca:admin` is only registered on that seeded client, so
    // the client id is the actor and the tier is full.
    let client_id = monaca_types::ClientId::parse(&sub).map_err(|_| {
        ApiError::problem(kinds::UNAUTHORIZED, "the token subject is not a principal")
    })?;
    let client = state
        .store
        .client_by_id(&tenant, client_id.uuid())
        .await?
        .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "the client is gone"))?;
    state
        .enforce_rate_limit(&tenant, "management", Some(client.client_id.as_str()))
        .await?;
    Ok((
        tenant,
        AdminPrincipal {
            subject: sub,
            account_id: None,
            actor_uuid: client.id,
            access: ManagementAccess::Full,
        },
    ))
}

/// Require write access: ordinary management mutations (`POST`, `PATCH`, `DELETE`).
pub async fn authorize_admin(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    authorize_management(state, headers, ManagementAccess::Write, false).await
}

/// Require read access: `GET` on the management API.
pub async fn authorize_admin_read(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    authorize_management(state, headers, ManagementAccess::Read, false).await
}

/// Require full access: role administration, which would otherwise let a write-tier caller
/// escalate itself by minting a role with `monaca:admin`.
pub async fn authorize_admin_full(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    authorize_management(state, headers, ManagementAccess::Full, false).await
}

/// Any authenticated account, even one whose roles grant no management tier. Used by `/v1/me`.
pub async fn authorize_self(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    authorize_management(state, headers, ManagementAccess::None, false).await
}

/// Read a tenant's own lifecycle record while it is archived, so the console can explain the
/// state and offer reactivation.
pub async fn authorize_tenant_read(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    authorize_management(state, headers, ManagementAccess::Read, true).await
}

/// Reactivate an archived tenant: the only management operation that works while archived.
pub async fn authorize_tenant_full(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(TenantRow, AdminPrincipal), ApiError> {
    authorize_management(state, headers, ManagementAccess::Full, true).await
}

/// A role as `/v1/me` reports it to its holder.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MeRoleView {
    /// The `rol_…` id.
    pub id: String,
    /// The role name carried by the id_token.
    pub name: String,
    /// The permission scopes the role grants.
    pub permissions: Vec<String>,
}

/// `GET /v1/me` — the signed-in account and its current management tier.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MeView {
    /// The `acc_…` id.
    pub account_id: String,
    /// Primary email.
    pub email: String,
    /// Display name.
    pub display_name: String,
    /// `active` or `disabled`.
    pub state: String,
    /// The owner override, set only by bootstrap or the CLI.
    pub is_tenant_admin: bool,
    /// `none`, `read`, `write` or `full`.
    pub management: &'static str,
    /// The tenant roles the account holds.
    pub roles: Vec<MeRoleView>,
}

/// `GET /v1/tenant` — the tenant's own lifecycle record.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantView {
    /// The `ten_…` id.
    pub id: String,
    /// The URL slug.
    pub slug: String,
    /// `active`, `suspended` or `archived`.
    pub state: String,
    /// The issuer prefix, `{base}/t/{slug}`.
    pub issuer: String,
}

/// The body of `PATCH /v1/tenant`; only the archive/reactivate pair is accepted.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateTenantBody {
    /// `archived` from active, or `active` from archived.
    pub state: String,
}

fn tenant_view(tenant: &TenantRow) -> TenantView {
    TenantView {
        id: tenant.tenant_id().to_typed_string(),
        slug: tenant.slug.clone(),
        state: tenant.state.clone(),
        issuer: tenant.issuer.clone(),
    }
}

/// `GET /v1/me` — the account's identity, roles and effective management tier.
#[utoipa::path(
    get,
    path = "/v1/me",
    tag = "management",
    summary = "Read the signed-in account and its management tier",
    responses(
        (status = 200, description = "The account and its current roles.", body = MeView),
        (status = 403, description = "An automation client has no account identity.")
    )
)]
pub async fn get_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<MeView>, ApiError> {
    let (tenant, admin) = authorize_self(&state, &headers).await?;
    let Some(account_id) = admin.account_id else {
        return Err(ApiError::problem(
            kinds::INSUFFICIENT_SCOPE,
            "an automation client has no /v1/me",
        ));
    };
    let account = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::problem(kinds::UNAUTHORIZED, "the account is gone"))?;
    let roles = state.store.account_roles(&tenant, account_id).await?;
    Ok(Json(MeView {
        account_id: account_id.to_typed_string(),
        email: account.primary_email.clone(),
        display_name: account.display_name.clone(),
        state: account.state.clone(),
        is_tenant_admin: account.is_tenant_admin,
        management: admin.access.as_str(),
        roles: roles
            .into_iter()
            .map(|role| MeRoleView {
                id: role.role_id().to_typed_string(),
                name: role.name,
                permissions: role.permissions,
            })
            .collect(),
    }))
}

/// `GET /v1/tenant` — the tenant's own lifecycle record.
#[utoipa::path(
    get,
    path = "/v1/tenant",
    tag = "management",
    summary = "Read the tenant lifecycle record",
    responses((status = 200, description = "The tenant record.", body = TenantView))
)]
pub async fn get_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TenantView>, ApiError> {
    let (tenant, _) = authorize_tenant_read(&state, &headers).await?;
    Ok(Json(tenant_view(&tenant)))
}

/// `PATCH /v1/tenant` — archive an active tenant, or reactivate an archived one.
#[utoipa::path(
    patch,
    path = "/v1/tenant",
    tag = "management",
    summary = "Archive or reactivate the tenant",
    request_body = UpdateTenantBody,
    responses(
        (status = 200, description = "The updated tenant record.", body = TenantView),
        (status = 400, description = "A state outside active/archived or a transition the API does not offer."),
        (status = 403, description = "The caller does not hold full management.")
    )
)]
pub async fn update_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateTenantBody>,
) -> Result<Json<TenantView>, ApiError> {
    let (tenant, admin) = authorize_tenant_full(&state, &headers).await?;
    let target = body.state.trim();
    if !matches!(target, "active" | "archived") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "state must be `active` or `archived`; `suspended` is a platform CLI action",
        ));
    }
    if tenant.state == target {
        return Ok(Json(tenant_view(&tenant)));
    }
    let allowed = matches!(
        (tenant.state.as_str(), target),
        ("active", "archived") | ("archived", "active")
    );
    if !allowed {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!(
                "tenant cannot move from `{}` to `{target}` through the management API",
                tenant.state
            ),
        ));
    }
    let updated = state.store.set_tenant_state(&tenant.slug, target).await?;
    let action = if target == "archived" {
        "tenant.archived"
    } else {
        "tenant.reactivated"
    };
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: action.into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: Some(tenant.tenant_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "from": &tenant.state, "to": &updated.state }),
    };
    if let Err(err) = state.audit_tenant(&updated, &event).await {
        tracing::warn!(%err, "could not append {action} audit event");
    }
    Ok(Json(tenant_view(&updated)))
}

/// The query string of `GET /v1/accounts`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AccountsQuery {
    /// Case-insensitive substring of the email or display name.
    pub query: Option<String>,
    /// Page size, default 50, max 200.
    pub limit: Option<i64>,
}

/// `GET /v1/accounts` — search the tenant's accounts (§6.2).
#[utoipa::path(
    get,
    path = "/v1/accounts",
    tag = "management",
    summary = "Search accounts",
    params(AccountsQuery),
    responses((status = 200, description = "The matched accounts.", body = AccountList))
)]
pub async fn list_accounts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AccountsQuery>,
) -> Result<Json<AccountList>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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
    Ok(Json(AccountList { items, next: None }))
}

/// `POST /v1/accounts`.
#[utoipa::path(
    post,
    path = "/v1/accounts",
    tag = "management",
    summary = "Create an account",
    request_body = CreateAccountBody,
    responses(
        (status = 201, description = "The created account.", body = AccountView),
        (status = 400, description = "The email, display name or password is invalid.")
    )
)]
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
    let experience = state.store.sign_in_experience(&tenant).await?;
    let email = body.email.trim();
    let local_part = email.split('@').next().unwrap_or(email);
    crate::protocol::check_password(&body.password, &experience, &[local_part])?;
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
            None,
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
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}",
    tag = "management",
    summary = "Read an account",
    params(("id" = String, Path, description = "The `acc_…` id.")),
    responses(
        (status = 200, description = "The account with its username.", body = AccountDetailView),
        (status = 404, description = "No such account.")
    )
)]
pub async fn get_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<AccountDetailView>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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
    let username = state.store.account_username(&tenant, id).await?;
    Ok(Json(account_detail_json(
        &account,
        &roles,
        username.as_deref(),
    )))
}

/// The body of `PATCH /v1/accounts/{id}`.
///
/// Any subset may be sent: `state` suspends or reactivates, while `display_name` and `username`
/// edit the profile an administrator sees in the directory and the account can edit itself.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateAccountBody {
    /// `active` | `disabled`.
    pub state: Option<String>,
    /// The new display name.
    pub display_name: Option<String>,
    /// The new username, a second sign-in identifier (§6.1).
    pub username: Option<String>,
    /// An absolute http(s) avatar URL; an empty string clears it.
    pub avatar_url: Option<String>,
}

/// `PATCH /v1/accounts/{id}` — suspend/reactivate or edit the profile (§6.2).
#[utoipa::path(
    patch,
    path = "/v1/accounts/{id}",
    tag = "management",
    summary = "Update an account",
    params(("id" = String, Path, description = "The `acc_…` id.")),
    request_body = UpdateAccountBody,
    responses(
        (status = 200, description = "The updated account.", body = AccountDetailView),
        (status = 400, description = "Nothing to update or a value is invalid."),
        (status = 404, description = "No such account.")
    )
)]
///
/// Suspension is immediate: every live session and refresh token is revoked with the state
/// change, so the browser is signed out and no new access token can be minted. Repeating the
/// current state is a no-op that answers with the unchanged account. A profile edit writes
/// `account.updated`; a username another account holds is `409 MONACA_USERNAME_TAKEN`.
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateAccountBody>,
) -> Result<Json<AccountDetailView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    if body.state.is_none()
        && body.display_name.is_none()
        && body.username.is_none()
        && body.avatar_url.is_none()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "nothing to update; send `state`, `display_name`, `username` and/or `avatar_url`",
        ));
    }
    let state_change = match body.state.as_deref() {
        Some(value) if !matches!(value, "active" | "disabled") => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "state must be `active` or `disabled`",
            ));
        }
        Some(value) => Some(value),
        None => None,
    };
    let account = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    let display_name = body
        .display_name
        .as_deref()
        .map(crate::account::check_display_name)
        .transpose()?;
    let username = body
        .username
        .as_deref()
        .map(|raw| crate::protocol::check_username(raw, &experience, Some(&account.primary_email)))
        .transpose()?;
    let avatar_url = body
        .avatar_url
        .as_deref()
        .map(crate::account::check_avatar_url)
        .transpose()?;

    if let Some(target) = state_change
        && account.state != target
    {
        if !state
            .store
            .set_account_state(&tenant, account_id, target)
            .await?
        {
            return Err(ApiError::not_found("account"));
        }
        if target == "disabled" {
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
            action: if target == "disabled" {
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

    let current_username = state.store.account_username(&tenant, account_id).await?;
    let mut changed: Vec<&str> = Vec::new();
    let mut profile_payload = serde_json::Map::new();
    if let Some(name) = display_name
        && name != account.display_name
    {
        state
            .store
            .update_display_name(&tenant, account_id, &name)
            .await?;
        changed.push("display_name");
        profile_payload.insert("display_name".into(), json!(name));
    }
    if let Some(username) = username {
        let display = username.display.as_deref().unwrap_or(&username.value);
        if current_username.as_deref() != Some(display) {
            state
                .store
                .set_username(
                    &tenant,
                    account_id,
                    &username.value,
                    username.display.as_deref(),
                )
                .await?;
            changed.push("username");
            profile_payload.insert("username".into(), json!(display));
        }
    }
    if let Some(avatar_url) = avatar_url
        && account.avatar_url.as_deref() != avatar_url.as_deref()
    {
        state
            .store
            .update_avatar_url(&tenant, account_id, avatar_url.as_deref())
            .await?;
        changed.push("avatar_url");
        profile_payload.insert("avatar_url".into(), json!(avatar_url));
    }
    if !changed.is_empty() {
        let event = AuditEvent {
            id: EventId::new(),
            at: state.now(),
            action: "account.updated".into(),
            actor_chain: vec![admin.actor()],
            subject: AuditSubject {
                subject_type: AuditActorType::Account,
                id: Some(account.account_id().to_typed_string()),
            },
            decision: AuditDecision::Allow,
            grant_id: None,
            jti: None,
            payload: json!({
                "email": account.primary_email,
                "fields": changed,
                "display_name": profile_payload.get("display_name"),
                "username": profile_payload.get("username"),
                "avatar_url": profile_payload.get("avatar_url"),
            }),
        };
        if let Err(err) = state.audit_tenant(&tenant, &event).await {
            tracing::warn!(%err, "could not append account.updated audit event");
        }
    }

    let updated = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;
    let roles = state.store.account_roles(&tenant, account_id).await?;
    let username = state.store.account_username(&tenant, account_id).await?;
    Ok(Json(account_detail_json(
        &updated,
        &roles,
        username.as_deref(),
    )))
}

/// The query string of `DELETE /v1/accounts/{id}` (§6.2).
///
/// Deletion is permanent, so the endpoint has two deliberate steps: `?dry_run=true` reports what
/// would be destroyed, and a real call must repeat the account's email in `?confirm=`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct DeleteAccountQuery {
    /// Report the live sessions and refresh tokens without deleting anything.
    pub dry_run: Option<bool>,
    /// The account's email address, proving the destructive call is intentional.
    pub confirm: Option<String>,
}

/// `DELETE /v1/accounts/{id}` — delete an account and everything that depends on it (§6.2).
///
/// The store disables the account and revokes its sessions and refresh tokens before removing the
/// rows, so a partial failure leaves it unable to sign in. The tenant audit chain keeps the
/// `account.deleted` event: history is not account data.
#[utoipa::path(
    delete,
    path = "/v1/accounts/{id}",
    tag = "management",
    summary = "Delete an account",
    params(
        ("id" = String, Path, description = "The `acc_…` id."),
        DeleteAccountQuery
    ),
    responses(
        (status = 200, description = "The dry-run counts, or the deletion result."),
        (status = 400, description = "The confirmation is missing or names another address."),
        (status = 404, description = "No such account.")
    )
)]
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<DeleteAccountQuery>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    let account = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;

    if admin.account_id == Some(account_id) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "an administrator cannot delete their own account here",
        ));
    }

    let (sessions, refresh_tokens) = state
        .store
        .account_token_counts(&tenant, account_id)
        .await?;

    if query.dry_run == Some(true) {
        return Ok(Json(json!({
            "dry_run": true,
            "account_id": account.account_id().to_typed_string(),
            "email": account.primary_email,
            "state": account.state,
            "sessions": sessions,
            "refresh_tokens": refresh_tokens,
            "confirmation": format!(
                "repeat DELETE with ?confirm={}",
                account.primary_email
            ),
        })));
    }

    let confirmed = query
        .confirm
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(confirmed) = confirmed else {
        return Err(ApiError::problem(
            kinds::CONFIRMATION_REQUIRED,
            format!(
                "send ?dry_run=true first, then ?confirm={} to delete",
                account.primary_email
            ),
        ));
    };
    if !confirmed.eq_ignore_ascii_case(&account.primary_email) {
        return Err(ApiError::problem(
            kinds::CONFIRMATION_REQUIRED,
            "confirm must repeat the account's email address",
        ));
    }

    // The last active administrator must stay: otherwise the tenant would have no one who can
    // reach `/v1` any more.
    if account.is_tenant_admin
        && account.state == "active"
        && state.store.count_tenant_admins(&tenant).await? <= 1
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the last active tenant administrator cannot be deleted",
        ));
    }

    if !state.store.delete_account(&tenant, account_id).await? {
        return Err(ApiError::not_found("account"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "email": account.primary_email,
            "self_service": false,
            "sessions": sessions,
            "refresh_tokens": refresh_tokens,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append account.deleted audit event");
    }

    Ok(Json(json!({
        "deleted": true,
        "account_id": account.account_id().to_typed_string(),
        "email": account.primary_email,
        "sessions_revoked": sessions,
        "refresh_tokens_revoked": refresh_tokens,
    })))
}

/// The optional hosted-page branding in `PATCH /v1/sign-in-experience` (§6.2).
///
/// Absent fields keep their value; an empty string clears one. That is the whole reason this is a
/// nested object rather than five more top-level members: a cleared field has to be expressible.
#[derive(Debug, Default, Deserialize)]
pub struct BrandingPatch {
    /// A name shown instead of the tenant slug.
    pub display_name: Option<String>,
    /// An absolute http(s) logo URL.
    pub logo_url: Option<String>,
    /// An absolute http(s) logo URL used in dark mode.
    pub dark_logo_url: Option<String>,
    /// An absolute http(s) favicon URL.
    pub favicon_url: Option<String>,
    /// A `#rrggbb` primary colour.
    pub primary_color: Option<String>,
    /// Terms-of-service link.
    pub terms_url: Option<String>,
    /// Privacy-policy link.
    pub privacy_url: Option<String>,
    /// An address visitors can write to for help.
    pub support_email: Option<String>,
    /// The tenant's own website.
    pub website_url: Option<String>,
    /// CSS appended after the built-in stylesheet, at most 20 000 characters.
    pub custom_css: Option<String>,
}

impl BrandingPatch {
    fn is_empty(&self) -> bool {
        self.display_name.is_none()
            && self.logo_url.is_none()
            && self.dark_logo_url.is_none()
            && self.favicon_url.is_none()
            && self.primary_color.is_none()
            && self.terms_url.is_none()
            && self.privacy_url.is_none()
            && self.support_email.is_none()
            && self.website_url.is_none()
            && self.custom_css.is_none()
    }
}

/// The CAPTCHA switches in `PATCH /v1/sign-in-experience` (§6.2).
///
/// `secret` is write-only: sending it replaces the sealed value, sending an empty string removes
/// it, and omitting it keeps the stored one. No response ever carries the secret back.
#[derive(Debug, Default, Deserialize)]
pub struct CaptchaPatch {
    /// Whether a challenge gates the entrances named below.
    pub enabled: Option<bool>,
    /// `turnstile` | `recaptcha` | `hcaptcha` | `cap`.
    pub provider: Option<String>,
    /// The public site key; an empty string clears it.
    pub site_key: Option<String>,
    /// The Cap instance's public base URL; an empty string clears it.
    pub base_url: Option<String>,
    /// The provider secret; an empty string clears it.
    pub secret: Option<String>,
    /// Whether password sign-in demands a token.
    pub on_sign_in: Option<bool>,
    /// Whether sign-up demands a token.
    pub on_sign_up: Option<bool>,
    /// Whether password-reset code requests demand a token.
    pub on_password_reset: Option<bool>,
}

impl CaptchaPatch {
    fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.provider.is_none()
            && self.site_key.is_none()
            && self.base_url.is_none()
            && self.secret.is_none()
            && self.on_sign_in.is_none()
            && self.on_sign_up.is_none()
            && self.on_password_reset.is_none()
    }
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
    /// Whether passwordless passkey sign-in is offered.
    pub passkey_sign_in_enabled: Option<bool>,
    /// Whether enterprise SSO connectors are reachable from the hosted page.
    pub single_sign_on_enabled: Option<bool>,
    /// Whether second factors are used at sign-in at all.
    pub mfa_enabled: Option<bool>,
    /// `user_controlled` | `mandatory`.
    pub mfa_policy: Option<String>,
    /// Whether a browser may be remembered past the second factor.
    pub mfa_trusted_devices_enabled: Option<bool>,
    /// How long a remembered browser keeps its trust, 1–365 days.
    pub mfa_trusted_device_ttl_days: Option<i32>,
    /// The shortest password every entrance accepts, 8–64 characters.
    pub password_min_length: Option<i32>,
    /// How many character classes a password must use, 1–4.
    pub password_min_character_types: Option<i32>,
    /// Whether a password may not contain the account's email local part or username.
    pub password_reject_user_info: Option<bool>,
    /// Whether a password may not repeat a character or follow a sequence four times.
    pub password_reject_repetition_and_sequence: Option<bool>,
    /// Lowercased words a password may not contain, at most 100.
    pub password_rejected_words: Option<Vec<String>>,
    /// How long a browser session stays signed in, 3600–7776000 seconds.
    pub session_ttl_secs: Option<i32>,
    /// How long a refresh token stays usable, 3600–31536000 seconds.
    pub refresh_token_ttl_secs: Option<i32>,
    /// The identifiers a new account may claim at sign-up (`email`, `username`).
    pub sign_up_identifiers: Option<Vec<String>>,
    /// Whether an address must be proved with an emailed code before the account exists.
    pub sign_up_email_verification_required: Option<bool>,
    /// Whether usernames keep their case and are compared exactly.
    pub username_case_sensitive: Option<bool>,
    /// The shortest accepted username, 3–32 characters.
    pub username_min_length: Option<i32>,
    /// The longest accepted username, 3–32 characters.
    pub username_max_length: Option<i32>,
    /// Punctuation allowed beside ASCII letters and digits: a subset of `_`, `-`, `.`.
    pub username_allowed_punctuation: Option<Vec<String>>,
    /// Whether a username may equal the account's email local part.
    pub username_allow_email_local_part: Option<bool>,
    /// Whether a case-insensitive tenant keeps the typed form for display.
    pub username_preserve_case: Option<bool>,
    /// Lowercased whole usernames the tenant refuses, at most 100.
    pub username_reserved_words: Option<Vec<String>>,
    /// The profile fields the sign-up form collects (`name`, `avatar`).
    pub sign_up_profile_fields: Option<Vec<String>>,
    /// The CAPTCHA provider and the entrances it gates.
    pub captcha: Option<CaptchaPatch>,
    /// Consecutive wrong passwords before the identifier is refused; zero disables lockout.
    pub login_lockout_threshold: Option<i32>,
    /// How long a lock lasts, 30–86400 seconds.
    pub login_lockout_duration_secs: Option<i32>,
    /// The hosted page's optional look.
    pub branding: Option<BrandingPatch>,
}

/// `GET /v1/sign-in-experience` — the tenant's hosted sign-in switches (§6.2).
pub async fn get_sign_in_experience(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    let branding = state.store.branding(&tenant).await?;
    Ok(Json(sign_in_experience_json(&experience, &branding)))
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
        && body.passkey_sign_in_enabled.is_none()
        && body.single_sign_on_enabled.is_none()
        && body.mfa_enabled.is_none()
        && body.mfa_policy.is_none()
        && body.mfa_trusted_devices_enabled.is_none()
        && body.mfa_trusted_device_ttl_days.is_none()
        && body.password_min_length.is_none()
        && body.password_min_character_types.is_none()
        && body.password_reject_user_info.is_none()
        && body.password_reject_repetition_and_sequence.is_none()
        && body.password_rejected_words.is_none()
        && body.session_ttl_secs.is_none()
        && body.refresh_token_ttl_secs.is_none()
        && body.sign_up_identifiers.is_none()
        && body.sign_up_email_verification_required.is_none()
        && body.username_case_sensitive.is_none()
        && body.username_min_length.is_none()
        && body.username_max_length.is_none()
        && body.username_allowed_punctuation.is_none()
        && body.username_allow_email_local_part.is_none()
        && body.username_preserve_case.is_none()
        && body.username_reserved_words.is_none()
        && body.sign_up_profile_fields.is_none()
        && body.captcha.as_ref().is_none_or(CaptchaPatch::is_empty)
        && body.login_lockout_threshold.is_none()
        && body.login_lockout_duration_secs.is_none()
        && body.branding.is_none()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one switch must be present",
        ));
    }
    if let Some(policy) = body.mfa_policy.as_deref()
        && !matches!(policy, "user_controlled" | "mandatory")
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "mfa_policy must be user_controlled or mandatory",
        ));
    }
    if let Some(min_length) = body.password_min_length
        && !(8..=64).contains(&min_length)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "password_min_length must be between 8 and 64",
        ));
    }
    if let Some(min_types) = body.password_min_character_types
        && !(1..=4).contains(&min_types)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "password_min_character_types must be between 1 and 4",
        ));
    }
    if let Some(days) = body.mfa_trusted_device_ttl_days
        && !(1..=365).contains(&days)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "mfa_trusted_device_ttl_days must be between 1 and 365",
        ));
    }
    if let Some(identifiers) = body.sign_up_identifiers.as_deref() {
        let allowed = identifiers
            .iter()
            .all(|identifier| matches!(identifier.as_str(), "email" | "username"));
        if identifiers.is_empty() || !allowed || !identifiers.iter().any(|id| id == "email") {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "sign_up_identifiers must be a non-empty subset of email, username that contains email",
            ));
        }
    }
    if let Some(allowed) = body.username_allowed_punctuation.as_deref() {
        let valid = allowed.iter().enumerate().all(|(index, punctuation)| {
            matches!(punctuation.as_str(), "_" | "-" | ".")
                && !allowed[..index].contains(punctuation)
        });
        if !valid || allowed.len() > 3 {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "username_allowed_punctuation may only contain a unique subset of _, - and .",
            ));
        }
    }
    if let Some(fields) = body.sign_up_profile_fields.as_deref()
        && fields
            .iter()
            .any(|field| !matches!(field.as_str(), "name" | "avatar"))
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "sign_up_profile_fields may only name name or avatar",
        ));
    }
    if let Some(captcha) = &body.captcha {
        if let Some(provider) = captcha.provider.as_deref()
            && !matches!(provider, "turnstile" | "recaptcha" | "hcaptcha" | "cap")
        {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "captcha.provider must be turnstile, recaptcha, hcaptcha or cap",
            ));
        }
        if let Some(site_key) = captcha.site_key.as_deref()
            && site_key.trim().chars().count() > 200
        {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "captcha.site_key must be at most 200 characters",
            ));
        }
        if let Some(base_url) = captcha.base_url.as_deref()
            && !base_url.trim().is_empty()
        {
            check_captcha_base_url(base_url)?;
        }
        if let Some(secret) = captcha.secret.as_deref()
            && secret.trim().chars().count() > 500
        {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "captcha.secret must be at most 500 characters",
            ));
        }
    }
    if let Some(threshold) = body.login_lockout_threshold
        && !(0..=100).contains(&threshold)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "login_lockout_threshold must be between 0 and 100",
        ));
    }
    if let Some(duration) = body.login_lockout_duration_secs
        && !(30..=86_400).contains(&duration)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "login_lockout_duration_secs must be between 30 and 86400",
        ));
    }
    let rejected_words = normalise_rejected_words(body.password_rejected_words.as_deref())?;
    let username_reserved_words =
        normalise_username_reserved_words(body.username_reserved_words.as_deref())?;
    if let Some(branding) = &body.branding {
        check_branding(branding)?;
    }
    if let Some(ttl) = body.session_ttl_secs
        && !(3_600..=7_776_000).contains(&ttl)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "session_ttl_secs must be between 3600 and 7776000",
        ));
    }
    if let Some(ttl) = body.refresh_token_ttl_secs
        && !(3_600..=31_536_000).contains(&ttl)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "refresh_token_ttl_secs must be between 3600 and 31536000",
        ));
    }

    let current = state.store.sign_in_experience(&tenant).await?;
    let username_min = body
        .username_min_length
        .unwrap_or(current.username_min_length);
    let username_max = body
        .username_max_length
        .unwrap_or(current.username_max_length);
    if !(3..=32).contains(&username_min)
        || !(3..=32).contains(&username_max)
        || username_min > username_max
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "username lengths must be 3–32 characters and min must not exceed max",
        ));
    }
    let username_case_sensitive = body
        .username_case_sensitive
        .unwrap_or(current.username_case_sensitive);
    let username_preserve_case = body
        .username_preserve_case
        .unwrap_or(current.username_preserve_case);
    if username_case_sensitive && username_preserve_case {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "username_preserve_case requires username_case_sensitive to be false",
        ));
    }
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
    // A mandatory policy with MFA switched off would demand an enrollment no page offers, so the
    // resulting pair is checked before the write just like the first-factor pair above.
    let mfa_enabled = body.mfa_enabled.unwrap_or(current.mfa_enabled);
    let mfa_policy = body
        .mfa_policy
        .as_deref()
        .unwrap_or(current.mfa_policy.as_str());
    if !mfa_enabled && mfa_policy == "mandatory" {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "mfa_policy cannot be mandatory while MFA is disabled",
        ));
    }
    // Enabling a challenge without both halves of the provider configuration would strand every
    // gated visitor, so the resulting state is checked before the write.
    let captcha_enabled = body
        .captcha
        .as_ref()
        .and_then(|captcha| captcha.enabled)
        .unwrap_or(current.captcha_enabled);
    let captcha_site_key = match body
        .captcha
        .as_ref()
        .and_then(|captcha| captcha.site_key.as_deref())
    {
        Some(value) => (!value.trim().is_empty()).then(|| value.trim()),
        None => current.captcha_site_key.as_deref(),
    };
    let captcha_secret_set = match body
        .captcha
        .as_ref()
        .and_then(|captcha| captcha.secret.as_deref())
    {
        Some(value) => !value.trim().is_empty(),
        None => current.captcha_secret_enc.is_some(),
    };
    let captcha_provider = body
        .captcha
        .as_ref()
        .and_then(|captcha| captcha.provider.as_deref())
        .unwrap_or(current.captcha_provider.as_str());
    let captcha_base_url = match body
        .captcha
        .as_ref()
        .and_then(|captcha| captcha.base_url.as_deref())
    {
        Some(value) => (!value.trim().is_empty()).then(|| value.trim()),
        None => current.captcha_cap_base_url.as_deref(),
    };
    if captcha_enabled && (captcha_site_key.is_none() || !captcha_secret_set) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "captcha.enabled requires a site key and a secret",
        ));
    }
    if captcha_enabled && captcha_provider == "cap" && captcha_base_url.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "captcha.enabled with cap requires a base URL",
        ));
    }

    let mut experience = state
        .store
        .update_sign_in_experience(
            &tenant,
            body.sign_up_enabled,
            body.password_sign_in_enabled,
            body.email_code_sign_in_enabled,
            body.passkey_sign_in_enabled,
            body.mfa_enabled,
            body.mfa_policy.as_deref(),
            body.password_min_length,
            body.password_min_character_types,
            body.password_reject_user_info,
            body.password_reject_repetition_and_sequence,
            rejected_words,
            body.session_ttl_secs,
            body.refresh_token_ttl_secs,
            body.mfa_trusted_devices_enabled,
            body.mfa_trusted_device_ttl_days,
            body.single_sign_on_enabled,
            body.sign_up_identifiers,
            body.sign_up_email_verification_required,
            body.username_case_sensitive,
            body.username_min_length,
            body.username_max_length,
            body.username_allowed_punctuation,
            body.username_allow_email_local_part,
            body.username_preserve_case,
            username_reserved_words,
            body.sign_up_profile_fields,
        )
        .await?;
    let captcha = body.captcha.as_ref();
    let guardrails = SignInGuardrailsPatch {
        captcha_enabled: captcha.and_then(|captcha| captcha.enabled),
        captcha_provider: captcha.and_then(|captcha| captcha.provider.clone()),
        captcha_site_key: captcha
            .and_then(|captcha| captcha.site_key.as_deref())
            .map(|value| (!value.trim().is_empty()).then(|| value.trim().to_owned())),
        captcha_cap_base_url: captcha
            .and_then(|captcha| captcha.base_url.as_deref())
            .map(|value| (!value.trim().is_empty()).then(|| value.trim().to_owned())),
        captcha_secret_enc: match captcha.and_then(|captcha| captcha.secret.as_deref()) {
            Some(value) if value.trim().is_empty() => Some(None),
            Some(value) => Some(Some(
                seal(&state.tenant_dek(&tenant)?, value.trim().as_bytes())
                    .map_err(ApiError::internal)?,
            )),
            None => None,
        },
        captcha_on_sign_in: captcha.and_then(|captcha| captcha.on_sign_in),
        captcha_on_sign_up: captcha.and_then(|captcha| captcha.on_sign_up),
        captcha_on_password_reset: captcha.and_then(|captcha| captcha.on_password_reset),
        login_lockout_threshold: body.login_lockout_threshold,
        login_lockout_duration_secs: body.login_lockout_duration_secs,
    };
    if !guardrails.is_empty() {
        experience = state
            .store
            .update_sign_in_guardrails(&tenant, &guardrails)
            .await?;
    }
    let branding = match &body.branding {
        Some(patch) => {
            let trimmed =
                |value: &Option<String>| value.as_deref().map(str::trim).map(str::to_owned);
            let display_name = trimmed(&patch.display_name);
            let logo_url = trimmed(&patch.logo_url);
            let dark_logo_url = trimmed(&patch.dark_logo_url);
            let favicon_url = trimmed(&patch.favicon_url);
            let primary_color = trimmed(&patch.primary_color);
            let terms_url = trimmed(&patch.terms_url);
            let privacy_url = trimmed(&patch.privacy_url);
            let support_email = trimmed(&patch.support_email);
            let website_url = trimmed(&patch.website_url);
            let custom_css = patch
                .custom_css
                .as_deref()
                .map(str::trim)
                .map(str::to_owned);
            state
                .store
                .update_branding(
                    &tenant,
                    display_name.as_deref(),
                    logo_url.as_deref(),
                    dark_logo_url.as_deref(),
                    favicon_url.as_deref(),
                    primary_color.as_deref(),
                    terms_url.as_deref(),
                    privacy_url.as_deref(),
                    support_email.as_deref(),
                    website_url.as_deref(),
                    custom_css.as_deref(),
                )
                .await?
        }
        None => state.store.branding(&tenant).await?,
    };

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
            "passkey_sign_in_enabled": experience.passkey_sign_in_enabled,
            "single_sign_on_enabled": experience.single_sign_on_enabled,
            "mfa_enabled": experience.mfa_enabled,
            "mfa_policy": experience.mfa_policy,
            "mfa_trusted_devices_enabled": experience.mfa_trusted_devices_enabled,
            "mfa_trusted_device_ttl_days": experience.mfa_trusted_device_ttl_days,
            "password_min_length": experience.password_min_length,
            "password_min_character_types": experience.password_min_character_types,
            "password_reject_user_info": experience.password_reject_user_info,
            "password_reject_repetition_and_sequence":
                experience.password_reject_repetition_and_sequence,
            "password_rejected_words": experience.password_rejected_words,
            "session_ttl_secs": experience.session_ttl_secs,
            "refresh_token_ttl_secs": experience.refresh_token_ttl_secs,
            "captcha": captcha_json(&experience, true),
            "login_lockout_threshold": experience.login_lockout_threshold,
            "login_lockout_duration_secs": experience.login_lockout_duration_secs,
            "branding": branding_json(&branding),
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sign_in_experience.updated audit event");
    }

    Ok(Json(sign_in_experience_json(&experience, &branding)))
}

fn sign_in_experience_json(experience: &SignInExperienceRow, branding: &BrandingRow) -> Value {
    json!({
        "sign_up_enabled": experience.sign_up_enabled,
        "password_sign_in_enabled": experience.password_sign_in_enabled,
        "email_code_sign_in_enabled": experience.email_code_sign_in_enabled,
        "passkey_sign_in_enabled": experience.passkey_sign_in_enabled,
        "single_sign_on_enabled": experience.single_sign_on_enabled,
        "mfa_enabled": experience.mfa_enabled,
        "mfa_policy": experience.mfa_policy,
        "mfa_trusted_devices_enabled": experience.mfa_trusted_devices_enabled,
        "mfa_trusted_device_ttl_days": experience.mfa_trusted_device_ttl_days,
        "password_min_length": experience.password_min_length,
        "password_min_character_types": experience.password_min_character_types,
        "password_reject_user_info": experience.password_reject_user_info,
        "password_reject_repetition_and_sequence":
            experience.password_reject_repetition_and_sequence,
        "password_rejected_words": experience.password_rejected_words,
        "session_ttl_secs": experience.session_ttl_secs,
        "refresh_token_ttl_secs": experience.refresh_token_ttl_secs,
        "sign_up_identifiers": experience.sign_up_identifiers,
        "sign_up_email_verification_required": experience.sign_up_email_verification_required,
        "username_case_sensitive": experience.username_case_sensitive,
        "username_min_length": experience.username_min_length,
        "username_max_length": experience.username_max_length,
        "username_allowed_punctuation": experience.username_allowed_punctuation,
        "username_allow_email_local_part": experience.username_allow_email_local_part,
        "username_preserve_case": experience.username_preserve_case,
        "username_reserved_words": experience.username_reserved_words,
        "sign_up_profile_fields": experience.sign_up_profile_fields,
        "captcha": captcha_json(experience, true),
        "login_lockout_threshold": experience.login_lockout_threshold,
        "login_lockout_duration_secs": experience.login_lockout_duration_secs,
        "branding": branding_json(branding),
        "updated_at": ts(experience.updated_at),
    })
}

/// The Cap instance URL the server prefixes with the site key; it may not carry credentials.
fn check_captcha_base_url(raw: &str) -> Result<(), ApiError> {
    let url = raw.trim();
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default()
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !is_absolute_http_url(url) || authority.contains('@') || url.chars().count() > 500 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "captcha.base_url must be an absolute http(s) URL of at most 500 characters without credentials",
        ));
    }
    Ok(())
}

/// The CAPTCHA object. A management reader also learns whether a secret is stored — never the
/// secret itself, which exists only sealed in the tenant database.
pub(crate) fn captcha_json(experience: &SignInExperienceRow, management: bool) -> Value {
    let mut captcha = json!({
        "enabled": experience.captcha_enabled,
        "provider": experience.captcha_provider,
        "site_key": experience.captcha_site_key,
        "base_url": experience.captcha_cap_base_url,
        "on_sign_in": experience.captcha_on_sign_in,
        "on_sign_up": experience.captcha_on_sign_up,
        "on_password_reset": experience.captcha_on_password_reset,
    });
    if management {
        captcha["secret_set"] = json!(experience.captcha_secret_enc.is_some());
    }
    captcha
}

/// The public shape of the branding object; `null` means "use the built-in look".
pub(crate) fn branding_json(branding: &BrandingRow) -> Value {
    json!({
        "display_name": branding.display_name,
        "logo_url": branding.logo_url,
        "dark_logo_url": branding.dark_logo_url,
        "favicon_url": branding.favicon_url,
        "primary_color": branding.primary_color,
        "terms_url": branding.terms_url,
        "privacy_url": branding.privacy_url,
        "support_email": branding.support_email,
        "website_url": branding.website_url,
        "custom_css": branding.custom_css,
    })
}

/// Lowercase, trim and de-duplicate the tenant's reserved usernames.
fn normalise_username_reserved_words(
    words: Option<&[String]>,
) -> Result<Option<Vec<String>>, ApiError> {
    let Some(words) = words else {
        return Ok(None);
    };
    if words.len() > 100 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "username_reserved_words must list at most 100 words",
        ));
    }
    let mut normalised = Vec::with_capacity(words.len());
    for word in words {
        let word = word.trim().to_lowercase();
        if word.chars().count() < 3 || word.chars().count() > 64 {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "each reserved username must be 3-64 characters",
            ));
        }
        if !normalised.contains(&word) {
            normalised.push(word);
        }
    }
    Ok(Some(normalised))
}

/// Validate and normalise the rejected-word list: lowercase, de-duplicated and bounded.
fn normalise_rejected_words(words: Option<&[String]>) -> Result<Option<Vec<String>>, ApiError> {
    let Some(words) = words else {
        return Ok(None);
    };
    if words.len() > 100 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "password_rejected_words must list at most 100 words",
        ));
    }
    let mut normalised = Vec::with_capacity(words.len());
    for word in words {
        let word = word.trim().to_lowercase();
        if word.chars().count() < 3 || word.chars().count() > 64 {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "each rejected word must be 3-64 characters",
            ));
        }
        if !normalised.contains(&word) {
            normalised.push(word);
        }
    }
    Ok(Some(normalised))
}

/// Reject a stylesheet over the contract's 20 000-character limit.
pub(crate) fn validate_custom_css(css: &str) -> Result<(), ApiError> {
    if css.trim().chars().count() > 20_000 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "custom_css must be at most 20000 characters",
        ));
    }
    Ok(())
}

/// Validate a branding patch: non-empty values must be usable by the page.
fn check_branding(branding: &BrandingPatch) -> Result<(), ApiError> {
    if branding.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one branding field must be present",
        ));
    }
    if let Some(name) = branding.display_name.as_deref()
        && name.trim().chars().count() > 64
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "display_name must be at most 64 characters",
        ));
    }
    for (label, value) in [
        ("logo_url", branding.logo_url.as_deref()),
        ("dark_logo_url", branding.dark_logo_url.as_deref()),
        ("favicon_url", branding.favicon_url.as_deref()),
        ("terms_url", branding.terms_url.as_deref()),
        ("privacy_url", branding.privacy_url.as_deref()),
        ("website_url", branding.website_url.as_deref()),
    ] {
        if let Some(url) = value
            && !url.trim().is_empty()
            && !is_absolute_http_url(url.trim())
        {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("{label} must be an absolute http(s) URL or empty"),
            ));
        }
    }
    if let Some(email) = branding.support_email.as_deref() {
        let email = email.trim();
        let one_address = email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        });
        if !email.is_empty()
            && (email.chars().count() > 254 || email.contains(char::is_whitespace) || !one_address)
        {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "support_email must be an address or empty",
            ));
        }
    }
    if let Some(color) = branding.primary_color.as_deref() {
        let color = color.trim();
        if !color.is_empty() && !is_hex_color(color) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "primary_color must be `#rrggbb` or empty",
            ));
        }
    }
    if let Some(css) = branding.custom_css.as_deref() {
        validate_custom_css(css)?;
    }
    Ok(())
}

/// `#rrggbb`, either case. The page converts it to the CSS variables it needs.
fn is_hex_color(value: &str) -> bool {
    let Some(hex) = value.strip_prefix('#') else {
        return false;
    };
    hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// The body of `POST /v1/roles`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
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

/// The body of `PATCH /v1/roles/{role}`; an absent field is left alone.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateRoleBody {
    /// A new unique name.
    pub name: Option<String>,
    /// A new free-form description.
    pub description: Option<String>,
    /// The replacement permission set; an empty array clears every permission.
    pub permissions: Option<Vec<String>>,
}

/// `POST /v1/roles` — define a role.
#[utoipa::path(
    post,
    path = "/v1/roles",
    tag = "management",
    summary = "Create a tenant role",
    request_body = CreateRoleBody,
    responses(
        (status = 201, description = "The created role.", body = RoleView),
        (status = 400, description = "The name or a permission is invalid.")
    )
)]
pub async fn create_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateRoleBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin_full(&state, &headers).await?;
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

/// `PATCH /v1/roles/{role}` — change a role's name, description or permissions.
#[utoipa::path(
    patch,
    path = "/v1/roles/{role}",
    tag = "management",
    summary = "Update a tenant role",
    request_body = UpdateRoleBody,
    responses(
        (status = 200, description = "The updated role.", body = RoleView),
        (status = 400, description = "No field, an invalid name or a permission outside the scope grammar."),
        (status = 404, description = "No such role.")
    )
)]
pub async fn update_role(
    State(state): State<Arc<AppState>>,
    Path(role): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateRoleBody>,
) -> Result<Json<RoleView>, ApiError> {
    let (tenant, admin) = authorize_admin_full(&state, &headers).await?;
    let role_id = RoleId::parse(&role)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a role id"))?;
    let Some(before) = state.store.role_by_id(&tenant, role_id.uuid()).await? else {
        return Err(ApiError::not_found("role"));
    };
    if body.name.is_none() && body.description.is_none() && body.permissions.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "nothing to update; send `name`, `description` or `permissions`",
        ));
    }
    let name = match body.name {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.len() > 80 {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "name must be 1-80 characters",
                ));
            }
            Some(trimmed.to_owned())
        }
        None => None,
    };
    let description = body.description.as_deref().map(str::trim);
    let permissions = match body.permissions {
        Some(raw) => {
            let mut cleaned: Vec<String> = Vec::new();
            for permission in &raw {
                let permission = permission.trim();
                if !valid_scope(permission) {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        "permissions must match the scope grammar",
                    ));
                }
                if !cleaned.iter().any(|existing| existing == permission) {
                    cleaned.push(permission.to_owned());
                }
            }
            Some(cleaned)
        }
        None => None,
    };
    let Some(role) = state
        .store
        .update_role(
            &tenant,
            role_id.uuid(),
            name.as_deref(),
            description,
            permissions.as_deref(),
        )
        .await?
    else {
        return Err(ApiError::not_found("role"));
    };

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "role.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "id": role_id.to_typed_string(),
            "from": {
                "name": &before.name,
                "description": &before.description,
                "permissions": &before.permissions,
            },
            "to": {
                "name": &role.name,
                "description": &role.description,
                "permissions": &role.permissions,
            },
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append role.updated audit event");
    }

    Ok(Json(role_json(&role)))
}

/// `GET /v1/roles` — every role the tenant defined.
#[utoipa::path(
    get,
    path = "/v1/roles",
    tag = "management",
    summary = "List tenant roles",
    responses((status = 200, description = "The tenant roles.", body = RoleList))
)]
pub async fn list_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RoleList>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let rows = state.store.roles(&tenant).await?;
    let items: Vec<RoleView> = rows.iter().map(role_json).collect();
    Ok(Json(RoleList { items, next: None }))
}

/// `DELETE /v1/roles/{role}` — remove a role and every assignment of it.
pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    Path(role): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin_full(&state, &headers).await?;
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
    let (tenant, admin) = authorize_admin_full(&state, &headers).await?;
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
    let Some(role_row) = state.store.role_by_id(&tenant, role_id.uuid()).await? else {
        return Err(ApiError::not_found("role"));
    };
    if !state
        .store
        .assign_role(&tenant, account_id, role_id.uuid())
        .await?
    {
        return Ok(StatusCode::NO_CONTENT);
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "role.assigned".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "role": role_row.name,
            "role_id": role_id.to_typed_string(),
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append role.assigned audit event");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/accounts/{id}/roles/{role}` — remove an assignment.
pub async fn unassign_role(
    State(state): State<Arc<AppState>>,
    Path((account, role)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin_full(&state, &headers).await?;
    let account_id = AccountId::parse(&account)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))?;
    let role_id = RoleId::parse(&role)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a role id"))?;
    let Some(role_row) = state.store.role_by_id(&tenant, role_id.uuid()).await? else {
        return Err(ApiError::not_found("role assignment"));
    };
    if !state
        .store
        .unassign_role(&tenant, account_id, role_id.uuid())
        .await?
    {
        return Err(ApiError::not_found("role assignment"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "role.unassigned".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "role": role_row.name,
            "role_id": role_id.to_typed_string(),
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append role.unassigned audit event");
    }
    Ok(StatusCode::NO_CONTENT)
}

fn role_json(role: &RoleRow) -> RoleView {
    RoleView {
        id: role.role_id().to_typed_string(),
        name: role.name.clone(),
        description: role.description.clone(),
        permissions: role.permissions.clone(),
        created_at: ts(role.created_at),
        updated_at: ts(role.updated_at),
    }
}

/// `GET /v1/accounts/{id}/sessions`.
#[utoipa::path(
    get,
    path = "/v1/accounts/{id}/sessions",
    tag = "management",
    summary = "List an account's sessions",
    params(("id" = String, Path, description = "The `acc_…` id.")),
    responses(
        (status = 200, description = "The active sessions.", body = SessionList),
        (status = 404, description = "No such account.")
    )
)]
pub async fn list_account_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SessionList>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("account"))?;

    let sessions = state.store.list_sessions(&tenant, account_id).await?;
    let items: Vec<SessionView> = sessions.iter().map(session_json).collect();
    Ok(Json(SessionList { items, next: None }))
}

/// `DELETE /v1/accounts/{id}/sessions/{session}`.
#[utoipa::path(
    delete,
    path = "/v1/accounts/{id}/sessions/{session}",
    tag = "management",
    summary = "Revoke one session",
    params(
        ("id" = String, Path, description = "The `acc_…` id."),
        ("session" = String, Path, description = "The `ses_…` id.")
    ),
    responses(
        (status = 204, description = "The session was revoked."),
        (status = 404, description = "No such session for this account.")
    )
)]
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
    // A kick ends renewal too, not just the SSO cookie: every refresh token this session issued
    // stops working immediately.
    let refresh_revoked = state
        .store
        .revoke_session_refresh_tokens(&tenant, owned.id)
        .await?;

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
        payload: json!({ "account_id": account_id.to_typed_string(), "refresh_revoked": refresh_revoked }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append session.revoked audit event");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/accounts/{id}/sessions` — revoke every live session of the account.
#[utoipa::path(
    delete,
    path = "/v1/accounts/{id}/sessions",
    tag = "management",
    summary = "Revoke every session of an account",
    params(("id" = String, Path, description = "The `acc_…` id.")),
    responses(
        (status = 200, description = "How many sessions were revoked.", body = crate::schemas::RevokedSessionsView),
        (status = 404, description = "No such account.")
    )
)]
pub async fn revoke_account_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<crate::schemas::RevokedSessionsView>, ApiError> {
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
    // Ending sessions must end renewal as well; legacy tokens without a `session_id` are covered
    // by the account-wide refresh revocation.
    let refresh_revoked = state
        .store
        .revoke_account_refresh_tokens(&tenant, account_id)
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
        payload: json!({ "revoked": revoked, "refresh_revoked": refresh_revoked }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append session.revoked_all audit event");
    }
    Ok(Json(crate::schemas::RevokedSessionsView {
        revoked,
        refresh_revoked,
    }))
}

pub(crate) fn parse_account(raw: &str) -> Result<AccountId, ApiError> {
    AccountId::parse(raw)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an account id"))
}

/// `GET /v1/accounts/{id}/security` — what the account has enrolled, as the console shows it.
///
/// The administrator sees presence and metadata, never a secret: whether an authenticator exists,
/// how many recovery codes remain, and the passkeys with their labels. Reading it is not a
/// credential, so the response is the same shape a user would see in the account centre.
pub async fn get_account_security(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    if state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("account"));
    }

    let totp = state
        .store
        .totp_secret(&tenant, account_id)
        .await?
        .is_some();
    let backup_codes = state.store.backup_code_count(&tenant, account_id).await?;
    let passkeys = state.store.passkeys(&tenant, account_id).await?;
    let trusted_devices = state
        .store
        .trusted_devices(&tenant, account_id)
        .await?
        .len();
    let keys: Vec<Value> = passkeys
        .iter()
        .map(|row| {
            json!({
                "id": row.passkey_id().to_typed_string(),
                "name": row.name,
                "created_at": ts(row.created_at),
                "last_used_at": row.last_used_at.map(ts),
            })
        })
        .collect();

    Ok(Json(json!({
        "account_id": account_id.to_typed_string(),
        "mfa": { "totp": totp, "backup_codes": backup_codes },
        "passkeys": keys,
        "trusted_devices": trusted_devices,
    })))
}

/// `DELETE /v1/accounts/{id}/mfa` — reset the account's authenticator and recovery codes.
///
/// Passkeys are separate credentials and stay: removing them is a per-key decision, and deleting an
/// account's only second factor without being asked is a destructive surprise.
pub async fn reset_account_mfa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    if state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("account"));
    }

    state.store.delete_totp_secret(&tenant, account_id).await?;
    state.store.delete_backup_codes(&tenant, account_id).await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.security_changed".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({ "account_id": account_id.to_typed_string(), "kind": "mfa_reset" }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append account.security_changed audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/accounts/{id}/passkeys/{passkey}` — remove one enrolled passkey.
pub async fn delete_account_passkey(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, raw)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let account_id = parse_account(&id)?;
    let passkey = PasskeyId::parse(&raw)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a passkey id"))?;
    if state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("account"));
    }
    if !state
        .store
        .delete_passkey(&tenant, account_id, passkey.uuid())
        .await?
    {
        return Err(ApiError::not_found("passkey"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.security_changed".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({
            "account_id": account_id.to_typed_string(),
            "kind": "passkey_removed",
            "passkey": passkey.to_typed_string(),
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append account.security_changed audit event");
    }

    Ok(StatusCode::NO_CONTENT)
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
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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
    let filter = AuditFilter {
        before: query.before,
        action: query
            .action
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        grant_id,
        jti: query.jti,
        ..AuditFilter::default()
    };

    let mut tx = state.store.begin_org(&ctx).await?;
    let (rows, total) = state
        .store
        .audit_page(&mut *tx, &ctx.schema_name, limit, &filter)
        .await?;
    let head = state.store.audit_head(&mut *tx, &ctx.schema_name).await?;
    tx.rollback().await?;

    Ok(Json(audit_page_json(
        rows, total, limit, head.seq, &head.hash,
    )))
}

/// `GET /v1/audit` — the tenant chain, for operator actions that are not org-scoped (§6.2).
///
/// Reads are not audited: the handler only selects. The page size is clamped to the same 200
/// rows the org list uses, and every response states the effective `limit` and the filtered
/// `total`, so a client can page without asking for the whole table.
#[utoipa::path(
    get,
    path = "/v1/audit",
    tag = "management",
    summary = "Search the tenant audit chain",
    params(TenantAuditQuery),
    responses(
        (status = 200, description = "One page of events, the filtered total and the chain head."),
        (status = 400, description = "A filter is malformed."),
        (status = 403, description = "The caller is not a tenant administrator.")
    )
)]
pub async fn list_tenant_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TenantAuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let from = parse_audit_time(query.from.as_deref(), "from")?;
    let to = parse_audit_time(query.to.as_deref(), "to")?;
    if let (Some(from), Some(to)) = (from, to)
        && from >= to
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "`from` must be earlier than `to`",
        ));
    }
    let filter = AuditFilter {
        before: query.before,
        action: bounded_filter(query.action.as_deref(), "action")?,
        action_prefix: bounded_filter(query.action_prefix.as_deref(), "action_prefix")?,
        actor: bounded_filter(query.actor.as_deref(), "actor")?,
        subject: bounded_filter(query.subject.as_deref(), "subject")?,
        from,
        to,
        ..AuditFilter::default()
    };

    let mut tx = state.store.begin_tenant(&tenant).await?;
    let (rows, total) = state
        .store
        .audit_page(&mut *tx, "tenant", limit, &filter)
        .await?;
    let head = state.store.audit_head(&mut *tx, "tenant").await?;
    tx.rollback().await?;

    Ok(Json(audit_page_json(
        rows, total, limit, head.seq, &head.hash,
    )))
}

/// The one envelope both audit lists return.
fn audit_page_json(
    rows: Vec<monaca_store::AuditRow>,
    total: i64,
    limit: i64,
    head_seq: i64,
    head_hash: &[u8; 32],
) -> Value {
    let next = if rows.len() as i64 == limit {
        rows.last().map(|row| row.seq)
    } else {
        None
    };
    let items: Vec<Value> = rows.iter().map(audit_json).collect();
    json!({
        "items": items,
        "next": next,
        "limit": limit,
        "total": total,
        "head": { "seq": head_seq, "hash": monaca_audit::hash_hex(head_hash) },
    })
}

/// `GET /v1/usage` — the tenant's real counts and quota, from one snapshot (§6.2).
#[utoipa::path(
    get,
    path = "/v1/usage",
    tag = "management",
    summary = "Read tenant usage and quota",
    responses(
        (status = 200, description = "The account counter, today's activity and the quota.", body = UsageView)
    )
)]
pub async fn get_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UsageView>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let summary = state.store.usage_summary(&tenant).await?;
    Ok(Json(usage_view(summary)))
}

/// `PATCH /v1/usage` — set or clear the account cap (§6.2).
#[utoipa::path(
    patch,
    path = "/v1/usage",
    tag = "management",
    summary = "Set the tenant account quota",
    request_body = UpdateUsageBody,
    responses(
        (status = 200, description = "The updated usage snapshot.", body = UsageView),
        (status = 400, description = "No field, a non-integer cap or one outside 0–10,000,000.")
    )
)]
pub async fn update_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateUsageBody>,
) -> Result<Json<UsageView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let Some(value) = body.max_accounts else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "nothing to update; send `max_accounts` (a number or null)",
        ));
    };
    let max_accounts = match value {
        None => None,
        Some(raw) => {
            if !(0..=10_000_000).contains(&raw) {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "`max_accounts` must be between 0 and 10,000,000",
                ));
            }
            Some(raw)
        }
    };
    let summary = state.store.set_account_quota(&tenant, max_accounts).await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "usage.quota_changed".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: Some(tenant.tenant_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "max_accounts": max_accounts }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append usage.quota_changed audit event");
    }
    Ok(Json(usage_view(summary)))
}

fn usage_view(summary: UsageSummaryRow) -> UsageView {
    let remaining = summary
        .max_accounts
        .map(|quota| (quota - summary.accounts_used).max(0));
    UsageView {
        users: UsageUsersView {
            total: summary.accounts_used,
            quota: summary.max_accounts,
            remaining,
            enforcement: "reject",
        },
        daily: UsageDailyView {
            date: summary.today,
            active_accounts: summary.active_today,
            logins: summary.logins_today,
            timezone: "UTC",
        },
        updated_at: ts(summary.updated_at),
    }
}

/// A filter value, trimmed; empty is absent and an over-long value is refused.
fn bounded_filter<'a>(raw: Option<&'a str>, field: &str) -> Result<Option<&'a str>, ApiError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 200 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("`{field}` must be at most 200 characters"),
        ));
    }
    Ok(Some(value))
}

fn parse_audit_time(raw: Option<&str>, field: &str) -> Result<Option<OffsetDateTime>, ApiError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    OffsetDateTime::parse(value, &Rfc3339)
        .map(Some)
        .map_err(|_| {
            ApiError::problem(kinds::INVALID_REQUEST, format!("`{field}` is not RFC 3339"))
        })
}

/// `GET /v1/orgs/{org}/audit/verify`.
pub async fn verify_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Query(bounds): Query<AuditBounds>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
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

fn account_json(account: &AccountRow, roles: &[RoleRow]) -> AccountView {
    AccountView {
        id: account.account_id().to_typed_string(),
        email: account.primary_email.clone(),
        display_name: account.display_name.clone(),
        avatar_url: account.avatar_url.clone(),
        state: account.state.clone(),
        created_at: ts(account.created_at),
        roles: roles
            .iter()
            .map(|role| RoleRef {
                id: role.role_id().to_typed_string(),
                name: role.name.clone(),
            })
            .collect(),
    }
}

/// The detail shape, which also names the sign-in username. Lists omit it to avoid a second
/// identifier read per row; `GET` and `PATCH` are where an edit form reads it.
fn account_detail_json(
    account: &AccountRow,
    roles: &[RoleRow],
    username: Option<&str>,
) -> AccountDetailView {
    let view = account_json(account, roles);
    AccountDetailView {
        id: view.id,
        email: view.email,
        display_name: view.display_name,
        avatar_url: view.avatar_url,
        state: view.state,
        created_at: view.created_at,
        roles: view.roles,
        username: username.map(str::to_owned),
    }
}

fn session_json(session: &SessionRow) -> SessionView {
    SessionView {
        id: session.session_id().to_typed_string(),
        account_id: AccountId::from_uuid(session.account_id).to_typed_string(),
        client_id: session
            .client_id
            .map(|id| monaca_types::ClientId::from_uuid(id).to_typed_string()),
        issued_at: ts(session.issued_at),
        expires_at: ts(session.expires_at),
        last_seen_at: ts(session.last_seen_at),
        user_agent: session.user_agent.clone(),
    }
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

pub(crate) fn audit_json(row: &monaca_store::AuditRow) -> Value {
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

/// One configured layer in `PATCH /v1/rate-limits` — §6.2.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RateLimitItem {
    /// `authorize` | `token` | `userinfo` | `management`.
    pub endpoint: String,
    /// The protocol client id for a per-client layer; absent for the tenant-wide layer.
    pub client_id: Option<String>,
    /// Requests allowed per window.
    pub limit: i32,
    /// Window length in seconds.
    pub window_secs: i32,
}

/// `PATCH /v1/rate-limits` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RateLimitsPatch {
    /// The complete replacement set. An empty list restores the built-in defaults.
    pub items: Vec<RateLimitItem>,
}

/// A built-in default in the `/v1/rate-limits` document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RateLimitDefaultView {
    /// The endpoint class.
    pub endpoint: String,
    /// Requests allowed per window.
    pub limit: i32,
    /// Window length in seconds.
    pub window_secs: i32,
}

/// One configured row in the `/v1/rate-limits` document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RateLimitView {
    /// The endpoint class.
    pub endpoint: String,
    /// The protocol client id, or `null` for the tenant-wide layer.
    pub client_id: Option<String>,
    /// Requests allowed per window.
    pub limit: i32,
    /// Window length in seconds.
    pub window_secs: i32,
}

/// The per-IP layer as the console sees it. It is a server setting, not a tenant row: the
/// address space is much larger than the tenant set, so it is counted in a bounded per-process
/// map rather than in PostgreSQL.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IpLimitView {
    /// Requests allowed per window, per address (`0` disables the layer).
    pub limit: i32,
    /// Window length in seconds.
    pub window_secs: i32,
    /// How addresses are grouped and where the counter lives.
    pub scope: String,
}

/// One live fixed-window counter, so the console can show "is this layer rejecting now?".
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RateLimitStatusView {
    /// The endpoint class.
    pub endpoint: String,
    /// The protocol client id, or `null` for the tenant-wide layer.
    pub client_id: Option<String>,
    /// Requests counted in the current window.
    pub count: i64,
    /// The effective limit for this layer.
    pub limit: i32,
    /// Window length in seconds.
    pub window_secs: i32,
    /// When the current window started (RFC 3339).
    pub window_started_at: String,
    /// Whole seconds until the window ends.
    pub retry_after: u64,
    /// Whether the next request would be rejected.
    pub limited: bool,
}

/// `GET`/`PATCH /v1/rate-limits` response — §6.2.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RateLimitsDocument {
    /// The built-in defaults, always present.
    pub defaults: Vec<RateLimitDefaultView>,
    /// Every configured layer.
    pub items: Vec<RateLimitView>,
    /// The per-IP layer.
    pub ip: IpLimitView,
    /// Counters that exist in the current or a recently started window.
    pub status: Vec<RateLimitStatusView>,
}

/// `GET /v1/rate-limits` — the effective defaults plus every configured row.
#[utoipa::path(
    get,
    path = "/v1/rate-limits",
    tag = "management",
    summary = "Read the request gates",
    description = "Returns the four built-in defaults and every configured tenant or client layer.",
    responses(
        (status = 200, description = "The effective gates.", body = RateLimitsDocument)
    )
)]
pub async fn get_rate_limits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RateLimitsDocument>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let rows = state.store.rate_limits(&tenant).await?;
    let counters = state.store.rate_limit_counters(&tenant).await?;
    Ok(Json(rate_limits_document(&state, &rows, &counters)))
}

/// `PATCH /v1/rate-limits` — replace the tenant's whole gate configuration.
#[utoipa::path(
    patch,
    path = "/v1/rate-limits",
    tag = "management",
    summary = "Replace the request gates",
    description = "Replaces the complete set. An empty items list restores the built-in defaults.",
    request_body = RateLimitsPatch,
    responses(
        (status = 200, description = "The saved gates.", body = RateLimitsDocument),
        (status = 400, description = "An endpoint, limit, window or client id is invalid.")
    )
)]
pub async fn update_rate_limits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RateLimitsPatch>,
) -> Result<Json<RateLimitsDocument>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;

    let mut seen: HashSet<(String, Option<String>)> = HashSet::new();
    let mut rows = Vec::with_capacity(body.items.len());
    for item in body.items {
        if !crate::rate_limit::ENDPOINTS.contains(&item.endpoint.as_str()) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "endpoint must be authorize, token, userinfo or management",
            ));
        }
        if !(1..=1_000_000).contains(&item.limit) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "limit must be between 1 and 1000000",
            ));
        }
        if !(1..=86_400).contains(&item.window_secs) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "window_secs must be between 1 and 86400",
            ));
        }
        if let Some(client) = item.client_id.as_deref()
            && state
                .store
                .client_by_client_id(&tenant, client)
                .await?
                .is_none()
        {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("unknown client `{client}`"),
            ));
        }
        if !seen.insert((item.endpoint.clone(), item.client_id.clone())) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "the same endpoint and client_id appears twice",
            ));
        }
        rows.push((item.endpoint, item.client_id, item.limit, item.window_secs));
    }

    state.store.replace_rate_limits(&tenant, &rows).await?;
    state.store.reset_rate_limit_counters(&tenant).await?;
    state.invalidate_rate_limits(&tenant).await;
    let saved = state.store.rate_limits(&tenant).await?;
    Ok(Json(rate_limits_document(&state, &saved, &[])))
}

fn rate_limits_document(
    state: &AppState,
    rows: &[RateLimitRow],
    counters: &[(String, i64, OffsetDateTime)],
) -> RateLimitsDocument {
    let now = state.now();
    RateLimitsDocument {
        defaults: crate::rate_limit::defaults()
            .into_iter()
            .map(|(endpoint, limit, window_secs)| RateLimitDefaultView {
                endpoint: endpoint.to_owned(),
                limit,
                window_secs,
            })
            .collect(),
        items: rows
            .iter()
            .map(|row| RateLimitView {
                endpoint: row.endpoint.clone(),
                client_id: row.client_id.clone(),
                limit: row.limit_count,
                window_secs: row.window_secs,
            })
            .collect(),
        ip: IpLimitView {
            limit: state.config.ip_rate_limit_per_minute as i32,
            window_secs: crate::ip_limit::WINDOW.as_secs() as i32,
            scope: "per address (IPv6: /64), per server instance".to_owned(),
        },
        status: counters
            .iter()
            .filter_map(|(key, count, window_start)| {
                status_row(rows, key, *count, *window_start, now)
            })
            .collect(),
    }
}

/// One live counter. A window that has already ended is omitted: the next hit resets it, so
/// reporting it as "limited" would be wrong.
fn status_row(
    rows: &[RateLimitRow],
    key: &str,
    count: i64,
    window_start: OffsetDateTime,
    now: OffsetDateTime,
) -> Option<RateLimitStatusView> {
    let mut parts = key.splitn(3, '|');
    let endpoint = parts.next()?;
    let client = match parts.next()? {
        "tenant" => None,
        "client" => Some(parts.next()?.to_owned()),
        _ => return None,
    };
    let ((tenant_limit, tenant_window), client_layer) =
        crate::rate_limit::layer_limits(rows, endpoint, client.as_deref());
    let (limit, window_secs) = match (&client, client_layer) {
        (Some(_), Some(layer)) => layer,
        (Some(_), None) => (tenant_limit, tenant_window),
        (None, _) => (tenant_limit, tenant_window),
    };
    let window_end = window_start + time::Duration::seconds(i64::from(window_secs));
    if now >= window_end {
        return None;
    }
    Some(RateLimitStatusView {
        endpoint: endpoint.to_owned(),
        client_id: client,
        count,
        limit: limit as i32,
        window_secs: window_secs as i32,
        window_started_at: window_start.format(&Rfc3339).unwrap_or_default(),
        retry_after: (window_end - now).whole_seconds().max(1) as u64,
        limited: count > i64::from(limit),
    })
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
