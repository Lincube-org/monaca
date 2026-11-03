//! The signed-in account's own security page — §6.1 `mfa`.
//!
//! These routes authenticate with the SSO session cookie, not a bearer token: the only caller is
//! the auth-ui page that owns the cookie, and an account must be able to enroll its authenticator
//! without first starting an authorization flow. A missing or stale cookie is always the same
//! `401`, so the endpoint does not disclose which tenant/account combination it was.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{
    BACKUP_CODE_COUNT, format_backup_code, generate_backup_codes, generate_challenge,
    generate_totp_secret, hash_password, hash_secret, seal, totp_base32, totp_otpauth_url,
    verify_password, verify_registration, verify_totp,
};
use monaca_store::{AccountRow, PasskeyRow, SessionRow, TenantRow, TrustedDeviceRow, topics};
use monaca_types::{AccountId, EventId, PasskeyId, SessionId, TrustedDeviceId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::protocol::{check_password, check_username};
use crate::session;
use crate::state::AppState;

/// How long a generated secret stays acceptable before the setup page must start over.
const ENROLLMENT_TTL_SECS: i64 = 600;

/// The issuer an authenticator app displays; the contract fixes it (§6.1 `mfa`).
pub(crate) const ISSUER: &str = "Monaca";

/// The longest display name an account may set, in characters.
const MAX_DISPLAY_NAME_LEN: usize = 80;

/// The longest avatar URL an account may set, in characters.
const MAX_AVATAR_URL_LEN: usize = 2048;

/// How many passkeys one account may register. A person has a handful of devices; ten leaves room
/// for a spare key without letting a script fill the table.
const MAX_PASSKEYS: usize = 10;

/// The longest label an account may give a passkey, in characters.
const MAX_PASSKEY_NAME_LEN: usize = 80;

/// The account behind the request's SSO cookie.
pub(crate) async fn signed_in_account(
    state: &Arc<AppState>,
    slug: &str,
    headers: &HeaderMap,
) -> Result<(TenantRow, AccountRow), ApiError> {
    let tenant = state.tenant(slug).await?;
    let Some(session_id) = session::session_id(headers) else {
        return Err(no_session());
    };
    let Some(row) = state.store.session_by_id(&tenant, session_id).await? else {
        return Err(no_session());
    };
    if !row.is_active(state.now()) {
        return Err(no_session());
    }
    let Some(account) = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(row.account_id))
        .await?
    else {
        return Err(no_session());
    };
    // A disabled account must not keep managing its security settings on an old session.
    if account.state != "active" {
        return Err(no_session());
    }
    Ok((tenant, account))
}

/// The one response every failed cookie authentication gets.
fn no_session() -> ApiError {
    ApiError::problem(kinds::UNAUTHORIZED, "a signed-in session is required")
}

/// The profile shape `GET` and `PATCH` return: identity, whether a password exists, and factors.
async fn profile_json(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account: &AccountRow,
) -> Result<Value, ApiError> {
    let totp = state
        .store
        .totp_secret(tenant, account.account_id())
        .await?
        .is_some();
    let backup_codes = state
        .store
        .backup_code_count(tenant, account.account_id())
        .await?;
    let passkeys = state
        .store
        .passkeys(tenant, account.account_id())
        .await?
        .len();
    let has_password = state
        .store
        .account_by_email(tenant, &account.primary_email)
        .await?
        .and_then(|(_, phc)| phc)
        .is_some();
    let username = state
        .store
        .account_username(tenant, account.account_id())
        .await?;
    let social = state
        .store
        .social_identities(tenant, account.account_id())
        .await?;
    let trusted_devices = state
        .store
        .trusted_devices(tenant, account.account_id())
        .await?
        .len();
    let roles = state
        .store
        .account_roles(tenant, account.account_id())
        .await?;
    Ok(json!({
        "id": account.account_id().to_typed_string(),
        "email": account.primary_email,
        "username": username,
        "display_name": account.display_name,
        "avatar_url": account.avatar_url,
        "has_password": has_password,
        "mfa": {
            "totp": totp,
            "backup_codes": backup_codes,
            "passkeys": passkeys,
            "trusted_devices": trusted_devices,
        },
        "social": social
            .iter()
            .map(|row| json!({ "connector": row.connector, "display_name": row.display_name }))
            .collect::<Vec<_>>(),
        "roles": roles
            .iter()
            .map(|row| json!({ "id": row.role_id().to_typed_string(), "name": row.name }))
            .collect::<Vec<_>>(),
    }))
}

/// `GET /t/{tenant}/account` — the account's profile and which factors are enrolled.
pub async fn get_account(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    Ok(Json(profile_json(&state, &tenant, &account).await?))
}

/// The body of `PATCH /t/{tenant}/account`.
///
/// Every field is optional so one call can change either the display name, the username, or both;
/// an absent field leaves its value untouched.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileBody {
    /// The new display name.
    pub display_name: Option<String>,
    /// The new username, a second sign-in identifier (§6.1).
    pub username: Option<String>,
    /// An absolute http(s) avatar URL; an empty string clears it.
    pub avatar_url: Option<String>,
}

/// Reject a display name that is blank or too long, trimming the accepted one.
pub(crate) fn check_display_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "display_name must not be empty",
        ));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_LEN {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("display_name must be at most {MAX_DISPLAY_NAME_LEN} characters"),
        ));
    }
    Ok(name.to_owned())
}

/// Reject an avatar that is not a single absolute `http(s)` URL; an empty string clears it.
pub(crate) fn check_avatar_url(raw: &str) -> Result<Option<String>, ApiError> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let absolute = value.starts_with("http://") || value.starts_with("https://");
    if !absolute || value.split_whitespace().count() != 1 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "avatar_url must be an absolute http(s) URL or empty",
        ));
    }
    if value.chars().count() > MAX_AVATAR_URL_LEN {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("avatar_url must be at most {MAX_AVATAR_URL_LEN} characters"),
        ));
    }
    Ok(Some(value.to_owned()))
}

/// `PATCH /t/{tenant}/account` — change the display name, username and/or avatar.
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateProfileBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, mut account) = signed_in_account(&state, &tenant, &headers).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    let display_name = body
        .display_name
        .as_deref()
        .map(check_display_name)
        .transpose()?;
    let username = body
        .username
        .as_deref()
        .map(|raw| check_username(raw, &experience, Some(&account.primary_email)))
        .transpose()?;
    let avatar_url = body
        .avatar_url
        .as_deref()
        .map(check_avatar_url)
        .transpose()?;
    if display_name.is_none() && username.is_none() && avatar_url.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "nothing to update; send `display_name`, `username` and/or `avatar_url`",
        ));
    }

    if let Some(display_name) = display_name {
        account = state
            .store
            .update_display_name(&tenant, account.account_id(), &display_name)
            .await?;
    }
    if let Some(avatar_url) = avatar_url {
        account = state
            .store
            .update_avatar_url(&tenant, account.account_id(), avatar_url.as_deref())
            .await?;
    }
    if let Some(username) = username {
        // A username another account holds is a `409 MONACA_USERNAME_TAKEN` (§6.1).
        state
            .store
            .set_username(
                &tenant,
                account.account_id(),
                &username.value,
                username.display.as_deref(),
            )
            .await?;
    }
    Ok(Json(profile_json(&state, &tenant, &account).await?))
}

/// The body of `POST /t/{tenant}/account/email`.
#[derive(Debug, Deserialize)]
pub struct ChangeEmailBody {
    /// The address the account wants to move to.
    pub email: String,
}

/// The body of `POST /t/{tenant}/account/email/verify`.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailBody {
    /// The address the code was mailed to.
    pub email: String,
    /// The six-digit code from the mail.
    pub code: String,
}

/// `POST /t/{tenant}/account/email` — mail a code to the address the account wants to move to.
///
/// The code is keyed by the *new* address, not by the account, so two accounts racing for the same
/// address cannot redeem each other's mail. An address another account already holds is refused
/// before anything is sent, and the account's own address is a no-op the caller should not make.
pub async fn request_email_change(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ChangeEmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let email = crate::protocol::normalise_email(&body.email)?;
    if account.primary_email.eq_ignore_ascii_case(&email) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "that is already the account's email",
        ));
    }
    if let Some((other, _)) = state.store.account_by_email(&tenant, &email).await?
        && other.account_id() != account.account_id()
    {
        return Err(ApiError::problem(
            kinds::EMAIL_TAKEN,
            "email is already taken",
        ));
    }
    crate::protocol::request_verification(
        &state,
        &tenant,
        crate::protocol::PURPOSE_EMAIL_CHANGE,
        &email,
    )
    .await
}

/// `POST /t/{tenant}/account/email/verify` — redeem the code and move the account to the address.
pub async fn verify_email_change(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<VerifyEmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let email = crate::protocol::normalise_email(&body.email)?;
    let previous = account.primary_email.clone();
    crate::protocol::take_verification_code(
        &state,
        &tenant,
        crate::protocol::PURPOSE_EMAIL_CHANGE,
        &email,
        &body.code,
    )
    .await?;
    let account = state
        .store
        .update_primary_email(&tenant, account.account_id(), &email)
        .await?;
    // The previous owner of the address is told the address no longer belongs to this account.
    notify(&state, &tenant, &previous, "email_changed").await?;
    Ok(Json(profile_json(&state, &tenant, &account).await?))
}

/// Mail a security notice through the dev outbox. There is no code: the payload is the fact itself.
async fn notify(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    to: &str,
    purpose: &str,
) -> Result<(), ApiError> {
    let (subject, body) = crate::email_templates::mail_copy(
        state,
        tenant,
        purpose,
        &[("tenant", tenant.slug.as_str())],
    )
    .await;
    let mut tx = state.store.begin_tenant(tenant).await?;
    state
        .store
        .outbox_append(
            &mut *tx,
            topics::MAIL,
            &json!({ "to": to, "purpose": purpose, "subject": subject, "body": body }),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

/// The body of `POST /t/{tenant}/account/deletion/confirm`.
#[derive(Debug, Deserialize)]
pub struct ConfirmDeletionBody {
    /// The six-digit code mailed by the request step.
    pub code: String,
}

/// `POST /t/{tenant}/account/deletion` — mail a code before the account is deleted.
///
/// Deletion is irreversible, so the address on file must prove it can receive mail first; the code
/// purpose is `delete_account`, which keeps it separate from sign-in and reset codes.
pub async fn request_deletion(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    crate::protocol::request_verification(
        &state,
        &tenant,
        crate::protocol::PURPOSE_DELETE_ACCOUNT,
        &account.primary_email,
    )
    .await
}

/// `POST /t/{tenant}/account/deletion/confirm` — delete the account and clear its cookies.
///
/// The account row, its credentials, identifiers, tokens, social links and trusted devices all go;
/// the audit chains keep the `account.deleted` event, because history is not account data.
pub async fn confirm_deletion(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ConfirmDeletionBody>,
) -> Result<Response, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    crate::protocol::take_verification_code(
        &state,
        &tenant,
        crate::protocol::PURPOSE_DELETE_ACCOUNT,
        &account.primary_email,
        &body.code,
    )
    .await?;
    notify(&state, &tenant, &account.primary_email, "account_deleted").await?;
    if !state
        .store
        .delete_account(&tenant, account.account_id())
        .await?
    {
        return Err(ApiError::not_found("account"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.deleted".into(),
        actor_chain: vec![AuditActor::account(account.account_id())],
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
        tracing::warn!(%err, "could not append account.deleted audit event");
    }

    let secure = session::secure_origin(&state.config);
    let mut response = StatusCode::NO_CONTENT.into_response();
    for cookie in [
        session::clear_cookie(secure),
        session::clear_device_cookie(secure, &tenant.slug),
    ] {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).map_err(ApiError::internal)?,
        );
    }
    Ok(response)
}

/// The body of `POST /t/{tenant}/account/password`.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordBody {
    /// The password in use now; a wrong value is `401`.
    pub current_password: String,
    /// The replacement, at least [`crate::protocol::MIN_PASSWORD_LEN`] characters.
    pub new_password: String,
}

/// `POST /t/{tenant}/account/password` — change the password from the account centre.
///
/// The current password is required: a stolen cookie must not be enough to lock the owner out.
/// Every other live session is revoked, because those browsers proved the old password.
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let Some(current_session) = session::session_id(&headers) else {
        return Err(no_session());
    };

    let Some((_, phc)) = state
        .store
        .account_by_email(&tenant, &account.primary_email)
        .await?
    else {
        return Err(no_session());
    };
    let Some(phc) = phc else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this account has no password credential to change",
        ));
    };
    if verify_password(body.current_password.clone(), phc, state.argon)
        .await
        .is_err()
    {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the current password is incorrect",
        ));
    }
    let experience = state.store.sign_in_experience(&tenant).await?;
    let local_part = account
        .primary_email
        .split('@')
        .next()
        .unwrap_or(&account.primary_email);
    let username = state
        .store
        .account_username(&tenant, account.account_id())
        .await?;
    let mut identifiers = vec![local_part];
    if let Some(username) = username.as_deref() {
        identifiers.push(username);
    }
    check_password(&body.new_password, &experience, &identifiers)?;

    let phc = hash_password(body.new_password.clone(), state.argon)
        .await
        .map_err(ApiError::internal)?;
    state
        .store
        .set_password(&tenant, account.account_id(), &phc)
        .await?;
    state
        .store
        .revoke_other_sessions(&tenant, account.account_id(), current_session)
        .await?;
    notify(&state, &tenant, &account.primary_email, "password_changed").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One session as the account centre sees it, with `current` marking the requesting browser.
fn account_session_json(session: &SessionRow, current: Uuid) -> Value {
    json!({
        "id": session.session_id().to_typed_string(),
        "current": session.id == current,
        "client_id": session
            .client_id
            .map(|id| monaca_types::ClientId::from_uuid(id).to_typed_string()),
        "issued_at": crate::management::ts(session.issued_at),
        "expires_at": crate::management::ts(session.expires_at),
        "last_seen_at": crate::management::ts(session.last_seen_at),
        "user_agent": session.user_agent,
    })
}

/// `GET /t/{tenant}/account/sessions` — every live session of the signed-in account.
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let Some(current) = session::session_id(&headers) else {
        return Err(no_session());
    };
    let sessions = state
        .store
        .list_sessions(&tenant, account.account_id())
        .await?;
    let items: Vec<Value> = sessions
        .iter()
        .map(|session| account_session_json(session, current))
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /t/{tenant}/account/sessions/{session}` — sign out one of the account's sessions.
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Path((tenant, session)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let session_id = SessionId::parse(&session)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a session id"))?;

    // Only the owner's own sessions are visible here; anything else is a 404, not a 403.
    let owned = state
        .store
        .session_by_id(&tenant, session_id.uuid())
        .await?
        .filter(|row| row.account_id == account.id)
        .ok_or_else(|| ApiError::not_found("session"))?;
    if !state.store.revoke_session(&tenant, owned.id).await? {
        return Err(ApiError::not_found("session"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /t/{tenant}/account/sessions` — sign out every other browser.
pub async fn revoke_other_sessions(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let Some(current) = session::session_id(&headers) else {
        return Err(no_session());
    };
    state
        .store
        .revoke_other_sessions(&tenant, account.account_id(), current)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One third-party application the account approved, with both approval kinds a client may hold
/// folded into a single row.
struct AuthorizedAppSummary {
    client_id: String,
    name: String,
    scopes: Vec<String>,
    remembered: bool,
    one_shot: bool,
    granted_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
}

/// Fold a client's remembered and one-shot rows into one entry, keeping the union of scopes and
/// the earliest grant time.
fn aggregate_authorized_apps(apps: &[monaca_store::AuthorizedAppRow]) -> Vec<AuthorizedAppSummary> {
    let mut merged: Vec<AuthorizedAppSummary> = Vec::new();
    for app in apps {
        if let Some(existing) = merged.iter_mut().find(|row| row.client_id == app.client_id) {
            for scope in &app.scopes {
                if !existing.scopes.contains(scope) {
                    existing.scopes.push(scope.clone());
                }
            }
            if app.kind == "remember" {
                existing.remembered = true;
            } else {
                existing.one_shot = true;
            }
            existing.granted_at = existing.granted_at.min(app.granted_at);
            existing.updated_at = existing.updated_at.max(app.updated_at);
        } else {
            merged.push(AuthorizedAppSummary {
                client_id: app.client_id.clone(),
                name: app.name.clone(),
                scopes: app.scopes.clone(),
                remembered: app.kind == "remember",
                one_shot: app.kind == "one_shot",
                granted_at: app.granted_at,
                updated_at: app.updated_at,
            });
        }
    }
    merged
}

/// One entry as the account centre renders it. `remember` stays for older clients; `kinds` names
/// every approval the account holds for the client.
fn authorized_app_json(app: &AuthorizedAppSummary) -> Value {
    let mut kinds = Vec::new();
    if app.remembered {
        kinds.push("remember");
    }
    if app.one_shot {
        kinds.push("one_shot");
    }
    json!({
        "client_id": app.client_id,
        "name": app.name,
        "scopes": app.scopes,
        "remember": app.remembered,
        "kinds": kinds,
        "granted_at": crate::management::ts(app.granted_at),
        "updated_at": crate::management::ts(app.updated_at),
    })
}

/// `GET /t/{tenant}/account/authorized-apps` — third-party applications this account approved.
pub async fn list_authorized_apps(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let apps = state
        .store
        .authorized_apps(&tenant, account.account_id())
        .await?;
    let items: Vec<Value> = aggregate_authorized_apps(&apps)
        .iter()
        .map(authorized_app_json)
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /t/{tenant}/account/authorized-apps/{client}` — withdraw an approval.
///
/// Removing the grant makes the next authorize request ask again, and the account's refresh
/// tokens for that client are revoked so the withdrawn access cannot renew itself.
pub async fn revoke_authorized_app(
    State(state): State<Arc<AppState>>,
    Path((tenant, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let Some(client_row) = state.store.client_by_client_id(&tenant, &client).await? else {
        return Err(ApiError::not_found("application"));
    };
    let grants = state
        .store
        .consents_for_client(&tenant, account.account_id(), client_row.id)
        .await?;
    if grants.is_empty() {
        return Err(ApiError::not_found("application"));
    }
    let mut scopes: Vec<String> = Vec::new();
    for grant in &grants {
        for scope in &grant.scopes {
            if !scopes.contains(scope) {
                scopes.push(scope.clone());
            }
        }
    }
    let kinds: Vec<&str> = grants.iter().map(|grant| grant.kind.as_str()).collect();
    if !state
        .store
        .revoke_consent(&tenant, account.account_id(), client_row.id)
        .await?
    {
        return Err(ApiError::not_found("application"));
    }
    if let Err(err) = state
        .store
        .revoke_account_client_refresh_tokens(&tenant, account.account_id(), client_row.id)
        .await
    {
        tracing::warn!(%err, "could not revoke the application's refresh tokens");
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "consent.revoked".into(),
        actor_chain: vec![AuditActor::account(account.account_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "client_id": client_row.client_id,
            "name": client_row.name,
            "scopes": scopes,
            "kinds": kinds,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append consent.revoked audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// One remembered browser as the account centre sees it, with `current` marking this one.
fn trusted_device_json(device: &TrustedDeviceRow, current: Option<&str>) -> Value {
    json!({
        "id": TrustedDeviceId::from_uuid(device.id).to_typed_string(),
        "current": current == Some(device.token_hash.as_str()),
        "user_agent": device.user_agent,
        "created_at": crate::management::ts(device.created_at),
        "last_used_at": device.last_used_at.map(crate::management::ts),
        "expires_at": crate::management::ts(device.expires_at),
    })
}

/// `GET /t/{tenant}/account/mfa/devices` — the browsers remembered past the second factor.
pub async fn list_trusted_devices(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let devices = state
        .store
        .trusted_devices(&tenant, account.account_id())
        .await?;
    let current = session::trusted_device_token(&headers).map(|token| hash_secret(&token));
    let items: Vec<Value> = devices
        .iter()
        .map(|device| trusted_device_json(device, current.as_deref()))
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /t/{tenant}/account/mfa/devices/{device}` — forget one remembered browser.
///
/// Revoking the browser that made this request also clears its cookie, so the page and the
/// browser agree immediately instead of waiting for the next sign-in to discover the trust is gone.
pub async fn revoke_trusted_device(
    State(state): State<Arc<AppState>>,
    Path((tenant, device)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let device_id = TrustedDeviceId::parse(&device)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a trusted-device id"))?;
    let devices = state
        .store
        .trusted_devices(&tenant, account.account_id())
        .await?;
    let Some(row) = devices.iter().find(|row| row.id == device_id.uuid()) else {
        return Err(ApiError::not_found("trusted device"));
    };
    let current = session::trusted_device_token(&headers).map(|token| hash_secret(&token));
    let is_current = current.as_deref() == Some(row.token_hash.as_str());
    if !state
        .store
        .revoke_trusted_device(&tenant, account.account_id(), device_id.uuid())
        .await?
    {
        return Err(ApiError::not_found("trusted device"));
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    if is_current {
        let secure = session::secure_origin(&state.config);
        let cookie = session::clear_device_cookie(secure, &tenant.slug);
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).map_err(ApiError::internal)?,
        );
    }
    Ok(response)
}

/// `POST /t/{tenant}/account/mfa/totp` — start an enrollment.
///
/// The secret is returned once, in base32, together with the `otpauth://` URL the setup page turns
/// into a QR code. It is held unconfirmed for [`ENROLLMENT_TTL_SECS`] and only written to
/// `tenant.credentials` by the verify step, so an abandoned setup leaves no credential behind.
pub async fn begin_totp(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    if state
        .store
        .totp_secret(&tenant, account.account_id())
        .await?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::MFA_ALREADY_ENABLED,
            "an authenticator app is already enrolled; remove it first",
        ));
    }

    let secret = generate_totp_secret();
    state
        .put_totp_enrollment(
            account.id,
            secret.clone(),
            state.now() + Duration::seconds(ENROLLMENT_TTL_SECS),
        )
        .await;

    Ok(Json(json!({
        "secret": totp_base32(&secret),
        "otpauth_url": totp_otpauth_url(ISSUER, &account.primary_email, &secret),
        "expires_in": ENROLLMENT_TTL_SECS,
    })))
}

/// The code the setup page read out of the app.
#[derive(Debug, Deserialize)]
pub struct TotpCodeBody {
    /// The six-digit TOTP.
    pub code: String,
}

/// `POST /t/{tenant}/account/mfa/totp/verify` — confirm the enrollment.
///
/// Without this proof a mistyped secret would lock the account out of its own second factor, so
/// nothing is persisted until the app produces a valid code. The secret is sealed with the
/// tenant's DEK, exactly like the password PHC strings next to it (§5.6 `credentials`).
pub async fn verify_totp_enrollment(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<TotpCodeBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let Some(secret) = state.totp_enrollment(account.id).await else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "no TOTP enrollment is pending; start again",
        ));
    };
    if !verify_totp(&secret, &body.code, state.now()) {
        return Err(ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        ));
    }

    let sealed = seal(&state.tenant_dek(&tenant)?, &secret)
        .map_err(|err| ApiError::internal(format!("totp secret: {err}")))?;
    state
        .store
        .set_totp_secret(&tenant, account.account_id(), &sealed)
        .await?;
    state.drop_totp_enrollment(account.id).await;
    Ok(Json(json!({ "enabled": true })))
}

/// `DELETE /t/{tenant}/account/mfa/totp` — remove the enrolled authenticator.
///
/// Turning the second factor off makes every existing sign-in single-factor again, which is the
/// same state a fresh account is in, so it needs no confirmation beyond the session cookie.
pub async fn disable_totp(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    state
        .store
        .delete_totp_secret(&tenant, account.account_id())
        .await?;
    // Backup codes recover a lost authenticator; with no authenticator left they are dead weight and
    // must not stay usable.
    state
        .store
        .delete_backup_codes(&tenant, account.account_id())
        .await?;
    state.drop_totp_enrollment(account.id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /t/{tenant}/account/mfa/backup-codes` — how many recovery codes remain unused.
pub async fn list_backup_codes(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let remaining = state
        .store
        .backup_code_count(&tenant, account.account_id())
        .await?;
    Ok(Json(json!({ "remaining": remaining })))
}

/// `POST /t/{tenant}/account/mfa/backup-codes` — mint a fresh sheet of single-use codes.
///
/// The plaintext is shown exactly once, in this response; only SHA-256 digests reach storage, exactly
/// like the email codes. Generating replaces the previous sheet, and requires an enrolled
/// authenticator: backup codes recover a lost device, they do not replace the factor itself.
pub async fn create_backup_codes(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    if state
        .store
        .totp_secret(&tenant, account.account_id())
        .await?
        .is_none()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "enroll an authenticator app before generating backup codes",
        ));
    }

    let codes = generate_backup_codes(BACKUP_CODE_COUNT);
    let hashes: Vec<String> = codes.iter().map(|code| hash_secret(code)).collect();
    state
        .store
        .replace_backup_codes(&tenant, account.account_id(), &hashes)
        .await?;

    Ok(Json(json!({
        "codes": codes.iter().map(|code| format_backup_code(code)).collect::<Vec<_>>(),
        "remaining": codes.len(),
    })))
}

/// `DELETE /t/{tenant}/account/mfa/backup-codes` — remove every recovery code.
pub async fn remove_backup_codes(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    state
        .store
        .delete_backup_codes(&tenant, account.account_id())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// -----------------------------------------------------------------------------------------
// Passkeys
//
// A passkey is a WebAuthn credential the account registers here and can later use either as the
// primary sign-in factor or as a second factor. Registration is two calls because the challenge
// must be minted server-side and redeemed once: options, then the browser's result.

/// Trim and bound the optional label, treating a blank one as no label.
fn check_passkey_name(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > MAX_PASSKEY_NAME_LEN {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("a passkey name must be at most {MAX_PASSKEY_NAME_LEN} characters"),
        ));
    }
    Ok(Some(name.to_owned()))
}

/// The public shape of one passkey. The credential id stays server-side: the page never needs it,
/// and handing it out only widens the surface a script can probe.
fn passkey_json(row: &PasskeyRow) -> Value {
    json!({
        "id": row.passkey_id().to_typed_string(),
        "name": row.name,
        "transports": row.transports,
        "created_at": crate::management::ts(row.created_at),
        "last_used_at": row.last_used_at.map(crate::management::ts),
    })
}

/// `POST /t/{tenant}/account/passkeys/options` — start a passkey registration.
///
/// The challenge is held for [`crate::passkey::CHALLENGE_TTL_SECS`] under `reg:{account}`, and the
/// existing passkeys are sent back as `excludeCredentials` so the authenticator refuses to enrol
/// the same credential twice.
pub async fn begin_passkey_registration(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let existing = state.store.passkeys(&tenant, account.account_id()).await?;
    if existing.len() >= MAX_PASSKEYS {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("an account may register at most {MAX_PASSKEYS} passkeys"),
        ));
    }

    let rp = crate::passkey::relying_party(&state.config)?;
    let challenge = generate_challenge();
    state
        .put_passkey_challenge(
            format!("reg:{}", account.id),
            challenge.clone(),
            state.now() + Duration::seconds(crate::passkey::CHALLENGE_TTL_SECS),
        )
        .await;
    let exclude = existing
        .iter()
        .map(crate::passkey::credential_descriptor)
        .collect();
    Ok(Json(crate::passkey::registration_options(
        &rp, &account, &challenge, exclude,
    )))
}

/// `POST /t/{tenant}/account/passkeys` — verify the browser's registration and store it.
///
/// Nothing is written until the attestation verifies: a credential that cannot produce a valid
/// signature is useless, and a failed attempt must not consume one of the ten slots.
pub async fn register_passkey(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<crate::passkey::CeremonyBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let existing = state.store.passkeys(&tenant, account.account_id()).await?;
    if existing.len() >= MAX_PASSKEYS {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("an account may register at most {MAX_PASSKEYS} passkeys"),
        ));
    }

    let Some(challenge) = state
        .take_passkey_challenge(&format!("reg:{}", account.id))
        .await
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "no passkey registration is pending; start again",
        ));
    };
    let malformed = || {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "the browser's passkey response is malformed",
        )
    };
    let Some(registration) = crate::passkey::parse_registration(&body) else {
        return Err(malformed());
    };

    let rp = crate::passkey::relying_party(&state.config)?;
    let credential = verify_registration(
        &registration.client_data_json,
        &registration.attestation_object,
        &challenge,
        &rp.id,
        &rp.origin,
    )
    .map_err(|err| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("the passkey registration did not verify: {err}"),
        )
    })?;
    // `rawId` is what the browser will send back later; if it disagrees with the id inside the
    // attestation, the two halves of one ceremony describe different credentials.
    if credential.credential_id != registration.credential_id {
        return Err(malformed());
    }
    if state
        .store
        .passkey_by_credential_id(&tenant, &credential.credential_id)
        .await?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this passkey is already registered",
        ));
    }

    let name = check_passkey_name(body.name.as_deref())?;
    let sealed = seal(&state.tenant_dek(&tenant)?, &credential.public_key)
        .map_err(|err| ApiError::internal(format!("passkey public key: {err}")))?;
    let sign_count = credential.sign_count.min(i64::MAX as u64) as i64;
    let row = state
        .store
        .insert_passkey(
            &tenant,
            account.account_id(),
            &credential.credential_id,
            &sealed,
            sign_count,
            &registration.transports,
            name.as_deref(),
            credential.aaguid,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(passkey_json(&row))))
}

/// `GET /t/{tenant}/account/passkeys` — every passkey of the signed-in account.
pub async fn list_passkeys(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let rows = state.store.passkeys(&tenant, account.account_id()).await?;
    Ok(Json(json!({
        "items": rows.iter().map(passkey_json).collect::<Vec<_>>(),
    })))
}

/// The body of `PATCH /t/{tenant}/account/passkeys/{passkey}`.
#[derive(Debug, Deserialize)]
pub struct RenamePasskeyBody {
    /// The new label.
    pub name: String,
}

/// `PATCH /t/{tenant}/account/passkeys/{passkey}` — relabel one passkey.
pub async fn rename_passkey(
    State(state): State<Arc<AppState>>,
    Path((tenant, passkey)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RenamePasskeyBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let passkey_id = PasskeyId::parse(&passkey)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a passkey id"))?;
    let name = check_passkey_name(Some(&body.name))?.ok_or_else(|| {
        ApiError::problem(kinds::INVALID_REQUEST, "a passkey name must not be empty")
    })?;
    let row = state
        .store
        .rename_passkey(&tenant, account.account_id(), passkey_id.uuid(), &name)
        .await?
        .ok_or_else(|| ApiError::not_found("passkey"))?;
    Ok(Json(passkey_json(&row)))
}

/// `DELETE /t/{tenant}/account/passkeys/{passkey}` — remove one passkey.
///
/// Removing the last passkey only removes an optional factor; a password (or an enrolled
/// authenticator app) still protects the account, so no confirmation beyond the session is asked.
pub async fn delete_passkey(
    State(state): State<Arc<AppState>>,
    Path((tenant, passkey)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let passkey_id = PasskeyId::parse(&passkey)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a passkey id"))?;
    if !state
        .store
        .delete_passkey(&tenant, account.account_id(), passkey_id.uuid())
        .await?
    {
        return Err(ApiError::not_found("passkey"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_enrollment_ttl_is_ten_minutes() {
        assert_eq!(ENROLLMENT_TTL_SECS, 600);
    }

    #[test]
    fn the_issuer_is_the_product_name() {
        assert_eq!(ISSUER, "Monaca");
    }

    #[test]
    fn a_display_name_is_trimmed_and_bounded() {
        assert_eq!(
            check_display_name("  Ada Lovelace  ").unwrap(),
            "Ada Lovelace"
        );
        assert!(check_display_name("   ").is_err());
        assert!(check_display_name(&"a".repeat(MAX_DISPLAY_NAME_LEN)).is_ok());
        assert!(check_display_name(&"a".repeat(MAX_DISPLAY_NAME_LEN + 1)).is_err());
    }
}
