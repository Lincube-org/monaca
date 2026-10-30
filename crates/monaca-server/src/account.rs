//! The signed-in account's own security page — §6.1 `mfa`.
//!
//! These routes authenticate with the SSO session cookie, not a bearer token: the only caller is
//! the auth-ui page that owns the cookie, and an account must be able to enroll its authenticator
//! without first starting an authorization flow. A missing or stale cookie is always the same
//! `401`, so the endpoint does not disclose which tenant/account combination it was.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use monaca_crypto::{
    BACKUP_CODE_COUNT, format_backup_code, generate_backup_codes, generate_totp_secret,
    hash_password, hash_secret, seal, totp_base32, totp_otpauth_url, verify_password, verify_totp,
};
use monaca_store::{AccountRow, SessionRow, TenantRow};
use monaca_types::{AccountId, SessionId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::protocol::check_password;
use crate::session;
use crate::state::AppState;

/// How long a generated secret stays acceptable before the setup page must start over.
const ENROLLMENT_TTL_SECS: i64 = 600;

/// The issuer an authenticator app displays; the contract fixes it (§6.1 `mfa`).
const ISSUER: &str = "Monaca";

/// The longest display name an account may set, in characters.
const MAX_DISPLAY_NAME_LEN: usize = 80;

/// The account behind the request's SSO cookie.
async fn signed_in_account(
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
    let has_password = state
        .store
        .account_by_email(tenant, &account.primary_email)
        .await?
        .and_then(|(_, phc)| phc)
        .is_some();
    Ok(json!({
        "id": account.account_id().to_typed_string(),
        "email": account.primary_email,
        "display_name": account.display_name,
        "has_password": has_password,
        "mfa": { "totp": totp, "backup_codes": backup_codes },
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
#[derive(Debug, Deserialize)]
pub struct UpdateProfileBody {
    /// The new display name.
    pub display_name: String,
}

/// Reject a display name that is blank or too long, trimming the accepted one.
fn check_display_name(raw: &str) -> Result<String, ApiError> {
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

/// `PATCH /t/{tenant}/account` — change the display name shown to applications.
pub async fn update_account(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateProfileBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let display_name = check_display_name(&body.display_name)?;
    let account = state
        .store
        .update_display_name(&tenant, account.account_id(), &display_name)
        .await?;
    Ok(Json(profile_json(&state, &tenant, &account).await?))
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
    check_password(&body.new_password)?;

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
        assert_eq!(check_display_name("  Ada Lovelace  ").unwrap(), "Ada Lovelace");
        assert!(check_display_name("   ").is_err());
        assert!(check_display_name(&"a".repeat(MAX_DISPLAY_NAME_LEN)).is_ok());
        assert!(check_display_name(&"a".repeat(MAX_DISPLAY_NAME_LEN + 1)).is_err());
    }
}
