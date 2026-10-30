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
use monaca_crypto::{generate_totp_secret, seal, totp_base32, totp_otpauth_url, verify_totp};
use monaca_store::{AccountRow, TenantRow};
use monaca_types::{AccountId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use crate::error::{ApiError, kinds};
use crate::session;
use crate::state::AppState;

/// How long a generated secret stays acceptable before the setup page must start over.
const ENROLLMENT_TTL_SECS: i64 = 600;

/// The issuer an authenticator app displays; the contract fixes it (§6.1 `mfa`).
const ISSUER: &str = "Monaca";

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

/// `GET /t/{tenant}/account` — the account's profile and which factors are enrolled.
pub async fn get_account(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant, &headers).await?;
    let totp = state
        .store
        .totp_secret(&tenant, account.account_id())
        .await?
        .is_some();
    Ok(Json(json!({
        "id": account.account_id().to_typed_string(),
        "email": account.primary_email,
        "display_name": account.display_name,
        "mfa": { "totp": totp },
    })))
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
    state.drop_totp_enrollment(account.id).await;
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
}
