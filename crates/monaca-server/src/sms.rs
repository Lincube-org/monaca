//! SMS verification codes — docs/contracts/m0.md §6.1/§6.3.
//!
//! The request path is channel-independent above the transport: the same `verification_codes`
//! table holds the single-use code, the same `outbox` holds the rendered message, and the
//! per-address cooldown is a `tenant.rate_limit_counters` row, so every server instance enforces
//! the same window. Only delivery differs: the mailer hands `sms.verification` rows to the
//! tenant's SMS connector.
//!
//! Fail-closed: a tenant with no enabled SMS connector is refused before a code is minted, instead
//! of queueing mail nobody can send.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use monaca_crypto::{DEFAULT_CODE_DIGITS, generate_numeric_code, hash_secret, verify_secret};
use monaca_store::topics;
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use crate::client_ip::ClientIp;
use crate::delivery::SMS;
use crate::error::{ApiError, kinds};
use crate::message_templates;
use crate::state::AppState;

/// The `verification_codes.purpose` this endpoint writes; separate from every email purpose.
const PURPOSE: &str = "sms_verification";
/// Wrong guesses a code survives.
const MAX_ATTEMPTS: i32 = 5;

/// `POST /t/{tenant}/verification/sms` body.
#[derive(Debug, Deserialize)]
pub struct SmsRequestBody {
    /// The recipient number; an optional leading `+` is kept, spaces are refused.
    pub phone: String,
    /// The recipient's language for this message; the tenant default and then English follow.
    #[serde(default)]
    pub locale: Option<String>,
}

/// `POST /t/{tenant}/verification/sms/verify` body.
#[derive(Debug, Deserialize)]
pub struct SmsVerifyBody {
    /// The same number the code was sent to.
    pub phone: String,
    /// The six-digit code.
    pub code: String,
}

/// Mint a code, enforce the shared per-address cooldown, render the localized text and queue it.
pub async fn request_code(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    client_ip: ClientIp,
    Json(body): Json<SmsRequestBody>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    state
        .enforce_ip_rate_limit(client_ip.0, "sms")
        .await?;
    let phone = normalise_phone(&body.phone)?;

    if state
        .store
        .delivery_connector(&tenant, SMS)
        .await?
        .filter(|connector| connector.enabled)
        .is_none()
    {
        return Err(ApiError::problem(
            kinds::SMS_NOT_CONFIGURED,
            "this tenant has no enabled SMS connector",
        ));
    }

    let now = state.now();
    let code = generate_numeric_code(DEFAULT_CODE_DIGITS);
    let expires_at = now + Duration::seconds(state.config.sms_code_ttl_secs);
    let expires_in = (state.config.sms_code_ttl_secs / 60).max(1).to_string();

    // Render before touching the counter or the code table: a missing template must fail loudly
    // and must not consume the recipient's window.
    let (subject, text) = message_templates::message_copy(
        &state,
        &tenant,
        PURPOSE,
        body.locale.as_deref(),
        &[
            ("tenant", tenant.slug.as_str()),
            ("code", code.as_str()),
            ("expires_in", expires_in.as_str()),
        ],
    )
    .await?;

    // The cooldown is the same fixed-window counter the request-path gates use, so a second
    // instance sees the first instance's send immediately.
    let (count, _window_start) = state
        .store
        .rate_limit_hit(
            &tenant,
            &cooldown_key(&phone),
            state.config.sms_resend_secs as u32,
            now,
        )
        .await?;
    if count > 1 {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "a code was requested moments ago; try again shortly",
        ));
    }

    state
        .store
        .insert_verification_code(&tenant, PURPOSE, &phone, &hash_secret(&code), expires_at)
        .await?;

    let mut tx = state.store.begin_tenant(&tenant).await?;
    state
        .store
        .outbox_append(
            &mut *tx,
            topics::SMS,
            &json!({
                "to": phone,
                "purpose": PURPOSE,
                "subject": subject,
                "body": text,
                "code": code,
                "expires_at": expires_at.unix_timestamp(),
            }),
        )
        .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "verification_required": true,
        "expires_in": state.config.sms_code_ttl_secs,
    })))
}

/// Redeem a code. An expired code names expiry; a wrong one is indistinguishable from an unknown
/// one, so guessing learns nothing beyond the attempt budget.
pub async fn verify_code(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    client_ip: ClientIp,
    Json(body): Json<SmsVerifyBody>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    state
        .enforce_ip_rate_limit(client_ip.0, "sms")
        .await?;
    let phone = normalise_phone(&body.phone)?;
    let invalid = || {
        ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        )
    };

    let Some(row) = state
        .store
        .verification_code_latest(&tenant, PURPOSE, &phone)
        .await?
    else {
        return Err(invalid());
    };
    if row.expires_at <= state.now() {
        return Err(ApiError::problem(
            kinds::VERIFICATION_CODE_EXPIRED,
            "the code has expired; request a new one",
        ));
    }
    if row.attempts >= MAX_ATTEMPTS {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "too many guesses; request a new code",
        ));
    }
    let Some(attempts) = state
        .store
        .verification_code_attempt(&tenant, row.id)
        .await?
    else {
        return Err(invalid());
    };
    if attempts > MAX_ATTEMPTS {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "too many guesses; request a new code",
        ));
    }
    if !verify_secret(body.code.trim(), &row.code_hash) {
        return Err(invalid());
    }
    if !state
        .store
        .consume_verification_code(&tenant, row.id)
        .await?
    {
        return Err(invalid());
    }
    Ok(Json(json!({ "verified": true })))
}

/// The fixed-window bucket for one recipient. Addresses are normalised before hashing, so `+1…`
/// and `1…` cannot hold two windows.
fn cooldown_key(phone: &str) -> String {
    format!("sms|verification|{phone}")
}

/// A phone number without spaces or formatting, keeping an optional leading `+`.
fn normalise_phone(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    let (prefix, digits) = match trimmed.strip_prefix('+') {
        Some(digits) => ("+", digits),
        None => ("", trimmed),
    };
    if !(6..=15).contains(&digits.len()) || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "phone must be 6–15 digits with an optional leading `+`",
        ));
    }
    Ok(format!("{prefix}{digits}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_numbers_keep_at_most_one_plus_and_no_formatting() {
        assert_eq!(normalise_phone("+15551234567").expect("plus"), "+15551234567");
        assert_eq!(normalise_phone(" 15551234567 ").expect("trim"), "15551234567");
        assert!(normalise_phone("+1 555 123 4567").is_err());
        assert!(normalise_phone("12345").is_err());
        assert!(normalise_phone("+1555123456789012").is_err());
        assert!(normalise_phone("1555abc").is_err());
    }
}
