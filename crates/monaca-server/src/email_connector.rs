//! `/v1/email-connector` and `/v1/sms-connector` — the tenant's outbound routes (§6.3).
//!
//! A tenant has at most one route per channel. The response never echoes the credential, only
//! whether one is stored, mirroring the webhook secret policy: a stolen console session must not
//! read a secret that can send messages as the tenant. Delivery itself lives in
//! [`crate::mailer`]/[`crate::delivery`].

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::seal;
use monaca_oidc::is_absolute_http_url;
use monaca_store::DeliveryConnectorRow;
use monaca_types::EventId;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::delivery::{EMAIL, SMS};
use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// A route as an administrator submits it. `secret` omitted keeps the stored one; an empty string
/// clears it. The route fields replace the previous route wholesale.
#[derive(Debug, Deserialize)]
pub struct UpdateConnectorBody {
    /// Delivery mechanism: `http`|`smtp` for email, `http`|`twilio` for SMS.
    pub provider: String,
    /// Absolute http(s) URL, or an SMTP URL for the `smtp` provider.
    pub endpoint: String,
    /// Envelope sender for email, sender id/number for SMS.
    pub from_address: String,
    /// Optional display name; omitted or empty means no name.
    #[serde(default)]
    pub from_name: Option<String>,
    /// Credential blob; omitted preserves, empty clears. Sealed before storage.
    #[serde(default)]
    pub secret: Option<String>,
    /// Pause switch; omitted preserves the current value.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// `GET /v1/email-connector` — never returns the secret.
pub async fn get_email_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    get_connector(&state, &headers, EMAIL).await
}

/// `PATCH /v1/email-connector` — create or replace the email route.
pub async fn update_email_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateConnectorBody>,
) -> Result<Json<Value>, ApiError> {
    update_connector(&state, &headers, EMAIL, body).await
}

/// `DELETE /v1/email-connector` — remove the email route.
pub async fn delete_email_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    delete_connector(&state, &headers, EMAIL).await
}

/// `GET /v1/sms-connector` — never returns the secret.
pub async fn get_sms_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    get_connector(&state, &headers, SMS).await
}

/// `PATCH /v1/sms-connector` — create or replace the SMS route.
pub async fn update_sms_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateConnectorBody>,
) -> Result<Json<Value>, ApiError> {
    update_connector(&state, &headers, SMS, body).await
}

/// `DELETE /v1/sms-connector` — remove the SMS route.
pub async fn delete_sms_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    delete_connector(&state, &headers, SMS).await
}

async fn get_connector(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    channel: &str,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(state, headers).await?;
    let row = state.store.delivery_connector(&tenant, channel).await?;
    Ok(Json(connector_json(channel, row.as_ref())))
}

async fn update_connector(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    channel: &str,
    body: UpdateConnectorBody,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(state, headers).await?;
    let (provider, endpoint, from_address, from_name) =
        validate_route(state, channel, &body)?;
    let secret_enc = seal_secret(state, &tenant, body.secret.as_deref(), &provider)?;
    let set_secret = body.secret.is_some();
    let existing = state.store.delivery_connector(&tenant, channel).await?;
    let secret_enc = if set_secret {
        secret_enc
    } else {
        existing.as_ref().and_then(|row| row.secret_enc.clone())
    };

    // Index before the tenant-database write: if the upsert fails, the worst case is a tenant the
    // mailer queries and finds without a connector, not a connector it never discovers.
    state
        .store
        .mark_delivery_connector_present(&tenant)
        .await?;
    let row = state
        .store
        .upsert_delivery_connector(
            &tenant,
            channel,
            &provider,
            &endpoint,
            &from_address,
            from_name.as_deref(),
            secret_enc.as_deref(),
            set_secret,
            body.enabled,
        )
        .await?;

    audit_connector(
        state,
        &tenant,
        &admin,
        channel,
        "updated",
        &row,
    )
    .await;

    Ok(Json(connector_json(channel, Some(&row))))
}

async fn delete_connector(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    channel: &str,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(state, headers).await?;
    let deleted = state.store.delete_delivery_connector(&tenant, channel).await?;
    // Reconcile rather than removing the index outright: the other channel may still be routed.
    if let Err(err) = state
        .store
        .reconcile_delivery_connector_index(&tenant)
        .await
    {
        tracing::warn!(%err, "could not reconcile the delivery-connector index");
    }
    if !deleted {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    audit_connector_action(state, &tenant, &admin, channel, "deleted", json!({ "channel": channel }))
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Validate the route fields for one channel and return them trimmed.
fn validate_route(
    state: &AppState,
    channel: &str,
    body: &UpdateConnectorBody,
) -> Result<(String, String, String, Option<String>), ApiError> {
    let provider = body.provider.trim();
    let endpoint = body.endpoint.trim();
    if endpoint.len() > 2000 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "endpoint must be at most 2000 characters",
        ));
    }

    match channel {
        EMAIL => {
            if !matches!(provider, "http" | "smtp") {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "provider must be `http` or `smtp`",
                ));
            }
            if provider == "http" {
                if !is_absolute_http_url(endpoint) {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        "endpoint must be an absolute http(s) URL",
                    ));
                }
                if has_userinfo(endpoint) {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        "endpoint must not embed credentials; use the secret field",
                    ));
                }
            } else {
                crate::delivery::validate_smtp_endpoint(endpoint).map_err(|why| {
                    ApiError::problem(kinds::INVALID_REQUEST, why)
                })?;
            }
        }
        SMS => {
            if !matches!(provider, "http" | "twilio") {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "provider must be `http` or `twilio`",
                ));
            }
            if provider == "http" {
                if !is_absolute_http_url(endpoint) {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        "endpoint must be an absolute http(s) URL",
                    ));
                }
                if has_userinfo(endpoint) {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        "endpoint must not embed credentials; use the secret field",
                    ));
                }
            } else {
                crate::delivery::validate_twilio_endpoint(endpoint, state.config.production)
                    .map_err(|why| ApiError::problem(kinds::INVALID_REQUEST, why))?;
            }
        }
        _ => return Err(ApiError::internal("unknown delivery channel")),
    }

    let from_address = body.from_address.trim();
    if from_address.is_empty() || from_address.len() > 320 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "from_address must be 1–320 characters",
        ));
    }
    if channel == EMAIL
        && (!from_address.contains('@') || from_address.len() < 3)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "from_address must contain `@`",
        ));
    }
    if from_address
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "from_address must not contain whitespace or control characters",
        ));
    }

    let from_name = body.from_name.as_deref().map(str::trim);
    if let Some(name) = from_name {
        if name.len() > 100 {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "from_name must be at most 100 characters",
            ));
        }
        if name.chars().any(char::is_control) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "from_name must not contain control characters",
            ));
        }
    }
    let from_name = from_name.filter(|name| !name.is_empty()).map(str::to_owned);

    Ok((provider.to_owned(), endpoint.to_owned(), from_address.to_owned(), from_name))
}

/// Seal the submitted credential, validating its shape first.
fn seal_secret(
    state: &Arc<AppState>,
    tenant: &monaca_store::TenantRow,
    secret: Option<&str>,
    provider: &str,
) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    if secret.is_empty() {
        return Ok(None);
    }
    if secret.len() > 500 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "secret must be at most 500 characters",
        ));
    }
    if secret.chars().any(char::is_control) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "secret must not contain control characters",
        ));
    }
    if provider == "smtp" && !secret.contains(':') {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the SMTP secret must be `username:password`",
        ));
    }
    if provider == "twilio" && !secret.contains(':') {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the Twilio secret must be `account_sid:auth_token`",
        ));
    }
    let sealed = seal(&state.tenant_dek(tenant)?, secret.as_bytes()).map_err(ApiError::internal)?;
    Ok(Some(sealed))
}

/// Append the channel's audit event on the tenant chain.
async fn audit_connector(
    state: &Arc<AppState>,
    tenant: &monaca_store::TenantRow,
    admin: &crate::management::AdminPrincipal,
    channel: &str,
    verb: &str,
    row: &DeliveryConnectorRow,
) {
    audit_connector_action(
        state,
        tenant,
        admin,
        channel,
        verb,
        json!({
            "channel": channel,
            "provider": row.provider,
            "endpoint": row.endpoint,
            "from_address": row.from_address,
            "from_name": row.from_name,
            "enabled": row.enabled,
            "secret_set": row.secret_enc.is_some(),
        }),
    )
    .await;
}

/// Append one connector audit event with a pre-built payload.
async fn audit_connector_action(
    state: &Arc<AppState>,
    tenant: &monaca_store::TenantRow,
    admin: &crate::management::AdminPrincipal,
    channel: &str,
    verb: &str,
    payload: Value,
) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: format!("{channel}_connector.{verb}"),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload,
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append a connector audit event");
    }
}

/// The console shape: `configured:false` when nothing is stored, and never the secret itself.
fn connector_json(channel: &str, row: Option<&DeliveryConnectorRow>) -> Value {
    match row {
        None => json!({
            "channel": channel,
            "configured": false,
            "provider": null,
            "endpoint": null,
            "from_address": null,
            "from_name": null,
            "secret_set": false,
            "enabled": false,
            "updated_at": null,
        }),
        Some(row) => json!({
            "channel": row.channel,
            "configured": true,
            "provider": row.provider,
            "endpoint": row.endpoint,
            "from_address": row.from_address,
            "from_name": row.from_name,
            "secret_set": row.secret_enc.is_some(),
            "enabled": row.enabled,
            "updated_at": ts(row.updated_at),
        }),
    }
}

/// Whether an absolute URL carries `user:password@` before its path.
fn has_userinfo(url: &str) -> bool {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default()
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    authority.contains('@')
}

#[cfg(test)]
mod tests {
    use super::has_userinfo;

    #[test]
    fn embedded_credentials_are_detected() {
        assert!(has_userinfo("https://user:pass@mail.example/send"));
        assert!(has_userinfo("http://user@mail.example"));
        assert!(!has_userinfo("https://mail.example/send"));
        assert!(!has_userinfo("https://mail.example/path?to=a@b.example"));
    }
}
