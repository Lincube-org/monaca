//! `GET/PATCH/DELETE /v1/email-connector` — the tenant's outbound mail route (§6.3).
//!
//! A tenant has at most one route. The response never echoes the bearer token, only whether one
//! is stored, mirroring the webhook secret policy: a stolen console session must not read a
//! credential that can send mail as the tenant. Delivery itself lives in [`crate::mailer`].

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::seal;
use monaca_oidc::is_absolute_http_url;
use monaca_store::EmailConnectorRow;
use monaca_types::EventId;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// A route as an administrator submits it. `secret` omitted keeps the stored one; an empty string
/// clears it. The route fields replace the previous route wholesale.
#[derive(Debug, Deserialize)]
pub struct UpdateEmailConnectorBody {
    /// Delivery mechanism; only `http` is implemented.
    pub provider: String,
    /// Absolute http(s) URL that receives the JSON payload.
    pub endpoint: String,
    /// Envelope sender.
    pub from_address: String,
    /// Optional display name; omitted or empty means no name.
    #[serde(default)]
    pub from_name: Option<String>,
    /// Bearer token for the endpoint; omitted preserves, empty clears.
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
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let row = state.store.email_connector(&tenant).await?;
    Ok(Json(connector_json(row.as_ref())))
}

/// `PATCH /v1/email-connector` — create or replace the route.
pub async fn update_email_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateEmailConnectorBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;

    let provider = body.provider.trim();
    if provider != "http" {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "provider must be `http`",
        ));
    }

    let endpoint = body.endpoint.trim();
    if endpoint.len() > 2000 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "endpoint must be at most 2000 characters",
        ));
    }
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

    let from_address = body.from_address.trim();
    if !from_address.contains('@') || from_address.len() < 3 || from_address.len() > 320 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "from_address must contain `@` and be at most 320 characters",
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
    let from_name = from_name.filter(|name| !name.is_empty());

    let existing = state.store.email_connector(&tenant).await?;
    let (secret_enc, set_secret) = match body.secret.as_deref() {
        None => (
            existing.as_ref().and_then(|row| row.secret_enc.clone()),
            false,
        ),
        Some("") => (None, true),
        Some(secret) => {
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
            let sealed =
                seal(&state.tenant_dek(&tenant)?, secret.as_bytes()).map_err(ApiError::internal)?;
            (Some(sealed), true)
        }
    };

    // Index before the tenant-database write: if the upsert fails, the worst case is a tenant the
    // mailer queries and finds without a connector, not a connector it never discovers.
    state.store.mark_email_connector_present(&tenant).await?;
    let row = state
        .store
        .upsert_email_connector(
            &tenant,
            provider,
            endpoint,
            from_address,
            from_name,
            secret_enc.as_deref(),
            set_secret,
            body.enabled,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "email_connector.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "provider": row.provider,
            "endpoint": row.endpoint,
            "from_address": row.from_address,
            "from_name": row.from_name,
            "enabled": row.enabled,
            "secret_set": row.secret_enc.is_some(),
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append email_connector.updated audit event");
    }

    Ok(Json(connector_json(Some(&row))))
}

/// `DELETE /v1/email-connector` — remove the route. Idempotent, and queued mail is left intact.
pub async fn delete_email_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let deleted = state.store.delete_email_connector(&tenant).await?;
    // Delete the tenant row first: a stale index entry only costs the mailer one query, while a
    // missing entry would stop delivery. `migrate` reconciles any entry left behind here.
    if let Err(err) = state.store.forget_email_connector_index(&tenant).await {
        tracing::warn!(%err, "could not remove the email-connector index entry");
    }
    if !deleted {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "email_connector.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({}),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append email_connector.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The console shape: `configured:false` when nothing is stored, and never the secret itself.
fn connector_json(row: Option<&EmailConnectorRow>) -> Value {
    match row {
        None => json!({
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
