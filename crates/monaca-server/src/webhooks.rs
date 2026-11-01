//! Tenant webhooks — docs/contracts/m0.md §6.2, §8.1.
//!
//! A webhook is an outbound subscription to audit actions. When the server appends a matching
//! event it posts the event to the tenant's endpoint, signed with a tenant-specific key. Delivery
//! happens after the audit row is committed, in a detached task: a slow or dead endpoint must
//! never delay the request that produced the event.
//!
//! The signing key is sealed at rest (like every credential blob). It is returned once when the
//! webhook is created and again when it is rotated; a list never echoes it, so a stolen console
//! session cannot read every tenant's keys.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use monaca_audit::{AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{generate_challenge, open, seal, KeyProvider};
use monaca_oidc::is_absolute_http_url;
use monaca_store::{Store, WebhookDeliveryRow, WebhookRow};
use monaca_types::{EventId, TenantId, TypedId, WebhookDeliveryId, WebhookId};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// Audit actions a tenant may subscribe to.
///
/// These are the actions appended through [`AppState::audit_tenant`] and
/// [`AppState::audit_org`]. Actions written straight into an org schema inside a business
/// transaction (member, agent and grant changes) are not in this catalog yet: subscribing to them
/// would promise a delivery the server cannot make.
pub const WEBHOOK_EVENTS: &[&str] = &[
    "account.created",
    "account.deleted",
    "account.suspended",
    "account.reactivated",
    "account.security_changed",
    "client.created",
    "client.updated",
    "client.secret_rotated",
    "client.deleted",
    "connector.created",
    "connector.deleted",
    "sso_connector.created",
    "sso_connector.deleted",
    "interaction.sign_in.succeeded",
    "interaction.sign_in.failed",
    "org.created",
    "org.archived",
    "org.reactivated",
    "org.domain.added",
    "org.domain.removed",
    "org.invitation.created",
    "org.invitation.revoked",
    "resource.created",
    "resource.updated",
    "resource.deleted",
    "role.created",
    "role.deleted",
    "session.logout",
    "session.revoked",
    "session.revoked_all",
    "sign_in_experience.updated",
    "webhook.created",
    "webhook.updated",
    "webhook.deleted",
    "webhook.secret_rotated",
];

/// Attempts per delivery. A transient outage should not lose the event; a dead endpoint should not
/// keep a task alive forever.
const MAX_ATTEMPTS: u32 = 3;

/// Pause before the second and third attempt.
const RETRY_DELAYS_MS: [u64; 2] = [500, 1_500];

/// The header carrying `sha256=<hex HMAC of the raw body>`.
pub const SIGNATURE_HEADER: &str = "x-monaca-signature";

/// The header naming the audit action, so a receiver can route without parsing first.
pub const EVENT_HEADER: &str = "x-monaca-event";

/// `POST /v1/webhooks` body.
#[derive(Debug, Deserialize)]
pub struct CreateWebhookBody {
    /// Absolute http(s) endpoint.
    pub url: String,
    /// Audit actions to deliver.
    pub events: Vec<String>,
}

/// `PATCH /v1/webhooks/{webhook}` body. Every member is optional; at least one is required.
#[derive(Debug, Deserialize)]
pub struct UpdateWebhookBody {
    /// New endpoint.
    pub url: Option<String>,
    /// Replacement subscription set.
    pub events: Option<Vec<String>>,
    /// Pause or resume deliveries.
    pub enabled: Option<bool>,
}

/// `GET /v1/webhooks/{webhook}/deliveries` query.
#[derive(Debug, Deserialize)]
pub struct DeliveriesQuery {
    /// Page size, default 50, max 200.
    pub limit: Option<i64>,
}

/// `GET /v1/webhooks` — every subscription the tenant configured.
pub async fn list_webhooks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.webhooks(&tenant).await?;
    let items: Vec<Value> = rows.iter().map(webhook_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/webhooks` — subscribe an endpoint.
pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateWebhookBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let url = check_endpoint(&body.url)?;
    let events = check_events(&body.events)?;

    let secret = new_secret();
    let sealed = seal(&state.tenant_dek(&tenant)?, secret.as_bytes()).map_err(ApiError::internal)?;
    let row = state
        .store
        .create_webhook(&tenant, url, &events, &sealed)
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "webhook.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "webhook_id": WebhookId::from_uuid(row.id).to_typed_string(),
            "url": row.url,
            "events": row.events,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append webhook.created audit event");
    }

    // The secret is shown exactly here (and on rotation); it is never part of a list.
    let mut value = webhook_json(&row);
    value["secret"] = json!(secret);
    Ok((StatusCode::CREATED, Json(value)).into_response())
}

/// `PATCH /v1/webhooks/{webhook}` — change the endpoint, the subscriptions or the pause state.
pub async fn update_webhook(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateWebhookBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let id = parse_webhook_id(&id)?;
    if body.url.is_none() && body.events.is_none() && body.enabled.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one field must be present",
        ));
    }
    let url = body.url.as_deref().map(check_endpoint).transpose()?;
    let events = body.events.as_deref().map(check_events).transpose()?;

    let row = state
        .store
        .update_webhook(&tenant, id, url, events.as_deref(), body.enabled)
        .await?
        .ok_or_else(|| ApiError::not_found("webhook"))?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "webhook.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "webhook_id": id.to_typed_string(),
            "url": row.url,
            "events": row.events,
            "enabled": row.enabled,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append webhook.updated audit event");
    }

    Ok(Json(webhook_json(&row)))
}

/// `POST /v1/webhooks/{webhook}/secret` — replace the signing key and return the new one.
pub async fn rotate_webhook_secret(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let id = parse_webhook_id(&id)?;

    let secret = new_secret();
    let sealed = seal(&state.tenant_dek(&tenant)?, secret.as_bytes()).map_err(ApiError::internal)?;
    let row = state
        .store
        .set_webhook_secret(&tenant, id, &sealed)
        .await?
        .ok_or_else(|| ApiError::not_found("webhook"))?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "webhook.secret_rotated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "webhook_id": id.to_typed_string() }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append webhook.secret_rotated audit event");
    }

    Ok(Json(json!({ "id": id.to_typed_string(), "secret": secret })))
}

/// `DELETE /v1/webhooks/{webhook}` — remove the subscription and its delivery history.
pub async fn delete_webhook(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let id = parse_webhook_id(&id)?;
    if !state.store.delete_webhook(&tenant, id).await? {
        return Err(ApiError::not_found("webhook"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "webhook.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: monaca_audit::AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "webhook_id": id.to_typed_string() }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append webhook.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/webhooks/{webhook}/deliveries` — the recent outcomes of one subscription.
pub async fn list_webhook_deliveries(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<DeliveriesQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let id = parse_webhook_id(&id)?;
    if state.store.webhook(&tenant, id).await?.is_none() {
        return Err(ApiError::not_found("webhook"));
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let rows = state.store.webhook_deliveries(&tenant, id, limit).await?;
    let items: Vec<Value> = rows.iter().map(delivery_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

fn parse_webhook_id(raw: &str) -> Result<WebhookId, ApiError> {
    WebhookId::parse(raw)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a webhook id"))
}

fn check_endpoint(raw: &str) -> Result<&str, ApiError> {
    let url = raw.trim();
    if !is_absolute_http_url(url) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "url must be an absolute http(s) URL",
        ));
    }
    Ok(url)
}

/// Trim and de-duplicate a subscription set, and refuse anything outside the catalog.
fn check_events(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut events: Vec<String> = Vec::new();
    for event in raw {
        let event = event.trim();
        if !WEBHOOK_EVENTS.contains(&event) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("`{event}` is not a subscribable event"),
            ));
        }
        if !events.iter().any(|existing| existing == event) {
            events.push(event.to_owned());
        }
    }
    if events.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "events must name at least one audit action",
        ));
    }
    Ok(events)
}

/// `whsec_` plus 64 lowercase hex characters — 256 bits from the OS.
fn new_secret() -> String {
    format!("whsec_{}", hex::encode(generate_challenge()))
}

/// The HMAC-SHA256 over the exact request body, in the `sha256=<hex>` form.
pub fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// The JSON body posted to the endpoint. See §6.2 for the shape.
pub fn webhook_body(row: &WebhookRow, event: &AuditEvent) -> Value {
    json!({
        "hook_id": WebhookId::from_uuid(row.id).to_typed_string(),
        "event": event.action,
        "created_at": ts(event.at),
        "data": event,
    })
}

/// Post a matching event to every enabled subscription, then return.
///
/// The task owns everything it needs, so the request that produced the event can finish first.
pub async fn dispatch(
    state: &Arc<AppState>,
    tenant_id: TenantId,
    db_name: &str,
    event: &AuditEvent,
) {
    let hooks = match state.store.webhooks_for_event(db_name, &event.action).await {
        Ok(hooks) => hooks,
        Err(err) => {
            tracing::warn!(%err, "could not read webhook subscriptions");
            return;
        }
    };
    if hooks.is_empty() {
        return;
    }
    let Some(dek) = state.keys.tenant_dek(&tenant_id) else {
        tracing::warn!("tenant DEK missing; skipping webhook deliveries");
        return;
    };

    for hook in hooks {
        let secret = match open(&dek, &hook.secret_enc).ok().and_then(|bytes| String::from_utf8(bytes).ok()) {
            Some(secret) => secret,
            None => {
                tracing::warn!(webhook = %WebhookId::from_uuid(hook.id), "webhook signing key could not be opened");
                continue;
            }
        };
        let body = match serde_json::to_vec(&webhook_body(&hook, event)) {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(%err, "webhook body could not be serialized");
                continue;
            }
        };

        let http = state.http.clone();
        let store = Arc::clone(&state.store);
        let db_name = db_name.to_owned();
        let url = hook.url.clone();
        let action = event.action.clone();
        let webhook_id = hook.id;
        tokio::spawn(async move {
            deliver(http, store, db_name, url, secret, body, webhook_id, action).await;
        });
    }
}

/// Post one payload, retrying twice, and record the final outcome.
#[allow(clippy::too_many_arguments)]
async fn deliver(
    http: reqwest::Client,
    store: Arc<Store>,
    db_name: String,
    url: String,
    secret: String,
    body: Vec<u8>,
    webhook_id: Uuid,
    event: String,
) {
    let signature = signature(&secret, &body);
    let mut status_code = None;
    let mut error = None;
    let mut success = false;
    let mut attempts = 0;

    for attempt in 0..MAX_ATTEMPTS {
        attempts += 1;
        let response = http
            .post(&url)
            .header("content-type", "application/json")
            .header("user-agent", "monaca-webhook/0.1")
            .header(EVENT_HEADER, &event)
            .header(SIGNATURE_HEADER, &signature)
            .body(body.clone())
            .send()
            .await;
        match response {
            Ok(response) => {
                let code = response.status().as_u16();
                status_code = Some(i32::from(code));
                if response.status().is_success() {
                    success = true;
                    error = None;
                    break;
                }
                error = Some(format!("the endpoint answered {code}"));
            }
            Err(err) => {
                status_code = None;
                error = Some(err.to_string());
            }
        }
        if attempt + 1 < MAX_ATTEMPTS {
            let delay = RETRY_DELAYS_MS[attempt as usize];
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    if success {
        tracing::info!(%event, attempts, "webhook delivered");
    } else {
        tracing::warn!(%event, attempts, error = ?error, "webhook delivery failed");
    }
    if let Err(err) = store
        .record_webhook_delivery(
            &db_name,
            webhook_id,
            &event,
            status_code,
            success,
            i32::try_from(attempts).unwrap_or(i32::MAX),
            error.as_deref(),
        )
        .await
    {
        tracing::warn!(%err, "could not record webhook delivery");
    }
}

fn webhook_json(row: &WebhookRow) -> Value {
    json!({
        "id": WebhookId::from_uuid(row.id).to_typed_string(),
        "url": row.url,
        "events": row.events,
        "enabled": row.enabled,
        "created_at": ts(row.created_at),
        "updated_at": ts(row.updated_at),
    })
}

fn delivery_json(row: &WebhookDeliveryRow) -> Value {
    json!({
        "id": WebhookDeliveryId::from_uuid(row.id).to_typed_string(),
        "event": row.event,
        "status_code": row.status_code,
        "success": row.success,
        "attempts": row.attempts,
        "error": row.error,
        "created_at": ts(row.created_at),
    })
}
