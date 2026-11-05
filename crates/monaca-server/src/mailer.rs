//! Outbound mail delivery through the tenant's HTTP connector — docs/contracts/m0.md §6.3.
//!
//! The outbox is the queue and `tenant.email_connector` is the route. This loop claims unpublished
//! `mail.verification` rows, posts the rendered copy to the tenant's endpoint, and marks a row
//! published only after a 2xx. A tenant with no connector keeps its rows untouched, so `/internal/mail`
//! and the acceptance walk-through still read exactly what the server would have mailed.
//!
//! Templates are not this module's business: `email_templates` already rendered subject and body
//! into the payload. Delivery is also not a mail transfer agent — a provider owns queuing, SPF and
//! bounces; the server only owns the HTTP call and the attempt counter.

use std::sync::Arc;
use std::time::{Duration, Instant};

use monaca_store::{EmailConnectorRow, OutboxMailRow, TenantRow};
use serde_json::{Value, json};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

use crate::state::AppState;

/// How often a worker looks for new mail.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long one tick may keep *starting* tenant visits. Visits already running finish within one
/// [`DELIVERY_TIMEOUT`], so a tick is bounded by this plus that timeout, instead of by the tenant
/// count.
const TICK_BUDGET: Duration = Duration::from_secs(5);

/// The longest one provider call may take. The shared client has a 10 s timeout; the mailer's own
/// calls are tighter so a hanging provider cannot hold a worker for the whole tick.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Rows claimed per tenant per tick. Bounded so one backlog cannot starve other tenants.
const BATCH: i64 = 20;

/// Attempts before a row is abandoned. The payload stays in the outbox for inspection.
const MAX_ATTEMPTS: i32 = 5;

/// Start the single delivery loop for this process.
///
/// One worker is deliberate: the server is one process in M0, and `SKIP LOCKED` keeps a second
/// process from claiming the same row if that changes. The task ends with the runtime, so a
/// graceful shutdown does not leave a detached sender behind.
pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut cursor = 0usize;
        loop {
            ticker.tick().await;
            let started = Instant::now();
            let visited = deliver_pending(&state, &mut cursor).await;
            state.metrics.record_mailer_tick(started.elapsed(), visited);
        }
    });
}

/// One pass over the tenants that have a connector.
///
/// The cursor makes a partial pass resumable: when the tick budget runs out, the next tick starts
/// at the first tenant this pass did not visit, so a tenant cannot be skipped forever because it
/// sorts late. Tenants are visited with `MONACA_MAILER_TENANT_CONCURRENCY` workers; a slow
/// provider occupies one worker, not the tick.
async fn deliver_pending(state: &Arc<AppState>, cursor: &mut usize) -> usize {
    let tenants = match state.mailer_store.tenants_with_email_connector().await {
        Ok(tenants) => tenants,
        Err(err) => {
            tracing::warn!(%err, "mailer could not list indexed tenants");
            return 0;
        }
    };
    if tenants.is_empty() {
        *cursor = 0;
        return 0;
    }

    let len = tenants.len();
    let start = *cursor % len;
    let deadline = Instant::now() + TICK_BUDGET;
    let concurrency = state.config.mailer_tenant_concurrency;
    let mut tasks = JoinSet::new();
    let mut started = 0usize;

    while started < len && Instant::now() < deadline {
        if tasks.len() >= concurrency
            && let Some(result) = tasks.join_next().await
        {
            log_join(result);
        }
        let tenant = tenants[(start + started) % len].clone();
        let state = Arc::clone(state);
        tasks.spawn(async move { deliver_tenant(&state, &tenant, deadline).await });
        started += 1;
    }

    *cursor = (start + started) % len;
    while let Some(result) = tasks.join_next().await {
        log_join(result);
    }
    started
}

fn log_join(result: Result<Result<(), monaca_store::StoreError>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(%err, "mailer skipped a tenant"),
        Err(err) => tracing::warn!(%err, "mailer task did not finish"),
    }
}

/// Deliver up to [`BATCH`] rows for one tenant, one request at a time.
///
/// A row is claimed immediately before its send, not in a batch: a row claimed and then skipped
/// because the deadline arrived would consume an attempt without a provider call and could reach
/// [`MAX_ATTEMPTS`] without ever being tried.
async fn deliver_tenant(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    deadline: Instant,
) -> Result<(), monaca_store::StoreError> {
    let Some(connector) = state.mailer_store.email_connector(tenant).await? else {
        return Ok(());
    };
    if !connector.enabled {
        return Ok(());
    }
    let secret = match open_secret(state, tenant, &connector) {
        Ok(secret) => secret,
        Err(err) => {
            tracing::warn!(%err, tenant = %tenant.slug, "mailer cannot open the connector secret");
            return Ok(());
        }
    };

    for _ in 0..BATCH {
        if Instant::now() >= deadline {
            break;
        }
        let rows = state
            .mailer_store
            .outbox_claim_mail(tenant, 1, MAX_ATTEMPTS)
            .await?;
        let Some(row) = rows.into_iter().next() else {
            break;
        };
        match deliver_one(state, tenant, &connector, secret.as_deref(), &row).await {
            Ok(status) => match state
                .mailer_store
                .outbox_mark_published(tenant, row.id)
                .await
            {
                Ok(()) => {
                    let age_ms = (state.now() - row.created_at).whole_milliseconds().max(0);
                    tracing::info!(
                        tenant = %tenant.slug,
                        outbox_id = %row.id,
                        attempts = row.attempts,
                        age_ms,
                        %status,
                        "mail delivered"
                    );
                }
                Err(err) => {
                    // The provider already accepted it. Leaving the row unpublished can duplicate
                    // the mail on the next tick; the payload carries its id so a receiver can drop it.
                    tracing::warn!(
                        %err,
                        tenant = %tenant.slug,
                        outbox_id = %row.id,
                        "mail delivered but the outbox row could not be marked published"
                    );
                }
            },
            Err(err) => tracing::warn!(
                tenant = %tenant.slug,
                outbox_id = %row.id,
                attempts = row.attempts,
                max_attempts = MAX_ATTEMPTS,
                "mail delivery failed: {err}"
            ),
        }
    }
    Ok(())
}

/// The connector's bearer token, when one is stored.
fn open_secret(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &EmailConnectorRow,
) -> Result<Option<String>, String> {
    let Some(sealed) = connector.secret_enc.as_deref() else {
        return Ok(None);
    };
    let opened = state
        .open_tenant_id(&tenant.tenant_id(), sealed)
        .map_err(|err| err.to_string())?;
    let secret =
        String::from_utf8(opened).map_err(|_| "the stored secret is not UTF-8".to_owned())?;
    Ok(Some(secret))
}

/// Post one row; a 2xx is success, anything else is a retryable failure.
async fn deliver_one(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &EmailConnectorRow,
    secret: Option<&str>,
    row: &OutboxMailRow,
) -> Result<reqwest::StatusCode, String> {
    let body = mail_body(tenant, connector, row.id, &row.payload);
    let mut request = state.http.post(&connector.endpoint).json(&body);
    if let Some(secret) = secret {
        request = request.bearer_auth(secret);
    }
    let response = request
        .timeout(DELIVERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("provider answered {status}"));
    }
    Ok(status)
}

/// The JSON body a provider receives. `text` is the already-rendered plain-text copy; `id` is the
/// outbox row so a retry after a lost 2xx can be de-duplicated by the receiver.
fn mail_body(
    tenant: &TenantRow,
    connector: &EmailConnectorRow,
    id: Uuid,
    payload: &Value,
) -> Value {
    json!({
        "id": id.to_string(),
        "tenant": tenant.slug,
        "purpose": payload.get("purpose"),
        "to": payload.get("to"),
        "subject": payload.get("subject"),
        "text": payload.get("body"),
        "from": connector.from_address,
        "from_name": connector.from_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use monaca_store::{EmailConnectorRow, TenantRow};
    use time::OffsetDateTime;

    fn tenant() -> TenantRow {
        TenantRow {
            id: Uuid::now_v7(),
            slug: "demo".into(),
            short: "demo".into(),
            db_name: "mt_demo".into(),
            issuer: "https://sso.example/t/demo".into(),
            state: "active".into(),
        }
    }

    fn connector() -> EmailConnectorRow {
        EmailConnectorRow {
            provider: "http".into(),
            endpoint: "https://mail.example/send".into(),
            from_address: "no-reply@example.com".into(),
            from_name: Some("Demo".into()),
            secret_enc: None,
            enabled: true,
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn the_provider_body_carries_the_rendered_copy_and_route() {
        let id = Uuid::now_v7();
        let payload = json!({
            "to": "person@example.com",
            "purpose": "sign_up",
            "subject": "Your demo code",
            "body": "Enter 123456.",
        });
        let body = mail_body(&tenant(), &connector(), id, &payload);
        assert_eq!(body["id"], id.to_string());
        assert_eq!(body["tenant"], "demo");
        assert_eq!(body["purpose"], "sign_up");
        assert_eq!(body["to"], "person@example.com");
        assert_eq!(body["subject"], "Your demo code");
        assert_eq!(body["text"], "Enter 123456.");
        assert_eq!(body["from"], "no-reply@example.com");
        assert_eq!(body["from_name"], "Demo");
    }
}
