//! Outbound delivery loop — docs/contracts/m0.md §6.3.
//!
//! The outbox is the queue and `tenant.delivery_connector` is the route, one route per channel.
//! This loop claims unpublished `mail.verification` and `sms.verification` rows, hands them to
//! [`crate::delivery::deliver`], and marks a row published only after the transport accepts it. A
//! tenant with no connector keeps its rows untouched, so `/internal/mail` still reads exactly what
//! the server would have sent.
//!
//! Retry state lives in the database: a claim increments `attempts` and schedules the next attempt
//! with a growing delay (5 s → 15 s → 45 s → 135 s, capped at 300 s), so a broken provider is not
//! hammered on every tick and two processes cannot send the same row.

use std::sync::Arc;
use std::time::{Duration, Instant};

use monaca_store::{DeliveryConnectorRow, TenantRow};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::delivery;
use crate::state::AppState;

/// How often a worker looks for new messages.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long one tick may keep *starting* tenant visits. Visits already running finish within one
/// [`delivery::DELIVERY_TIMEOUT`], so a tick is bounded by this plus that timeout, instead of by
/// the tenant count.
const TICK_BUDGET: Duration = Duration::from_secs(5);

/// Rows claimed per connector per tick. Bounded so one backlog cannot starve other tenants.
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

/// One pass over the tenants that have at least one connector.
///
/// The cursor makes a partial pass resumable: when the tick budget runs out, the next tick starts
/// at the first tenant this pass did not visit, so a tenant cannot be skipped forever because it
/// sorts late. Tenants are visited with `MONACA_MAILER_TENANT_CONCURRENCY` workers; a slow
/// provider occupies one worker, not the tick.
async fn deliver_pending(state: &Arc<AppState>, cursor: &mut usize) -> usize {
    let tenants = match state.mailer_store.tenants_with_delivery_connector().await {
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

/// Deliver up to [`BATCH`] rows per configured channel for one tenant, one request at a time.
///
/// A row is claimed immediately before its send, not in a batch: a row claimed and then skipped
/// because the deadline arrived would consume an attempt without a transport call and could reach
/// [`MAX_ATTEMPTS`] without ever being tried.
async fn deliver_tenant(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    deadline: Instant,
) -> Result<(), monaca_store::StoreError> {
    let connectors = state.mailer_store.delivery_connectors(tenant).await?;
    for connector in connectors {
        if !connector.enabled {
            continue;
        }
        let secret = match open_secret(state, tenant, &connector) {
            Ok(secret) => secret,
            Err(err) => {
                tracing::warn!(
                    %err,
                    tenant = %tenant.slug,
                    channel = %connector.channel,
                    "mailer cannot open the connector secret"
                );
                continue;
            }
        };
        deliver_channel(state, tenant, &connector, secret.as_deref(), deadline).await?;
    }
    Ok(())
}

async fn deliver_channel(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &DeliveryConnectorRow,
    secret: Option<&str>,
    deadline: Instant,
) -> Result<(), monaca_store::StoreError> {
    let topic = delivery::topic_for(&connector.channel);
    for _ in 0..BATCH {
        if Instant::now() >= deadline {
            break;
        }
        let rows = state
            .mailer_store
            .outbox_claim(tenant, topic, 1, MAX_ATTEMPTS)
            .await?;
        let Some(row) = rows.into_iter().next() else {
            break;
        };
        if row.attempts > 1 {
            state
                .metrics
                .record_delivery_retry(if connector.channel == delivery::SMS {
                    "sms"
                } else {
                    "email"
                });
        }
        match delivery::deliver(state, tenant, connector, secret, &row).await {
            Ok(status) => {
                state
                    .metrics
                    .record_delivery_sent(if connector.channel == delivery::SMS {
                        "sms"
                    } else {
                        "email"
                    });
                match state
                    .mailer_store
                    .outbox_mark_published(tenant, row.id)
                    .await
                {
                    Ok(()) => {
                        let age_ms = (state.now() - row.created_at).whole_milliseconds().max(0);
                        tracing::info!(
                            tenant = %tenant.slug,
                            channel = %connector.channel,
                            outbox_id = %row.id,
                            attempts = row.attempts,
                            age_ms,
                            %status,
                            "message delivered"
                        );
                    }
                    Err(err) => {
                        // The provider already accepted it. Leaving the row unpublished can
                        // duplicate the message on a later tick; the payload carries its id so a
                        // receiver can drop it.
                        tracing::warn!(
                            %err,
                            tenant = %tenant.slug,
                            outbox_id = %row.id,
                            "message delivered but the outbox row could not be marked published"
                        );
                    }
                }
            }
            Err(err) => {
                state
                    .metrics
                    .record_delivery_failed(if connector.channel == delivery::SMS {
                        "sms"
                    } else {
                        "email"
                    });
                tracing::warn!(
                    tenant = %tenant.slug,
                    channel = %connector.channel,
                    outbox_id = %row.id,
                    attempts = row.attempts,
                    max_attempts = MAX_ATTEMPTS,
                    "message delivery failed: {err}"
                );
            }
        }
    }
    Ok(())
}

/// The connector's credential, when one is stored.
fn open_secret(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &DeliveryConnectorRow,
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

#[cfg(test)]
mod tests {
    use monaca_store::DeliveryConnectorRow;
    use time::OffsetDateTime;

    #[test]
    fn connector_rows_carry_a_channel() {
        // The store row is the boundary the mailer switches on; a missing field would be a compile
        // error, so this only pins the row's shape.
        let row = DeliveryConnectorRow {
            channel: "sms".into(),
            provider: "http".into(),
            endpoint: "http://127.0.0.1/capture".into(),
            from_address: "+15550000000".into(),
            from_name: None,
            secret_enc: None,
            enabled: true,
            updated_at: OffsetDateTime::now_utc(),
        };
        assert_eq!(super::delivery::topic_for(&row.channel), "sms.verification");
        assert_eq!(super::delivery::topic_for("email"), "mail.verification");
    }
}
