//! Prometheus text metrics — `docs/contracts/m0.md` §6.4.
//!
//! The counters answer three questions without a tracing backend: which tenant/endpoint is slow,
//! which rate limit rejected whom, and which surface rejected a revoked token. Latency is a fixed
//! histogram (no external client), and every map is capacity-bounded so a long-lived process
//! cannot grow without limit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::state::AppState;

/// Upper bound on distinct request/latency series.
const SERIES_CAP: usize = 4_096;
/// Upper bound on distinct rate-limit rejection series.
const REJECTION_CAP: usize = 4_096;

/// The finite histogram bounds, in seconds. The `+Inf` bucket is implicit.
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestKey {
    tenant: String,
    endpoint: String,
    method: String,
    status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LatencyKey {
    tenant: String,
    endpoint: String,
}

#[derive(Debug, Default)]
struct Latency {
    buckets: [u64; 11],
    sum_micros: u64,
    count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RejectionKey {
    tenant: String,
    endpoint: String,
    layer: String,
    client: Option<String>,
}

/// The process metrics.
#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<HashMap<RequestKey, u64>>,
    latency: Mutex<HashMap<LatencyKey, Latency>>,
    rejections: Mutex<HashMap<RejectionKey, u64>>,
    revoked: Mutex<HashMap<&'static str, u64>>,
    rendered: AtomicU64,
}

impl Metrics {
    /// Record one HTTP response.
    pub fn record_request(
        &self,
        tenant: &str,
        endpoint: &str,
        method: &str,
        status: u16,
        elapsed: Duration,
    ) {
        let key = RequestKey {
            tenant: tenant.to_owned(),
            endpoint: endpoint.to_owned(),
            method: method.to_owned(),
            status,
        };
        let mut requests = lock(&self.requests);
        if requests.len() >= SERIES_CAP && !requests.contains_key(&key) {
            if let Some(first) = requests.keys().next().cloned() {
                requests.remove(&first);
            }
        }
        *requests.entry(key).or_insert(0) += 1;

        let key = LatencyKey {
            tenant: tenant.to_owned(),
            endpoint: endpoint.to_owned(),
        };
        let mut latency = lock(&self.latency);
        if latency.len() >= SERIES_CAP && !latency.contains_key(&key) {
            if let Some(first) = latency.keys().next().cloned() {
                latency.remove(&first);
            }
        }
        let entry = latency.entry(key).or_default();
        entry.count += 1;
        entry.sum_micros = entry.sum_micros.saturating_add(elapsed.as_micros() as u64);
        let seconds = elapsed.as_secs_f64();
        for (index, bound) in BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                entry.buckets[index] += 1;
            }
        }
    }

    /// Record a rate-limit rejection, naming the tenant, endpoint, layer and client when known.
    pub fn record_rejection(
        &self,
        tenant: &str,
        endpoint: &str,
        layer: &str,
        client: Option<&str>,
    ) {
        let key = RejectionKey {
            tenant: tenant.to_owned(),
            endpoint: endpoint.to_owned(),
            layer: layer.to_owned(),
            client: client.map(str::to_owned),
        };
        let mut rejections = lock(&self.rejections);
        if rejections.len() >= REJECTION_CAP && !rejections.contains_key(&key) {
            if let Some(first) = rejections.keys().next().cloned() {
                rejections.remove(&first);
            }
        }
        *rejections.entry(key).or_insert(0) += 1;
    }

    /// Record a revoked-token rejection on a surface (`management` or `userinfo`).
    pub fn record_revoked(&self, surface: &'static str) {
        let mut revoked = lock(&self.revoked);
        *revoked.entry(surface).or_insert(0) += 1;
    }

    /// Render the Prometheus text exposition.
    pub fn render(&self) -> String {
        self.rendered.fetch_add(1, Ordering::Relaxed);
        let mut out = String::with_capacity(8_192);
        out.push_str("# HELP monaca_http_requests_total HTTP responses by tenant, endpoint, method and status.\n");
        out.push_str("# TYPE monaca_http_requests_total counter\n");
        for (key, value) in lock(&self.requests)
            .iter()
            .map(|(key, value)| (key.clone(), *value))
        {
            out.push_str(&format!(
                "monaca_http_requests_total{{tenant=\"{}\",endpoint=\"{}\",method=\"{}\",status=\"{}\"}} {value}\n",
                escape(&key.tenant),
                escape(&key.endpoint),
                escape(&key.method),
                key.status
            ));
        }

        out.push_str("# HELP monaca_http_request_duration_seconds Request latency.\n");
        out.push_str("# TYPE monaca_http_request_duration_seconds histogram\n");
        for (key, value) in lock(&self.latency)
            .iter()
            .map(|(key, value)| (key.clone(), clone_latency(value)))
        {
            let mut cumulative = 0u64;
            for (index, bound) in BUCKETS.iter().enumerate() {
                cumulative += value.buckets[index];
                out.push_str(&format!(
                    "monaca_http_request_duration_seconds_bucket{{tenant=\"{}\",endpoint=\"{}\",le=\"{}\"}} {cumulative}\n",
                    escape(&key.tenant),
                    escape(&key.endpoint),
                    bound
                ));
            }
            out.push_str(&format!(
                "monaca_http_request_duration_seconds_bucket{{tenant=\"{}\",endpoint=\"{}\",le=\"+Inf\"}} {}\n",
                escape(&key.tenant),
                escape(&key.endpoint),
                value.count
            ));
            out.push_str(&format!(
                "monaca_http_request_duration_seconds_sum{{tenant=\"{}\",endpoint=\"{}\"}} {}\n",
                escape(&key.tenant),
                escape(&key.endpoint),
                value.sum_micros as f64 / 1_000_000.0
            ));
            out.push_str(&format!(
                "monaca_http_request_duration_seconds_count{{tenant=\"{}\",endpoint=\"{}\"}} {}\n",
                escape(&key.tenant),
                escape(&key.endpoint),
                value.count
            ));
        }

        out.push_str("# HELP monaca_rate_limit_rejections_total Requests rejected by a gate.\n");
        out.push_str("# TYPE monaca_rate_limit_rejections_total counter\n");
        for (key, value) in lock(&self.rejections)
            .iter()
            .map(|(key, value)| (key.clone(), *value))
        {
            let client = key
                .client
                .as_deref()
                .map(|client| format!(",client=\"{}\"", escape(client)))
                .unwrap_or_default();
            out.push_str(&format!(
                "monaca_rate_limit_rejections_total{{tenant=\"{}\",endpoint=\"{}\",layer=\"{}\"{client}}} {value}\n",
                escape(&key.tenant),
                escape(&key.endpoint),
                escape(&key.layer)
            ));
        }

        out.push_str("# HELP monaca_revoked_token_rejections_total Requests rejected because the token's jti was revoked.\n");
        out.push_str("# TYPE monaca_revoked_token_rejections_total counter\n");
        for (surface, value) in lock(&self.revoked)
            .iter()
            .map(|(surface, value)| (*surface, *value))
        {
            out.push_str(&format!(
                "monaca_revoked_token_rejections_total{{surface=\"{}\"}} {value}\n",
                escape(surface)
            ));
        }

        out
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clone_latency(value: &Latency) -> Latency {
    Latency {
        buckets: value.buckets,
        sum_micros: value.sum_micros,
        count: value.count,
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Split a request path into the tenant label and the endpoint class.
pub fn classify(path: &str) -> (String, &'static str) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.first() == Some(&"t") {
        let tenant = parts.get(1).copied().unwrap_or("-").to_owned();
        let endpoint = match parts.as_slice() {
            [_, _, "oauth2", "authorize", ..] => "authorize",
            [_, _, "oauth2", "token", ..] => "token",
            [_, _, "oauth2", "userinfo", ..] => "userinfo",
            [_, _, "oauth2", ..] => "protocol",
            [_, _, "interaction", ..] => "interaction",
            [_, _, "account", ..] => "account",
            [_, _, "connectors", ..] | [_, _, "sso", ..] | [_, _, "social", ..] => "protocol",
            _ => "protocol",
        };
        return (tenant, endpoint);
    }
    match parts.first() {
        Some(&"v1") => ("-".to_owned(), "management"),
        Some(&"internal") => ("-".to_owned(), "internal"),
        Some(&"healthz") | Some(&"version") | Some(&"metrics") => ("-".to_owned(), "meta"),
        _ => ("-".to_owned(), "other"),
    }
}

/// Axum middleware: time every request, record it, and log slow or rejected answers.
pub async fn middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = request.method().clone();
    let (tenant, endpoint) = classify(request.uri().path());
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let elapsed = started.elapsed();
    state
        .metrics
        .record_request(&tenant, endpoint, method.as_str(), status, elapsed);

    if status >= 500 {
        tracing::error!(
            tenant = %tenant,
            endpoint,
            method = %method,
            status,
            elapsed_ms = elapsed.as_millis() as u64,
            "request failed"
        );
    } else if status == 429 {
        tracing::warn!(
            tenant = %tenant,
            endpoint,
            method = %method,
            elapsed_ms = elapsed.as_millis() as u64,
            "request rate limited"
        );
    } else {
        tracing::debug!(
            tenant = %tenant,
            endpoint,
            method = %method,
            status,
            elapsed_ms = elapsed.as_millis() as u64,
            "request"
        );
    }
    response
}

/// `GET /metrics` — the Prometheus text exposition.
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "meta",
    summary = "Prometheus metrics",
    description = "Prometheus text exposition. Keep it off the public origin.",
    responses(
        (status = 200, description = "Prometheus text.", content_type = "text/plain")
    )
)]
pub async fn scrape(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_series_are_rendered_with_escaped_labels() {
        let metrics = Metrics::default();
        metrics.record_request("demo", "token", "POST", 200, Duration::from_millis(3));
        metrics.record_request("demo", "token", "POST", 429, Duration::from_millis(4));
        metrics.record_rejection("demo", "token", "client", Some("monaca-admin"));
        metrics.record_revoked("management");
        let text = metrics.render();
        assert!(text.contains(
            "monaca_http_requests_total{tenant=\"demo\",endpoint=\"token\",method=\"POST\",status=\"200\"} 1"
        ));
        assert!(text.contains(
            "monaca_rate_limit_rejections_total{tenant=\"demo\",endpoint=\"token\",layer=\"client\",client=\"monaca-admin\"} 1"
        ));
        assert!(text.contains("monaca_revoked_token_rejections_total{surface=\"management\"} 1"));
        assert!(text.contains("monaca_http_request_duration_seconds_bucket"));
    }

    #[test]
    fn the_classifier_names_the_endpoint_and_tenant() {
        assert_eq!(classify("/t/demo/oauth2/token"), ("demo".into(), "token"));
        assert_eq!(
            classify("/t/demo/interaction/int_x/sign-in"),
            ("demo".into(), "interaction")
        );
        assert_eq!(classify("/v1/accounts"), ("-".into(), "management"));
        assert_eq!(classify("/internal/health"), ("-".into(), "internal"));
    }
}
