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

use monaca_store::PoolStatsSnapshot;

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
    mailer_ticks: AtomicU64,
    mailer_last_tick_micros: AtomicU64,
    mailer_max_tick_micros: AtomicU64,
    mailer_tenants_last: AtomicU64,
    delivery_sent: Mutex<HashMap<&'static str, u64>>,
    delivery_failed: Mutex<HashMap<&'static str, u64>>,
    delivery_retries: Mutex<HashMap<&'static str, u64>>,
    template_missing: Mutex<HashMap<(String, String), u64>>,
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

    /// Record one accepted delivery, by channel.
    pub fn record_delivery_sent(&self, channel: &'static str) {
        *lock(&self.delivery_sent).entry(channel).or_insert(0) += 1;
    }

    /// Record one refused delivery, by channel.
    pub fn record_delivery_failed(&self, channel: &'static str) {
        *lock(&self.delivery_failed).entry(channel).or_insert(0) += 1;
    }

    /// Record one retry claim (the row's second or later attempt), by channel.
    pub fn record_delivery_retry(&self, channel: &'static str) {
        *lock(&self.delivery_retries).entry(channel).or_insert(0) += 1;
    }

    /// Record one send refused because no template exists for the purpose in the requested locale.
    pub fn record_template_missing(&self, purpose: &str, locale: &str) {
        let key = (purpose.to_owned(), locale.to_owned());
        let mut map = lock(&self.template_missing);
        if map.len() >= SERIES_CAP && !map.contains_key(&key) {
            if let Some(first) = map.keys().next().cloned() {
                map.remove(&first);
            }
        }
        *map.entry(key).or_insert(0) += 1;
    }

    /// The delivery and template section of `/metrics`.
    pub fn delivery_stats_text(&self) -> String {
        let mut out = String::with_capacity(512);
        for (name, help, map) in [
            (
                "monaca_delivery_sent_total",
                "Messages accepted by a provider, by channel.",
                &self.delivery_sent,
            ),
            (
                "monaca_delivery_failed_total",
                "Messages a provider or transport refused, by channel.",
                &self.delivery_failed,
            ),
            (
                "monaca_delivery_retries_total",
                "Delivery attempts after the first, by channel.",
                &self.delivery_retries,
            ),
        ] {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
            for (channel, value) in lock(map).iter().map(|(channel, value)| (*channel, *value)) {
                out.push_str(&format!(
                    "{name}{{channel=\"{}\"}} {value}\n",
                    escape(channel)
                ));
            }
        }
        out.push_str(
            "# HELP monaca_template_missing_total Sends refused because no locale in the fallback chain had the template.\n",
        );
        out.push_str("# TYPE monaca_template_missing_total counter\n");
        for ((purpose, locale), value) in lock(&self.template_missing)
            .iter()
            .map(|((purpose, locale), value)| ((purpose.clone(), locale.clone()), *value))
        {
            out.push_str(&format!(
                "monaca_template_missing_total{{purpose=\"{}\",locale=\"{}\"}} {value}\n",
                escape(&purpose),
                escape(&locale)
            ));
        }
        out
    }

    /// Record one mailer tick. `visited` is how many tenants this pass started on.
    pub fn record_mailer_tick(&self, elapsed: Duration, visited: usize) {
        let micros = elapsed.as_micros() as u64;
        self.mailer_ticks.fetch_add(1, Ordering::Relaxed);
        self.mailer_last_tick_micros
            .store(micros, Ordering::Relaxed);
        self.mailer_max_tick_micros
            .fetch_max(micros, Ordering::Relaxed);
        self.mailer_tenants_last
            .store(visited as u64, Ordering::Relaxed);
    }

    /// The mailer tick section of `/metrics`.
    pub fn mailer_stats_text(&self) -> String {
        let ticks = self.mailer_ticks.load(Ordering::Relaxed);
        let last = self.mailer_last_tick_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let max = self.mailer_max_tick_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let tenants = self.mailer_tenants_last.load(Ordering::Relaxed);
        let mut out = String::with_capacity(512);
        out.push_str(
            "# HELP monaca_mailer_ticks_total Mailer passes over the connector tenants.\n",
        );
        out.push_str("# TYPE monaca_mailer_ticks_total counter\n");
        out.push_str(&format!("monaca_mailer_ticks_total {ticks}\n"));
        out.push_str("# HELP monaca_mailer_tick_seconds Duration of the last mailer tick.\n");
        out.push_str("# TYPE monaca_mailer_tick_seconds gauge\n");
        out.push_str(&format!("monaca_mailer_tick_seconds {last}\n"));
        out.push_str("# HELP monaca_mailer_tick_seconds_max Longest mailer tick since start.\n");
        out.push_str("# TYPE monaca_mailer_tick_seconds_max gauge\n");
        out.push_str(&format!("monaca_mailer_tick_seconds_max {max}\n"));
        out.push_str(
            "# HELP monaca_mailer_tenants_last Tenants started by the last mailer tick.\n",
        );
        out.push_str("# TYPE monaca_mailer_tenants_last gauge\n");
        out.push_str(&format!("monaca_mailer_tenants_last {tenants}\n"));
        out
    }
}

/// Append the tenant-pool cache counters to the request metrics (§6.4).
///
/// They live in the store rather than here because the store owns the pool cache; `/metrics` joins
/// the two text sections so a benchmark can tell a warm pool from a cold one without instrumenting
/// every query.
pub fn pool_stats_text(prefix: &str, stats: &PoolStatsSnapshot) -> String {
    let lookups = stats.hits.saturating_add(stats.misses);
    let mut out = String::with_capacity(512);
    out.push_str(&format!(
        "# HELP {prefix}_cache_total Tenant pool cache lookups by result.\n"
    ));
    out.push_str(&format!("# TYPE {prefix}_cache_total counter\n"));
    out.push_str(&format!(
        "{prefix}_cache_total{{result=\"hit\"}} {}\n",
        stats.hits
    ));
    out.push_str(&format!(
        "{prefix}_cache_total{{result=\"miss\"}} {}\n",
        stats.misses
    ));
    out.push_str(&format!(
        "# HELP {prefix}_cache_lookup_seconds Time spent in the tenant-pool cache lookup.\n"
    ));
    out.push_str(&format!("# TYPE {prefix}_cache_lookup_seconds summary\n"));
    out.push_str(&format!(
        "{prefix}_cache_lookup_seconds_sum {}\n",
        stats.lookup_nanos as f64 / 1_000_000_000.0
    ));
    out.push_str(&format!("{prefix}_cache_lookup_seconds_count {lookups}\n"));
    out.push_str(&format!(
        "# HELP {prefix}_connect_seconds Time spent creating a tenant pool and validating a connection.\n"
    ));
    out.push_str(&format!("# TYPE {prefix}_connect_seconds summary\n"));
    out.push_str(&format!(
        "{prefix}_connect_seconds_sum {}\n",
        stats.connect_nanos as f64 / 1_000_000_000.0
    ));
    out.push_str(&format!(
        "{prefix}_connect_seconds_count {}\n",
        stats.misses
    ));
    out
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
    let mut body = state.metrics.render();
    body.push_str(&pool_stats_text(
        "monaca_tenant_pool",
        &state.store.pool_stats(),
    ));
    body.push_str(&pool_stats_text(
        "monaca_mailer_pool",
        &state.mailer_store.pool_stats(),
    ));
    body.push_str(&state.metrics.mailer_stats_text());
    body.push_str(&state.metrics.delivery_stats_text());
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
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
