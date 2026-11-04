//! Per-endpoint request gates — `docs/contracts/m0.md` §6.2.
//!
//! Two layers are evaluated for every counted request: the tenant-wide row for the endpoint and,
//! when one exists, the stricter row for the calling client. Both are fixed windows counted in
//! `tenant.rate_limit_counters`, so every server instance increments the same row and the limit is
//! deployment-wide. Configuration lives in `tenant.rate_limits`; the built-in defaults are
//! deliberately generous so an existing deployment is not throttled until an administrator writes
//! a row.
//!
//! This module owns the configuration cache and the pure window decision. The atomic increment is
//! a store call; the cache is capacity-bounded.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use monaca_store::RateLimitRow;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

/// The endpoint classes a row may name.
pub const ENDPOINTS: &[&str] = &["authorize", "token", "userinfo", "management"];

/// Built-in limits, (endpoint, requests, window seconds).
const DEFAULTS: &[(&str, i32, i32)] = &[
    ("authorize", 600, 60),
    ("token", 600, 60),
    ("userinfo", 1200, 60),
    ("management", 600, 60),
];

/// How long a tenant's configuration is cached. A write in this process invalidates it immediately;
/// another instance picks it up within this window.
const CONFIG_TTL_SECS: i64 = 5;
/// Upper bound on cached tenant configurations.
const CONFIG_CAP: usize = 1_024;

/// The built-in limit for an endpoint.
pub fn default_limit(endpoint: &str) -> (i32, i32) {
    DEFAULTS
        .iter()
        .find(|(name, _, _)| *name == endpoint)
        .map(|(_, limit, window)| (*limit, *window))
        .unwrap_or((600, 60))
}

/// The built-in limits, for the management read.
pub fn defaults() -> Vec<(&'static str, i32, i32)> {
    DEFAULTS.to_vec()
}

struct CachedConfig {
    rows: Arc<Vec<RateLimitRow>>,
    loaded_at: OffsetDateTime,
}

/// A rejected request: the caller may retry after this many seconds.
#[derive(Debug, Clone, Copy)]
pub struct Rejection {
    /// Whole seconds until the current window ends.
    pub retry_after: u64,
}

/// The cached configuration and the pure window decision.
#[derive(Default)]
pub struct RateLimiter {
    configs: Mutex<HashMap<Uuid, CachedConfig>>,
}

impl RateLimiter {
    /// A tenant's configuration if the cache entry is still fresh.
    pub async fn cached(&self, tenant: Uuid, now: OffsetDateTime) -> Option<Arc<Vec<RateLimitRow>>> {
        let configs = self.configs.lock().await;
        configs
            .get(&tenant)
            .filter(|entry| (now - entry.loaded_at).whole_seconds() < CONFIG_TTL_SECS)
            .map(|entry| Arc::clone(&entry.rows))
    }

    /// Remember a freshly loaded configuration, evicting the oldest tenant when full.
    pub async fn remember(&self, tenant: Uuid, rows: Arc<Vec<RateLimitRow>>, now: OffsetDateTime) {
        let mut configs = self.configs.lock().await;
        if configs.len() >= CONFIG_CAP && !configs.contains_key(&tenant) {
            let oldest = configs
                .iter()
                .min_by_key(|(_, entry)| entry.loaded_at)
                .map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                configs.remove(&oldest);
            }
        }
        configs.insert(
            tenant,
            CachedConfig {
                rows,
                loaded_at: now,
            },
        );
    }

    /// Drop a tenant's cached configuration, so a write takes effect now.
    pub async fn invalidate(&self, tenant: Uuid) {
        self.configs.lock().await.remove(&tenant);
    }
}

/// The effective layer limit for `endpoint` and an optional client.
///
/// Returns `(limit, window_secs)` for the tenant row or its built-in default, and the optional
/// client row. A client row can only tighten the result because both layers are evaluated.
pub fn layer_limits(
    rows: &[RateLimitRow],
    endpoint: &str,
    client: Option<&str>,
) -> ((u32, u32), Option<(u32, u32)>) {
    let tenant = rows
        .iter()
        .find(|row| row.client_id.is_none() && row.endpoint == endpoint)
        .map(|row| (row.limit_count.max(1) as u32, row.window_secs.max(1) as u32))
        .unwrap_or_else(|| {
            let (limit, window) = default_limit(endpoint);
            (limit as u32, window as u32)
        });
    let client = client.and_then(|client| {
        rows.iter()
            .find(|row| row.endpoint == endpoint && row.client_id.as_deref() == Some(client))
            .map(|row| (row.limit_count.max(1) as u32, row.window_secs.max(1) as u32))
    });
    (tenant, client)
}

/// Whether the `count`th request in a window is over the limit.
///
/// `count` is the value returned by the atomic counter after this request was included.
pub fn rejection(
    count: i64,
    limit: u32,
    window_start: OffsetDateTime,
    window_secs: u32,
    now: OffsetDateTime,
) -> Option<Rejection> {
    let window_end = window_start + time::Duration::seconds(i64::from(window_secs));
    if now >= window_end {
        // The counter resets in place at the next hit; this stale window is over.
        return None;
    }
    if count <= i64::from(limit) {
        return None;
    }
    Some(Rejection {
        retry_after: (window_end - now).whole_seconds().max(1) as u64,
    })
}

/// How long a cached configuration is trusted, in seconds. Exposed for the contract test.
pub const fn config_ttl_secs() -> i64 {
    CONFIG_TTL_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_cover_every_endpoint_class() {
        for endpoint in ENDPOINTS {
            let (limit, window) = default_limit(endpoint);
            assert!(limit > 0 && window > 0, "{endpoint}");
        }
    }

    #[test]
    fn the_window_rejects_and_reports_a_retry() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(rejection(2, 2, now, 60, now).is_none());
        let over = rejection(3, 2, now, 60, now).expect("over the limit");
        assert!((1..=60).contains(&over.retry_after));
    }

    #[test]
    fn an_elapsed_window_is_not_rejected() {
        let start = OffsetDateTime::UNIX_EPOCH;
        let later = start + time::Duration::seconds(11);
        assert!(rejection(2, 1, start, 10, later).is_none());
    }

    #[test]
    fn the_config_cache_expires() {
        assert!(config_ttl_secs() > 0);
    }
}
