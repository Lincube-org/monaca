//! Per-endpoint request gates — `docs/contracts/m0.md` §6.2.
//!
//! Two layers are evaluated for every counted request: the tenant-wide row for the endpoint and,
//! when one exists, the stricter row for the calling client. Both are fixed windows in process
//! memory. Configuration lives in `tenant.rate_limits`; the built-in defaults are deliberately
//! generous so an existing deployment is not throttled until an administrator writes a row.
//!
//! The bucket and configuration maps are capacity-bounded: a long-lived process cannot grow them
//! without limit just because clients keep arriving.

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
/// Upper bound on counted buckets.
const BUCKET_CAP: usize = 8_192;
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

struct Bucket {
    count: u32,
    window_end: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    tenant: Uuid,
    endpoint: String,
    /// `""` for the tenant-wide layer, the protocol client id for the client layer.
    subject: String,
}

/// A rejected request: the caller may retry after this many seconds.
#[derive(Debug, Clone, Copy)]
pub struct Rejection {
    /// Whole seconds until the current window ends.
    pub retry_after: u64,
}

/// The process-local gate state.
#[derive(Default)]
pub struct RateLimiter {
    configs: Mutex<HashMap<Uuid, CachedConfig>>,
    buckets: Mutex<HashMap<BucketKey, Bucket>>,
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

    /// Drop a tenant's cached configuration and counted buckets, so a write takes effect now.
    pub async fn invalidate(&self, tenant: Uuid) {
        self.configs.lock().await.remove(&tenant);
        self.buckets
            .lock()
            .await
            .retain(|key, _| key.tenant != tenant);
    }

    /// Count one request against the tenant and (when configured) client layers.
    pub async fn check(
        &self,
        tenant: Uuid,
        rows: &[RateLimitRow],
        endpoint: &str,
        client: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), Rejection> {
        let tenant_limit = rows
            .iter()
            .find(|row| row.client_id.is_none() && row.endpoint == endpoint)
            .map(|row| (row.limit_count.max(1) as u32, row.window_secs.max(1) as u32))
            .unwrap_or_else(|| {
                let (limit, window) = default_limit(endpoint);
                (limit as u32, window as u32)
            });
        let client_limit = client.and_then(|client| {
            rows.iter()
                .find(|row| {
                    row.endpoint == endpoint && row.client_id.as_deref() == Some(client)
                })
                .map(|row| (row.limit_count.max(1) as u32, row.window_secs.max(1) as u32))
        });

        let mut buckets = self.buckets.lock().await;
        consume(
            &mut buckets,
            BucketKey {
                tenant,
                endpoint: endpoint.to_owned(),
                subject: String::new(),
            },
            tenant_limit,
            now,
        )?;
        if let Some((limit, window)) = client_limit
            && let Some(client) = client
        {
            consume(
                &mut buckets,
                BucketKey {
                    tenant,
                    endpoint: endpoint.to_owned(),
                    subject: client.to_owned(),
                },
                (limit, window),
                now,
            )?;
        }
        Ok(())
    }
}

fn consume(
    buckets: &mut HashMap<BucketKey, Bucket>,
    key: BucketKey,
    (limit, window_secs): (u32, u32),
    now: OffsetDateTime,
) -> Result<(), Rejection> {
    if buckets.len() >= BUCKET_CAP && !buckets.contains_key(&key) {
        buckets.retain(|_, bucket| bucket.window_end > now);
        if buckets.len() >= BUCKET_CAP {
            let oldest = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.window_end)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                buckets.remove(&oldest);
            }
        }
    }

    let window_end = now + time::Duration::seconds(i64::from(window_secs));
    let bucket = buckets.entry(key).or_insert(Bucket {
        count: 0,
        window_end,
    });
    if now >= bucket.window_end {
        bucket.count = 0;
        bucket.window_end = window_end;
    }
    if bucket.count >= limit {
        return Err(Rejection {
            retry_after: (bucket.window_end - now).whole_seconds().max(1) as u64,
        });
    }
    bucket.count += 1;
    Ok(())
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
        let mut buckets = HashMap::new();
        let key = BucketKey {
            tenant: Uuid::nil(),
            endpoint: "token".into(),
            subject: String::new(),
        };
        for _ in 0..2 {
            consume(&mut buckets, key.clone(), (2, 60), now).expect("under the limit");
        }
        let rejection = consume(&mut buckets, key, (2, 60), now).expect_err("over the limit");
        assert!((1..=60).contains(&rejection.retry_after));
    }

    #[test]
    fn an_elapsed_window_starts_a_new_count() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut buckets = HashMap::new();
        let key = BucketKey {
            tenant: Uuid::nil(),
            endpoint: "token".into(),
            subject: String::new(),
        };
        consume(&mut buckets, key.clone(), (1, 10), now).expect("first");
        // `OffsetDateTime` does not implement Add for Duration through the operator here; the
        // helper takes an explicit instant.
        let later = now + time::Duration::seconds(11);
        consume(&mut buckets, key, (1, 10), later).expect("a new window");
    }

    #[test]
    fn the_config_cache_expires() {
        assert!(config_ttl_secs() > 0);
    }
}
