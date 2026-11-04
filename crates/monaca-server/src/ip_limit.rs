//! Per-IP request gates for the authentication endpoints — `docs/contracts/m0.md` §6.2.
//!
//! The tenant and client layers are fixed windows counted in PostgreSQL so every instance shares
//! the limit. The address space is a different order of magnitude: one row per IP per endpoint
//! would add a write to every unauthenticated request and a table that grows with the internet.
//! This layer therefore counts in a bounded, per-process map. It is a flood and credential-stuffing
//! gate, not a deployment-wide quota: two instances each allow up to the limit.
//!
//! IPv6 addresses are bucketed by their /64 prefix; otherwise a client could rotate its interface
//! identifier and never reach the limit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// One fixed window.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Upper bound on tracked (address, endpoint) pairs. Reaching it evicts the oldest window.
const CAP: usize = 16_384;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    started: Instant,
    count: u32,
}

/// The in-process per-IP counters.
#[derive(Default)]
pub struct IpRateLimiter {
    buckets: Mutex<HashMap<(IpAddr, &'static str), Bucket>>,
}

impl IpRateLimiter {
    /// Count one request and return the `Retry-After` seconds when the limit is exceeded.
    pub async fn hit(
        &self,
        ip: IpAddr,
        endpoint: &'static str,
        limit: u32,
        now: Instant,
    ) -> Option<u64> {
        let key = (bucket_key(ip), endpoint);
        let mut buckets = self.buckets.lock().await;
        if buckets.len() >= CAP
            && !buckets.contains_key(&key)
            && let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.started)
                .map(|(key, _)| *key)
        {
            buckets.remove(&oldest);
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            started: now,
            count: 0,
        });
        let elapsed = now.saturating_duration_since(bucket.started);
        if elapsed >= WINDOW {
            *bucket = Bucket {
                started: now,
                count: 0,
            };
        }
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count <= limit {
            return None;
        }
        let elapsed = now.saturating_duration_since(bucket.started);
        Some((WINDOW.as_secs().saturating_sub(elapsed.as_secs())).max(1))
    }
}

/// The bucket key for an address: IPv4 as-is, IPv6 truncated to its /64 network.
pub fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_limit_is_counted_per_address_and_endpoint() {
        let limiter = IpRateLimiter::default();
        let now = Instant::now();
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        let other: IpAddr = "198.51.100.9".parse().expect("ip");
        assert!(limiter.hit(ip, "token", 2, now).await.is_none());
        assert!(limiter.hit(ip, "token", 2, now).await.is_none());
        let retry = limiter.hit(ip, "token", 2, now).await.expect("limited");
        assert!((1..=60).contains(&retry));
        // Another address and another endpoint have their own window.
        assert!(limiter.hit(other, "token", 2, now).await.is_none());
        assert!(limiter.hit(ip, "authorize", 2, now).await.is_none());
    }

    #[tokio::test]
    async fn an_elapsed_window_starts_over() {
        let limiter = IpRateLimiter::default();
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        let start = Instant::now();
        assert!(limiter.hit(ip, "token", 1, start).await.is_none());
        assert!(limiter.hit(ip, "token", 1, start).await.is_some());
        assert!(limiter.hit(ip, "token", 1, start + WINDOW).await.is_none());
    }

    #[test]
    fn ipv6_is_bucketed_by_its_64_bit_network() {
        let a: IpAddr = "2001:db8::1".parse().expect("ip");
        let b: IpAddr = "2001:db8::ffff".parse().expect("ip");
        let c: IpAddr = "2001:db8:1::1".parse().expect("ip");
        assert_eq!(bucket_key(a), bucket_key(b));
        assert_ne!(bucket_key(a), bucket_key(c));
    }
}
