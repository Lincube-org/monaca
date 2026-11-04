//! Resolve the client address behind a reverse proxy — `docs/contracts/m0.md` §6.2.
//!
//! `X-Forwarded-For` is attacker-controlled unless the socket peer is a proxy we configured. The
//! trust boundary is [`Config::trusted_proxies`](crate::config::Config::trusted_proxies)
//! (`MONACA_TRUSTED_PROXY_CIDRS`); when the immediate peer is not in that list the header is
//! ignored and the peer address is the client.
//!
//! The list is read right to left. Each hop a trusted proxy appended is skipped; the first
//! untrusted address is the client. A forged value at the left of the list therefore cannot
//! outweigh the address the last trusted proxy saw.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::config::{TrustedProxy, unmap};
use crate::error::ApiError;
use crate::state::AppState;

/// The client address for the request.
///
/// `None` means the request did not arrive through a socket (a router exercised directly in a
/// unit test). The gate is skipped in that case only; a real connection always has a peer.
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<Arc<AppState>> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let forwarded = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok());
        Ok(ClientIp(peer.map(|peer| {
            resolve(&state.config.trusted_proxies, peer, forwarded)
        })))
    }
}

/// Resolve `peer` and an optional `X-Forwarded-For` value to the client address.
pub fn resolve(proxies: &[TrustedProxy], peer: IpAddr, forwarded: Option<&str>) -> IpAddr {
    let peer = unmap(peer);
    if !proxies.iter().any(|proxy| proxy.contains(peer)) {
        return peer;
    }
    let Some(value) = forwarded else {
        return peer;
    };
    for entry in value.rsplit(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Ok(ip) = entry.parse::<IpAddr>() else {
            continue;
        };
        let ip = unmap(ip);
        if proxies.iter().any(|proxy| proxy.contains(ip)) {
            continue;
        }
        return ip;
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> Vec<TrustedProxy> {
        vec![TrustedProxy::parse("127.0.0.1/32").expect("literal")]
    }

    #[test]
    fn the_socket_peer_is_the_client_without_a_trusted_proxy() {
        // A direct client that sets the header must not be able to choose its bucket.
        let peer: IpAddr = "198.51.100.9".parse().expect("ip");
        assert_eq!(resolve(&[], peer, Some("203.0.113.7")), peer);
    }

    #[test]
    fn a_trusted_proxy_may_speak_for_the_client() {
        let peer: IpAddr = "127.0.0.1".parse().expect("ip");
        let client: IpAddr = "203.0.113.7".parse().expect("ip");
        assert_eq!(resolve(&loopback(), peer, Some("203.0.113.7")), client);
    }

    #[test]
    fn the_rightmost_untrusted_hop_wins_over_a_forged_prefix() {
        let peer: IpAddr = "127.0.0.1".parse().expect("ip");
        let client: IpAddr = "203.0.113.7".parse().expect("ip");
        // The client forged the left value; the proxy appended the address it actually saw.
        assert_eq!(
            resolve(&loopback(), peer, Some("1.2.3.4, 203.0.113.7, 127.0.0.1")),
            client
        );
    }

    #[test]
    fn an_unparseable_header_falls_back_to_the_peer() {
        let peer: IpAddr = "127.0.0.1".parse().expect("ip");
        assert_eq!(resolve(&loopback(), peer, Some("not-an-ip")), peer);
        assert_eq!(resolve(&loopback(), peer, None), peer);
    }

    #[test]
    fn ipv4_mapped_peers_match_an_ipv4_network() {
        let peer: IpAddr = "::ffff:127.0.0.1".parse().expect("ip");
        assert!(loopback()[0].contains(peer));
        assert_eq!(
            resolve(&loopback(), peer, Some("203.0.113.7")),
            "203.0.113.7".parse::<IpAddr>().expect("ip")
        );
    }
}
