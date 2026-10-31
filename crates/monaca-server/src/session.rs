//! The SSO session cookie — OpenID Connect "login state" across authorize requests.
//!
//! The cookie carries only the session row id; everything else lives in `tenant.sessions`. The
//! name has no `__Host-` prefix because the dev/test origin is plain HTTP, and a browser rejects a
//! `__Host-` cookie that is not `Secure`. `Secure` is added whenever the public origin is HTTPS.

use axum::http::{HeaderMap, header};
use uuid::Uuid;

/// The cookie's name.
pub const COOKIE_NAME: &str = "monaca_session";

/// The remembered-browser cookie's name (§6.1 `mfa`).
pub const DEVICE_COOKIE_NAME: &str = "monaca_mfa_device";

/// The `Set-Cookie` value that establishes a session.
pub fn set_cookie(session_id: Uuid, ttl_secs: u64, secure: bool) -> String {
    format!(
        "{COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl_secs}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// The `Set-Cookie` value that remembers this browser past the second factor.
///
/// The path is scoped to the tenant's API prefix, so a trust minted for one tenant is never
/// offered to another — and the row still names the account, so the two checks agree.
pub fn set_device_cookie(token: &str, ttl_secs: u64, secure: bool, tenant: &str) -> String {
    format!(
        "{DEVICE_COOKIE_NAME}={token}; Path=/t/{tenant}; HttpOnly; SameSite=Lax; Max-Age={ttl_secs}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// The `Set-Cookie` value that forgets it.
pub fn clear_device_cookie(secure: bool, tenant: &str) -> String {
    format!(
        "{DEVICE_COOKIE_NAME}=; Path=/t/{tenant}; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}

/// The `Set-Cookie` value that removes it.
pub fn clear_cookie(secure: bool) -> String {
    format!(
        "{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Whether cookies must be `Secure`: the public origin is HTTPS.
pub fn secure_origin(config: &crate::config::Config) -> bool {
    config.public_base_url.starts_with("https://")
}

/// The session id in the request's `Cookie` header, if it is a well-formed one.
///
/// A malformed value is ignored rather than rejected: a stale or hand-edited cookie must never
/// turn a valid authorize request into an error.
pub fn session_id(headers: &HeaderMap) -> Option<Uuid> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name == COOKIE_NAME {
            return Uuid::parse_str(value.trim()).ok();
        }
    }
    None
}

/// The remembered-browser token in the request's `Cookie` header.
///
/// The value is validated as 64 hex characters (a 32-byte random token), so a hand-edited cookie
/// can never reach a hash lookup with an unexpected shape.
pub fn trusted_device_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name == DEVICE_COOKIE_NAME {
            let value = value.trim();
            return (value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
                .then(|| value.to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn a_cookie_round_trips() {
        let id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {COOKIE_NAME}={id}; last=2")).expect("ascii"),
        );
        assert_eq!(session_id(&headers), Some(id));
    }

    #[test]
    fn a_malformed_cookie_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("monaca_session=nope"),
        );
        assert_eq!(session_id(&headers), None);
        headers.insert(header::COOKIE, HeaderValue::from_static("other=1"));
        assert_eq!(session_id(&headers), None);
    }

    #[test]
    fn the_cookie_is_host_only_and_httponly() {
        let value = set_cookie(Uuid::nil(), 60, false);
        assert!(value.contains("Path=/"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(!value.contains("Secure"));
        assert!(set_cookie(Uuid::nil(), 60, true).contains("Secure"));
    }

    #[test]
    fn clearing_expires_immediately() {
        let value = clear_cookie(false);
        assert!(value.starts_with(&format!("{COOKIE_NAME}=;")));
        assert!(value.contains("Max-Age=0"));
    }
}
