//! The SSO session cookie — OpenID Connect "login state" across authorize requests.
//!
//! The cookie carries only the session row id; everything else lives in `tenant.sessions`. The
//! name has no `__Host-` prefix because the dev/test origin is plain HTTP, and a browser rejects a
//! `__Host-` cookie that is not `Secure`. `Secure` is added whenever the public origin is HTTPS.

use axum::http::{HeaderMap, header};
use uuid::Uuid;

/// The cookie's name.
pub const COOKIE_NAME: &str = "monaca_session";

/// The `Set-Cookie` value that establishes a session.
pub fn set_cookie(session_id: Uuid, ttl_secs: u64, secure: bool) -> String {
    format!(
        "{COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl_secs}{}",
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
        headers.insert(header::COOKIE, HeaderValue::from_static("monaca_session=nope"));
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
