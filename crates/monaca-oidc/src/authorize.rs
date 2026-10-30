//! `GET /t/{tenant}/oauth2/authorize` — §6.1.
//!
//! Validation is split from routing because the failure mode differs: an unknown `client_id` or an
//! unregistered `redirect_uri` must be shown as an error page and **never** redirected (§6.1),
//! while every other failure redirects with `error=invalid_request`. [`AuthorizeError`] therefore
//! carries whether the request is safe to redirect.

use serde::Deserialize;

use crate::parse_scope;

/// The query parameters of an authorize request. Every member is optional so a missing one is a
/// protocol error rather than an extractor rejection with the wrong shape.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizeParams {
    /// Must be `code`.
    pub response_type: Option<String>,
    /// The client's protocol id.
    pub client_id: Option<String>,
    /// Where to send the code.
    pub redirect_uri: Option<String>,
    /// Space-delimited scopes.
    pub scope: Option<String>,
    /// Opaque CSRF value, echoed back.
    pub state: Option<String>,
    /// PKCE S256 challenge.
    pub code_challenge: Option<String>,
    /// Must be `S256`.
    pub code_challenge_method: Option<String>,
    /// OIDC nonce, echoed into the id_token.
    pub nonce: Option<String>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// Monaca extension: the org slug the flow issues into.
    pub organization: Option<String>,
    /// `none` | `login` | `consent`; M0 only records it.
    pub prompt: Option<String>,
}

/// A validated authorize request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeRequest {
    /// The client's protocol id.
    pub client_id: String,
    /// The validated redirect URI.
    pub redirect_uri: String,
    /// Sorted, de-duplicated scopes.
    pub scopes: Vec<String>,
    /// The `state` to echo.
    pub state: String,
    /// The PKCE challenge.
    pub code_challenge: String,
    /// Echoed into the id_token.
    pub nonce: Option<String>,
    /// RFC 8707 resource, which becomes the access token's `aud`.
    pub resource: Option<String>,
    /// The requested org slug.
    pub organization: Option<String>,
}

/// Why an authorize request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizeError {
    /// The request is malformed; safe to redirect with `error=invalid_request`.
    #[error("{0}")]
    InvalidRequest(String),
    /// The client is unknown or the redirect URI is not registered.
    ///
    /// Never redirected: redirecting would turn the endpoint into an open redirector.
    #[error("{0}")]
    UntrustedClient(String),
}

impl AuthorizeError {
    /// The OAuth error code to report when this failure is redirectable.
    pub const fn code(&self) -> &'static str {
        match self {
            AuthorizeError::InvalidRequest(_) => "invalid_request",
            // Only used on the error page, never as a redirect parameter.
            AuthorizeError::UntrustedClient(_) => "unauthorized_client",
        }
    }

    /// Whether the request may be answered with a redirect to its `redirect_uri`.
    pub const fn is_redirectable(&self) -> bool {
        matches!(self, AuthorizeError::InvalidRequest(_))
    }
}

impl AuthorizeParams {
    /// Validate everything that does not need a database.
    ///
    /// The caller must still check `client_id` and `redirect_uri` against the registry; those two
    /// are why [`AuthorizeError::UntrustedClient`] exists.
    pub fn validate(&self) -> Result<AuthorizeRequest, AuthorizeError> {
        let client_id = required(&self.client_id, "client_id")?;
        let redirect_uri = required(&self.redirect_uri, "redirect_uri")?;
        let state = required(&self.state, "state")?;

        if self.response_type.as_deref() != Some("code") {
            return Err(AuthorizeError::InvalidRequest(
                "response_type must be `code`".into(),
            ));
        }

        let code_challenge = required(&self.code_challenge, "code_challenge")?;
        if self.code_challenge_method.as_deref() != Some("S256") {
            return Err(AuthorizeError::InvalidRequest(
                "code_challenge_method must be `S256`".into(),
            ));
        }

        let scope = required(&self.scope, "scope")?;
        let scopes = parse_scope(&scope);
        if scopes.is_empty() {
            return Err(AuthorizeError::InvalidRequest(
                "scope must not be empty".into(),
            ));
        }
        if !scopes.iter().any(|scope| scope == "openid") {
            return Err(AuthorizeError::InvalidRequest(
                "scope must contain `openid`".into(),
            ));
        }

        if let Some(resource) = self.resource.as_deref()
            && !is_absolute_http_url(resource)
        {
            return Err(AuthorizeError::InvalidRequest(
                "resource must be an absolute http(s) URL".into(),
            ));
        }

        Ok(AuthorizeRequest {
            client_id,
            redirect_uri,
            scopes,
            state,
            code_challenge,
            nonce: self.nonce.clone().filter(|value| !value.is_empty()),
            resource: self.resource.clone().filter(|value| !value.is_empty()),
            organization: self.organization.clone().filter(|value| !value.is_empty()),
        })
    }
}

fn required(value: &Option<String>, name: &str) -> Result<String, AuthorizeError> {
    match value {
        Some(value) if !value.is_empty() => Ok(value.clone()),
        _ => Err(AuthorizeError::InvalidRequest(format!(
            "`{name}` is required"
        ))),
    }
}

/// Whether `value` is an absolute `http`/`https` URL — §6.2's rule for `resource`.
pub fn is_absolute_http_url(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !host.is_empty() && !host.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> AuthorizeParams {
        AuthorizeParams {
            response_type: Some("code".into()),
            client_id: Some("monaca-console".into()),
            redirect_uri: Some("http://localhost:5173/bff/callback".into()),
            scope: Some("openid profile".into()),
            state: Some("s".into()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            nonce: Some("n".into()),
            resource: Some("http://localhost:8080/v1".into()),
            organization: Some("acme".into()),
            prompt: None,
        }
    }

    #[test]
    fn a_valid_request_is_accepted() {
        let request = valid().validate().expect("valid");
        assert_eq!(request.scopes, vec!["openid", "profile"]);
        assert_eq!(request.organization.as_deref(), Some("acme"));
    }

    #[test]
    fn the_response_type_must_be_code() {
        let mut params = valid();
        params.response_type = Some("token".into());
        assert!(matches!(
            params.validate(),
            Err(AuthorizeError::InvalidRequest(_))
        ));
    }

    #[test]
    fn pkce_is_mandatory_and_s256_only() {
        let mut params = valid();
        params.code_challenge = None;
        assert!(params.validate().is_err());

        let mut params = valid();
        params.code_challenge_method = Some("plain".into());
        assert!(params.validate().is_err());
    }

    #[test]
    fn state_and_openid_are_required() {
        let mut params = valid();
        params.state = None;
        assert!(params.validate().is_err());

        let mut params = valid();
        params.scope = Some("profile".into());
        assert!(params.validate().is_err());
    }

    #[test]
    fn only_invalid_request_is_redirectable() {
        assert!(AuthorizeError::InvalidRequest("x".into()).is_redirectable());
        assert!(!AuthorizeError::UntrustedClient("x".into()).is_redirectable());
    }

    #[test]
    fn resource_must_be_an_absolute_http_url() {
        assert!(is_absolute_http_url("http://localhost:8080/mcp/demo"));
        assert!(is_absolute_http_url("https://a.test/x"));
        assert!(!is_absolute_http_url("/mcp/demo"));
        assert!(!is_absolute_http_url("ftp://a.test"));
        assert!(!is_absolute_http_url("http://"));
    }
}
