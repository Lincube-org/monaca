//! `GET /t/{tenant}/oauth2/authorize` — §6.1.
//!
//! Validation is split from routing because the failure mode differs: an unknown `client_id` or an
//! unregistered `redirect_uri` must be shown as an error page and **never** redirected (§6.1),
//! while every other failure redirects with `error=invalid_request`. [`AuthorizeError`] therefore
//! carries whether the request is safe to redirect.

use serde::{Deserialize, Serialize};

use crate::parse_scope;

/// The query parameters of an authorize request. Every member is optional so a missing one is a
/// protocol error rather than an extractor rejection with the wrong shape.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
    /// `none` | `login` | `consent`, space-delimited.
    pub prompt: Option<String>,
    /// OpenID Connect Core §3.1.2.1: the maximum age of the authentication, in seconds.
    pub max_age: Option<String>,
    /// RFC 9126: a pushed request to redeem instead of the inline parameters.
    pub request_uri: Option<String>,
    /// RFC 9449 §10: the JWK thumbprint the authorization code is bound to.
    pub dpop_jkt: Option<String>,
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
    /// Validated prompt values.
    pub prompt: Vec<String>,
    /// The maximum acceptable age of the authentication, in seconds.
    pub max_age: Option<i64>,
    /// RFC 9449 §10 key binding.
    pub dpop_jkt: Option<String>,
}

impl AuthorizeRequest {
    /// `prompt=consent` forces the consent step even for a first-party client.
    pub fn forces_consent(&self) -> bool {
        self.prompt.iter().any(|value| value == "consent")
    }

    /// `prompt=none` asks for a silent authentication. Without a cross-application session,
    /// monaca has to answer `login_required`.
    pub fn is_silent(&self) -> bool {
        self.prompt.iter().any(|value| value == "none")
    }

    /// Whether this request must show the consent screen before a code is issued.
    pub fn requires_consent(&self, client_is_third_party: bool) -> bool {
        client_is_third_party || self.forces_consent()
    }
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

        let prompt = parse_prompt(self.prompt.as_deref())?;
        let max_age = parse_max_age(self.max_age.as_deref())?;
        let dpop_jkt = parse_dpop_jkt(self.dpop_jkt.as_deref())?;

        Ok(AuthorizeRequest {
            client_id,
            redirect_uri,
            scopes,
            state,
            code_challenge,
            nonce: self.nonce.clone().filter(|value| !value.is_empty()),
            resource: self.resource.clone().filter(|value| !value.is_empty()),
            organization: self.organization.clone().filter(|value| !value.is_empty()),
            prompt,
            max_age,
            dpop_jkt,
        })
    }
}

/// Validate `prompt` — OpenID Connect Core §3.1.2.1.
///
/// `none` must be the only value; `select_account` is not implemented, because monaca has no
/// cross-application session to select an account from.
fn parse_prompt(raw: Option<&str>) -> Result<Vec<String>, AuthorizeError> {
    let values = raw.unwrap_or_default();
    let prompt: Vec<String> = values.split_ascii_whitespace().map(str::to_owned).collect();
    for value in &prompt {
        if !matches!(value.as_str(), "none" | "login" | "consent") {
            return Err(AuthorizeError::InvalidRequest(format!(
                "unsupported prompt value `{value}`"
            )));
        }
    }
    if prompt.iter().any(|value| value == "none") && prompt.len() > 1 {
        return Err(AuthorizeError::InvalidRequest(
            "prompt=none cannot be combined with other values".into(),
        ));
    }
    Ok(prompt)
}

/// Validate `max_age` — OpenID Connect Core §3.1.2.1: a non-negative integer number of seconds.
fn parse_max_age(raw: Option<&str>) -> Result<Option<i64>, AuthorizeError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let seconds: i64 = value.parse().map_err(|_| {
        AuthorizeError::InvalidRequest("max_age must be an integer number of seconds".into())
    })?;
    if seconds < 0 {
        return Err(AuthorizeError::InvalidRequest(
            "max_age must not be negative".into(),
        ));
    }
    Ok(Some(seconds))
}

/// Validate an RFC 9449 §10 `dpop_jkt`: base64url(SHA-256(JWK)), 43 characters.
fn parse_dpop_jkt(raw: Option<&str>) -> Result<Option<String>, AuthorizeError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AuthorizeError::InvalidRequest(
            "dpop_jkt is not a JWK thumbprint".into(),
        ));
    }
    Ok(Some(value.to_owned()))
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
            max_age: None,
            request_uri: None,
            dpop_jkt: None,
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

    #[test]
    fn prompt_values_are_validated() {
        let mut params = valid();
        params.prompt = Some("consent login".into());
        let request = params.validate().expect("valid");
        assert!(request.forces_consent());
        assert!(!request.is_silent());

        let mut params = valid();
        params.prompt = Some("none".into());
        assert!(params.validate().expect("valid").is_silent());

        let mut params = valid();
        params.prompt = Some("none login".into());
        assert!(params.validate().is_err());

        let mut params = valid();
        params.prompt = Some("select_account".into());
        assert!(params.validate().is_err());
    }

    #[test]
    fn a_third_party_client_always_consents() {
        let request = valid().validate().expect("valid");
        assert!(!request.requires_consent(false));
        assert!(request.requires_consent(true));

        let mut params = valid();
        params.prompt = Some("consent".into());
        assert!(params.validate().expect("valid").requires_consent(false));
    }

    #[test]
    fn max_age_is_a_non_negative_integer() {
        let mut params = valid();
        params.max_age = Some("600".into());
        assert_eq!(params.validate().expect("valid").max_age, Some(600));

        let mut params = valid();
        params.max_age = Some("0".into());
        assert_eq!(params.validate().expect("valid").max_age, Some(0));

        let mut params = valid();
        params.max_age = Some("-1".into());
        assert!(params.validate().is_err());

        let mut params = valid();
        params.max_age = Some("soon".into());
        assert!(params.validate().is_err());

        let mut params = valid();
        params.max_age = Some("".into());
        assert_eq!(params.validate().expect("valid").max_age, None);
    }

    #[test]
    fn dpop_jkt_must_be_a_thumbprint() {
        let mut params = valid();
        params.dpop_jkt = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into());
        assert_eq!(
            params.validate().expect("valid").dpop_jkt.as_deref(),
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        );

        let mut params = valid();
        params.dpop_jkt = Some("short".into());
        assert!(params.validate().is_err());
    }
}
