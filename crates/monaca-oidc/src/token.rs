//! The token endpoint — §6.1 and §7.
//!
//! This module owns the request shape, the RFC 6749 §5.2 error codes (the one place the API is not
//! RFC 9457) and the claim shapes for access and id tokens. It does not own keys, storage or the
//! client registry; those are the caller's.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::parse_scope;

/// The OAuth 2.0 / RFC 6749 §5.2 token-endpoint error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenErrorCode {
    /// The request is missing a parameter or is otherwise malformed.
    InvalidRequest,
    /// Client authentication failed. Answered with 401 and `WWW-Authenticate: Basic realm="monaca"`.
    InvalidClient,
    /// The grant or refresh token is invalid, expired or revoked.
    InvalidGrant,
    /// The client is not allowed to use this grant type.
    UnauthorizedClient,
    /// The grant type is not supported.
    UnsupportedGrantType,
    /// The requested scope exceeds what the grant allows.
    InvalidScope,
    /// The request carried no DPoP proof, or the proof did not verify (RFC 9449 §7.1).
    InvalidDpopProof,
}

impl TokenErrorCode {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            TokenErrorCode::InvalidRequest => "invalid_request",
            TokenErrorCode::InvalidClient => "invalid_client",
            TokenErrorCode::InvalidGrant => "invalid_grant",
            TokenErrorCode::UnauthorizedClient => "unauthorized_client",
            TokenErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            TokenErrorCode::InvalidScope => "invalid_scope",
            TokenErrorCode::InvalidDpopProof => "invalid_dpop_proof",
        }
    }

    /// The HTTP status §6.1 requires for this code.
    pub const fn status(self) -> u16 {
        match self {
            TokenErrorCode::InvalidClient => 401,
            _ => 400,
        }
    }
}

/// The grant types the token endpoint accepts — §6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    /// `authorization_code`, with mandatory PKCE S256.
    AuthorizationCode,
    /// `refresh_token`.
    RefreshToken,
    /// `client_credentials`, with RFC 8707 `resource` and RFC 9396 `authorization_details`.
    ClientCredentials,
}

impl GrantType {
    /// The wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
        }
    }

    /// Parse a `grant_type` parameter.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "refresh_token" => Some(GrantType::RefreshToken),
            "client_credentials" => Some(GrantType::ClientCredentials),
            _ => None,
        }
    }
}

/// The raw form body of a token request.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenForm {
    /// `authorization_code` | `refresh_token` | `client_credentials`.
    pub grant_type: Option<String>,
    /// Authorization code.
    pub code: Option<String>,
    /// Must match the code's binding.
    pub redirect_uri: Option<String>,
    /// The client's protocol id (also may come from HTTP Basic).
    pub client_id: Option<String>,
    /// `client_secret_post` secret.
    pub client_secret: Option<String>,
    /// PKCE verifier.
    pub code_verifier: Option<String>,
    /// Refresh token.
    pub refresh_token: Option<String>,
    /// Requested scope.
    pub scope: Option<String>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// RFC 9396 authorization details (JSON string).
    pub authorization_details: Option<String>,
    /// `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
    pub client_assertion_type: Option<String>,
    /// `private_key_jwt` assertion.
    pub client_assertion: Option<String>,
}

/// A parsed, not yet authorized token request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// The grant type.
    pub grant_type: GrantType,
    /// The code / refresh token / assertion, depending on the grant.
    pub code: Option<String>,
    /// The redirect URI the code was issued for.
    pub redirect_uri: Option<String>,
    /// The client id supplied in the body (Basic auth wins when present).
    pub client_id: Option<String>,
    /// The `client_secret_post` secret, when the client used that method.
    pub client_secret: Option<String>,
    /// PKCE verifier.
    pub code_verifier: Option<String>,
    /// Refresh token.
    pub refresh_token: Option<String>,
    /// Requested scopes, when the request narrowed them.
    pub scope: Option<Vec<String>>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// RFC 9396 authorization details, parsed.
    pub authorization_details: Option<Value>,
    /// `private_key_jwt` assertion.
    pub client_assertion: Option<String>,
}

impl TokenRequest {
    /// Parse a form into a request, rejecting only what is malformed without a database.
    pub fn parse(form: &TokenForm) -> Result<Self, TokenErrorCode> {
        let grant_type = form
            .grant_type
            .as_deref()
            .and_then(GrantType::parse)
            .ok_or(TokenErrorCode::UnsupportedGrantType)?;

        let authorization_details = match form.authorization_details.as_deref() {
            Some(raw) if !raw.is_empty() => {
                let value: Value =
                    serde_json::from_str(raw).map_err(|_| TokenErrorCode::InvalidRequest)?;
                if !value.is_array() {
                    return Err(TokenErrorCode::InvalidRequest);
                }
                Some(value)
            }
            _ => None,
        };

        if let Some(resource) = form.resource.as_deref()
            && !crate::authorize::is_absolute_http_url(resource)
        {
            return Err(TokenErrorCode::InvalidRequest);
        }

        let request = Self {
            grant_type,
            code: non_empty(&form.code),
            redirect_uri: non_empty(&form.redirect_uri),
            client_id: non_empty(&form.client_id),
            client_secret: non_empty(&form.client_secret),
            code_verifier: non_empty(&form.code_verifier),
            refresh_token: non_empty(&form.refresh_token),
            scope: form.scope.as_deref().map(parse_scope),
            resource: non_empty(&form.resource),
            authorization_details,
            client_assertion: non_empty(&form.client_assertion),
        };

        match grant_type {
            GrantType::AuthorizationCode => {
                if request.code.is_none()
                    || request.redirect_uri.is_none()
                    || request.code_verifier.is_none()
                {
                    return Err(TokenErrorCode::InvalidRequest);
                }
            }
            GrantType::RefreshToken => {
                if request.refresh_token.is_none() {
                    return Err(TokenErrorCode::InvalidRequest);
                }
            }
            GrantType::ClientCredentials => {}
        }

        Ok(request)
    }

    /// The grant id named by RFC 9396 `authorization_details`, if any.
    pub fn grant_id_from_details(&self) -> Option<&str> {
        self.authorization_details
            .as_ref()?
            .as_array()?
            .iter()
            .find(|detail| detail.get("type").and_then(Value::as_str) == Some("monaca_grant"))?
            .get("grant_id")?
            .as_str()
    }
}

fn non_empty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// A parsed `private_key_jwt` client assertion — §7.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAssertion {
    /// `iss`, which must equal the client id.
    pub iss: String,
    /// `sub`, which must equal the client id.
    pub sub: String,
    /// `aud`, which must be the token endpoint exactly.
    pub aud: String,
    /// `jti`, single-use.
    pub jti: String,
    /// `iat`.
    pub iat: i64,
    /// `exp`; at most `iat + 300`.
    pub exp: i64,
}

/// Why an assertion is unacceptable before its signature is even checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    /// A required claim is missing or has the wrong type.
    #[error("client assertion claim is missing or malformed")]
    Malformed,
    /// `iss`/`sub` does not name the client.
    #[error("client assertion does not name this client")]
    WrongSubject,
    /// `aud` is not the token endpoint.
    #[error("client assertion audience is not the token endpoint")]
    WrongAudience,
    /// `exp` is more than 300 s after `iat`, or already past.
    #[error("client assertion is expired or too long-lived")]
    Expired,
}

/// Validate an assertion's claims — §7.4.
pub fn validate_assertion_claims(
    claims: &Value,
    client_id: &str,
    token_endpoint: &str,
    now: i64,
) -> Result<ClientAssertion, AssertionError> {
    let string = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or(AssertionError::Malformed)
    };
    let number = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_i64)
            .ok_or(AssertionError::Malformed)
    };

    let assertion = ClientAssertion {
        iss: string("iss")?,
        sub: string("sub")?,
        aud: string("aud")?,
        jti: string("jti")?,
        iat: number("iat")?,
        exp: number("exp")?,
    };

    if assertion.iss != client_id || assertion.sub != client_id {
        return Err(AssertionError::WrongSubject);
    }
    if assertion.aud != token_endpoint {
        return Err(AssertionError::WrongAudience);
    }
    if assertion.exp <= now || assertion.exp > assertion.iat.saturating_add(300) {
        return Err(AssertionError::Expired);
    }

    Ok(assertion)
}

/// The user access-token claims — §7.1.
#[derive(Debug, Clone)]
pub struct AccessTokenClaims {
    /// `iss`.
    pub iss: String,
    /// `sub`, the account (`acc_…`).
    pub sub: String,
    /// `aud`, the resource.
    pub aud: String,
    /// `tid`, the tenant (`ten_…`).
    pub tid: String,
    /// `org`, the organization (`org_…`).
    pub org: String,
    /// `scope`, sorted.
    pub scope: Vec<String>,
    /// `jti`, a raw UUIDv7.
    pub jti: String,
    /// `iat`.
    pub iat: i64,
    /// `exp`.
    pub exp: i64,
    /// `act`, present on delegated tokens.
    pub act: Option<Value>,
    /// `grant_id`, present on delegated tokens.
    pub grant_id: Option<String>,
    /// `cnf`, the proof-of-possession binding (RFC 7800); `{"jkt": …}` for DPoP tokens.
    pub cnf: Option<Value>,
}

impl AccessTokenClaims {
    /// The JSON body of the JWS.
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "tid": self.tid,
            "org": self.org,
            "scope": self.scope,
            "jti": self.jti,
            "iat": self.iat,
            "exp": self.exp,
        });
        if let Some(act) = &self.act {
            value["act"] = act.clone();
        }
        if let Some(grant_id) = &self.grant_id {
            value["grant_id"] = Value::String(grant_id.clone());
        }
        if let Some(cnf) = &self.cnf {
            value["cnf"] = cnf.clone();
        }
        value
    }
}

/// The id_token claims — §7.3.
#[derive(Debug, Clone)]
pub struct IdTokenClaims {
    /// `iss`.
    pub iss: String,
    /// `sub`, the account (`acc_…`).
    pub sub: String,
    /// `aud`, the client id.
    pub aud: String,
    /// `tid`.
    pub tid: String,
    /// `org`.
    pub org: String,
    /// `iat`.
    pub iat: i64,
    /// `exp`.
    pub exp: i64,
    /// `nonce`, echoed when the authorize request supplied one.
    pub nonce: Option<String>,
    /// `email`, only for `scope` containing `email`.
    pub email: Option<String>,
    /// `name`, only for `scope` containing `profile`.
    pub name: Option<String>,
    /// `auth_time`, the instant the user actually authenticated (OIDC Core §2).
    pub auth_time: Option<i64>,
    /// `at_hash`, the access token's left-half digest (OIDC Core §3.1.3.6).
    pub at_hash: Option<String>,
    /// `roles`, the RBAC role names granted to this account; omitted when it holds none (§7.3).
    pub roles: Vec<String>,
}

impl IdTokenClaims {
    /// The JSON body of the JWS.
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "tid": self.tid,
            "org": self.org,
            "iat": self.iat,
            "exp": self.exp,
        });
        if let Some(nonce) = &self.nonce {
            value["nonce"] = Value::String(nonce.clone());
        }
        if let Some(email) = &self.email {
            value["email"] = Value::String(email.clone());
        }
        if let Some(name) = &self.name {
            value["name"] = Value::String(name.clone());
        }
        if let Some(auth_time) = self.auth_time {
            value["auth_time"] = Value::from(auth_time);
        }
        if let Some(at_hash) = &self.at_hash {
            value["at_hash"] = Value::String(at_hash.clone());
        }
        if !self.roles.is_empty() {
            value["roles"] = json!(self.roles);
        }
        value
    }
}

/// The UserInfo response — OIDC Core §5.3.
#[derive(Debug, Clone)]
pub struct UserInfoClaims {
    /// `sub`, the account (`acc_…`). Always present.
    pub sub: String,
    /// `name`, only for `scope` containing `profile`.
    pub name: Option<String>,
    /// `email`, only for `scope` containing `email`.
    pub email: Option<String>,
    /// `email_verified`, alongside `email`.
    pub email_verified: Option<bool>,
}

impl UserInfoClaims {
    /// The JSON body.
    pub fn to_json(&self) -> Value {
        let mut value = json!({ "sub": self.sub });
        if let Some(name) = &self.name {
            value["name"] = Value::String(name.clone());
        }
        if let Some(email) = &self.email {
            value["email"] = Value::String(email.clone());
        }
        if let Some(verified) = self.email_verified {
            value["email_verified"] = Value::from(verified);
        }
        value
    }
}

/// `base64url(left-half(SHA-256(access_token)))` — OIDC Core §3.1.3.6.
pub fn at_hash(access_token: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(access_token.as_bytes());
    data_encoding::BASE64URL_NOPAD.encode(&digest[..digest.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(grant: &str) -> TokenForm {
        TokenForm {
            grant_type: Some(grant.into()),
            ..TokenForm::default()
        }
    }

    #[test]
    fn token_error_codes_match_rfc_6749() {
        assert_eq!(TokenErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(TokenErrorCode::InvalidClient.status(), 401);
        assert_eq!(TokenErrorCode::InvalidScope.status(), 400);
    }

    #[test]
    fn grant_types_round_trip() {
        for grant in [
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
        ] {
            assert_eq!(GrantType::parse(grant.as_str()), Some(grant));
        }
        assert_eq!(GrantType::parse("password"), None);
    }

    #[test]
    fn an_unknown_grant_type_is_unsupported() {
        assert_eq!(
            TokenRequest::parse(&form("password")).unwrap_err(),
            TokenErrorCode::UnsupportedGrantType
        );
    }

    #[test]
    fn authorization_code_requires_code_redirect_and_verifier() {
        assert_eq!(
            TokenRequest::parse(&form("authorization_code")).unwrap_err(),
            TokenErrorCode::InvalidRequest
        );

        let mut ok = form("authorization_code");
        ok.code = Some("c".into());
        ok.redirect_uri = Some("http://localhost:5173/bff/callback".into());
        ok.code_verifier = Some("v".repeat(43));
        assert!(TokenRequest::parse(&ok).is_ok());
    }

    #[test]
    fn refresh_requires_a_token() {
        assert_eq!(
            TokenRequest::parse(&form("refresh_token")).unwrap_err(),
            TokenErrorCode::InvalidRequest
        );
    }

    #[test]
    fn authorization_details_must_be_an_array() {
        let mut request = form("client_credentials");
        request.authorization_details = Some("{}".into());
        assert_eq!(
            TokenRequest::parse(&request).unwrap_err(),
            TokenErrorCode::InvalidRequest
        );

        request.authorization_details =
            Some(r#"[{"type":"monaca_grant","grant_id":"grt_x"}]"#.into());
        let parsed = TokenRequest::parse(&request).expect("parses");
        assert_eq!(parsed.grant_id_from_details(), Some("grt_x"));
    }

    #[test]
    fn assertion_claims_are_checked() {
        let now = 1_767_225_600i64;
        let claims = json!({
            "iss": "agt_x", "sub": "agt_x", "aud": "http://localhost:8080/t/demo/oauth2/token",
            "jti": "j", "iat": now, "exp": now + 120,
        });
        let assertion = validate_assertion_claims(
            &claims,
            "agt_x",
            "http://localhost:8080/t/demo/oauth2/token",
            now,
        )
        .expect("valid");
        assert_eq!(assertion.jti, "j");

        let mut wrong = claims.clone();
        wrong["aud"] = json!("http://localhost:8080/v1");
        assert_eq!(
            validate_assertion_claims(
                &wrong,
                "agt_x",
                "http://localhost:8080/t/demo/oauth2/token",
                now
            )
            .unwrap_err(),
            AssertionError::WrongAudience
        );

        let mut long = claims.clone();
        long["exp"] = json!(now + 301);
        assert_eq!(
            validate_assertion_claims(
                &long,
                "agt_x",
                "http://localhost:8080/t/demo/oauth2/token",
                now
            )
            .unwrap_err(),
            AssertionError::Expired
        );
    }

    #[test]
    fn the_access_token_shape_matches_the_contract() {
        let claims = AccessTokenClaims {
            iss: "http://localhost:8080/t/demo".into(),
            sub: "acc_00000000000000000000000000".into(),
            aud: "http://localhost:8080/mcp/demo".into(),
            tid: "ten_00000000000000000000000000".into(),
            org: "org_00000000000000000000000000".into(),
            scope: vec!["tools:read".into()],
            jti: "01920000-0000-7000-8000-000000000000".into(),
            iat: 1_767_225_600,
            exp: 1_767_226_500,
            act: None,
            grant_id: None,
            cnf: None,
        };
        let value = claims.to_json();
        assert_eq!(value["scope"], json!(["tools:read"]));
        assert!(value.get("act").is_none());
        assert!(value.get("grant_id").is_none());
        assert!(value.get("cnf").is_none());
    }

    #[test]
    fn a_dpop_binding_appears_as_cnf() {
        let claims = AccessTokenClaims {
            iss: "http://localhost:8080/t/demo".into(),
            sub: "acc_x".into(),
            aud: "http://localhost:8080/v1".into(),
            tid: "ten_x".into(),
            org: "org_x".into(),
            scope: vec!["openid".into()],
            jti: "j".into(),
            iat: 0,
            exp: 1,
            act: None,
            grant_id: None,
            cnf: Some(json!({ "jkt": "jkt" })),
        };
        assert_eq!(claims.to_json()["cnf"], json!({ "jkt": "jkt" }));
    }

    #[test]
    fn the_id_token_carries_auth_time_and_at_hash() {
        let claims = IdTokenClaims {
            iss: "http://localhost:8080/t/demo".into(),
            sub: "acc_x".into(),
            aud: "monaca-console".into(),
            tid: "ten_x".into(),
            org: "org_x".into(),
            iat: 100,
            exp: 200,
            nonce: None,
            email: None,
            name: None,
            auth_time: Some(90),
            at_hash: Some(at_hash("access-token")),
            roles: vec!["admin".into()],
        };
        let value = claims.to_json();
        assert_eq!(value["auth_time"], json!(90));
        assert_eq!(value["at_hash"], json!(at_hash("access-token")));
        assert_eq!(value["roles"], json!(["admin"]));
    }

    #[test]
    fn an_account_without_roles_gets_no_roles_claim() {
        let claims = IdTokenClaims {
            iss: "http://localhost:8080/t/demo".into(),
            sub: "acc_x".into(),
            aud: "monaca-console".into(),
            tid: "ten_x".into(),
            org: "org_x".into(),
            iat: 100,
            exp: 200,
            nonce: None,
            email: None,
            name: None,
            auth_time: None,
            at_hash: None,
            roles: Vec::new(),
        };
        assert!(claims.to_json().get("roles").is_none());
    }

    #[test]
    fn at_hash_is_the_left_half_of_the_digest() {
        // 32-byte digest, so the left half is 16 bytes and the encoding is 22 characters.
        assert_eq!(at_hash("x").len(), 22);
        assert_ne!(at_hash("a"), at_hash("b"));
    }

    #[test]
    fn userinfo_only_echoes_scoped_claims() {
        let claims = UserInfoClaims {
            sub: "acc_x".into(),
            name: Some("Ada".into()),
            email: Some("ada@example.test".into()),
            email_verified: Some(true),
        };
        let value = claims.to_json();
        assert_eq!(value["sub"], "acc_x");
        assert_eq!(value["name"], "Ada");
        assert_eq!(value["email_verified"], json!(true));

        let bare = UserInfoClaims {
            sub: "acc_x".into(),
            name: None,
            email: None,
            email_verified: None,
        };
        assert_eq!(bare.to_json(), json!({ "sub": "acc_x" }));
    }
}
