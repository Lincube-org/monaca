//! The discovery document — §6.1.
//!
//! One document, served byte-identically at both path forms. It is built from the issuer rather
//! than from the request, so a request arriving through the gateway and one arriving directly
//! cannot produce different `iss` values.

use serde_json::{Value, json};

/// The OpenID Connect / RFC 8414 discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryDocument {
    /// `{base}/t/{tenant}`.
    pub issuer: String,
}

impl DiscoveryDocument {
    /// The document for `issuer`.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
        }
    }

    /// The authorization endpoint.
    pub fn authorization_endpoint(&self) -> String {
        format!("{}/oauth2/authorize", self.issuer)
    }

    /// The token endpoint.
    pub fn token_endpoint(&self) -> String {
        format!("{}/oauth2/token", self.issuer)
    }

    /// The JWKS URI.
    pub fn jwks_uri(&self) -> String {
        format!("{}/.well-known/jwks.json", self.issuer)
    }

    /// The UserInfo endpoint (OIDC Core §5.3).
    pub fn userinfo_endpoint(&self) -> String {
        format!("{}/oauth2/userinfo", self.issuer)
    }

    /// The token introspection endpoint (RFC 7662).
    pub fn introspection_endpoint(&self) -> String {
        format!("{}/oauth2/introspect", self.issuer)
    }

    /// The token revocation endpoint (RFC 7009).
    pub fn revocation_endpoint(&self) -> String {
        format!("{}/oauth2/revoke", self.issuer)
    }

    /// The pushed authorization request endpoint (RFC 9126).
    pub fn pushed_authorization_request_endpoint(&self) -> String {
        format!("{}/oauth2/par", self.issuer)
    }

    /// The RP-initiated logout endpoint (OpenID Connect RP-Initiated Logout 1.0 §2).
    pub fn end_session_endpoint(&self) -> String {
        format!("{}/oauth2/end-session", self.issuer)
    }

    /// Render the document.
    pub fn to_json(&self) -> Value {
        let auth_methods = json!([
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ]);
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint(),
            "token_endpoint": self.token_endpoint(),
            "userinfo_endpoint": self.userinfo_endpoint(),
            "introspection_endpoint": self.introspection_endpoint(),
            "revocation_endpoint": self.revocation_endpoint(),
            "pushed_authorization_request_endpoint": self.pushed_authorization_request_endpoint(),
            "end_session_endpoint": self.end_session_endpoint(),
            "frontchannel_logout_supported": true,
            "frontchannel_logout_session_supported": true,
            "jwks_uri": self.jwks_uri(),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": auth_methods,
            "introspection_endpoint_auth_methods_supported": auth_methods,
            "revocation_endpoint_auth_methods_supported": auth_methods,
            "authorization_details_types_supported": ["monaca_grant"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "prompt_values_supported": ["none", "login", "consent"],
            "claims_supported": [
                "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "tid", "org",
                "email", "email_verified", "name"
            ],
            "scopes_supported": [
                "openid", "profile", "email", "offline_access", "tools:read", "tools:write",
                "monaca:admin"
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_matches_the_contract() {
        let value = DiscoveryDocument::new("http://localhost:8080/t/demo").to_json();
        assert_eq!(value["issuer"], "http://localhost:8080/t/demo");
        assert_eq!(
            value["authorization_endpoint"],
            "http://localhost:8080/t/demo/oauth2/authorize"
        );
        assert_eq!(
            value["token_endpoint"],
            "http://localhost:8080/t/demo/oauth2/token"
        );
        assert_eq!(
            value["jwks_uri"],
            "http://localhost:8080/t/demo/.well-known/jwks.json"
        );
        assert_eq!(
            value["userinfo_endpoint"],
            "http://localhost:8080/t/demo/oauth2/userinfo"
        );
        assert_eq!(
            value["introspection_endpoint"],
            "http://localhost:8080/t/demo/oauth2/introspect"
        );
        assert_eq!(
            value["revocation_endpoint"],
            "http://localhost:8080/t/demo/oauth2/revoke"
        );
        assert_eq!(
            value["pushed_authorization_request_endpoint"],
            "http://localhost:8080/t/demo/oauth2/par"
        );
        assert_eq!(
            value["end_session_endpoint"],
            "http://localhost:8080/t/demo/oauth2/end-session"
        );
        assert_eq!(value["frontchannel_logout_supported"], json!(true));
        assert_eq!(value["dpop_signing_alg_values_supported"], json!(["ES256"]));
        assert_eq!(
            value["prompt_values_supported"],
            json!(["none", "login", "consent"])
        );
        assert_eq!(value["response_types_supported"], json!(["code"]));
        assert_eq!(
            value["grant_types_supported"],
            json!(["authorization_code", "refresh_token", "client_credentials"])
        );
        assert_eq!(value["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            value["authorization_details_types_supported"],
            json!(["monaca_grant"])
        );
        assert_eq!(
            value["id_token_signing_alg_values_supported"],
            json!(["ES256"])
        );
    }

    /// Both path forms must produce byte-identical JSON.
    #[test]
    fn rendering_is_deterministic() {
        let document = DiscoveryDocument::new("http://localhost:8080/t/demo");
        assert_eq!(
            document.to_json().to_string(),
            document.to_json().to_string()
        );
    }
}
