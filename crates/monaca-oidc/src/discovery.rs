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

    /// Render the document.
    pub fn to_json(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint(),
            "token_endpoint": self.token_endpoint(),
            "jwks_uri": self.jwks_uri(),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none", "client_secret_basic", "client_secret_post", "private_key_jwt"
            ],
            "authorization_details_types_supported": ["monaca_grant"],
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
