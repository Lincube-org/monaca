//! The interaction (login challenge) — §6.1.
//!
//! The interaction id is the bearer of the request: whoever holds it can complete the flow, which
//! is why it is high-entropy, short-lived and single-use. Everything the token endpoint will need
//! to mint a code lives in this struct, so the auth-ui never sees (or has to echo) the flow's
//! internals.

use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use monaca_types::InteractionId;

/// A pending authorize request, as stored between the redirect and the sign-in.
#[derive(Debug, Clone)]
pub struct Interaction {
    /// `int_…`, the bearer of this request.
    pub interaction_id: InteractionId,
    /// Tenant slug.
    pub tenant: String,
    /// The client's row id.
    pub client_row_id: Uuid,
    /// The client's protocol id.
    pub client_id: String,
    /// The client's display name.
    pub client_name: String,
    /// Where the code is sent.
    pub redirect_uri: String,
    /// Scopes the client asked for.
    pub scopes: Vec<String>,
    /// The org slug the flow will issue into.
    pub organization: String,
    /// PKCE challenge.
    pub code_challenge: String,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// The `state` to echo on the final redirect.
    pub state: String,
    /// RFC 9449 §10 key binding for the code this flow will mint.
    pub dpop_jkt: Option<String>,
    /// Whether the consent screen must be shown before a code is issued.
    pub consent_required: bool,
    /// When the interaction stops being usable.
    pub expires_at: OffsetDateTime,
}

impl Interaction {
    /// The JSON the auth-ui reads — §6.1's `GET /interaction/{iid}` body.
    pub fn to_public_json(&self) -> Value {
        json!({
            "interaction_id": self.interaction_id.to_string(),
            "tenant": self.tenant,
            "client": { "client_id": self.client_id, "name": self.client_name },
            "scopes": self.scopes,
            "organization": self.organization,
            "consent_required": self.consent_required,
            "expires_at": self.expires_at,
        })
    }

    /// Whether the interaction is past its TTL.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }
}

/// Why an interaction cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InteractionError {
    /// No interaction with this id exists (or it was already consumed and dropped).
    #[error("interaction not found")]
    NotFound,
    /// The interaction outlived its TTL.
    #[error("interaction expired")]
    Expired,
    /// The interaction was already used.
    #[error("interaction already consumed")]
    Consumed,
    /// Consent was requested before sign-in completed.
    #[error("interaction has not been signed in")]
    NotSignedIn,
}

impl InteractionError {
    /// The RFC 9457 `monaca_error_code`.
    pub const fn code(self) -> &'static str {
        match self {
            InteractionError::NotFound => "MONACA_INTERACTION_NOT_FOUND",
            InteractionError::Expired => "MONACA_INTERACTION_EXPIRED",
            InteractionError::Consumed => "MONACA_INTERACTION_CONSUMED",
            InteractionError::NotSignedIn => "MONACA_INTERACTION_NOT_SIGNED_IN",
        }
    }

    /// The HTTP status.
    pub const fn status(self) -> u16 {
        match self {
            InteractionError::NotFound => 404,
            InteractionError::Expired => 410,
            InteractionError::Consumed => 409,
            InteractionError::NotSignedIn => 409,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interaction() -> Interaction {
        Interaction {
            interaction_id: InteractionId::new(),
            tenant: "demo".into(),
            client_row_id: Uuid::now_v7(),
            client_id: "monaca-console".into(),
            client_name: "Monaca Console".into(),
            redirect_uri: "http://localhost:5173/bff/callback".into(),
            scopes: vec!["openid".into()],
            organization: "acme".into(),
            code_challenge: "challenge".into(),
            nonce: None,
            resource: None,
            state: "s".into(),
            dpop_jkt: None,
            consent_required: false,
            expires_at: OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("ts"),
        }
    }

    #[test]
    fn the_public_shape_matches_the_contract() {
        let value = interaction().to_public_json();
        assert_eq!(value["tenant"], "demo");
        assert_eq!(value["client"]["client_id"], "monaca-console");
        assert_eq!(value["client"]["name"], "Monaca Console");
        assert_eq!(value["scopes"], json!(["openid"]));
        assert_eq!(value["organization"], "acme");
        assert_eq!(value["consent_required"], json!(false));
        // Never expose the challenge, the state or the nonce to the page.
        assert!(value.get("code_challenge").is_none());
        assert!(value.get("state").is_none());
        assert!(value.get("nonce").is_none());
        assert!(value.get("dpop_jkt").is_none());
    }

    #[test]
    fn expiry_is_inclusive() {
        let value = interaction();
        assert!(value.is_expired(value.expires_at));
        assert!(!value.is_expired(value.expires_at - time::Duration::seconds(1)));
    }

    #[test]
    fn error_codes_match_the_contract() {
        assert_eq!(
            InteractionError::NotFound.code(),
            "MONACA_INTERACTION_NOT_FOUND"
        );
        assert_eq!(InteractionError::Expired.status(), 410);
        assert_eq!(InteractionError::Consumed.status(), 409);
        assert_eq!(
            InteractionError::NotSignedIn.code(),
            "MONACA_INTERACTION_NOT_SIGNED_IN"
        );
    }
}
