//! The interaction (login challenge) — §6.1.
//!
//! The interaction id is the bearer of the request: whoever holds it can complete the flow, which
//! is why it is high-entropy, short-lived and single-use. Everything the token endpoint will need
//! to mint a code lives in this struct, so the auth-ui never sees (or has to echo) the flow's
//! internals.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use monaca_types::InteractionId;

/// A pending authorize request, as stored between the redirect and the sign-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// The authorize request's `login_hint`, so the page can prefill its identifier field.
    pub login_hint: Option<String>,
    /// RFC 8707 resource.
    pub resource: Option<String>,
    /// The `state` to echo on the final redirect.
    pub state: String,
    /// RFC 9449 §10 key binding for the code this flow will mint.
    pub dpop_jkt: Option<String>,
    /// Whether the consent screen must be shown before a code is issued.
    pub consent_required: bool,
    /// Whether `prompt=consent` asked for the screen even if a grant already covers the scopes.
    pub consent_prompted: bool,
    /// When the interaction stops being usable.
    pub expires_at: OffsetDateTime,
    /// The IdP identity a verified SAML assertion carried, waiting for the session this flow
    /// creates. Absent on every other path; `#[serde(default)]` keeps interactions written
    /// before this field existed readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<SamlLogin>,
}

/// What a verified SAML assertion says about the IdP session it authenticates.
///
/// These three values are what an inbound `LogoutRequest` can name. `session_indexes` is empty
/// when the IdP supplied no `SessionIndex`; the SLO contract defines that state rather than
/// guessing a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlLogin {
    /// The connector the assertion came from.
    pub connector_id: String,
    /// The asserted NameID value.
    pub name_id: String,
    /// The NameID Format URI, when the assertion carried one.
    pub name_id_format: Option<String>,
    /// Every `AuthnStatement/SessionIndex` the assertion carried.
    pub session_indexes: Vec<String>,
}

impl Interaction {
    /// The JSON the auth-ui reads — §6.1's `GET /interaction/{iid}` body.
    ///
    /// `signed_in` is true when an existing session already authenticated this flow, so the page
    /// shows the consent step directly instead of asking for a password again.
    pub fn to_public_json(&self, signed_in: bool) -> Value {
        json!({
            "interaction_id": self.interaction_id.to_string(),
            "tenant": self.tenant,
            "client": { "client_id": self.client_id, "name": self.client_name },
            "scopes": self.scopes,
            "organization": self.organization,
            "login_hint": self.login_hint,
            "consent_required": self.consent_required,
            "signed_in": signed_in,
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
            login_hint: Some("person@demo.localhost".into()),
            resource: None,
            state: "s".into(),
            dpop_jkt: None,
            consent_required: false,
            consent_prompted: false,
            expires_at: OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("ts"),
            saml: None,
        }
    }

    #[test]
    fn the_public_shape_matches_the_contract() {
        let value = interaction().to_public_json(false);
        assert_eq!(value["tenant"], "demo");
        assert_eq!(value["client"]["client_id"], "monaca-console");
        assert_eq!(value["client"]["name"], "Monaca Console");
        assert_eq!(value["scopes"], json!(["openid"]));
        assert_eq!(value["organization"], "acme");
        assert_eq!(value["login_hint"], "person@demo.localhost");
        assert_eq!(value["consent_required"], json!(false));
        assert_eq!(value["signed_in"], json!(false));
        assert_eq!(
            interaction().to_public_json(true)["signed_in"],
            json!(true),
            "an SSO-reused flow skips the password form"
        );
        // Never expose the challenge, the state or the nonce to the page.
        assert!(value.get("code_challenge").is_none());
        assert!(value.get("state").is_none());
        assert!(value.get("nonce").is_none());
        assert!(value.get("dpop_jkt").is_none());
        assert!(value.get("saml").is_none());
    }

    #[test]
    fn an_interaction_written_before_the_saml_field_still_parses() {
        let mut value = serde_json::to_value(interaction()).expect("payload");
        value.as_object_mut().expect("object").remove("saml");
        let decoded: Interaction = serde_json::from_value(value).expect("backward compatible");
        assert!(decoded.saml.is_none());
    }

    #[test]
    fn the_saml_binding_round_trips() {
        let mut value = interaction();
        value.saml = Some(SamlLogin {
            connector_id: "okta".into(),
            name_id: "user@corp.example".into(),
            name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
            session_indexes: vec!["_s1".into(), "_s2".into()],
        });
        let decoded: Interaction =
            serde_json::from_value(serde_json::to_value(&value).expect("payload"))
                .expect("the field round-trips");
        assert_eq!(decoded.saml, value.saml);
    }

    #[test]
    fn an_absent_login_hint_is_reported_as_null() {
        // The key is always present so the page can bind it without a conditional type.
        let mut value = interaction();
        value.login_hint = None;
        assert_eq!(value.to_public_json(false)["login_hint"], json!(null));
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
