//! WebAuthn ceremony plumbing shared by the account centre and the sign-in protocol.
//!
//! The cryptographic checks live in `monaca-crypto`; this module only does the parts that are
//! HTTP-shaped: deriving the relying party from the configured sign-in origin, serialising the
//! options the browser's `navigator.credentials` expects, and parsing what the browser returns.
//!
//! The relying party is the *hosted sign-in origin* (`MONACA_AUTH_UI_URL`), not the API origin:
//! that is where `navigator.credentials` runs, and a credential is bound to the host that asked
//! for it.

use monaca_crypto::{decode_base64url, encode_base64url};
use monaca_store::PasskeyRow;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::error::ApiError;

/// How long a ceremony's challenge stays acceptable.
pub const CHALLENGE_TTL_SECS: i64 = 600;

/// The transport hints the WebAuthn spec defines. Anything else the browser sends is ignored.
const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"];

/// The host and origin a passkey ceremony is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    /// Bare host (no scheme, no port), hashed into the authenticator data.
    pub id: String,
    /// The full `scheme://authority` the browser checks in `clientDataJSON.origin`.
    pub origin: String,
}

/// The relying party for this deployment.
pub fn relying_party(config: &Config) -> Result<RelyingParty, ApiError> {
    parse_relying_party(&config.auth_ui_url)
}

fn parse_relying_party(url: &str) -> Result<RelyingParty, ApiError> {
    let origin = url.trim().trim_end_matches('/');
    let (scheme, rest) = origin
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "http" | "https"))
        .ok_or_else(|| ApiError::internal("MONACA_AUTH_UI_URL must be an absolute http(s) URL"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host_of(authority);
    if authority.is_empty() || host.is_empty() {
        return Err(ApiError::internal("MONACA_AUTH_UI_URL has no host"));
    }
    Ok(RelyingParty {
        id: host.to_owned(),
        origin: format!("{scheme}://{authority}"),
    })
}

/// Strip the port from an authority. IPv6 literals keep the address inside their brackets.
fn host_of(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    }
}

/// `PublicKeyCredentialCreationOptions`, as the browser expects them.
///
/// `resident_key` is required because the sign-in page cannot name an account up front: without a
/// discoverable credential the browser would have no passkey to offer for a passwordless sign-in.
pub fn registration_options(
    rp: &RelyingParty,
    account_id: &monaca_store::AccountRow,
    challenge: &[u8],
    exclude: Vec<Value>,
) -> Value {
    json!({
        "challenge": encode_base64url(challenge),
        "rp": { "id": rp.id, "name": crate::account::ISSUER },
        "user": {
            "id": encode_base64url(account_id.id.as_bytes()),
            "name": account_id.primary_email,
            "displayName": account_id.display_name,
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "timeout": CHALLENGE_TTL_SECS * 1000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "required",
        },
        "excludeCredentials": exclude,
    })
}

/// `PublicKeyCredentialRequestOptions`, as the browser expects them.
///
/// An empty `allow` is the discoverable-credential case: the browser chooses among the passkeys it
/// holds for this host, and the assertion arrives with the user handle the account can be resolved
/// from.
pub fn assertion_options(rp_id: &str, challenge: &[u8], allow: Vec<Value>) -> Value {
    json!({
        "challenge": encode_base64url(challenge),
        "rpId": rp_id,
        "timeout": CHALLENGE_TTL_SECS * 1000,
        "userVerification": "required",
        "allowCredentials": allow,
    })
}

/// One `allowCredentials` / `excludeCredentials` entry for a stored passkey.
pub fn credential_descriptor(row: &PasskeyRow) -> Value {
    json!({
        "type": "public-key",
        "id": encode_base64url(&row.credential_id),
        "transports": row.transports,
    })
}

/// What the browser posts back for either ceremony.
#[derive(Debug, Deserialize)]
pub struct CeremonyBody {
    /// Base64url credential id (`rawId`).
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// The ceremony response.
    pub response: CeremonyResponse,
    /// Optional label, only read at registration.
    #[serde(default)]
    pub name: Option<String>,
}

/// The `response` member of a `PublicKeyCredential`, holding whichever fields the ceremony uses.
#[derive(Debug, Deserialize)]
pub struct CeremonyResponse {
    /// Base64url JSON naming the ceremony, its challenge and its origin.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Registration only.
    #[serde(default, rename = "attestationObject")]
    pub attestation_object: Option<String>,
    /// Assertion only.
    #[serde(default, rename = "authenticatorData")]
    pub authenticator_data: Option<String>,
    /// Assertion only.
    #[serde(default)]
    pub signature: Option<String>,
    /// Assertion only; the account handle the authenticator asserted.
    #[serde(default, rename = "userHandle")]
    pub user_handle: Option<String>,
    /// What the browser knows about how the authenticator is reached.
    #[serde(default)]
    pub transports: Vec<String>,
}

/// A registration body decoded into bytes.
#[derive(Debug)]
pub struct Registration {
    /// Raw credential id from `rawId`.
    pub credential_id: Vec<u8>,
    /// The client data JSON, still unverified.
    pub client_data_json: Vec<u8>,
    /// The attestation object, still unverified.
    pub attestation_object: Vec<u8>,
    /// Sanitised transport hints.
    pub transports: Vec<String>,
}

/// A decoded assertion body. None of these values has been trusted yet.
#[derive(Debug)]
pub struct Assertion {
    /// Raw credential id from `rawId`.
    pub credential_id: Vec<u8>,
    /// The client data JSON, still unverified.
    pub client_data_json: Vec<u8>,
    /// The authenticator data, still unverified.
    pub authenticator_data: Vec<u8>,
    /// The ECDSA signature, still unverified.
    pub signature: Vec<u8>,
    /// The user handle, when the authenticator reported one.
    pub user_handle: Option<Vec<u8>>,
}

/// Decode a registration body. `None` means the body is not a well-formed ceremony result.
pub fn parse_registration(body: &CeremonyBody) -> Option<Registration> {
    Some(Registration {
        credential_id: decode_base64url(&body.raw_id).ok()?,
        client_data_json: decode_base64url(&body.response.client_data_json).ok()?,
        attestation_object: decode_base64url(body.response.attestation_object.as_deref()?).ok()?,
        transports: sanitise_transports(&body.response.transports),
    })
}

/// Decode an assertion body. `None` means the body is not a well-formed ceremony result.
pub fn parse_assertion(body: &CeremonyBody) -> Option<Assertion> {
    Some(Assertion {
        credential_id: decode_base64url(&body.raw_id).ok()?,
        client_data_json: decode_base64url(&body.response.client_data_json).ok()?,
        authenticator_data: decode_base64url(body.response.authenticator_data.as_deref()?).ok()?,
        signature: decode_base64url(body.response.signature.as_deref()?).ok()?,
        user_handle: body
            .response
            .user_handle
            .as_deref()
            .map(decode_base64url)
            .transpose()
            .ok()?,
    })
}

/// Keep the transport hints the spec defines, in order, without duplicates.
fn sanitise_transports(reported: &[String]) -> Vec<String> {
    let mut clean: Vec<String> = Vec::new();
    for transport in reported {
        let value = transport.trim().to_ascii_lowercase();
        if TRANSPORTS.contains(&value.as_str()) && !clean.contains(&value) {
            clean.push(value);
        }
    }
    clean
}

/// Whether a fresh signature counter is acceptable given the one that was stored.
///
/// A zero in either place means the authenticator does not implement the counter, and the spec
/// forbids enforcing monotonicity then. Otherwise the counter must strictly increase, which is
/// what detection of a cloned authenticator rests on.
pub fn counter_is_acceptable(stored: i64, fresh: u64) -> bool {
    if stored == 0 || fresh == 0 {
        return true;
    }
    i64::try_from(fresh).is_ok_and(|fresh| fresh > stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(url: &str) -> RelyingParty {
        parse_relying_party(url).expect("parses")
    }

    #[test]
    fn the_relying_party_comes_from_the_hosted_origin() {
        let party = rp("http://localhost:5174");
        assert_eq!(party.id, "localhost");
        assert_eq!(party.origin, "http://localhost:5174");

        let party = rp("https://signin.example.com/");
        assert_eq!(party.id, "signin.example.com");
        assert_eq!(party.origin, "https://signin.example.com");
    }

    #[test]
    fn a_hostile_or_relative_origin_is_refused() {
        assert!(parse_relying_party("localhost:5174").is_err());
        assert!(parse_relying_party("ftp://localhost").is_err());
        assert!(parse_relying_party("https://").is_err());
    }

    #[test]
    fn transports_are_filtered_and_deduplicated() {
        let transports = sanitise_transports(&[
            "internal".to_owned(),
            "INTERNAL".to_owned(),
            "telepathy".to_owned(),
            "usb".to_owned(),
        ]);
        assert_eq!(transports, ["internal", "usb"]);
    }

    #[test]
    fn the_signature_counter_must_advance_only_when_it_exists() {
        assert!(counter_is_acceptable(0, 7));
        assert!(counter_is_acceptable(3, 0));
        assert!(counter_is_acceptable(3, 4));
        assert!(!counter_is_acceptable(4, 4));
        assert!(!counter_is_acceptable(4, 3));
    }

    #[test]
    fn a_registration_body_needs_all_three_values() {
        let body = CeremonyBody {
            raw_id: "AAAA".to_owned(),
            response: CeremonyResponse {
                client_data_json: "e30".to_owned(), // {}
                attestation_object: Some("e30".to_owned()),
                authenticator_data: None,
                signature: None,
                user_handle: None,
                transports: vec!["internal".to_owned()],
            },
            name: None,
        };
        let registration = parse_registration(&body).expect("decodes");
        assert_eq!(registration.credential_id, [0, 0, 0]);
        assert_eq!(registration.transports, ["internal"]);
        assert!(parse_assertion(&body).is_none());

        let mut body = body;
        body.response.attestation_object = None;
        assert!(parse_registration(&body).is_none());
    }
}
