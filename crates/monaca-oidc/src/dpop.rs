//! DPoP proof validation — RFC 9449.
//!
//! The proof is a short-lived JWS signed by a key the client generates, with that public key
//! embedded in its own header. Verification therefore proves *possession* of the key, nothing
//! more; the thumbprint is what the server binds the resulting tokens to (`cnf.jkt`).
//!
//! Replay protection is not here: the `jti` is returned to the caller, which records it in the
//! tenant's `dpop_replays` table (a database constraint, not process memory, so two server
//! instances cannot both accept the same proof).

use data_encoding::BASE64URL_NOPAD;
use serde_json::Value;
use sha2::{Digest, Sha256};

use monaca_crypto::CryptoError;

/// How far a proof's `iat` may be from the server's clock, either direction.
pub const PROOF_WINDOW_SECS: i64 = 300;

/// A verified DPoP proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopProof {
    /// RFC 7638 thumbprint of the proof's embedded key.
    pub jkt: String,
    /// The proof's `jti`; single-use within [`PROOF_WINDOW_SECS`].
    pub jti: String,
    /// The proof's `iat`, in Unix seconds.
    pub issued_at: i64,
}

/// Why a DPoP proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpopError {
    /// The request carried no `DPoP` header.
    #[error("the DPoP proof is missing")]
    Missing,
    /// The proof is not a well-formed `dpop+jwt`.
    #[error("the DPoP proof is malformed: {0}")]
    Malformed(String),
    /// The signature did not verify with the embedded key.
    #[error("the DPoP proof signature does not verify")]
    Signature,
    /// The `jti` is missing or not a string.
    #[error("the DPoP proof has no usable `jti`")]
    MissingJti,
    /// `jti` was already seen inside the freshness window.
    #[error("the DPoP proof was already used")]
    Replay,
    /// `htm`/`htu` name a different request.
    #[error("the DPoP proof names a different HTTP method or URL")]
    WrongTarget,
    /// `iat` is missing or outside the freshness window.
    #[error("the DPoP proof is not fresh")]
    NotFresh,
    /// `ath` does not hash the access token being presented.
    #[error("the DPoP proof does not bind the access token")]
    AccessTokenMismatch,
    /// The token is bound to a different key.
    #[error("the DPoP key does not match the token binding")]
    KeyMismatch,
}

impl DpopError {
    /// The RFC 9449 §7.1 error code.
    pub const fn code(&self) -> &'static str {
        "invalid_dpop_proof"
    }
}

/// Verify a `DPoP` proof against the request it accompanies.
///
/// `access_token` is `Some` only for resource requests, where RFC 9449 §7.1 requires `ath`.
pub fn verify(
    proof: &str,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    now: i64,
) -> Result<DpopProof, DpopError> {
    let (header, claims) = monaca_crypto::verify_embedded_jwk(proof, "dpop+jwt").map_err(
        |err| match err {
            CryptoError::BadSignature(_) => DpopError::Signature,
            other => DpopError::Malformed(other.to_string()),
        },
    )?;

    let jwk = header
        .get("jwk")
        .ok_or_else(|| DpopError::Malformed("the header has no `jwk`".into()))?;
    let jkt = monaca_crypto::jwk_thumbprint(jwk)
        .map_err(|err| DpopError::Malformed(err.to_string()))?;

    let htm = claims
        .get("htm")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::Malformed("`htm` is missing".into()))?;
    if htm != method {
        return Err(DpopError::WrongTarget);
    }

    let htu = claims
        .get("htu")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::Malformed("`htu` is missing".into()))?;
    if without_query(htu) != without_query(url) {
        return Err(DpopError::WrongTarget);
    }

    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(DpopError::NotFresh)?;
    if (now - issued_at).abs() > PROOF_WINDOW_SECS {
        return Err(DpopError::NotFresh);
    }

    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(DpopError::MissingJti)?
        .to_owned();

    if let Some(token) = access_token {
        let ath = claims
            .get("ath")
            .and_then(Value::as_str)
            .ok_or(DpopError::AccessTokenMismatch)?;
        if ath != access_token_hash(token) {
            return Err(DpopError::AccessTokenMismatch);
        }
    }

    Ok(DpopProof {
        jkt,
        jti,
        issued_at,
    })
}

/// Require a token bound to `jkt` to present a proof for the same key.
pub fn check_binding(bound_to: Option<&str>, proof: Option<&DpopProof>) -> Result<(), DpopError> {
    match bound_to {
        None => Ok(()),
        Some(expected) => match proof {
            Some(proof) if proof.jkt == expected => Ok(()),
            Some(_) => Err(DpopError::KeyMismatch),
            None => Err(DpopError::Missing),
        },
    }
}

/// `base64url(SHA-256(token))`, the `ath` member of a resource-request proof.
pub fn access_token_hash(token: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(token.as_bytes()))
}

/// RFC 9449 §4.3: `htu` is the target URI without query and fragment.
fn without_query(url: &str) -> &str {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    &url[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_proof_is_refused() {
        assert!(matches!(
            verify("not-a-jwt", "POST", "https://a.test/token", None, 1_700_000_000),
            Err(DpopError::Malformed(_))
        ));
    }

    #[test]
    fn query_and_fragment_are_ignored_in_htu() {
        assert_eq!(
            without_query("https://a.test/token?x=1#f"),
            "https://a.test/token"
        );
        assert_eq!(without_query("https://a.test/token"), "https://a.test/token");
    }

    #[test]
    fn the_access_token_hash_is_stable() {
        let first = access_token_hash("token");
        assert_eq!(first, access_token_hash("token"));
        assert_ne!(first, access_token_hash("other"));
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn binding_requires_a_matching_proof() {
        let proof = DpopProof {
            jkt: "jkt-a".into(),
            jti: "j".into(),
            issued_at: 0,
        };
        assert!(check_binding(None, None).is_ok());
        assert!(check_binding(Some("jkt-a"), Some(&proof)).is_ok());
        assert_eq!(
            check_binding(Some("jkt-a"), None).unwrap_err(),
            DpopError::Missing
        );
        assert_eq!(
            check_binding(Some("jkt-b"), Some(&proof)).unwrap_err(),
            DpopError::KeyMismatch
        );
    }
}
