//! JWK utilities — RFC 7638 thumbprints and verification against a JWK carried in the token's
//! own header.
//!
//! Access tokens are verified against the tenant's published key set. Two protocol features need
//! the other direction: a DPoP proof (RFC 9449) is signed by a key the client invents per request
//! and embeds as the header's `jwk`, so the verifier must (1) trust nothing but that embedded key
//! and (2) identify it by its RFC 7638 thumbprint.

use data_encoding::BASE64URL_NOPAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jws::classify;
use crate::{CryptoError, decode_unverified};

/// The RFC 7638 thumbprint of a public JWK — base64url(SHA-256(canonical JWK)).
///
/// The canonical form is the required members only, sorted lexicographically, with no whitespace:
/// EC `{crv,kty,x,y}`, RSA `{e,kty,n}`, OKP `{crv,kty,x}`. `kid`, `use` and `alg` are deliberately
/// absent — they are not part of the key.
pub fn jwk_thumbprint(jwk: &Value) -> Result<String, CryptoError> {
    let object = jwk
        .as_object()
        .ok_or_else(|| CryptoError::KeyMaterial("JWK is not an object".into()))?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| CryptoError::KeyMaterial("JWK has no `kty`".into()))?;

    let members: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        other => {
            return Err(CryptoError::KeyMaterial(format!(
                "unsupported JWK key type `{other}`"
            )));
        }
    };

    // Insertion order is lexicographic and `serde_json::Map` is ordered, so the serialized bytes
    // are the canonical form without a second pass.
    let mut canonical = Map::new();
    for name in members {
        let value = object
            .get(*name)
            .and_then(Value::as_str)
            .ok_or_else(|| CryptoError::KeyMaterial(format!("JWK has no `{name}`")))?;
        canonical.insert((*name).to_owned(), Value::String(value.to_owned()));
    }
    let bytes = serde_json::to_vec(&Value::Object(canonical))
        .map_err(|err| CryptoError::KeyMaterial(format!("JWK is not serializable: {err}")))?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(bytes)))
}

/// Verify a JWS with the `jwk` member of its own header and return `(header, claims)`.
///
/// Used only for DPoP proofs. The embedded key is attacker-supplied, so this proves possession,
/// not identity; the caller binds the resulting thumbprint to the token it protects. A JWK with a
/// private component, a non-ES256 algorithm or a wrong `typ` is rejected before the signature is
/// considered.
pub fn verify_embedded_jwk(token: &str, expected_typ: &str) -> Result<(Value, Value), CryptoError> {
    let (header, _) = decode_unverified(token)?;

    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(CryptoError::BadSignature(
            "DPoP proofs must be ES256".into(),
        ));
    }
    if header.get("typ").and_then(Value::as_str) != Some(expected_typ) {
        return Err(CryptoError::Claims(format!(
            "the JWS header `typ` is not `{expected_typ}`"
        )));
    }

    let jwk = header
        .get("jwk")
        .ok_or_else(|| CryptoError::BadSignature("the JWS header has no `jwk`".into()))?;
    let object = jwk
        .as_object()
        .ok_or_else(|| CryptoError::BadSignature("the header `jwk` is not an object".into()))?;
    if ["d", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(CryptoError::BadSignature(
            "the header `jwk` contains private key material".into(),
        ));
    }

    let key = DecodingKey::from_jwk(
        &serde_json::from_value(jwk.clone())
            .map_err(|err| CryptoError::KeyMaterial(format!("unusable JWK: {err}")))?,
    )
    .map_err(|err| CryptoError::KeyMaterial(format!("unusable JWK: {err}")))?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    // DPoP proofs use `iat` freshness, not `exp`; the caller enforces the window.
    validation.validate_exp = false;
    // `set_required_spec_claims(&[])` cannot infer its item type, and the docs say an empty
    // set must be assigned directly rather than set through the helper.
    validation.required_spec_claims.clear();

    let data = decode::<Value>(token, &key, &validation).map_err(|err| classify(&err))?;
    Ok((header, data.claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The RFC 7638 §3.1 example vector.
    #[test]
    fn the_rfc7638_rsa_vector_matches() {
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            jwk_thumbprint(&jwk).expect("thumbprint"),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn thumbprints_ignore_kid_use_and_alg() {
        let base = json!({"kty":"EC","crv":"P-256","x":"a","y":"b"});
        let decorated = json!({"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"k","use":"sig","alg":"ES256"});
        assert_eq!(
            jwk_thumbprint(&base).expect("a"),
            jwk_thumbprint(&decorated).expect("b")
        );
    }

    #[test]
    fn an_unsupported_key_type_is_refused() {
        assert!(jwk_thumbprint(&json!({"kty":"oct","k":"a"})).is_err());
        assert!(jwk_thumbprint(&json!({"kty":"EC","crv":"P-256","x":"a"})).is_err());
    }
}
