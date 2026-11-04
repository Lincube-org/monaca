//! JWS compact signing and verification — §7.
//!
//! Every token the system issues is `alg = ES256` and carries `typ` (§7). The header's `kid` is
//! the tenant signing key's wire id (`key_…`, §5.2), which is also the `kid` in the JWKS.

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header,
};
use monaca_types::{KeyId, TypedId};
use serde_json::Value;

use crate::keys::public_jwk_from_der;
use crate::{CryptoError, generate_pkcs8_der};

/// One ES256 signing key: the private half, its `kid`, and the public JWK to publish.
///
/// The private half is held as PKCS#8 DER because that is what [`EncodingKey`] consumes; the
/// caller is responsible for sealing it at rest (`signing_keys.private_enc`, §5.6).
pub struct SigningKeyPair {
    kid: KeyId,
    encoding: EncodingKey,
    jwk: Value,
    der: Vec<u8>,
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material, even accidentally in a log line.
        f.debug_struct("SigningKeyPair")
            .field("kid", &self.kid.to_typed_string())
            .finish_non_exhaustive()
    }
}

impl SigningKeyPair {
    /// Adopt an existing PKCS#8 DER private key.
    pub fn from_pkcs8_der(kid: KeyId, der: Vec<u8>) -> Result<Self, CryptoError> {
        let jwk = public_jwk_from_der(&kid.to_typed_string(), &der)?;
        Ok(Self {
            kid,
            encoding: EncodingKey::from_ec_der(&der),
            jwk,
            der,
        })
    }

    /// Generate a new key under `kid`.
    pub fn generate(kid: KeyId) -> Result<Self, CryptoError> {
        Self::from_pkcs8_der(kid, generate_pkcs8_der()?)
    }

    /// The signing key's id, which is the JWS `kid`.
    pub const fn kid(&self) -> KeyId {
        self.kid
    }

    /// The `kid` as it appears on the wire.
    pub fn kid_string(&self) -> String {
        self.kid.to_typed_string()
    }

    /// The public JWK served in the JWKS.
    pub fn public_jwk(&self) -> &Value {
        &self.jwk
    }

    /// The private half, PKCS#8 DER. The caller seals this; it must never be logged.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.der
    }

    /// Sign `claims` as a JWS compact token with the given `typ` header.
    pub fn sign(&self, typ: &str, claims: &Value) -> Result<String, CryptoError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.to_typed_string());
        header.typ = Some(typ.to_owned());
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|err| CryptoError::KeyMaterial(format!("signing failed: {err}")))
    }
}

/// Decode a JWS header and claims **without verifying the signature**.
///
/// Only for reading a `kid` or surfacing a `state`/`nonce` echo. Nothing returned here may be
/// trusted until [`verify_jws`] has run.
pub fn decode_unverified(token: &str) -> Result<(Value, Value), CryptoError> {
    // Decoded by hand rather than through jsonwebtoken: v11 dropped
    // `insecure_disable_signature_validation`, and a function whose name says "unverified" should
    // not depend on a library flag to make that true.
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CryptoError::Malformed(
            "expected three dot-separated segments".into(),
        ));
    };
    let decode = |segment: &str, what: &str| -> Result<Value, CryptoError> {
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(segment.as_bytes())
            .map_err(|err| CryptoError::Malformed(format!("{what} is not base64url: {err}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| CryptoError::Malformed(format!("{what} is not JSON: {err}")))
    };
    Ok((decode(header, "header")?, decode(payload, "payload")?))
}

/// Verify a JWS against a set of public JWKs, requiring `typ` to be `expected_typ`.
pub fn verify_jws(token: &str, jwks: &[Value], expected_typ: &str) -> Result<Value, CryptoError> {
    verify_inner(token, jwks, expected_typ, None)
}

/// Verify a JWS and require `aud` to name `audience`.
pub fn verify_jws_with_audience(
    token: &str,
    jwks: &[Value],
    expected_typ: &str,
    audience: &str,
) -> Result<Value, CryptoError> {
    verify_inner(token, jwks, expected_typ, Some(audience))
}

/// Verify a provider-issued ID token signed with **RS256**.
///
/// This is deliberately separate from [`verify_jws`]: the server's own tokens stay ES256-only, and
/// accepting RS256 there would widen the algorithm-confusion surface. The header algorithm is
/// checked against a one-entry whitelist before any key is selected, so `none` and MAC algorithms
/// (`HS256`/`HS384`/`HS512`) are rejected even when a caller supplies a matching key.
///
/// Claim policy (issuer, audience, nonce, `iat`) belongs to the provider flow; this function only
/// enforces the signature, `kid`, `typ`, and `exp`.
pub fn verify_rs256_jws(
    token: &str,
    jwks: &[Value],
    expected_typ: Option<&str>,
) -> Result<Value, CryptoError> {
    let header = decode_header(token).map_err(|err| malformed(&err))?;
    if header.alg != Algorithm::RS256 {
        return Err(CryptoError::BadSignature(format!(
            "alg is {:?}, only RS256 is accepted for provider ID tokens",
            header.alg
        )));
    }
    if let Some(expected) = expected_typ
        && header.typ.as_deref() != Some(expected)
    {
        return Err(CryptoError::Claims(format!(
            "typ `{:?}` is not `{expected}`",
            header.typ
        )));
    }

    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| CryptoError::BadSignature("token header has no `kid`".into()))?;

    let jwk = jwks
        .iter()
        .find(|jwk| jwk.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| CryptoError::BadSignature(format!("kid `{kid}` is not in the key set")))?;
    if let Some(alg) = jwk.get("alg").and_then(Value::as_str)
        && alg != "RS256"
    {
        return Err(CryptoError::BadSignature(format!(
            "the key named by `{kid}` is not an RS256 key"
        )));
    }

    let key = DecodingKey::from_jwk(
        &serde_json::from_value(jwk.clone())
            .map_err(|err| CryptoError::KeyMaterial(format!("unusable JWK: {err}")))?,
    )
    .map_err(|err| CryptoError::KeyMaterial(format!("unusable JWK: {err}")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.leeway = 60;
    validation.set_required_spec_claims(&["exp"]);

    let data = decode::<Value>(token, &key, &validation).map_err(|err| classify(&err))?;
    Ok(data.claims)
}

fn verify_inner(
    token: &str,
    jwks: &[Value],
    expected_typ: &str,
    audience: Option<&str>,
) -> Result<Value, CryptoError> {
    let header = decode_header(token).map_err(|err| malformed(&err))?;

    if header.alg != Algorithm::ES256 {
        // §7: every token is ES256. Accepting another alg is algorithm confusion.
        return Err(CryptoError::BadSignature(format!(
            "alg is {:?}, only ES256 is accepted",
            header.alg
        )));
    }

    if let Some(typ) = header.typ.as_deref()
        && typ != expected_typ
    {
        return Err(CryptoError::Claims(format!(
            "typ `{typ}` is not `{expected_typ}`"
        )));
    }

    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| CryptoError::BadSignature("token header has no `kid`".into()))?;

    let jwk = jwks
        .iter()
        .find(|jwk| jwk.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| CryptoError::BadSignature(format!("kid `{kid}` is not in the key set")))?;

    let key = DecodingKey::from_jwk(
        &serde_json::from_value(jwk.clone())
            .map_err(|err| CryptoError::KeyMaterial(format!("unusable JWK: {err}")))?,
    )
    .map_err(|err| CryptoError::KeyMaterial(format!("unusable JWK: {err}")))?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.leeway = 60;
    validation.set_required_spec_claims(&["exp"]);

    let data = decode::<Value>(token, &key, &validation).map_err(|err| classify(&err))?;

    if let Some(expected) = audience {
        let aud = &data.claims["aud"];
        let matches = match aud {
            Value::String(value) => value == expected,
            Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
            _ => false,
        };
        if !matches {
            return Err(CryptoError::Claims(format!(
                "audience does not include `{expected}`"
            )));
        }
    }

    Ok(data.claims)
}

pub(crate) fn classify(err: &jsonwebtoken::errors::Error) -> CryptoError {
    use jsonwebtoken::errors::ErrorKind as Kind;
    match err.kind() {
        Kind::ExpiredSignature => CryptoError::Claims("token has expired".into()),
        Kind::ImmatureSignature => CryptoError::Claims("token is not valid yet".into()),
        Kind::MissingRequiredClaim(claim) => {
            CryptoError::Claims(format!("required claim `{claim}` is missing"))
        }
        Kind::InvalidSignature | Kind::InvalidAlgorithm | Kind::MissingAlgorithm => {
            CryptoError::BadSignature("signature does not verify".into())
        }
        Kind::Json(_) => CryptoError::Malformed("claims are not a JSON object".into()),
        Kind::InvalidKeyFormat | Kind::InvalidEcdsaKey => {
            CryptoError::KeyMaterial("loaded key cannot verify ES256".into())
        }
        other => CryptoError::Malformed(format!("could not decode token: {other:?}")),
    }
}

fn malformed(err: &jsonwebtoken::errors::Error) -> CryptoError {
    CryptoError::Malformed(format!("{err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pair() -> SigningKeyPair {
        SigningKeyPair::generate(KeyId::new()).expect("key")
    }

    #[test]
    fn a_signed_token_verifies_with_its_public_jwk() {
        let key = pair();
        let token = key
            .sign("at+jwt", &json!({"sub": "acc_x", "exp": 4_102_444_800i64}))
            .expect("signs");
        let claims = verify_jws(&token, &[key.public_jwk().clone()], "at+jwt").expect("verifies");
        assert_eq!(claims["sub"], "acc_x");
    }

    #[test]
    fn the_header_carries_alg_kid_and_typ() {
        let key = pair();
        let token = key
            .sign("JWT", &json!({"exp": 4_102_444_800i64}))
            .expect("signs");
        let (header, _) = decode_unverified(&token).expect("decodes");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], key.kid_string());
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let signer = pair();
        let other = pair();
        let token = signer
            .sign("at+jwt", &json!({"exp": 4_102_444_800i64}))
            .expect("signs");
        let error = verify_jws(&token, &[other.public_jwk().clone()], "at+jwt")
            .expect_err("must not verify");
        assert!(matches!(error, CryptoError::BadSignature(_)));
    }

    fn segmented(header: &Value, payload: &Value) -> String {
        use data_encoding::BASE64URL_NOPAD;
        let encode = |value: &Value| {
            let bytes = serde_json::to_vec(value).expect("serializes");
            BASE64URL_NOPAD.encode(&bytes)
        };
        format!("{}.{}.", encode(header), encode(payload))
    }

    #[test]
    fn the_rs256_verifier_rejects_alg_none() {
        let token = segmented(
            &json!({"alg": "none", "typ": "JWT", "kid": "kid-1"}),
            &json!({"exp": 4_102_444_800i64}),
        );
        let error = verify_rs256_jws(&token, &[], Some("JWT")).expect_err("must refuse");
        assert!(matches!(error, CryptoError::BadSignature(_)));
    }

    #[test]
    fn the_rs256_verifier_rejects_an_ec_token_and_an_unknown_kid() {
        let key = pair();
        let token = key
            .sign("JWT", &json!({"exp": 4_102_444_800i64}))
            .expect("signs");
        assert!(verify_rs256_jws(&token, &[key.public_jwk().clone()], Some("JWT")).is_err());

        let header = json!({"alg": "RS256", "typ": "JWT", "kid": "not-in-the-set"});
        let token = segmented(&header, &json!({"exp": 4_102_444_800i64}));
        let error = verify_rs256_jws(&token, &[], Some("JWT")).expect_err("must refuse");
        assert!(matches!(error, CryptoError::BadSignature(_)));
    }

    #[test]
    fn the_wrong_typ_is_refused() {
        let key = pair();
        let token = key
            .sign("at+jwt", &json!({"exp": 4_102_444_800i64}))
            .expect("signs");
        let error =
            verify_jws(&token, &[key.public_jwk().clone()], "JWT").expect_err("must refuse");
        assert!(matches!(error, CryptoError::Claims(_)));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let key = pair();
        let token = key
            .sign("at+jwt", &json!({"exp": 1_000_000_000i64}))
            .expect("signs");
        let error =
            verify_jws(&token, &[key.public_jwk().clone()], "at+jwt").expect_err("must refuse");
        assert!(matches!(error, CryptoError::Claims(_)));
    }

    #[test]
    fn the_audience_must_match() {
        let key = pair();
        let token = key
            .sign(
                "at+jwt",
                &json!({"aud": "https://a.test/v1", "exp": 4_102_444_800i64}),
            )
            .expect("signs");
        assert!(
            verify_jws_with_audience(
                &token,
                &[key.public_jwk().clone()],
                "at+jwt",
                "https://a.test/v1"
            )
            .is_ok()
        );
        assert!(
            verify_jws_with_audience(
                &token,
                &[key.public_jwk().clone()],
                "at+jwt",
                "https://b.test/v1"
            )
            .is_err()
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let key = pair();
        let token = key
            .sign("at+jwt", &json!({"sub": "acc_x", "exp": 4_102_444_800i64}))
            .expect("signs");
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = monaca_types::encode_suffix(uuid::Uuid::now_v7());
        let forged = format!("{{\"sub\":\"acc_forged\",\"exp\":4102444800,\"_n\":\"{forged}\"}}");
        let forged = data_encoding::BASE64URL_NOPAD.encode(forged.as_bytes());
        parts[1] = &forged;
        let error = verify_jws(&parts.join("."), &[key.public_jwk().clone()], "at+jwt")
            .expect_err("must refuse");
        assert!(matches!(error, CryptoError::BadSignature(_)));
    }
}
