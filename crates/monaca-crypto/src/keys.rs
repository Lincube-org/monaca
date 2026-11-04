//! Key material: ES256 signing keys, the public JWKS, envelope encryption and the dev provider.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use data_encoding::BASE64URL_NOPAD;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{CryptoError, KeyProvider};

/// Nonce length for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Seal `plaintext` under `key`, returning `nonce || ciphertext`.
///
/// The nonce is random per call and prepended, so `open` needs nothing but the sealed bytes and
/// the same key. A fresh random 96-bit nonce is the standard construction; the collision bound is
/// far above the number of DEK uses in this system.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| CryptoError::KeyMaterial(format!("AES-256 key: {err}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| CryptoError::Decryption)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open `nonce || ciphertext` produced by [`seal`].
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() <= NONCE_LEN {
        return Err(CryptoError::Decryption);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Decryption)?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| CryptoError::KeyMaterial(format!("AES-256 key: {err}")))?;
    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|_| CryptoError::Decryption)
}

/// The public half of an ES256 key, as a JWK — §6.1 `jwks_uri`.
///
/// `kid` is the [`monaca_types::KeyId`] wire form (`key_…`), which is the JWS `kid` (§5.2).
pub fn public_jwk_from_der(kid: &str, pkcs8_der: &[u8]) -> Result<Value, CryptoError> {
    let secret = p256::SecretKey::from_pkcs8_der(pkcs8_der)
        .map_err(|err| CryptoError::KeyMaterial(format!("not a PKCS#8 EC key: {err}")))?;
    let point = secret.public_key().to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| CryptoError::KeyMaterial("public point has no x".into()))?;
    let y = point
        .y()
        .ok_or_else(|| CryptoError::KeyMaterial("public point has no y".into()))?;
    Ok(json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "x": BASE64URL_NOPAD.encode(x),
        "y": BASE64URL_NOPAD.encode(y),
    }))
}

/// The JWKS document served at `/t/{tenant}/.well-known/jwks.json`.
#[derive(Debug, Clone, Default)]
pub struct Jwks {
    keys: Vec<Value>,
}

impl Jwks {
    /// An empty document. A JWKS with no keys is a provisioning bug, not a valid answer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a public JWK.
    pub fn push(&mut self, jwk: Value) {
        self.keys.push(jwk);
    }

    /// How many keys the document holds.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the document is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Render the document, bytes identical for the same key set.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&json!({ "keys": self.keys }))
            .unwrap_or_else(|_| String::from(r#"{"keys":[]}"#))
    }

    /// The keys, for a caller that wants to build a document itself.
    pub fn keys(&self) -> &[Value] {
        &self.keys
    }
}

/// The environment key provider: a 32-byte KEK supplied by the deployment, tenant DEKs derived
/// from it.
///
/// The server reads `MONACA_KEK` in `prod` (required) and `MONACA_DEV_KEK` or a public constant
/// elsewhere (§2.2). The derivation is a domain-separated SHA-256 of the KEK and the tenant id, not
/// a KDF with a work factor — it exists so one deployment key yields a stable DEK per tenant
/// without a database table of its own.
///
/// This is the only `KeyProvider` in M0. A KMS-backed provider would implement the same trait and
/// slot in where `AppState::new` builds this one; no call site knows the difference.
///
/// Deliberately no `Debug`: a derived one would print the KEK into any log line that formats the
/// provider.
#[derive(Clone)]
pub struct EnvKeyProvider {
    kek: [u8; 32],
}

impl EnvKeyProvider {
    /// Build a provider from a 64-character hex KEK.
    pub fn from_hex(kek_hex: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(kek_hex.trim())
            .map_err(|err| CryptoError::KeyMaterial(format!("the KEK is not hex: {err}")))?;
        let kek: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            CryptoError::KeyMaterial(format!(
                "the KEK must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ))
        })?;
        Ok(Self { kek })
    }

    /// The KEK, for callers that need to wrap a DEK themselves.
    pub fn kek(&self) -> &[u8; 32] {
        &self.kek
    }
}

impl KeyProvider for EnvKeyProvider {
    fn platform_kek(&self) -> &[u8; 32] {
        &self.kek
    }

    fn tenant_dek(&self, tenant: &monaca_types::TenantId) -> Option<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(self.kek);
        hasher.update(b"monaca:tenant-dek:v1");
        hasher.update(tenant.uuid().as_bytes());
        let digest = hasher.finalize();
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&digest);
        Some(dek)
    }
}

/// Generate a fresh PKCS#8 DER-encoded P-256 private key.
///
/// Returned as DER rather than as a typed key so the caller can seal it immediately and keep the
/// decoded form in memory only for the request that needs to sign.
pub fn generate_pkcs8_der() -> Result<Vec<u8>, CryptoError> {
    let secret = p256::SecretKey::random(&mut OsRng);
    let document = secret
        .to_pkcs8_der()
        .map_err(|err| CryptoError::KeyMaterial(format!("could not encode PKCS#8: {err}")))?;
    Ok(document.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use monaca_types::TenantId;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn seal_and_open_round_trip() {
        let sealed = seal(&key(), b"hello").expect("seals");
        assert_ne!(sealed, b"hello");
        assert_eq!(open(&key(), &sealed).expect("opens"), b"hello");
    }

    #[test]
    fn a_different_key_does_not_open() {
        let sealed = seal(&key(), b"hello").expect("seals");
        assert_eq!(open(&[8u8; 32], &sealed), Err(CryptoError::Decryption));
    }

    #[test]
    fn tampered_sealed_bytes_do_not_open() {
        let mut sealed = seal(&key(), b"hello").expect("seals");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(open(&key(), &sealed), Err(CryptoError::Decryption));
    }

    #[test]
    fn two_seals_of_the_same_value_differ() {
        let first = seal(&key(), b"hello").expect("seals");
        let second = seal(&key(), b"hello").expect("seals");
        assert_ne!(first, second, "the nonce must be fresh per call");
    }

    #[test]
    fn a_generated_key_has_a_usable_public_jwk() {
        let der = generate_pkcs8_der().expect("generates");
        let jwk = public_jwk_from_der("key_test", &der).expect("jwk");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert_eq!(jwk["kid"], "key_test");
        assert!(jwk.get("d").is_none(), "the private half must never appear");
        assert_eq!(
            BASE64URL_NOPAD
                .decode(jwk["x"].as_str().expect("x").as_bytes())
                .expect("x is base64url")
                .len(),
            32
        );
    }

    #[test]
    fn the_dev_provider_derives_stable_per_tenant_keys() {
        let provider = EnvKeyProvider::from_hex(&"ab".repeat(32)).expect("provider");
        let first = TenantId::new();
        let second = TenantId::new();
        let a = provider.tenant_dek(&first).expect("dek");
        let b = provider.tenant_dek(&first).expect("dek");
        let c = provider.tenant_dek(&second).expect("dek");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, *provider.platform_kek());
    }

    #[test]
    fn a_malformed_kek_is_refused() {
        assert!(EnvKeyProvider::from_hex("zz").is_err());
        assert!(EnvKeyProvider::from_hex("aabb").is_err());
    }

    #[test]
    fn the_jwks_document_has_the_contract_shape() {
        let der = generate_pkcs8_der().expect("generates");
        let mut jwks = Jwks::new();
        jwks.push(public_jwk_from_der("key_a", &der).expect("jwk"));
        let value: Value = serde_json::from_str(&jwks.to_json()).expect("json");
        assert_eq!(value["keys"].as_array().expect("array").len(), 1);
        assert_eq!(value["keys"][0]["kid"], "key_a");
    }
}
