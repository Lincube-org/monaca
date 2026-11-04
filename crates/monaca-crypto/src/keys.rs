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
    /// The key a rotation is retiring. Data sealed under it stays readable until
    /// [`rewrap`](crate::rewrap) has moved every value to `kek`.
    previous: Option<[u8; 32]>,
}

impl EnvKeyProvider {
    /// Build a provider from a 64-character hex KEK.
    pub fn from_hex(kek_hex: &str) -> Result<Self, CryptoError> {
        Self::from_hex_with_previous(kek_hex, None)
    }

    /// Build a provider with an optional previous KEK for a rotation.
    pub fn from_hex_with_previous(
        kek_hex: &str,
        previous_hex: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let kek = decode_kek(kek_hex)?;
        let previous = previous_hex.map(decode_kek).transpose()?;
        if previous.is_some_and(|previous| previous == kek) {
            return Err(CryptoError::KeyMaterial(
                "MONACA_KEK_PREVIOUS is the current KEK".to_owned(),
            ));
        }
        Ok(Self { kek, previous })
    }

    /// The KEK, for callers that need to wrap a DEK themselves.
    pub fn kek(&self) -> &[u8; 32] {
        &self.kek
    }

    /// The KEK a rotation is retiring, if one is configured.
    pub fn previous_kek(&self) -> Option<&[u8; 32]> {
        self.previous.as_ref()
    }
}

fn decode_kek(kek_hex: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(kek_hex.trim())
        .map_err(|err| CryptoError::KeyMaterial(format!("the KEK is not hex: {err}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CryptoError::KeyMaterial(format!(
            "the KEK must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        ))
    })
}

/// The DEK derived from one KEK for one tenant.
fn derive_tenant_dek(kek: &[u8; 32], tenant: &monaca_types::TenantId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(kek);
    hasher.update(b"monaca:tenant-dek:v1");
    hasher.update(tenant.uuid().as_bytes());
    let digest = hasher.finalize();
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&digest);
    dek
}

/// Open `sealed` with the first DEK that authenticates it.
///
/// The order is the caller's: the current key first, then any key kept for a rotation. AES-GCM's
/// authentication tag means a wrong key fails rather than returning other plaintext.
pub fn open_any(deks: &[[u8; 32]], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if deks.is_empty() {
        return Err(CryptoError::TenantKeyMissing);
    }
    let mut last = None;
    for dek in deks {
        match open(dek, sealed) {
            Ok(plain) => return Ok(plain),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or(CryptoError::Decryption))
}

/// Move a sealed value to the current key.
///
/// `None` means the value already opens with `deks[0]`, so a re-run skips it. `Some` is the value
/// re-sealed under the current key. [`CryptoError::Decryption`] means no configured key opens it —
/// the caller must stop rather than overwrite data it cannot read.
pub fn rewrap(deks: &[[u8; 32]], sealed: &[u8]) -> Result<Option<Vec<u8>>, CryptoError> {
    if deks.is_empty() {
        return Err(CryptoError::TenantKeyMissing);
    }
    if open(&deks[0], sealed).is_ok() {
        return Ok(None);
    }
    for dek in &deks[1..] {
        if let Ok(plain) = open(dek, sealed) {
            return Ok(Some(seal(&deks[0], &plain)?));
        }
    }
    Err(CryptoError::Decryption)
}

impl KeyProvider for EnvKeyProvider {
    fn platform_kek(&self) -> &[u8; 32] {
        &self.kek
    }

    fn tenant_dek(&self, tenant: &monaca_types::TenantId) -> Option<[u8; 32]> {
        Some(derive_tenant_dek(&self.kek, tenant))
    }

    fn tenant_deks(&self, tenant: &monaca_types::TenantId) -> Vec<[u8; 32]> {
        let mut deks = vec![derive_tenant_dek(&self.kek, tenant)];
        if let Some(previous) = self.previous.as_ref() {
            deks.push(derive_tenant_dek(previous, tenant));
        }
        deks
    }

    fn previous_platform_kek(&self) -> Option<[u8; 32]> {
        self.previous
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
    fn a_rotation_opens_with_either_key_and_rewraps_once() {
        let current = EnvKeyProvider::from_hex(&"ab".repeat(32)).expect("provider");
        let previous = EnvKeyProvider::from_hex(&"cd".repeat(32)).expect("provider");
        let tenant = TenantId::new();

        // Seal under the retiring key, then read it through a provider that keeps both.
        let old_dek = previous.tenant_dek(&tenant).expect("dek");
        let sealed = seal(&old_dek, b"connector secret").expect("seals");
        let rotating =
            EnvKeyProvider::from_hex_with_previous(&"ab".repeat(32), Some(&"cd".repeat(32)))
                .expect("rotation provider");
        assert_eq!(
            open_any(&rotating.tenant_deks(&tenant), &sealed).expect("opens"),
            b"connector secret"
        );

        // The first re-wrap moves it to the current key; the second run is a no-op.
        let rewrapped = rewrap(&rotating.tenant_deks(&tenant), &sealed)
            .expect("rewraps")
            .expect("was under the previous key");
        assert_eq!(
            open(&current.tenant_dek(&tenant).expect("dek"), &rewrapped).expect("opens"),
            b"connector secret"
        );
        assert_eq!(rewrap(&rotating.tenant_deks(&tenant), &rewrapped), Ok(None));

        // Without the previous key, the migrated value still opens and the old one does not.
        let only_current = EnvKeyProvider::from_hex(&"ab".repeat(32)).expect("provider");
        assert!(open(&only_current.tenant_dek(&tenant).expect("dek"), &rewrapped).is_ok());
        assert_eq!(
            open(&only_current.tenant_dek(&tenant).expect("dek"), &sealed),
            Err(CryptoError::Decryption)
        );
    }

    #[test]
    fn an_unknown_ciphertext_is_not_rewrapped() {
        let provider =
            EnvKeyProvider::from_hex_with_previous(&"ab".repeat(32), Some(&"cd".repeat(32)))
                .expect("provider");
        let tenant = TenantId::new();
        let deks = provider.tenant_deks(&tenant);
        let foreign = seal(&[9u8; 32], b"someone else's key").expect("seals");
        assert_eq!(rewrap(&deks, &foreign), Err(CryptoError::Decryption));
    }

    #[test]
    fn the_previous_key_must_differ_from_the_current_one() {
        let hex = "ab".repeat(32);
        assert!(EnvKeyProvider::from_hex_with_previous(&hex, Some(&hex)).is_err());
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
