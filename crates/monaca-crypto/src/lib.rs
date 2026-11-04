//! JWS/ES256 signing, argon2id password hashing, envelope encryption and key provisioning.
//!
//! This crate is the only place that touches key material. Everything above it works with
//! [`KeyProvider`] handles and sealed bytes, so a deployment can swap the dev environment
//! variable for KMS or Vault without any caller changing.
//!
//! **M0 scope.** ES256 key generation and JWKS (one active key per tenant), JWS compact
//! signing/verification, argon2id password hashing behind a semaphore, and AES-256-GCM envelope
//! encryption for per-tenant data-encryption keys and sealed secrets.
//!
//! The `monaca-core` verifier deliberately does **not** depend on this crate: verification needs
//! only public keys, and keeping that path free of key material is what lets the napi module be
//! I/O-free. This crate's verifier is the server-side counterpart, for the flows that run inside
//! a request (`private_key_jwt`, and the server checking its own management tokens).
//!
//! M1 adds key rotation and a KMS-backed [`KeyProvider`]; the `fips` feature swaps the
//! RustCrypto backend for `aws-lc-rs`.

mod jwk;
mod jws;
mod keys;
mod password;
mod secret;
mod totp;
mod webauthn;

pub use jwk::{jwk_thumbprint, verify_embedded_jwk};
pub use jws::{SigningKeyPair, decode_unverified, verify_jws, verify_jws_with_audience};
pub use keys::{EnvKeyProvider, Jwks, generate_pkcs8_der, open, public_jwk_from_der, seal};
pub use password::{Argon2Params, hash_password, verify_password};
pub use secret::{
    BACKUP_CODE_COUNT, BACKUP_CODE_LEN, DEFAULT_CODE_DIGITS, format_backup_code,
    generate_backup_codes, generate_numeric_code, hash_secret, normalize_backup_code,
    verify_secret,
};
pub use totp::{
    DIGITS as TOTP_DIGITS, PERIOD_SECS as TOTP_PERIOD_SECS, SECRET_LEN as TOTP_SECRET_LEN,
    base32_secret as totp_base32, code_at as totp_code, generate_secret as generate_totp_secret,
    otpauth_url as totp_otpauth_url, verify as verify_totp,
};
pub use webauthn::{
    RegisteredCredential, assertion_user_verified, decode_base64url, encode_base64url,
    generate_challenge, verify_assertion, verify_registration,
};

/// Where a tenant's data-encryption key comes from.
///
/// M0 has one implementation: [`EnvKeyProvider`], which takes the KEK from the deployment's
/// environment. A future KMS or Vault provider binds a handle behind the same trait. The trait is
/// async-free on purpose: a provider that needs I/O can do it once at construction and cache the
/// resolved key.
///
/// The DEK is returned by value rather than by reference: a derived key (the dev provider) has no
/// stable address inside the provider, and a KMS-backed provider caches a copy anyway. Thirty-two
/// bytes is not a copy worth optimizing.
pub trait KeyProvider: Send + Sync + 'static {
    /// The 32-byte key-encryption key that wraps per-tenant DEKs.
    fn platform_kek(&self) -> &[u8; 32];

    /// The 32-byte data-encryption key for `tenant`, derived or fetched on demand.
    fn tenant_dek(&self, tenant: &monaca_types::TenantId) -> Option<[u8; 32]>;
}

/// A cryptographic failure.
///
/// One enum for the crate rather than one per operation: every caller above turns these into a
/// problem document, and the distinctions that matter to a caller (bad password, unusable key,
/// failed decryption) are the variants, not the operation that hit them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The key material was the wrong length or shape.
    #[error("unusable key material: {0}")]
    KeyMaterial(String),
    /// The provider has no key for this tenant yet.
    #[error("no data-encryption key for this tenant")]
    TenantKeyMissing,
    /// Sealed bytes did not authenticate.
    #[error("sealed value failed authentication")]
    Decryption,
    /// A password hash could not be produced.
    #[error("password hashing failed")]
    Hashing,
    /// The supplied password does not match the stored hash.
    #[error("password does not match")]
    PasswordMismatch,
    /// A JWS could not be parsed: wrong segment count, bad base64url, bad JSON.
    #[error("malformed JWS: {0}")]
    Malformed(String),
    /// The signature did not verify, or no key matched the header's `kid`.
    #[error("JWS signature does not verify: {0}")]
    BadSignature(String),
    /// A required claim is missing or a time claim has expired.
    #[error("JWS claims are invalid: {0}")]
    Claims(String),
}

impl CryptoError {
    /// The stable machine code for this failure.
    pub const fn code(&self) -> &'static str {
        match self {
            CryptoError::KeyMaterial(_) | CryptoError::TenantKeyMissing => "MONACA_KEY_UNUSABLE",
            CryptoError::Decryption => "MONACA_DECRYPTION_FAILED",
            CryptoError::Hashing => "MONACA_HASHING_FAILED",
            CryptoError::PasswordMismatch => "MONACA_INVALID_CREDENTIALS",
            CryptoError::Malformed(_) => "MONACA_TOKEN_MALFORMED",
            CryptoError::BadSignature(_) => "MONACA_TOKEN_INVALID_SIGNATURE",
            CryptoError::Claims(_) => "MONACA_TOKEN_CLAIMS_INVALID",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_render_a_useful_message() {
        assert!(
            CryptoError::TenantKeyMissing
                .to_string()
                .contains("data-encryption key")
        );
        assert!(
            CryptoError::PasswordMismatch
                .to_string()
                .contains("does not match")
        );
    }

    /// The trait is object-safe, which is what lets a deployment pick a provider at runtime.
    #[test]
    fn key_provider_is_object_safe() {
        fn assert_object_safe(_: &dyn KeyProvider) {}
        let _ = assert_object_safe;
    }

    #[test]
    fn every_error_has_a_monaca_code() {
        for error in [
            CryptoError::KeyMaterial("x".into()),
            CryptoError::TenantKeyMissing,
            CryptoError::Decryption,
            CryptoError::Hashing,
            CryptoError::PasswordMismatch,
            CryptoError::Malformed("x".into()),
            CryptoError::BadSignature("x".into()),
            CryptoError::Claims("x".into()),
        ] {
            assert!(error.code().starts_with("MONACA_"));
        }
    }
}
