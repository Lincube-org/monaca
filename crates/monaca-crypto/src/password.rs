//! argon2id password hashing — §2.2, §5.6 `credentials.secret_enc`.
//!
//! Hashing is CPU- and memory-bound by design, so every call runs on `spawn_blocking` behind a
//! process-wide semaphore capped by `MONACA_ARGON2_MAX_CONCURRENCY`. Without the cap, a burst of
//! sign-ins would exhaust the blocking pool and stall the whole runtime.

use std::sync::OnceLock;

use argon2::password_hash::PasswordHasher as _;
use argon2::password_hash::PasswordVerifier as _;
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::sync::Semaphore;

use crate::CryptoError;

/// The argon2id parameters — §2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB (`MONACA_ARGON2_MEMORY_KIB`, default 19456).
    pub memory_kib: u32,
    /// Iterations (`MONACA_ARGON2_ITERATIONS`, default 2).
    pub iterations: u32,
    /// Parallelism (`MONACA_ARGON2_PARALLELISM`, default 1).
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Argon2Params {
    /// Read the three parameters from the environment, falling back to the defaults.
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            memory_kib: env_u32("MONACA_ARGON2_MEMORY_KIB").unwrap_or(default.memory_kib),
            iterations: env_u32("MONACA_ARGON2_ITERATIONS").unwrap_or(default.iterations),
            parallelism: env_u32("MONACA_ARGON2_PARALLELISM").unwrap_or(default.parallelism),
        }
    }

    fn to_argon2(self) -> Result<Argon2<'static>, CryptoError> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, None)
            .map_err(|_| CryptoError::Hashing)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok()?.trim().parse().ok()
}

/// The process-wide concurrency cap — §2.2 `MONACA_ARGON2_MAX_CONCURRENCY`.
fn semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| {
        let permits = env_u32("MONACA_ARGON2_MAX_CONCURRENCY")
            .filter(|permits| *permits > 0)
            .unwrap_or(4);
        Semaphore::new(permits as usize)
    })
}

/// Hash a password into an argon2id PHC string.
pub async fn hash_password(password: String, params: Argon2Params) -> Result<String, CryptoError> {
    let permit = semaphore()
        .acquire()
        .await
        .map_err(|_| CryptoError::Hashing)?;
    let joined = tokio::task::spawn_blocking(move || {
        let argon2 = params.to_argon2()?;
        let hash = argon2
            .hash_password(password.as_bytes())
            .map_err(|_| CryptoError::Hashing)?;
        Ok::<_, CryptoError>(hash.to_string())
    })
    .await
    .map_err(|_| CryptoError::Hashing)?;
    drop(permit);
    joined
}

/// Verify a password against a stored PHC string.
///
/// A malformed hash is [`CryptoError::Hashing`] (a data problem); a well-formed hash that does not
/// match is [`CryptoError::PasswordMismatch`] (a credential problem). Callers must report both to
/// the user as the same failure — §6.1 requires an unknown email and a wrong password to be
/// indistinguishable.
pub async fn verify_password(
    password: String,
    phc: String,
    params: Argon2Params,
) -> Result<(), CryptoError> {
    let permit = semaphore()
        .acquire()
        .await
        .map_err(|_| CryptoError::Hashing)?;
    let joined = tokio::task::spawn_blocking(move || {
        let argon2 = params.to_argon2()?;
        argon2
            .verify_password(password.as_bytes(), phc.as_str())
            .map_err(|_| CryptoError::PasswordMismatch)
    })
    .await
    .map_err(|_| CryptoError::Hashing)?;
    drop(permit);
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test parameters are cheap on purpose; production reads §2.2's values.
    fn params() -> Argon2Params {
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[tokio::test]
    async fn a_password_round_trips() {
        let phc = hash_password("correct horse".into(), params())
            .await
            .expect("hashes");
        assert!(phc.starts_with("$argon2id$"));
        verify_password("correct horse".into(), phc, params())
            .await
            .expect("verifies");
    }

    #[tokio::test]
    async fn a_wrong_password_is_a_mismatch() {
        let phc = hash_password("correct horse".into(), params())
            .await
            .expect("hashes");
        assert_eq!(
            verify_password("wrong".into(), phc, params()).await,
            Err(CryptoError::PasswordMismatch)
        );
    }

    #[tokio::test]
    async fn two_hashes_of_the_same_password_differ() {
        let first = hash_password("same".into(), params())
            .await
            .expect("hashes");
        let second = hash_password("same".into(), params())
            .await
            .expect("hashes");
        assert_ne!(first, second, "a fresh salt per hash is the point");
    }

    #[tokio::test]
    async fn the_defaults_match_the_contract() {
        let params = Argon2Params::default();
        assert_eq!(params.memory_kib, 19_456);
        assert_eq!(params.iterations, 2);
        assert_eq!(params.parallelism, 1);
    }
}
