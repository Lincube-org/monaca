//! Short, single-use secrets delivered out of band — the email verification code.
//!
//! Two properties matter and both live here rather than in a handler:
//!
//! * **Uniform digits.** `generate_numeric_code` rejection-samples each digit from `OsRng`, so the
//!   six-digit space is flat. A modulo-reduced 32-bit draw would bias the first six values.
//! * **Only a digest is stored.** A database read must not hand out a usable code, and comparison
//!   must not leak how many leading digits matched, so [`verify_secret`] compares SHA-256 hex in
//!   constant time.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The code length the contract's email flows use.
pub const DEFAULT_CODE_DIGITS: usize = 6;

/// A code of `digits` uniformly distributed decimal digits.
///
/// Rejection sampling keeps the distribution flat: a draw is kept only when it is below the
/// largest multiple of ten that fits in a `u32`.
pub fn generate_numeric_code(digits: usize) -> String {
    const LIMIT: u32 = u32::MAX - (u32::MAX % 10);
    let mut rng = OsRng;
    let mut code = String::with_capacity(digits);
    for _ in 0..digits {
        loop {
            let draw = rng.next_u32();
            if draw < LIMIT {
                code.push(char::from(b'0' + (draw % 10) as u8));
                break;
            }
        }
    }
    code
}

/// The lowercase hex SHA-256 of a secret — the only form that reaches storage.
pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Compare a presented secret with a stored digest in constant time.
///
/// A malformed or empty digest simply does not match; the length check inside `ct_eq` is itself
/// constant time for byte slices.
pub fn verify_secret(secret: &str, expected_hash: &str) -> bool {
    let computed = hash_secret(secret);
    computed.as_bytes().ct_eq(expected_hash.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_has_the_requested_shape() {
        let code = generate_numeric_code(DEFAULT_CODE_DIGITS);
        assert_eq!(code.len(), DEFAULT_CODE_DIGITS);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn codes_are_not_constant() {
        let codes: Vec<String> = (0..64).map(|_| generate_numeric_code(6)).collect();
        assert!(
            codes.iter().any(|code| code != &codes[0]),
            "the generator must not return a fixed value"
        );
    }

    #[test]
    fn a_secret_round_trips() {
        let code = generate_numeric_code(DEFAULT_CODE_DIGITS);
        let hash = hash_secret(&code);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(verify_secret(&code, &hash));
    }

    #[test]
    fn a_wrong_secret_or_digest_does_not_verify() {
        let hash = hash_secret("123456");
        assert!(!verify_secret("123457", &hash));
        assert!(!verify_secret("123456", ""));
        assert!(!verify_secret("123456", &hash.to_uppercase()));
    }
}
