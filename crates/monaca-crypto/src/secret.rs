//! Short, single-use secrets delivered out of band — the email verification code and MFA backup
//! codes.
//!
//! Two properties matter and both live here rather than in a handler:
//!
//! * **Uniform digits.** `generate_numeric_code` rejection-samples each digit from `OsRng`, so the
//!   six-digit space is flat. A modulo-reduced 32-bit draw would bias the first six values.
//! * **Only a digest is stored.** A database read must not hand out a usable code, and comparison
//!   must not leak how many leading digits matched, so [`verify_secret`] compares SHA-256 hex in
//!   constant time.
//!
//! Backup codes reuse that second rule and add a third: they are drawn from a 32-symbol alphabet
//! with the easily confused `i`, `l`, `o` and `u` removed, and the canonical (hyphen-free, lowercase)
//! form is what gets hashed. The grouped form is only for display and for what the user types.

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

/// The alphabet a backup code is drawn from: digits plus lowercase letters without `i`, `l`, `o`
/// and `u`. Exactly 32 symbols, so one random 32-bit draw maps onto it without bias.
const BACKUP_ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// The characters in one backup code, not counting the display hyphen.
pub const BACKUP_CODE_LEN: usize = 10;

/// How many backup codes an enrollment receives.
pub const BACKUP_CODE_COUNT: usize = 10;

/// `count` distinct backup codes, each in canonical (hyphen-free, lowercase) form.
///
/// Collisions within one batch are retired rather than returned: two identical codes would be a
/// noticeable weakness for the 32^10 space, but rejecting one costs a single retry.
pub fn generate_backup_codes(count: usize) -> Vec<String> {
    let mut rng = OsRng;
    let mut seen = std::collections::HashSet::with_capacity(count);
    let mut codes = Vec::with_capacity(count);
    while codes.len() < count {
        let code: String = (0..BACKUP_CODE_LEN)
            .map(|_| BACKUP_ALPHABET[(rng.next_u32() % 32) as usize] as char)
            .collect();
        if seen.insert(code.clone()) {
            codes.push(code);
        }
    }
    codes
}

/// The grouped form shown to the user: two blocks of five, `xxxxx-xxxxx`.
///
/// Anything that is not a canonical code is returned unchanged; the display helper never rewrites a
/// value it did not produce.
pub fn format_backup_code(canonical: &str) -> String {
    if canonical.len() != BACKUP_CODE_LEN {
        return canonical.to_owned();
    }
    let (head, tail) = canonical.split_at(BACKUP_CODE_LEN / 2);
    format!("{head}-{tail}")
}

/// Normalise what a user typed into the canonical form a stored digest was made from.
///
/// Case, spaces and the display hyphen are all discarded, so `AAAAA-BBBBB`, `aaaaa bbbbb` and
/// `aaaaabbbbb` are the same code. Anything that is not exactly ten symbols from the alphabet is
/// `None`, which the caller answers with the same "wrong code" response as a mismatch.
pub fn normalize_backup_code(input: &str) -> Option<String> {
    let mut canonical = String::with_capacity(BACKUP_CODE_LEN);
    for ch in input.chars() {
        if !ch.is_ascii_alphanumeric() {
            continue;
        }
        canonical.push(ch.to_ascii_lowercase());
    }
    if canonical.len() != BACKUP_CODE_LEN
        || !canonical
            .bytes()
            .all(|byte| BACKUP_ALPHABET.contains(&byte))
    {
        return None;
    }
    Some(canonical)
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
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert!(verify_secret(&code, &hash));
    }

    #[test]
    fn backup_codes_have_the_documented_shape() {
        let codes = generate_backup_codes(BACKUP_CODE_COUNT);
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), BACKUP_CODE_LEN);
            assert!(
                code.bytes().all(|byte| BACKUP_ALPHABET.contains(&byte)),
                "unexpected symbol in {code}"
            );
            assert_eq!(
                format_backup_code(code),
                format!("{}-{}", &code[..5], &code[5..])
            );
        }
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT);
    }

    #[test]
    fn backup_codes_are_not_constant() {
        let codes: Vec<String> = (0..8).flat_map(|_| generate_backup_codes(2)).collect();
        assert!(
            codes.iter().any(|code| code != &codes[0]),
            "the generator must not return a fixed value"
        );
    }

    #[test]
    fn typed_backup_codes_normalise_to_the_canonical_form() {
        let canonical = "abcde12345";
        for typed in [
            canonical,
            "ABCDE12345",
            "abcde-12345",
            "ABCDE-12345",
            " abcde 12345 ",
            "a b c d e 1 2 3 4 5",
        ] {
            assert_eq!(normalize_backup_code(typed).as_deref(), Some(canonical));
        }
    }

    #[test]
    fn malformed_backup_codes_are_rejected() {
        assert!(normalize_backup_code("").is_none());
        assert!(normalize_backup_code("abcde-1234").is_none());
        assert!(normalize_backup_code("abcde-123456").is_none());
        // `i`, `l`, `o` and `u` are outside the alphabet precisely so they cannot be confused.
        assert!(normalize_backup_code("ilou-12345").is_none());
    }

    #[test]
    fn a_wrong_secret_or_digest_does_not_verify() {
        let hash = hash_secret("123456");
        assert!(!verify_secret("123457", &hash));
        assert!(!verify_secret("123456", ""));
        assert!(!verify_secret("123456", &hash.to_uppercase()));
    }
}
