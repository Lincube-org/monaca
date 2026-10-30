//! RFC 6238 TOTP — the authenticator segment of MFA (§6.1 `mfa`, §7.5).
//!
//! The secret never leaves this module in a form the database sees: it is 160 random bits, shown
//! once to the user as base32, and the only thing stored is an envelope-encrypted blob (§5.6
//! `credentials.secret_enc`). Codes are HMAC-SHA1 of the 30-second step, truncated to six digits —
//! SHA1 because that is what every authenticator app assumes by default, not because this module
//! prefers it.
//!
//! Verification accepts the previous and the next step as well as the current one. Phone clocks
//! drift, and a 30-second window is the RFC 6238 §5.2 recommendation; a wider one would multiply
//! the guessing surface, a narrower one would reject honest users.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

/// The number of random bytes in a secret. 160 bits, the RFC 6238 §5.1 recommendation.
pub const SECRET_LEN: usize = 20;

/// The step length in seconds (RFC 6238 §5.2 default).
pub const PERIOD_SECS: i64 = 30;

/// The code length every authenticator app renders by default.
pub const DIGITS: u32 = 6;

/// The HMAC a TOTP code is built from.
type HmacSha1 = Hmac<Sha1>;

/// Generate a fresh TOTP secret.
pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// The secret as the base32 string an authenticator app expects (no padding, uppercase).
pub fn base32_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// The six-digit code for `at` — RFC 6238 §4 with the dynamic truncation of RFC 4226 §5.3.
pub fn code_at(secret: &[u8], at: OffsetDateTime) -> String {
    let step = at.unix_timestamp() / PERIOD_SECS;
    truncated_code(secret, step)
}

/// Whether `code` is a valid TOTP for `at`, allowing one step either way.
///
/// Every comparison is constant-time and every candidate is evaluated, so the answer reveals
/// nothing about which step was near.
pub fn verify(secret: &[u8], code: &str, at: OffsetDateTime) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let step = at.unix_timestamp() / PERIOD_SECS;
    let mut matched = false;
    for delta in -1..=1 {
        let candidate = truncated_code(secret, step + delta);
        matched |= bool::from(candidate.as_bytes().ct_eq(code.as_bytes()));
    }
    matched
}

/// The `otpauth://` URI an authenticator app scans or imports by hand.
pub fn otpauth_url(issuer: &str, account: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECS}",
        base32_secret(secret)
    )
}

/// The code for a raw step index.
fn truncated_code(secret: &[u8], step: i64) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // offset is the low nibble of the last byte; RFC 4226 guarantees offset + 3 < digest length.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let value = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    format!("{:06}", value % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 Appendix B secret, as raw ASCII bytes.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).expect("valid timestamp")
    }

    /// RFC 6238 Appendix B, SHA1 column, last six digits.
    #[test]
    fn the_rfc_vectors_match() {
        for (time, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(code_at(RFC_SECRET, at(time)), expected, "T={time}");
        }
    }

    #[test]
    fn a_code_is_accepted_for_one_step_either_way() {
        let secret = generate_secret();
        let moment = at(59);
        let current = code_at(&secret, moment);
        assert!(verify(&secret, &current, moment));
        assert!(verify(&secret, &current, at(59 + PERIOD_SECS)));
        assert!(verify(&secret, &current, at(59 - PERIOD_SECS)));
        assert!(!verify(&secret, &current, at(59 + 2 * PERIOD_SECS)));
        assert!(!verify(&secret, &current, at(59 - 2 * PERIOD_SECS)));
    }

    #[test]
    fn a_wrong_or_malformed_code_is_refused() {
        let secret = generate_secret();
        let moment = at(59);
        assert!(!verify(&secret, "12345", moment));
        assert!(!verify(&secret, "1234567", moment));
        assert!(!verify(&secret, "abcdef", moment));
        assert!(!verify(&secret, "", moment));
        let mut wrong = code_at(&secret, moment);
        let last = wrong.pop().expect("six digits");
        wrong.push(if last == '0' { '1' } else { '0' });
        assert!(!verify(&secret, &wrong, moment));
    }

    #[test]
    fn the_otpauth_url_names_the_issuer_and_account() {
        let secret = [0u8; SECRET_LEN];
        let url = otpauth_url("Monaca", "person@example.com", &secret);
        assert!(url.starts_with("otpauth://totp/Monaca:person@example.com?"));
        assert!(url.contains(&format!("secret={}", base32_secret(&secret))));
        assert!(url.contains("issuer=Monaca"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
        assert!(url.contains("algorithm=SHA1"));
    }

    #[test]
    fn base32_has_no_padding_and_round_trips() {
        let secret = generate_secret();
        let encoded = base32_secret(&secret);
        assert_eq!(encoded.len(), 32);
        assert!(!encoded.contains('='));
        assert_eq!(
            BASE32_NOPAD.decode(encoded.as_bytes()).expect("valid base32"),
            secret
        );
    }
}
