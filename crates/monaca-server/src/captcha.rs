//! CAPTCHA verification for the hosted entrances (§6.1).
//!
//! The tenant names one provider and stores its write-only secret sealed with the tenant DEK. A
//! gated request carries the widget's token; the server posts it to the provider's documented
//! siteverify endpoint before it looks at any credential. A token is single use at the provider,
//! so a rejected sign-in makes the page solve a fresh challenge.

use monaca_crypto::open;
use monaca_store::{SignInExperienceRow, TenantRow};

use crate::error::{ApiError, kinds};
use crate::state::AppState;

/// Which entrance is asking; the tenant's three switches map one-to-one onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Password sign-in, and the emailed-code or link request that starts a sign-in.
    SignIn,
    /// Self-service registration, including the code request that precedes it.
    SignUp,
    /// The forgot-password code request.
    PasswordReset,
}

impl Flow {
    fn gated(self, experience: &SignInExperienceRow) -> bool {
        match self {
            Self::SignIn => experience.captcha_on_sign_in,
            Self::SignUp => experience.captcha_on_sign_up,
            Self::PasswordReset => experience.captcha_on_password_reset,
        }
    }
}

/// The three providers the contract names and the siteverify endpoint each documents.
fn verify_url(provider: &str) -> Option<&'static str> {
    match provider {
        "turnstile" => Some("https://challenges.cloudflare.com/turnstile/v0/siteverify"),
        "recaptcha" => Some("https://www.google.com/recaptcha/api/siteverify"),
        "hcaptcha" => Some("https://api.hcaptcha.com/siteverify"),
        _ => None,
    }
}

/// All three providers answer `{"success": true|false, …}` — a rejected token is still a 200.
fn verification_passed(body: &[u8]) -> Result<bool, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct Answer {
        success: bool,
    }
    Ok(serde_json::from_slice::<Answer>(body)?.success)
}

/// The form all three siteverify endpoints read.
fn verification_form<'a>(secret: &'a str, token: &'a str) -> [(&'a str, &'a str); 2] {
    [("secret", secret), ("response", token)]
}

/// Refuse the request unless the tenant's CAPTCHA switch for `flow` is satisfied.
pub async fn enforce(
    state: &AppState,
    tenant: &TenantRow,
    experience: &SignInExperienceRow,
    flow: Flow,
    token: Option<&str>,
) -> Result<(), ApiError> {
    if !experience.captcha_enabled || !flow.gated(experience) {
        return Ok(());
    }
    let token = token
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::problem(kinds::CAPTCHA_FAILED, "a CAPTCHA token is required"))?;
    let sealed = experience
        .captcha_secret_enc
        .as_deref()
        .ok_or_else(|| ApiError::internal("captcha is enabled without a secret"))?;
    let secret = open(&state.tenant_dek(tenant)?, sealed).map_err(|err| {
        ApiError::internal(format!("the CAPTCHA secret could not be opened: {err}"))
    })?;
    let secret = String::from_utf8(secret)
        .map_err(|_| ApiError::internal("the stored CAPTCHA secret is not text"))?;
    let provider_url = verify_url(&experience.captcha_provider).ok_or_else(|| {
        ApiError::internal(format!(
            "unknown CAPTCHA provider `{}`",
            experience.captcha_provider
        ))
    })?;
    // The override exists so the acceptance walk-through can run a local siteverify; it is only
    // populated in dev/CI and is `None` in production, where the provider's URL always wins.
    let url = state
        .config
        .captcha_siteverify_url
        .as_deref()
        .unwrap_or(provider_url);

    let response = state
        .http
        .post(url)
        .form(&verification_form(&secret, token))
        .send()
        .await
        .map_err(|err| {
            ApiError::internal(format!("the CAPTCHA provider could not be reached: {err}"))
        })?;
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        ApiError::internal(format!("the CAPTCHA answer could not be read: {err}"))
    })?;
    if !status.is_success() {
        return Err(ApiError::internal(format!(
            "the CAPTCHA provider answered {status}"
        )));
    }
    let passed = verification_passed(&body)
        .map_err(|err| ApiError::internal(format!("the CAPTCHA answer was malformed: {err}")))?;
    if !passed {
        return Err(ApiError::problem(
            kinds::CAPTCHA_FAILED,
            "the CAPTCHA challenge was not solved",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_provider_maps_to_its_siteverify_endpoint() {
        assert_eq!(
            verify_url("turnstile"),
            Some("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        );
        assert_eq!(
            verify_url("recaptcha"),
            Some("https://www.google.com/recaptcha/api/siteverify")
        );
        assert_eq!(
            verify_url("hcaptcha"),
            Some("https://api.hcaptcha.com/siteverify")
        );
        assert_eq!(verify_url("hcaptcha2"), None);
    }

    #[test]
    fn the_answer_is_the_provider_success_flag() {
        assert!(verification_passed(br#"{"success":true}"#).unwrap());
        assert!(!verification_passed(br#"{"success":false}"#).unwrap());
        assert!(verification_passed(b"not json").is_err());
    }

    #[test]
    fn the_form_names_the_parameters_all_providers_read() {
        assert_eq!(
            verification_form("sekrit", "tok"),
            [("secret", "sekrit"), ("response", "tok")]
        );
    }
}
