//! Error rendering: RFC 9457 everywhere except the token endpoint, which speaks RFC 6749 §5.2.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use monaca_oidc::{InteractionError, TokenErrorCode};
use monaca_types::{Problem, ProblemKind};
use serde_json::json;

/// The problem kinds this server raises.
pub mod kinds {
    use monaca_types::ProblemKind;

    /// A malformed request.
    pub const INVALID_REQUEST: ProblemKind = ProblemKind::new(
        "invalid_request",
        "MONACA_INVALID_REQUEST",
        "Invalid request",
        400,
    );
    /// Missing or invalid credentials.
    pub const UNAUTHORIZED: ProblemKind =
        ProblemKind::new("unauthorized", "MONACA_UNAUTHORIZED", "Unauthorized", 401);
    /// Sign-in failed. Deliberately indistinguishable from an unknown account (§6.1).
    pub const INVALID_CREDENTIALS: ProblemKind = ProblemKind::new(
        "invalid_credentials",
        "MONACA_INVALID_CREDENTIALS",
        "Invalid credentials",
        401,
    );
    /// A valid token without the required scope.
    pub const INSUFFICIENT_SCOPE: ProblemKind = ProblemKind::new(
        "insufficient_scope",
        "MONACA_INSUFFICIENT_SCOPE",
        "Insufficient scope",
        403,
    );
    /// Self-service registration is switched off for this tenant.
    pub const SIGN_UP_DISABLED: ProblemKind = ProblemKind::new(
        "sign_up_disabled",
        "MONACA_SIGN_UP_DISABLED",
        "Sign-up disabled",
        403,
    );
    /// The password form is switched off for this tenant.
    pub const PASSWORD_SIGN_IN_DISABLED: ProblemKind = ProblemKind::new(
        "password_sign_in_disabled",
        "MONACA_PASSWORD_SIGN_IN_DISABLED",
        "Password sign-in disabled",
        403,
    );
    /// Emailed codes and links are switched off for this tenant.
    pub const EMAIL_CODE_SIGN_IN_DISABLED: ProblemKind = ProblemKind::new(
        "email_code_sign_in_disabled",
        "MONACA_EMAIL_CODE_SIGN_IN_DISABLED",
        "Email code sign-in disabled",
        403,
    );
    /// Passwordless passkey sign-in is switched off for this tenant.
    pub const PASSKEY_SIGN_IN_DISABLED: ProblemKind = ProblemKind::new(
        "passkey_sign_in_disabled",
        "MONACA_PASSKEY_SIGN_IN_DISABLED",
        "Passkey sign-in disabled",
        403,
    );
    /// Enterprise SSO is switched off for this tenant.
    pub const SSO_DISABLED: ProblemKind = ProblemKind::new(
        "sso_disabled",
        "MONACA_SSO_DISABLED",
        "Single sign-on disabled",
        403,
    );
    /// The tenant is suspended: sign-in, token issuance and `/v1` are refused.
    pub const TENANT_SUSPENDED: ProblemKind = ProblemKind::new(
        "tenant_suspended",
        "MONACA_TENANT_SUSPENDED",
        "Tenant suspended",
        403,
    );
    /// The tenant is archived: it is retained but not addressable.
    pub const TENANT_ARCHIVED: ProblemKind = ProblemKind::new(
        "tenant_archived",
        "MONACA_TENANT_ARCHIVED",
        "Tenant archived",
        403,
    );
    /// The resource does not exist, or is outside the caller's tenant.
    pub const NOT_FOUND: ProblemKind =
        ProblemKind::new("not_found", "MONACA_NOT_FOUND", "Not found", 404);
    /// A state transition was refused because the resource is not in a state that allows it.
    pub const STATE_CONFLICT: ProblemKind = ProblemKind::new(
        "state_conflict",
        "MONACA_STATE_CONFLICT",
        "State conflict",
        409,
    );
    /// A dependency the request needs is temporarily unavailable; the caller may retry.
    pub const UNAVAILABLE: ProblemKind = ProblemKind::new(
        "unavailable",
        "MONACA_UNAVAILABLE",
        "Temporarily unavailable",
        503,
    );
    /// A JWK with a private component was submitted.
    pub const PRIVATE_KEY_SUBMITTED: ProblemKind = ProblemKind::new(
        "private_key_submitted",
        "MONACA_PRIVATE_KEY_SUBMITTED",
        "Private key submitted",
        400,
    );
    /// The grant is revoked or expired.
    pub const GRANT_REVOKED: ProblemKind = ProblemKind::new(
        "grant_revoked",
        "MONACA_GRANT_REVOKED",
        "Grant revoked",
        409,
    );
    /// Sign-up named an email that already has an account.
    pub const ACCOUNT_EXISTS: ProblemKind = ProblemKind::new(
        "account_exists",
        "MONACA_ACCOUNT_EXISTS",
        "Account exists",
        409,
    );
    /// A new password is shorter than the contract's minimum.
    pub const WEAK_PASSWORD: ProblemKind = ProblemKind::new(
        "weak_password",
        "MONACA_WEAK_PASSWORD",
        "Password too short",
        400,
    );
    /// A destructive request arrived without the confirmation the endpoint requires.
    pub const CONFIRMATION_REQUIRED: ProblemKind = ProblemKind::new(
        "confirmation_required",
        "MONACA_CONFIRMATION_REQUIRED",
        "Confirmation required",
        400,
    );
    /// The email code is unknown, expired, already used, or does not match.
    pub const INVALID_VERIFICATION_CODE: ProblemKind = ProblemKind::new(
        "invalid_verification_code",
        "MONACA_INVALID_VERIFICATION_CODE",
        "Invalid verification code",
        401,
    );
    /// A code was requested too soon, or guessed too many times.
    pub const TOO_MANY_ATTEMPTS: ProblemKind = ProblemKind::new(
        "too_many_attempts",
        "MONACA_TOO_MANY_ATTEMPTS",
        "Too many attempts",
        429,
    );
    /// The CAPTCHA token was missing or the provider rejected it.
    pub const CAPTCHA_FAILED: ProblemKind = ProblemKind::new(
        "captcha_failed",
        "MONACA_CAPTCHA_FAILED",
        "Captcha verification failed",
        400,
    );
    /// The identifier is temporarily refused after too many wrong passwords.
    pub const ACCOUNT_LOCKED: ProblemKind = ProblemKind::new(
        "account_locked",
        "MONACA_ACCOUNT_LOCKED",
        "Account locked",
        429,
    );
    /// The account already has an authenticator app; replacing it is a deliberate removal first.
    pub const MFA_ALREADY_ENABLED: ProblemKind = ProblemKind::new(
        "mfa_already_enabled",
        "MONACA_MFA_ALREADY_ENABLED",
        "MFA already enabled",
        409,
    );
    /// The tenant's account quota is exhausted; creation is refused rather than warned.
    pub const QUOTA_EXCEEDED: ProblemKind = ProblemKind::new(
        "quota_exceeded",
        "MONACA_QUOTA_EXCEEDED",
        "Tenant quota exceeded",
        403,
    );
    /// A username is already claimed by another account.
    pub const USERNAME_TAKEN: ProblemKind = ProblemKind::new(
        "username_taken",
        "MONACA_USERNAME_TAKEN",
        "Username taken",
        409,
    );
    /// An email address is already claimed by another account.
    pub const EMAIL_TAKEN: ProblemKind =
        ProblemKind::new("email_taken", "MONACA_EMAIL_TAKEN", "Email taken", 409);
    /// A role name is already registered in this tenant.
    pub const ROLE_EXISTS: ProblemKind =
        ProblemKind::new("role_exists", "MONACA_ROLE_EXISTS", "Role exists", 409);
    /// A protocol client id is already registered in this tenant.
    pub const CLIENT_EXISTS: ProblemKind = ProblemKind::new(
        "client_exists",
        "MONACA_CLIENT_EXISTS",
        "Client exists",
        409,
    );
    /// An API resource identifier is already registered in this tenant.
    pub const RESOURCE_EXISTS: ProblemKind = ProblemKind::new(
        "resource_exists",
        "MONACA_RESOURCE_EXISTS",
        "Resource exists",
        409,
    );
    /// An organization slug is already registered in this tenant.
    pub const ORG_EXISTS: ProblemKind = ProblemKind::new(
        "org_exists",
        "MONACA_ORG_EXISTS",
        "Organization exists",
        409,
    );
    /// An organization role name is already defined in this org.
    pub const ORG_ROLE_EXISTS: ProblemKind = ProblemKind::new(
        "org_role_exists",
        "MONACA_ORG_ROLE_EXISTS",
        "Organization role exists",
        409,
    );
    /// An organization email domain is already registered in this tenant.
    pub const DOMAIN_EXISTS: ProblemKind = ProblemKind::new(
        "domain_exists",
        "MONACA_DOMAIN_EXISTS",
        "Domain exists",
        409,
    );
    /// A live organization invitation already names this address.
    pub const INVITATION_EXISTS: ProblemKind = ProblemKind::new(
        "invitation_exists",
        "MONACA_INVITATION_EXISTS",
        "Invitation exists",
        409,
    );
    /// An SSO connector slug is already registered in this tenant.
    pub const SSO_CONNECTOR_EXISTS: ProblemKind = ProblemKind::new(
        "sso_connector_exists",
        "MONACA_SSO_CONNECTOR_EXISTS",
        "SSO connector exists",
        409,
    );
    /// An email domain is already routed to another SSO connector.
    pub const SSO_DOMAIN_TAKEN: ProblemKind = ProblemKind::new(
        "sso_domain_taken",
        "MONACA_SSO_DOMAIN_TAKEN",
        "SSO email domain taken",
        409,
    );
    /// The identity provider asserted no verified email address.
    pub const SSO_EMAIL_UNVERIFIED: ProblemKind = ProblemKind::new(
        "sso_email_unverified",
        "MONACA_SSO_EMAIL_UNVERIFIED",
        "SSO email unverified",
        403,
    );
    /// The identity provider asserted an address outside the connector's domains.
    pub const SSO_DOMAIN_MISMATCH: ProblemKind = ProblemKind::new(
        "sso_domain_mismatch",
        "MONACA_SSO_DOMAIN_MISMATCH",
        "SSO email domain mismatch",
        403,
    );
    /// A connector slug is already registered in this tenant.
    pub const CONNECTOR_EXISTS: ProblemKind = ProblemKind::new(
        "connector_exists",
        "MONACA_CONNECTOR_EXISTS",
        "Connector exists",
        409,
    );
    /// An account already owns the provider's verified email, and the policy does not link.
    pub const SOCIAL_EMAIL_TAKEN: ProblemKind = ProblemKind::new(
        "social_email_taken",
        "MONACA_SOCIAL_EMAIL_TAKEN",
        "Email already in use",
        409,
    );
    pub const SOCIAL_IDENTITY_TAKEN: ProblemKind = ProblemKind::new(
        "social_identity_taken",
        "MONACA_SOCIAL_IDENTITY_TAKEN",
        "Social identity taken",
        409,
    );
    /// The provider account is not linked, and it asserted no verified email to match on.
    pub const SOCIAL_UNLINKED: ProblemKind = ProblemKind::new(
        "social_unlinked",
        "MONACA_SOCIAL_UNLINKED",
        "Social account not linked",
        403,
    );
    /// The provider refused the code exchange or returned an unusable document.
    pub const SOCIAL_PROVIDER_ERROR: ProblemKind = ProblemKind::new(
        "social_provider_error",
        "MONACA_SOCIAL_PROVIDER_ERROR",
        "Social provider error",
        502,
    );
    /// No copy exists for the purpose in any locale of the fallback chain.
    pub const TEMPLATE_MISSING: ProblemKind = ProblemKind::new(
        "template_missing",
        "MONACA_TEMPLATE_MISSING",
        "Message template missing",
        500,
    );
    /// The tenant has no enabled SMS connector.
    pub const SMS_NOT_CONFIGURED: ProblemKind = ProblemKind::new(
        "sms_not_configured",
        "MONACA_SMS_NOT_CONFIGURED",
        "SMS channel not configured",
        503,
    );
    /// The SMS code exists but its expiry passed.
    pub const VERIFICATION_CODE_EXPIRED: ProblemKind = ProblemKind::new(
        "verification_code_expired",
        "MONACA_VERIFICATION_CODE_EXPIRED",
        "Verification code expired",
        401,
    );
    /// The server could not complete a valid request.
    pub const INTERNAL: ProblemKind =
        ProblemKind::new("internal", "MONACA_INTERNAL", "Internal error", 500);
}

/// Anything a handler can fail with.
#[derive(Debug)]
pub enum ApiError {
    /// A problem document.
    Problem(Problem),
    /// The token endpoint's flat error shape.
    Token {
        /// The RFC 6749 code.
        code: TokenErrorCode,
        /// A short explanation.
        detail: String,
    },
    /// An interaction that is gone, expired or consumed.
    Interaction(InteractionError),
    /// A resource-server rejection — RFC 6750, answered with a `WWW-Authenticate: Bearer` header.
    Bearer {
        /// The HTTP status (401 or 403).
        status: u16,
        /// `invalid_token` | `insufficient_scope`.
        code: &'static str,
        /// A short explanation.
        detail: String,
    },
    /// A per-endpoint request gate (§6.2), answered with `Retry-After`.
    RateLimited {
        /// Whole seconds until the current window ends.
        retry_after: u64,
    },
}

impl ApiError {
    /// A problem with a kind and a detail.
    pub fn problem(kind: ProblemKind, detail: impl Into<String>) -> Self {
        ApiError::Problem(Problem::new(kind, detail))
    }

    /// An internal error. The detail is logged, never returned.
    pub fn internal(detail: impl std::fmt::Display) -> Self {
        tracing::error!(error = %detail, "internal error");
        ApiError::Problem(Problem::new(
            kinds::INTERNAL,
            "the request could not be completed",
        ))
    }

    /// A token-endpoint error.
    pub fn token(code: TokenErrorCode, detail: impl Into<String>) -> Self {
        ApiError::Token {
            code,
            detail: detail.into(),
        }
    }

    /// A 404 that does not disclose whether the resource exists elsewhere (§6.2).
    pub fn not_found(what: &str) -> Self {
        ApiError::problem(kinds::NOT_FOUND, format!("{what} not found"))
    }

    /// An RFC 6750 bearer-token rejection for a protected resource.
    pub fn bearer(status: u16, code: &'static str, detail: impl Into<String>) -> Self {
        ApiError::Bearer {
            status,
            code,
            detail: detail.into(),
        }
    }

    /// A rate-limit rejection; `retry_after` is whole seconds.
    pub fn rate_limited(retry_after: u64) -> Self {
        ApiError::RateLimited { retry_after }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Problem(problem) => write!(f, "{}: {}", problem.code(), problem.title),
            ApiError::Token { code, detail } => write!(f, "{}: {detail}", code.as_str()),
            ApiError::Bearer { code, detail, .. } => write!(f, "{code}: {detail}"),
            ApiError::Interaction(err) => write!(f, "{err}"),
            ApiError::RateLimited { retry_after } => {
                write!(f, "too_many_attempts: retry after {retry_after}s")
            }
        }
    }
}

impl std::error::Error for ApiError {}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::internal(err)
    }
}

impl From<monaca_store::StoreError> for ApiError {
    fn from(err: monaca_store::StoreError) -> Self {
        match &err {
            monaca_store::StoreError::UnknownTenant(slug) => {
                ApiError::problem(kinds::NOT_FOUND, format!("tenant `{slug}` not found"))
            }
            monaca_store::StoreError::UnknownOrg(slug) => {
                ApiError::problem(kinds::NOT_FOUND, format!("organization `{slug}` not found"))
            }
            monaca_store::StoreError::NotFound { entity, id } => {
                ApiError::problem(kinds::NOT_FOUND, format!("{entity} `{id}` not found"))
            }
            monaca_store::StoreError::Conflict { entity, id } => ApiError::problem(
                kinds::STATE_CONFLICT,
                format!("{entity} `{id}` is not in a state that allows this transition"),
            ),
            monaca_store::StoreError::AlreadyExists { entity } => {
                let kind = match *entity {
                    "email" => kinds::EMAIL_TAKEN,
                    "connector" => kinds::CONNECTOR_EXISTS,
                    "social identity" => kinds::SOCIAL_IDENTITY_TAKEN,
                    "role" => kinds::ROLE_EXISTS,
                    "client" => kinds::CLIENT_EXISTS,
                    "api resource" => kinds::RESOURCE_EXISTS,
                    "organization" => kinds::ORG_EXISTS,
                    "email domain" => kinds::DOMAIN_EXISTS,
                    "custom domain" => kinds::DOMAIN_EXISTS,
                    "invitation" => kinds::INVITATION_EXISTS,
                    "sso connector" => kinds::SSO_CONNECTOR_EXISTS,
                    "sso email domain" => kinds::SSO_DOMAIN_TAKEN,
                    "org role" => kinds::ORG_ROLE_EXISTS,
                    _ => kinds::USERNAME_TAKEN,
                };
                ApiError::problem(kind, format!("{entity} is already taken"))
            }
            monaca_store::StoreError::QuotaExceeded => ApiError::problem(
                kinds::QUOTA_EXCEEDED,
                "the tenant's account quota is exhausted",
            ),
            _ => ApiError::internal(err),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Problem(mut problem) => {
                problem.status = problem.status.max(400);
                let status = StatusCode::from_u16(problem.status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (
                    status,
                    [(header::CONTENT_TYPE, "application/problem+json")],
                    Json(problem),
                )
                    .into_response()
            }
            ApiError::Token { code, detail } => {
                let status = StatusCode::from_u16(code.status()).unwrap_or(StatusCode::BAD_REQUEST);
                let body = json!({
                    "error": code.as_str(),
                    "error_description": detail,
                });
                let mut response = (status, Json(body)).into_response();
                if code == TokenErrorCode::InvalidClient {
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static("Basic realm=\"monaca\""),
                    );
                }
                response
            }
            ApiError::Bearer {
                status,
                code,
                detail,
            } => {
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
                let body = json!({ "error": code, "error_description": detail });
                let mut response = (status, Json(body)).into_response();
                // Only the code goes in the header: `detail` is free-form and may contain
                // characters a header value cannot carry.
                let challenge = format!("Bearer error=\"{code}\"");
                if let Ok(value) = HeaderValue::from_str(&challenge) {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
                response
            }
            ApiError::RateLimited { retry_after } => {
                let problem = Problem::new(
                    kinds::TOO_MANY_ATTEMPTS,
                    format!("rate limit exceeded; retry in {retry_after} s"),
                );
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::CONTENT_TYPE, "application/problem+json")],
                    Json(problem),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                response
            }
            ApiError::Interaction(err) => {
                let problem = Problem::new(
                    ProblemKind::new(
                        "interaction",
                        err.code(),
                        "Interaction unavailable",
                        err.status(),
                    ),
                    err.to_string(),
                );
                let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::CONFLICT);
                (
                    status,
                    [(header::CONTENT_TYPE, "application/problem+json")],
                    Json(problem),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_the_monaca_prefix() {
        for kind in [
            kinds::INVALID_REQUEST,
            kinds::UNAUTHORIZED,
            kinds::INVALID_CREDENTIALS,
            kinds::INSUFFICIENT_SCOPE,
            kinds::NOT_FOUND,
            kinds::PRIVATE_KEY_SUBMITTED,
            kinds::GRANT_REVOKED,
            kinds::ACCOUNT_EXISTS,
            kinds::WEAK_PASSWORD,
            kinds::CONFIRMATION_REQUIRED,
            kinds::QUOTA_EXCEEDED,
            kinds::INVALID_VERIFICATION_CODE,
            kinds::TOO_MANY_ATTEMPTS,
            kinds::CAPTCHA_FAILED,
            kinds::ACCOUNT_LOCKED,
            kinds::MFA_ALREADY_ENABLED,
            kinds::INTERNAL,
        ] {
            assert!(kind.code().starts_with("MONACA_"));
            assert!((400..=500).contains(&kind.status()));
        }
    }
}
