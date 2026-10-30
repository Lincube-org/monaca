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
    /// The resource does not exist, or is outside the caller's tenant.
    pub const NOT_FOUND: ProblemKind =
        ProblemKind::new("not_found", "MONACA_NOT_FOUND", "Not found", 404);
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
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Problem(problem) => write!(f, "{}: {}", problem.code(), problem.title),
            ApiError::Token { code, detail } => write!(f, "{}: {detail}", code.as_str()),
            ApiError::Bearer { code, detail, .. } => write!(f, "{code}: {detail}"),
            ApiError::Interaction(err) => write!(f, "{err}"),
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
            kinds::INTERNAL,
        ] {
            assert!(kind.code().starts_with("MONACA_"));
            assert!((400..=500).contains(&kind.status()));
        }
    }
}
