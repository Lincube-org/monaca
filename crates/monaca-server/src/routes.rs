//! The HTTP surface and its three audiences — `docs/contracts/m0.md` §6.
//!
//! The grouping is not cosmetic: the gateway proxies `/t`, `/.well-known` and `/v1`, and **never**
//! `/internal`. Keeping the three in separate functions makes that boundary readable at the mount
//! point and lets each grow its own middleware without touching the others.

use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

/// The OpenAPI document.
///
/// The M0 walk-through is exercised by `scripts/e2e/skeleton.ts`, which speaks the endpoints
/// directly; the `/v1` operations are added to `paths(...)` as their review lands. The drift check
/// in `rust.yml` compares the generated document against `spec/openapi.json`, so the two are
/// always the same document even while it is this small.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Monaca",
        version = env!("CARGO_PKG_VERSION"),
        description = "Identity and access management for the AI-agent era."
    ),
    paths(healthz, version)
)]
pub struct ApiDoc;

/// Build the application router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(health_routes())
        .merge(protocol_routes())
        .merge(account_routes())
        .merge(management_routes())
        .merge(internal_routes())
        .with_state(state)
}

/// The generated OpenAPI document.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    <ApiDoc as utoipa::OpenApi>::openapi()
}

/// `/healthz` and `/version`.
pub fn health_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
}

/// The protocol endpoints — §6.1.
pub fn protocol_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/t/{tenant}/.well-known/openid-configuration",
            get(crate::protocol::discovery),
        )
        .route(
            "/.well-known/oauth-authorization-server/t/{tenant}",
            get(crate::protocol::discovery),
        )
        .route(
            "/t/{tenant}/.well-known/jwks.json",
            get(crate::protocol::jwks),
        )
        .route(
            "/t/{tenant}/oauth2/authorize",
            get(crate::protocol::authorize),
        )
        .route("/t/{tenant}/oauth2/token", post(crate::protocol::token))
        .route(
            "/t/{tenant}/oauth2/userinfo",
            get(crate::oauth::userinfo).post(crate::oauth::userinfo),
        )
        .route(
            "/t/{tenant}/oauth2/introspect",
            post(crate::oauth::introspect),
        )
        .route("/t/{tenant}/oauth2/revoke", post(crate::oauth::revoke))
        .route("/t/{tenant}/oauth2/par", post(crate::oauth::par))
        .route(
            "/t/{tenant}/oauth2/end-session",
            get(crate::protocol::end_session).post(crate::protocol::end_session_post),
        )
        .route(
            "/t/{tenant}/interaction/{iid}",
            get(crate::protocol::interaction_details),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-in",
            post(crate::protocol::sign_in),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-up",
            post(crate::protocol::sign_up),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-up/verify",
            post(crate::protocol::sign_up_verify),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-in/code",
            post(crate::protocol::sign_in_code),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-in/code/verify",
            post(crate::protocol::sign_in_code_verify),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/password/forgot",
            post(crate::protocol::password_forgot),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/password/reset",
            post(crate::protocol::password_reset),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/mfa/verify",
            post(crate::protocol::mfa_verify),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/consent",
            post(crate::protocol::consent),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/abort",
            post(crate::protocol::abort),
        )
}

/// The signed-in account's own security settings — §6.1 `mfa`.
///
/// These live under `/t/{tenant}` because they are cookie-authenticated browser calls, not `/v1`
/// management calls: only the account itself may enroll or remove its second factor.
pub fn account_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/t/{tenant}/account",
            get(crate::account::get_account).patch(crate::account::update_account),
        )
        .route(
            "/t/{tenant}/account/password",
            post(crate::account::change_password),
        )
        .route(
            "/t/{tenant}/account/sessions",
            get(crate::account::list_sessions).delete(crate::account::revoke_other_sessions),
        )
        .route(
            "/t/{tenant}/account/sessions/{session}",
            delete(crate::account::revoke_session),
        )
        .route(
            "/t/{tenant}/account/mfa/totp",
            post(crate::account::begin_totp).delete(crate::account::disable_totp),
        )
        .route(
            "/t/{tenant}/account/mfa/totp/verify",
            post(crate::account::verify_totp_enrollment),
        )
}

/// The `/v1` management API — §6.2.
pub fn management_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/accounts", post(crate::management::create_account))
        .route("/v1/accounts/{id}", get(crate::management::get_account))
        .route(
            "/v1/accounts/{id}/sessions",
            get(crate::management::list_account_sessions)
                .delete(crate::management::revoke_account_sessions),
        )
        .route(
            "/v1/accounts/{id}/sessions/{session}",
            delete(crate::management::revoke_account_session),
        )
        .route(
            "/v1/orgs/{org}/members",
            get(crate::management::list_members).post(crate::management::add_member),
        )
        .route(
            "/v1/orgs/{org}/agents",
            get(crate::management::list_agents).post(crate::management::create_agent),
        )
        .route(
            "/v1/orgs/{org}/agents/{agent}/keys",
            post(crate::management::register_agent_key),
        )
        .route(
            "/v1/orgs/{org}/agents/{agent}/keys/{key}",
            delete(crate::management::revoke_agent_key),
        )
        .route(
            "/v1/orgs/{org}/grants",
            get(crate::management::list_grants).post(crate::management::create_grant),
        )
        .route(
            "/v1/orgs/{org}/grants/{grant}",
            delete(crate::management::revoke_grant),
        )
        .route("/v1/orgs/{org}/audit", get(crate::management::list_audit))
        .route(
            "/v1/orgs/{org}/audit/verify",
            get(crate::management::verify_audit),
        )
}

/// `/internal/*` — §6.3. The gateway must never proxy this group.
pub fn internal_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/internal/audit", post(crate::internal::append_audit))
        .route(
            "/internal/tenants/{slug}/jwks",
            get(crate::internal::tenant_jwks),
        )
        .route(
            "/internal/tenants/{slug}/issuer",
            get(crate::internal::tenant_issuer),
        )
        .route("/internal/health", get(crate::internal::health))
        .route("/internal/mail", get(crate::internal::latest_mail))
}

/// `GET /healthz` — always `200` with `{"status":"ok"}`.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "meta",
    summary = "Liveness",
    description = "Always 200 with {\"status\":\"ok\"} while the process can serve.",
    responses(
        (status = 200, description = "The server is alive.", body = HealthResponse)
    )
)]
pub(crate) async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// `GET /version` — the crate version, as compiled.
#[utoipa::path(
    get,
    path = "/version",
    tag = "meta",
    summary = "Build version",
    responses(
        (status = 200, description = "The binary's name and version.", body = VersionResponse)
    )
)]
pub(crate) async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// The `/healthz` body — §6.1.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// Always `"ok"`; the endpoint does not answer otherwise.
    pub status: &'static str,
}

/// The `/version` body.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VersionResponse {
    /// The binary's package name.
    pub name: &'static str,
    /// The version it was built from.
    pub version: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_health_body_is_exactly_the_contract_shape() {
        let value = serde_json::to_value(HealthResponse { status: "ok" }).expect("serializes");
        assert_eq!(value, serde_json::json!({"status": "ok"}));
    }

    #[test]
    fn the_version_body_names_the_binary() {
        let value = serde_json::to_value(VersionResponse {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        })
        .expect("serializes");
        assert_eq!(value["name"], "monaca-server");
        assert!(value["version"].as_str().expect("version").contains('.'));
    }
}
