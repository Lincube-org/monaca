//! The HTTP surface and its three audiences — `docs/contracts/m0.md` §6.
//!
//! The grouping is not cosmetic: the gateway proxies `/t`, `/.well-known` and `/v1`, and **never**
//! `/internal`. Keeping the three in separate functions makes that boundary readable at the mount
//! point and lets each grow its own middleware without touching the others.

use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
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
    paths(
        healthz,
        version,
        crate::metrics::scrape,
        crate::management::get_rate_limits,
        crate::management::update_rate_limits,
        crate::management::get_me,
        crate::management::get_tenant,
        crate::management::update_tenant,
        crate::management::list_accounts,
        crate::management::create_account,
        crate::management::get_account,
        crate::management::update_account,
        crate::management::list_roles,
        crate::management::create_role,
        crate::management::update_role,
        crate::management::list_account_sessions,
        crate::management::revoke_account_session,
        crate::management::revoke_account_sessions,
        crate::clients::list_clients,
        crate::clients::create_client,
        crate::clients::get_client,
        crate::clients::update_client,
        crate::clients::rotate_client_secret,
        crate::orgs::list_orgs,
        crate::orgs::create_org,
        crate::orgs::get_org,
        crate::orgs::update_org,
        crate::social::list_connectors,
        crate::social::create_connector,
        crate::social::update_connector
    ),
    components(schemas(
        crate::management::RateLimitItem,
        crate::management::RateLimitsPatch,
        crate::management::RateLimitDefaultView,
        crate::management::RateLimitView,
        crate::management::IpLimitView,
        crate::management::RateLimitStatusView,
        crate::management::RateLimitsDocument,
        crate::management::CreateAccountBody,
        crate::management::UpdateAccountBody,
        crate::management::CreateRoleBody,
        crate::management::UpdateRoleBody,
        crate::management::MeRoleView,
        crate::management::MeView,
        crate::management::TenantView,
        crate::management::UpdateTenantBody,
        crate::clients::CreateClientBody,
        crate::clients::UpdateClientBody,
        crate::orgs::CreateOrgBody,
        crate::orgs::UpdateOrgBody,
        crate::social::CreateConnectorBody,
        crate::social::UpdateConnectorBody,
        crate::schemas::AccountView,
        crate::schemas::AccountDetailView,
        crate::schemas::AccountList,
        crate::schemas::RoleRef,
        crate::schemas::ClientView,
        crate::schemas::CreatedClientView,
        crate::schemas::ClientList,
        crate::schemas::ClientSecretView,
        crate::schemas::OrgView,
        crate::schemas::OrgList,
        crate::schemas::RoleView,
        crate::schemas::RoleList,
        crate::schemas::ConnectorView,
        crate::schemas::ConnectorList,
        crate::schemas::SessionView,
        crate::schemas::SessionList,
        crate::schemas::RevokedSessionsView
    ))
)]
pub struct ApiDoc;

/// Build the application router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(health_routes())
        .merge(protocol_routes())
        .merge(account_routes())
        .merge(management_routes())
        .merge(internal_routes(state.config.production))
        .with_state(state.clone())
        // Only the protocol paths it recognizes are touched; see `cors` for the tenant gate.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::cors::tenant_cors,
        ))
        // Outermost: every response, including a CORS preflight or an error page, is counted.
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::metrics::middleware,
        ))
}

/// The generated OpenAPI document.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    <ApiDoc as utoipa::OpenApi>::openapi()
}

/// The complete route surface, with the methods each path accepts.
///
/// The typed slice (`healthz`, `version`, `metrics`, `/v1/rate-limits`) is annotated on the
/// handlers and carries schemas. The rest is registered here with a summary. Every mounted path
/// and method outside `/internal/*` appears here; `/internal/*` is excluded because the gateway
/// never proxies it. Response schemas are filled in incrementally, but the path/method set is not
/// a gap.
const SURFACE: &[(&str, &[&str], &str)] = &[
    (
        "/t/{tenant}/.well-known/openid-configuration",
        &["get"],
        "Tenant discovery",
    ),
    (
        "/.well-known/oauth-authorization-server/t/{tenant}",
        &["get"],
        "Tenant discovery (RFC 8414 path)",
    ),
    ("/t/{tenant}/.well-known/jwks.json", &["get"], "Tenant JWKS"),
    (
        "/t/{tenant}/oauth2/authorize",
        &["get"],
        "Authorization request",
    ),
    ("/t/{tenant}/oauth2/token", &["post"], "Token endpoint"),
    ("/t/{tenant}/oauth2/userinfo", &["get", "post"], "UserInfo"),
    (
        "/t/{tenant}/oauth2/introspect",
        &["post"],
        "Token introspection",
    ),
    ("/t/{tenant}/oauth2/revoke", &["post"], "Token revocation"),
    (
        "/t/{tenant}/oauth2/par",
        &["post"],
        "Pushed authorization request",
    ),
    (
        "/t/{tenant}/oauth2/end-session",
        &["get", "post"],
        "End a session",
    ),
    (
        "/t/{tenant}/interaction/{iid}",
        &["get"],
        "Interaction details",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in",
        &["post"],
        "Password sign-in",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-up",
        &["post"],
        "Sign-up",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-up/verify",
        &["post"],
        "Verify a sign-up code",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in/code",
        &["post"],
        "Sign-in by email code",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in/code/verify",
        &["post"],
        "Verify a sign-in code",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in/link",
        &["post"],
        "Sign-in by emailed link",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in/link/verify",
        &["get"],
        "Redeem a sign-in link",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in/passkey/options",
        &["post"],
        "Passkey sign-in options",
    ),
    (
        "/t/{tenant}/interaction/{iid}/sign-in/passkey",
        &["post"],
        "Passkey sign-in",
    ),
    (
        "/t/{tenant}/interaction/{iid}/mfa/passkey/options",
        &["post"],
        "Passkey second-factor options",
    ),
    (
        "/t/{tenant}/interaction/{iid}/mfa/passkey",
        &["post"],
        "Passkey second factor",
    ),
    (
        "/t/{tenant}/interaction/{iid}/password/forgot",
        &["post"],
        "Request a password reset",
    ),
    (
        "/t/{tenant}/interaction/{iid}/password/reset",
        &["post"],
        "Reset a password",
    ),
    (
        "/t/{tenant}/interaction/{iid}/mfa/verify",
        &["post"],
        "Verify a second factor",
    ),
    (
        "/t/{tenant}/interaction/{iid}/mfa/enroll",
        &["post"],
        "Begin second-factor enrollment",
    ),
    (
        "/t/{tenant}/interaction/{iid}/mfa/enroll/verify",
        &["post"],
        "Finish second-factor enrollment",
    ),
    (
        "/t/{tenant}/interaction/{iid}/consent",
        &["post"],
        "Consent",
    ),
    (
        "/t/{tenant}/interaction/{iid}/abort",
        &["post"],
        "Abort an interaction",
    ),
    (
        "/t/{tenant}/connectors",
        &["get"],
        "Public social connectors",
    ),
    (
        "/t/{tenant}/sign-in-experience",
        &["get"],
        "Public sign-in experience",
    ),
    ("/t/{tenant}/sign-in-copy", &["get"], "Public sign-in copy"),
    (
        "/t/{tenant}/connectors/{connector}/authorize",
        &["get"],
        "Start a social sign-in",
    ),
    (
        "/t/{tenant}/connectors/{connector}/callback",
        &["get"],
        "Social provider callback",
    ),
    (
        "/t/{tenant}/social/link/{token}",
        &["get"],
        "Pending social link",
    ),
    (
        "/t/{tenant}/social/link/{token}/confirm",
        &["post"],
        "Confirm a social link",
    ),
    (
        "/t/{tenant}/sso-connectors",
        &["get"],
        "Public SSO connectors",
    ),
    (
        "/t/{tenant}/sso/{connector}/authorize",
        &["get"],
        "Start an SSO sign-in",
    ),
    (
        "/t/{tenant}/sso/{connector}/callback",
        &["get"],
        "SSO provider callback",
    ),
    (
        "/t/{tenant}/sso/{connector}/acs",
        &["post"],
        "SAML assertion consumer service",
    ),
    (
        "/t/{tenant}/sso/{connector}/metadata",
        &["get"],
        "SAML SP metadata",
    ),
    (
        "/t/{tenant}/account",
        &["get", "patch"],
        "Signed-in account",
    ),
    (
        "/t/{tenant}/account/email",
        &["post"],
        "Request an email change",
    ),
    (
        "/t/{tenant}/account/email/verify",
        &["post"],
        "Verify an email change",
    ),
    (
        "/t/{tenant}/account/deletion",
        &["post"],
        "Request account deletion",
    ),
    (
        "/t/{tenant}/account/deletion/confirm",
        &["post"],
        "Confirm account deletion",
    ),
    (
        "/t/{tenant}/account/password",
        &["post"],
        "Change the account password",
    ),
    (
        "/t/{tenant}/account/sessions",
        &["get", "delete"],
        "Account sessions",
    ),
    (
        "/t/{tenant}/account/sessions/{session}",
        &["delete"],
        "Revoke one account session",
    ),
    (
        "/t/{tenant}/account/authorized-apps",
        &["get"],
        "Authorized applications",
    ),
    (
        "/t/{tenant}/account/authorized-apps/{client}",
        &["delete"],
        "Withdraw an authorized application",
    ),
    (
        "/t/{tenant}/account/mfa/totp",
        &["post", "delete"],
        "TOTP second factor",
    ),
    (
        "/t/{tenant}/account/mfa/totp/verify",
        &["post"],
        "Verify TOTP enrollment",
    ),
    (
        "/t/{tenant}/account/mfa/devices",
        &["get"],
        "Trusted devices",
    ),
    (
        "/t/{tenant}/account/mfa/devices/{device}",
        &["delete"],
        "Revoke a trusted device",
    ),
    (
        "/t/{tenant}/account/mfa/backup-codes",
        &["get", "post", "delete"],
        "Backup codes",
    ),
    (
        "/t/{tenant}/account/passkeys/options",
        &["post"],
        "Passkey registration options",
    ),
    (
        "/t/{tenant}/account/passkeys",
        &["get", "post"],
        "Registered passkeys",
    ),
    (
        "/t/{tenant}/account/passkeys/{passkey}",
        &["patch", "delete"],
        "One registered passkey",
    ),
    (
        "/t/{tenant}/account/social/{connector}/authorize",
        &["get"],
        "Connect a social provider",
    ),
    (
        "/t/{tenant}/account/social/{connector}",
        &["delete"],
        "Disconnect a social provider",
    ),
    ("/v1/accounts", &["get", "post"], "List and create accounts"),
    ("/v1/usage", &["get", "patch"], "Tenant usage and quota"),
    (
        "/v1/accounts/{id}",
        &["get", "patch", "delete"],
        "Read, update or delete an account",
    ),
    (
        "/v1/accounts/{id}/sessions",
        &["get", "delete"],
        "Account sessions",
    ),
    (
        "/v1/accounts/{id}/sessions/{session}",
        &["delete"],
        "Revoke one session",
    ),
    (
        "/v1/accounts/{id}/security",
        &["get"],
        "Account security summary",
    ),
    (
        "/v1/accounts/{id}/mfa",
        &["delete"],
        "Remove the second factor",
    ),
    (
        "/v1/accounts/{id}/passkeys/{passkey}",
        &["delete"],
        "Remove a passkey",
    ),
    (
        "/v1/accounts/{id}/roles/{role}",
        &["post", "delete"],
        "Assign or remove a role",
    ),
    (
        "/v1/orgs",
        &["get", "post"],
        "List and create organizations",
    ),
    (
        "/v1/orgs/{org}",
        &["get", "patch"],
        "Read and update an organization",
    ),
    (
        "/v1/orgs/{org}/members",
        &["get", "post"],
        "Organization members",
    ),
    (
        "/v1/orgs/{org}/members/{account}",
        &["patch", "delete"],
        "One member",
    ),
    (
        "/v1/orgs/{org}/email-domains",
        &["get", "post"],
        "Email domains",
    ),
    (
        "/v1/orgs/{org}/email-domains/{domain}",
        &["delete"],
        "Remove an email domain",
    ),
    (
        "/v1/orgs/{org}/invitations",
        &["get", "post"],
        "Invitations",
    ),
    (
        "/v1/orgs/{org}/invitations/{invitation}",
        &["delete"],
        "Revoke an invitation",
    ),
    (
        "/v1/orgs/{org}/roles",
        &["get", "post"],
        "Organization roles",
    ),
    (
        "/v1/orgs/{org}/roles/{role}",
        &["patch", "delete"],
        "One organization role",
    ),
    (
        "/v1/orgs/{org}/members/{account}/roles",
        &["get", "post"],
        "Member role assignments",
    ),
    (
        "/v1/orgs/{org}/members/{account}/roles/{role}",
        &["delete"],
        "Remove a member role",
    ),
    ("/v1/orgs/{org}/agents", &["get", "post"], "Agents"),
    (
        "/v1/orgs/{org}/agents/{agent}/keys",
        &["post"],
        "Register an agent key",
    ),
    (
        "/v1/orgs/{org}/agents/{agent}/keys/{key}",
        &["delete"],
        "Revoke an agent key",
    ),
    ("/v1/orgs/{org}/grants", &["get", "post"], "Grants"),
    (
        "/v1/orgs/{org}/grants/{grant}",
        &["delete"],
        "Revoke a grant",
    ),
    ("/v1/audit", &["get"], "Tenant audit events"),
    ("/v1/orgs/{org}/audit", &["get"], "Audit events"),
    (
        "/v1/orgs/{org}/audit/verify",
        &["get"],
        "Verify an audit chain",
    ),
    ("/v1/connectors", &["get", "post"], "Social connectors"),
    (
        "/v1/connectors/{connector}",
        &["patch", "delete"],
        "One social connector",
    ),
    ("/v1/sso-connectors", &["get", "post"], "SSO connectors"),
    (
        "/v1/sso-connectors/{connector}",
        &["delete"],
        "One SSO connector",
    ),
    ("/v1/saml-connectors", &["get", "post"], "SAML connectors"),
    (
        "/v1/saml-connectors/{connector}",
        &["delete"],
        "One SAML connector",
    ),
    ("/v1/clients", &["get", "post"], "OAuth clients"),
    (
        "/v1/clients/{client}",
        &["get", "patch", "delete"],
        "One OAuth client",
    ),
    (
        "/v1/clients/{client}/secret",
        &["post"],
        "Rotate a client secret",
    ),
    (
        "/v1/sign-in-experience",
        &["get", "patch"],
        "Sign-in policy",
    ),
    ("/v1/sign-in-copy", &["get", "patch"], "Sign-in copy"),
    ("/v1/email-templates", &["get"], "Email templates"),
    (
        "/v1/email-templates/{purpose}",
        &["patch", "delete"],
        "One email template",
    ),
    (
        "/v1/email-connector",
        &["get", "patch", "delete"],
        "Delivery connector",
    ),
    (
        "/v1/sms-connector",
        &["get", "patch", "delete"],
        "SMS connector",
    ),
    ("/v1/message-templates", &["get"], "Message templates"),
    (
        "/v1/message-templates/{purpose}/{locale}",
        &["patch", "delete"],
        "One message template",
    ),
    (
        "/v1/message-templates/{purpose}/{locale}/restore",
        &["post"],
        "Restore a built-in message template",
    ),
    (
        "/t/{tenant}/verification/sms",
        &["post"],
        "Send an SMS verification code",
    ),
    (
        "/t/{tenant}/verification/sms/verify",
        &["post"],
        "Verify an SMS code",
    ),
    ("/v1/resources", &["get", "post"], "API resources"),
    (
        "/v1/resources/{resource}",
        &["get", "patch", "delete"],
        "One API resource",
    ),
    ("/v1/me", &["get"], "The signed-in account"),
    ("/v1/tenant", &["get", "patch"], "Tenant lifecycle"),
    ("/v1/roles", &["get", "post"], "Tenant roles"),
    ("/v1/roles/{role}", &["patch", "delete"], "One tenant role"),
    ("/v1/webhooks", &["get", "post"], "Webhooks"),
    (
        "/v1/webhooks/{webhook}",
        &["patch", "delete"],
        "One webhook",
    ),
    (
        "/v1/webhooks/{webhook}/secret",
        &["post"],
        "Rotate a webhook secret",
    ),
    (
        "/v1/webhooks/{webhook}/deliveries",
        &["get"],
        "Webhook deliveries",
    ),
];

/// The generated document plus the path overlay above, as JSON.
pub fn openapi_value() -> serde_json::Value {
    let mut value = serde_json::to_value(openapi_document())
        .expect("the generated OpenAPI document serializes");
    let paths = value["paths"]
        .as_object_mut()
        .expect("the generated document has a paths object");
    for (path, methods, summary) in SURFACE {
        let item = paths
            .entry((*path).to_owned())
            .or_insert_with(|| serde_json::json!({}));
        for method in *methods {
            if item.get(*method).is_some() {
                continue;
            }
            item[*method] = serde_json::json!({
                "summary": summary,
                "responses": {
                    "200": { "description": "See docs/contracts/m0.md for the body." }
                }
            });
        }
    }
    value
}

/// `/healthz`, `/version` and the Prometheus scrape endpoint — §6.4.
pub fn health_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/metrics", get(crate::metrics::scrape))
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
            "/t/{tenant}/verification/sms",
            post(crate::sms::request_code),
        )
        .route(
            "/t/{tenant}/verification/sms/verify",
            post(crate::sms::verify_code),
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
            "/t/{tenant}/interaction/{iid}/sign-in/link",
            post(crate::protocol::sign_in_link),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-in/link/verify",
            get(crate::protocol::sign_in_link_verify),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-in/passkey/options",
            post(crate::protocol::passkey_sign_in_options),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/sign-in/passkey",
            post(crate::protocol::passkey_sign_in_verify),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/mfa/passkey/options",
            post(crate::protocol::mfa_passkey_options),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/mfa/passkey",
            post(crate::protocol::mfa_passkey_verify),
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
            "/t/{tenant}/interaction/{iid}/mfa/enroll",
            post(crate::protocol::mfa_enroll_start),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/mfa/enroll/verify",
            post(crate::protocol::mfa_enroll_verify),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/consent",
            post(crate::protocol::consent),
        )
        .route(
            "/t/{tenant}/interaction/{iid}/abort",
            post(crate::protocol::abort),
        )
        .route(
            "/t/{tenant}/connectors",
            get(crate::social::list_public_connectors),
        )
        .route(
            "/t/{tenant}/sign-in-experience",
            get(crate::protocol::sign_in_experience),
        )
        .route("/t/{tenant}/sign-in-copy", get(crate::copy::sign_in_copy))
        .route(
            "/t/{tenant}/connectors/{connector}/authorize",
            get(crate::social::connector_authorize),
        )
        .route(
            "/t/{tenant}/connectors/{connector}/callback",
            get(crate::social::connector_callback),
        )
        .route(
            "/t/{tenant}/social/link/{token}",
            get(crate::social::social_link_details),
        )
        .route(
            "/t/{tenant}/social/link/{token}/confirm",
            post(crate::social::confirm_social_link),
        )
        .route(
            "/t/{tenant}/sso-connectors",
            get(crate::sso::list_public_sso_connectors),
        )
        .route(
            "/t/{tenant}/sso/{connector}/authorize",
            get(crate::sso::sso_authorize),
        )
        .route(
            "/t/{tenant}/sso/{connector}/callback",
            get(crate::sso::sso_callback),
        )
        .route(
            "/t/{tenant}/sso/{connector}/acs",
            post(crate::saml::saml_acs),
        )
        .route(
            "/t/{tenant}/sso/{connector}/metadata",
            get(crate::saml::sp_metadata),
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
            "/t/{tenant}/account/email",
            post(crate::account::request_email_change),
        )
        .route(
            "/t/{tenant}/account/email/verify",
            post(crate::account::verify_email_change),
        )
        .route(
            "/t/{tenant}/account/deletion",
            post(crate::account::request_deletion),
        )
        .route(
            "/t/{tenant}/account/deletion/confirm",
            post(crate::account::confirm_deletion),
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
            "/t/{tenant}/account/authorized-apps",
            get(crate::account::list_authorized_apps),
        )
        .route(
            "/t/{tenant}/account/authorized-apps/{client}",
            delete(crate::account::revoke_authorized_app),
        )
        .route(
            "/t/{tenant}/account/mfa/totp",
            post(crate::account::begin_totp).delete(crate::account::disable_totp),
        )
        .route(
            "/t/{tenant}/account/mfa/totp/verify",
            post(crate::account::verify_totp_enrollment),
        )
        .route(
            "/t/{tenant}/account/mfa/devices",
            get(crate::account::list_trusted_devices),
        )
        .route(
            "/t/{tenant}/account/mfa/devices/{device}",
            delete(crate::account::revoke_trusted_device),
        )
        .route(
            "/t/{tenant}/account/mfa/backup-codes",
            get(crate::account::list_backup_codes)
                .post(crate::account::create_backup_codes)
                .delete(crate::account::remove_backup_codes),
        )
        .route(
            "/t/{tenant}/account/passkeys/options",
            post(crate::account::begin_passkey_registration),
        )
        .route(
            "/t/{tenant}/account/passkeys",
            get(crate::account::list_passkeys).post(crate::account::register_passkey),
        )
        .route(
            "/t/{tenant}/account/passkeys/{passkey}",
            patch(crate::account::rename_passkey).delete(crate::account::delete_passkey),
        )
        .route(
            "/t/{tenant}/account/social/{connector}/authorize",
            get(crate::social::account_link_start),
        )
        .route(
            "/t/{tenant}/account/social/{connector}",
            delete(crate::social::unlink_account),
        )
}

/// The `/v1` management API — §6.2.
pub fn management_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v1/accounts",
            get(crate::management::list_accounts).post(crate::management::create_account),
        )
        .route("/v1/me", get(crate::management::get_me))
        .route(
            "/v1/tenant",
            get(crate::management::get_tenant).patch(crate::management::update_tenant),
        )
        .route(
            "/v1/usage",
            get(crate::management::get_usage).patch(crate::management::update_usage),
        )
        .route(
            "/v1/accounts/{id}",
            get(crate::management::get_account)
                .patch(crate::management::update_account)
                .delete(crate::management::delete_account),
        )
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
            "/v1/accounts/{id}/security",
            get(crate::management::get_account_security),
        )
        .route(
            "/v1/accounts/{id}/mfa",
            delete(crate::management::reset_account_mfa),
        )
        .route(
            "/v1/accounts/{id}/passkeys/{passkey}",
            delete(crate::management::delete_account_passkey),
        )
        .route(
            "/v1/orgs",
            get(crate::orgs::list_orgs).post(crate::orgs::create_org),
        )
        .route(
            "/v1/orgs/{org}",
            get(crate::orgs::get_org).patch(crate::orgs::update_org),
        )
        .route(
            "/v1/orgs/{org}/members",
            get(crate::management::list_members).post(crate::management::add_member),
        )
        .route(
            "/v1/orgs/{org}/members/{account}",
            patch(crate::management::update_member).delete(crate::management::remove_member),
        )
        .route(
            "/v1/orgs/{org}/email-domains",
            get(crate::orgs::list_email_domains).post(crate::orgs::add_email_domain),
        )
        .route(
            "/v1/orgs/{org}/email-domains/{domain}",
            delete(crate::orgs::remove_email_domain),
        )
        .route(
            "/v1/orgs/{org}/invitations",
            get(crate::orgs::list_invitations).post(crate::orgs::create_invitation),
        )
        .route(
            "/v1/orgs/{org}/invitations/{invitation}",
            delete(crate::orgs::revoke_invitation),
        )
        .route(
            "/v1/orgs/{org}/roles",
            get(crate::org_roles::list_org_roles).post(crate::org_roles::create_org_role),
        )
        .route(
            "/v1/orgs/{org}/roles/{role}",
            patch(crate::org_roles::update_org_role).delete(crate::org_roles::delete_org_role),
        )
        .route(
            "/v1/orgs/{org}/members/{account}/roles",
            get(crate::org_roles::list_member_roles).post(crate::org_roles::assign_member_role),
        )
        .route(
            "/v1/orgs/{org}/members/{account}/roles/{role}",
            delete(crate::org_roles::unassign_member_role),
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
        .route("/v1/audit", get(crate::management::list_tenant_audit))
        .route("/v1/orgs/{org}/audit", get(crate::management::list_audit))
        .route(
            "/v1/orgs/{org}/audit/verify",
            get(crate::management::verify_audit),
        )
        .route(
            "/v1/connectors",
            get(crate::social::list_connectors).post(crate::social::create_connector),
        )
        .route(
            "/v1/connectors/{connector}",
            patch(crate::social::update_connector).delete(crate::social::delete_connector),
        )
        .route(
            "/v1/sso-connectors",
            get(crate::sso::list_sso_connectors).post(crate::sso::create_sso_connector),
        )
        .route(
            "/v1/sso-connectors/{connector}",
            delete(crate::sso::delete_sso_connector),
        )
        .route(
            "/v1/saml-connectors",
            get(crate::saml::list_saml_connectors).post(crate::saml::create_saml_connector),
        )
        .route(
            "/v1/saml-connectors/{connector}",
            delete(crate::saml::delete_saml_connector),
        )
        .route(
            "/v1/clients",
            get(crate::clients::list_clients).post(crate::clients::create_client),
        )
        .route(
            "/v1/clients/{client}",
            get(crate::clients::get_client)
                .patch(crate::clients::update_client)
                .delete(crate::clients::delete_client),
        )
        .route(
            "/v1/clients/{client}/secret",
            post(crate::clients::rotate_client_secret),
        )
        .route(
            "/v1/sign-in-experience",
            get(crate::management::get_sign_in_experience)
                .patch(crate::management::update_sign_in_experience),
        )
        .route(
            "/v1/sign-in-copy",
            get(crate::copy::get_sign_in_copy).patch(crate::copy::update_sign_in_copy),
        )
        .route(
            "/v1/rate-limits",
            get(crate::management::get_rate_limits).patch(crate::management::update_rate_limits),
        )
        .route(
            "/v1/email-templates",
            get(crate::message_templates::list_email_templates),
        )
        .route(
            "/v1/email-templates/{purpose}",
            patch(crate::message_templates::update_email_template)
                .delete(crate::message_templates::reset_email_template),
        )
        .route(
            "/v1/message-templates",
            get(crate::message_templates::list_message_templates),
        )
        .route(
            "/v1/message-templates/{purpose}/{locale}",
            patch(crate::message_templates::update_message_template)
                .delete(crate::message_templates::delete_message_template),
        )
        .route(
            "/v1/message-templates/{purpose}/{locale}/restore",
            post(crate::message_templates::restore_message_template),
        )
        .route(
            "/v1/email-connector",
            get(crate::email_connector::get_email_connector)
                .patch(crate::email_connector::update_email_connector)
                .delete(crate::email_connector::delete_email_connector),
        )
        .route(
            "/v1/sms-connector",
            get(crate::email_connector::get_sms_connector)
                .patch(crate::email_connector::update_sms_connector)
                .delete(crate::email_connector::delete_sms_connector),
        )
        .route(
            "/v1/resources",
            get(crate::resources::list_resources).post(crate::resources::create_resource),
        )
        .route(
            "/v1/resources/{resource}",
            get(crate::resources::get_resource)
                .patch(crate::resources::update_resource)
                .delete(crate::resources::delete_resource),
        )
        .route(
            "/v1/roles",
            get(crate::management::list_roles).post(crate::management::create_role),
        )
        .route(
            "/v1/roles/{role}",
            patch(crate::management::update_role).delete(crate::management::delete_role),
        )
        .route(
            "/v1/accounts/{id}/roles/{role}",
            post(crate::management::assign_role).delete(crate::management::unassign_role),
        )
        .route(
            "/v1/webhooks",
            get(crate::webhooks::list_webhooks).post(crate::webhooks::create_webhook),
        )
        .route(
            "/v1/webhooks/{webhook}",
            patch(crate::webhooks::update_webhook).delete(crate::webhooks::delete_webhook),
        )
        .route(
            "/v1/webhooks/{webhook}/secret",
            post(crate::webhooks::rotate_webhook_secret),
        )
        .route(
            "/v1/webhooks/{webhook}/deliveries",
            get(crate::webhooks::list_webhook_deliveries),
        )
}

/// `/internal/*` — §6.3. The gateway must never proxy this group.
///
/// `/internal/mail` is the dev/CI outbox reader: its payload carries the verification code in
/// plaintext, so the route is mounted only outside `prod`. In production it does not exist at all,
/// which is a `404` rather than an authentication failure.
pub fn internal_routes(production: bool) -> Router<Arc<AppState>> {
    let routes = Router::new()
        .route(
            "/internal/audit",
            post(crate::internal::append_audit).get(crate::internal::tenant_audit),
        )
        .route(
            "/internal/tenants/{slug}/jwks",
            get(crate::internal::tenant_jwks),
        )
        .route(
            "/internal/tenants/{slug}/issuer",
            get(crate::internal::tenant_issuer),
        )
        .route("/internal/health", get(crate::internal::health));
    if production {
        routes
    } else {
        routes.route("/internal/mail", get(crate::internal::latest_mail))
    }
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
