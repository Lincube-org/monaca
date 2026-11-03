//! Social (OAuth2) connectors — `docs/contracts/m0.md` §6.1.
//!
//! A connector is tenant configuration, not code: the tenant points Monaca at a provider's
//! authorization, token and userinfo endpoints, and the server performs the ordinary authorization
//! code exchange a web application would. Nothing about the provider's protocol is assumed beyond
//! the OAuth2 code grant and an OIDC-shaped userinfo document (`sub`, `email`, `email_verified`,
//! `name`).
//!
//! Two flows share the callback:
//!
//! - **sign-in** starts from the sign-in page with an interaction id; the callback resolves the
//!   provider subject to an account and hands the interaction to the same completion path a
//!   password uses, so MFA and consent are not reimplemented here.
//! - **link** starts from the account centre while already signed in; the callback attaches the
//!   provider subject to that account and returns to the account page.
//!
//! The `state` parameter is stored, single-use and short-lived: it is what binds a callback to the
//! interaction (or account) that started it, and what stops a replayed authorization code.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{open, seal};
use monaca_oidc::is_absolute_http_url;
use monaca_store::{AccountRow, SocialConnectorRow, StoreError, TenantRow};
use monaca_types::{AccountId, EventId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration as TimeDuration, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::account::signed_in_account;
use crate::error::{ApiError, kinds};
use crate::management::authorize_admin;
use crate::session;
use crate::state::AppState;

/// How long a visitor may spend at the provider before the `state` is refused.
const SOCIAL_STATE_TTL_SECS: i64 = 600;

/// A hanging provider must not hold a request forever.
const PROVIDER_TIMEOUT_SECS: u64 = 10;

/// The body of `POST /v1/connectors` (§6.2).
#[derive(Debug, Deserialize)]
pub struct CreateConnectorBody {
    /// The slug the protocol and the page use, e.g. `github`.
    pub connector_id: String,
    /// The name the sign-in page shows.
    pub display_name: String,
    /// The provider's authorization endpoint.
    pub authorize_url: String,
    /// The provider's token endpoint.
    pub token_url: String,
    /// The provider's userinfo endpoint.
    pub userinfo_url: String,
    /// The client id registered at the provider.
    pub client_id: String,
    /// The client secret; sealed before it reaches the store.
    pub client_secret: String,
    /// Scopes to request; empty means none.
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// `POST /v1/connectors` — register a provider.
pub async fn create_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateConnectorBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let connector_id = check_connector_id(&body.connector_id)?;
    let display_name = body.display_name.trim();
    if display_name.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "display_name must not be empty",
        ));
    }
    for (name, url) in [
        ("authorize_url", body.authorize_url.trim()),
        ("token_url", body.token_url.trim()),
        ("userinfo_url", body.userinfo_url.trim()),
    ] {
        if !is_absolute_http_url(url) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("{name} must be an absolute http(s) URL"),
            ));
        }
    }
    if body.client_id.trim().is_empty() || body.client_secret.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "client_id and client_secret must not be empty",
        ));
    }
    let mut scopes: Vec<String> = Vec::new();
    for scope in &body.scopes {
        let scope = scope.trim();
        if scope.is_empty() || scope.contains(char::is_whitespace) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "each scope must be a single non-empty token",
            ));
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.to_owned());
        }
    }

    let sealed = seal(&state.tenant_dek(&tenant)?, body.client_secret.as_bytes())
        .map_err(ApiError::internal)?;
    let connector = state
        .store
        .create_social_connector(
            &tenant,
            &connector_id,
            display_name,
            body.authorize_url.trim(),
            body.token_url.trim(),
            body.userinfo_url.trim(),
            body.client_id.trim(),
            &sealed,
            &scopes,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "connector.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "connector_id": connector.connector_id }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append connector.created audit event");
    }

    Ok((StatusCode::CREATED, Json(connector_json(&connector))).into_response())
}

/// `GET /v1/connectors` — every connector the tenant configured.
pub async fn list_connectors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.social_connectors(&tenant).await?;
    let items: Vec<Value> = rows.iter().map(connector_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /v1/connectors/{connector}` — remove a connector and every identity that used it.
pub async fn delete_connector(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if !state
        .store
        .delete_social_connector(&tenant, &connector_id)
        .await?
    {
        return Err(ApiError::not_found("connector"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "connector.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "connector_id": connector_id }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append connector.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /t/{tenant}/connectors` — the public list the sign-in page renders.
///
/// Only the two fields a button needs are public: the URLs and the client secret stay inside the
/// tenant's configuration.
pub async fn list_public_connectors(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let rows = state.store.social_connectors(&tenant).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "connector_id": row.connector_id,
                "display_name": row.display_name,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// The query of `GET /t/{tenant}/connectors/{connector}/authorize`.
#[derive(Debug, Deserialize)]
pub struct ConnectorAuthorizeQuery {
    /// The interaction the provider is authenticating for.
    pub interaction: String,
}

/// `GET /t/{tenant}/connectors/{connector}/authorize` — send the browser to the provider.
pub async fn connector_authorize(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    Query(query): Query<ConnectorAuthorizeQuery>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let Some(connector) = state.store.social_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("connector"));
    };
    let interaction = state
        .peek_interaction(&query.interaction)
        .await
        .map_err(ApiError::Interaction)?;
    if interaction.tenant != tenant.slug {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the interaction belongs to another tenant",
        ));
    }

    let state_id = state
        .store
        .insert_social_state(
            &tenant,
            &connector_id,
            "sign_in",
            Some(&query.interaction),
            None,
            state.now() + TimeDuration::seconds(SOCIAL_STATE_TTL_SECS),
        )
        .await?;
    Ok(provider_redirect(
        &state,
        &connector,
        &state_id,
        &tenant.slug,
    ))
}

/// `GET /t/{tenant}/account/social/{connector}/authorize` — connect a provider from the account
/// centre. The caller is already signed in, so the callback attaches to that account.
pub async fn account_link_start(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant_slug, &headers).await?;
    let Some(connector) = state.store.social_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("connector"));
    };
    let state_id = state
        .store
        .insert_social_state(
            &tenant,
            &connector_id,
            "link",
            None,
            Some(account.id),
            state.now() + TimeDuration::seconds(SOCIAL_STATE_TTL_SECS),
        )
        .await?;
    Ok(provider_redirect(
        &state,
        &connector,
        &state_id,
        &tenant.slug,
    ))
}

/// `DELETE /t/{tenant}/account/social/{connector}` — disconnect a provider.
pub async fn unlink_account(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, account) = signed_in_account(&state, &tenant_slug, &headers).await?;
    if !state
        .store
        .unlink_social_identity(&tenant, account.account_id(), &connector_id)
        .await?
    {
        return Err(ApiError::not_found("connected account"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The query of the provider callback.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The single-use state this server minted.
    pub state: String,
    /// The authorization code, when the provider granted one.
    pub code: Option<String>,
    /// The provider's error code, when it refused.
    pub error: Option<String>,
}

/// `GET /t/{tenant}/connectors/{connector}/callback` — finish the provider round-trip.
pub async fn connector_callback(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let Ok(state_id) = Uuid::parse_str(&query.state) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state is malformed",
        ));
    };
    let Some(pending) = state.store.take_social_state(&tenant, state_id).await? else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state is unknown, expired or already used",
        ));
    };
    if pending.connector != connector_id {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state belongs to another connector",
        ));
    }
    let Some(connector) = state.store.social_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("connector"));
    };

    if let Some(error) = query.error.as_deref() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("the provider refused the request: {error}"),
        ));
    }
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the provider returned no code",
        ));
    };

    let secret = open(&state.tenant_dek(&tenant)?, &connector.client_secret_enc)
        .map_err(ApiError::internal)?;
    let secret = String::from_utf8(secret).map_err(ApiError::internal)?;
    let redirect_uri = callback_url(&state, &tenant.slug, &connector_id);
    let userinfo = exchange_code(
        &connector.connector_id,
        &connector.client_id,
        &connector.token_url,
        &connector.userinfo_url,
        &secret,
        code,
        &redirect_uri,
    )
    .await?;

    let Some(subject) = userinfo
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider returned no subject",
        ));
    };

    match pending.purpose.as_str() {
        "sign_in" => {
            let Some(iid) = pending.interaction_id.as_deref() else {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "the state carries no interaction",
                ));
            };
            let interaction = state
                .peek_interaction(iid)
                .await
                .map_err(ApiError::Interaction)?;
            let account = resolve_sign_in_account(
                &state,
                &tenant,
                &connector_id,
                subject,
                userinfo.get("email").and_then(Value::as_str),
                userinfo
                    .get("email_verified")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                userinfo.get("name").and_then(Value::as_str),
                &interaction.organization,
            )
            .await?;
            crate::protocol::finish_sign_in_browser(
                state,
                tenant,
                interaction,
                iid,
                &headers,
                account,
            )
            .await
        }
        "link" => {
            let Some(account_id) = pending.account_id else {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "the state carries no account",
                ));
            };
            let Some(session_id) = session::session_id(&headers) else {
                return Err(ApiError::problem(
                    kinds::UNAUTHORIZED,
                    "a signed-in session is required",
                ));
            };
            let Some(row) = state.store.session_by_id(&tenant, session_id).await? else {
                return Err(ApiError::problem(
                    kinds::UNAUTHORIZED,
                    "a signed-in session is required",
                ));
            };
            if !row.is_active(state.now()) || row.account_id != account_id {
                return Err(ApiError::problem(
                    kinds::UNAUTHORIZED,
                    "a signed-in session is required",
                ));
            }

            // Re-connecting the same provider account is a no-op, not a conflict.
            if let Some(existing) = state
                .store
                .social_identity_account(&tenant, &connector_id, subject)
                .await?
            {
                if existing.id == account_id {
                    return Ok(found(&account_page(&state, &tenant.slug, &connector_id)));
                }
                return Ok(found(&account_page_with_error(
                    &state,
                    &tenant.slug,
                    "taken",
                )));
            }
            match state
                .store
                .link_social_identity(
                    &tenant,
                    AccountId::from_uuid(account_id),
                    &connector_id,
                    subject,
                )
                .await
            {
                Ok(()) => Ok(found(&account_page(&state, &tenant.slug, &connector_id))),
                Err(StoreError::AlreadyExists { .. }) => Ok(found(&account_page_with_error(
                    &state,
                    &tenant.slug,
                    "already",
                ))),
                Err(other) => Err(other.into()),
            }
        }
        _ => Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state has an unknown purpose",
        )),
    }
}

/// Resolve a provider subject to the account it signs in.
///
/// A linked subject wins. Otherwise a *verified* email is the one thing that may attach an
/// unlinked provider to an existing account — the provider is asserting the address, which is the
/// same proof the email flows accept. A sign-in for an address that has no account creates one and
/// joins it to the interaction's org, so a first social sign-in is not a dead end. An unverified
/// address proves nothing and is refused.
#[allow(clippy::too_many_arguments)]
async fn resolve_sign_in_account(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &str,
    subject: &str,
    email: Option<&str>,
    email_verified: bool,
    name: Option<&str>,
    org_slug: &str,
) -> Result<AccountRow, ApiError> {
    if let Some(account) = state
        .store
        .social_identity_account(tenant, connector, subject)
        .await?
    {
        if account.state != "active" {
            return Err(invalid_credentials());
        }
        return Ok(account);
    }

    let Some(email) = email.filter(|_| email_verified) else {
        return Err(ApiError::problem(
            kinds::SOCIAL_UNLINKED,
            "this provider account is not connected to an account, and it asserted no verified email; sign in with your email and connect it from the account centre",
        ));
    };
    let email = crate::protocol::normalise_email(email)?;

    let (account, created) = match state.store.account_by_email(tenant, &email).await? {
        Some((account, _)) => (account, false),
        None => {
            let display = name
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| email.split('@').next().unwrap_or(&email))
                .to_owned();
            let account = state
                .store
                .create_account(
                    tenant,
                    AccountId::new(),
                    &email,
                    &display,
                    None,
                    false,
                    None,
                    None,
                )
                .await?;
            (account, true)
        }
    };
    if account.state != "active" {
        return Err(invalid_credentials());
    }
    if created {
        join_org_and_audit(state, tenant, &account, org_slug, connector).await?;
    }

    match state
        .store
        .link_social_identity(tenant, account.account_id(), connector, subject)
        .await
    {
        Ok(()) => Ok(account),
        Err(StoreError::AlreadyExists { .. }) => Err(ApiError::problem(
            kinds::SOCIAL_IDENTITY_TAKEN,
            "this provider account is already connected to another account",
        )),
        Err(other) => Err(other.into()),
    }
}

/// A first social sign-in creates the account; it joins the interaction's org the way a self
/// service registration does, and both chains record it (§8.1).
async fn join_org_and_audit(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account: &AccountRow,
    org_slug: &str,
    connector: &str,
) -> Result<(), ApiError> {
    let org = state.store.org_by_slug(tenant, org_slug).await?;
    let org_ctx = org.ctx(tenant);
    let mut tx = state.store.begin_org(&org_ctx).await?;
    state
        .store
        .org_member_add(&mut *tx, account.account_id(), "member")
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.member.added".into(),
        actor_chain: vec![AuditActor::account(account.account_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "org": org.slug,
            "role": "member",
            "self_service": true,
            "social_connector": connector,
        }),
    };
    state
        .store
        .audit_append(&mut *tx, &org_ctx.schema_name, &event)
        .await?;
    tx.commit().await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.created".into(),
        actor_chain: vec![AuditActor::account(account.account_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "email": account.primary_email,
            "self_service": true,
            "social_connector": connector,
        }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append account.created audit event");
    }
    Ok(())
}

/// Exchange the code and read the provider's userinfo document.
///
/// Shared with enterprise SSO: the round-trip is the ordinary OAuth2 code grant against a
/// confidential client, and the two connector kinds differ only in where the configuration lives.
pub(crate) async fn exchange_code(
    connector_id: &str,
    client_id: &str,
    token_url: &str,
    userinfo_url: &str,
    secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<Value, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(PROVIDER_TIMEOUT_SECS))
        .build()
        .map_err(ApiError::internal)?;

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", secret),
    ];
    let response = client
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            tracing::warn!(%err, connector = %connector_id, "provider token endpoint unreachable");
            ApiError::problem(
                kinds::SOCIAL_PROVIDER_ERROR,
                "the provider's token endpoint could not be reached",
            )
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            connector = %connector_id,
            "provider token exchange refused"
        );
        return Err(ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider rejected the code exchange",
        ));
    }
    let body: Value = response.json().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector_id, "provider token response is not JSON");
        ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider's token response is not usable",
        )
    })?;
    let Some(token) = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider returned no access token",
        ));
    };

    let response = client
        .get(userinfo_url)
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| {
            tracing::warn!(%err, connector = %connector_id, "provider userinfo endpoint unreachable");
            ApiError::problem(
                kinds::SOCIAL_PROVIDER_ERROR,
                "the provider's userinfo endpoint could not be reached",
            )
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            connector = %connector_id,
            "provider userinfo refused"
        );
        return Err(ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider refused the userinfo request",
        ));
    }
    response.json().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector_id, "provider userinfo is not JSON");
        ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider's userinfo document is not usable",
        )
    })
}

/// Where the provider sends the browser back to.
fn callback_url(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/connectors/{connector_id}/callback",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// Send the browser to the provider with the `state` this server just minted.
fn provider_redirect(
    state: &AppState,
    connector: &SocialConnectorRow,
    state_id: &Uuid,
    tenant_slug: &str,
) -> Response {
    let redirect_uri = callback_url(state, tenant_slug, &connector.connector_id);
    let scope = connector.scopes.join(" ");
    let state_value = state_id.to_string();
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", connector.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("state", state_value.as_str()),
    ];
    if !scope.is_empty() {
        params.push(("scope", scope.as_str()));
    }
    found(&crate::protocol::append_query(
        &connector.authorize_url,
        &params,
    ))
}

/// Where the account page lives, with the connector it just linked (or the error it hit).
fn account_page(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/account/{tenant_slug}?linked={connector_id}",
        state.config.auth_ui_url.trim_end_matches('/')
    )
}

fn account_page_with_error(state: &AppState, tenant_slug: &str, reason: &str) -> String {
    format!(
        "{}/account/{tenant_slug}?social_error={reason}",
        state.config.auth_ui_url.trim_end_matches('/')
    )
}

fn invalid_credentials() -> ApiError {
    ApiError::problem(kinds::INVALID_CREDENTIALS, "this account cannot sign in")
}

/// A `302`. A header that cannot carry the URL is an internal error, never a silent success.
pub(crate) fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        Err(err) => ApiError::internal(err).into_response(),
    }
}

/// The connector's public shape — never the sealed secret.
fn connector_json(row: &SocialConnectorRow) -> Value {
    json!({
        "connector_id": row.connector_id,
        "display_name": row.display_name,
        "authorize_url": row.authorize_url,
        "token_url": row.token_url,
        "userinfo_url": row.userinfo_url,
        "client_id": row.client_id,
        "scopes": row.scopes,
        "created_at": row.created_at.format(&Rfc3339).unwrap_or_default(),
    })
}

/// The slug grammar: lowercase, starts with a letter or digit, 2–32 characters.
pub(crate) fn check_connector_id(raw: &str) -> Result<String, ApiError> {
    let value = raw.trim().to_ascii_lowercase();
    let mut chars = value.chars();
    let valid = match chars.next() {
        Some(first) => first.is_ascii_lowercase() || first.is_ascii_digit(),
        None => false,
    } && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    if !valid || !(2..=32).contains(&value.len()) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "connector_id must be 2-32 lowercase letters, digits or hyphens",
        ));
    }
    Ok(value)
}
