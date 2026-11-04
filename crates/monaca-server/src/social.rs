//! Social (OAuth2/OIDC) connectors — `docs/contracts/m0.md` §6.1.
//!
//! A connector is tenant configuration. `provider` names a built-in mapping (`github`, `google`)
//! whose endpoints, scopes and userinfo field names are fixed here; `generic` keeps the original
//! tenant-supplied URLs and OIDC-shaped userinfo contract. The client secret is sealed with the
//! tenant DEK and never persisted in plaintext.
//!
//! Two flows share the callback:
//!
//! - **sign-in** starts from the sign-in page with an interaction id; the callback resolves the
//!   provider subject to an account (or asks the page to confirm a link) and hands the interaction
//!   to the same completion path a password uses, so MFA and consent are not reimplemented here.
//! - **link** starts from the account centre while already signed in; the callback attaches the
//!   provider subject to that account and returns to the account page.
//!
//! The `state` parameter is stored, single-use and short-lived. Built-in providers also mint a
//! PKCE verifier (S256); Google additionally mints and checks an OIDC nonce in the id_token that
//! arrives with the token response. The provider access token is used for the userinfo call only
//! and is never written to the database.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{
    decode_unverified, encode_base64url, generate_challenge, seal, verify_rs256_jws,
};
use monaca_oidc::is_absolute_http_url;
use monaca_store::{AccountRow, SocialConnectorRow, StoreError, TenantRow};
use monaca_types::{AccountId, EventId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::account::signed_in_account;
use crate::error::{ApiError, kinds};
use crate::management::authorize_admin;
use crate::schemas::{ConnectorList, ConnectorView};
use crate::session;
use crate::state::AppState;

/// How long a visitor may spend at the provider before the `state` is refused.
const SOCIAL_STATE_TTL_SECS: i64 = 600;

/// How long a confirm-link prompt may stay open.
const SOCIAL_LINK_TTL_SECS: i64 = 600;

/// A hanging provider must not hold a request forever.
const PROVIDER_TIMEOUT_SECS: u64 = 10;

/// GitHub's email list, the only place that marks an address primary and verified.
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";

/// Google accepts both the `https://` and the bare issuer in its ID tokens.
const GOOGLE_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];

/// An ID token older than this is refused even if its `exp` is still ahead: the code exchange
/// happens seconds after the provider minted it, and the state itself expires in ten minutes.
const GOOGLE_ID_TOKEN_MAX_AGE_SECS: i64 = 600;

/// Binds the one-time `state` to the browser that started the flow, so a callback URL copied to
/// another browser cannot complete the interaction (login CSRF).
const SOCIAL_STATE_COOKIE: &str = "monaca_social_state";

/// The built-in endpoint, scope and nonce mapping for a provider.
struct ProviderPreset {
    authorize_url: &'static str,
    token_url: &'static str,
    userinfo_url: &'static str,
    scopes: &'static [&'static str],
    nonce: bool,
}

/// The providers whose protocol this server implements itself.
fn provider_preset(provider: &str) -> Option<ProviderPreset> {
    match provider {
        "github" => Some(ProviderPreset {
            authorize_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            userinfo_url: "https://api.github.com/user",
            scopes: &["read:user", "user:email"],
            nonce: false,
        }),
        "google" => Some(ProviderPreset {
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
            scopes: &["openid", "email", "profile"],
            nonce: true,
        }),
        _ => None,
    }
}

/// The policy values §6.2 accepts.
const LINK_POLICIES: &[&str] = &[
    "auto_link_verified_email",
    "confirm_link",
    "create_new_only",
];

/// A built-in provider's endpoints, or the dev/CI mock base that replaces them.
fn preset_urls(
    state: &AppState,
    provider: &str,
    preset: &ProviderPreset,
) -> (String, String, String) {
    match state.config.social_provider_base_url.as_deref() {
        Some(base) => (
            format!("{}/{provider}/authorize", base.trim_end_matches('/')),
            format!("{}/{provider}/token", base.trim_end_matches('/')),
            format!("{}/{provider}/userinfo", base.trim_end_matches('/')),
        ),
        None => (
            preset.authorize_url.to_owned(),
            preset.token_url.to_owned(),
            preset.userinfo_url.to_owned(),
        ),
    }
}

/// GitHub's email list at the real host, or the dev/CI mock's sibling path.
fn github_emails_url(state: &AppState) -> String {
    match state.config.social_provider_base_url.as_deref() {
        Some(base) => format!("{}/github/emails", base.trim_end_matches('/')),
        None => GITHUB_EMAILS_URL.to_owned(),
    }
}

/// The body of `POST /v1/connectors` (§6.2).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateConnectorBody {
    /// The slug the protocol and the page use, e.g. `github`.
    pub connector_id: String,
    /// `generic` | `github` | `google`; defaults to `generic`, the pre-existing behaviour.
    #[serde(default)]
    pub provider: Option<String>,
    /// The name the sign-in page shows.
    pub display_name: String,
    /// `auto_link_verified_email` | `confirm_link` | `create_new_only`.
    #[serde(default)]
    pub link_policy: Option<String>,
    /// Whether the connector is offered immediately.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// The provider's authorization endpoint; required for `generic`.
    pub authorize_url: Option<String>,
    /// The provider's token endpoint; required for `generic`.
    pub token_url: Option<String>,
    /// The provider's userinfo endpoint; required for `generic`.
    pub userinfo_url: Option<String>,
    /// The client id registered at the provider.
    pub client_id: String,
    /// The client secret; sealed before it reaches the store.
    pub client_secret: String,
    /// Scopes to request; built-in providers own their scopes and ignore this.
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// `POST /v1/connectors` — register a provider.
#[utoipa::path(
    post,
    path = "/v1/connectors",
    tag = "management",
    summary = "Create a social connector",
    request_body = CreateConnectorBody,
    responses(
        (status = 201, description = "The created connector without its secret.", body = ConnectorView),
        (status = 400, description = "A field is invalid."),
        (status = 409, description = "The connector id is already in use.")
    )
)]
pub async fn create_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateConnectorBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let connector_id = check_connector_id(&body.connector_id)?;
    let provider = check_provider(body.provider.as_deref())?;
    let link_policy = check_link_policy(body.link_policy.as_deref())?;
    let display_name = body.display_name.trim();
    if display_name.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "display_name must not be empty",
        ));
    }
    if body.client_id.trim().is_empty() || body.client_secret.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "client_id and client_secret must not be empty",
        ));
    }

    let (authorize_url, token_url, userinfo_url, scopes) = match provider_preset(provider) {
        Some(preset) => {
            let (authorize, token, userinfo) = preset_urls(&state, provider, &preset);
            (
                authorize,
                token,
                userinfo,
                preset
                    .scopes
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect(),
            )
        }
        None => {
            let authorize = required_url("authorize_url", body.authorize_url.as_deref())?;
            let token = required_url("token_url", body.token_url.as_deref())?;
            let userinfo = required_url("userinfo_url", body.userinfo_url.as_deref())?;
            (authorize, token, userinfo, normalise_scopes(&body.scopes)?)
        }
    };

    let sealed = seal(&state.tenant_dek(&tenant)?, body.client_secret.as_bytes())
        .map_err(ApiError::internal)?;
    let connector = state
        .store
        .create_social_connector(
            &tenant,
            &connector_id,
            provider,
            display_name,
            body.enabled.unwrap_or(true),
            link_policy,
            &authorize_url,
            &token_url,
            &userinfo_url,
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
        payload: json!({
            "connector_id": connector.connector_id,
            "provider": connector.provider,
            "link_policy": connector.link_policy,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append connector.created audit event");
    }

    Ok((StatusCode::CREATED, Json(connector_json(&connector))).into_response())
}

/// `GET /v1/connectors` — every connector the tenant configured.
#[utoipa::path(
    get,
    path = "/v1/connectors",
    tag = "management",
    summary = "List social connectors",
    responses((status = 200, description = "The connectors, without secrets.", body = ConnectorList))
)]
pub async fn list_connectors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ConnectorList>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.social_connectors(&tenant).await?;
    let items: Vec<ConnectorView> = rows.iter().map(connector_json).collect();
    Ok(Json(ConnectorList { items, next: None }))
}

/// The body of `PATCH /v1/connectors/{connector}` (§6.2).
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct UpdateConnectorBody {
    /// The name the sign-in page shows.
    pub display_name: Option<String>,
    /// The client id; omitted keeps it.
    pub client_id: Option<String>,
    /// The client secret; omitted keeps the sealed value, an empty string is refused.
    pub client_secret: Option<String>,
    /// Scopes; generic connectors only.
    pub scopes: Option<Vec<String>>,
    /// Whether the connector is offered publicly.
    pub enabled: Option<bool>,
    /// `auto_link_verified_email` | `confirm_link` | `create_new_only`.
    pub link_policy: Option<String>,
}

impl UpdateConnectorBody {
    fn is_empty(&self) -> bool {
        self.display_name.is_none()
            && self.client_id.is_none()
            && self.client_secret.is_none()
            && self.scopes.is_none()
            && self.enabled.is_none()
            && self.link_policy.is_none()
    }
}

/// `PATCH /v1/connectors/{connector}` — change the writable half of a connector.
#[utoipa::path(
    patch,
    path = "/v1/connectors/{connector}",
    tag = "management",
    summary = "Update a social connector",
    params(("connector" = String, Path, description = "The connector id.")),
    request_body = UpdateConnectorBody,
    responses(
        (status = 200, description = "The updated connector without its secret.", body = ConnectorView),
        (status = 400, description = "The patch is empty or a value is invalid."),
        (status = 404, description = "No such connector.")
    )
)]
pub async fn update_connector(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateConnectorBody>,
) -> Result<Json<ConnectorView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if body.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the patch must name at least one field",
        ));
    }
    let Some(current) = state.store.social_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("connector"));
    };
    let display_name = match body.display_name.as_deref() {
        Some(value) if value.trim().is_empty() => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "display_name must not be empty",
            ));
        }
        Some(value) => Some(value.trim()),
        None => None,
    };
    let client_id = match body.client_id.as_deref() {
        Some(value) if value.trim().is_empty() => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "client_id must not be empty",
            ));
        }
        Some(value) => Some(value.trim()),
        None => None,
    };
    if body
        .client_secret
        .as_deref()
        .is_some_and(|value| value.is_empty())
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "client_secret must not be empty",
        ));
    }
    if provider_preset(&current.provider).is_some() && body.scopes.is_some() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "a built-in provider owns its scopes",
        ));
    }
    let link_policy = match body.link_policy.as_deref() {
        Some(value) => Some(check_link_policy(Some(value))?),
        None => None,
    };
    let scopes = match body.scopes.as_deref() {
        Some(value) => Some(normalise_scopes(value)?),
        None => None,
    };
    let sealed = match body.client_secret.as_deref() {
        Some(secret) => {
            Some(seal(&state.tenant_dek(&tenant)?, secret.as_bytes()).map_err(ApiError::internal)?)
        }
        None => None,
    };
    let Some(connector) = state
        .store
        .update_social_connector(
            &tenant,
            &connector_id,
            display_name,
            client_id,
            sealed.as_deref(),
            scopes.as_deref(),
            body.enabled,
            link_policy,
        )
        .await?
    else {
        return Err(ApiError::not_found("connector"));
    };

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "connector.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "connector_id": connector.connector_id,
            "provider": connector.provider,
            "enabled": connector.enabled,
            "link_policy": connector.link_policy,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append connector.updated audit event");
    }

    Ok(Json(connector_json(&connector)))
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
/// Only the fields a button needs are public: the URLs, the policy and the client secret stay
/// inside the tenant's configuration. Disabled connectors are omitted entirely.
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
        .filter(|row| row.enabled)
        .map(|row| {
            json!({
                "connector_id": row.connector_id,
                "display_name": row.display_name,
                "provider": row.provider,
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
    if !connector.enabled {
        return Err(ApiError::not_found("connector"));
    }
    let interaction = state
        .peek_interaction(&tenant, &query.interaction)
        .await
        .map_err(ApiError::Interaction)?;
    if interaction.tenant != tenant.slug {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the interaction belongs to another tenant",
        ));
    }

    let pending = PendingProvider::mint(&state, &tenant, &connector)?;
    let state_id = state
        .store
        .insert_social_state(
            &tenant,
            &connector_id,
            "sign_in",
            Some(&query.interaction),
            None,
            pending.verifier_enc.as_deref(),
            pending.nonce.as_deref(),
            state.now() + TimeDuration::seconds(SOCIAL_STATE_TTL_SECS),
        )
        .await?;
    Ok(provider_redirect(
        &state,
        &connector,
        &state_id,
        pending.challenge.as_deref(),
        pending.nonce.as_deref(),
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
    if !connector.enabled {
        return Err(ApiError::not_found("connector"));
    }
    let pending = PendingProvider::mint(&state, &tenant, &connector)?;
    let state_id = state
        .store
        .insert_social_state(
            &tenant,
            &connector_id,
            "link",
            None,
            Some(account.id),
            pending.verifier_enc.as_deref(),
            pending.nonce.as_deref(),
            state.now() + TimeDuration::seconds(SOCIAL_STATE_TTL_SECS),
        )
        .await?;
    Ok(provider_redirect(
        &state,
        &connector,
        &state_id,
        pending.challenge.as_deref(),
        pending.nonce.as_deref(),
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
    audit_identity(
        &state,
        &tenant,
        account.account_id(),
        "social_identity.unlinked",
        &connector_id,
        None,
        None,
    )
    .await;
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
        audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state is malformed",
        ));
    };
    // The state is stored server-side, but that alone does not prove this browser started the
    // flow: a callback URL copied to another browser must also carry the cookie minted at start.
    let cookie_state = state_cookie(&headers).and_then(|raw| Uuid::parse_str(&raw).ok());
    if cookie_state != Some(state_id) {
        audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state does not belong to this browser",
        ));
    }
    let Some(pending) = state.store.take_social_state(&tenant, state_id).await? else {
        audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state is unknown, expired or already used",
        ));
    };
    if pending.connector != connector_id {
        audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state belongs to another connector",
        ));
    }
    let Some(connector) = state.store.social_connector(&tenant, &connector_id).await? else {
        audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
        return Err(ApiError::not_found("connector"));
    };
    if !connector.enabled {
        audit_failed(&state, &tenant, &connector_id, "connector_disabled").await;
        return Err(ApiError::not_found("connector"));
    }

    if let Some(error) = query.error.as_deref() {
        audit_failed(&state, &tenant, &connector_id, "provider_error").await;
        tracing::warn!(connector = %connector_id, error = %error, "provider refused the request");
        return Err(ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider refused the request",
        ));
    }
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        audit_failed(&state, &tenant, &connector_id, "provider_error").await;
        return Err(ApiError::problem(
            kinds::SOCIAL_PROVIDER_ERROR,
            "the provider returned no code",
        ));
    };

    let verifier = match pending.code_verifier_enc.as_deref() {
        Some(sealed) => {
            let bytes = state
                .open_tenant(&tenant, sealed)
                .map_err(ApiError::internal)?;
            Some(String::from_utf8(bytes).map_err(ApiError::internal)?)
        }
        None => None,
    };
    let user = match exchange_and_read(
        &connector,
        &state,
        &tenant,
        code,
        &callback_url(&state, &tenant.slug, &connector_id),
        verifier.as_deref(),
        pending.nonce.as_deref(),
    )
    .await
    {
        Ok(user) => user,
        Err(err) => {
            audit_failed(&state, &tenant, &connector_id, "provider_error").await;
            return Err(err);
        }
    };

    match pending.purpose.as_str() {
        "sign_in" => {
            let Some(iid) = pending.interaction_id.as_deref() else {
                audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "the state carries no interaction",
                ));
            };
            let interaction = match state.peek_interaction(&tenant, iid).await {
                Ok(interaction) => interaction,
                Err(err) => {
                    audit_failed(&state, &tenant, &connector_id, "state_invalid").await;
                    return Err(ApiError::Interaction(err));
                }
            };
            match resolve_sign_in_account(
                &state,
                &tenant,
                &connector,
                &user,
                &interaction.organization,
            )
            .await
            {
                Ok(SocialResolution::SignedIn { account, created }) => {
                    audit_succeeded(&state, &tenant, &connector, &account, &user, created, false)
                        .await;
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
                Ok(SocialResolution::LinkRequired { account, email }) => {
                    let token = state
                        .store
                        .insert_social_link_request(
                            &tenant,
                            &connector_id,
                            &user.subject,
                            &email,
                            account.id,
                            iid,
                            state.now() + TimeDuration::seconds(SOCIAL_LINK_TTL_SECS),
                        )
                        .await?;
                    Ok(found(&confirm_location(&state, &tenant.slug, iid, &token)))
                }
                Err(err) => {
                    let reason = match &err {
                        ApiError::Problem(problem)
                            if problem.monaca_error_code == kinds::SOCIAL_UNLINKED.code() =>
                        {
                            "unverified_email"
                        }
                        ApiError::Problem(problem)
                            if problem.monaca_error_code == kinds::SOCIAL_EMAIL_TAKEN.code()
                                || problem.monaca_error_code
                                    == kinds::SOCIAL_IDENTITY_TAKEN.code() =>
                        {
                            "link_conflict"
                        }
                        ApiError::Problem(problem)
                            if problem.monaca_error_code == kinds::INVALID_CREDENTIALS.code() =>
                        {
                            "account_disabled"
                        }
                        _ => "provider_error",
                    };
                    audit_failed(&state, &tenant, &connector_id, reason).await;
                    Err(err)
                }
            }
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
                .social_identity_account(&tenant, &connector_id, &user.subject)
                .await?
            {
                if existing.id == account_id {
                    return Ok(found(&account_page(&state, &tenant.slug, &connector_id)));
                }
                audit_failed(&state, &tenant, &connector_id, "link_conflict").await;
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
                    &user.subject,
                    user.email.as_deref(),
                )
                .await
            {
                Ok(()) => {
                    audit_identity(
                        &state,
                        &tenant,
                        AccountId::from_uuid(account_id),
                        "social_identity.linked",
                        &connector_id,
                        Some(&user.subject),
                        user.email.as_deref(),
                    )
                    .await;
                    Ok(found(&account_page(&state, &tenant.slug, &connector_id)))
                }
                Err(StoreError::AlreadyExists { .. }) => {
                    audit_failed(&state, &tenant, &connector_id, "link_conflict").await;
                    Ok(found(&account_page_with_error(
                        &state,
                        &tenant.slug,
                        "already",
                    )))
                }
                Err(other) => Err(other.into()),
            }
        }
        _ => Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state has an unknown purpose",
        )),
    }
}

/// The query token of a confirm-link prompt.
#[derive(Debug, Deserialize)]
pub struct ConfirmLinkPath {
    /// The tenant slug.
    pub tenant: String,
    /// The opaque token minted by the callback.
    pub token: String,
}

/// `GET /t/{tenant}/social/link/{token}` — what the hosted page asks before confirming.
pub async fn social_link_details(
    State(state): State<Arc<AppState>>,
    Path(path): Path<ConfirmLinkPath>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&path.tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let token = parse_link_token(&path.token)?;
    let Some(pending) = state.store.social_link_request(&tenant, token).await? else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the confirmation is unknown, expired or already used",
        ));
    };
    let Some(connector) = state
        .store
        .social_connector(&tenant, &pending.connector)
        .await?
    else {
        return Err(ApiError::not_found("connector"));
    };
    if !connector.enabled {
        return Err(ApiError::not_found("connector"));
    }
    Ok(Json(json!({
        "connector_id": connector.connector_id,
        "display_name": connector.display_name,
        "provider": connector.provider,
        "email": pending.email,
        "expires_at": pending.expires_at.format(&Rfc3339).unwrap_or_default(),
    })))
}

/// `POST /t/{tenant}/social/link/{token}/confirm` — link the identity and finish the sign-in.
pub async fn confirm_social_link(
    State(state): State<Arc<AppState>>,
    Path(path): Path<ConfirmLinkPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&path.tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let token = parse_link_token(&path.token)?;
    let Some(pending) = state.store.take_social_link_request(&tenant, token).await? else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the confirmation is unknown, expired or already used",
        ));
    };
    let Some(connector) = state
        .store
        .social_connector(&tenant, &pending.connector)
        .await?
    else {
        return Err(ApiError::not_found("connector"));
    };
    if !connector.enabled {
        audit_failed(&state, &tenant, &pending.connector, "connector_disabled").await;
        return Err(ApiError::not_found("connector"));
    }
    let interaction = state
        .peek_interaction(&tenant, &pending.interaction_id)
        .await
        .map_err(ApiError::Interaction)?;
    if interaction.tenant != tenant.slug {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the interaction belongs to another tenant",
        ));
    }
    let account = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(pending.account_id))
        .await?
        .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "account is gone"))?;
    if account.state != "active" {
        audit_failed(&state, &tenant, &pending.connector, "account_disabled").await;
        return Err(invalid_credentials());
    }
    match state
        .store
        .link_social_identity(
            &tenant,
            account.account_id(),
            &pending.connector,
            &pending.subject,
            Some(&pending.email),
        )
        .await
    {
        Ok(()) => {}
        Err(StoreError::AlreadyExists { .. }) => {
            audit_failed(&state, &tenant, &pending.connector, "link_conflict").await;
            return Err(ApiError::problem(
                kinds::SOCIAL_IDENTITY_TAKEN,
                "this provider account is already connected to another account",
            ));
        }
        Err(other) => return Err(other.into()),
    }
    audit_identity(
        &state,
        &tenant,
        account.account_id(),
        "social_identity.linked",
        &pending.connector,
        Some(&pending.subject),
        Some(&pending.email),
    )
    .await;
    let user = SocialUser {
        subject: pending.subject.clone(),
        email: Some(pending.email.clone()),
        email_verified: true,
        name: None,
    };
    audit_succeeded(&state, &tenant, &connector, &account, &user, false, true).await;
    crate::protocol::finish_sign_in(
        state,
        tenant,
        interaction,
        &pending.interaction_id,
        &headers,
        account,
    )
    .await
}

/// A provider account's identity, normalised across the built-in mappings.
struct SocialUser {
    subject: String,
    email: Option<String>,
    email_verified: bool,
    name: Option<String>,
}

/// The result of resolving a provider identity to a Monaca account.
enum SocialResolution {
    SignedIn { account: AccountRow, created: bool },
    LinkRequired { account: AccountRow, email: String },
}

/// Resolve a provider subject to the account it signs in, or ask for a link confirmation.
///
/// A linked subject always wins. An unlinked subject needs a verified address. The connector's
/// policy then decides whether that address may attach to an existing account:
/// `auto_link_verified_email` binds silently, `confirm_link` pauses on a page, and
/// `create_new_only` refuses because Monaca keeps one account per address.
async fn resolve_sign_in_account(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &SocialConnectorRow,
    user: &SocialUser,
    org_slug: &str,
) -> Result<SocialResolution, ApiError> {
    if let Some(account) = state
        .store
        .social_identity_account(tenant, &connector.connector_id, &user.subject)
        .await?
    {
        if account.state != "active" {
            return Err(invalid_credentials());
        }
        return Ok(SocialResolution::SignedIn {
            account,
            created: false,
        });
    }

    let Some(email) = user
        .email
        .as_deref()
        .filter(|_| user.email_verified)
        .map(crate::protocol::normalise_email)
        .transpose()?
    else {
        return Err(ApiError::problem(
            kinds::SOCIAL_UNLINKED,
            "this provider account is not connected to an account, and it asserted no verified email; sign in with your email and connect it from the account centre",
        ));
    };

    let existing = state.store.account_by_email(tenant, &email).await?;
    match connector.link_policy.as_str() {
        "confirm_link" => {
            if let Some((account, _)) = existing {
                if account.state != "active" {
                    return Err(invalid_credentials());
                }
                return Ok(SocialResolution::LinkRequired { account, email });
            }
        }
        "create_new_only" => {
            if existing.is_some() {
                return Err(ApiError::problem(
                    kinds::SOCIAL_EMAIL_TAKEN,
                    "an account with this email already exists and this connector does not link automatically",
                ));
            }
        }
        _ => {}
    }

    let (account, created) = match existing {
        Some((account, _)) => (account, false),
        None => {
            let display = user
                .name
                .as_deref()
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
        join_org_and_audit(state, tenant, &account, org_slug, &connector.connector_id).await?;
    }

    match state
        .store
        .link_social_identity(
            tenant,
            account.account_id(),
            &connector.connector_id,
            &user.subject,
            Some(&email),
        )
        .await
    {
        Ok(()) => {
            audit_identity(
                state,
                tenant,
                account.account_id(),
                "social_identity.linked",
                &connector.connector_id,
                Some(&user.subject),
                Some(&email),
            )
            .await;
            Ok(SocialResolution::SignedIn { account, created })
        }
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

/// The PKCE/nonce material a start request mints.
struct PendingProvider {
    verifier_enc: Option<Vec<u8>>,
    challenge: Option<String>,
    nonce: Option<String>,
}

impl PendingProvider {
    fn mint(
        state: &AppState,
        tenant: &TenantRow,
        connector: &SocialConnectorRow,
    ) -> Result<Self, ApiError> {
        // Only the built-in mappings are known to accept PKCE and to return an id_token. A
        // generic connector keeps the original bare code exchange.
        let preset = provider_preset(&connector.provider);
        let verifier = preset
            .as_ref()
            .map(|_| encode_base64url(&generate_challenge()));
        let verifier_enc = match verifier.as_deref() {
            Some(value) => Some(
                seal(&state.tenant_dek(tenant)?, value.as_bytes()).map_err(ApiError::internal)?,
            ),
            None => None,
        };
        let challenge = verifier
            .as_deref()
            .map(|value| encode_base64url(&Sha256::digest(value.as_bytes())));
        let nonce = preset
            .as_ref()
            .filter(|preset| preset.nonce)
            .map(|_| encode_base64url(&generate_challenge()));
        Ok(Self {
            verifier_enc,
            challenge,
            nonce,
        })
    }
}

/// Exchange the code and read the provider's userinfo document.
///
/// The access token lives only in this call. Provider failures are logged by status and connector
/// only; their response bodies never reach the client or the log.
async fn exchange_and_read(
    connector: &SocialConnectorRow,
    state: &AppState,
    tenant: &TenantRow,
    code: &str,
    redirect_uri: &str,
    verifier: Option<&str>,
    nonce: Option<&str>,
) -> Result<SocialUser, ApiError> {
    let secret = state
        .open_tenant(tenant, &connector.client_secret_enc)
        .map_err(ApiError::internal)?;
    let secret = String::from_utf8(secret).map_err(ApiError::internal)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(PROVIDER_TIMEOUT_SECS))
        .build()
        .map_err(ApiError::internal)?;

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", connector.client_id.as_str()),
        ("client_secret", secret.as_str()),
    ];
    if let Some(verifier) = verifier {
        form.push(("code_verifier", verifier));
    }
    let mut request = client
        .post(&connector.token_url)
        .header(header::ACCEPT, "application/json")
        .form(&form);
    if connector.provider == "github" {
        // GitHub's API requires a User-Agent and answers JSON only when asked.
        request = request.header(header::USER_AGENT, "monaca");
    }
    let response = request.send().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector.connector_id, "provider token endpoint unreachable");
        provider_error("the provider's token endpoint could not be reached")
    })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            connector = %connector.connector_id,
            "provider token exchange refused"
        );
        return Err(provider_error("the provider rejected the code exchange"));
    }
    let body: Value = response.json().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector.connector_id, "provider token response is not JSON");
        provider_error("the provider's token response is not usable")
    })?;
    let Some(access_token) = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(provider_error("the provider returned no access token"));
    };

    // Google's identity comes from the signed ID token, not from userinfo. The token is verified
    // against Google's JWKS before any claim is used; the nonce binds it to the state this server
    // minted. GitHub and generic connectors keep the userinfo path below.
    if connector.provider == "google" {
        let Some(expected) = nonce else {
            return Err(provider_error("the state carries no nonce"));
        };
        let Some(id_token) = body.get("id_token").and_then(Value::as_str) else {
            return Err(provider_error("the provider returned no id_token"));
        };
        let claims = google_id_token_claims(state, connector, id_token, expected).await?;
        return google_user(&claims);
    }

    let mut userinfo = client
        .get(&connector.userinfo_url)
        .bearer_auth(access_token)
        .header(header::ACCEPT, "application/json");
    if connector.provider == "github" {
        userinfo = userinfo.header(header::USER_AGENT, "monaca");
    }
    let response = userinfo.send().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector.connector_id, "provider userinfo endpoint unreachable");
        provider_error("the provider's userinfo endpoint could not be reached")
    })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            connector = %connector.connector_id,
            "provider userinfo refused"
        );
        return Err(provider_error("the provider refused the userinfo request"));
    }
    let document: Value = response.json().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector.connector_id, "provider userinfo is not JSON");
        provider_error("the provider's userinfo document is not usable")
    })?;

    match connector.provider.as_str() {
        "github" => {
            let emails_url = github_emails_url(state);
            github_user(&client, access_token, &document, &emails_url).await
        }
        _ => Ok(SocialUser {
            subject: required_subject(&document)?,
            email: document
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_owned),
            email_verified: document
                .get("email_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            name: document
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }),
    }
}

/// GitHub's `/user` document plus its separate primary-and-verified email list.
async fn github_user(
    client: &reqwest::Client,
    access_token: &str,
    document: &Value,
    emails_url: &str,
) -> Result<SocialUser, ApiError> {
    let subject = document
        .get("id")
        .and_then(|id| {
            id.as_i64()
                .map(|value| value.to_string())
                .or_else(|| id.as_str().map(str::to_owned))
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| provider_error("the provider returned no subject"))?;
    let name = document
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| document.get("login").and_then(Value::as_str))
        .map(str::to_owned);

    let response = client
        .get(emails_url)
        .bearer_auth(access_token)
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "monaca")
        .send()
        .await
        .map_err(|err| {
            tracing::warn!(%err, "GitHub email list unreachable");
            provider_error("GitHub's email list could not be reached")
        })?;
    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "GitHub email list refused");
        return Err(provider_error(
            "GitHub refused the email list; check the user:email scope",
        ));
    }
    let emails: Value = response.json().await.map_err(|err| {
        tracing::warn!(%err, "GitHub email list is not JSON");
        provider_error("GitHub's email list is not usable")
    })?;
    let verified = emails
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|row| {
                row.get("primary").and_then(Value::as_bool).unwrap_or(false)
                    && row
                        .get("verified")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
            })
        })
        .and_then(|row| row.get("email").and_then(Value::as_str))
        .map(str::to_owned);
    Ok(SocialUser {
        subject,
        // GitHub proves the address through `primary && verified`; without that pair it asserts
        // nothing, even when `/user` carries a public email.
        email_verified: verified.is_some(),
        email: verified,
        name,
    })
}

/// Verify Google's ID token and enforce the claims that bind it to this exchange.
///
/// The signature is checked against Google's JWKS with an RS256-only whitelist. An unknown `kid`
/// forces one refresh, which is how a provider key rotation becomes visible without waiting for
/// the hour-long cache TTL. `iss`, `aud`, `iat`, `exp` (checked by the verifier with 60 s leeway)
/// and `nonce` are all required; `email_verified` is carried into [`SocialUser`] and decides
/// whether an unlinked identity may attach to an existing account.
async fn google_id_token_claims(
    state: &AppState,
    connector: &SocialConnectorRow,
    id_token: &str,
    expected_nonce: &str,
) -> Result<Value, ApiError> {
    let (header, _) = decode_unverified(id_token).map_err(|err| {
        tracing::warn!(%err, connector = %connector.connector_id, "Google id_token is malformed");
        provider_error("the provider's identity token is not valid")
    })?;
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| {
            tracing::warn!(connector = %connector.connector_id, "Google id_token has no kid");
            provider_error("the provider's identity token is not valid")
        })?;

    let mut keys = state.google_jwks(false).await?;
    if !keys
        .iter()
        .any(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
    {
        tracing::info!(connector = %connector.connector_id, %kid, "refreshing Google JWKS for an unknown kid");
        keys = state.google_jwks(true).await?;
    }

    let claims = verify_rs256_jws(id_token, &keys, Some("JWT")).map_err(|err| {
        tracing::warn!(%err, connector = %connector.connector_id, "Google id_token did not verify");
        provider_error("the provider's identity token is not valid")
    })?;

    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !GOOGLE_ISSUERS.contains(&issuer) {
        tracing::warn!(connector = %connector.connector_id, "Google id_token issuer mismatch");
        return Err(provider_error("the provider's identity token is not valid"));
    }
    let audience = &claims["aud"];
    let audience_matches = match audience {
        Value::String(value) => value == &connector.client_id,
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str() == Some(connector.client_id.as_str())),
        _ => false,
    };
    if !audience_matches {
        tracing::warn!(connector = %connector.connector_id, "Google id_token audience mismatch");
        return Err(provider_error("the provider's identity token is not valid"));
    }

    let now = state.now().unix_timestamp();
    let issued_at = claims.get("iat").and_then(Value::as_i64).ok_or_else(|| {
        tracing::warn!(connector = %connector.connector_id, "Google id_token has no iat");
        provider_error("the provider's identity token is not valid")
    })?;
    if issued_at > now + 60 || issued_at < now - GOOGLE_ID_TOKEN_MAX_AGE_SECS {
        tracing::warn!(connector = %connector.connector_id, "Google id_token iat is outside the window");
        return Err(provider_error("the provider's identity token is not valid"));
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
        tracing::warn!(connector = %connector.connector_id, "Google id_token nonce mismatch");
        return Err(provider_error("the provider's nonce did not match"));
    }

    Ok(claims)
}

/// Google's identity fields from the verified ID token. `email_verified` is only true when Google
/// asserted the boolean `true`; a linked subject still signs in, but an unlinked one needs a
/// verified address before it can attach to an account.
fn google_user(claims: &Value) -> Result<SocialUser, ApiError> {
    Ok(SocialUser {
        subject: required_subject(claims)?,
        email: claims
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned),
        email_verified: claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        name: claims
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn required_subject(document: &Value) -> Result<String, ApiError> {
    document
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| provider_error("the provider returned no subject"))
}

fn provider_error(detail: &str) -> ApiError {
    ApiError::problem(kinds::SOCIAL_PROVIDER_ERROR, detail)
}

/// The enterprise SSO variant: the ordinary OAuth2 code grant plus an OIDC-shaped userinfo read.
/// SSO keeps its own connector table, so this stays independent of the social presets.
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
        .header(header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            tracing::warn!(%err, connector = %connector_id, "provider token endpoint unreachable");
            provider_error("the provider's token endpoint could not be reached")
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            connector = %connector_id,
            "provider token exchange refused"
        );
        return Err(provider_error("the provider rejected the code exchange"));
    }
    let body: Value = response.json().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector_id, "provider token response is not JSON");
        provider_error("the provider's token response is not usable")
    })?;
    let Some(token) = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(provider_error("the provider returned no access token"));
    };

    let response = client
        .get(userinfo_url)
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| {
            tracing::warn!(%err, connector = %connector_id, "provider userinfo endpoint unreachable");
            provider_error("the provider's userinfo endpoint could not be reached")
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            connector = %connector_id,
            "provider userinfo refused"
        );
        return Err(provider_error("the provider refused the userinfo request"));
    }
    response.json().await.map_err(|err| {
        tracing::warn!(%err, connector = %connector_id, "provider userinfo is not JSON");
        provider_error("the provider's userinfo document is not usable")
    })
}

/// Where the provider sends the browser back to.
fn callback_url(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/connectors/{connector_id}/callback",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// The social-state cookie from the request, if present.
fn state_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name == SOCIAL_STATE_COOKIE {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Send the browser to the provider with the `state` this server just minted.
fn provider_redirect(
    state: &AppState,
    connector: &SocialConnectorRow,
    state_id: &Uuid,
    challenge: Option<&str>,
    nonce: Option<&str>,
    tenant_slug: &str,
) -> Response {
    let redirect_uri = callback_url(state, tenant_slug, &connector.connector_id);
    let scope = connector.scopes.join(" ");
    let state_value = state_id.to_string();
    let mut params = vec![
        ("response_type", "code".to_owned()),
        ("client_id", connector.client_id.clone()),
        ("redirect_uri", redirect_uri),
        ("state", state_value.clone()),
    ];
    if !scope.is_empty() {
        params.push(("scope", scope));
    }
    if let Some(challenge) = challenge {
        params.push(("code_challenge", challenge.to_owned()));
        params.push(("code_challenge_method", "S256".to_owned()));
    }
    if let Some(nonce) = nonce {
        params.push(("nonce", nonce.to_owned()));
    }
    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    let mut response = found(&crate::protocol::append_query(
        &connector.authorize_url,
        &borrowed,
    ));
    let secure = if crate::session::secure_origin(&state.config) {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{SOCIAL_STATE_COOKIE}={state_value}; Path=/t/{tenant_slug}/connectors/{}; HttpOnly; SameSite=Lax; Max-Age={SOCIAL_STATE_TTL_SECS}{secure}",
        connector.connector_id
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// Where the hosted page asks the visitor to confirm a link.
fn confirm_location(state: &AppState, tenant_slug: &str, iid: &str, token: &Uuid) -> String {
    format!(
        "{}/sign-in?tenant={}&interaction={}&social_link={}",
        state.config.auth_ui_url.trim_end_matches('/'),
        tenant_slug,
        iid,
        token
    )
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

fn parse_link_token(raw: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw).map_err(|_| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "the confirmation token is malformed",
        )
    })
}

/// A `302`. A header that cannot carry the URL is an internal error, never a silent success.
pub(crate) fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        Err(err) => ApiError::internal(err).into_response(),
    }
}

/// The connector's management shape — never the sealed secret.
fn connector_json(row: &SocialConnectorRow) -> ConnectorView {
    ConnectorView {
        connector_id: row.connector_id.clone(),
        provider: row.provider.clone(),
        display_name: row.display_name.clone(),
        enabled: row.enabled,
        link_policy: row.link_policy.clone(),
        authorize_url: row.authorize_url.clone(),
        token_url: row.token_url.clone(),
        userinfo_url: row.userinfo_url.clone(),
        client_id: row.client_id.clone(),
        scopes: row.scopes.clone(),
        created_at: row.created_at.format(&Rfc3339).unwrap_or_default(),
    }
}

/// A successful social sign-in on the tenant chain; the account is the subject.
async fn audit_succeeded(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &SocialConnectorRow,
    account: &AccountRow,
    user: &SocialUser,
    created: bool,
    confirmed: bool,
) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "social_sign_in.succeeded".into(),
        actor_chain: vec![AuditActor::account(account.account_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "connector_id": connector.connector_id,
            "provider": connector.provider,
            "email": user.email,
            "email_verified": user.email_verified,
            "new_account": created,
            "confirmed": confirmed,
            "link_policy": connector.link_policy,
        }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append social_sign_in.succeeded audit event");
    }
}

/// A failed social sign-in on the tenant chain; no account is known, so the subject id is null.
async fn audit_failed(state: &Arc<AppState>, tenant: &TenantRow, connector_id: &str, reason: &str) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "social_sign_in.failed".into(),
        actor_chain: vec![AuditActor::tenant(tenant.tenant_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: None,
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({ "connector_id": connector_id, "reason": reason }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append social_sign_in.failed audit event");
    }
}

/// A link/unlink change on the tenant chain.
#[allow(clippy::too_many_arguments)]
async fn audit_identity(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account_id: AccountId,
    action: &str,
    connector_id: &str,
    subject: Option<&str>,
    email: Option<&str>,
) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: action.into(),
        actor_chain: vec![AuditActor::account(account_id)],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "connector_id": connector_id,
            "subject": subject,
            "email": email,
        }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, action, "could not append social identity audit event");
    }
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

/// `generic` | `github` | `google`; absent keeps the pre-existing generic behaviour.
fn check_provider(raw: Option<&str>) -> Result<&'static str, ApiError> {
    match raw.map(str::trim) {
        None | Some("") | Some("generic") => Ok("generic"),
        Some("github") => Ok("github"),
        Some("google") => Ok("google"),
        Some(_) => Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "provider must be generic, github or google",
        )),
    }
}

/// The three binding policies §6.1 accepts.
fn check_link_policy(raw: Option<&str>) -> Result<&'static str, ApiError> {
    let value = raw.map(str::trim).unwrap_or("confirm_link");
    if LINK_POLICIES.contains(&value) {
        return Ok(match value {
            "auto_link_verified_email" => "auto_link_verified_email",
            "create_new_only" => "create_new_only",
            _ => "confirm_link",
        });
    }
    Err(ApiError::problem(
        kinds::INVALID_REQUEST,
        "link_policy must be auto_link_verified_email, confirm_link or create_new_only",
    ))
}

fn required_url(name: &str, raw: Option<&str>) -> Result<String, ApiError> {
    let url = raw.map(str::trim).unwrap_or_default();
    if !is_absolute_http_url(url) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("{name} must be an absolute http(s) URL"),
        ));
    }
    Ok(url.to_owned())
}

fn normalise_scopes(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut scopes: Vec<String> = Vec::new();
    for scope in raw {
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
    Ok(scopes)
}
