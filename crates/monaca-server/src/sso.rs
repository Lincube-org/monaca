//! Enterprise SSO (OIDC federation) — `docs/contracts/m0.md` §6.1 and §6.2.
//!
//! A tenant-level SSO connector points at an identity provider's OIDC endpoints and owns one or
//! more email domains. The sign-in page asks which connector owns an address's domain and sends
//! that address's browser to the provider; the callback asserts the address, creates the account
//! if this is its first sign-in, and hands the interaction to the same completion path a password
//! uses — so MFA, consent, organization membership and the SSO session are not reimplemented here.
//!
//! The security property this module enforces is domain ownership: a provider may only sign in
//! addresses at the domains it was configured for. A verified email outside those domains is
//! refused even though the provider vouched for it, because otherwise any tenant-level IdP could
//! mint accounts at another organization's domain.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::seal;
use monaca_oidc::is_absolute_http_url;
use monaca_store::{AccountRow, SsoConnectorRow, TenantRow};
use monaca_types::{AccountId, EventId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, authorize_admin_read};
use crate::orgs::normalise_domain;
use crate::social::{check_connector_id, exchange_code, found};
use crate::state::AppState;

/// How long a visitor may spend at the identity provider before the `state` is refused.
const SSO_STATE_TTL_SECS: i64 = 600;

/// The scopes an OIDC sign-in needs when the administrator names none.
const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];

/// The body of `POST /v1/sso-connectors` (§6.2).
#[derive(Debug, Deserialize)]
pub struct CreateSsoConnectorBody {
    /// The slug the protocol and the page use, e.g. `okta`.
    pub connector_id: String,
    /// The name the sign-in page shows.
    pub display_name: String,
    /// The provider's issuer identifier.
    pub issuer: String,
    /// The provider's authorization endpoint.
    pub authorize_url: String,
    /// The provider's token endpoint.
    pub token_url: String,
    /// The provider's userinfo endpoint.
    pub userinfo_url: String,
    /// The client id the tenant registered at the provider.
    pub client_id: String,
    /// The client secret; sealed before it reaches the store.
    pub client_secret: String,
    /// Scopes to request; empty means `openid profile email`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The email domains whose sign-ins route to this provider.
    pub email_domains: Vec<String>,
}

/// `POST /v1/sso-connectors` — register an identity provider.
pub async fn create_sso_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateSsoConnectorBody>,
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
        ("issuer", body.issuer.trim()),
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
    if scopes.is_empty() {
        scopes = DEFAULT_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect();
    }

    let email_domains = normalise_domains(&body.email_domains)?;

    let sealed = seal(&state.tenant_dek(&tenant)?, body.client_secret.as_bytes())
        .map_err(ApiError::internal)?;
    let connector = state
        .store
        .create_sso_connector(
            &tenant,
            &connector_id,
            display_name,
            body.issuer.trim(),
            body.authorize_url.trim(),
            body.token_url.trim(),
            body.userinfo_url.trim(),
            body.client_id.trim(),
            &sealed,
            &scopes,
            &email_domains,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sso_connector.created".into(),
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
            "email_domains": connector.email_domains,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sso_connector.created audit event");
    }

    Ok((StatusCode::CREATED, Json(sso_connector_json(&connector))).into_response())
}

/// `GET /v1/sso-connectors` — every identity provider the tenant configured.
pub async fn list_sso_connectors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let rows = state.store.sso_connectors(&tenant).await?;
    let items: Vec<Value> = rows.iter().map(sso_connector_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /v1/sso-connectors/{connector}` — remove the provider and its pending states.
pub async fn delete_sso_connector(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if !state
        .store
        .delete_sso_connector(&tenant, &connector_id)
        .await?
    {
        return Err(ApiError::not_found("SSO connector"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sso_connector.deleted".into(),
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
        tracing::warn!(%err, "could not append sso_connector.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// The query of the public list — optionally narrowed to one email's domain.
#[derive(Debug, Deserialize)]
pub struct SsoLookupQuery {
    /// The address the visitor entered; when present, only the connector that owns its domain is
    /// returned.
    pub email: Option<String>,
}

/// `GET /t/{tenant}/sso-connectors` — the public routing lookup of §6.1.
///
/// The page needs a display name and a identifier, never endpoints or domains: the browser is sent
/// through `/t/{tenant}/sso/{connector}/authorize`, and which domains a tenant federates is not
/// something an unauthenticated caller should learn by listing.
pub async fn list_public_sso_connectors(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    Query(query): Query<SsoLookupQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    // The switch hides SSO from the hosted page: an empty lookup is a fallback to the ordinary
    // forms, not an error, so a disabled method cannot block a visitor who could sign in another way.
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .single_sign_on_enabled
    {
        return Ok(Json(json!({ "items": [], "next": null })));
    }

    let rows = match query.email.as_deref().and_then(email_domain) {
        Some(domain) => state
            .store
            .sso_connector_for_domain(&tenant, &domain)
            .await?
            .into_iter()
            .collect(),
        None if query.email.is_none() => state.store.sso_connectors(&tenant).await?,
        None => Vec::new(),
    };
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

/// The query of `GET /t/{tenant}/sso/{connector}/authorize`.
#[derive(Debug, Deserialize)]
pub struct SsoAuthorizeQuery {
    /// The interaction the provider is authenticating for.
    pub interaction: String,
}

/// `GET /t/{tenant}/sso/{connector}/authorize` — send the browser to the identity provider.
pub async fn sso_authorize(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    Query(query): Query<SsoAuthorizeQuery>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .single_sign_on_enabled
    {
        return Err(ApiError::problem(
            kinds::SSO_DISABLED,
            "single sign-on is disabled for this tenant",
        ));
    }
    let Some(connector) = state.store.sso_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("SSO connector"));
    };
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

    let state_id = state
        .store
        .insert_sso_state(
            &tenant,
            &connector_id,
            &query.interaction,
            state.now() + Duration::seconds(SSO_STATE_TTL_SECS),
        )
        .await?;
    Ok(provider_redirect(
        &state,
        &connector,
        &state_id,
        &tenant.slug,
    ))
}

/// `GET /t/{tenant}/sso/{connector}/callback` — finish the identity-provider round-trip.
pub async fn sso_callback(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<crate::social::CallbackQuery>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    // A provider round-trip that started before the switch was turned off must not complete a
    // sign-in through a method the tenant has since disabled.
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .single_sign_on_enabled
    {
        return Err(ApiError::problem(
            kinds::SSO_DISABLED,
            "single sign-on is disabled for this tenant",
        ));
    }
    let Ok(state_id) = Uuid::parse_str(&query.state) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the state is malformed",
        ));
    };
    let Some(pending) = state.store.take_sso_state(&tenant, state_id).await? else {
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
    let Some(connector) = state.store.sso_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("SSO connector"));
    };

    if let Some(error) = query.error.as_deref() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("the identity provider refused the request: {error}"),
        ));
    }
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the identity provider returned no code",
        ));
    };

    let secret = state
        .open_tenant(&tenant, &connector.client_secret_enc)
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

    // The provider's word is the whole authentication: without a verified address there is nothing
    // to resolve an account by, and the address must be at a domain this connector owns.
    let email = match userinfo.get("email").and_then(Value::as_str) {
        Some(email) if userinfo.get("email_verified").and_then(Value::as_bool) == Some(true) => {
            crate::protocol::normalise_email(email)?
        }
        _ => {
            return Err(ApiError::problem(
                kinds::SSO_EMAIL_UNVERIFIED,
                "the identity provider asserted no verified email address",
            ));
        }
    };
    let Some(domain) = email_domain(&email) else {
        return Err(ApiError::problem(
            kinds::SSO_DOMAIN_MISMATCH,
            "the asserted address is outside this connector's domains",
        ));
    };
    if !connector.email_domains.iter().any(|owned| owned == &domain) {
        return Err(ApiError::problem(
            kinds::SSO_DOMAIN_MISMATCH,
            "the asserted address is outside this connector's domains",
        ));
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

    let (account, created) = match state.store.account_by_email(&tenant, &email).await? {
        Some((account, _)) => (account, false),
        None => {
            let display = userinfo
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| email.split('@').next().unwrap_or(&email))
                .to_owned();
            let account = state
                .store
                .create_account(
                    &tenant,
                    AccountId::new(),
                    &email,
                    &display,
                    None,
                    false,
                    None,
                    None,
                    None,
                )
                .await?;
            (account, true)
        }
    };
    if account.state != "active" {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "this account cannot sign in",
        ));
    }
    if created {
        join_org_and_audit(
            &state,
            &tenant,
            &account,
            &interaction.organization,
            &connector.connector_id,
        )
        .await?;
    }

    crate::protocol::finish_sign_in_browser(
        state,
        tenant,
        interaction,
        &pending.interaction_id,
        &headers,
        account,
    )
    .await
}

/// A first SSO sign-in creates the account; it joins the interaction's org the way a self-service
/// registration does, and both chains record the connector (§8.1).
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
            "sso_connector": connector,
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
            "sso_connector": connector,
        }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append account.created audit event");
    }
    Ok(())
}

/// Where the identity provider sends the browser back to.
fn callback_url(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/sso/{connector_id}/callback",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// Send the browser to the identity provider with the `state` this server just minted.
fn provider_redirect(
    state: &AppState,
    connector: &SsoConnectorRow,
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

/// The lowercased domain of an email address, or `None` when it has no usable `@domain`.
fn email_domain(email: &str) -> Option<String> {
    let (_, domain) = email.rsplit_once('@')?;
    let domain = domain.trim().to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// Trim, lowercase and de-duplicate the configured domains, rejecting a connector that owns none.
fn normalise_domains(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut domains: Vec<String> = Vec::new();
    for domain in raw {
        let Some(domain) = normalise_domain(domain) else {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("`{domain}` is not a DNS name of lowercase letters, digits, `-` and `.`"),
            ));
        };
        if !domains.iter().any(|existing| existing == &domain) {
            domains.push(domain);
        }
    }
    if domains.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "email_domains must name at least one domain",
        ));
    }
    Ok(domains)
}

/// The connector's management shape — never the sealed secret.
fn sso_connector_json(row: &SsoConnectorRow) -> Value {
    json!({
        "connector_id": row.connector_id,
        "display_name": row.display_name,
        "issuer": row.issuer,
        "authorize_url": row.authorize_url,
        "token_url": row.token_url,
        "userinfo_url": row.userinfo_url,
        "client_id": row.client_id,
        "scopes": row.scopes,
        "email_domains": row.email_domains,
        "created_at": row.created_at.format(&Rfc3339).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_domain_of_an_address_is_lowercased() {
        assert_eq!(
            email_domain("User@Corp.Example"),
            Some("corp.example".to_owned())
        );
        assert_eq!(email_domain("no-at-sign"), None);
        assert_eq!(email_domain("user@"), None);
    }

    #[test]
    fn domains_are_normalised_and_deduplicated() {
        let domains = normalise_domains(&[
            " Corp.Example ".to_owned(),
            "corp.example".to_owned(),
            "sub.corp.example".to_owned(),
        ])
        .expect("valid domains");
        assert_eq!(domains, vec!["corp.example", "sub.corp.example"]);
    }

    #[test]
    fn a_connector_without_domains_or_with_junk_is_rejected() {
        assert!(normalise_domains(&[]).is_err());
        for bad in ["", "not a domain", "@corp", "corp."] {
            assert!(
                normalise_domains(&[bad.to_owned()]).is_err(),
                "{bad} must be rejected"
            );
        }
    }
}
