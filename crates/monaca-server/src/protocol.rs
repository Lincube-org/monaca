//! The protocol endpoints — §6.1 and §7.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use monaca_agent::{Permission, attenuate};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{
    DEFAULT_CODE_DIGITS, assertion_user_verified, generate_challenge, generate_numeric_code,
    generate_totp_secret, hash_password, hash_secret, normalize_backup_code, open, seal,
    totp_base32, totp_otpauth_url, verify_assertion, verify_password, verify_secret, verify_totp,
};
use monaca_oidc::{
    AccessTokenClaims, AuthorizeParams, DiscoveryDocument, DpopProof, GrantType, IdTokenClaims,
    Interaction, TokenErrorCode, TokenForm, TokenRequest, at_hash, scope_subset, verify_pkce_s256,
};
use monaca_store::{AccountRow, OrgRow, PasskeyRow, SignInExperienceRow, TenantRow, topics};
use monaca_types::{
    AccountId, AgentId, ClientId, EventId, GrantId, InteractionId, OrgId, OrgInvitationId, TypedId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::client_ip::ClientIp;
use crate::error::{ApiError, kinds};
use crate::session;
use crate::state::AppState;

/// `GET /t/{tenant}/.well-known/openid-configuration` and the RFC 8414 form.
pub async fn discovery(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::problem(kinds::NOT_FOUND, "tenant is not active"));
    }
    Ok(Json(DiscoveryDocument::new(tenant.issuer).to_json()))
}

/// The optional application whose CSS should override the tenant's.
#[derive(Debug, Deserialize)]
pub struct SignInExperienceQuery {
    /// The protocol `client_id` from the authorize request.
    pub client_id: Option<String>,
}

/// `GET /t/{tenant}/sign-in-experience` — the hosted switches the page applies before rendering.
///
/// Public like the connector list: the sign-in page must know which forms to offer before anyone
/// is signed in, and these switches disclose nothing about accounts. An optional `client_id`
/// selects the application's CSS when it has one; the tenant's branding stays the fallback.
pub async fn sign_in_experience(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    Query(query): Query<SignInExperienceQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::problem(kinds::NOT_FOUND, "tenant is not active"));
    }
    let experience = state.store.sign_in_experience(&tenant).await?;
    let mut branding = state.store.branding(&tenant).await?;
    if let Some(client_id) = query
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && let Some(client) = state.store.client_by_client_id(&tenant, client_id).await?
        && let Some(css) = client.custom_css.filter(|css| !css.trim().is_empty())
    {
        branding.custom_css = Some(css);
    }
    Ok(Json(json!({
        "sign_up_enabled": experience.sign_up_enabled,
        "password_sign_in_enabled": experience.password_sign_in_enabled,
        "email_code_sign_in_enabled": experience.email_code_sign_in_enabled,
        "passkey_sign_in_enabled": experience.passkey_sign_in_enabled,
        "single_sign_on_enabled": experience.single_sign_on_enabled,
        "mfa_enabled": experience.mfa_enabled,
        "mfa_policy": experience.mfa_policy,
        "mfa_trusted_devices_enabled": experience.mfa_trusted_devices_enabled,
        "mfa_trusted_device_ttl_days": experience.mfa_trusted_device_ttl_days,
        "password_min_length": experience.password_min_length,
        "password_min_character_types": experience.password_min_character_types,
        "password_reject_user_info": experience.password_reject_user_info,
        "password_reject_repetition_and_sequence":
            experience.password_reject_repetition_and_sequence,
        "password_rejected_words": experience.password_rejected_words,
        "session_ttl_secs": experience.session_ttl_secs,
        "refresh_token_ttl_secs": experience.refresh_token_ttl_secs,
        "sign_up_identifiers": experience.sign_up_identifiers,
        "sign_up_email_verification_required": experience.sign_up_email_verification_required,
        "username_case_sensitive": experience.username_case_sensitive,
        "username_min_length": experience.username_min_length,
        "username_max_length": experience.username_max_length,
        "username_allowed_punctuation": experience.username_allowed_punctuation,
        "username_allow_email_local_part": experience.username_allow_email_local_part,
        "username_preserve_case": experience.username_preserve_case,
        "username_reserved_words": experience.username_reserved_words,
        "sign_up_profile_fields": experience.sign_up_profile_fields,
        "captcha": crate::management::captcha_json(&experience, false),
        "branding": crate::management::branding_json(&branding),
    })))
}

/// `GET /t/{tenant}/.well-known/jwks.json`.
pub async fn jwks(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    let keys = state.jwks(&tenant).await?;
    let body =
        serde_json::to_vec(&json!({ "keys": keys })).map_err(|err| ApiError::internal(err))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

/// `GET /t/{tenant}/oauth2/authorize`.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    Query(mut params): Query<AuthorizeParams>,
    headers: HeaderMap,
    client_ip: ClientIp,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "authorize")
        .await?;
    let tenant = state.tenant(&tenant_slug).await?;

    // RFC 9126: a pushed request replaces the inline parameters entirely.
    let mut pushed_for: Option<Uuid> = None;
    if let Some(request_uri) = params
        .request_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let Some(row) = state
            .store
            .par_take(&tenant, &sha256_hex(request_uri))
            .await?
        else {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "request_uri is unknown or expired",
            ));
        };
        params = serde_json::from_value(row.params)
            .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "request_uri is malformed"))?;
        pushed_for = Some(row.client_id);
    }

    // The client and the redirect URI are checked before anything is validated, because an
    // unregistered redirect must produce an error page and never a redirect (§6.1).
    let client_id = params
        .client_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "`client_id` is required"))?;
    state
        .enforce_rate_limit(&tenant, "authorize", Some(client_id))
        .await?;
    let client = state
        .store
        .client_by_client_id(&tenant, client_id)
        .await?
        .ok_or_else(|| {
            ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("unknown client `{client_id}`"),
            )
        })?;

    // A pushed request may only be redeemed by the client that pushed it.
    if let Some(row_id) = pushed_for
        && client.id != row_id
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "request_uri belongs to another client",
        ));
    }

    let redirect_uri = params.redirect_uri.as_deref().unwrap_or_default();
    let registered = state.store.client_redirect_uris(&tenant, client.id).await?;
    if !registered.iter().any(|uri| uri == redirect_uri) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "redirect_uri is not registered for this client",
        ));
    }

    // From here on every failure is a redirect: the redirect URI is known to be safe.
    let state_value = params.state.clone().unwrap_or_default();
    let request = match params.validate() {
        Ok(request) => request,
        Err(err) => return Ok(redirect_error(redirect_uri, err.code(), &state_value)),
    };

    if !scope_subset(&request.scopes, &client.scopes) {
        return Ok(redirect_error(
            &request.redirect_uri,
            "invalid_scope",
            &request.state,
        ));
    }

    // A registered resource owns its scope namespace: a non-standard scope it does not define is
    // `invalid_scope`, exactly like a scope the client may not ask for. An unregistered resource
    // indicator keeps the pre-registry behaviour, because agent/MCP flows use resource URLs that
    // are not tenant configuration (§6.2 resources).
    if let Some(resource) = request.resource.as_deref()
        && let Some(row) = state
            .store
            .api_resource_by_identifier(&tenant, resource)
            .await?
    {
        let unknown = request.scopes.iter().any(|scope| {
            !matches!(
                scope.as_str(),
                "openid" | "profile" | "email" | "offline_access"
            ) && !row.scopes.iter().any(|known| known == scope)
        });
        if unknown {
            return Ok(redirect_error(
                &request.redirect_uri,
                "invalid_scope",
                &request.state,
            ));
        }
    }

    let org_slug = request
        .organization
        .clone()
        .unwrap_or_else(|| state.config.default_org.clone());
    let org = match state.store.org_by_slug(&tenant, &org_slug).await {
        Ok(org) => org,
        Err(_) => {
            return Ok(redirect_error(
                &request.redirect_uri,
                "invalid_request",
                &request.state,
            ));
        }
    };

    // The SSO cookie is the cross-application login state: a valid session means this authorize
    // request needs no interaction at all. `prompt=login` and `max_age` are the two ways a client
    // asks for a fresh authentication anyway (OpenID Connect Core §3.1.2.1).
    let now = state.now();
    let session = match session::session_id(&headers) {
        Some(id) => state.store.session_by_id(&tenant, id).await?,
        None => None,
    };
    let session = session
        .filter(|row| row.is_active(now))
        .filter(|_| !request.prompt.iter().any(|value| value == "login"))
        .filter(|row| match request.max_age {
            Some(max_age) => now - row.issued_at <= Duration::seconds(max_age),
            None => true,
        });

    let mut silent_approved = false;
    let mut silent_interaction: Option<String> = None;
    if let Some(session) = session {
        // A disabled account must not keep riding an old session.
        if let Some(account) = state
            .store
            .account_by_id(&tenant, AccountId::from_uuid(session.account_id))
            .await?
            .filter(|account| account.state == "active")
        {
            if request.requires_consent(client.is_third_party) {
                // A remembered grant lets a returning user through without the screen.
                // `prompt=consent` overrides it, and a first-party client never records one.
                let grant =
                    remember_consent(&state, &tenant, account.account_id(), client.id).await?;
                let approved = !request.forces_consent()
                    && client.is_third_party
                    && grant
                        .as_ref()
                        .is_some_and(|grant| consent_covers(grant, &request.scopes));
                if approved {
                    silent_approved = true;
                    silent_interaction = grant
                        .as_ref()
                        .and_then(|grant| grant.interaction_id.clone());
                }
                if !approved {
                    // `prompt=none` may not open a page; with a session but no recorded consent the
                    // only compliant answer is the `consent_required` error (OIDC Core §3.1.2.6).
                    if request.is_silent() {
                        return Ok(redirect_error(
                            &request.redirect_uri,
                            "consent_required",
                            &request.state,
                        ));
                    }
                    // Consent still has to be shown, but not the password form: record the session as
                    // this interaction's authentication, and let the page render its consent step.
                    let interaction =
                        build_interaction(&state, &tenant, &client, &request, &org, true);
                    state.put_interaction(&tenant, interaction.clone()).await?;
                    state
                        .mark_interaction_signed_in(
                            &tenant,
                            &interaction.interaction_id.to_string(),
                            account.id,
                            session.id,
                        )
                        .await
                        .map_err(ApiError::Interaction)?;
                    return Ok(found(&sign_in_location(&state, &tenant, &interaction)));
                }
            }

            let code = issue_code(
                &state,
                &tenant,
                client.id,
                account.id,
                org.id,
                &request.redirect_uri,
                &request.scopes,
                &request.code_challenge,
                request.nonce.as_deref(),
                request.resource.as_deref(),
                Some(session.id),
                request.dpop_jkt.as_deref(),
                session.issued_at,
                client.client_id.as_str(),
                true,
            )
            .await?;
            state.store.touch_session(&tenant, session.id, now).await?;
            if silent_approved {
                audit_consent_granted(
                    &state,
                    &tenant,
                    account.account_id(),
                    &client.client_id,
                    &client.name,
                    &request.scopes,
                    true,
                    "silent",
                    silent_interaction.as_deref(),
                )
                .await;
            }
            return Ok(found(&append_query(
                &request.redirect_uri,
                &[("code", code.as_str()), ("state", request.state.as_str())],
            )));
        }
    }

    // `prompt=none` without a usable session cannot be satisfied.
    if request.is_silent() {
        return Ok(redirect_error(
            &request.redirect_uri,
            "login_required",
            &request.state,
        ));
    }

    let consent_required = request.requires_consent(client.is_third_party);
    let interaction = build_interaction(&state, &tenant, &client, &request, &org, consent_required);
    let location = sign_in_location(&state, &tenant, &interaction);
    state.put_interaction(&tenant, interaction).await?;
    Ok(found(&location))
}

/// Capture the authorize request as an interaction the auth-ui can resolve.
fn build_interaction(
    state: &AppState,
    tenant: &TenantRow,
    client: &monaca_store::ClientRow,
    request: &monaca_oidc::AuthorizeRequest,
    org: &OrgRow,
    consent_required: bool,
) -> Interaction {
    Interaction {
        interaction_id: InteractionId::new(),
        tenant: tenant.slug.clone(),
        client_row_id: client.id,
        client_id: client.client_id.clone(),
        client_name: client.name.clone(),
        redirect_uri: request.redirect_uri.clone(),
        scopes: request.scopes.clone(),
        organization: org.slug.clone(),
        code_challenge: request.code_challenge.clone(),
        nonce: request.nonce.clone(),
        login_hint: request.login_hint.clone(),
        resource: request.resource.clone(),
        state: request.state.clone(),
        dpop_jkt: request.dpop_jkt.clone(),
        consent_required,
        consent_prompted: request.forces_consent(),
        expires_at: state.now() + Duration::seconds(state.config.interaction_ttl.as_secs() as i64),
    }
}

/// The account's *remembered* approval for a client, if any.
async fn remember_consent(
    state: &AppState,
    tenant: &TenantRow,
    account_id: AccountId,
    client_row_id: Uuid,
) -> Result<Option<monaca_store::ConsentRow>, ApiError> {
    Ok(state
        .store
        .consent(tenant, account_id, client_row_id)
        .await?)
}

/// Whether a remembered approval covers every requested scope.
fn consent_covers(grant: &monaca_store::ConsentRow, scopes: &[String]) -> bool {
    scopes
        .iter()
        .all(|scope| grant.scopes.iter().any(|approved| approved == scope))
}

/// The requested scopes a remembered grant does not cover yet.
fn consent_new_scopes(grant: Option<&monaca_store::ConsentRow>, scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .filter(|scope| {
            grant.is_none_or(|grant| !grant.scopes.iter().any(|approved| approved == *scope))
        })
        .cloned()
        .collect()
}

/// The remembered scopes plus the request, so a later request that names only a new scope
/// does not erase what was approved earlier.
fn merged_scopes(grant: Option<&monaca_store::ConsentRow>, scopes: &[String]) -> Vec<String> {
    let mut merged = grant.map(|grant| grant.scopes.clone()).unwrap_or_default();
    for scope in scopes {
        if !merged.contains(scope) {
            merged.push(scope.clone());
        }
    }
    merged
}

/// Where the auth-ui sign-in page lives for this interaction.
fn sign_in_location(state: &AppState, tenant: &TenantRow, interaction: &Interaction) -> String {
    format!(
        "{}/sign-in?tenant={}&interaction={}",
        state.config.auth_ui_url.trim_end_matches('/'),
        tenant.slug,
        interaction.interaction_id
    )
}

/// `GET /t/{tenant}/interaction/{iid}`.
pub async fn interaction_details(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let (interaction, signed_in) = state
        .peek_interaction_state(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    let pending = state
        .mfa_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    let mut body = interaction.to_public_json(signed_in.is_some());
    if interaction.consent_required {
        // A previously approved scope is not part of the incremental consent screen; before
        // sign-in there is no account, so the page shows the whole request.
        let scopes = match signed_in {
            Some(account_id) => {
                let tenant = state.tenant(&interaction.tenant).await?;
                let grant = remember_consent(
                    &state,
                    &tenant,
                    AccountId::from_uuid(account_id),
                    interaction.client_row_id,
                )
                .await?;
                consent_new_scopes(grant.as_ref(), &interaction.scopes)
            }
            None => interaction.scopes.clone(),
        };
        body["consent_scopes"] = json!(scopes);
    }
    body["mfa_required"] = json!(pending.is_some());
    // A mandatory policy parks the flow on an enrollment step instead; the page needs to know
    // which of the two it is rendering.
    let enrollment = state
        .mfa_enrollment_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    body["mfa_enrollment_required"] = json!(enrollment.is_some());
    // A reload resumes the second-factor step, so the page needs to know which factor forms to offer
    // without asking the account endpoint (which the browser may not be signed in to yet).
    let factors = match pending {
        Some(account_id) => {
            let tenant = state.tenant(&interaction.tenant).await?;
            mfa_factors(&state, &tenant, account_id).await?
        }
        None => Vec::new(),
    };
    body["mfa_factors"] = json!(factors);
    Ok(Json(body))
}

/// The factors a paused interaction may be completed with, in the order the page offers them.
///
/// `backup_code` is only listed when the account actually has unused codes: offering a form that
/// cannot succeed would be a dead end.
async fn mfa_factors(
    state: &AppState,
    tenant: &TenantRow,
    account_id: Uuid,
) -> Result<Vec<&'static str>, ApiError> {
    let account_id = AccountId::from_uuid(account_id);
    let mut factors = Vec::new();
    if state.store.totp_secret(tenant, account_id).await?.is_some() {
        factors.push("totp");
        if state.store.backup_code_count(tenant, account_id).await? > 0 {
            factors.push("backup_code");
        }
    }
    // A passkey is a second factor too, but only when one is actually enrolled: an empty list
    // would render a button that cannot work. It is offered without TOTP as well — an account that
    // chose passkeys as its only second factor has no authenticator app to fall back on.
    if !state.store.passkeys(tenant, account_id).await?.is_empty() {
        factors.push("passkey");
    }
    Ok(factors)
}

/// The sign-in body.
///
/// `identifier` is the account's email address or its username (§6.1); `email` is the older field
/// name and is still accepted so a client that predates usernames keeps working.
#[derive(Debug, Deserialize)]
pub struct SignInBody {
    /// Email address or username.
    pub identifier: Option<String>,
    /// The legacy email-only field, honoured when `identifier` is absent.
    pub email: Option<String>,
    /// The password.
    pub password: String,
    /// The CAPTCHA widget's token when the tenant gates password sign-in.
    pub captcha_token: Option<String>,
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in`.
pub async fn sign_in(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    Json(body): Json<SignInBody>,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let tenant = state.tenant(&tenant_slug).await?;
    let interaction = state
        .peek_interaction(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.password_sign_in_enabled {
        return Err(ApiError::problem(
            kinds::PASSWORD_SIGN_IN_DISABLED,
            "password sign-in is disabled for this tenant",
        ));
    }
    crate::captcha::enforce(
        &state,
        &tenant,
        &experience,
        crate::captcha::Flow::SignIn,
        body.captcha_token.as_deref(),
    )
    .await?;
    let org_slug = interaction.organization.clone();
    let org = state.store.org_by_slug(&tenant, &org_slug).await?;
    let org_ctx = org.ctx(&tenant);

    // An email address or a username; both are matched case-insensitively (§6.1).
    let identifier = body
        .identifier
        .as_deref()
        .or(body.email.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "`identifier` is required"))?;

    let account = state
        .store
        .account_by_identifier(&tenant, identifier, experience.username_case_sensitive)
        .await?;

    // Lockout is keyed by the identifier the attempt named, so a wrong password counts against
    // the account it was aimed at rather than the source address. Only a real, active account
    // owns a counter: an unknown address must not be able to create rows on request.
    let lockout_enabled = experience.login_lockout_threshold > 0;
    let account_can_lock = account
        .as_ref()
        .is_some_and(|(account, phc)| account.state == "active" && phc.is_some());
    let lock_key = identifier.to_lowercase();
    if lockout_enabled
        && account_can_lock
        && let Some(failure) = state.store.login_failure(&tenant, &lock_key).await?
    {
        match failure.locked_until {
            Some(until) if until > state.now() => {
                let event = sign_in_event(
                    state.now(),
                    &org_ctx.org_id,
                    AuditDecision::Deny,
                    identifier,
                    "account_locked",
                );
                if let Err(err) = state.audit_org(&org_ctx, &event).await {
                    tracing::warn!(%err, "could not append sign-in.failed audit event");
                }
                return Err(ApiError::problem(
                    kinds::ACCOUNT_LOCKED,
                    "too many failed sign-ins; try again later",
                ));
            }
            // An expired lock starts a fresh count instead of carrying the old total over.
            Some(_) => state.store.clear_login_failures(&tenant, &lock_key).await?,
            None => {}
        }
    }

    let authenticated = match account {
        Some((account, Some(phc))) if account.state == "active" => {
            match verify_password(body.password.clone(), phc, state.argon).await {
                Ok(()) => Some(account),
                Err(_) => None,
            }
        }
        // An unknown identifier and a wrong password must be indistinguishable (§6.1). The
        // verifier path above and this branch both end in the same response; the audit event is
        // what records which one happened, and it is only visible to the tenant's own admins.
        _ => None,
    };

    let Some(account) = authenticated else {
        if lockout_enabled && account_can_lock {
            state
                .store
                .record_login_failure(
                    &tenant,
                    &lock_key,
                    experience.login_lockout_threshold,
                    experience.login_lockout_duration_secs,
                )
                .await?;
        }
        let event = sign_in_event(
            state.now(),
            &org_ctx.org_id,
            AuditDecision::Deny,
            identifier,
            "invalid_credentials",
        );
        if let Err(err) = state.audit_org(&org_ctx, &event).await {
            tracing::warn!(%err, "could not append sign-in.failed audit event");
        }
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "identifier or password is incorrect",
        ));
    };

    if lockout_enabled && account_can_lock {
        state.store.clear_login_failures(&tenant, &lock_key).await?;
    }

    finish_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// Scopes every authenticated app may request without an RBAC role.
///
/// `monaca:admin` is governed by the account's tenant-admin flag rather than a role, so it is
/// exempt here too; every other client-registered scope must be granted by a role (§6.2).
const UNGOVERNED_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "offline_access",
    "monaca:admin",
];

/// Refuse a sign-in whose requested scopes exceed what the account's roles grant.
///
/// Tenant roles grant a scope everywhere; organization roles grant it only while signing into the
/// org whose role the account holds (§6.2).
async fn check_scope_grants(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account: &AccountRow,
    org: &OrgRow,
    scopes: &[String],
) -> Result<(), ApiError> {
    if scopes
        .iter()
        .all(|scope| UNGOVERNED_SCOPES.iter().any(|allowed| *allowed == scope))
    {
        return Ok(());
    }
    let roles = state
        .store
        .account_roles(tenant, account.account_id())
        .await?;
    let org_scopes = state
        .store
        .org_role_scopes(tenant, org.org_id(), account.account_id())
        .await?;
    if let Some(scope) = scopes.iter().find(|scope| {
        !UNGOVERNED_SCOPES.iter().any(|allowed| allowed == *scope)
            && !roles.iter().any(|role| {
                role.permissions
                    .iter()
                    .any(|permission| permission == *scope)
            })
            && !org_scopes.iter().any(|granted| granted == *scope)
    }) {
        return Err(ApiError::problem(
            kinds::INSUFFICIENT_SCOPE,
            format!("the account's roles do not grant `{scope}`"),
        ));
    }
    Ok(())
}

/// The tail every sign-in path shares: scope grants, second factor, membership check, SSO session,
/// consent pause or code mint.
///
/// Every primary proof — password, emailed code, a new account, a password reset — lands here, so
/// all four agree on cookies, consent and MFA. An account with an authenticator app is stopped
/// before anything is consumed: the interaction stays redeemable and the caller answers with the
/// challenge shape instead of a redirect (§6.1 `mfa`).
pub(crate) async fn finish_sign_in(
    state: Arc<AppState>,
    tenant: TenantRow,
    interaction: Interaction,
    iid: &str,
    headers: &HeaderMap,
    account: AccountRow,
) -> Result<Response, ApiError> {
    let org = state
        .store
        .org_by_slug(&tenant, &interaction.organization)
        .await?;
    check_scope_grants(&state, &tenant, &account, &org, &interaction.scopes).await?;

    // The tenant's policy decides what happens after the first factor. MFA switched off means an
    // enrolled authenticator is not demanded either — the administrator turned the step off.
    let experience = state.store.sign_in_experience(&tenant).await?;
    let satisfied = state
        .mfa_satisfied(&tenant, iid)
        .await
        .map_err(ApiError::Interaction)?;
    if experience.mfa_enabled && !satisfied {
        let factors = mfa_factors(&state, &tenant, account.id).await?;
        // The pause is driven by an authenticator app, as it always was: a passkey is offered as an
        // alternative second factor when one exists, but an account whose only credential is a
        // passkey already proved possession of it and is not asked for a second step.
        let challenge = factors.iter().any(|factor| *factor == "totp");
        if challenge {
            // A browser this account chose to remember skips the second factor until it is revoked
            // or expires (§6.1 `mfa`). A tenant that switches the policy off stops trusting every
            // cookie immediately, including one issued before the switch. The cookie is per tenant
            // and the row names the account, so a stale trust from another account does nothing.
            if experience.mfa_trusted_devices_enabled
                && let Some(token) = session::trusted_device_token(headers)
                && let Some(device) = state
                    .store
                    .trusted_device(&tenant, &hash_secret(&token))
                    .await?
                && device.account_id == account.id
            {
                state
                    .store
                    .touch_trusted_device(&tenant, device.id, state.now())
                    .await?;
                return complete_sign_in(state, tenant, interaction, iid, headers, account).await;
            }

            state
                .mark_mfa_pending(&tenant, iid, account.id)
                .await
                .map_err(ApiError::Interaction)?;
            return Ok(Json(json!({
                "mfa_required": true,
                "factors": factors,
            }))
            .into_response());
        }
        if experience.mfa_policy == "mandatory" && factors.is_empty() {
            // No factor is enrolled and the tenant requires one: the flow pauses on a setup step
            // instead of silently letting a weaker sign-in through.
            state
                .mark_mfa_enrollment(&tenant, iid, account.id)
                .await
                .map_err(ApiError::Interaction)?;
            return Ok(Json(json!({
                "mfa_enrollment_required": true,
                "factors": ["totp"],
            }))
            .into_response());
        }
    }
    complete_sign_in(state, tenant, interaction, iid, headers, account).await
}

/// The lowercased domain of an email address, or `None` when it has no usable `@domain`.
///
/// It only ever gates the just-in-time join of [`complete_sign_in`]: a malformed stored address
/// simply matches no registered domain.
fn email_domain(email: &str) -> Option<String> {
    let (_, domain) = email.rsplit_once('@')?;
    let domain = domain.trim().to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// Sign-in with every factor satisfied: membership check, SSO session, consent pause or code mint.
///
/// Sign-in is only *recorded* here when the client demands consent; otherwise the interaction is
/// consumed and the authorization code is minted.
async fn complete_sign_in(
    state: Arc<AppState>,
    tenant: TenantRow,
    interaction: Interaction,
    iid: &str,
    headers: &HeaderMap,
    account: AccountRow,
) -> Result<Response, ApiError> {
    let org_slug = interaction.organization.clone();
    let org = state.store.org_by_slug(&tenant, &org_slug).await?;
    let org_ctx = org.ctx(&tenant);

    // The account must be a member of the org the flow issues into. Two tenant-level rules can
    // admit a non-member (§6.2): a pending invitation naming the account's primary email (with the
    // role it carries), or a registered email domain (as `member`). The invitation is checked
    // first so an invited admin is not downgraded by a domain rule; both record the join on the
    // org chain, and the invitation also gets its own acceptance mark.
    let mut tx = state.store.begin_org(&org_ctx).await?;
    let role = state
        .store
        .org_member_role(&mut *tx, account.account_id())
        .await?;
    tx.rollback().await?;
    if role.is_none() {
        let email = account.primary_email.trim().to_ascii_lowercase();
        let invitation = state
            .store
            .pending_org_invitation(&tenant, org.org_id(), &email)
            .await?;
        let join_role = match &invitation {
            Some((_, invited_role)) => invited_role.clone(),
            None => {
                let admitted = match email_domain(&account.primary_email) {
                    Some(domain) => {
                        state
                            .store
                            .has_org_email_domain(&tenant, org.org_id(), &domain)
                            .await?
                    }
                    None => false,
                };
                if !admitted {
                    return Err(ApiError::problem(
                        kinds::INSUFFICIENT_SCOPE,
                        format!("account is not a member of `{org_slug}`"),
                    ));
                }
                "member".to_owned()
            }
        };

        let mut tx = state.store.begin_org(&org_ctx).await?;
        state
            .store
            .org_member_add(&mut *tx, account.account_id(), &join_role)
            .await?;
        let mut payload = json!({
            "org": org_slug,
            "role": join_role,
            "jit": invitation.is_none(),
        });
        if let Some((id, _)) = &invitation {
            payload["invitation"] = json!(OrgInvitationId::from_uuid(*id).to_typed_string());
        }
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
            payload,
        };
        state
            .store
            .audit_append(&mut *tx, &org_ctx.schema_name, &event)
            .await?;
        tx.commit().await?;

        // `tenant.organization_invitations` is outside the org role's privileges, so the mark is
        // a separate tenant-level write after the membership commits. A failure here leaves a
        // live invitation pointing at a member, which only the expiry cleans up — the join itself
        // is already correct, so this is a warning rather than a failed sign-in.
        if let Some((id, _)) = invitation
            && let Err(err) = state.store.accept_org_invitation(&tenant, id).await
        {
            tracing::warn!(%err, "could not mark the organization invitation accepted");
        }
    }

    // Establish (or reuse) the cross-application session before the code is minted, so the browser
    // leaves sign-in with the SSO cookie and the next application skips the password page. The
    // tenant's session lifetime is read here, so this is the one place the cookie and the row agree.
    let session_ttl_secs = (state
        .store
        .sign_in_experience(&tenant)
        .await?
        .session_ttl_secs
        .max(60) as u64)
        .min(state.config.session_ttl.as_secs());
    let session_id = establish_session(
        &state,
        &tenant,
        headers,
        &account,
        interaction.client_row_id,
        session_ttl_secs,
    )
    .await?;

    // A third-party client (or `prompt=consent`) pauses here: the page must ask the user to
    // approve the scopes before a code is minted. Sign-in is recorded but not consumed, so the
    // consent step can redeem it. An approval recorded earlier skips the screen unless
    // `prompt=consent` explicitly asked for it again.
    if interaction.consent_required {
        let grant = remember_consent(
            &state,
            &tenant,
            account.account_id(),
            interaction.client_row_id,
        )
        .await?;
        let approved = !interaction.consent_prompted
            && grant
                .as_ref()
                .is_some_and(|grant| consent_covers(grant, &interaction.scopes));
        if !approved {
            state
                .mark_interaction_signed_in(&tenant, iid, account.id, session_id)
                .await
                .map_err(ApiError::Interaction)?;
            let response = Json(json!({ "consent_required": true })).into_response();
            return Ok(with_session_cookie(
                response,
                session_id,
                session_ttl_secs,
                &state,
            ));
        }
    }

    // Consume only after authentication succeeds, so a typo does not burn the interaction.
    let interaction = state
        .consume_interaction(&tenant, iid)
        .await
        .map_err(ApiError::Interaction)?;

    let response = approve_interaction(
        state.clone(),
        tenant,
        interaction,
        account,
        Some(session_id),
        false,
        true,
        Some("silent"),
        None,
    )
    .await?;
    Ok(with_session_cookie(
        response,
        session_id,
        session_ttl_secs,
        &state,
    ))
}

/// The browser-facing variant of [`finish_sign_in`].
///
/// A social callback is a browser navigation, so it cannot answer the JSON shape the page expects.
/// A completed flow becomes a `302` to the client's `redirect_to`; a paused flow (second factor or
/// consent) becomes a `302` back to the sign-in page, where the page renders the remaining step.
/// The session cookie `finish_sign_in` set is carried over to whichever redirect is returned.
pub(crate) async fn finish_sign_in_browser(
    state: Arc<AppState>,
    tenant: TenantRow,
    interaction: Interaction,
    iid: &str,
    headers: &HeaderMap,
    account: AccountRow,
) -> Result<Response, ApiError> {
    let paused_at = sign_in_location(&state, &tenant, &interaction);
    let response = finish_sign_in(state, tenant, interaction, iid, headers, account).await?;
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(ApiError::internal)?;
    let redirect_to = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|value| {
            value
                .get("redirect_to")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let mut response = found(redirect_to.as_deref().unwrap_or(&paused_at));
    if let Some(cookie) = parts.headers.get(header::SET_COOKIE) {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, cookie.clone());
    }
    Ok(response)
}

/// How long an emailed code stays usable.
const VERIFICATION_CODE_TTL_SECS: i64 = 600;

/// The shortest wait between two codes for the same purpose and address.
const VERIFICATION_RESEND_SECS: i64 = 60;

/// Wrong guesses a code survives before it stops being checked.
const MAX_VERIFICATION_ATTEMPTS: i32 = 5;

/// Wrong TOTP codes an interaction survives before the challenge is refused (§6.1 `mfa`).
const MAX_MFA_ATTEMPTS: u32 = 5;

/// How long an enrollment started from a sign-in may stay unconfirmed.
const MFA_ENROLLMENT_TTL_SECS: i64 = 600;

/// The shortest accepted password, in characters. Shared with the account centre's change-password
/// endpoint so both entrances enforce the same rule.
pub(crate) const MIN_PASSWORD_LEN: usize = 8;

/// The `verification_codes.purpose` values the email flows write.
const PURPOSE_SIGN_UP: &str = "sign_up";
const PURPOSE_SIGN_IN: &str = "sign_in";
const PURPOSE_PASSWORD_RESET: &str = "password_reset";
/// A code mailed to a new address from the account centre (§6.1).
pub(crate) const PURPOSE_EMAIL_CHANGE: &str = "email_change";
/// A code mailed before the account centre deletes the account (§6.1).
pub(crate) const PURPOSE_DELETE_ACCOUNT: &str = "delete_account";
/// A one-time sign-in link mailed by the code mode's alternative (§6.1).
pub(crate) const PURPOSE_SIGN_IN_LINK: &str = "sign_in_link";

/// The body of every code-request endpoint.
#[derive(Debug, Deserialize)]
pub struct EmailBody {
    /// The address to mail the code to.
    pub email: String,
    /// The CAPTCHA widget's token when the tenant gates this request.
    pub captcha_token: Option<String>,
}

/// `POST …/sign-up` body.
#[derive(Debug, Deserialize)]
pub struct SignUpBody {
    /// The new account's address.
    pub email: String,
    /// The initial password; only read when email verification is disabled, because otherwise the
    /// password belongs to the verification step.
    pub password: Option<String>,
    /// An optional username when the tenant offers that identifier (§6.1).
    pub username: Option<String>,
    /// An optional display name when the tenant collects one at sign-up.
    pub display_name: Option<String>,
    /// An optional avatar URL when the tenant collects one at sign-up.
    pub avatar_url: Option<String>,
    /// The CAPTCHA widget's token when the tenant gates sign-up.
    pub captcha_token: Option<String>,
}

/// `POST …/sign-up/verify` body.
#[derive(Debug, Deserialize)]
pub struct SignUpVerifyBody {
    /// The address the code was mailed to.
    pub email: String,
    /// The six-digit code from the mail.
    pub code: String,
    /// The initial password.
    pub password: String,
    /// Optional display name; the address's local part is used when absent.
    pub display_name: Option<String>,
    /// Optional username, a second sign-in identifier (§6.1).
    pub username: Option<String>,
    /// An optional avatar URL when the tenant collects one at sign-up.
    pub avatar_url: Option<String>,
}

/// The body of the email-code sign-in verification.
#[derive(Debug, Deserialize)]
pub struct CodeVerifyBody {
    /// The address the code was mailed to.
    pub email: String,
    /// The six-digit code from the mail.
    pub code: String,
}

/// `POST …/password/reset` body.
#[derive(Debug, Deserialize)]
pub struct PasswordResetBody {
    /// The address the code was mailed to.
    pub email: String,
    /// The six-digit code from the mail.
    pub code: String,
    /// The new password.
    pub password: String,
}

/// Normalise and validate an address the way the code table indexes it.
pub(crate) fn normalise_email(email: &str) -> Result<String, ApiError> {
    let normalised = email.trim().to_lowercase();
    if normalised.is_empty() || !normalised.contains('@') {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "email must be an address",
        ));
    }
    Ok(normalised)
}

/// Reject a password that does not meet the tenant's length, complexity or rejection rules.
///
/// The character classes are ASCII lowercase, ASCII uppercase, ASCII digits and everything else
/// (symbols, whitespace and non-ASCII letters). A policy of 1 therefore accepts any password long
/// enough, which is the pre-existing behaviour the column defaults to.
///
/// `identifiers` are the account's own names (the email's local part and its username); they are
/// checked only when the tenant enabled the rule, and only once they are three characters long so
/// a one-letter local part cannot ban ordinary words.
pub(crate) fn check_password(
    password: &str,
    experience: &SignInExperienceRow,
    identifiers: &[&str],
) -> Result<(), ApiError> {
    let minimum = experience.password_min_length.max(MIN_PASSWORD_LEN as i32) as usize;
    if password.chars().count() < minimum {
        return Err(ApiError::problem(
            kinds::WEAK_PASSWORD,
            format!("password must be at least {minimum} characters"),
        ));
    }
    let required = experience.password_min_character_types.max(1) as usize;
    let present = password_character_types(password);
    if present < required {
        return Err(ApiError::problem(
            kinds::WEAK_PASSWORD,
            format!(
                "password must use at least {required} character types \
                 (lowercase, uppercase, digits, symbols)"
            ),
        ));
    }
    if experience.password_reject_repetition_and_sequence
        && (has_repeated_run(password, 4) || has_sequential_run(password, 4))
    {
        return Err(ApiError::problem(
            kinds::WEAK_PASSWORD,
            "password must not repeat a character or a sequence four times in a row",
        ));
    }
    if experience.password_reject_user_info || !experience.password_rejected_words.is_empty() {
        let candidate = password.to_lowercase();
        if experience.password_reject_user_info {
            for identifier in identifiers {
                let identifier = identifier.trim().to_lowercase();
                if identifier.chars().count() >= 3 && candidate.contains(&identifier) {
                    return Err(ApiError::problem(
                        kinds::WEAK_PASSWORD,
                        "password must not contain the account's email or username",
                    ));
                }
            }
        }
        for word in &experience.password_rejected_words {
            if word.chars().count() >= 3 && candidate.contains(word) {
                return Err(ApiError::problem(
                    kinds::WEAK_PASSWORD,
                    "password must not contain a rejected word",
                ));
            }
        }
    }
    Ok(())
}

/// How many of the four character classes the password uses.
fn password_character_types(password: &str) -> usize {
    let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
    for character in password.chars() {
        if character.is_ascii_lowercase() {
            lower = true;
        } else if character.is_ascii_uppercase() {
            upper = true;
        } else if character.is_ascii_digit() {
            digit = true;
        } else {
            symbol = true;
        }
    }
    usize::from(lower) + usize::from(upper) + usize::from(digit) + usize::from(symbol)
}

/// Whether one character repeats `run` times consecutively.
fn has_repeated_run(password: &str, run: usize) -> bool {
    let mut length = 0;
    let mut previous: Option<char> = None;
    for character in password.chars() {
        if previous == Some(character) {
            length += 1;
        } else {
            length = 1;
            previous = Some(character);
        }
        if length >= run {
            return true;
        }
    }
    false
}

/// Whether the password follows an ASCII alphanumeric sequence `run` characters long.
///
/// A sequence is an ascending or descending run of consecutive characters (`abcd`, `4321`). The
/// characters must be ASCII alphanumeric on both sides, so a digit cannot continue into a letter.
fn has_sequential_run(password: &str, run: usize) -> bool {
    let mut length = 1;
    let mut step: Option<i64> = None;
    let mut previous: Option<char> = None;
    for character in password.chars() {
        if let Some(prev) = previous {
            let difference = character as i64 - prev as i64;
            let consecutive = matches!(difference, 1 | -1)
                && prev.is_ascii_alphanumeric()
                && character.is_ascii_alphanumeric();
            if consecutive && step == Some(difference) {
                length += 1;
            } else if consecutive {
                step = Some(difference);
                length = 2;
            } else {
                step = None;
                length = 1;
            }
            if length >= run {
                return true;
            }
        }
        previous = Some(character);
    }
    false
}

/// A username that passed the tenant's policy: the stored identifier and its display form.
#[derive(Debug, Clone)]
pub(crate) struct CheckedUsername {
    /// The sign-in identifier: the typed form when case-sensitive, otherwise lowercased.
    pub value: String,
    /// The typed form to show while `username_preserve_case` is on, otherwise `None`.
    pub display: Option<String>,
}

/// Validate and normalise a username under the tenant's policy (§6.1).
///
/// It is a sign-in identifier, so it may not contain `@` (that is how the sign-in endpoint tells the
/// two namespaces apart). A tenant that keeps usernames case-sensitive stores them as typed and
/// compares exactly; otherwise they are stored lowercased, matching the case-insensitive lookup,
/// and `username_preserve_case` may keep the typed form in a separate display column.
///
/// `email` is the account's own address, used only by the local-part switch. Existing identifiers
/// are never re-checked: this runs on creation and on a username change, which is why a tightened
/// policy cannot strand an account that already signed in.
pub(crate) fn check_username(
    raw: &str,
    experience: &SignInExperienceRow,
    email: Option<&str>,
) -> Result<CheckedUsername, ApiError> {
    let trimmed = raw.trim();
    let username = if experience.username_case_sensitive {
        trimmed.to_owned()
    } else {
        trimmed.to_lowercase()
    };
    let min = experience.username_min_length.max(1) as usize;
    let max = experience.username_max_length.max(1) as usize;
    let length = username.chars().count();
    let allowed = &experience.username_allowed_punctuation;
    if !(min..=max).contains(&length)
        || !username.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || allowed
                    .iter()
                    .any(|punctuation| punctuation.chars().next() == Some(c))
        })
    {
        let punctuation = if allowed.is_empty() {
            String::new()
        } else {
            format!(" or one of {}", allowed.join(" "))
        };
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("username must be {min}-{max} ASCII letters, digits{punctuation}"),
        ));
    }
    let lowered = username.to_lowercase();
    if experience
        .username_reserved_words
        .iter()
        .any(|word| word == &lowered)
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "username is reserved",
        ));
    }
    if !experience.username_allow_email_local_part
        && let Some(email) = email
    {
        let local_part = email
            .split('@')
            .next()
            .unwrap_or(email)
            .trim()
            .to_lowercase();
        if lowered == local_part {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "username must not match the account's email local part",
            ));
        }
    }
    let display = (!experience.username_case_sensitive
        && experience.username_preserve_case
        && trimmed != username)
        .then(|| trimmed.to_owned());
    Ok(CheckedUsername {
        value: username,
        display,
    })
}

/// The interaction and its tenant, or the interaction error the page should render.
async fn interaction_and_tenant(
    state: &Arc<AppState>,
    tenant_slug: &str,
    iid: &str,
) -> Result<(Interaction, TenantRow), ApiError> {
    // Interactions are stored in the tenant's own database, so the path's tenant is the address.
    let tenant = state.tenant(tenant_slug).await?;
    let interaction = state
        .peek_interaction(&tenant, iid)
        .await
        .map_err(ApiError::Interaction)?;
    Ok((interaction, tenant))
}

/// Mint a code, mail it through the dev outbox and answer the request endpoint.
///
/// The answer is identical whether or not an account exists, so a caller cannot enumerate
/// addresses; sign-in and forgot-password both call this unconditionally.
pub(crate) async fn request_verification(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    purpose: &str,
    email: &str,
) -> Result<Json<Value>, ApiError> {
    let now = state.now();
    if let Some(row) = state
        .store
        .verification_code_latest(tenant, purpose, email)
        .await?
        && now - row.created_at < Duration::seconds(VERIFICATION_RESEND_SECS)
    {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "a code was requested moments ago; try again shortly",
        ));
    }

    let code = generate_numeric_code(DEFAULT_CODE_DIGITS);
    let expires_at = now + Duration::seconds(VERIFICATION_CODE_TTL_SECS);
    state
        .store
        .insert_verification_code(tenant, purpose, email, &hash_secret(&code), expires_at)
        .await?;

    let expires_in = (VERIFICATION_CODE_TTL_SECS / 60).to_string();
    let (subject, body) = crate::email_templates::mail_copy(
        state,
        tenant,
        purpose,
        &[
            ("tenant", tenant.slug.as_str()),
            ("code", code.as_str()),
            ("expires_in", expires_in.as_str()),
        ],
    )
    .await;

    // §6.3: the outbox is how the Bun side and the acceptance script see what would be mailed.
    let mut tx = state.store.begin_tenant(tenant).await?;
    state
        .store
        .outbox_append(
            &mut *tx,
            topics::MAIL,
            &json!({
                "to": email,
                "purpose": purpose,
                "subject": subject,
                "body": body,
                "code": code,
                "expires_at": expires_at.unix_timestamp(),
            }),
        )
        .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "verification_required": true,
        "expires_in": VERIFICATION_CODE_TTL_SECS,
    })))
}

/// Verify and redeem a code, counting the attempt before comparing so guesses cost.
///
/// Every rejection is the same 401 except the brute-force limit, which is a 429: an attacker
/// learns nothing about whether a live code existed, only that they have exhausted it.
pub(crate) async fn take_verification_code(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    purpose: &str,
    email: &str,
    code: &str,
) -> Result<(), ApiError> {
    let invalid = || {
        ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        )
    };

    let Some(row) = state
        .store
        .verification_code_latest(tenant, purpose, email)
        .await?
    else {
        return Err(invalid());
    };
    if row.expires_at <= state.now() {
        return Err(invalid());
    }
    if row.attempts >= MAX_VERIFICATION_ATTEMPTS {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "too many guesses; request a new code",
        ));
    }
    let Some(attempts) = state
        .store
        .verification_code_attempt(tenant, row.id)
        .await?
    else {
        return Err(invalid());
    };
    if attempts > MAX_VERIFICATION_ATTEMPTS {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "too many guesses; request a new code",
        ));
    }
    if !verify_secret(code.trim(), &row.code_hash) {
        return Err(invalid());
    }
    if !state
        .store
        .consume_verification_code(tenant, row.id)
        .await?
    {
        return Err(invalid());
    }
    Ok(())
}

/// Validate the optional profile fields a sign-up carries against the tenant's policy.
fn check_sign_up_profile(
    experience: &SignInExperienceRow,
    username: Option<&str>,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    email: &str,
) -> Result<(Option<CheckedUsername>, Option<String>, Option<String>), ApiError> {
    let username = match username.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => {
            if !experience
                .sign_up_identifiers
                .iter()
                .any(|identifier| identifier == "username")
            {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "username is not an available sign-up identifier",
                ));
            }
            Some(check_username(raw, experience, Some(email))?)
        }
        None => None,
    };
    let display_name = display_name
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if display_name.is_some()
        && !experience
            .sign_up_profile_fields
            .iter()
            .any(|field| field == "name")
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "display_name is not collected at sign-up",
        ));
    }
    let avatar_url = match avatar_url.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => {
            if !experience
                .sign_up_profile_fields
                .iter()
                .any(|field| field == "avatar")
            {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "avatar_url is not collected at sign-up",
                ));
            }
            crate::account::check_avatar_url(raw)?
        }
        None => None,
    };
    Ok((username, display_name.map(str::to_owned), avatar_url))
}

/// Create the account, join the interaction's org and finish the sign-in.
#[allow(clippy::too_many_arguments)]
async fn complete_sign_up(
    state: Arc<AppState>,
    tenant: TenantRow,
    interaction: Interaction,
    iid: &str,
    headers: &HeaderMap,
    email: &str,
    password: &str,
    username: Option<String>,
    username_display: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
) -> Result<Response, ApiError> {
    let phc = hash_password(password.to_owned(), state.argon)
        .await
        .map_err(ApiError::internal)?;
    let display_name =
        display_name.unwrap_or_else(|| email.split('@').next().unwrap_or(email).to_owned());
    let account = state
        .store
        .create_account(
            &tenant,
            AccountId::new(),
            email,
            &display_name,
            Some(&phc),
            false,
            username.as_deref(),
            username_display.as_deref(),
        )
        .await?;
    let account = match avatar_url.as_deref() {
        Some(url) => {
            state
                .store
                .update_avatar_url(&tenant, account.account_id(), Some(url))
                .await?
        }
        None => account,
    };

    // The new account joins the org the interaction issues into, so the flow can complete without
    // an admin round-trip. The org and tenant chains both record it (§8.1).
    let org = state
        .store
        .org_by_slug(&tenant, &interaction.organization)
        .await?;
    let org_ctx = org.ctx(&tenant);
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
        payload: json!({ "org": org.slug, "role": "member", "self_service": true }),
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
            "username": username,
            "self_service": true,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append account.created audit event");
    }

    finish_sign_in(state, tenant, interaction, iid, headers, account).await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-up` — start self-service registration.
///
/// When the tenant requires an emailed code, this only requests one and the password and profile
/// fields belong to `sign-up/verify`. When it does not, the same request creates the account and
/// signs in, because there is nothing left to prove.
pub async fn sign_up(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    Json(body): Json<SignUpBody>,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.sign_up_enabled {
        return Err(ApiError::problem(
            kinds::SIGN_UP_DISABLED,
            "self-service sign-up is disabled for this tenant",
        ));
    }
    crate::captcha::enforce(
        &state,
        &tenant,
        &experience,
        crate::captcha::Flow::SignUp,
        body.captcha_token.as_deref(),
    )
    .await?;
    let email = normalise_email(&body.email)?;
    if state
        .store
        .account_by_email(&tenant, &email)
        .await?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::ACCOUNT_EXISTS,
            "an account with this email already exists",
        ));
    }
    let has_profile =
        body.username.is_some() || body.display_name.is_some() || body.avatar_url.is_some();
    if experience.sign_up_email_verification_required {
        if body.password.is_some() || has_profile {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "email verification is required; send the password and profile fields to sign-up/verify",
            ));
        }
        return Ok(
            request_verification(&state, &tenant, PURPOSE_SIGN_UP, &email)
                .await?
                .into_response(),
        );
    }
    let Some(password) = body.password else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "password is required when email verification is disabled",
        ));
    };
    let (username, display_name, avatar_url) = check_sign_up_profile(
        &experience,
        body.username.as_deref(),
        body.display_name.as_deref(),
        body.avatar_url.as_deref(),
        &email,
    )?;
    let username_value = username.as_ref().map(|checked| checked.value.clone());
    let username_display = username
        .as_ref()
        .and_then(|checked| checked.display.clone());
    let local_part = email.split('@').next().unwrap_or(&email);
    let mut identifiers = vec![local_part];
    if let Some(username) = username_value.as_deref() {
        identifiers.push(username);
    }
    check_password(&password, &experience, &identifiers)?;
    complete_sign_up(
        state,
        tenant,
        interaction,
        &iid,
        &headers,
        &email,
        &password,
        username_value,
        username_display,
        display_name,
        avatar_url,
    )
    .await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-up/verify` — prove the address and sign in.
pub async fn sign_up_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SignUpVerifyBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.sign_up_enabled {
        return Err(ApiError::problem(
            kinds::SIGN_UP_DISABLED,
            "self-service sign-up is disabled for this tenant",
        ));
    }
    let email = normalise_email(&body.email)?;
    let (username, display_name, avatar_url) = check_sign_up_profile(
        &experience,
        body.username.as_deref(),
        body.display_name.as_deref(),
        body.avatar_url.as_deref(),
        &email,
    )?;
    let username_value = username.as_ref().map(|checked| checked.value.clone());
    let username_display = username
        .as_ref()
        .and_then(|checked| checked.display.clone());
    let local_part = email.split('@').next().unwrap_or(&email);
    let mut identifiers = vec![local_part];
    if let Some(username) = username_value.as_deref() {
        identifiers.push(username);
    }
    check_password(&body.password, &experience, &identifiers)?;
    // A second registration for the same address is a conflict even with a valid code, because
    // the code proves the address, not the account's absence.
    if state
        .store
        .account_by_email(&tenant, &email)
        .await?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::ACCOUNT_EXISTS,
            "an account with this email already exists",
        ));
    }
    take_verification_code(&state, &tenant, PURPOSE_SIGN_UP, &email, &body.code).await?;
    complete_sign_up(
        state,
        tenant,
        interaction,
        &iid,
        &headers,
        &email,
        &body.password,
        username_value,
        username_display,
        display_name,
        avatar_url,
    )
    .await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/code` — request a passwordless sign-in code.
pub async fn sign_in_code(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (_interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.email_code_sign_in_enabled {
        return Err(ApiError::problem(
            kinds::EMAIL_CODE_SIGN_IN_DISABLED,
            "email code sign-in is disabled for this tenant",
        ));
    }
    crate::captcha::enforce(
        &state,
        &tenant,
        &experience,
        crate::captcha::Flow::SignIn,
        body.captcha_token.as_deref(),
    )
    .await?;
    let email = normalise_email(&body.email)?;
    request_verification(&state, &tenant, PURPOSE_SIGN_IN, &email).await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/code/verify`.
pub async fn sign_in_code_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    Json(body): Json<CodeVerifyBody>,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .email_code_sign_in_enabled
    {
        return Err(ApiError::problem(
            kinds::EMAIL_CODE_SIGN_IN_DISABLED,
            "email code sign-in is disabled for this tenant",
        ));
    }
    let email = normalise_email(&body.email)?;
    take_verification_code(&state, &tenant, PURPOSE_SIGN_IN, &email, &body.code).await?;

    let Some((account, _)) = state.store.account_by_email(&tenant, &email).await? else {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "email or code is incorrect",
        ));
    };
    if account.state != "active" {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "email or code is incorrect",
        ));
    }
    finish_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/link` — mail a one-time sign-in URL.
///
/// The link carries a 256-bit token and no address: the token row supplies the identifier, so the
/// URL itself does not disclose who it belongs to. A request is answered the same way whatever the
/// address is, and the throttle matches the six-digit code path.
pub async fn sign_in_link(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (_interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.email_code_sign_in_enabled {
        return Err(ApiError::problem(
            kinds::EMAIL_CODE_SIGN_IN_DISABLED,
            "email code sign-in is disabled for this tenant",
        ));
    }
    // A mailed link is another way to start a sign-in, so the same challenge covers it.
    crate::captcha::enforce(
        &state,
        &tenant,
        &experience,
        crate::captcha::Flow::SignIn,
        body.captcha_token.as_deref(),
    )
    .await?;
    let email = normalise_email(&body.email)?;
    let now = state.now();
    if let Some(row) = state
        .store
        .verification_code_latest(&tenant, PURPOSE_SIGN_IN_LINK, &email)
        .await?
        && now - row.created_at < Duration::seconds(VERIFICATION_RESEND_SECS)
    {
        return Err(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "a link was requested moments ago; try again shortly",
        ));
    }

    let token = hex::encode(generate_challenge());
    let expires_at = now + Duration::seconds(VERIFICATION_CODE_TTL_SECS);
    state
        .store
        .insert_verification_code(
            &tenant,
            PURPOSE_SIGN_IN_LINK,
            &email,
            &hash_secret(&token),
            expires_at,
        )
        .await?;

    let url = append_query(
        &format!(
            "{}/t/{}/interaction/{}/sign-in/link/verify",
            state.config.public_base_url.trim_end_matches('/'),
            tenant.slug,
            iid
        ),
        &[("token", token.as_str())],
    );
    let expires_in = (VERIFICATION_CODE_TTL_SECS / 60).to_string();
    let (subject, body) = crate::email_templates::mail_copy(
        &state,
        &tenant,
        PURPOSE_SIGN_IN_LINK,
        &[
            ("tenant", tenant.slug.as_str()),
            ("url", url.as_str()),
            ("expires_in", expires_in.as_str()),
        ],
    )
    .await;
    let mut tx = state.store.begin_tenant(&tenant).await?;
    state
        .store
        .outbox_append(
            &mut *tx,
            topics::MAIL,
            &json!({
                "to": email,
                "purpose": PURPOSE_SIGN_IN_LINK,
                "subject": subject,
                "body": body,
                "token": token,
                "url": url,
                "expires_at": expires_at.unix_timestamp(),
            }),
        )
        .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "verification_required": true,
        "expires_in": VERIFICATION_CODE_TTL_SECS,
    })))
}

/// The query of the sign-in link callback.
#[derive(Debug, Deserialize)]
pub struct LinkTokenQuery {
    /// The 256-bit token the mailed URL carries.
    pub token: String,
}

/// `GET /t/{tenant}/interaction/{iid}/sign-in/link/verify?token=…` — redeem a sign-in link.
///
/// This is a browser navigation: success redirects to the client, and a paused flow (MFA or
/// consent) redirects back to the sign-in page, exactly like any other primary proof.
pub async fn sign_in_link_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<LinkTokenQuery>,
) -> Result<Response, ApiError> {
    // The token is checked before the interaction: a replay must answer 401 like any other dead
    // link, not disclose that the interaction was already consumed.
    let tenant = state.tenant(&tenant_slug).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .email_code_sign_in_enabled
    {
        return Err(ApiError::problem(
            kinds::EMAIL_CODE_SIGN_IN_DISABLED,
            "email code sign-in is disabled for this tenant",
        ));
    }
    let invalid = || {
        ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the link is incorrect or expired",
        )
    };
    let token = query.token.trim();
    if token.is_empty() {
        return Err(invalid());
    }
    let Some(row) = state
        .store
        .verification_code_by_hash(&tenant, PURPOSE_SIGN_IN_LINK, &hash_secret(token))
        .await?
    else {
        return Err(invalid());
    };
    if row.expires_at <= state.now() {
        return Err(invalid());
    }
    if !state
        .store
        .consume_verification_code(&tenant, row.id)
        .await?
    {
        return Err(invalid());
    }

    let interaction = state
        .peek_interaction(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    if interaction.tenant != tenant.slug {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the interaction belongs to another tenant",
        ));
    }

    let Some((account, _)) = state
        .store
        .account_by_email(&tenant, &row.identifier)
        .await?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the link does not sign in this account",
        ));
    };
    if account.state != "active" {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the link does not sign in this account",
        ));
    }
    finish_sign_in_browser(state, tenant, interaction, &iid, &headers, account).await
}

/// `POST /t/{tenant}/interaction/{iid}/password/forgot` — request a reset code.
pub async fn password_forgot(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (_interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.password_sign_in_enabled {
        return Err(ApiError::problem(
            kinds::PASSWORD_SIGN_IN_DISABLED,
            "password sign-in is disabled for this tenant",
        ));
    }
    crate::captcha::enforce(
        &state,
        &tenant,
        &experience,
        crate::captcha::Flow::PasswordReset,
        body.captcha_token.as_deref(),
    )
    .await?;
    let email = normalise_email(&body.email)?;
    request_verification(&state, &tenant, PURPOSE_PASSWORD_RESET, &email).await
}

/// `POST /t/{tenant}/interaction/{iid}/password/reset` — prove the address, set a new password.
pub async fn password_reset(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PasswordResetBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let experience = state.store.sign_in_experience(&tenant).await?;
    if !experience.password_sign_in_enabled {
        return Err(ApiError::problem(
            kinds::PASSWORD_SIGN_IN_DISABLED,
            "password sign-in is disabled for this tenant",
        ));
    }
    let email = normalise_email(&body.email)?;
    let local_part = email.split('@').next().unwrap_or(&email);
    check_password(&body.password, &experience, &[local_part])?;
    take_verification_code(&state, &tenant, PURPOSE_PASSWORD_RESET, &email, &body.code).await?;

    let Some((account, _)) = state.store.account_by_email(&tenant, &email).await? else {
        return Err(ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        ));
    };
    if account.state != "active" {
        return Err(ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        ));
    }

    let phc = hash_password(body.password.clone(), state.argon)
        .await
        .map_err(ApiError::internal)?;
    state
        .store
        .set_password(&tenant, account.account_id(), &phc)
        .await?;
    // Every existing session belonged to whoever knew the old password. The browser's cookie is
    // revoked too, and `finish_sign_in` issues a fresh session for this reset flow.
    state
        .store
        .revoke_account_sessions(&tenant, account.account_id())
        .await?;

    finish_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// The second-factor body.
#[derive(Debug, Deserialize)]
pub struct MfaVerifyBody {
    /// The six-digit TOTP from the authenticator app, or one of the saved backup codes.
    pub code: String,
    /// `totp` (default) or `backup_code`.
    pub factor: Option<String>,
    /// Ask the server to remember this browser once the factor is accepted, when the tenant's
    /// trusted-device policy allows it.
    #[serde(default)]
    pub remember_device: bool,
}

/// Mint a trust for this browser and return the cookie that carries it.
///
/// Only the SHA-256 of the token is stored; the cookie is the one place the token exists in
/// plaintext, and it is per tenant and HttpOnly.
async fn issue_trusted_device(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account: &AccountRow,
    headers: &HeaderMap,
    ttl_secs: u64,
) -> Result<HeaderValue, ApiError> {
    let token = hex::encode(generate_challenge());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|raw| raw.chars().take(160).collect::<String>());
    state
        .store
        .insert_trusted_device(
            tenant,
            account.account_id(),
            &hash_secret(&token),
            user_agent.as_deref(),
            state.now() + Duration::seconds(ttl_secs as i64),
        )
        .await?;
    let secure = session::secure_origin(&state.config);
    HeaderValue::from_str(&session::set_device_cookie(
        &token,
        ttl_secs,
        secure,
        &tenant.slug,
    ))
    .map_err(ApiError::internal)
}

/// Refuse a second-factor attempt, counting it against the interaction's limit.
///
/// Both factors share one counter: trying five backup codes must not leave the TOTP form with a
/// fresh budget.
async fn refuse_mfa_code(
    state: &AppState,
    tenant: &TenantRow,
    iid: &str,
) -> Result<ApiError, ApiError> {
    let attempts = state
        .record_mfa_failure(tenant, iid)
        .await
        .map_err(ApiError::Interaction)?;
    if attempts >= MAX_MFA_ATTEMPTS {
        Ok(ApiError::problem(
            kinds::TOO_MANY_ATTEMPTS,
            "too many wrong second-factor codes",
        ))
    } else {
        Ok(ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        ))
    }
}

/// `POST /t/{tenant}/interaction/{iid}/mfa/verify` — prove the second factor.
///
/// The interaction remembers which account passed the primary factor, so this handler needs no
/// credential of its own; it only proves possession of an authenticator or a backup code enrolled
/// for that account. A backup code is burned on use, so the same sheet cannot be replayed.
pub async fn mfa_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let Some(account_id) = state
        .mfa_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is not waiting for a second factor",
        ));
    };

    let Some(account) = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(account_id))
        .await?
    else {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    };
    if account.state != "active" {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    }

    match body.factor.as_deref().unwrap_or("totp") {
        "totp" => {
            let Some(sealed) = state
                .store
                .totp_secret(&tenant, account.account_id())
                .await?
            else {
                return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
            };
            let dek = state.tenant_dek(&tenant)?;
            let secret = open(&dek, &sealed)
                .map_err(|err| ApiError::internal(format!("totp secret: {err}")))?;

            if !verify_totp(&secret, &body.code, state.now()) {
                return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
            }
            state
                .store
                .touch_totp(&tenant, account.account_id(), state.now())
                .await?;
        }
        "backup_code" => {
            // A malformed code is indistinguishable from a used or unknown one: both are a single
            // attempt and the same `401`.
            let Some(hash) = normalize_backup_code(&body.code).map(|code| hash_secret(&code))
            else {
                return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
            };
            if !state
                .store
                .consume_backup_code(&tenant, account.account_id(), &hash)
                .await?
            {
                return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
            }
        }
        _ => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "unknown second factor",
            ));
        }
    }

    state
        .clear_mfa_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;

    let experience = state.store.sign_in_experience(&tenant).await?;
    let trust = if body.remember_device && experience.mfa_trusted_devices_enabled {
        let ttl_secs = u64::try_from(experience.mfa_trusted_device_ttl_days)
            .unwrap_or(30)
            .saturating_mul(86_400);
        Some(issue_trusted_device(&state, &tenant, &account, &headers, ttl_secs).await?)
    } else {
        None
    };
    let mut response =
        complete_sign_in(state, tenant, interaction, &iid, &headers, account).await?;
    if let Some(cookie) = trust {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

/// The body of `POST …/mfa/enroll/verify`.
#[derive(Debug, Deserialize)]
pub struct MfaEnrollmentBody {
    /// The six-digit code from the authenticator.
    pub code: String,
}

/// `POST /t/{tenant}/interaction/{iid}/mfa/enroll` — start the setup a mandatory policy demands.
///
/// The secret is held unconfirmed in the same in-memory map the account centre uses, keyed by the
/// account this interaction is parked on. It is written to `credentials` only by the verify step.
pub async fn mfa_enroll_start(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (_interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let Some(account_id) = state
        .mfa_enrollment_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is not waiting for an enrollment",
        ));
    };
    let Some(account) = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(account_id))
        .await?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "this account cannot sign in",
        ));
    };
    if state
        .store
        .totp_secret(&tenant, account.account_id())
        .await?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::MFA_ALREADY_ENABLED,
            "an authenticator app is already enrolled",
        ));
    }

    let secret = generate_totp_secret();
    state
        .put_totp_enrollment(
            &tenant,
            account.id,
            secret.clone(),
            state.now() + Duration::seconds(MFA_ENROLLMENT_TTL_SECS),
        )
        .await?;
    Ok(Json(json!({
        "secret": totp_base32(&secret),
        "otpauth_url": totp_otpauth_url(crate::account::ISSUER, &account.primary_email, &secret),
        "expires_in": MFA_ENROLLMENT_TTL_SECS,
    })))
}

/// `POST /t/{tenant}/interaction/{iid}/mfa/enroll/verify` — prove the app and finish the sign-in.
///
/// The freshly verified factor counts as satisfied for this interaction only: the account signs in
/// once, and every later sign-in is challenged normally.
pub async fn mfa_enroll_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<MfaEnrollmentBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let Some(account_id) = state
        .mfa_enrollment_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is not waiting for an enrollment",
        ));
    };
    let Some(secret) = state.totp_enrollment(&tenant, account_id).await else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "no enrollment is pending; start again",
        ));
    };
    if !verify_totp(&secret, &body.code, state.now()) {
        return Err(ApiError::problem(
            kinds::INVALID_VERIFICATION_CODE,
            "the code is incorrect or expired",
        ));
    }
    let account_id = AccountId::from_uuid(account_id);
    if state
        .store
        .totp_secret(&tenant, account_id)
        .await?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::MFA_ALREADY_ENABLED,
            "an authenticator app is already enrolled",
        ));
    }

    let sealed = seal(&state.tenant_dek(&tenant)?, &secret)
        .map_err(|err| ApiError::internal(format!("totp secret: {err}")))?;
    state
        .store
        .set_totp_secret(&tenant, account_id, &sealed)
        .await?;
    state.drop_totp_enrollment(&tenant, account_id.uuid()).await;
    state
        .mark_mfa_satisfied(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;

    let Some(account) = state.store.account_by_id(&tenant, account_id).await? else {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "this account cannot sign in",
        ));
    };
    if account.state != "active" {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "this account cannot sign in",
        ));
    }
    finish_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// Record a rejected passkey sign-in.
///
/// The password path audits denials inline; a passkey denial happens before any address is known
/// (the credential is the identifier), so the credential-bearing account's email is only recorded
/// when the credential itself resolved.
async fn audit_passkey_denial(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    interaction: &Interaction,
    email: &str,
    reason: &str,
) {
    let Ok(org) = state
        .store
        .org_by_slug(tenant, &interaction.organization)
        .await
    else {
        return;
    };
    let ctx = org.ctx(tenant);
    let event = sign_in_event(state.now(), &ctx.org_id, AuditDecision::Deny, email, reason);
    if let Err(err) = state.audit_org(&ctx, &event).await {
        tracing::warn!(%err, "could not append sign-in.failed audit event");
    }
}

/// Resolve a sign-in interaction that may still take a primary factor.
///
/// A passkey is a *primary* factor here. Once the interaction is signed in (consent only) or
/// waiting for a second factor, the discoverable-credential path would be a way around the factor
/// the page is currently asking for, so both are refused rather than silently accepted.
async fn passkey_sign_in_interaction(
    state: &Arc<AppState>,
    tenant_slug: &str,
    iid: &str,
) -> Result<(Interaction, TenantRow), ApiError> {
    let (interaction, tenant) = interaction_and_tenant(state, tenant_slug, iid).await?;
    // The tenant's switch gates both halves of the ceremony: a disabled method must not hand the
    // browser assertion options, and a stale challenge must not still complete a sign-in.
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .passkey_sign_in_enabled
    {
        return Err(ApiError::problem(
            kinds::PASSKEY_SIGN_IN_DISABLED,
            "passkey sign-in is disabled for this tenant",
        ));
    }
    let (_, signed_in) = state
        .peek_interaction_state(&tenant, iid)
        .await
        .map_err(ApiError::Interaction)?;
    if signed_in.is_some() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is already signed in",
        ));
    }
    if state
        .mfa_pending(&tenant, iid)
        .await
        .map_err(ApiError::Interaction)?
        .is_some()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is waiting for a second factor",
        ));
    }
    Ok((interaction, tenant))
}

/// Decrypt the sealed public key and check one assertion against the stored credential.
///
/// `Ok(None)` is every *attacker-controlled* failure — bad signature, no user verification, a
/// replayed or cloned counter — because the two callers render it differently (a `401` for primary
/// sign-in, a counted refusal for the second factor). Decryption failing is not attacker-shaped and
/// stays an `Err`.
fn verify_passkey_assertion(
    state: &AppState,
    tenant: &TenantRow,
    row: &PasskeyRow,
    assertion: &crate::passkey::Assertion,
    challenge: &[u8],
    rp: &crate::passkey::RelyingParty,
) -> Result<Option<u64>, ApiError> {
    let dek = state.tenant_dek(tenant)?;
    let public_key = open(&dek, &row.secret_enc)
        .map_err(|err| ApiError::internal(format!("passkey public key: {err}")))?;

    let Ok(sign_count) = verify_assertion(
        &assertion.client_data_json,
        &assertion.authenticator_data,
        &assertion.signature,
        &public_key,
        challenge,
        &rp.id,
        &rp.origin,
    ) else {
        return Ok(None);
    };
    if !assertion_user_verified(&assertion.authenticator_data) {
        return Ok(None);
    }
    if !crate::passkey::counter_is_acceptable(row.sign_count, sign_count) {
        return Ok(None);
    }
    Ok(Some(sign_count))
}

/// Store the counter a verified assertion reported, so a cloned authenticator shows up next time.
async fn record_passkey_counter(
    state: &AppState,
    tenant: &TenantRow,
    row: &PasskeyRow,
    sign_count: u64,
) -> Result<(), ApiError> {
    state
        .store
        .record_passkey_use(
            tenant,
            row.id,
            sign_count.min(i64::MAX as u64) as i64,
            state.now(),
        )
        .await?;
    Ok(())
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/passkey/options` — start a passwordless sign-in.
///
/// `allowCredentials` is empty on purpose: the page cannot name an account, so the browser offers
/// the discoverable passkeys it holds for this host and reports the user handle with the result.
pub async fn passkey_sign_in_options(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (_, tenant) = passkey_sign_in_interaction(&state, &tenant_slug, &iid).await?;
    let rp = crate::passkey::relying_party(&state.config)?;
    let challenge = generate_challenge();
    state
        .put_passkey_challenge(
            &tenant,
            format!("in:{iid}"),
            challenge.clone(),
            state.now() + Duration::seconds(crate::passkey::CHALLENGE_TTL_SECS),
        )
        .await?;
    Ok(Json(crate::passkey::assertion_options(
        &rp.id,
        &challenge,
        Vec::new(),
    )))
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/passkey` — complete a passwordless sign-in.
///
/// The account is resolved from the credential the authenticator signed with; the `userHandle` must
/// name the same account, otherwise one account's credential could assert an interaction into
/// another account. Everything after that is shared with the password path, so a passkey sign-in
/// still honours an enrolled second factor.
pub async fn passkey_sign_in_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    Json(body): Json<crate::passkey::CeremonyBody>,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (interaction, tenant) = passkey_sign_in_interaction(&state, &tenant_slug, &iid).await?;
    let Some(challenge) = state
        .take_passkey_challenge(&tenant, &format!("in:{iid}"))
        .await
    else {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "no passkey sign-in is pending; start again",
        ));
    };
    let Some(assertion) = crate::passkey::parse_assertion(&body) else {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the browser's passkey response is malformed",
        ));
    };
    let Some(row) = state
        .store
        .passkey_by_credential_id(&tenant, &assertion.credential_id)
        .await?
    else {
        audit_passkey_denial(&state, &tenant, &interaction, "", "unknown_passkey").await;
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the passkey did not sign in",
        ));
    };
    // A discoverable credential always carries the user handle; without it the assertion cannot
    // name the account the signature was meant for.
    if !assertion
        .user_handle
        .as_deref()
        .and_then(|handle| Uuid::from_slice(handle).ok())
        .is_some_and(|handle| handle == row.account_id)
    {
        audit_passkey_denial(&state, &tenant, &interaction, "", "passkey_user_handle").await;
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the passkey did not sign in",
        ));
    }
    let Some(account) = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(row.account_id))
        .await?
    else {
        audit_passkey_denial(&state, &tenant, &interaction, "", "passkey_account_gone").await;
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the passkey did not sign in",
        ));
    };
    if account.state != "active" {
        audit_passkey_denial(
            &state,
            &tenant,
            &interaction,
            &account.primary_email,
            "account_disabled",
        )
        .await;
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the passkey did not sign in",
        ));
    }

    let rp = crate::passkey::relying_party(&state.config)?;
    let Some(sign_count) =
        verify_passkey_assertion(&state, &tenant, &row, &assertion, &challenge, &rp)?
    else {
        audit_passkey_denial(
            &state,
            &tenant,
            &interaction,
            &account.primary_email,
            "invalid_passkey",
        )
        .await;
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "the passkey did not sign in",
        ));
    };
    record_passkey_counter(&state, &tenant, &row, sign_count).await?;

    finish_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// `POST /t/{tenant}/interaction/{iid}/mfa/passkey/options` — offer a passkey as the second factor.
///
/// Only the passkeys of the account waiting on this interaction are allowed, so the authenticator
/// cannot answer with someone else's credential.
pub async fn mfa_passkey_options(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (_, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let Some(account_id) = state
        .mfa_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is not waiting for a second factor",
        ));
    };
    let rows = state
        .store
        .passkeys(&tenant, AccountId::from_uuid(account_id))
        .await?;
    if rows.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this account has no passkeys",
        ));
    }

    let rp = crate::passkey::relying_party(&state.config)?;
    let challenge = generate_challenge();
    state
        .put_passkey_challenge(
            &tenant,
            format!("mfa:{iid}"),
            challenge.clone(),
            state.now() + Duration::seconds(crate::passkey::CHALLENGE_TTL_SECS),
        )
        .await?;
    let allow = rows
        .iter()
        .map(crate::passkey::credential_descriptor)
        .collect();
    Ok(Json(crate::passkey::assertion_options(
        &rp.id, &challenge, allow,
    )))
}

/// `POST /t/{tenant}/interaction/{iid}/mfa/passkey` — prove the second factor with a passkey.
///
/// Every rejection is counted exactly like a wrong code: the two factors share the interaction's
/// five-attempt budget, so a passkey cannot be used to reset the TOTP counter (or the reverse).
pub async fn mfa_passkey_verify(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    Json(body): Json<crate::passkey::CeremonyBody>,
) -> Result<Response, ApiError> {
    state
        .enforce_ip_rate_limit(client_ip.0, "interaction")
        .await?;
    let (interaction, tenant) = interaction_and_tenant(&state, &tenant_slug, &iid).await?;
    let Some(account_id) = state
        .mfa_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is not waiting for a second factor",
        ));
    };

    let Some(challenge) = state
        .take_passkey_challenge(&tenant, &format!("mfa:{iid}"))
        .await
    else {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    };
    let Some(assertion) = crate::passkey::parse_assertion(&body) else {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    };
    let Some(account) = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(account_id))
        .await?
    else {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    };
    if account.state != "active" {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    }
    let Some(row) = state
        .store
        .passkey_by_credential_id(&tenant, &assertion.credential_id)
        .await?
    else {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    };
    // The credential must belong to the account this interaction is proving; otherwise a valid
    // passkey of a different account would satisfy the challenge.
    if row.account_id != account.id {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    }
    if let Some(handle) = assertion.user_handle.as_deref()
        && !Uuid::from_slice(handle).is_ok_and(|handle| handle == account.id)
    {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    }

    let rp = crate::passkey::relying_party(&state.config)?;
    let Some(sign_count) =
        verify_passkey_assertion(&state, &tenant, &row, &assertion, &challenge, &rp)?
    else {
        return Err(refuse_mfa_code(&state, &tenant, &iid).await?);
    };
    record_passkey_counter(&state, &tenant, &row, sign_count).await?;

    state
        .clear_mfa_pending(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    complete_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// Reuse a valid cookie session for the same account, or insert a fresh one.
async fn establish_session(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    headers: &HeaderMap,
    account: &AccountRow,
    client_row_id: Uuid,
    session_ttl_secs: u64,
) -> Result<Uuid, ApiError> {
    let now = state.now();
    if let Some(id) = session::session_id(headers)
        && let Some(row) = state.store.session_by_id(tenant, id).await?
        && row.account_id == account.id
        && row.is_active(now)
    {
        state.store.touch_session(tenant, id, now).await?;
        return Ok(id);
    }

    // A v7 uuid, like every other row id, so the session is addressable as a `ses_…` typed id.
    let id = Uuid::now_v7();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    state
        .store
        .insert_session(
            tenant,
            id,
            account.id,
            Some(client_row_id),
            now + Duration::seconds(session_ttl_secs as i64),
            user_agent,
        )
        .await?;
    Ok(id)
}

/// Attach the SSO cookie to a sign-in response.
fn with_session_cookie(
    mut response: Response,
    session_id: Uuid,
    ttl_secs: u64,
    state: &AppState,
) -> Response {
    let secure = session::secure_origin(&state.config);
    let value = session::set_cookie(session_id, ttl_secs, secure);
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// The consent body.
#[derive(Debug, Deserialize)]
pub struct ConsentBody {
    /// `allow` | `deny`.
    pub decision: String,
    /// Whether the approval should cover future authorize requests; defaults to `true`, the
    /// pre-existing behaviour.
    #[serde(default)]
    pub remember: Option<bool>,
    /// The subset of the requested scopes this decision approves, in request order. Absent means
    /// the whole request, the pre-existing behaviour.
    #[serde(default)]
    pub allowed_scopes: Option<Vec<String>>,
}

/// `POST /t/{tenant}/interaction/{iid}/consent` — the second half of the login/consent challenge.
pub async fn consent(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
    Json(body): Json<ConsentBody>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if body.decision != "allow" && body.decision != "deny" {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "decision must be `allow` or `deny`",
        ));
    }
    if body.decision == "deny" {
        let interaction = state
            .consume_interaction(&tenant, &iid)
            .await
            .map_err(ApiError::Interaction)?;
        return Ok(Json(json!({
            "redirect_to": append_query(
                &interaction.redirect_uri,
                &[("error", "access_denied"), ("state", interaction.state.as_str())],
            )
        }))
        .into_response());
    }

    // Peek first: a scope list outside the request, or every scope refused, must not leave the
    // interaction half-answerable. Only an actual approval consumes it.
    let (interaction, _) = state
        .peek_interaction_state(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    let approved: Vec<String> = match body.allowed_scopes.as_deref() {
        None => interaction.scopes.clone(),
        Some(allowed) => {
            if let Some(unknown) = allowed
                .iter()
                .find(|scope| !interaction.scopes.contains(*scope))
            {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    &format!("allowed_scopes contains a scope that was not requested: {unknown}"),
                ));
            }
            interaction
                .scopes
                .iter()
                .filter(|scope| allowed.iter().any(|candidate| candidate == *scope))
                .cloned()
                .collect()
        }
    };
    if approved.is_empty() {
        // Refusing every scope is the same decision as `deny`: the client gets `access_denied`
        // and no code is minted, so a refusal can never leave a partial grant behind.
        let interaction = state
            .consume_interaction(&tenant, &iid)
            .await
            .map_err(ApiError::Interaction)?;
        return Ok(Json(json!({
            "redirect_to": append_query(
                &interaction.redirect_uri,
                &[("error", "access_denied"), ("state", interaction.state.as_str())],
            )
        }))
        .into_response());
    }

    let (interaction, account_id, session_id) = state
        .take_signed_in_interaction(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    let account = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(account_id))
        .await?
        .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "account is gone"))?;

    approve_interaction(
        state,
        tenant,
        interaction,
        account,
        session_id,
        true,
        body.remember.unwrap_or(true),
        Some("interactive"),
        Some(&approved),
    )
    .await
}

/// Mint the authorization code for an approved interaction and return the client redirect.
///
/// `record_consent` is true only when the user actually answered the consent screen, so the
/// silent and stored-grant paths do not rewrite a grant that already exists. `approved_scopes`
/// narrows the code (and the recorded approval) to the scopes the account actually allowed;
/// `None` means the whole request.
#[allow(clippy::too_many_arguments)]
async fn approve_interaction(
    state: Arc<AppState>,
    tenant: TenantRow,
    interaction: Interaction,
    account: AccountRow,
    session_id: Option<Uuid>,
    record_consent: bool,
    remember: bool,
    audit_mode: Option<&str>,
    approved_scopes: Option<&[String]>,
) -> Result<Response, ApiError> {
    let scopes = approved_scopes.unwrap_or(&interaction.scopes);
    let org_slug = interaction.organization.clone();
    let org = state.store.org_by_slug(&tenant, &org_slug).await?;
    let existing = remember_consent(
        &state,
        &tenant,
        account.account_id(),
        interaction.client_row_id,
    )
    .await?;
    let new_scopes = consent_new_scopes(existing.as_ref(), scopes);
    let client = state
        .store
        .client_by_id(&tenant, interaction.client_row_id)
        .await?;

    // A standing approval belongs to third-party applications; `prompt=consent` on a first-party
    // client is a one-off confirmation, not something the account centre should list. A one-shot
    // decision is recorded so it can be listed and withdrawn, but it never covers a later request.
    if record_consent
        && client.as_ref().is_some_and(|client| client.is_third_party)
        && let Some(client) = client.as_ref()
    {
        let kind = if remember { "remember" } else { "one_shot" };
        let stored_scopes = if remember {
            merged_scopes(existing.as_ref(), scopes)
        } else {
            scopes.to_vec()
        };
        if let Err(err) = state
            .store
            .upsert_consent(
                &tenant,
                account.account_id(),
                interaction.client_row_id,
                &stored_scopes,
                kind,
                Some(&interaction.interaction_id.to_string()),
            )
            .await
        {
            tracing::warn!(%err, "could not record the consent grant");
        }
        if let Some(mode) = audit_mode {
            audit_consent_granted(
                &state,
                &tenant,
                account.account_id(),
                &client.client_id,
                &client.name,
                &new_scopes,
                remember,
                mode,
                Some(&interaction.interaction_id.to_string()),
            )
            .await;
        }
    } else if audit_mode == Some("silent")
        && client.as_ref().is_some_and(|client| client.is_third_party)
        && let Some(client) = client.as_ref()
    {
        audit_consent_granted(
            &state,
            &tenant,
            account.account_id(),
            &client.client_id,
            &client.name,
            scopes,
            true,
            "silent",
            Some(&interaction.interaction_id.to_string()),
        )
        .await;
    }
    // `auth_time` is the authentication instant, which is the session's creation when one exists.
    let auth_time = match session_id {
        Some(id) => state
            .store
            .session_by_id(&tenant, id)
            .await?
            .map(|row| row.issued_at)
            .unwrap_or_else(|| state.now()),
        None => state.now(),
    };

    let code = issue_code(
        &state,
        &tenant,
        interaction.client_row_id,
        account.id,
        org.id,
        &interaction.redirect_uri,
        scopes,
        &interaction.code_challenge,
        interaction.nonce.as_deref(),
        interaction.resource.as_deref(),
        session_id,
        interaction.dpop_jkt.as_deref(),
        auth_time,
        &interaction.client_id,
        false,
    )
    .await?;

    let redirect_to = append_query(
        &interaction.redirect_uri,
        &[
            ("code", code.as_str()),
            ("state", interaction.state.as_str()),
        ],
    );
    Ok(Json(json!({ "redirect_to": redirect_to })).into_response())
}

/// Record a consent decision — interactive or inherited silently — on the tenant chain.
///
/// `interaction_id` names the screen (or, for the session fast path, the interaction that recorded
/// the remembered grant), and a silent event also gets its own `authorization_id` so two silent
/// issuances under one remembered grant remain distinguishable.
#[allow(clippy::too_many_arguments)]
async fn audit_consent_granted(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account_id: AccountId,
    client_id: &str,
    client_name: &str,
    scopes: &[String],
    remember: bool,
    mode: &str,
    interaction_id: Option<&str>,
) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "consent.granted".into(),
        actor_chain: vec![AuditActor::account(account_id)],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "client_id": client_id,
            "name": client_name,
            "scopes": scopes,
            "remember": remember,
            "mode": mode,
            "interaction_id": interaction_id,
            "authorization_id": (mode == "silent").then(|| Uuid::now_v7().to_string()),
        }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append consent.granted audit event");
    }
}

/// Store a single-use authorization code and record the audit event.
///
/// Both paths use this: the interactive one (`approve_interaction`) and the silent SSO one in
/// `authorize`, which is why the session and its authentication instant are explicit parameters.
#[allow(clippy::too_many_arguments)]
async fn issue_code(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    client_row_id: Uuid,
    account_id: Uuid,
    org_id: Uuid,
    redirect_uri: &str,
    scopes: &[String],
    code_challenge: &str,
    nonce: Option<&str>,
    resource: Option<&str>,
    session_id: Option<Uuid>,
    dpop_jkt: Option<&str>,
    auth_time: OffsetDateTime,
    client_id: &str,
    sso: bool,
) -> Result<String, ApiError> {
    let code = issue_code_value();
    let code_hash = sha256_hex(&code);
    let now = state.now();
    state
        .store
        .insert_auth_code(
            tenant,
            &code_hash,
            client_row_id,
            account_id,
            org_id,
            redirect_uri,
            scopes,
            code_challenge,
            nonce,
            resource,
            session_id,
            dpop_jkt,
            auth_time,
            now + Duration::seconds(state.config.auth_code_ttl.as_secs() as i64),
        )
        .await?;

    let org = state
        .store
        .org_by_id(tenant, OrgId::from_uuid(org_id))
        .await?;
    let org_ctx = org.ctx(tenant);
    let event = AuditEvent {
        id: EventId::new(),
        at: now,
        action: "interaction.sign_in.succeeded".into(),
        actor_chain: vec![AuditActor::account(AccountId::from_uuid(account_id))],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(AccountId::from_uuid(account_id).to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "org": org.slug,
            "client_id": client_id,
            "sso": sso,
            "session_id": session_id.map(|id| id.to_string()),
        }),
    };
    if let Err(err) = state.audit_org(&org_ctx, &event).await {
        tracing::warn!(%err, "could not append sign-in.succeeded audit event");
    }

    Ok(code)
}

/// `POST /t/{tenant}/interaction/{iid}/abort`.
pub async fn abort(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let interaction = state
        .consume_interaction(&tenant, &iid)
        .await
        .map_err(ApiError::Interaction)?;
    Ok(Json(json!({
        "redirect_to": append_query(
            &interaction.redirect_uri,
            &[("error", "access_denied"), ("state", interaction.state.as_str())],
        )
    })))
}

/// `GET /t/{tenant}/oauth2/end-session` and its POST form — OpenID Connect RP-Initiated Logout.
pub async fn end_session(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    Query(params): Query<EndSessionParams>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    end_session_core(state, tenant_slug, params, headers).await
}

/// `POST /t/{tenant}/oauth2/end-session` — the spec allows either method.
pub async fn end_session_post(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    headers: HeaderMap,
    Form(params): Form<EndSessionParams>,
) -> Result<Response, ApiError> {
    end_session_core(state, tenant_slug, params, headers).await
}

/// The RP-initiated logout parameters (OpenID Connect RP-Initiated Logout 1.0 §2).
#[derive(Debug, Default, Deserialize)]
pub struct EndSessionParams {
    /// An id_token the OP issued to this client; identifies the client and the issuer.
    pub id_token_hint: Option<String>,
    /// Where to send the browser after logout. Must be registered for the client.
    pub post_logout_redirect_uri: Option<String>,
    /// Opaque client state, echoed onto the logout redirect.
    pub state: Option<String>,
    /// OAuth 2.0 `client_id`, when no hint is supplied.
    pub client_id: Option<String>,
}

async fn end_session_core(
    state: Arc<AppState>,
    tenant_slug: String,
    params: EndSessionParams,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;

    // Resolve the client from the hint when given, otherwise from `client_id`. The hint is verified
    // in full: its signature, its issuer, and that its audience names the client we will redirect
    // to. An unverifiable hint is a malformed request, never a reason to trust a redirect.
    let mut hint_client: Option<String> = None;
    if let Some(raw) = params
        .id_token_hint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (_, claims) = monaca_crypto::decode_unverified(raw)
            .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "id_token_hint is malformed"))?;
        if claims.get("iss").and_then(Value::as_str) != Some(tenant.issuer.as_str()) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "id_token_hint was issued by another issuer",
            ));
        }
        let aud = claims
            .get("aud")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ApiError::problem(kinds::INVALID_REQUEST, "id_token_hint has no audience")
            })?
            .to_owned();
        let jwks = state.jwks(&tenant).await?;
        monaca_crypto::verify_jws(raw, &jwks, "JWT").map_err(|_| {
            ApiError::problem(
                kinds::INVALID_REQUEST,
                "id_token_hint is not signed by this issuer",
            )
        })?;
        hint_client = Some(aud);
    }

    if let (Some(hint), Some(requested)) = (hint_client.as_deref(), params.client_id.as_deref())
        && hint != requested
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "client_id does not match the id_token",
        ));
    }
    let client_id = hint_client.or_else(|| params.client_id.clone());
    let client = match client_id.as_deref() {
        Some(id) => state.store.client_by_client_id(&tenant, id).await?,
        None => None,
    };

    // A logout redirect is only allowed to a registered target; otherwise the endpoint would be an
    // open redirector. When the parameter is absent the caller gets a small confirmation body.
    let redirect_to = match params
        .post_logout_redirect_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(uri) => {
            let client = client.as_ref().ok_or_else(|| {
                ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "post_logout_redirect_uri requires an identified client",
                )
            })?;
            let registered = state
                .store
                .client_post_logout_uris(&tenant, client.id)
                .await?;
            if !registered.iter().any(|candidate| candidate == uri) {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "post_logout_redirect_uri is not registered for this client",
                ));
            }
            Some(uri.to_owned())
        }
        None => None,
    };

    // End the browser's session, whether or not the caller named a client.
    if let Some(session_id) = session::session_id(&headers)
        && let Some(row) = state.store.session_by_id(&tenant, session_id).await?
        && state.store.revoke_session(&tenant, session_id).await?
    {
        // The account behind the session is the actor: §8.1 forbids an empty chain, and the
        // session row is the only place it can be read.
        let event = AuditEvent {
            id: EventId::new(),
            at: state.now(),
            action: "session.logout".into(),
            actor_chain: vec![AuditActor::account(AccountId::from_uuid(row.account_id))],
            subject: AuditSubject {
                subject_type: AuditActorType::Session,
                id: Some(monaca_types::SessionId::from_uuid(session_id).to_typed_string()),
            },
            decision: AuditDecision::Allow,
            grant_id: None,
            jti: None,
            payload: json!({ "client_id": client.as_ref().map(|c| c.client_id.clone()) }),
        };
        if let Err(err) = state.audit_tenant(&tenant, &event).await {
            tracing::warn!(%err, "could not append session.logout audit event");
        }
    }

    let mut response = match redirect_to {
        Some(uri) => {
            let location = match params.state.as_deref().filter(|value| !value.is_empty()) {
                Some(state_value) => append_query(&uri, &[("state", state_value)]),
                None => uri,
            };
            found(&location)
        }
        None => Json(json!({ "status": "logged_out" })).into_response(),
    };
    let secure = session::secure_origin(&state.config);
    if let Ok(value) = HeaderValue::from_str(&session::clear_cookie(secure)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(response)
}

/// `POST /t/{tenant}/oauth2/token`.
pub async fn token(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    headers: HeaderMap,
    client_ip: ClientIp,
    Form(form): Form<TokenForm>,
) -> Result<Response, ApiError> {
    state.enforce_ip_rate_limit(client_ip.0, "token").await?;
    let tenant = state.tenant(&tenant_slug).await?;
    let request = TokenRequest::parse(&form)
        .map_err(|code| ApiError::token(code, "the token request is malformed"))?;

    let basic = basic_auth(&headers);
    let client_id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| request.client_id.clone())
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidRequest, "client_id is required"))?;

    // Count before authentication: a client that keeps guessing a secret is still a client, and
    // the tenant-wide layer has to bound it. The client layer is keyed by the claimed id.
    state
        .enforce_rate_limit(&tenant, "token", Some(client_id.as_str()))
        .await?;

    let endpoint = state.config.token_endpoint(&tenant.slug);

    if client_id.starts_with("agt_") {
        return agent_token(state, tenant, request, client_id, basic).await;
    }

    let client = state
        .store
        .client_by_client_id(&tenant, &client_id)
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidClient, "unknown client"))?;

    // `client_secret_basic` carries the secret in the `Authorization` header, so anything sent in
    // the body is only a fallback for `client_secret_post`.
    let secret = basic
        .as_ref()
        .map(|(_, secret)| secret.clone())
        .or_else(|| request.client_secret.clone());

    authenticate_client(
        &state,
        &client,
        secret.as_deref(),
        request.client_assertion.as_deref(),
        &endpoint,
    )
    .await?;

    // After the caller is known to be the client, so an unauthenticated request cannot burn a
    // proof's `jti`.
    let dpop = verify_dpop(&state, &tenant, &headers, "POST", &endpoint, None).await?;

    match request.grant_type {
        GrantType::AuthorizationCode => {
            authorization_code_grant(state, tenant, request, client, &endpoint, dpop).await
        }
        GrantType::RefreshToken => {
            refresh_grant(state, tenant, request, client, &endpoint, dpop).await
        }
        GrantType::ClientCredentials => {
            client_credentials_grant(state, tenant, request, client, &endpoint, dpop).await
        }
    }
}

async fn authorization_code_grant(
    state: Arc<AppState>,
    tenant: TenantRow,
    request: TokenRequest,
    client: monaca_store::ClientRow,
    _endpoint: &str,
    dpop: Option<DpopProof>,
) -> Result<Response, ApiError> {
    let code = request.code.as_deref().unwrap_or_default();
    let code_hash = sha256_hex(code);
    let row = state
        .store
        .take_auth_code(&tenant, &code_hash)
        .await?
        .ok_or_else(|| {
            ApiError::token(TokenErrorCode::InvalidGrant, "code is invalid or expired")
        })?;

    if row.client_id != client.id {
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "code was issued to another client",
        ));
    }
    if Some(row.redirect_uri.as_str()) != request.redirect_uri.as_deref() {
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "redirect_uri does not match the code",
        ));
    }
    let verifier = request.code_verifier.as_deref().unwrap_or_default();
    if !verify_pkce_s256(verifier, &row.code_challenge) {
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "PKCE verification failed",
        ));
    }

    // RFC 9449 §9: the code's binding decides whether a proof is required. A code bound at the
    // authorization endpoint cannot be redeemed without proving the same key.
    let jkt = match (row.dpop_jkt.as_deref(), dpop.as_ref()) {
        (Some(bound), Some(proof)) if proof.jkt == bound => Some(bound.to_owned()),
        (Some(_), _) => {
            return Err(ApiError::token(
                TokenErrorCode::InvalidDpopProof,
                "the authorization code is bound to a different DPoP key",
            ));
        }
        (None, Some(proof)) => Some(proof.jkt.clone()),
        (None, None) => None,
    };

    let org = state
        .store
        .org_by_id(&tenant, OrgId::from_uuid(row.org_id))
        .await?;
    let account = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(row.account_id))
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidGrant, "account is gone"))?;

    let key = state.signing_key(&tenant).await?;
    let now = state.now().unix_timestamp();
    let access_exp = now + state.config.access_token_ttl.as_secs() as i64;
    let aud = row
        .resource
        .clone()
        .unwrap_or_else(|| tenant.issuer.clone());

    let claims = AccessTokenClaims {
        iss: tenant.issuer.clone(),
        sub: account.account_id().to_typed_string(),
        aud,
        tid: tenant.tenant_id().to_typed_string(),
        org: org.org_id().to_typed_string(),
        scope: row.scope.clone(),
        jti: Uuid::now_v7().to_string(),
        iat: now,
        exp: access_exp,
        act: None,
        grant_id: None,
        cnf: jkt.as_deref().map(binding),
    };
    let access_token = key
        .sign("at+jwt", &claims.to_json())
        .map_err(ApiError::internal)?;

    let id_token = if row.scope.iter().any(|scope| scope == "openid") {
        let id_claims = IdTokenClaims {
            iss: tenant.issuer.clone(),
            sub: account.account_id().to_typed_string(),
            aud: client.client_id.clone(),
            tid: tenant.tenant_id().to_typed_string(),
            org: org.org_id().to_typed_string(),
            iat: now,
            exp: now + state.config.id_token_ttl.as_secs() as i64,
            nonce: row.nonce.clone(),
            email: row
                .scope
                .iter()
                .any(|scope| scope == "email")
                .then(|| account.primary_email.clone()),
            name: row
                .scope
                .iter()
                .any(|scope| scope == "profile")
                .then(|| account.display_name.clone()),
            picture: row
                .scope
                .iter()
                .any(|scope| scope == "profile")
                .then(|| account.avatar_url.clone())
                .flatten(),
            auth_time: Some(row.auth_time.unix_timestamp()),
            at_hash: Some(at_hash(&access_token)),
            roles: state
                .store
                .account_roles(&tenant, account.account_id())
                .await?
                .into_iter()
                .map(|role| role.name)
                .collect(),
            org_roles: state
                .store
                .org_role_names(&tenant, org.org_id(), account.account_id())
                .await?,
        };
        Some(
            key.sign("JWT", &id_claims.to_json())
                .map_err(ApiError::internal)?,
        )
    } else {
        None
    };

    let refresh_token = if row.scope.iter().any(|scope| scope == "offline_access") {
        Some(
            issue_refresh(
                Arc::clone(&state),
                tenant,
                client.id,
                account.id,
                org.id,
                row.scope.clone(),
                row.resource.clone(),
                None,
                Uuid::now_v7(),
                jkt.clone(),
                row.auth_time,
            )
            .await?,
        )
    } else {
        None
    };

    let mut body = json!({
        "access_token": access_token,
        "token_type": token_type(&jkt),
        "expires_in": state.config.access_token_ttl.as_secs(),
        "scope": row.scope,
    });
    if let Some(id_token) = id_token {
        body["id_token"] = Value::String(id_token);
    }
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = Value::String(refresh_token);
    }
    Ok(Json(body).into_response())
}

async fn refresh_grant(
    state: Arc<AppState>,
    tenant: TenantRow,
    request: TokenRequest,
    client: monaca_store::ClientRow,
    _endpoint: &str,
    dpop: Option<DpopProof>,
) -> Result<Response, ApiError> {
    let raw = request.refresh_token.as_deref().unwrap_or_default();
    let hash = sha256_hex(raw);
    let row = state
        .store
        .refresh_by_hash(&tenant, &hash)
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidGrant, "refresh token is invalid"))?;

    if row.revoked_at.is_some() {
        // Reuse detection: a revoked token presented again kills the whole rotation family.
        let family = row.family_id.unwrap_or(row.id);
        state.store.revoke_refresh_family(&tenant, family).await?;
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "refresh token was already used",
        ));
    }
    if row.expires_at <= state.now() {
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "refresh token has expired",
        ));
    }
    if row.client_id != client.id {
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "refresh token was issued to another client",
        ));
    }

    // Suspension revokes the live refresh tokens, but a rotation that raced with the suspension
    // must not mint either: the account state is the authority.
    let account = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(row.account_id))
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidGrant, "account is gone"))?;
    if account.state != "active" {
        return Err(ApiError::token(
            TokenErrorCode::InvalidGrant,
            "account is disabled",
        ));
    }

    let scope = match request.scope {
        Some(requested) => {
            if !scope_subset(&requested, &row.scope) {
                return Err(ApiError::token(
                    TokenErrorCode::InvalidScope,
                    "requested scope exceeds the refresh token",
                ));
            }
            requested
        }
        None => row.scope.clone(),
    };

    // RFC 9449 §5: a token bound to a key may only be refreshed by proving that key. A refresh
    // that starts using DPoP binds the rotated tokens to the proof's key.
    monaca_oidc::check_binding(row.dpop_jkt.as_deref(), dpop.as_ref())
        .map_err(|err| ApiError::token(TokenErrorCode::InvalidDpopProof, err.to_string()))?;
    let jkt = row
        .dpop_jkt
        .clone()
        .or_else(|| dpop.as_ref().map(|proof| proof.jkt.clone()));

    let family = row.family_id.unwrap_or(row.id);
    state.store.revoke_refresh_token(&tenant, row.id).await?;
    let refresh_token = issue_refresh(
        Arc::clone(&state),
        tenant.clone(),
        client.id,
        row.account_id,
        row.org_id,
        scope.clone(),
        row.resource.clone(),
        Some(row.id),
        family,
        jkt.clone(),
        row.auth_time,
    )
    .await?;

    let org = state
        .store
        .org_by_id(&tenant, OrgId::from_uuid(row.org_id))
        .await?;
    let key = state.signing_key(&tenant).await?;
    let now = state.now().unix_timestamp();
    let aud = row
        .resource
        .clone()
        .unwrap_or_else(|| tenant.issuer.clone());

    let claims = AccessTokenClaims {
        iss: tenant.issuer.clone(),
        sub: AccountId::from_uuid(row.account_id).to_typed_string(),
        aud,
        tid: tenant.tenant_id().to_typed_string(),
        org: org.org_id().to_typed_string(),
        scope: scope.clone(),
        jti: Uuid::now_v7().to_string(),
        iat: now,
        exp: now + state.config.access_token_ttl.as_secs() as i64,
        act: None,
        grant_id: None,
        cnf: jkt.as_deref().map(binding),
    };
    let access_token = key
        .sign("at+jwt", &claims.to_json())
        .map_err(ApiError::internal)?;

    let id_token = if scope.iter().any(|scope| scope == "openid") {
        let id_claims = IdTokenClaims {
            iss: tenant.issuer.clone(),
            sub: account.account_id().to_typed_string(),
            aud: client.client_id.clone(),
            tid: tenant.tenant_id().to_typed_string(),
            org: org.org_id().to_typed_string(),
            iat: now,
            exp: now + state.config.id_token_ttl.as_secs() as i64,
            // The nonce belongs to the original authentication only.
            nonce: None,
            email: scope
                .iter()
                .any(|scope| scope == "email")
                .then(|| account.primary_email.clone()),
            name: scope
                .iter()
                .any(|scope| scope == "profile")
                .then(|| account.display_name.clone()),
            picture: scope
                .iter()
                .any(|scope| scope == "profile")
                .then(|| account.avatar_url.clone())
                .flatten(),
            auth_time: Some(row.auth_time.unix_timestamp()),
            at_hash: Some(at_hash(&access_token)),
            roles: state
                .store
                .account_roles(&tenant, account.account_id())
                .await?
                .into_iter()
                .map(|role| role.name)
                .collect(),
            org_roles: state
                .store
                .org_role_names(&tenant, org.org_id(), account.account_id())
                .await?,
        };
        Some(
            key.sign("JWT", &id_claims.to_json())
                .map_err(ApiError::internal)?,
        )
    } else {
        None
    };

    let mut body = json!({
        "access_token": access_token,
        "token_type": token_type(&jkt),
        "expires_in": state.config.access_token_ttl.as_secs(),
        "scope": scope,
        "refresh_token": refresh_token,
    });
    if let Some(id_token) = id_token {
        body["id_token"] = Value::String(id_token);
    }
    Ok(Json(body).into_response())
}

async fn client_credentials_grant(
    state: Arc<AppState>,
    tenant: TenantRow,
    request: TokenRequest,
    client: monaca_store::ClientRow,
    _endpoint: &str,
    dpop: Option<DpopProof>,
) -> Result<Response, ApiError> {
    let requested = request.scope.clone().unwrap_or_default();
    if !requested.is_empty() && !scope_subset(&requested, &client.scopes) {
        return Err(ApiError::token(
            TokenErrorCode::InvalidScope,
            "requested scope exceeds the client's registration",
        ));
    }
    let scope = if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    };

    let org = state.org(&tenant, None).await?;
    // The management API's audience is the one every automation token needs; anything else must
    // name its resource explicitly (RFC 8707).
    let aud = request.resource.clone().unwrap_or_else(|| {
        if scope.iter().any(|scope| scope == "monaca:admin") {
            state.config.management_audience()
        } else {
            tenant.issuer.clone()
        }
    });

    let key = state.signing_key(&tenant).await?;
    let now = state.now().unix_timestamp();
    let jkt = dpop.as_ref().map(|proof| proof.jkt.clone());
    let claims = AccessTokenClaims {
        iss: tenant.issuer.clone(),
        sub: ClientId::from_uuid(client.id).to_typed_string(),
        aud,
        tid: tenant.tenant_id().to_typed_string(),
        org: org.org_id().to_typed_string(),
        scope: scope.clone(),
        jti: Uuid::now_v7().to_string(),
        iat: now,
        exp: now + state.config.access_token_ttl.as_secs() as i64,
        act: None,
        grant_id: None,
        cnf: jkt.as_deref().map(binding),
    };
    let access_token = key
        .sign("at+jwt", &claims.to_json())
        .map_err(ApiError::internal)?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": token_type(&jkt),
        "expires_in": state.config.access_token_ttl.as_secs(),
        "scope": scope,
    }))
    .into_response())
}

async fn agent_token(
    state: Arc<AppState>,
    tenant: TenantRow,
    request: TokenRequest,
    client_id: String,
    basic: Option<(String, String)>,
) -> Result<Response, ApiError> {
    if request.grant_type != GrantType::ClientCredentials {
        return Err(ApiError::token(
            TokenErrorCode::UnauthorizedClient,
            "an agent may only use client_credentials",
        ));
    }
    if basic.is_some() {
        return Err(ApiError::token(
            TokenErrorCode::InvalidClient,
            "an agent authenticates with private_key_jwt only",
        ));
    }

    let agent_id = AgentId::parse(&client_id)
        .map_err(|_| ApiError::token(TokenErrorCode::InvalidClient, "unknown agent"))?;
    let org = state
        .store
        .org_of_agent(&tenant, agent_id)
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidClient, "unknown agent"))?;
    let org_ctx = org.ctx(&tenant);

    // Authenticate: the assertion must verify against one of the agent's registered keys.
    let assertion = request.client_assertion.as_deref().ok_or_else(|| {
        ApiError::token(
            TokenErrorCode::InvalidClient,
            "client_assertion is required",
        )
    })?;
    let mut tx = state.store.begin_org(&org_ctx).await?;
    let keys = state.store.agent_keys(&mut *tx, agent_id).await?;
    tx.rollback().await?;
    let jwks: Vec<Value> = keys
        .iter()
        .filter(|key| key.revoked_at.is_none())
        .map(|key| key.public_jwk.clone())
        .collect();
    if jwks.is_empty() {
        return Err(ApiError::token(
            TokenErrorCode::InvalidClient,
            "agent has no active key",
        ));
    }
    let claims = monaca_crypto::verify_jws(assertion, &jwks, "JWT").map_err(|err| {
        ApiError::token(
            TokenErrorCode::InvalidClient,
            format!("client assertion: {err}"),
        )
    })?;
    let endpoint = state.config.token_endpoint(&tenant.slug);
    monaca_oidc::validate_assertion_claims(
        &claims,
        &client_id,
        &endpoint,
        state.now().unix_timestamp(),
    )
    .map_err(|err| ApiError::token(TokenErrorCode::InvalidClient, err.to_string()))?;

    let grant_id = request
        .grant_id_from_details()
        .ok_or_else(|| {
            ApiError::token(
                TokenErrorCode::InvalidRequest,
                "authorization_details must name a monaca_grant",
            )
        })
        .and_then(|raw| {
            GrantId::parse(raw).map_err(|_| {
                ApiError::token(TokenErrorCode::InvalidRequest, "grant_id is not a grant id")
            })
        })?;

    let requested = request.scope.clone().unwrap_or_default();
    let denied = |detail: &str| ApiError::token(TokenErrorCode::InvalidScope, detail.to_owned());

    let mut tx = state.store.begin_org(&org_ctx).await?;
    let grant = state.store.grant(&mut *tx, grant_id).await?;
    tx.rollback().await?;
    let grant = grant.ok_or_else(|| denied("grant does not exist"))?;

    if grant.agent_id != agent_id.uuid() {
        return Err(denied("grant does not belong to this agent"));
    }
    if grant.revoked_at.is_some() {
        return Err(ApiError::Problem(monaca_types::Problem::new(
            kinds::GRANT_REVOKED,
            format!("grant {} was revoked", grant_id),
        )));
    }
    if let Some(expires_at) = grant.expires_at {
        if expires_at <= state.now() {
            return Err(denied("grant has expired"));
        }
    }

    let requested_scopes = if requested.is_empty() {
        grant.scopes.clone()
    } else {
        requested
    };

    let now = state.now();
    let ttl_expiry = now + Duration::seconds(monaca_agent::DELEGATED_TOKEN_TTL_SECS);
    let child_expiry = match grant.expires_at {
        Some(grant_expiry) if grant_expiry < ttl_expiry => grant_expiry,
        _ => ttl_expiry,
    };
    let aud = request
        .resource
        .clone()
        .unwrap_or_else(|| grant.resource.clone());

    // The attenuation algebra is the single authority on what a hop may narrow to (§7.2).
    let parent = Permission {
        scopes: grant.scopes.clone(),
        resource: grant.resource.clone(),
        expires_at: grant.expires_at,
    };
    let child = Permission {
        scopes: requested_scopes,
        resource: aud.clone(),
        expires_at: Some(child_expiry),
    };
    let narrowed = attenuate(&parent, &child)
        .map_err(|err| ApiError::token(TokenErrorCode::InvalidScope, err.to_string()))?;

    let key = state.signing_key(&tenant).await?;
    let claims = AccessTokenClaims {
        iss: tenant.issuer.clone(),
        sub: AccountId::from_uuid(grant.account_id).to_typed_string(),
        aud: narrowed.resource,
        tid: tenant.tenant_id().to_typed_string(),
        org: org.org_id().to_typed_string(),
        scope: narrowed.scopes.clone(),
        jti: Uuid::now_v7().to_string(),
        iat: now.unix_timestamp(),
        exp: child_expiry.unix_timestamp(),
        act: Some(json!({ "sub": agent_id.to_typed_string() })),
        grant_id: Some(grant_id.to_typed_string()),
        cnf: None,
    };
    let access_token = key
        .sign("at+jwt", &claims.to_json())
        .map_err(ApiError::internal)?;

    let event = AuditEvent {
        id: EventId::new(),
        at: now,
        action: "agent.token.issued".into(),
        actor_chain: vec![
            AuditActor::account(AccountId::from_uuid(grant.account_id)),
            AuditActor::agent(agent_id),
        ],
        subject: AuditSubject {
            subject_type: AuditActorType::Grant,
            id: Some(grant_id.to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: Some(grant_id),
        jti: Uuid::parse_str(&claims.jti).ok(),
        payload: json!({ "scope": narrowed.scopes, "aud": claims.aud }),
    };
    if let Err(err) = state.audit_org(&org_ctx, &event).await {
        tracing::warn!(%err, "could not append token.issued audit event");
    }

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": monaca_agent::DELEGATED_TOKEN_TTL_SECS,
        "scope": narrowed.scopes,
    }))
    .into_response())
}

#[allow(clippy::too_many_arguments)]
async fn issue_refresh(
    state: Arc<AppState>,
    tenant: TenantRow,
    client_row_id: Uuid,
    account_id: Uuid,
    org_id: Uuid,
    scope: Vec<String>,
    resource: Option<String>,
    rotated_from: Option<Uuid>,
    family_id: Uuid,
    dpop_jkt: Option<String>,
    auth_time: OffsetDateTime,
) -> Result<String, ApiError> {
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let hash = sha256_hex(&token);
    let refresh_ttl_secs = (state
        .store
        .sign_in_experience(&tenant)
        .await?
        .refresh_token_ttl_secs
        .max(60) as u64)
        .min(state.config.refresh_token_ttl.as_secs());
    state
        .store
        .insert_refresh_token(
            &tenant,
            &hash,
            client_row_id,
            account_id,
            org_id,
            &scope,
            resource.as_deref(),
            rotated_from,
            family_id,
            dpop_jkt.as_deref(),
            auth_time,
            state.now() + Duration::seconds(refresh_ttl_secs as i64),
        )
        .await?;
    Ok(token)
}

/// Authenticate a client at a token-like endpoint — §7.4.
pub(crate) async fn authenticate_client(
    state: &Arc<AppState>,
    client: &monaca_store::ClientRow,
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    endpoint: &str,
) -> Result<(), ApiError> {
    match client.token_auth_method.as_str() {
        "none" => Ok(()),
        "client_secret_basic" | "client_secret_post" => {
            let secret = client_secret.ok_or_else(|| {
                ApiError::token(TokenErrorCode::InvalidClient, "client_secret is required")
            })?;
            check_secret(state, client, secret).await
        }
        "private_key_jwt" => {
            let assertion = client_assertion.ok_or_else(|| {
                ApiError::token(
                    TokenErrorCode::InvalidClient,
                    "client_assertion is required",
                )
            })?;
            let jwks = client
                .jwks
                .as_ref()
                .and_then(|value| value.get("keys"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if jwks.is_empty() {
                return Err(ApiError::token(
                    TokenErrorCode::InvalidClient,
                    "client has no registered key",
                ));
            }
            let claims = monaca_crypto::verify_jws(assertion, &jwks, "JWT").map_err(|err| {
                ApiError::token(
                    TokenErrorCode::InvalidClient,
                    format!("client assertion: {err}"),
                )
            })?;
            monaca_oidc::validate_assertion_claims(
                &claims,
                &client.client_id,
                endpoint,
                state.now().unix_timestamp(),
            )
            .map_err(|err| ApiError::token(TokenErrorCode::InvalidClient, err.to_string()))?;
            Ok(())
        }
        other => Err(ApiError::token(
            TokenErrorCode::InvalidClient,
            format!("unsupported token auth method `{other}`"),
        )),
    }
}

async fn check_secret(
    state: &Arc<AppState>,
    client: &monaca_store::ClientRow,
    secret: &str,
) -> Result<(), ApiError> {
    let phc = client
        .secret_hash
        .as_deref()
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidClient, "client has no secret"))?;
    verify_password(secret.to_owned(), phc.to_owned(), state.argon)
        .await
        .map_err(|_| ApiError::token(TokenErrorCode::InvalidClient, "invalid client secret"))
}

/// Verify the request's `DPoP` header, if any, and record its `jti` against replay.
///
/// `access_token` is `Some` only for resource requests, where RFC 9449 §7.1 requires `ath`.
pub(crate) async fn verify_dpop(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    headers: &HeaderMap,
    method: &str,
    url: &str,
    access_token: Option<&str>,
) -> Result<Option<DpopProof>, ApiError> {
    let Some(raw) = headers.get("dpop").and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let proof =
        monaca_oidc::verify_proof(raw, method, url, access_token, state.now().unix_timestamp())
            .map_err(|err| ApiError::token(TokenErrorCode::InvalidDpopProof, err.to_string()))?;

    let expires_at = state.now() + Duration::seconds(monaca_oidc::PROOF_WINDOW_SECS);
    if !state
        .store
        .dpop_replay_add(tenant, &proof.jti, expires_at)
        .await?
    {
        return Err(ApiError::token(
            TokenErrorCode::InvalidDpopProof,
            "the DPoP proof was already used",
        ));
    }
    Ok(Some(proof))
}

/// The RFC 7800 `cnf` claim for a DPoP-bound token.
fn binding(jkt: &str) -> Value {
    json!({ "jkt": jkt })
}

/// RFC 9449 §5: a DPoP-bound token is `token_type` `DPoP`.
fn token_type(jkt: &Option<String>) -> &'static str {
    if jkt.is_some() { "DPoP" } else { "Bearer" }
}

fn sign_in_event(
    at: OffsetDateTime,
    org: &OrgId,
    decision: AuditDecision,
    email: &str,
    reason: &str,
) -> AuditEvent {
    AuditEvent {
        id: EventId::new(),
        at,
        action: "interaction.sign_in.failed".into(),
        actor_chain: vec![AuditActor::org(*org)],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: None,
        },
        decision,
        grant_id: None,
        jti: None,
        payload: json!({ "email": email, "reason": reason }),
    }
}

fn issue_code_value() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub(crate) fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Parse HTTP Basic credentials into `(client_id, secret)`.
pub(crate) fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_owned(), secret.to_owned()))
}

pub(crate) fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::from(base);
    let mut first = !base.contains('?');
    for (name, value) in params {
        out.push(if first { '?' } else { '&' });
        first = false;
        out.push_str(name);
        out.push('=');
        out.push_str(&percent_encode(value));
    }
    out
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn found(location: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, location.to_owned())]).into_response()
}

fn redirect_error(redirect_uri: &str, error: &str, state: &str) -> Response {
    found(&append_query(
        redirect_uri,
        &[("error", error), ("state", state)],
    ))
}
