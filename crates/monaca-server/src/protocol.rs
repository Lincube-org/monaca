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
    hash_password, hash_secret, normalize_backup_code, open, verify_assertion, verify_password,
    verify_secret, verify_totp,
};
use monaca_oidc::{
    AccessTokenClaims, AuthorizeParams, DiscoveryDocument, DpopProof, GrantType, IdTokenClaims,
    Interaction, TokenErrorCode, TokenForm, TokenRequest, at_hash, scope_subset, verify_pkce_s256,
};
use monaca_store::{AccountRow, OrgRow, PasskeyRow, TenantRow, topics};
use monaca_types::{AccountId, AgentId, ClientId, EventId, GrantId, InteractionId, OrgId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

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

/// `GET /t/{tenant}/sign-in-experience` — the hosted switches the page applies before rendering.
///
/// Public like the connector list: the sign-in page must know which forms to offer before anyone
/// is signed in, and these switches disclose nothing about accounts.
pub async fn sign_in_experience(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::problem(kinds::NOT_FOUND, "tenant is not active"));
    }
    let experience = state.store.sign_in_experience(&tenant).await?;
    Ok(Json(json!({
        "sign_up_enabled": experience.sign_up_enabled,
        "password_sign_in_enabled": experience.password_sign_in_enabled,
        "email_code_sign_in_enabled": experience.email_code_sign_in_enabled,
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
) -> Result<Response, ApiError> {
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

    if let Some(session) = session {
        // A disabled account must not keep riding an old session.
        if let Some(account) = state
            .store
            .account_by_id(&tenant, AccountId::from_uuid(session.account_id))
            .await?
            .filter(|account| account.state == "active")
        {
            if request.requires_consent(client.is_third_party) {
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
                let interaction = build_interaction(&state, &tenant, &client, &request, &org, true);
                state
                    .mark_interaction_signed_in(
                        &interaction.interaction_id.to_string(),
                        account.id,
                        session.id,
                    )
                    .await
                    .map_err(ApiError::Interaction)?;
                return Ok(found(&sign_in_location(&state, &tenant, &interaction)));
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

    let interaction = build_interaction(&state, &tenant, &client, &request, &org, false);
    let location = sign_in_location(&state, &tenant, &interaction);
    state.put_interaction(interaction).await;
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
        expires_at: state.now() + Duration::seconds(state.config.interaction_ttl.as_secs() as i64),
    }
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
    Path((_tenant, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (interaction, signed_in) = state
        .peek_interaction_state(&iid)
        .await
        .map_err(ApiError::Interaction)?;
    let pending = state
        .mfa_pending(&iid)
        .await
        .map_err(ApiError::Interaction)?;
    let mut body = interaction.to_public_json(signed_in.is_some());
    body["mfa_required"] = json!(pending.is_some());
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
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in`.
pub async fn sign_in(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SignInBody>,
) -> Result<Response, ApiError> {
    let interaction = state
        .peek_interaction(&iid)
        .await
        .map_err(ApiError::Interaction)?;
    let tenant = state.tenant(&interaction.tenant).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .password_sign_in_enabled
    {
        return Err(ApiError::problem(
            kinds::PASSWORD_SIGN_IN_DISABLED,
            "password sign-in is disabled for this tenant",
        ));
    }
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
        .account_by_identifier(&tenant, identifier)
        .await?;

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
async fn check_scope_grants(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account: &AccountRow,
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
    if let Some(scope) = scopes.iter().find(|scope| {
        !UNGOVERNED_SCOPES.iter().any(|allowed| allowed == *scope)
            && !roles.iter().any(|role| {
                role.permissions
                    .iter()
                    .any(|permission| permission == *scope)
            })
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
    check_scope_grants(&state, &tenant, &account, &interaction.scopes).await?;
    if state
        .store
        .totp_secret(&tenant, account.account_id())
        .await?
        .is_some()
    {
        // A browser this account chose to remember skips the second factor until it is revoked or
        // expires (§6.1 `mfa`). The cookie is per tenant and the row names the account, so a stale
        // trust from another account does nothing.
        if let Some(token) = session::trusted_device_token(headers)
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
            .mark_mfa_pending(iid, account.id)
            .await
            .map_err(ApiError::Interaction)?;
        let factors = mfa_factors(&state, &tenant, account.id).await?;
        return Ok(Json(json!({
            "mfa_required": true,
            "factors": factors,
        }))
        .into_response());
    }
    complete_sign_in(state, tenant, interaction, iid, headers, account).await
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

    // The account must be a member of the org the flow issues into.
    let mut tx = state.store.begin_org(&org_ctx).await?;
    let role = state
        .store
        .org_member_role(&mut *tx, account.account_id())
        .await?;
    tx.rollback().await?;
    if role.is_none() {
        return Err(ApiError::problem(
            kinds::INSUFFICIENT_SCOPE,
            format!("account is not a member of `{org_slug}`"),
        ));
    }

    // Establish (or reuse) the cross-application session before the code is minted, so the browser
    // leaves sign-in with the SSO cookie and the next application skips the password page.
    let session_id = establish_session(
        &state,
        &tenant,
        headers,
        &account,
        interaction.client_row_id,
    )
    .await?;

    // A third-party client (or `prompt=consent`) pauses here: the page must ask the user to
    // approve the scopes before a code is minted. Sign-in is recorded but not consumed, so the
    // consent step can redeem it.
    if interaction.consent_required {
        state
            .mark_interaction_signed_in(iid, account.id, session_id)
            .await
            .map_err(ApiError::Interaction)?;
        let response = Json(json!({ "consent_required": true })).into_response();
        return Ok(with_session_cookie(response, session_id, &state));
    }

    // Consume only after authentication succeeds, so a typo does not burn the interaction.
    let interaction = state
        .consume_interaction(iid)
        .await
        .map_err(ApiError::Interaction)?;

    let response = approve_interaction(
        state.clone(),
        tenant,
        interaction,
        account,
        Some(session_id),
    )
    .await?;
    Ok(with_session_cookie(response, session_id, &state))
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

/// Reject a password shorter than the contract's minimum.
pub(crate) fn check_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::problem(
            kinds::WEAK_PASSWORD,
            format!("password must be at least {MIN_PASSWORD_LEN} characters"),
        ));
    }
    Ok(())
}

/// The shortest and longest accepted username, in characters.
const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 32;

/// Validate and normalise a username (§6.1).
///
/// It is a sign-in identifier, so it may not contain `@` (that is how the sign-in endpoint tells the
/// two namespaces apart) and it is stored lowercased, matching the case-insensitive unique index.
pub(crate) fn check_username(raw: &str) -> Result<String, ApiError> {
    let username = raw.trim().to_lowercase();
    let length = username.chars().count();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&length)
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!(
                "username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} letters, digits, `_` or `-`"
            ),
        ));
    }
    Ok(username)
}

/// The interaction and its tenant, or the interaction error the page should render.
async fn interaction_and_tenant(
    state: &Arc<AppState>,
    iid: &str,
) -> Result<(Interaction, TenantRow), ApiError> {
    let interaction = state
        .peek_interaction(iid)
        .await
        .map_err(ApiError::Interaction)?;
    let tenant = state.tenant(&interaction.tenant).await?;
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

/// `POST /t/{tenant}/interaction/{iid}/sign-up` — start self-service registration.
pub async fn sign_up(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (_interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .sign_up_enabled
    {
        return Err(ApiError::problem(
            kinds::SIGN_UP_DISABLED,
            "self-service sign-up is disabled for this tenant",
        ));
    }
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
    request_verification(&state, &tenant, PURPOSE_SIGN_UP, &email).await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-up/verify` — prove the address and sign in.
pub async fn sign_up_verify(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SignUpVerifyBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .sign_up_enabled
    {
        return Err(ApiError::problem(
            kinds::SIGN_UP_DISABLED,
            "self-service sign-up is disabled for this tenant",
        ));
    }
    let email = normalise_email(&body.email)?;
    check_password(&body.password)?;
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
    let username = body.username.as_deref().map(check_username).transpose()?;

    let phc = hash_password(body.password.clone(), state.argon)
        .await
        .map_err(ApiError::internal)?;
    let display_name = body
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| email.split('@').next().unwrap_or(&email).to_owned());
    let account = state
        .store
        .create_account(
            &tenant,
            AccountId::new(),
            &email,
            &display_name,
            Some(&phc),
            false,
            username.as_deref(),
        )
        .await?;

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

    finish_sign_in(state, tenant, interaction, &iid, &headers, account).await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/code` — request a passwordless sign-in code.
pub async fn sign_in_code(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (_interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
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
    request_verification(&state, &tenant, PURPOSE_SIGN_IN, &email).await
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in/code/verify`.
pub async fn sign_in_code_verify(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<CodeVerifyBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
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
    Path((_tenant, iid)): Path<(String, String)>,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (_interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
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
    let mut tx = state.store.begin_tenant(&tenant).await?;
    state
        .store
        .outbox_append(
            &mut *tx,
            topics::MAIL,
            &json!({
                "to": email,
                "purpose": PURPOSE_SIGN_IN_LINK,
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
        .peek_interaction(&iid)
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
    Path((_tenant, iid)): Path<(String, String)>,
    Json(body): Json<EmailBody>,
) -> Result<Json<Value>, ApiError> {
    let (_interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .password_sign_in_enabled
    {
        return Err(ApiError::problem(
            kinds::PASSWORD_SIGN_IN_DISABLED,
            "password sign-in is disabled for this tenant",
        ));
    }
    let email = normalise_email(&body.email)?;
    request_verification(&state, &tenant, PURPOSE_PASSWORD_RESET, &email).await
}

/// `POST /t/{tenant}/interaction/{iid}/password/reset` — prove the address, set a new password.
pub async fn password_reset(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PasswordResetBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .password_sign_in_enabled
    {
        return Err(ApiError::problem(
            kinds::PASSWORD_SIGN_IN_DISABLED,
            "password sign-in is disabled for this tenant",
        ));
    }
    let email = normalise_email(&body.email)?;
    check_password(&body.password)?;
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
    /// Ask the server to remember this browser for thirty days once the factor is accepted.
    #[serde(default)]
    pub remember_device: bool,
}

/// How long a remembered browser may skip the second factor.
const TRUSTED_DEVICE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Mint a trust for this browser and return the cookie that carries it.
///
/// Only the SHA-256 of the token is stored; the cookie is the one place the token exists in
/// plaintext, and it is per tenant and HttpOnly.
async fn issue_trusted_device(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    account: &AccountRow,
    headers: &HeaderMap,
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
            state.now() + Duration::seconds(TRUSTED_DEVICE_TTL_SECS as i64),
        )
        .await?;
    let secure = session::secure_origin(&state.config);
    HeaderValue::from_str(&session::set_device_cookie(
        &token,
        TRUSTED_DEVICE_TTL_SECS,
        secure,
        &tenant.slug,
    ))
    .map_err(ApiError::internal)
}

/// Refuse a second-factor attempt, counting it against the interaction's limit.
///
/// Both factors share one counter: trying five backup codes must not leave the TOTP form with a
/// fresh budget.
async fn refuse_mfa_code(state: &AppState, iid: &str) -> Result<ApiError, ApiError> {
    let attempts = state
        .record_mfa_failure(iid)
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
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
    let Some(account_id) = state
        .mfa_pending(&iid)
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
        return Err(refuse_mfa_code(&state, &iid).await?);
    };
    if account.state != "active" {
        return Err(refuse_mfa_code(&state, &iid).await?);
    }

    match body.factor.as_deref().unwrap_or("totp") {
        "totp" => {
            let Some(sealed) = state
                .store
                .totp_secret(&tenant, account.account_id())
                .await?
            else {
                return Err(refuse_mfa_code(&state, &iid).await?);
            };
            let dek = state.tenant_dek(&tenant)?;
            let secret = open(&dek, &sealed)
                .map_err(|err| ApiError::internal(format!("totp secret: {err}")))?;

            if !verify_totp(&secret, &body.code, state.now()) {
                return Err(refuse_mfa_code(&state, &iid).await?);
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
                return Err(refuse_mfa_code(&state, &iid).await?);
            };
            if !state
                .store
                .consume_backup_code(&tenant, account.account_id(), &hash)
                .await?
            {
                return Err(refuse_mfa_code(&state, &iid).await?);
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
        .clear_mfa_pending(&iid)
        .await
        .map_err(ApiError::Interaction)?;

    let trust = if body.remember_device {
        Some(issue_trusted_device(&state, &tenant, &account, &headers).await?)
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
    iid: &str,
) -> Result<(Interaction, TenantRow), ApiError> {
    let (interaction, tenant) = interaction_and_tenant(state, iid).await?;
    let (_, signed_in) = state
        .peek_interaction_state(iid)
        .await
        .map_err(ApiError::Interaction)?;
    if signed_in.is_some() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is already signed in",
        ));
    }
    if state
        .mfa_pending(iid)
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
    Path((_tenant, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    passkey_sign_in_interaction(&state, &iid).await?;
    let rp = crate::passkey::relying_party(&state.config)?;
    let challenge = generate_challenge();
    state
        .put_passkey_challenge(
            format!("in:{iid}"),
            challenge.clone(),
            state.now() + Duration::seconds(crate::passkey::CHALLENGE_TTL_SECS),
        )
        .await;
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
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<crate::passkey::CeremonyBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = passkey_sign_in_interaction(&state, &iid).await?;
    let Some(challenge) = state.take_passkey_challenge(&format!("in:{iid}")).await else {
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
    Path((_tenant, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (_, tenant) = interaction_and_tenant(&state, &iid).await?;
    let Some(account_id) = state
        .mfa_pending(&iid)
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
            format!("mfa:{iid}"),
            challenge.clone(),
            state.now() + Duration::seconds(crate::passkey::CHALLENGE_TTL_SECS),
        )
        .await;
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
    Path((_tenant, iid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<crate::passkey::CeremonyBody>,
) -> Result<Response, ApiError> {
    let (interaction, tenant) = interaction_and_tenant(&state, &iid).await?;
    let Some(account_id) = state
        .mfa_pending(&iid)
        .await
        .map_err(ApiError::Interaction)?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this interaction is not waiting for a second factor",
        ));
    };

    let Some(challenge) = state.take_passkey_challenge(&format!("mfa:{iid}")).await else {
        return Err(refuse_mfa_code(&state, &iid).await?);
    };
    let Some(assertion) = crate::passkey::parse_assertion(&body) else {
        return Err(refuse_mfa_code(&state, &iid).await?);
    };
    let Some(account) = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(account_id))
        .await?
    else {
        return Err(refuse_mfa_code(&state, &iid).await?);
    };
    if account.state != "active" {
        return Err(refuse_mfa_code(&state, &iid).await?);
    }
    let Some(row) = state
        .store
        .passkey_by_credential_id(&tenant, &assertion.credential_id)
        .await?
    else {
        return Err(refuse_mfa_code(&state, &iid).await?);
    };
    // The credential must belong to the account this interaction is proving; otherwise a valid
    // passkey of a different account would satisfy the challenge.
    if row.account_id != account.id {
        return Err(refuse_mfa_code(&state, &iid).await?);
    }
    if let Some(handle) = assertion.user_handle.as_deref()
        && !Uuid::from_slice(handle).is_ok_and(|handle| handle == account.id)
    {
        return Err(refuse_mfa_code(&state, &iid).await?);
    }

    let rp = crate::passkey::relying_party(&state.config)?;
    let Some(sign_count) =
        verify_passkey_assertion(&state, &tenant, &row, &assertion, &challenge, &rp)?
    else {
        return Err(refuse_mfa_code(&state, &iid).await?);
    };
    record_passkey_counter(&state, &tenant, &row, sign_count).await?;

    state
        .clear_mfa_pending(&iid)
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
            now + Duration::seconds(state.config.session_ttl.as_secs() as i64),
            user_agent,
        )
        .await?;
    Ok(id)
}

/// Attach the SSO cookie to a sign-in response.
fn with_session_cookie(mut response: Response, session_id: Uuid, state: &AppState) -> Response {
    let secure = session::secure_origin(&state.config);
    let value = session::set_cookie(session_id, state.config.session_ttl.as_secs(), secure);
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
}

/// `POST /t/{tenant}/interaction/{iid}/consent` — the second half of the login/consent challenge.
pub async fn consent(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    Json(body): Json<ConsentBody>,
) -> Result<Response, ApiError> {
    if body.decision != "allow" {
        if body.decision != "deny" {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "decision must be `allow` or `deny`",
            ));
        }
        let interaction = state
            .consume_interaction(&iid)
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
        .take_signed_in_interaction(&iid)
        .await
        .map_err(ApiError::Interaction)?;
    let tenant = state.tenant(&interaction.tenant).await?;
    let account = state
        .store
        .account_by_id(&tenant, AccountId::from_uuid(account_id))
        .await?
        .ok_or_else(|| ApiError::problem(kinds::INVALID_REQUEST, "account is gone"))?;

    approve_interaction(state, tenant, interaction, account, session_id).await
}

/// Mint the authorization code for an approved interaction and return the client redirect.
async fn approve_interaction(
    state: Arc<AppState>,
    tenant: TenantRow,
    interaction: Interaction,
    account: AccountRow,
    session_id: Option<Uuid>,
) -> Result<Response, ApiError> {
    let org_slug = interaction.organization.clone();
    let org = state.store.org_by_slug(&tenant, &org_slug).await?;
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
        &interaction.scopes,
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
    Path((_tenant, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let interaction = state
        .consume_interaction(&iid)
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
    Form(form): Form<TokenForm>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let request = TokenRequest::parse(&form)
        .map_err(|code| ApiError::token(code, "the token request is malformed"))?;

    let basic = basic_auth(&headers);
    let client_id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| request.client_id.clone())
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidRequest, "client_id is required"))?;

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
            auth_time: Some(row.auth_time.unix_timestamp()),
            at_hash: Some(at_hash(&access_token)),
            roles: state
                .store
                .account_roles(&tenant, account.account_id())
                .await?
                .into_iter()
                .map(|role| role.name)
                .collect(),
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
            auth_time: Some(row.auth_time.unix_timestamp()),
            at_hash: Some(at_hash(&access_token)),
            roles: state
                .store
                .account_roles(&tenant, account.account_id())
                .await?
                .into_iter()
                .map(|role| role.name)
                .collect(),
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
            state.now() + Duration::seconds(state.config.refresh_token_ttl.as_secs() as i64),
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
