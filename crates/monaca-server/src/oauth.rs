//! The OAuth 2.0 resource endpoints — UserInfo, introspection, revocation and PAR.
//!
//! These are the endpoints a *resource* talks to, as opposed to `protocol.rs` which is the
//! browser-facing flow. Two rules shape the module:
//!
//! - the token endpoints authenticate the *client* (`client_secret_basic`, `client_secret_post`,
//!   `private_key_jwt`), reusing [`crate::protocol::authenticate_client`] so the four auth methods
//!   stay in one place;
//! - a rejected caller is answered per RFC 6750 (`WWW-Authenticate: Bearer`), not with an RFC 9457
//!   problem document.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use monaca_oidc::{AuthorizeParams, DpopProof, TokenErrorCode, UserInfoClaims, scope_subset};
use monaca_store::{ClientRow, TenantRow};
use monaca_types::{AccountId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::ApiError;
use crate::protocol::{authenticate_client, basic_auth, sha256_hex};
use crate::state::AppState;

/// `GET /t/{tenant}/oauth2/userinfo` — OpenID Connect Core §5.3.
pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let token = resource_token(&headers)?;

    let jwks = state.jwks(&tenant).await?;
    let claims = monaca_crypto::verify_jws(token, &jwks, "at+jwt")
        .map_err(|err| ApiError::bearer(401, "invalid_token", err.to_string()))?;

    if claims.get("iss").and_then(Value::as_str) != Some(tenant.issuer.as_str()) {
        return Err(ApiError::bearer(
            401,
            "invalid_token",
            "the token was issued by another tenant",
        ));
    }

    let jti = token_jti(&claims)
        .ok_or_else(|| ApiError::bearer(401, "invalid_token", "the token has no usable `jti`"))?;
    if state.store.access_token_revoked(&tenant, jti).await? {
        return Err(ApiError::bearer(401, "invalid_token", "the token was revoked"));
    }

    // RFC 9449 §7.1: a token bound with `cnf.jkt` is only usable with a proof for the same key,
    // and the proof's `ath` must hash this very token.
    let bound = claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str);
    if bound.is_some() {
        let url = state.config.userinfo_endpoint(&tenant.slug);
        let proof = verify_resource_proof(&state, &tenant, &headers, "GET", &url, token).await?;
        monaca_oidc::check_binding(bound, proof.as_ref())
            .map_err(|err| ApiError::bearer(401, "invalid_token", err.to_string()))?;
    }

    let scopes = token_scopes(&claims);
    if !scopes.iter().any(|scope| scope == "openid") {
        return Err(ApiError::bearer(
            403,
            "insufficient_scope",
            "the token does not carry the `openid` scope",
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bearer(401, "invalid_token", "the token has no `sub`"))?;
    let account_id = AccountId::parse(sub).map_err(|_| {
        ApiError::bearer(401, "invalid_token", "the token subject is not an account")
    })?;
    let account = state
        .store
        .account_by_id(&tenant, account_id)
        .await?
        .ok_or_else(|| ApiError::bearer(401, "invalid_token", "the account no longer exists"))?;
    if account.state != "active" {
        return Err(ApiError::bearer(
            401,
            "invalid_token",
            "the account is not active",
        ));
    }

    let body = UserInfoClaims {
        sub: account.account_id().to_typed_string(),
        name: scopes
            .iter()
            .any(|scope| scope == "profile")
            .then(|| account.display_name.clone()),
        email: scopes
            .iter()
            .any(|scope| scope == "email")
            .then(|| account.primary_email.clone()),
        email_verified: scopes.iter().any(|scope| scope == "email").then_some(true),
    };
    Ok(Json(body.to_json()).into_response())
}

/// The introspection body — RFC 7662 §2.1.
#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    /// The token to inspect.
    pub token: Option<String>,
    /// `access_token` | `refresh_token`; a hint only.
    pub token_type_hint: Option<String>,
    /// The client's protocol id, when not sent with HTTP Basic.
    pub client_id: Option<String>,
    /// The `client_secret_post` secret.
    pub client_secret: Option<String>,
    /// The `private_key_jwt` assertion.
    pub client_assertion: Option<String>,
}

/// `POST /t/{tenant}/oauth2/introspect` — RFC 7662.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let endpoint = state.config.introspection_endpoint(&tenant.slug);
    let client = authenticate_request_client(
        &state,
        &tenant,
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion.as_deref(),
        &endpoint,
    )
    .await?;

    let token = form
        .token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidRequest, "`token` is required"))?;
    let hash = sha256_hex(token);

    // RFC 7662 §2.2: not every token is a JWT, so try the opaque refresh store first when the
    // caller did not say it holds an access token.
    if form.token_type_hint.as_deref() != Some("access_token")
        && let Some(body) = introspect_refresh(&state, &tenant, &client, &hash).await?
    {
        return Ok(Json(body));
    }

    if let Some(body) = introspect_access(&state, &tenant, token).await? {
        return Ok(Json(body));
    }

    Ok(Json(json!({ "active": false })))
}

/// `POST /t/{tenant}/oauth2/revoke` — RFC 7009.
///
/// Always answers `200`, even for an unknown token: the RFC forbids an endpoint that tells a caller
/// whether a token it does not own exists. Authentication failures still surface as `401`.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let endpoint = state.config.revocation_endpoint(&tenant.slug);
    let _client = authenticate_request_client(
        &state,
        &tenant,
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion.as_deref(),
        &endpoint,
    )
    .await?;

    let token = form
        .token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidRequest, "`token` is required"))?;

    // A refresh token revokes its whole rotation family; a revoked ancestor is what reuse
    // detection looks for, so revoking one link on purpose must not leave the rest alive.
    let hash = sha256_hex(token);
    if let Some(row) = state.store.refresh_by_hash(&tenant, &hash).await? {
        let family = row.family_id.unwrap_or(row.id);
        state.store.revoke_refresh_family(&tenant, family).await?;
        return Ok(StatusCode::OK.into_response());
    }

    // An access token is a JWT; recording its `jti` is enough because every verifier consults the
    // revoked list (see `userinfo`, and the management API's verifier).
    let jwks = state.jwks(&tenant).await?;
    if let Ok(claims) = monaca_crypto::verify_jws(token, &jwks, "at+jwt")
        && let Some(jti) = token_jti(&claims)
    {
        let expires_at = claims
            .get("exp")
            .and_then(Value::as_i64)
            .and_then(|exp| OffsetDateTime::from_unix_timestamp(exp).ok())
            .unwrap_or_else(|| state.now());
        state
            .store
            .revoke_access_token(&tenant, jti, expires_at)
            .await?;
    }

    Ok(StatusCode::OK.into_response())
}

/// `POST /t/{tenant}/oauth2/par` — RFC 9126.
///
/// The pushed request is validated exactly like an inline authorize request, then stored under a
/// hash of the `request_uri` it returns. `authorize` redeems it and re-validates, so the two
/// endpoints cannot drift.
pub async fn par(
    State(state): State<Arc<AppState>>,
    Path(tenant_slug): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    let endpoint = state.config.par_endpoint(&tenant.slug);
    let client = authenticate_request_client(
        &state,
        &tenant,
        &headers,
        form.get("client_id").map(String::as_str),
        form.get("client_secret").map(String::as_str),
        form.get("client_assertion").map(String::as_str),
        &endpoint,
    )
    .await?;

    // Every parameter is a string in the form; `AuthorizeParams` is the same shape the inline
    // endpoint reads, so one deserialize step is enough.
    let raw = Value::Object(
        form.iter()
            .map(|(name, value)| (name.clone(), Value::String(value.clone())))
            .collect(),
    );
    let params: AuthorizeParams = serde_json::from_value(raw).map_err(|_| {
        ApiError::token(TokenErrorCode::InvalidRequest, "a pushed request is malformed")
    })?;

    if params
        .request_uri
        .as_deref()
        .is_some_and(|uri| !uri.trim().is_empty())
    {
        return Err(ApiError::token(
            TokenErrorCode::InvalidRequest,
            "a pushed request must not reference another `request_uri`",
        ));
    }

    let request = params
        .validate()
        .map_err(|err| ApiError::token(TokenErrorCode::InvalidRequest, err.to_string()))?;
    if request.client_id != client.client_id {
        return Err(ApiError::token(
            TokenErrorCode::InvalidRequest,
            "client_id does not match the authenticated client",
        ));
    }
    if !scope_subset(&request.scopes, &client.scopes) {
        return Err(ApiError::token(
            TokenErrorCode::InvalidScope,
            "requested scope exceeds the client's registration",
        ));
    }
    let registered = state.store.client_redirect_uris(&tenant, client.id).await?;
    if !registered.iter().any(|uri| uri == &request.redirect_uri) {
        return Err(ApiError::token(
            TokenErrorCode::InvalidRequest,
            "redirect_uri is not registered for this client",
        ));
    }

    let request_uri = format!(
        "urn:ietf:params:oauth:request_uri:{}",
        Uuid::new_v4().simple()
    );
    let hash = sha256_hex(&request_uri);
    let mut stored = params;
    stored.request_uri = None;
    stored.client_id = Some(client.client_id.clone());
    let value = serde_json::to_value(&stored).map_err(ApiError::internal)?;
    state
        .store
        .par_insert(
            &tenant,
            &hash,
            client.id,
            &value,
            state.now() + Duration::seconds(state.config.par_request_ttl.as_secs() as i64),
        )
        .await?;

    let mut response = (
        StatusCode::CREATED,
        Json(json!({
            "request_uri": request_uri,
            "expires_in": state.config.par_request_ttl.as_secs(),
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Read `Authorization: Bearer|DPoP <token>` and return the raw token.
fn resource_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::bearer(401, "invalid_token", "the request carries no token"))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| ApiError::bearer(401, "invalid_token", "the authorization header is malformed"))?;
    match scheme {
        // RFC 9449 §7.1: a DPoP-bound token is presented with the `DPoP` scheme.
        "Bearer" | "DPoP" if !token.is_empty() => Ok(token),
        _ => Err(ApiError::bearer(
            401,
            "invalid_token",
            "the authorization scheme is not Bearer or DPoP",
        )),
    }
}

/// The access token's `jti` as a UUID, when it is one.
fn token_jti(claims: &Value) -> Option<Uuid> {
    claims
        .get("jti")
        .and_then(Value::as_str)
        .and_then(|raw| Uuid::parse_str(raw).ok())
}

/// The `scope` claim as a set.
fn token_scopes(claims: &Value) -> Vec<String> {
    claims
        .get("scope")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve and authenticate the client named by Basic or the form.
async fn authenticate_request_client(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    headers: &HeaderMap,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    endpoint: &str,
) -> Result<ClientRow, ApiError> {
    let basic = basic_auth(headers);
    let id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| client_id.map(str::to_owned))
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidClient, "client_id is required"))?;
    let client = state
        .store
        .client_by_client_id(tenant, &id)
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidClient, "unknown client"))?;
    let secret = basic
        .as_ref()
        .map(|(_, secret)| secret.clone())
        .or_else(|| client_secret.map(str::to_owned));
    authenticate_client(state, &client, secret.as_deref(), client_assertion, endpoint).await?;
    Ok(client)
}

/// Introspect an opaque refresh token, if `hash` is one.
async fn introspect_refresh(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    client: &ClientRow,
    hash: &str,
) -> Result<Option<Value>, ApiError> {
    let Some(row) = state.store.refresh_by_hash(tenant, hash).await? else {
        return Ok(None);
    };
    if row.client_id != client.id || row.revoked_at.is_some() || row.expires_at <= state.now() {
        return Ok(Some(json!({ "active": false })));
    }
    Ok(Some(json!({
        "active": true,
        "token_type": "refresh_token",
        "scope": row.scope.join(" "),
        "client_id": client.client_id,
        "sub": AccountId::from_uuid(row.account_id).to_typed_string(),
        "exp": row.expires_at.unix_timestamp(),
        "iat": row.created_at.unix_timestamp(),
    })))
}

/// Introspect a self-contained access token.
async fn introspect_access(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    token: &str,
) -> Result<Option<Value>, ApiError> {
    let jwks = state.jwks(tenant).await?;
    let Ok(claims) = monaca_crypto::verify_jws(token, &jwks, "at+jwt") else {
        return Ok(None);
    };
    let Some(jti) = token_jti(&claims) else {
        return Ok(None);
    };
    if state.store.access_token_revoked(tenant, jti).await? {
        return Ok(Some(json!({ "active": false })));
    }

    let token_type = if claims.get("cnf").is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut body = json!({
        "active": true,
        "token_type": token_type,
        "scope": token_scopes(&claims).join(" "),
        "sub": claims.get("sub").cloned().unwrap_or(Value::Null),
        "iss": claims.get("iss").cloned().unwrap_or(Value::Null),
        "aud": claims.get("aud").cloned().unwrap_or(Value::Null),
        "exp": claims.get("exp").cloned().unwrap_or(Value::Null),
        "iat": claims.get("iat").cloned().unwrap_or(Value::Null),
        "jti": claims.get("jti").cloned().unwrap_or(Value::Null),
        "tid": claims.get("tid").cloned().unwrap_or(Value::Null),
        "org": claims.get("org").cloned().unwrap_or(Value::Null),
    });
    if let Some(cnf) = claims.get("cnf") {
        body["cnf"] = cnf.clone();
    }
    Ok(Some(body))
}

/// Verify the `DPoP` header against a resource request and record its `jti`.
async fn verify_resource_proof(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    headers: &HeaderMap,
    method: &str,
    url: &str,
    access_token: &str,
) -> Result<Option<DpopProof>, ApiError> {
    let Some(raw) = headers.get("dpop").and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let proof = monaca_oidc::verify_proof(
        raw,
        method,
        url,
        Some(access_token),
        state.now().unix_timestamp(),
    )
    .map_err(|err| ApiError::bearer(401, "invalid_dpop_proof", err.to_string()))?;

    let expires_at = state.now() + Duration::seconds(monaca_oidc::PROOF_WINDOW_SECS);
    if !state
        .store
        .dpop_replay_add(tenant, &proof.jti, expires_at)
        .await?
    {
        return Err(ApiError::bearer(
            401,
            "invalid_dpop_proof",
            "the DPoP proof was already used",
        ));
    }
    Ok(Some(proof))
}
