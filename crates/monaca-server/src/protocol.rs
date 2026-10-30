//! The protocol endpoints — §6.1 and §7.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use monaca_agent::{Permission, attenuate};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::verify_password;
use monaca_oidc::{
    AccessTokenClaims, AuthorizeParams, DiscoveryDocument, GrantType, IdTokenClaims, Interaction,
    TokenErrorCode, TokenForm, TokenRequest, scope_subset, verify_pkce_s256,
};
use monaca_store::TenantRow;
use monaca_types::{AccountId, AgentId, ClientId, EventId, GrantId, InteractionId, OrgId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{ApiError, kinds};
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
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;

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

    let interaction = Interaction {
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
        resource: request.resource.clone(),
        state: request.state.clone(),
        expires_at: state.now() + Duration::seconds(state.config.interaction_ttl.as_secs() as i64),
    };

    let location = format!(
        "{}/sign-in?tenant={}&interaction={}",
        state.config.auth_ui_url.trim_end_matches('/'),
        tenant.slug,
        interaction.interaction_id
    );
    state.put_interaction(interaction).await;
    Ok(found(&location))
}

/// `GET /t/{tenant}/interaction/{iid}`.
pub async fn interaction_details(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let interaction = state
        .peek_interaction(&iid)
        .await
        .map_err(ApiError::Interaction)?;
    Ok(Json(interaction.to_public_json()))
}

/// The sign-in body.
#[derive(Debug, Deserialize)]
pub struct SignInBody {
    /// The account's primary email.
    pub email: String,
    /// The password.
    pub password: String,
}

/// `POST /t/{tenant}/interaction/{iid}/sign-in`.
pub async fn sign_in(
    State(state): State<Arc<AppState>>,
    Path((_tenant, iid)): Path<(String, String)>,
    Json(body): Json<SignInBody>,
) -> Result<Json<Value>, ApiError> {
    let interaction = state
        .peek_interaction(&iid)
        .await
        .map_err(ApiError::Interaction)?;
    let tenant = state.tenant(&interaction.tenant).await?;
    let org_slug = interaction.organization.clone();
    let org = state.store.org_by_slug(&tenant, &org_slug).await?;
    let org_ctx = org.ctx(&tenant);

    let account = state.store.account_by_email(&tenant, &body.email).await?;

    let authenticated = match account {
        Some((account, Some(phc))) if account.state == "active" => {
            match verify_password(body.password.clone(), phc, state.argon).await {
                Ok(()) => Some(account),
                Err(_) => None,
            }
        }
        // An unknown email and a wrong password must be indistinguishable (§6.1). The verifier
        // path above and this branch both end in the same response; the audit event is what
        // records which one happened, and it is only visible to the tenant's own admins.
        _ => None,
    };

    let Some(account) = authenticated else {
        let event = sign_in_event(
            state.now(),
            &org_ctx.org_id,
            AuditDecision::Deny,
            &body.email,
            "invalid_credentials",
        );
        if let Err(err) = state.audit_org(&org_ctx, &event).await {
            tracing::warn!(%err, "could not append sign-in.failed audit event");
        }
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "email or password is incorrect",
        ));
    };

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

    // Consume only after authentication succeeds, so a typo does not burn the interaction.
    let interaction = state
        .consume_interaction(&iid)
        .await
        .map_err(ApiError::Interaction)?;

    let code = issue_code();
    let code_hash = sha256_hex(&code);
    state
        .store
        .insert_auth_code(
            &tenant,
            &code_hash,
            interaction.client_row_id,
            account.id,
            org.id,
            &interaction.redirect_uri,
            &interaction.scopes,
            &interaction.code_challenge,
            interaction.nonce.as_deref(),
            interaction.resource.as_deref(),
            None,
            state.now() + Duration::seconds(state.config.auth_code_ttl.as_secs() as i64),
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "interaction.sign_in.succeeded".into(),
        actor_chain: vec![AuditActor::account(account.account_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org_slug, "client_id": interaction.client_id }),
    };
    if let Err(err) = state.audit_org(&org_ctx, &event).await {
        tracing::warn!(%err, "could not append sign-in.succeeded audit event");
    }

    let redirect_to = append_query(
        &interaction.redirect_uri,
        &[
            ("code", code.as_str()),
            ("state", interaction.state.as_str()),
        ],
    );
    Ok(Json(json!({ "redirect_to": redirect_to })))
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

    authenticate_client(&state, &client, &request, basic.as_ref(), &endpoint).await?;

    match request.grant_type {
        GrantType::AuthorizationCode => {
            authorization_code_grant(state, tenant, request, client, &endpoint).await
        }
        GrantType::RefreshToken => refresh_grant(state, tenant, request, client, &endpoint).await,
        GrantType::ClientCredentials => {
            client_credentials_grant(state, tenant, request, client, &endpoint).await
        }
    }
}

async fn authorization_code_grant(
    state: Arc<AppState>,
    tenant: TenantRow,
    request: TokenRequest,
    client: monaca_store::ClientRow,
    _endpoint: &str,
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
            )
            .await,
        )
    } else {
        None
    };
    let refresh_token = match refresh_token {
        Some(value) => Some(value?),
        None => None,
    };

    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
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
) -> Result<Response, ApiError> {
    let raw = request.refresh_token.as_deref().unwrap_or_default();
    let hash = sha256_hex(raw);
    let row = state
        .store
        .refresh_by_hash(&tenant, &hash)
        .await?
        .ok_or_else(|| ApiError::token(TokenErrorCode::InvalidGrant, "refresh token is invalid"))?;

    if row.revoked_at.is_some() {
        // Reuse detection: a revoked token presented again kills the whole family.
        state.store.revoke_refresh_family(&tenant, row.id).await?;
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

    state.store.revoke_refresh_token(&tenant, row.id).await?;
    let refresh_token = issue_refresh(
        Arc::clone(&state),
        tenant.clone(),
        client.id,
        row.account_id,
        row.org_id,
        scope.clone(),
        row.resource.clone(),
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
    };
    let access_token = key
        .sign("at+jwt", &claims.to_json())
        .map_err(ApiError::internal)?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_ttl.as_secs(),
        "scope": scope,
        "refresh_token": refresh_token,
    }))
    .into_response())
}

async fn client_credentials_grant(
    state: Arc<AppState>,
    tenant: TenantRow,
    request: TokenRequest,
    client: monaca_store::ClientRow,
    _endpoint: &str,
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
    };
    let access_token = key
        .sign("at+jwt", &claims.to_json())
        .map_err(ApiError::internal)?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
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

async fn issue_refresh(
    state: Arc<AppState>,
    tenant: TenantRow,
    client_row_id: Uuid,
    account_id: Uuid,
    org_id: Uuid,
    scope: Vec<String>,
    resource: Option<String>,
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
            state.now() + Duration::seconds(state.config.refresh_token_ttl.as_secs() as i64),
        )
        .await?;
    Ok(token)
}

async fn authenticate_client(
    state: &Arc<AppState>,
    client: &monaca_store::ClientRow,
    request: &TokenRequest,
    basic: Option<&(String, String)>,
    endpoint: &str,
) -> Result<(), ApiError> {
    match client.token_auth_method.as_str() {
        "none" => Ok(()),
        "client_secret_basic" => {
            let (_, secret) = basic.ok_or_else(|| {
                ApiError::token(TokenErrorCode::InvalidClient, "HTTP Basic is required")
            })?;
            check_secret(state, client, secret).await
        }
        "client_secret_post" => {
            let secret = request.client_secret.as_deref().ok_or_else(|| {
                ApiError::token(TokenErrorCode::InvalidClient, "client_secret is required")
            })?;
            check_secret(state, client, secret).await
        }
        "private_key_jwt" => {
            let assertion = request.client_assertion.as_deref().ok_or_else(|| {
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

fn issue_code() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = data_encoding::BASE64.decode(encoded.as_bytes()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_owned(), secret.to_owned()))
}

fn append_query(base: &str, params: &[(&str, &str)]) -> String {
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
