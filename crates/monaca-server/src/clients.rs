//! Application management — §6.2.
//!
//! An application is a `tenant.clients` row plus its registered redirect URIs. The protocol
//! `client_id` is chosen by the administrator because it appears in every authorize URL; the row
//! id (`cli_…`) is what this API addresses. A confidential client's secret is generated here,
//! returned exactly once, and stored as an argon2 PHC string — the plaintext exists nowhere else.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::{encode_base64url, generate_challenge, hash_password};
use monaca_oidc::{is_absolute_http_url, valid_scope};
use monaca_store::{ClientRow, TenantRow};
use monaca_types::{ClientId, EventId, TypedId};
use serde::Deserialize;
use serde_json::json;

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, authorize_admin_read, ts, validate_custom_css};
use crate::schemas::{ClientList, ClientSecretView, ClientView, CreatedClientView};
use crate::state::AppState;

/// The body of `POST /v1/clients`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateClientBody {
    /// The protocol id that appears in authorize URLs.
    pub client_id: String,
    /// Human-readable application name.
    pub name: String,
    /// `public` (no secret, PKCE only) or `confidential` (`client_secret_basic`).
    pub kind: String,
    /// Where authorization codes may be sent.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// RP-initiated-logout targets.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Scopes this application may ask for.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Browser origins that may call the tenant's protocol endpoints from this application.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// A third-party application must show the consent screen.
    #[serde(default)]
    pub is_third_party: bool,
}

/// The body of `PATCH /v1/clients/{client}`; absent fields are left alone.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateClientBody {
    /// New display name.
    pub name: Option<String>,
    /// Replacement redirect URIs (an empty array clears them).
    pub redirect_uris: Option<Vec<String>>,
    /// Replacement RP-initiated-logout targets.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Replacement scope set.
    pub scopes: Option<Vec<String>>,
    /// Replacement CORS origins (an empty array clears them).
    pub cors_allowed_origins: Option<Vec<String>>,
    /// Application CSS for the hosted page; an empty string clears it.
    pub custom_css: Option<String>,
}

/// `POST /v1/clients` — register an application.
#[utoipa::path(
    post,
    path = "/v1/clients",
    tag = "management",
    summary = "Create an application",
    request_body = CreateClientBody,
    responses(
        (status = 201, description = "The created application and its one-time secret.", body = CreatedClientView),
        (status = 400, description = "The client id, kind, URI, scope or origin is invalid."),
        (status = 409, description = "The client id is already registered.")
    )
)]
pub async fn create_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateClientBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;

    let client_id = body.client_id.trim();
    if !valid_client_id(client_id) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "client_id must be 2-32 characters of lowercase letters, digits or `-`, not starting or ending with `-`",
        ));
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "name must be 1-80 characters",
        ));
    }
    let (token_auth_method, secret) = match body.kind.as_str() {
        "public" => ("none", None),
        "confidential" => {
            let secret = generate_client_secret();
            let phc = hash_password(secret.clone(), state.argon)
                .await
                .map_err(ApiError::internal)?;
            ("client_secret_basic", Some((secret, phc)))
        }
        _ => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "kind must be `public` or `confidential`",
            ));
        }
    };

    let scopes = normalise_scopes(&body.scopes)?;
    let redirect_uris = normalise_uris(&body.redirect_uris, "redirect_uris")?;
    let post_logout_redirect_uris =
        normalise_uris(&body.post_logout_redirect_uris, "post_logout_redirect_uris")?;
    let cors_allowed_origins = normalise_origins(&body.cors_allowed_origins)?;

    let row = state
        .store
        .insert_client(
            &tenant,
            client_id,
            name,
            &body.kind,
            secret.as_ref().map(|(_, phc)| phc.as_str()),
            token_auth_method,
            &scopes,
            &redirect_uris,
            &post_logout_redirect_uris,
            &cors_allowed_origins,
            body.is_third_party,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "client.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "client_id": row.client_id,
            "name": row.name,
            "kind": row.kind,
            "is_third_party": row.is_third_party,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append client.created audit event");
    }

    let view = client_json(&row, &redirect_uris, &post_logout_redirect_uris);
    let created = CreatedClientView::from_view(view, secret.map(|(secret, _)| secret));
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// `GET /v1/clients` — every application in the tenant.
#[utoipa::path(
    get,
    path = "/v1/clients",
    tag = "management",
    summary = "List applications",
    responses((status = 200, description = "The applications.", body = ClientList))
)]
pub async fn list_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ClientList>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let rows = state.store.clients(&tenant).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let (redirect_uris, post_logout) = registered_uris(&state, &tenant, row).await?;
        items.push(client_json(row, &redirect_uris, &post_logout));
    }
    Ok(Json(ClientList { items, next: None }))
}

/// `GET /v1/clients/{client}`.
#[utoipa::path(
    get,
    path = "/v1/clients/{client}",
    tag = "management",
    summary = "Read an application",
    params(("client" = String, Path, description = "The protocol client id or the `cli_…` id.")),
    responses(
        (status = 200, description = "The application.", body = ClientView),
        (status = 404, description = "No such application.")
    )
)]
pub async fn get_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Result<Json<ClientView>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let row = load_client(&state, &tenant, &client).await?;
    let (redirect_uris, post_logout) = registered_uris(&state, &tenant, &row).await?;
    Ok(Json(client_json(&row, &redirect_uris, &post_logout)))
}

/// `PATCH /v1/clients/{client}` — rename it or replace its URIs, scopes or consent policy.
#[utoipa::path(
    patch,
    path = "/v1/clients/{client}",
    tag = "management",
    summary = "Update an application",
    params(("client" = String, Path, description = "The protocol client id or the `cli_…` id.")),
    request_body = UpdateClientBody,
    responses(
        (status = 200, description = "The updated application.", body = ClientView),
        (status = 400, description = "A URI, scope, origin or CSS value is invalid."),
        (status = 404, description = "No such application.")
    )
)]
pub async fn update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
    Json(body): Json<UpdateClientBody>,
) -> Result<Json<ClientView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let row = load_client(&state, &tenant, &client).await?;

    let name = match body.name.as_deref().map(str::trim) {
        Some(name) if name.is_empty() || name.len() > 80 => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "name must be 1-80 characters",
            ));
        }
        Some(name) => Some(name.to_owned()),
        None => None,
    };
    let scopes = body.scopes.as_deref().map(normalise_scopes).transpose()?;
    let redirect_uris = body
        .redirect_uris
        .as_deref()
        .map(|uris| normalise_uris(uris, "redirect_uris"))
        .transpose()?;
    let post_logout = body
        .post_logout_redirect_uris
        .as_deref()
        .map(|uris| normalise_uris(uris, "post_logout_redirect_uris"))
        .transpose()?;
    let cors_allowed_origins = body
        .cors_allowed_origins
        .as_deref()
        .map(normalise_origins)
        .transpose()?;
    let custom_css = match body.custom_css.as_deref() {
        Some(css) => {
            let css = css.trim();
            validate_custom_css(css)?;
            Some(css.to_owned())
        }
        None => None,
    };

    if !state
        .store
        .update_client(
            &tenant,
            row.id,
            name.as_deref(),
            scopes.as_deref(),
            redirect_uris.as_deref(),
            post_logout.as_deref(),
            cors_allowed_origins.as_deref(),
            custom_css.as_deref(),
        )
        .await?
    {
        return Err(ApiError::not_found("client"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "client.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "client_id": row.client_id }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append client.updated audit event");
    }

    let updated = load_client(&state, &tenant, &client).await?;
    let (stored_redirects, stored_post_logout) = registered_uris(&state, &tenant, &updated).await?;
    Ok(Json(client_json(
        &updated,
        &stored_redirects,
        &stored_post_logout,
    )))
}

/// `POST /v1/clients/{client}/secret` — replace the secret; the previous one stops working.
#[utoipa::path(
    post,
    path = "/v1/clients/{client}/secret",
    tag = "management",
    summary = "Rotate an application secret",
    params(("client" = String, Path, description = "The protocol client id or the `cli_…` id.")),
    responses(
        (status = 200, description = "The new secret.", body = ClientSecretView),
        (status = 400, description = "The application is public and has no secret."),
        (status = 404, description = "No such application.")
    )
)]
pub async fn rotate_client_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Result<Json<ClientSecretView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let row = load_client(&state, &tenant, &client).await?;
    if !row.secret_hash.is_some() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "a public client has no secret to rotate",
        ));
    }

    let secret = generate_client_secret();
    let phc = hash_password(secret.clone(), state.argon)
        .await
        .map_err(ApiError::internal)?;
    if !state.store.set_client_secret(&tenant, row.id, &phc).await? {
        return Err(ApiError::not_found("client"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "client.secret_rotated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "client_id": row.client_id }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append client.secret_rotated audit event");
    }

    Ok(Json(ClientSecretView {
        client_id: row.client_id,
        client_secret: secret,
    }))
}

/// `DELETE /v1/clients/{client}` — remove the application with its codes and refresh tokens.
pub async fn delete_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let row = load_client(&state, &tenant, &client).await?;
    if !state.store.delete_client(&tenant, row.id).await? {
        return Err(ApiError::not_found("client"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "client.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "client_id": row.client_id }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append client.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Resolve a `cli_…` path segment to its row, 404 when it is missing.
async fn load_client(
    state: &AppState,
    tenant: &TenantRow,
    client: &str,
) -> Result<ClientRow, ApiError> {
    let client_id = ClientId::parse(client)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not a client id"))?;
    state
        .store
        .client_by_id(tenant, client_id.uuid())
        .await?
        .ok_or_else(|| ApiError::not_found("client"))
}

/// The URIs an application registered, in storage order (which is sorted by the database).
async fn registered_uris(
    state: &AppState,
    tenant: &TenantRow,
    row: &ClientRow,
) -> Result<(Vec<String>, Vec<String>), ApiError> {
    let redirect_uris = state.store.client_redirect_uris(tenant, row.id).await?;
    let post_logout = state.store.client_post_logout_uris(tenant, row.id).await?;
    Ok((redirect_uris, post_logout))
}

fn client_json(row: &ClientRow, redirect_uris: &[String], post_logout: &[String]) -> ClientView {
    ClientView {
        id: ClientId::from_uuid(row.id).to_typed_string(),
        client_id: row.client_id.clone(),
        name: row.name.clone(),
        kind: row.kind.clone(),
        token_auth_method: row.token_auth_method.clone(),
        scopes: row.scopes.clone(),
        redirect_uris: redirect_uris.to_vec(),
        post_logout_redirect_uris: post_logout.to_vec(),
        cors_allowed_origins: row.cors_allowed_origins.clone(),
        custom_css: row.custom_css.clone(),
        is_third_party: row.is_third_party,
        created_at: ts(row.created_at),
    }
}

/// The protocol id rule: lowercase, digits and `-`, 2–32 characters.
fn valid_client_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=32).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// Validate and de-duplicate redirect URIs — §6.2.
fn normalise_uris(raw: &[String], field: &str) -> Result<Vec<String>, ApiError> {
    let mut uris: Vec<String> = Vec::new();
    for uri in raw {
        let uri = uri.trim();
        if !is_absolute_http_url(uri) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("{field} must be absolute http(s) URLs"),
            ));
        }
        if !uris.iter().any(|existing| existing == uri) {
            uris.push(uri.to_owned());
        }
    }
    Ok(uris)
}

/// Validate and de-duplicate CORS origins — §6.2.
fn normalise_origins(raw: &[String]) -> Result<Vec<String>, ApiError> {
    if raw.len() > MAX_CORS_ORIGINS {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("cors_allowed_origins accepts at most {MAX_CORS_ORIGINS} origins"),
        ));
    }
    let mut origins: Vec<String> = Vec::new();
    for raw_origin in raw {
        let Some(origin) = normalise_origin(raw_origin) else {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "cors_allowed_origins must be origins of the form https://app.example.com — no path, query, fragment, userinfo or wildcard",
            ));
        };
        if origin.len() > 255 {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "a CORS origin must be at most 255 characters",
            ));
        }
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    Ok(origins)
}

/// The ceiling on one application's origin list — §6.2 and the schema-38 check.
pub(crate) const MAX_CORS_ORIGINS: usize = 32;

/// Canonicalize one origin to `scheme://host[:port]`, or `None` when it is not an origin.
///
/// The serialization is the one a browser sends: lowercased scheme and host, the default port
/// omitted. A trailing slash is tolerated because that is how people write an origin; anything
/// after it is a path and is refused, so an entry can never admit URLs by prefix.
pub(crate) fn normalise_origin(raw: &str) -> Option<String> {
    let value = raw.trim();
    let (scheme, rest, default_port) = if let Some(rest) = value.strip_prefix("https://") {
        ("https", rest, 443)
    } else if let Some(rest) = value.strip_prefix("http://") {
        ("http", rest, 80)
    } else {
        return None;
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\'])
        || authority.chars().any(char::is_whitespace)
    {
        return None;
    }
    let bracketed = authority.starts_with('[');
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (host, tail) = after.split_once(']')?;
        let port = match tail {
            "" => None,
            tail => Some(parse_port(tail.strip_prefix(':')?)?),
        };
        (format!("[{host}]"), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_owned(), Some(parse_port(port)?))
    } else {
        (authority.to_owned(), None)
    };
    if host.is_empty() || host == "[]" || !host.is_ascii() || (!bracketed && host.contains(':')) {
        return None;
    }
    let authority = match port.filter(|port| *port != default_port) {
        Some(port) => format!("{}:{port}", host.to_ascii_lowercase()),
        None => host.to_ascii_lowercase(),
    };
    Some(format!("{scheme}://{authority}"))
}

fn parse_port(value: &str) -> Option<u16> {
    if value.is_empty() {
        return None;
    }
    value.parse().ok()
}

/// Validate and de-duplicate the requested scopes against the scope grammar.
pub(crate) fn normalise_scopes(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut scopes: Vec<String> = Vec::new();
    for scope in raw {
        let scope = scope.trim();
        if !valid_scope(scope) {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "scopes must match the scope grammar",
            ));
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.to_owned());
        }
    }
    Ok(scopes)
}

/// A fresh 256-bit secret, returned to the administrator exactly once.
fn generate_client_secret() -> String {
    encode_base64url(&generate_challenge())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ids_are_lowercase_slugs() {
        assert!(valid_client_id("my-app"));
        assert!(valid_client_id("app1"));
        assert!(!valid_client_id("My-App"));
        assert!(!valid_client_id("-app"));
        assert!(!valid_client_id("app-"));
        assert!(!valid_client_id("a"));
        assert!(!valid_client_id("app_1"));
    }

    #[test]
    fn redirect_uris_must_be_absolute_and_are_deduplicated() {
        let uris = normalise_uris(
            &[
                " https://app.example/callback ".into(),
                "https://app.example/callback".into(),
                "http://localhost:5173/cb".into(),
            ],
            "redirect_uris",
        )
        .expect("valid");
        assert_eq!(
            uris,
            vec![
                "https://app.example/callback".to_string(),
                "http://localhost:5173/cb".to_string()
            ]
        );
        assert!(normalise_uris(&["/callback".into()], "redirect_uris").is_err());
    }

    #[test]
    fn scopes_are_validated_and_deduplicated() {
        let scopes = normalise_scopes(&["openid".into(), "openid".into(), "tools:read".into()])
            .expect("valid");
        assert_eq!(scopes, vec!["openid".to_string(), "tools:read".to_string()]);
        assert!(normalise_scopes(&["bad scope".into()]).is_err());
    }

    #[test]
    fn cors_origins_are_canonicalized_and_deduplicated() {
        let origins = normalise_origins(&[
            " https://App.Example.com:443/ ".into(),
            "https://app.example.com".into(),
            "http://localhost:5173".into(),
            "http://localhost:80".into(),
            "http://[::1]:5174".into(),
        ])
        .expect("valid");
        assert_eq!(
            origins,
            vec![
                "https://app.example.com".to_string(),
                "http://localhost:5173".to_string(),
                "http://localhost".to_string(),
                "http://[::1]:5174".to_string(),
            ]
        );
    }

    #[test]
    fn cors_origins_refuse_paths_wildcards_and_junk() {
        for bad in [
            "*",
            "https://app.example.com/callback",
            "https://app.example.com?x=1",
            "https://app.example.com#frag",
            "https://user@app.example.com",
            "ftp://app.example.com",
            "https://",
            "https://app.example.com:99999",
            "https://app.example.com:port",
            "http://[::1",
            "https://::1",
            "https://app example.com",
        ] {
            assert!(normalise_origins(&[bad.into()]).is_err(), "accepted {bad}");
        }
        assert!(
            normalise_origins(&vec!["https://a.example".into(); MAX_CORS_ORIGINS + 1]).is_err()
        );
    }
}
