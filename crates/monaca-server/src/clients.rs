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
use serde_json::{Value, json};

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// The body of `POST /v1/clients`.
#[derive(Debug, Deserialize)]
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
    /// A third-party application must show the consent screen.
    #[serde(default)]
    pub is_third_party: bool,
}

/// The body of `PATCH /v1/clients/{client}`; absent fields are left alone.
#[derive(Debug, Deserialize)]
pub struct UpdateClientBody {
    /// New display name.
    pub name: Option<String>,
    /// Replacement redirect URIs (an empty array clears them).
    pub redirect_uris: Option<Vec<String>>,
    /// Replacement RP-initiated-logout targets.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Replacement scope set.
    pub scopes: Option<Vec<String>>,
}

/// `POST /v1/clients` — register an application.
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

    let mut body = client_json(&row, &redirect_uris, &post_logout_redirect_uris);
    if let Some((secret, _)) = secret {
        body["client_secret"] = json!(secret);
    }
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `GET /v1/clients` — every application in the tenant.
pub async fn list_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.clients(&tenant).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let (redirect_uris, post_logout) = registered_uris(&state, &tenant, row).await?;
        items.push(client_json(row, &redirect_uris, &post_logout));
    }
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `GET /v1/clients/{client}`.
pub async fn get_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let row = load_client(&state, &tenant, &client).await?;
    let (redirect_uris, post_logout) = registered_uris(&state, &tenant, &row).await?;
    Ok(Json(client_json(&row, &redirect_uris, &post_logout)))
}

/// `PATCH /v1/clients/{client}` — rename it or replace its URIs, scopes or consent policy.
pub async fn update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
    Json(body): Json<UpdateClientBody>,
) -> Result<Json<Value>, ApiError> {
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

    if !state
        .store
        .update_client(
            &tenant,
            row.id,
            name.as_deref(),
            scopes.as_deref(),
            redirect_uris.as_deref(),
            post_logout.as_deref(),
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
pub async fn rotate_client_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client): Path<String>,
) -> Result<Json<Value>, ApiError> {
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

    Ok(Json(json!({
        "client_id": row.client_id,
        "client_secret": secret,
    })))
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

fn client_json(row: &ClientRow, redirect_uris: &[String], post_logout: &[String]) -> Value {
    json!({
        "id": ClientId::from_uuid(row.id).to_typed_string(),
        "client_id": row.client_id,
        "name": row.name,
        "kind": row.kind,
        "token_auth_method": row.token_auth_method,
        "scopes": row.scopes,
        "redirect_uris": redirect_uris,
        "post_logout_redirect_uris": post_logout,
        "is_third_party": row.is_third_party,
        "created_at": ts(row.created_at),
    })
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

/// Validate and de-duplicate the requested scopes against the scope grammar.
fn normalise_scopes(raw: &[String]) -> Result<Vec<String>, ApiError> {
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
}
