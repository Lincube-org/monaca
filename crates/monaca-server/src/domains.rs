//! Custom tenant hostnames — `docs/contracts/m0.md` §5.8 and §6.5.
//!
//! A custom hostname is an **alternate front door for one tenant, never a second issuer**. DNS
//! ownership is proven by a TXT record carrying the tenant id and a one-time nonce; a verified
//! binding serves protocol requests by rewriting the custom host's path onto the tenant's
//! `/t/{slug}` path. Discovery and JWKS are deliberately not answered on a custom host: the issuer
//! stays `{MONACA_PUBLIC_BASE_URL}/t/{slug}`, so a client that configures the custom host as an
//! issuer is told, by contract, not to.
//!
//! Requests on a host that is unknown, unverified, or owned by an archived/suspended tenant all
//! fall through to the router's default `404`. There is exactly one such response and no branch
//! distinguishes the three, so the host header cannot be used to enumerate registrations.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header, uri::Uri};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::{TenantDomainRow, TenantRow};
use monaca_types::{EventId, TenantId, TypedId};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

use crate::error::{ApiError, kinds};
use crate::management::{AdminPrincipal, authorize_admin, authorize_admin_read};
use crate::state::AppState;

/// The TXT record name a tenant publishes: `_monaca-verify.<host>`.
pub const VERIFY_RECORD_PREFIX: &str = "_monaca-verify.";

/// The fixed prefix inside the TXT value. A version prefix lets a future record shape coexist.
pub const VERIFY_VALUE_PREFIX: &str = "monaca-verify-v1=";

/// Host-relative protocol paths a custom domain serves. Everything else is left alone, which
/// includes `/.well-known/*` (see the module comment) and the management `/v1` surface.
const CUSTOM_EXACT: &[&str] = &[
    "/oauth2/authorize",
    "/oauth2/token",
    "/oauth2/userinfo",
    "/oauth2/introspect",
    "/oauth2/revoke",
    "/oauth2/par",
    "/oauth2/end-session",
    "/verification/sms",
    "/verification/sms/verify",
    "/connectors",
    "/sso-connectors",
    "/sign-in-experience",
    "/sign-in-copy",
];

/// Prefix form of the same table: interaction pages, the account centre, connector entry points
/// and the SAML ACS/metadata paths (`/sso/{connector}/…`).
const CUSTOM_PREFIXES: &[&str] = &[
    "/interaction/",
    "/account",
    "/connectors/",
    "/social/",
    "/sso/",
];

/// The response body of a custom-host request that must not reveal the binding.
///
/// It is intentionally not a [`ApiError`]: every such request must look byte-for-byte like a host
/// the router has never heard of. The router's own fallback already produces this, and the host
/// rewrite below simply does nothing in that case.
fn custom_rest(path: &str) -> Option<&str> {
    if CUSTOM_EXACT.contains(&path) {
        return Some(path);
    }
    CUSTOM_PREFIXES
        .iter()
        .find(|prefix| path.starts_with(**prefix))
        .map(|_| path)
}

/// Normalise a `Host` header into the lowercase, port-free form stored in `tenant_domains`.
///
/// `None` means the value cannot be a public DNS hostname and the request must be left untouched.
/// IPv6 literals, single-label names and IP addresses are refused; a custom name is always a
/// dotted DNS name, so a mis-set `Host` never becomes a binding.
pub fn normalise_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('[') {
        return None;
    }
    // Strip a numeric port. A second colon means an IPv6 literal, already refused above only
    // when bracketed; an unbracketed one is not a hostname we accept either.
    let host = match raw.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => host,
        Some(_) => return None,
        None => raw,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.len() < 3 || host.len() > 253 || !host.contains('.') {
        return None;
    }
    let mut labels = host.split('.');
    let last = labels.next_back()?;
    // The last label of a DNS name is alphabetic. This also rejects an IP address, whose last
    // label is numeric.
    if !last.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return None;
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label.starts_with(|ch: char| ch.is_ascii_alphanumeric())
            || !label.ends_with(|ch: char| ch.is_ascii_alphanumeric())
            || !label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    }) {
        return None;
    }
    Some(host)
}

/// The record name a tenant publishes for `host`.
pub fn verification_name(host: &str) -> String {
    format!("{VERIFY_RECORD_PREFIX}{host}")
}

/// The exact TXT value expected for a tenant's claim.
///
/// Including the tenant id and a nonce, and storing the same pair server-side, means a record
/// published for one tenant cannot be re-used to claim the host from another tenant and a stale
/// record cannot re-claim a revoked binding.
pub fn verification_value(tenant: TenantId, nonce: &str) -> String {
    format!("{VERIFY_VALUE_PREFIX}{}:{nonce}", tenant.as_uuid())
}

/// A fresh one-time claim nonce.
fn new_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The platform's own hostname, from `MONACA_PUBLIC_BASE_URL`.
pub fn platform_host(base: &str) -> Option<String> {
    let uri: Uri = base.parse().ok()?;
    uri.host()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

/// Marks a request that arrived on a non-platform hostname. Inserted before routing and read by
/// [`custom_host_gate`].
#[derive(Debug, Clone)]
pub struct CustomHost {
    /// The tenant the host maps to, when the binding was serving at rewrite time.
    pub slug: Option<String>,
    /// Whether the path is one a custom host serves.
    pub allowed: bool,
}

/// The one response every custom-host failure returns.
///
/// Unknown host, unverified binding, revoked/degraded binding, archived/suspended tenant and a
/// path outside the allowlist must all look like this: same status, same headers, same body. The
/// gate never names the host, the tenant or the binding, and there is no `Retry-After`.
fn denied() -> Response {
    ApiError::problem(kinds::NOT_FOUND, "not found").into_response()
}

/// Rewrite a request addressed to a serving custom host onto its tenant's path.
///
/// Runs before routing (the make service wraps the router), so the rewritten path is what the
/// router matches and what every downstream middleware sees. A host that is not the platform host
/// gets a [`CustomHost`] marker either way: the gate downstream turns a non-serving binding or a
/// path outside the allowlist into one fixed `404`, without waiting for the routing cache to
/// notice a tenant lifecycle change.
pub fn rewrite_host(state: &AppState, request: &mut Request<axum::body::Body>) {
    let Some(raw_host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let Some(host) = normalise_host(raw_host) else {
        return;
    };
    if platform_host(&state.config.public_base_url).as_deref() == Some(host.as_str()) {
        return;
    }
    let path = request.uri().path().to_owned();
    let slug = state.domain_route(&host);
    let rest = custom_rest(&path);
    let allowed = slug.is_some() && rest.is_some();
    request.extensions_mut().insert(CustomHost {
        slug: slug.clone(),
        allowed,
    });
    if let (true, Some(slug), Some(rest)) = (allowed, slug, rest) {
        let target = format!("/t/{slug}{rest}{}", query_of(request));
        if let Ok(uri) = Uri::try_from(target) {
            *request.uri_mut() = uri;
        } else {
            request.extensions_mut().insert(CustomHost {
                slug: None,
                allowed: false,
            });
        }
    }
}

/// The `?query` suffix of the request, so a rewritten authorize keeps every parameter.
fn query_of(request: &Request<axum::body::Body>) -> String {
    request
        .uri()
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default()
}

/// Refuse a custom-host request before a handler can answer it with a tenant-specific error.
///
/// The routing cache is eventually consistent, but the tenant lifecycle is not negotiable: a
/// request whose rewritten slug now belongs to a suspended or archived tenant must not reach
/// `state.tenant()` and surface `403 MONACA_TENANT_ARCHIVED`. This gate re-reads the tenant for
/// every custom-host request and returns the same [`denied`] body as every other failed host.
pub async fn custom_host_gate(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let Some(marker) = request.extensions().get::<CustomHost>().cloned() else {
        return next.run(request).await;
    };
    if !marker.allowed {
        return denied();
    }
    let Some(slug) = marker.slug.as_deref() else {
        return denied();
    };
    match state.store.tenant_by_slug(slug).await {
        Ok(tenant) if tenant.serving().is_ok() => next.run(request).await,
        _ => denied(),
    }
}

/// One custom-domain binding as the management API reports it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantDomainView {
    /// The lower-case hostname.
    pub host: String,
    /// `pending` | `verified` | `active` | `degraded` | `revoked`.
    pub state: String,
    /// The TXT record name to publish.
    pub verification_record: String,
    /// The exact TXT value to publish (the tenant's nonce, as issued).
    pub verification_value: String,
    /// When ownership was first proven, RFC 3339.
    pub verified_at: Option<String>,
    /// When DNS was last checked, RFC 3339.
    pub last_checked_at: Option<String>,
    /// Consecutive failed checks.
    pub check_failures: i32,
    /// Creation time, RFC 3339.
    pub created_at: String,
}

/// The list response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantDomainList {
    /// The tenant's bindings.
    pub items: Vec<TenantDomainView>,
}

/// `POST /v1/tenant-domains` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTenantDomainBody {
    /// The hostname, for example `login.acme.com`. A scheme, port or path is refused.
    pub domain: String,
}

fn domain_view(domain: &TenantDomainRow) -> TenantDomainView {
    let tenant = domain.tenant();
    TenantDomainView {
        host: domain.host.clone(),
        state: domain.state.clone(),
        verification_record: verification_name(&domain.host),
        verification_value: verification_value(tenant, &domain.nonce),
        verified_at: domain
            .verified_at
            .map(|value| value.format(&Rfc3339).unwrap_or_default()),
        last_checked_at: domain
            .last_checked_at
            .map(|value| value.format(&Rfc3339).unwrap_or_default()),
        check_failures: domain.check_failures,
        created_at: domain.created_at.format(&Rfc3339).unwrap_or_default(),
    }
}

/// A hostname from a path or body, validated before it reaches SQL.
fn checked_host(raw: &str) -> Result<String, ApiError> {
    normalise_host(raw).ok_or_else(|| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "domain must be a lowercase DNS hostname without a scheme, port or path",
        )
    })
}

/// Register a hostname for the caller's tenant.
#[utoipa::path(
    post,
    path = "/v1/tenant-domains",
    tag = "management",
    summary = "Claim a custom hostname",
    request_body = CreateTenantDomainBody,
    responses(
        (status = 201, description = "The pending binding, including the TXT value to publish.", body = TenantDomainView),
        (status = 400, description = "The name is not a DNS hostname."),
        (status = 409, description = "Another tenant or this tenant already owns the host.")
    )
)]
pub async fn create_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateTenantDomainBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let host = checked_host(&body.domain)?;
    if platform_host(&state.config.public_base_url).as_deref() == Some(host.as_str()) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the platform's own hostname cannot be a custom domain",
        ));
    }
    let nonce = new_nonce();
    let domain = state
        .store
        .create_tenant_domain(tenant.tenant_id(), &host, &nonce)
        .await?;
    audit_admin(
        &state,
        &tenant,
        &admin,
        "tenant_domain.created",
        &domain.host,
        json!({
            "record": verification_name(&domain.host),
            "value": verification_value(domain.tenant(), &domain.nonce),
        }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(domain_view(&domain))).into_response())
}

/// List the caller tenant's bindings.
#[utoipa::path(
    get,
    path = "/v1/tenant-domains",
    tag = "management",
    summary = "List custom hostnames",
    responses((status = 200, description = "Every binding, including revoked ones.", body = TenantDomainList))
)]
pub async fn list_domains(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TenantDomainList>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let items = state
        .store
        .tenant_domains(tenant.tenant_id())
        .await?
        .iter()
        .map(domain_view)
        .collect();
    Ok(Json(TenantDomainList { items }))
}

/// Read one binding.
#[utoipa::path(
    get,
    path = "/v1/tenant-domains/{host}",
    tag = "management",
    summary = "Get a custom hostname",
    params(("host" = String, Path, description = "The hostname.")),
    responses(
        (status = 200, description = "The binding.", body = TenantDomainView),
        (status = 404, description = "No such binding in this tenant.")
    )
)]
pub async fn get_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<TenantDomainView>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let host = checked_host(&host)?;
    let domain = state.store.tenant_domain(tenant.tenant_id(), &host).await?;
    Ok(Json(domain_view(&domain)))
}

/// Prove DNS ownership by resolving the TXT record and comparing it to the stored tenant+nonce.
#[utoipa::path(
    post,
    path = "/v1/tenant-domains/{host}/verify",
    tag = "management",
    summary = "Verify a custom hostname",
    params(("host" = String, Path, description = "The hostname.")),
    responses(
        (status = 200, description = "Ownership proven; the binding is verified and serves.", body = TenantDomainView),
        (status = 400, description = "The TXT record is missing or carries another tenant's value."),
        (status = 409, description = "The binding is not pending.")
    )
)]
pub async fn verify_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<TenantDomainView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let host = checked_host(&host)?;
    let domain = state.store.tenant_domain(tenant.tenant_id(), &host).await?;
    if domain.state != "pending" {
        return Err(ApiError::problem(
            kinds::STATE_CONFLICT,
            "only a pending binding can be verified",
        ));
    }
    let expected = verification_value(domain.tenant(), &domain.nonce);
    if !txt_matches(&state, &host, &expected).await? {
        let checked = state
            .store
            .domain_check_failed(&host, state.now())
            .await
            .unwrap_or(domain);
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!(
                "no TXT record at {} carries the expected value; publish `{}` and retry ({} failed checks)",
                verification_name(&host),
                expected,
                checked.check_failures
            ),
        ));
    }
    let verified = state
        .store
        .verify_tenant_domain(tenant.tenant_id(), &host, state.now())
        .await?;
    state.refresh_domain_routes().await?;
    audit_admin(
        &state,
        &tenant,
        &admin,
        "tenant_domain.verified",
        &host,
        json!({ "verified_at": verified.verified_at.map(|at| at.format(&Rfc3339).unwrap_or_default()) }),
    )
    .await;
    Ok(Json(domain_view(&verified)))
}

/// Move a verified binding to `active`. Both states serve; `active` records that the tenant
/// deliberately put the name into service.
#[utoipa::path(
    post,
    path = "/v1/tenant-domains/{host}/activate",
    tag = "management",
    summary = "Activate a verified custom hostname",
    params(("host" = String, Path, description = "The hostname.")),
    responses(
        (status = 200, description = "The active binding.", body = TenantDomainView),
        (status = 409, description = "The binding is not verified.")
    )
)]
pub async fn activate_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<TenantDomainView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let host = checked_host(&host)?;
    let domain = state
        .store
        .activate_tenant_domain(tenant.tenant_id(), &host)
        .await?;
    state.refresh_domain_routes().await?;
    audit_admin(
        &state,
        &tenant,
        &admin,
        "tenant_domain.activated",
        &domain.host,
        json!({ "state": "active" }),
    )
    .await;
    Ok(Json(domain_view(&domain)))
}

/// Stop serving a hostname but keep the row. A later `renew` starts a fresh claim with a new
/// nonce; the old published record can never re-open the binding.
#[utoipa::path(
    post,
    path = "/v1/tenant-domains/{host}/revoke",
    tag = "management",
    summary = "Revoke a custom hostname",
    params(("host" = String, Path, description = "The hostname.")),
    responses(
        (status = 200, description = "The revoked binding, retained for history.", body = TenantDomainView),
        (status = 409, description = "The binding is already revoked.")
    )
)]
pub async fn revoke_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<TenantDomainView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let host = checked_host(&host)?;
    let domain = state
        .store
        .revoke_tenant_domain(tenant.tenant_id(), &host, state.now())
        .await?;
    state.refresh_domain_routes().await?;
    audit_admin(
        &state,
        &tenant,
        &admin,
        "tenant_domain.revoked",
        &domain.host,
        json!({ "state": "revoked" }),
    )
    .await;
    Ok(Json(domain_view(&domain)))
}

/// Start a fresh claim for a revoked binding. The nonce changes, so the old record is inert.
#[utoipa::path(
    post,
    path = "/v1/tenant-domains/{host}/renew",
    tag = "management",
    summary = "Re-claim a revoked custom hostname",
    params(("host" = String, Path, description = "The hostname.")),
    responses(
        (status = 200, description = "The pending binding with the new TXT value.", body = TenantDomainView),
        (status = 409, description = "The binding is not revoked.")
    )
)]
pub async fn renew_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<TenantDomainView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let host = checked_host(&host)?;
    let nonce = new_nonce();
    let domain = state
        .store
        .renew_tenant_domain(tenant.tenant_id(), &host, &nonce)
        .await?;
    state.refresh_domain_routes().await?;
    audit_admin(
        &state,
        &tenant,
        &admin,
        "tenant_domain.renewed",
        &domain.host,
        json!({
            "record": verification_name(&domain.host),
            "value": verification_value(domain.tenant(), &domain.nonce),
        }),
    )
    .await;
    Ok(Json(domain_view(&domain)))
}

/// Run one DNS check now. Pending verifies, degraded recovers, serving refreshes the timestamp
/// and degrades on failure. This is exactly what the daily job does for every binding.
#[utoipa::path(
    post,
    path = "/v1/tenant-domains/{host}/recheck",
    tag = "management",
    summary = "Re-check a custom hostname's DNS record",
    params(("host" = String, Path, description = "The hostname.")),
    responses(
        (status = 200, description = "The binding after the check; inspect `state` and `check_failures`.", body = TenantDomainView),
        (status = 400, description = "The binding is revoked."),
        (status = 409, description = "The binding is not in a checkable state.")
    )
)]
pub async fn recheck_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(host): Path<String>,
) -> Result<Json<TenantDomainView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let host = checked_host(&host)?;
    let domain = state.store.tenant_domain(tenant.tenant_id(), &host).await?;
    let updated = recheck_one(&state, &tenant, &host, &domain).await?;
    state.refresh_domain_routes().await?;
    audit_transition(&state, &tenant, Some(&admin), &updated, &domain).await;
    Ok(Json(domain_view(&updated)))
}

/// One DNS check and its state transition, shared by the on-demand endpoint and the daily job.
async fn recheck_one(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    host: &str,
    domain: &TenantDomainRow,
) -> Result<TenantDomainRow, ApiError> {
    let expected = verification_value(tenant.tenant_id(), &domain.nonce);
    let matched = match txt_matches(state, host, &expected).await {
        Ok(matched) => matched,
        Err(err) => {
            tracing::warn!(%err, %host, "custom-domain DNS check failed");
            false
        }
    };
    if matched {
        match domain.state.as_str() {
            "pending" => Ok(state
                .store
                .verify_tenant_domain(tenant.tenant_id(), host, state.now())
                .await?),
            "verified" | "active" | "degraded" => {
                Ok(state.store.domain_check_ok(host, state.now()).await?)
            }
            other => Err(ApiError::problem(
                kinds::STATE_CONFLICT,
                format!("a `{other}` binding cannot be checked"),
            )),
        }
    } else {
        Ok(state.store.domain_check_failed(host, state.now()).await?)
    }
}

/// Audit a state change made by `recheck`: verified, degraded, recovered, or no change.
async fn audit_transition(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    admin: Option<&AdminPrincipal>,
    after: &TenantDomainRow,
    before: &TenantDomainRow,
) {
    let action = match (before.state.as_str(), after.state.as_str()) {
        ("pending", "verified") => "tenant_domain.verified",
        (_, "degraded") => "tenant_domain.degraded",
        ("degraded", "verified" | "active") => "tenant_domain.recovered",
        _ => return,
    };
    let payload = json!({
        "from": before.state,
        "to": after.state,
        "check_failures": after.check_failures,
    });
    match admin {
        Some(admin) => {
            audit_admin(state, tenant, admin, action, &after.host, payload).await;
        }
        None => {
            let event = AuditEvent {
                id: EventId::new(),
                at: state.now(),
                action: action.into(),
                actor_chain: vec![AuditActor::tenant(tenant.tenant_id())],
                subject: AuditSubject {
                    subject_type: AuditActorType::Tenant,
                    id: Some(tenant.tenant_id().to_typed_string()),
                },
                decision: AuditDecision::Allow,
                grant_id: None,
                jti: None,
                payload: json!({ "host": after.host, "change": payload }),
            };
            if let Err(err) = state.audit_tenant(tenant, &event).await {
                tracing::warn!(%err, action, "could not append the custom-domain audit event");
            }
        }
    }
}

/// Write a management-API audit entry for a domain action.
async fn audit_admin(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    admin: &AdminPrincipal,
    action: &str,
    host: &str,
    change: serde_json::Value,
) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: action.into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: Some(tenant.tenant_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "host": host, "change": change }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, action, "could not append the custom-domain audit event");
    }
}

/// Resolve `_monaca-verify.<host>` TXT records and compare one to `expected`.
///
/// A lookup error is a `503`, not a "no match": an operator needs to know whether the record is
/// wrong or DNS itself failed. The daily job treats both as a failed check (degrade to
/// not-serving), which is the safe reading; a successful later check restores service.
async fn txt_matches(state: &Arc<AppState>, host: &str, expected: &str) -> Result<bool, ApiError> {
    let name = verification_name(host);
    let records = txt_records(state, &name).await.map_err(|err| {
        ApiError::problem(
            kinds::UNAVAILABLE,
            format!("could not resolve {name}: {err}"),
        )
    })?;
    Ok(records.iter().any(|value| value == expected))
}

/// Fetch the TXT records for `name`, through the dev/CI mock when configured and the system
/// resolver otherwise.
async fn txt_records(state: &Arc<AppState>, name: &str) -> Result<Vec<String>, String> {
    if let Some(endpoint) = state.config.domain_txt_endpoint.as_deref() {
        #[derive(Deserialize)]
        struct MockAnswer {
            #[serde(default)]
            records: Vec<String>,
        }
        let response = state
            .http
            .get(endpoint)
            .query(&[("name", name)])
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("TXT mock answered {}", response.status()));
        }
        let answer: MockAnswer = response.json().await.map_err(|err| err.to_string())?;
        return Ok(answer.records);
    }

    let resolver = state.dns().await?;
    let lookup = resolver
        .lookup(name, hickory_resolver::proto::rr::RecordType::TXT)
        .await
        .map_err(|err| err.to_string())?;
    let mut records = Vec::new();
    for record in lookup.record_iter() {
        if let hickory_resolver::proto::rr::RData::TXT(txt) = record.data() {
            // A TXT value may be split into character-string chunks; DNS semantics concatenate
            // them before an application compares the value.
            let joined: Vec<u8> = txt
                .txt_data()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect();
            records.push(String::from_utf8_lossy(&joined).into_owned());
        }
    }
    Ok(records)
}

/// Re-check every live binding once and refresh the routing cache when any state changed.
pub async fn recheck_all(state: &Arc<AppState>) {
    let domains = match state.store.domains_for_recheck().await {
        Ok(domains) => domains,
        Err(err) => {
            tracing::warn!(%err, "custom-domain re-check could not list bindings");
            return;
        }
    };
    let mut changed = false;
    for (tenant, domain) in domains {
        match recheck_one(state, &tenant, &domain.host, &domain).await {
            Ok(updated) => {
                if updated.state != domain.state {
                    changed = true;
                    audit_transition(state, &tenant, None, &updated, &domain).await;
                }
            }
            Err(err) => {
                tracing::warn!(%err, host = %domain.host, "custom-domain re-check failed");
            }
        }
    }
    if changed && let Err(err) = state.refresh_domain_routes().await {
        tracing::warn!(%err, "custom-domain routing cache refresh failed");
    }
}

/// Start the cache-refresh and daily re-check tasks. Both are idempotent across instances: the
/// conditional updates decide the transition and the audit entry is written only by the instance
/// that observed the state change.
pub fn spawn_background(state: Arc<AppState>) {
    let refresh = state.config.domain_cache_refresh;
    let recheck = state.config.domain_recheck_interval;
    let cache_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(refresh);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(err) = cache_state.refresh_domain_routes().await {
                tracing::warn!(%err, "custom-domain routing cache refresh failed");
            }
        }
    });
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(recheck);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            recheck_all(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_lowercased_and_port_free() {
        assert_eq!(
            normalise_host("Login.ACME.com:443").as_deref(),
            Some("login.acme.com")
        );
        assert_eq!(
            normalise_host("login.acme.com.").as_deref(),
            Some("login.acme.com")
        );
    }

    #[test]
    fn non_hostnames_are_refused() {
        for raw in [
            "",
            "localhost",
            "127.0.0.1",
            "[::1]:8080",
            "acme.com/path",
            "acme.com:port",
            "-acme.com",
            "acme..com",
            "acme.com_",
        ] {
            assert_eq!(normalise_host(raw), None, "accepted {raw:?}");
        }
    }

    #[test]
    fn only_the_protocol_surface_is_rewritten() {
        for path in CUSTOM_EXACT {
            assert_eq!(custom_rest(path), Some(*path));
        }
        assert_eq!(
            custom_rest("/interaction/i-1/sign-in"),
            Some("/interaction/i-1/sign-in")
        );
        assert_eq!(custom_rest("/sso/okta/acs"), Some("/sso/okta/acs"));
        assert_eq!(custom_rest("/.well-known/openid-configuration"), None);
        assert_eq!(custom_rest("/v1/tenant"), None);
        assert_eq!(custom_rest("/internal/mail"), None);
    }

    #[test]
    fn the_txt_value_names_the_tenant_and_nonce() {
        let tenant = TenantId::from_uuid(uuid::Uuid::nil());
        let value = verification_value(tenant, "abc");
        assert!(value.starts_with("monaca-verify-v1="));
        assert!(value.ends_with(":abc"));
    }
}
