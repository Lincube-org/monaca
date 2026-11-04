//! Organizations — §5.5 and §6.2.
//!
//! Creating an organization is the provisioning transaction of §5.5: a schema, a role, the org
//! migration set and the directory row. Archiving keeps all of that — and the org's audit chain —
//! but removes the org from every operational lookup, so `authorize` and the `/v1/orgs/{org}/…`
//! sub-resources stop resolving it. That is the reversible substitute for a hard delete, which
//! would destroy the chain the tenant is required to keep.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::{OrgInvitationRow, OrgRow, TenantRow};
use monaca_types::{AccountId, EventId, OrgId, OrgInvitationId, TypedId};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::schemas::{OrgList, OrgView};
use crate::state::AppState;

/// The body of `POST /v1/orgs`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateOrgBody {
    /// The org slug: lowercase, digits and `-`, 2–31 characters.
    pub slug: String,
}

/// The body of `PATCH /v1/orgs/{org}`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOrgBody {
    /// `active` | `archived`.
    pub state: Option<String>,
}

/// The body of `POST /v1/orgs/{org}/email-domains`.
#[derive(Debug, Deserialize)]
pub struct AddDomainBody {
    /// A DNS domain name, case-insensitive and stored lowercased.
    pub domain: String,
}

/// `POST /v1/orgs` — provision an organization.
#[utoipa::path(
    post,
    path = "/v1/orgs",
    tag = "management",
    summary = "Create an organization",
    request_body = CreateOrgBody,
    responses(
        (status = 201, description = "The created organization.", body = OrgView),
        (status = 400, description = "The slug is invalid."),
        (status = 409, description = "The slug is already in use.")
    )
)]
pub async fn create_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateOrgBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let slug = body.slug.trim();
    if !valid_slug(slug) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "slug must be 2-31 characters of lowercase letters, digits or `-`",
        ));
    }

    // The id is minted before the transaction so a retried request derives the same schema and
    // role names; the slug's uniqueness is what decides, and a duplicate is a 409 (§5.5).
    let org = state
        .store
        .provision_org(&tenant, slug, OrgId::new(), false)
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "slug": org.slug, "is_default": org.is_default }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append org.created audit event");
    }

    Ok((StatusCode::CREATED, Json(org_json(&org))).into_response())
}

/// `GET /v1/orgs` — every org in the tenant, archived included.
#[utoipa::path(
    get,
    path = "/v1/orgs",
    tag = "management",
    summary = "List organizations",
    responses((status = 200, description = "The organizations.", body = OrgList))
)]
pub async fn list_orgs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<OrgList>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.all_orgs(&tenant).await?;
    let items: Vec<OrgView> = rows.iter().map(org_json).collect();
    Ok(Json(OrgList { items, next: None }))
}

/// `GET /v1/orgs/{org}` — a slug or an `org_…` id, in either state.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org}",
    tag = "management",
    summary = "Read an organization",
    params(("org" = String, Path, description = "The org slug or the `org_…` id.")),
    responses(
        (status = 200, description = "The organization.", body = OrgView),
        (status = 404, description = "No such organization.")
    )
)]
pub async fn get_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<OrgView>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let row = load_org(&state, &tenant, &org).await?;
    Ok(Json(org_json(&row)))
}

/// `PATCH /v1/orgs/{org}` — archive or reactivate.
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org}",
    tag = "management",
    summary = "Archive or reactivate an organization",
    params(("org" = String, Path, description = "The org slug or the `org_…` id.")),
    request_body = UpdateOrgBody,
    responses(
        (status = 200, description = "The updated organization.", body = OrgView),
        (status = 400, description = "state is not active or archived."),
        (status = 404, description = "No such organization.")
    )
)]
pub async fn update_org(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<UpdateOrgBody>,
) -> Result<Json<OrgView>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let Some(target) = body.state.as_deref() else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "state must be `active` or `archived`",
        ));
    };
    if !matches!(target, "active" | "archived") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "state must be `active` or `archived`",
        ));
    }

    let row = load_org(&state, &tenant, &org).await?;
    if row.state == target {
        // Idempotent: an archive of an archived org is the same answer, and writes no second event.
        return Ok(Json(org_json(&row)));
    }
    if row.is_default && target == "archived" {
        // The default org is the fallback for every flow that names none — client_credentials
        // tokens included — so it has to keep serving.
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the tenant's default organization cannot be archived",
        ));
    }
    if !state
        .store
        .set_org_state(&tenant, row.org_id(), target)
        .await?
    {
        return Err(ApiError::not_found("organization"));
    }

    let action = if target == "archived" {
        "org.archived"
    } else {
        "org.reactivated"
    };
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: action.into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(row.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "slug": row.slug, "state": target }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append {action} audit event");
    }

    let updated = state.store.org_by_id(&tenant, row.org_id()).await?;
    Ok(Json(org_json(&updated)))
}

/// `GET /v1/orgs/{org}/email-domains` — the domains that admit their own accounts (§6.2).
pub async fn list_email_domains(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let rows = state.store.org_email_domains(&tenant, org.org_id()).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(domain, created_at)| json!({ "domain": domain, "created_at": ts(created_at) }))
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/orgs/{org}/email-domains` — register a domain for just-in-time membership.
pub async fn add_email_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<AddDomainBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let Some(domain) = normalise_domain(&body.domain) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "domain must be a DNS name of lowercase letters, digits, `-` and `.`",
        ));
    };
    let created_at = state
        .store
        .add_org_email_domain(&tenant, org.org_id(), &domain)
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.domain.added".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "domain": domain }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append org.domain.added audit event");
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({ "domain": domain, "created_at": ts(created_at) })),
    )
        .into_response())
}

/// `DELETE /v1/orgs/{org}/email-domains/{domain}`.
pub async fn remove_email_domain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, domain)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let Some(domain) = normalise_domain(&domain) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "domain must be a DNS name of lowercase letters, digits, `-` and `.`",
        ));
    };
    if !state
        .store
        .remove_org_email_domain(&tenant, org.org_id(), &domain)
        .await?
    {
        return Err(ApiError::not_found("domain"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.domain.removed".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "domain": domain }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append org.domain.removed audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// The body of `POST /v1/orgs/{org}/invitations`.
#[derive(Debug, Deserialize)]
pub struct CreateInvitationBody {
    /// The invited address, matched case-insensitively against an account's primary email.
    pub email: String,
    /// `owner` | `admin` | `member`; defaults to `member`.
    pub role: Option<String>,
    /// How long the invitation keeps admitting its address; defaults to 7 days.
    pub expires_in_days: Option<i64>,
}

/// `GET /v1/orgs/{org}/invitations` — the invitations that still admit their address (§6.2).
pub async fn list_invitations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let rows = state.store.org_invitations(&tenant, org.org_id()).await?;
    let items: Vec<Value> = rows.iter().map(invitation_json).collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `POST /v1/orgs/{org}/invitations` — invite an email address to join the org.
///
/// The invitation writes a tenant-chain audit event and nothing else: no token is minted and no
/// email is sent, because acceptance is the invited account signing in (§6.2).
pub async fn create_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
    Json(body): Json<CreateInvitationBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let Some(email) = normalise_email(&body.email) else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "email must be a single address without whitespace",
        ));
    };
    let role = body.role.as_deref().unwrap_or("member");
    if !matches!(role, "owner" | "admin" | "member") {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "role must be owner, admin or member",
        ));
    }
    let days = body.expires_in_days.unwrap_or(7);
    if !(1..=90).contains(&days) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "expires_in_days must be between 1 and 90",
        ));
    }

    let expires_at = state.now() + Duration::days(days);
    let row = state
        .store
        .create_org_invitation(
            &tenant,
            org.org_id(),
            OrgInvitationId::new().uuid(),
            &email,
            role,
            admin.account_id.map(|account| account.uuid()),
            expires_at,
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.invitation.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "org": org.slug,
            "email": row.email,
            "role": row.role,
            "expires_at": ts(row.expires_at),
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append org.invitation.created audit event");
    }

    Ok((StatusCode::CREATED, Json(invitation_json(&row))).into_response())
}

/// `DELETE /v1/orgs/{org}/invitations/{invitation}` — revoke a pending invitation.
pub async fn revoke_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((org, raw)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let org = state.store.org_by_slug(&tenant, &org).await?;
    let invitation = OrgInvitationId::parse(&raw).map_err(|_| {
        ApiError::problem(kinds::INVALID_REQUEST, "not an organization invitation id")
    })?;
    let Some(email) = state
        .store
        .revoke_org_invitation(&tenant, org.org_id(), invitation.uuid())
        .await?
    else {
        return Err(ApiError::not_found("invitation"));
    };

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "org.invitation.revoked".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Org,
            id: Some(org.org_id().to_typed_string()),
        },
        decision: AuditDecision::Deny,
        grant_id: None,
        jti: None,
        payload: json!({ "org": org.slug, "email": email, "invitation": invitation.to_typed_string() }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append org.invitation.revoked audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Trim and lowercase an email, rejecting anything that is not a single address.
///
/// The rule is deliberately looser than the account schema's: an invitation may name an address
/// before the account exists, so it only has to be one `local@domain` with no whitespace.
fn normalise_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();
    if email.matches('@').count() != 1 || email.chars().any(char::is_whitespace) {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    (!local.is_empty() && !domain.is_empty()).then_some(email)
}

fn invitation_json(row: &OrgInvitationRow) -> Value {
    json!({
        "id": row.invitation_id().to_typed_string(),
        "email": row.email,
        "role": row.role,
        "invited_by": row.invited_by.map(|id| AccountId::from_uuid(id).to_typed_string()),
        "created_at": ts(row.created_at),
        "expires_at": ts(row.expires_at),
    })
}

/// Trim and lowercase a domain, rejecting anything that is not a plain DNS name.
///
/// The same rule as the `organization_email_domains` CHECK constraint (§5.6), so a malformed value
/// is a 400 here rather than a constraint violation surfacing as a 500. Shared with the SSO
/// connector configuration, whose email domains obey the same grammar.
pub(crate) fn normalise_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().to_ascii_lowercase();
    if !(2..=100).contains(&domain.len()) {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let ok = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    });
    ok.then_some(domain)
}

/// Resolve `{org}`: a typed `org_…` id, or a slug, in either state.
///
/// The lifecycle endpoints accept the id so an archived org — which no longer resolves by slug in
/// the operational lookups — stays addressable for the `PATCH` that reverses the archive.
async fn load_org(state: &AppState, tenant: &TenantRow, raw: &str) -> Result<OrgRow, ApiError> {
    if raw.starts_with("org_") {
        let id = OrgId::parse(raw)
            .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "not an organization id"))?;
        Ok(state.store.org_by_id(tenant, id).await?)
    } else {
        Ok(state.store.org_by_slug_any(tenant, raw).await?)
    }
}

fn org_json(row: &OrgRow) -> OrgView {
    OrgView {
        id: row.org_id().to_typed_string(),
        slug: row.slug.clone(),
        state: row.state.clone(),
        is_default: row.is_default,
        created_at: ts(row.created_at),
    }
}

/// The slug rule the `tenant.organizations` CHECK constraint fixes: lowercase, digits and `-`,
/// 2–31 characters, and never leading with `-`.
fn valid_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=31).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slug_rule_matches_the_ddl_check() {
        for good in ["acme", "team-1", "a1", "x-"] {
            assert!(valid_slug(good), "{good} must be a valid slug");
        }
        for bad in [
            "",
            "a",
            "Acme",
            "acme_team",
            "-acme",
            "acme team",
            &"x".repeat(32),
        ] {
            assert!(!valid_slug(bad), "{bad} must be rejected");
        }
    }

    #[test]
    fn the_invitation_email_rule_lowercases_and_rejects_junk() {
        assert_eq!(
            normalise_email(" User@Example.COM "),
            Some("user@example.com".to_owned())
        );
        for bad in [
            "",
            "user",
            "@example.com",
            "user@",
            "user@@example.com",
            "us er@example.com",
        ] {
            assert!(normalise_email(bad).is_none(), "{bad} must be rejected");
        }
    }

    #[test]
    fn the_domain_rule_lowercases_and_rejects_junk() {
        assert_eq!(
            normalise_domain(" Example.COM "),
            Some("example.com".to_owned())
        );
        assert_eq!(
            normalise_domain("jit-1.example.com"),
            Some("jit-1.example.com".to_owned())
        );
        for bad in [
            "", "a", "@", "a@b", "http://x", ".x", "x.", "-x", "x-", "x..y", "x y",
        ] {
            assert!(normalise_domain(bad).is_none(), "{bad} must be rejected");
        }
    }
}
