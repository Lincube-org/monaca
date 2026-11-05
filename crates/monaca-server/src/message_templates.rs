//! Multilingual message copy and the template APIs — docs/contracts/m0.md §6.3/§6.5.
//!
//! Copy is data: built-in rows live in `message_templates` (seeded from the JSON resources in
//! `monaca-store`), tenant edits live in `message_template_overrides`. A send resolves
//! `user locale → tenant default language → en`; if none of the three carries the key, it fails
//! with `MONACA_TEMPLATE_MISSING` naming the purpose and the requested locale. There is no
//! English placeholder and no empty body.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::{MessageTemplateRow, TenantRow};
use monaca_types::EventId;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::copy::normalise_language;
use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// The fallback every chain ends with.
const FALLBACK_LOCALE: &str = "en";

/// One message purpose: the `purpose` string, its channel, and the placeholders it may render.
pub(crate) struct MessagePurpose {
    /// The `purpose` string carried in the outbox payload.
    pub name: &'static str,
    /// `email` or `sms`.
    pub channel: &'static str,
    /// The `{{…}}` names this purpose can render.
    pub variables: &'static [&'static str],
}

const CODE_VARIABLES: &[&str] = &["tenant", "code", "expires_in"];
const LINK_VARIABLES: &[&str] = &["tenant", "url", "expires_in"];
const NOTICE_VARIABLES: &[&str] = &["tenant"];
const INVITE_VARIABLES: &[&str] = &["tenant", "org"];

/// Every purpose the outbox can deliver, in console order.
pub(crate) const PURPOSES: &[MessagePurpose] = &[
    MessagePurpose {
        name: "sign_up",
        channel: "email",
        variables: CODE_VARIABLES,
    },
    MessagePurpose {
        name: "sign_in",
        channel: "email",
        variables: CODE_VARIABLES,
    },
    MessagePurpose {
        name: "password_reset",
        channel: "email",
        variables: CODE_VARIABLES,
    },
    MessagePurpose {
        name: "email_change",
        channel: "email",
        variables: CODE_VARIABLES,
    },
    MessagePurpose {
        name: "delete_account",
        channel: "email",
        variables: CODE_VARIABLES,
    },
    MessagePurpose {
        name: "sign_in_link",
        channel: "email",
        variables: LINK_VARIABLES,
    },
    MessagePurpose {
        name: "email_changed",
        channel: "email",
        variables: NOTICE_VARIABLES,
    },
    MessagePurpose {
        name: "password_changed",
        channel: "email",
        variables: NOTICE_VARIABLES,
    },
    MessagePurpose {
        name: "account_deleted",
        channel: "email",
        variables: NOTICE_VARIABLES,
    },
    MessagePurpose {
        name: "invitation",
        channel: "email",
        variables: INVITE_VARIABLES,
    },
    MessagePurpose {
        name: "sms_verification",
        channel: "sms",
        variables: CODE_VARIABLES,
    },
];

/// The purposes the legacy `/v1/email-templates` surface has always listed.
const LEGACY_PURPOSES: &[&str] = &[
    "sign_up",
    "sign_in",
    "password_reset",
    "email_change",
    "delete_account",
    "sign_in_link",
    "email_changed",
    "password_changed",
    "account_deleted",
];

/// The spec for a purpose, or `None` for a name the server never sends.
pub(crate) fn purpose(name: &str) -> Option<&'static MessagePurpose> {
    PURPOSES.iter().find(|spec| spec.name == name)
}

/// Replace every allowed `{{name}}` (spaces inside the braces are ignored) and leave anything
/// else untouched; [`check_placeholders`] is what keeps the untouched case out of real messages.
pub(crate) fn render(text: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = after[..end].trim();
        match values.iter().find(|(variable, _)| *variable == name) {
            Some((_, value)) => out.push_str(value),
            None => out.push_str(&rest[start..start + end + 4]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Refuse a placeholder the purpose cannot render, and a `{{` that is never closed.
fn check_placeholders(text: &str, allowed: &[&str]) -> Result<(), String> {
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err("a `{{` placeholder is never closed".into());
        };
        let name = after[..end].trim();
        if !allowed.contains(&name) {
            return Err(format!("unknown placeholder {{{{{name}}}}}"));
        }
        rest = &after[end + 2..];
    }
    Ok(())
}

/// The ordered locales a send tries: the user's, the tenant's, then English.
pub(crate) fn locale_chain(user: Option<&str>, tenant_default: &str) -> Vec<String> {
    let mut chain = Vec::new();
    for raw in [user, Some(tenant_default), Some(FALLBACK_LOCALE)] {
        if let Some(locale) = raw.and_then(normalise_language)
            && !chain.contains(&locale)
        {
            chain.push(locale);
        }
    }
    chain
}

/// The subject and body one message should carry.
///
/// A template is resolved locale by locale: the tenant's override first, then the built-in row.
/// Missing at every level is an explicit `MONACA_TEMPLATE_MISSING`, never a placeholder, an empty
/// body or a silent English sentence.
pub(crate) async fn message_copy(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    purpose_name: &str,
    user_locale: Option<&str>,
    values: &[(&str, &str)],
) -> Result<(String, String), ApiError> {
    purpose(purpose_name).ok_or_else(|| {
        state
            .metrics
            .record_template_missing(purpose_name, "unknown");
        ApiError::problem(
            kinds::TEMPLATE_MISSING,
            format!("template `{purpose_name}` is not a known purpose"),
        )
    })?;

    let tenant_default = state.store.sign_in_experience(tenant).await?.language;
    let chain = locale_chain(user_locale, &tenant_default);
    let requested = chain
        .first()
        .cloned()
        .unwrap_or_else(|| FALLBACK_LOCALE.to_owned());

    for locale in &chain {
        if let Some(row) = state
            .store
            .message_template_override(tenant, purpose_name, locale)
            .await?
        {
            return Ok((render(&row.subject, values), render(&row.body, values)));
        }
        if let Some(row) = state
            .store
            .builtin_message_template(tenant, purpose_name, locale)
            .await?
        {
            return Ok((render(&row.subject, values), render(&row.body, values)));
        }
    }

    state
        .metrics
        .record_template_missing(purpose_name, &requested);
    Err(ApiError::problem(
        kinds::TEMPLATE_MISSING,
        format!(
            "template `{purpose_name}` is missing for locale `{requested}` (tried: {})",
            chain.join(", ")
        ),
    ))
}

/// Where one effective row came from, for the console.
fn effective_json(
    spec: &MessagePurpose,
    locale: &str,
    row: &MessageTemplateRow,
    customized: bool,
) -> Value {
    json!({
        "purpose": spec.name,
        "channel": spec.channel,
        "locale": locale,
        "subject": row.subject,
        "body": row.body,
        "variables": spec.variables,
        "customized": customized,
        "updated_at": row.updated_at.map(ts),
    })
}

/// The effective English row for a legacy purpose, or `None` when neither level has it.
async fn english_row(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    purpose_name: &str,
) -> Result<Option<(MessageTemplateRow, bool)>, ApiError> {
    if let Some(row) = state
        .store
        .message_template_override(tenant, purpose_name, "en")
        .await?
    {
        return Ok(Some((row, true)));
    }
    Ok(state
        .store
        .builtin_message_template(tenant, purpose_name, "en")
        .await?
        .map(|row| (row, false)))
}

/// `GET /v1/email-templates` — the legacy English view of the nine email purposes (§6.2).
pub async fn list_email_templates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let mut items = Vec::new();
    for name in LEGACY_PURPOSES {
        let spec = purpose(name).ok_or_else(|| ApiError::internal("unknown legacy purpose"))?;
        match english_row(&state, &tenant, name).await? {
            Some((row, customized)) => {
                items.push(effective_json(spec, "en", &row, customized));
            }
            None => {
                // The row was purged; list the purpose without copy so the console can restore it.
                items.push(json!({
                    "purpose": spec.name,
                    "channel": spec.channel,
                    "locale": "en",
                    "subject": null,
                    "body": null,
                    "variables": spec.variables,
                    "customized": false,
                    "updated_at": null,
                }));
            }
        }
    }
    Ok(Json(json!({ "items": items, "next": null })))
}

/// The body of `PATCH /v1/email-templates/{purpose}`.
#[derive(Debug, Deserialize)]
pub struct UpdateEmailTemplateBody {
    /// The subject line.
    pub subject: String,
    /// The plain-text body.
    pub body: String,
}

/// `PATCH /v1/email-templates/{purpose}` — replace one legacy purpose's English copy (§6.2).
pub async fn update_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(purpose_name): Path<String>,
    Json(body): Json<UpdateEmailTemplateBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if !LEGACY_PURPOSES.contains(&purpose_name.as_str()) {
        return Err(ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown mail purpose {purpose_name:?}"),
        ));
    }
    let spec = purpose(&purpose_name).ok_or_else(|| ApiError::internal("unknown purpose"))?;
    let (subject, mail_body) = checked_copy(spec, &body.subject, &body.body)?;

    let row = state
        .store
        .upsert_message_template_override(
            &tenant,
            spec.name,
            "en",
            spec.channel,
            subject,
            mail_body,
        )
        .await?;
    audit_template(
        &state,
        &tenant,
        &admin,
        "email_template.updated",
        spec.name,
        "en",
        subject,
        mail_body,
    )
    .await;
    Ok(Json(effective_json(spec, "en", &row, true)))
}

/// `DELETE /v1/email-templates/{purpose}` — drop the English override (§6.2).
pub async fn reset_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(purpose_name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if !LEGACY_PURPOSES.contains(&purpose_name.as_str()) {
        return Err(ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown mail purpose {purpose_name:?}"),
        ));
    }
    if state
        .store
        .delete_message_template_override(&tenant, &purpose_name, "en")
        .await?
    {
        audit_template(
            &state,
            &tenant,
            &admin,
            "email_template.reset",
            &purpose_name,
            "en",
            "",
            "",
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The query of `GET /v1/message-templates`.
#[derive(Debug, Deserialize)]
pub struct ListMessagesQuery {
    /// Optional `email` | `sms` filter.
    pub channel: Option<String>,
}

/// `GET /v1/message-templates` — every purpose and locale with its effective copy (§6.2).
pub async fn list_message_templates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListMessagesQuery>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let builtin = state.store.builtin_message_templates(&tenant).await?;
    let overrides = state.store.message_template_overrides(&tenant).await?;

    // (purpose, locale) → effective row and whether an override supplied it.
    let mut merged: BTreeMap<(String, String), (MessageTemplateRow, bool)> = BTreeMap::new();
    for row in builtin {
        merged.insert((row.purpose.clone(), row.locale.clone()), (row, false));
    }
    for row in overrides {
        merged.insert((row.purpose.clone(), row.locale.clone()), (row, true));
    }

    let mut items = Vec::new();
    for ((purpose_name, locale), (row, customized)) in merged {
        let Some(spec) = purpose(&purpose_name) else {
            continue;
        };
        if let Some(channel) = query.channel.as_deref()
            && spec.channel != channel
        {
            continue;
        }
        items.push(effective_json(spec, &locale, &row, customized));
    }
    Ok(Json(json!({ "items": items, "next": null })))
}

/// The body of `PATCH /v1/message-templates/{purpose}/{locale}`.
#[derive(Debug, Deserialize)]
pub struct UpdateMessageTemplateBody {
    /// The subject line.
    pub subject: String,
    /// The plain-text body.
    pub body: String,
}

/// `PATCH /v1/message-templates/{purpose}/{locale}` — upsert one locale's copy (§6.2).
pub async fn update_message_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((purpose_name, locale)): Path<(String, String)>,
    Json(body): Json<UpdateMessageTemplateBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let spec = purpose(&purpose_name).ok_or_else(|| {
        ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown message purpose {purpose_name:?}"),
        )
    })?;
    let locale = normalise_language(&locale).ok_or_else(|| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "locale must be a BCP 47 language tag",
        )
    })?;
    let (subject, mail_body) = checked_copy(spec, &body.subject, &body.body)?;

    let row = state
        .store
        .upsert_message_template_override(
            &tenant,
            spec.name,
            &locale,
            spec.channel,
            subject,
            mail_body,
        )
        .await?;
    audit_template(
        &state,
        &tenant,
        &admin,
        "message_template.updated",
        spec.name,
        &locale,
        subject,
        mail_body,
    )
    .await;
    Ok(Json(effective_json(spec, &locale, &row, true)))
}

/// The query of `DELETE /v1/message-templates/{purpose}/{locale}`.
#[derive(Debug, Deserialize)]
pub struct DeleteTemplateQuery {
    /// Delete the built-in row too, leaving no copy for the locale.
    #[serde(default)]
    pub builtin: bool,
}

/// `DELETE /v1/message-templates/{purpose}/{locale}` — remove an override, or the built-in row.
///
/// `?builtin=true` is the explicit "no copy in this locale" state. A send that falls through to
/// it fails with `MONACA_TEMPLATE_MISSING`; `POST …/restore` brings the built-in row back.
pub async fn delete_message_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((purpose_name, locale)): Path<(String, String)>,
    Query(query): Query<DeleteTemplateQuery>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let spec = purpose(&purpose_name).ok_or_else(|| {
        ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown message purpose {purpose_name:?}"),
        )
    })?;
    let locale = normalise_language(&locale).ok_or_else(|| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "locale must be a BCP 47 language tag",
        )
    })?;

    let removed = state
        .store
        .delete_message_template_override(&tenant, spec.name, &locale)
        .await?;
    let removed_builtin = if query.builtin {
        state
            .store
            .delete_builtin_message_template(&tenant, spec.name, &locale)
            .await?
    } else {
        false
    };
    if removed || removed_builtin {
        audit_template(
            &state,
            &tenant,
            &admin,
            "message_template.deleted",
            spec.name,
            &locale,
            "",
            "",
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/message-templates/{purpose}/{locale}/restore` — re-seed the built-in row (§6.2).
pub async fn restore_message_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((purpose_name, locale)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let spec = purpose(&purpose_name).ok_or_else(|| {
        ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown message purpose {purpose_name:?}"),
        )
    })?;
    let locale = normalise_language(&locale).ok_or_else(|| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "locale must be a BCP 47 language tag",
        )
    })?;
    if !state
        .store
        .restore_builtin_message_template(&tenant, spec.name, &locale)
        .await?
    {
        return Err(ApiError::problem(
            kinds::NOT_FOUND,
            format!("no built-in copy for `{}` in `{locale}`", spec.name),
        ));
    }
    audit_template(
        &state,
        &tenant,
        &admin,
        "message_template.restored",
        spec.name,
        &locale,
        "",
        "",
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Trim and validate one subject/body pair, returning owned values.
fn checked_copy<'a>(
    spec: &MessagePurpose,
    subject: &'a str,
    body: &'a str,
) -> Result<(&'a str, &'a str), ApiError> {
    let subject = subject.trim();
    let body = body.trim();
    if subject.is_empty() || subject.chars().count() > 200 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "subject must be 1–200 characters",
        ));
    }
    if body.is_empty() || body.chars().count() > 10_000 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "body must be 1–10000 characters",
        ));
    }
    for (field, text) in [("subject", subject), ("body", body)] {
        check_placeholders(text, spec.variables)
            .map_err(|why| ApiError::problem(kinds::INVALID_REQUEST, format!("{field}: {why}")))?;
    }
    Ok((subject, body))
}

/// Append a tenant-chain audit event for a template write.
#[allow(clippy::too_many_arguments)]
async fn audit_template(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    admin: &crate::management::AdminPrincipal,
    action: &str,
    purpose_name: &str,
    locale: &str,
    subject: &str,
    body: &str,
) {
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: action.into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "purpose": purpose_name,
            "locale": locale,
            "subject": subject,
            "body": body,
        }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append {action} audit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_purpose_is_named_once() {
        let mut names: Vec<&str> = PURPOSES.iter().map(|spec| spec.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "a purpose name is used twice");
    }

    #[test]
    fn the_legacy_list_is_the_original_nine_email_purposes() {
        assert_eq!(LEGACY_PURPOSES.len(), 9);
        for name in LEGACY_PURPOSES {
            assert_eq!(purpose(name).expect("known purpose").channel, "email");
        }
    }

    #[test]
    fn rendering_substitutes_allowed_names_and_leaves_the_rest() {
        assert_eq!(
            render(
                "Hi {{tenant}}: {{ code }} / {{expires_in}} / {{missing}}",
                &[("tenant", "demo"), ("code", "123456"), ("expires_in", "10")]
            ),
            "Hi demo: 123456 / 10 / {{missing}}"
        );
    }

    #[test]
    fn placeholder_checks_name_the_offending_text() {
        assert!(check_placeholders("enter {{code}}", &["code"]).is_ok());
        let unknown = check_placeholders("enter {{nope}}", &["code"]).expect_err("unknown");
        assert!(unknown.contains("{{nope}}"), "{unknown}");
        let unclosed = check_placeholders("enter {{code", &["code"]).expect_err("unclosed");
        assert!(unclosed.contains("closed"), "{unclosed}");
    }

    #[test]
    fn the_locale_chain_drops_duplicates_and_ends_in_english() {
        assert_eq!(
            locale_chain(Some("zh-CN"), "en"),
            vec!["zh-cn".to_owned(), "en".to_owned()]
        );
        assert_eq!(
            locale_chain(None, "zh-cn"),
            vec!["zh-cn".to_owned(), "en".to_owned()]
        );
        assert_eq!(
            locale_chain(Some("de"), "de"),
            vec!["de".to_owned(), "en".to_owned()]
        );
    }
}
