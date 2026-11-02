//! Per-purpose mail copy — docs/contracts/m0.md §6.3.
//!
//! The server writes the rendered subject and body into every outbox mail payload, so this API is
//! how a tenant rewords those mails without a deployment. A purpose with no row uses the built-in
//! default below; `DELETE` drops the row and restores it. Placeholders are checked at write time
//! because a typo would otherwise be mailed literally to every recipient.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::{EmailTemplateRow, TenantRow};
use monaca_types::EventId;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, ts};
use crate::state::AppState;

/// One mail purpose, the placeholders its copy may use, and the copy it falls back to.
pub(crate) struct EmailPurpose {
    /// The `purpose` string carried in the outbox payload.
    pub name: &'static str,
    /// The `{{…}}` names this purpose can render.
    pub variables: &'static [&'static str],
    /// Default subject when the tenant has no row.
    pub subject: &'static str,
    /// Default body when the tenant has no row.
    pub body: &'static str,
}

const CODE_VARIABLES: &[&str] = &["tenant", "code", "expires_in"];
const LINK_VARIABLES: &[&str] = &["tenant", "url", "expires_in"];
const NOTICE_VARIABLES: &[&str] = &["tenant"];

/// Every purpose the outbox can mail, in the order the console lists them.
pub(crate) const PURPOSES: &[EmailPurpose] = &[
    EmailPurpose {
        name: "sign_up",
        variables: CODE_VARIABLES,
        subject: "Your {{tenant}} verification code",
        body: "Enter {{code}} to finish creating your account. \
               The code expires in {{expires_in}} minutes.",
    },
    EmailPurpose {
        name: "sign_in",
        variables: CODE_VARIABLES,
        subject: "Your {{tenant}} sign-in code",
        body: "Enter {{code}} to sign in. The code expires in {{expires_in}} minutes.",
    },
    EmailPurpose {
        name: "password_reset",
        variables: CODE_VARIABLES,
        subject: "Reset your {{tenant}} password",
        body: "Enter {{code}} to choose a new password. \
               The code expires in {{expires_in}} minutes.",
    },
    EmailPurpose {
        name: "email_change",
        variables: CODE_VARIABLES,
        subject: "Confirm your new {{tenant}} email address",
        body: "Enter {{code}} to use this address on your account. \
               The code expires in {{expires_in}} minutes.",
    },
    EmailPurpose {
        name: "delete_account",
        variables: CODE_VARIABLES,
        subject: "Delete your {{tenant}} account",
        body: "Enter {{code}} to delete your account. This cannot be undone. \
               The code expires in {{expires_in}} minutes.",
    },
    EmailPurpose {
        name: "sign_in_link",
        variables: LINK_VARIABLES,
        subject: "Your {{tenant}} sign-in link",
        body: "Open {{url}} to sign in. The link expires in {{expires_in}} minutes.",
    },
    EmailPurpose {
        name: "email_changed",
        variables: NOTICE_VARIABLES,
        subject: "Your {{tenant}} email address changed",
        body: "The email address on your {{tenant}} account was changed. \
               If this was not you, contact your administrator.",
    },
    EmailPurpose {
        name: "password_changed",
        variables: NOTICE_VARIABLES,
        subject: "Your {{tenant}} password changed",
        body: "The password on your {{tenant}} account was changed. \
               If this was not you, reset it now.",
    },
    EmailPurpose {
        name: "account_deleted",
        variables: NOTICE_VARIABLES,
        subject: "Your {{tenant}} account was deleted",
        body: "Your {{tenant}} account was deleted. \
               If this was not you, contact your administrator.",
    },
];

/// The spec for a purpose, or `None` for a name the server never mails.
pub(crate) fn purpose(name: &str) -> Option<&'static EmailPurpose> {
    PURPOSES.iter().find(|spec| spec.name == name)
}

/// Replace every allowed `{{name}}` (spaces inside the braces are ignored) and leave anything
/// else untouched; [`check_placeholders`] is what keeps the untouched case out of real mail.
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

/// The subject and body one mail should carry.
///
/// The tenant's row wins, the default fills the gap, and the placeholders are substituted. A
/// failed lookup falls back to the default instead of failing the mail the visitor is waiting for.
pub(crate) async fn mail_copy(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    purpose_name: &str,
    values: &[(&str, &str)],
) -> (String, String) {
    let Some(spec) = purpose(purpose_name) else {
        tracing::warn!(purpose = purpose_name, "mail purpose has no template spec");
        return (purpose_name.to_owned(), String::new());
    };
    let custom = match state.store.email_template(tenant, purpose_name).await {
        Ok(row) => row,
        Err(err) => {
            tracing::warn!(
                %err,
                purpose = purpose_name,
                "could not load the tenant's mail copy; using the default"
            );
            None
        }
    };
    let subject = custom
        .as_ref()
        .map_or(spec.subject, |row| row.subject.as_str());
    let body = custom.as_ref().map_or(spec.body, |row| row.body.as_str());
    (render(subject, values), render(body, values))
}

/// One purpose as the console reads it: the effective copy plus where it comes from.
fn template_json(spec: &EmailPurpose, row: Option<&EmailTemplateRow>) -> Value {
    json!({
        "purpose": spec.name,
        "subject": row.map_or(spec.subject, |row| row.subject.as_str()),
        "body": row.map_or(spec.body, |row| row.body.as_str()),
        "variables": spec.variables,
        "customized": row.is_some(),
        "updated_at": row.map(|row| ts(row.updated_at)),
    })
}

/// `GET /v1/email-templates` — every purpose with its effective copy (§6.2).
pub async fn list_email_templates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    let rows = state.store.email_templates(&tenant).await?;
    let items: Vec<Value> = PURPOSES
        .iter()
        .map(|spec| {
            let row = rows.iter().find(|row| row.purpose == spec.name);
            template_json(spec, row)
        })
        .collect();
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

/// `PATCH /v1/email-templates/{purpose}` — replace one purpose's copy (§6.2).
///
/// Both fields are required: a partial write would have to merge with an invisible default, and
/// the console edits the pair together. `DELETE` is the way back to the default.
pub async fn update_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(purpose_name): Path<String>,
    Json(body): Json<UpdateEmailTemplateBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let Some(spec) = purpose(&purpose_name) else {
        return Err(ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown mail purpose {purpose_name:?}"),
        ));
    };
    let subject = body.subject.trim();
    let mail_body = body.body.trim();
    if subject.is_empty() || subject.chars().count() > 200 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "subject must be 1–200 characters",
        ));
    }
    if mail_body.is_empty() || mail_body.chars().count() > 10_000 {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "body must be 1–10000 characters",
        ));
    }
    for (field, text) in [("subject", subject), ("body", mail_body)] {
        check_placeholders(text, spec.variables)
            .map_err(|why| ApiError::problem(kinds::INVALID_REQUEST, format!("{field}: {why}")))?;
    }

    let row = state
        .store
        .upsert_email_template(&tenant, spec.name, subject, mail_body)
        .await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "email_template.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "purpose": spec.name,
            "subject": subject,
            "body": mail_body,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append email_template.updated audit event");
    }
    Ok(Json(template_json(spec, Some(&row))))
}

/// `DELETE /v1/email-templates/{purpose}` — restore the built-in copy (§6.2).
///
/// Idempotent: a purpose that was already default answers the same `204`, because the caller asked
/// for a state, not for a row.
pub async fn reset_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(purpose_name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let Some(spec) = purpose(&purpose_name) else {
        return Err(ApiError::problem(
            kinds::NOT_FOUND,
            format!("unknown mail purpose {purpose_name:?}"),
        ));
    };
    if state
        .store
        .delete_email_template(&tenant, spec.name)
        .await?
    {
        let event = AuditEvent {
            id: EventId::new(),
            at: state.now(),
            action: "email_template.reset".into(),
            actor_chain: vec![admin.actor()],
            subject: AuditSubject {
                subject_type: AuditActorType::Tenant,
                id: None,
            },
            decision: AuditDecision::Allow,
            grant_id: None,
            jti: None,
            payload: json!({ "purpose": spec.name }),
        };
        if let Err(err) = state.audit_tenant(&tenant, &event).await {
            tracing::warn!(%err, "could not append email_template.reset audit event");
        }
    }
    Ok(StatusCode::NO_CONTENT)
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
    fn every_default_sticks_to_its_own_variables() {
        for spec in PURPOSES {
            check_placeholders(spec.subject, spec.variables)
                .unwrap_or_else(|why| panic!("{} subject: {why}", spec.name));
            check_placeholders(spec.body, spec.variables)
                .unwrap_or_else(|why| panic!("{} body: {why}", spec.name));
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
    fn rendering_keeps_an_unclosed_placeholder_literal() {
        assert_eq!(render("oops {{code", &[("code", "1")]), "oops {{code");
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
    fn a_rendered_default_has_no_placeholders_left() {
        let values: &[(&str, &str)] = &[
            ("tenant", "demo"),
            ("code", "123456"),
            ("url", "https://sso.example/link"),
            ("expires_in", "10"),
        ];
        for spec in PURPOSES {
            for text in [spec.subject, spec.body] {
                let rendered = render(text, values);
                assert!(!rendered.contains("{{"), "{}: {rendered}", spec.name);
            }
        }
    }
}
