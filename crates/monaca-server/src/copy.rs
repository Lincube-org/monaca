//! Tenant language and custom hosted-page copy — §6.1 sign-in experience, §6.2.
//!
//! The hosted page ships one built-in dictionary (English). A tenant may replace any phrase for any
//! language and choose the language visitors get by default. Overrides are addressed by the same
//! dotted keys the page renders; a key the page does not know is stored but never shown, so a typo
//! is inert instead of becoming new copy the page cannot place.
//!
//! The public read negotiates: an explicit `?lang=` wins when it names the default or a language
//! with overrides, otherwise `Accept-Language` is matched against those languages, otherwise the
//! tenant's default applies. The page announces the chosen language on `<html lang>` and merges the
//! phrases over its built-in dictionary.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use monaca_audit::{AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_store::TenantRow;
use monaca_types::EventId;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, kinds};
use crate::management::authorize_admin;
use crate::state::AppState;

/// The most overrides one language may carry; the hosted dictionary is far smaller.
pub(crate) const MAX_PHRASES: usize = 200;
/// The longest replacement text, matching the column's check.
pub(crate) const MAX_PHRASE_CHARS: usize = 500;

/// The body of `PATCH /v1/sign-in-copy`; absent parts keep their value.
#[derive(Debug, Deserialize)]
pub struct UpdateSignInCopyBody {
    /// A new default language tag.
    pub default_language: Option<String>,
    /// The language whose phrase set is being replaced; required with `phrases`.
    pub language: Option<String>,
    /// The complete replacement set for `language`; `null` or a blank value deletes one key.
    pub phrases: Option<BTreeMap<String, Option<String>>>,
}

/// The `lang` query on the public copy read.
#[derive(Debug, Deserialize)]
pub struct SignInCopyQuery {
    /// A language tag to use when it names the default or a language with overrides.
    pub lang: Option<String>,
}

/// `GET /v1/sign-in-copy` — the tenant's default language and every stored override.
pub async fn get_sign_in_copy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin(&state, &headers).await?;
    Ok(Json(copy_document(&state, &tenant).await?))
}

/// `PATCH /v1/sign-in-copy` — change the default language and/or replace one language's phrases.
pub async fn update_sign_in_copy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateSignInCopyBody>,
) -> Result<Json<Value>, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if body.default_language.is_none() && body.phrases.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "at least one of default_language or phrases must be present",
        ));
    }
    let default_language = match body.default_language.as_deref() {
        Some(raw) => Some(normalise_language(raw).ok_or_else(|| {
            ApiError::problem(
                kinds::INVALID_REQUEST,
                "default_language must be a BCP 47 language tag",
            )
        })?),
        None => None,
    };

    let mut edited_language: Option<String> = None;
    let mut phrase_count: Option<usize> = None;
    let phrases = match body.phrases {
        Some(raw) => {
            let language = body.language.as_deref().ok_or_else(|| {
                ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "language is required when phrases are present",
                )
            })?;
            let language = normalise_language(language).ok_or_else(|| {
                ApiError::problem(
                    kinds::INVALID_REQUEST,
                    "language must be a BCP 47 language tag",
                )
            })?;
            if raw.len() > MAX_PHRASES {
                return Err(ApiError::problem(
                    kinds::INVALID_REQUEST,
                    format!("at most {MAX_PHRASES} phrases may be stored for one language"),
                ));
            }
            let mut entries: Vec<(String, String)> = Vec::new();
            for (key, value) in raw {
                let key = key.trim();
                if !valid_phrase_key(key) {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        "phrase keys must be dotted camelCase segments, such as signIn.title",
                    ));
                }
                let value = value.as_deref().map(str::trim).unwrap_or("");
                if value.is_empty() {
                    continue;
                }
                if value.chars().count() > MAX_PHRASE_CHARS {
                    return Err(ApiError::problem(
                        kinds::INVALID_REQUEST,
                        format!("phrase values must be at most {MAX_PHRASE_CHARS} characters"),
                    ));
                }
                entries.push((key.to_owned(), value.to_owned()));
            }
            edited_language = Some(language.clone());
            phrase_count = Some(entries.len());
            Some((language, entries))
        }
        None => None,
    };

    state
        .store
        .update_sign_in_copy(
            &tenant,
            default_language.as_deref(),
            phrases
                .as_ref()
                .map(|(language, entries)| (language.as_str(), entries.as_slice())),
        )
        .await?;

    let document = copy_document(&state, &tenant).await?;
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sign_in_copy.updated".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "default_language": document["default_language"],
            "language": edited_language,
            "phrase_count": phrase_count,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sign_in_copy.updated audit event");
    }
    Ok(Json(document))
}

/// `GET /t/{tenant}/sign-in-copy` — the negotiated language and the phrases it overrides.
pub async fn sign_in_copy(
    State(state): State<Arc<AppState>>,
    Path(tenant): Path<String>,
    Query(query): Query<SignInCopyQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let tenant = state.tenant(&tenant).await?;
    if !tenant.is_active() {
        return Err(ApiError::problem(kinds::NOT_FOUND, "tenant is not active"));
    }
    let experience = state.store.sign_in_experience(&tenant).await?;
    let rows = state.store.sign_in_phrases(&tenant).await?;
    let configured: BTreeSet<String> = rows.iter().map(|row| row.language.clone()).collect();
    let default_language = experience.language;

    // An explicit tag is honoured only when it names copy the page can actually show; anything
    // else falls through to negotiation rather than failing a page load over a bad preview link.
    let explicit = query
        .lang
        .as_deref()
        .and_then(normalise_language)
        .filter(|language| *language == default_language || configured.contains(language));
    let languages: Vec<String> = configured.iter().cloned().collect();
    let negotiated = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| negotiate_language(value, &languages));
    let language = explicit
        .or(negotiated)
        .unwrap_or_else(|| default_language.clone());

    let phrases: BTreeMap<&str, &str> = rows
        .iter()
        .filter(|row| row.language == language)
        .map(|row| (row.phrase_key.as_str(), row.value.as_str()))
        .collect();
    let mut listed = configured;
    listed.insert(default_language.clone());
    Ok(Json(json!({
        "language": language,
        "default_language": default_language,
        "languages": listed.into_iter().collect::<Vec<_>>(),
        "phrases": phrases,
    })))
}

/// The management document: the default language first-class, every language with its overrides.
async fn copy_document(state: &AppState, tenant: &TenantRow) -> Result<Value, ApiError> {
    let experience = state.store.sign_in_experience(tenant).await?;
    let rows = state.store.sign_in_phrases(tenant).await?;
    let default_language = experience.language;
    let mut languages: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    // The default is always listed, even with no overrides: it is the language an editor starts
    // from, and a tenant that has customised nothing should still see where to type.
    languages.entry(default_language.clone()).or_default();
    for row in rows {
        languages
            .entry(row.language)
            .or_default()
            .insert(row.phrase_key, row.value);
    }
    let languages: Vec<Value> = languages
        .into_iter()
        .map(|(language, phrases)| {
            json!({
                "language": language,
                "phrases": phrases,
            })
        })
        .collect();
    Ok(json!({
        "default_language": default_language,
        "languages": languages,
    }))
}

/// A lowercased BCP 47-shaped tag: a 2–3 letter primary subtag, then 1–8 alphanumeric subtags.
pub(crate) fn normalise_language(raw: &str) -> Option<String> {
    let language = raw.trim().to_ascii_lowercase();
    if !(2..=35).contains(&language.len()) {
        return None;
    }
    let mut segments = language.split('-');
    let primary = segments.next()?;
    if !(2..=3).contains(&primary.len()) || !primary.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return None;
    }
    for segment in segments {
        if segment.is_empty()
            || segment.len() > 8
            || !segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return None;
        }
    }
    Some(language)
}

/// A dotted key built from 2–4 camelCase segments, such as `mfaEnroll.failed`.
///
/// A single segment names a dictionary section rather than a phrase, so it is refused: it would
/// store a string the page can never render.
pub(crate) fn valid_phrase_key(key: &str) -> bool {
    if !(3..=100).contains(&key.len()) {
        return false;
    }
    let segments: Vec<&str> = key.split('.').collect();
    if !(2..=4).contains(&segments.len()) {
        return false;
    }
    segments.iter().all(|segment| {
        let mut bytes = segment.bytes();
        matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
            && bytes.all(|byte| byte.is_ascii_alphanumeric())
    })
}

/// The first acceptable `Accept-Language` tag that matches a configured language.
///
/// A configured tag matches itself or a more specific browser tag (`de` matches `de-AT`), never the
/// other way around and never across scripts (`zh-hans` does not match `zh-hant`). The header is
/// already ordered by preference, so the first match wins; `q=0` means "not acceptable" and is
/// skipped rather than counted as the least preferred.
pub(crate) fn negotiate_language(header: &str, configured: &[String]) -> Option<String> {
    let mut by_specificity: Vec<&String> = configured.iter().collect();
    by_specificity.sort_by_key(|language| std::cmp::Reverse(language.len()));
    for candidate in header.split(',') {
        let mut parts = candidate.split(';');
        let tag = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        if tag.is_empty() || tag == "*" || parts.any(refuses_language) {
            continue;
        }
        if let Some(hit) = by_specificity
            .iter()
            .find(|language| language.as_str() == tag.as_str())
        {
            return Some((*hit).clone());
        }
        if let Some(hit) = by_specificity
            .iter()
            .find(|language| tag.starts_with(&format!("{language}-")))
        {
            return Some((*hit).clone());
        }
    }
    None
}

/// Whether an `Accept-Language` parameter is `q=0`, the explicit "do not use this" marker.
fn refuses_language(parameter: &str) -> bool {
    parameter
        .trim()
        .strip_prefix("q=")
        .and_then(|value| value.trim().parse::<f32>().ok())
        .is_some_and(|quality| quality == 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_tags_are_lowercased_and_validated() {
        assert_eq!(normalise_language(" EN "), Some("en".into()));
        assert_eq!(normalise_language("zh-Hans"), Some("zh-hans".into()));
        assert_eq!(normalise_language("pt-BR"), Some("pt-br".into()));
        assert_eq!(normalise_language("es-419"), Some("es-419".into()));
        for bad in [
            "",
            "e",
            "eng-",
            "-en",
            "en--us",
            "en_us",
            "en!",
            "x-private",
        ] {
            assert_eq!(normalise_language(bad), None, "{bad}");
        }
        assert_eq!(normalise_language(&format!("en-{}", "a".repeat(9))), None);
    }

    #[test]
    fn phrase_keys_follow_the_dotted_grammar() {
        for good in [
            "signIn.title",
            "errors.accountLocked",
            "mfaEnroll.failed",
            "brand.website",
        ] {
            assert!(valid_phrase_key(good), "{good}");
        }
        for bad in [
            "",
            "signIn",
            "signIn.",
            ".title",
            "signIn..title",
            "signIn.1title",
            "sign in.title",
            "signIn.title.extra.more.still",
            "SignIn.title",
        ] {
            assert!(!valid_phrase_key(bad), "{bad}");
        }
    }

    #[test]
    fn accept_language_matches_exactly_then_by_the_primary_subtag() {
        let configured = vec!["de".to_string(), "fr".to_string()];
        assert_eq!(
            negotiate_language("fr-CH, de;q=0.8", &configured),
            Some("fr".into())
        );
        assert_eq!(
            negotiate_language("de-DE,de;q=0.9", &configured),
            Some("de".into())
        );
        // A configured script variant never answers for a different script.
        assert_eq!(
            negotiate_language("zh-hans", &["zh-hant".to_string()]),
            None
        );
        // The exact variant wins over the shorter tag even though sorting is longest-first.
        assert_eq!(
            negotiate_language("de-at-1996", &["de".to_string(), "de-at".to_string()]),
            Some("de-at".into())
        );
        // q=0 is a refusal, not the least preferred choice.
        assert_eq!(
            negotiate_language("de;q=0, fr;q=0.5", &configured),
            Some("fr".into())
        );
        assert_eq!(negotiate_language("*", &configured), None);
    }
}
