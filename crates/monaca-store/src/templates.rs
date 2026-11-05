//! Built-in message copy, one JSON resource per locale — §6.3.
//!
//! The files are the seed for `tenant.message_templates`. They are resources rather than Rust
//! string literals so copy changes are a data diff, and they are parsed on use rather than once
//! into a global: the set is small and `migrate` runs rarely.

use serde_json::{Map, Value};

/// One seeded row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinTemplate {
    /// `message_templates.purpose`.
    pub purpose: String,
    /// Lowercase BCP 47 tag, e.g. `en` or `zh-cn`.
    pub locale: String,
    /// `email` or `sms`.
    pub channel: String,
    /// Subject line; SMS providers ignore it, but it keeps the row shape uniform.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
}

const LOCALES: &[(&str, &str)] = &[
    ("en", include_str!("../templates/en.json")),
    ("zh-cn", include_str!("../templates/zh-cn.json")),
];

/// Every built-in row for every locale, in resource order.
pub fn builtins() -> Vec<BuiltinTemplate> {
    let mut rows = Vec::new();
    for (locale, raw) in LOCALES {
        let document: Map<String, Value> =
            serde_json::from_str(*raw).expect("the built-in template resource is valid JSON");
        for (purpose, entry) in document {
            let object = entry.as_object().expect("a template entry is an object");
            let channel = text(object, &purpose, "channel");
            let subject = text(object, &purpose, "subject");
            let body = text(object, &purpose, "body");
            rows.push(BuiltinTemplate {
                purpose,
                locale: (*locale).to_owned(),
                channel,
                subject,
                body,
            });
        }
    }
    rows
}

/// One required string field of a resource entry; a missing field is a resource bug, not a runtime
/// condition, so it panics with the purpose and field name.
fn text(object: &Map<String, Value>, purpose: &str, key: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("template {purpose} has no {key}"))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_locale_carries_every_purpose() {
        let rows = builtins();
        let purposes: std::collections::BTreeSet<&str> =
            rows.iter().map(|row| row.purpose.as_str()).collect();
        assert_eq!(purposes.len(), 11);
        for locale in ["en", "zh-cn"] {
            for purpose in &purposes {
                assert!(
                    rows.iter()
                        .any(|row| row.locale == locale && row.purpose == *purpose),
                    "{locale} is missing {purpose}"
                );
            }
        }
    }
}
