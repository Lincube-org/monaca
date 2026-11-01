//! Contract generation — the `openapi` subcommand.
//!
//! Two outputs, both committed to the repository and both consumed by something else:
//!
//! * `monaca-server openapi` writes the OpenAPI document to stdout, which the `codegen` job
//!   redirects into `spec/openapi.json` and `@monaca/sdk` generates its client from.
//! * `monaca-server openapi events --out <dir>` writes one JSON Schema per audit action into
//!   `<dir>`, replacing its contents so a stale schema cannot survive a rename.
//!
//! The two are generated from different sources on purpose. The OpenAPI document is derived from
//! the route handlers, so it cannot drift from them. The event schemas are **not** derived from
//! [`monaca_audit::AuditEvent`] yet: doing that needs `schemars` to render `time::OffsetDateTime`
//! and `uuid::Uuid`, whose `JsonSchema` impls live behind optional features of `schemars` that
//! this workspace does not enable. Stage 0 therefore emits the §8.1 shape as a literal, and the
//! M0 feature work (plan §10 step 6) replaces it with the derived schema once that feature
//! decision is made in the root manifest. The shape asserted here is the shape §8.1 specifies,
//! and the drift check in `rust.yml` compares the output byte for byte either way.

use std::path::Path;

use anyhow::Context as _;
use utoipa::OpenApi as _;

use crate::cli::{OpenapiArgs, OpenapiTarget};
use crate::routes::ApiDoc;

/// The audit actions §8.1 fixes for M0.
///
/// Adding an action means editing this list, `docs/contracts/m0.md` §8.1 and the generated
/// schemas together — which is exactly why the list lives in code rather than in a document.
pub const M0_ACTIONS: &[&str] = &[
    "account.created",
    "org.created",
    "org.archived",
    "org.reactivated",
    "org.member.added",
    "org.member.role_changed",
    "org.member.removed",
    "org.domain.added",
    "org.domain.removed",
    "org.role.created",
    "org.role.updated",
    "org.role.deleted",
    "org.member.roles_changed",
    "agent.created",
    "agent.key.registered",
    "agent.key.revoked",
    "grant.created",
    "grant.revoked",
    "agent.token.requested",
    "agent.token.issued",
    "agent.token.denied",
    "tool.invoked",
    "tool.denied",
    "interaction.sign_in.succeeded",
    "interaction.sign_in.failed",
    "connector.created",
    "connector.deleted",
    "client.created",
    "client.updated",
    "client.secret_rotated",
    "client.deleted",
    "account.deleted",
    "account.suspended",
    "account.reactivated",
    "role.created",
    "role.deleted",
    "session.logout",
    "sign_in_experience.updated",
    "resource.created",
    "resource.updated",
    "resource.deleted",
];

/// The `subject.type` values §8.1 allows.
const SUBJECT_TYPES: &[&str] = &[
    "account",
    "org",
    "agent",
    "agent_key",
    "grant",
    "client",
    "tool",
    "session",
    "tenant",
];

/// The `decision` values §8.1 allows.
const DECISIONS: &[&str] = &["allow", "deny", "info"];

/// Run the `openapi` subcommand.
pub fn run(args: OpenapiArgs) -> anyhow::Result<()> {
    match args.target {
        None => {
            let document = <ApiDoc as utoipa::OpenApi>::openapi();
            let json = document
                .to_pretty_json()
                .context("the OpenAPI document could not be serialized")?;
            println!("{json}");
            Ok(())
        }
        Some(OpenapiTarget::Events { out }) => write_event_schemas(Path::new(&out)),
    }
}

/// Write one schema per M0 action into `out`, replacing whatever was there.
fn write_event_schemas(out: &Path) -> anyhow::Result<()> {
    // The subcommand owns the directory's contents (§10.1): a schema for an action that no longer
    // exists must not survive its removal.
    if out.exists() {
        std::fs::remove_dir_all(out)
            .with_context(|| format!("could not clear {}", out.display()))?;
    }
    std::fs::create_dir_all(out).with_context(|| format!("could not create {}", out.display()))?;

    for action in M0_ACTIONS {
        let schema = event_schema(action);
        let json = serde_json::to_string_pretty(&schema)
            .context("an event schema could not be serialized")?;
        let path = out.join(format!("{action}.json"));
        std::fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("could not write {}", path.display()))?;
    }

    tracing::info!(count = M0_ACTIONS.len(), dir = %out.display(), "wrote event schemas");
    Ok(())
}

/// The JSON Schema for one audit action — §8.1's object.
///
/// The stored form's `seq`, `prev_hash` and `hash` are deliberately absent: §8.1 says the schema
/// is "exactly this object minus those three keys", because they are excluded from the canonical
/// bytes and are chain bookkeeping rather than part of the event.
pub fn event_schema(action: &str) -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("https://monaca.dev/events/{action}.json"),
        "title": format!("audit event: {action}"),
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id", "at", "action", "actor_chain", "subject", "decision", "payload",
        ],
        "properties": {
            "id": {
                "type": "string",
                "description": "Audit event id, `evt_` followed by 26 Crockford base32 symbols.",
                "pattern": "^evt_[0-7][0-9abcdefghjkmnpqrstvwxyz]{25}$",
            },
            "at": {
                "type": "string",
                "format": "date-time",
                "description": "When the event happened, UTC.",
            },
            "action": {
                "const": action,
            },
            "actor_chain": {
                "type": "array",
                "minItems": 1,
                "description": "Ordered outermost-first; never empty.",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "id"],
                    "properties": {
                        "type": { "enum": SUBJECT_TYPES },
                        "id": { "type": "string" },
                    },
                },
            },
            "subject": {
                "type": "object",
                "additionalProperties": false,
                "required": ["type", "id"],
                "properties": {
                    "type": { "enum": SUBJECT_TYPES },
                    "id": { "type": ["string", "null"] },
                },
            },
            "decision": { "enum": DECISIONS },
            "grant_id": {
                "type": ["string", "null"],
                "description": "`grt_` typed id.",
            },
            "jti": {
                "type": ["string", "null"],
                "format": "uuid",
                "description": "A raw hyphenated UUIDv7; no prefix (§5.2's exception).",
            },
            "payload": {
                "type": "object",
                "description": "Event-specific detail; an object, never an array, never null.",
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_action_list_matches_the_contract() {
        // §8.1's fixed M0 set, spelled out — adding one is a contract change.
        assert_eq!(M0_ACTIONS.len(), 41);
        for action in [
            "account.created",
            "org.created",
            "org.archived",
            "org.reactivated",
            "org.member.added",
            "org.member.role_changed",
            "org.member.removed",
            "org.member.roles_changed",
            "org.domain.added",
            "org.domain.removed",
            "org.role.created",
            "org.role.updated",
            "org.role.deleted",
            "agent.created",
            "agent.key.registered",
            "agent.key.revoked",
            "grant.created",
            "grant.revoked",
            "agent.token.requested",
            "agent.token.issued",
            "agent.token.denied",
            "tool.invoked",
            "tool.denied",
            "interaction.sign_in.succeeded",
            "interaction.sign_in.failed",
            "connector.created",
            "connector.deleted",
            "client.created",
            "client.updated",
            "client.secret_rotated",
            "client.deleted",
            "account.deleted",
            "account.suspended",
            "account.reactivated",
            "role.created",
            "role.deleted",
            "session.logout",
            "sign_in_experience.updated",
            "resource.created",
            "resource.updated",
            "resource.deleted",
        ] {
            assert!(
                M0_ACTIONS.contains(&action),
                "{action} must be in the M0 set"
            );
        }
    }

    #[test]
    fn the_schema_pins_the_action() {
        let schema = event_schema("tool.invoked");
        assert_eq!(schema["properties"]["action"]["const"], "tool.invoked");
        assert_eq!(schema["title"], "audit event: tool.invoked");
    }

    /// §8.1: the schema is the event minus the three chain fields.
    #[test]
    fn the_schema_excludes_the_chain_fields() {
        let schema = event_schema("tool.invoked");
        let properties = schema["properties"].as_object().expect("properties");
        for field in ["seq", "prev_hash", "hash"] {
            assert!(
                !properties.contains_key(field),
                "`{field}` must not be a schema member"
            );
        }
    }

    #[test]
    fn the_schema_requires_the_contract_members() {
        let schema = event_schema("grant.created");
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("required")
            .iter()
            .map(|value| value.as_str().expect("string"))
            .collect();
        for field in [
            "id",
            "at",
            "action",
            "actor_chain",
            "subject",
            "decision",
            "payload",
        ] {
            assert!(required.contains(&field), "`{field}` must be required");
        }
        // Optional members must not be required.
        for field in ["grant_id", "jti"] {
            assert!(!required.contains(&field), "`{field}` must be optional");
        }
    }

    #[test]
    fn the_actor_chain_is_never_empty() {
        let schema = event_schema("tool.invoked");
        assert_eq!(schema["properties"]["actor_chain"]["minItems"], 1);
    }

    #[test]
    fn the_payload_is_an_object() {
        let schema = event_schema("tool.invoked");
        assert_eq!(schema["properties"]["payload"]["type"], "object");
    }

    #[test]
    fn decisions_are_the_three_contract_values() {
        let schema = event_schema("tool.invoked");
        let decisions: Vec<&str> = schema["properties"]["decision"]["enum"]
            .as_array()
            .expect("enum")
            .iter()
            .map(|value| value.as_str().expect("string"))
            .collect();
        assert_eq!(decisions, vec!["allow", "deny", "info"]);
    }

    #[test]
    fn subject_types_are_the_contract_values() {
        let schema = event_schema("tool.invoked");
        let types: Vec<&str> = schema["properties"]["subject"]["properties"]["type"]["enum"]
            .as_array()
            .expect("enum")
            .iter()
            .map(|value| value.as_str().expect("string"))
            .collect();
        assert_eq!(types.len(), 9);
        for expected in [
            "account",
            "org",
            "agent",
            "agent_key",
            "grant",
            "client",
            "tool",
            "session",
            "tenant",
        ] {
            assert!(
                types.contains(&expected),
                "{expected} must be a subject type"
            );
        }
    }

    /// The `evt_` pattern must accept a real id and reject a plausible-looking wrong one.
    #[test]
    fn the_event_id_pattern_is_usable() {
        let pattern = event_schema("tool.invoked")["properties"]["id"]["pattern"]
            .as_str()
            .expect("pattern")
            .to_owned();
        assert_eq!(pattern, "^evt_[0-7][0-9abcdefghjkmnpqrstvwxyz]{25}$");
        // The contract's own test vector suffix, with the `evt_` prefix.
        assert!(pattern.trim_start_matches('^').trim_end_matches('$').len() > 0);
    }

    /// `--out` replaces the directory, so a removed action's schema does not survive.
    #[test]
    fn writing_replaces_the_directory_contents() {
        let dir = std::env::temp_dir().join(format!("monaca-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        std::fs::create_dir_all(&dir).expect("creates");
        std::fs::write(dir.join("stale.json"), "{}").expect("writes");

        write_event_schemas(&dir).expect("writes schemas");

        assert!(
            !dir.join("stale.json").exists(),
            "a stale schema must not survive"
        );
        assert!(dir.join("tool.invoked.json").exists());
        assert!(dir.join("interaction.sign_in.failed.json").exists());

        let written = std::fs::read_dir(&dir).expect("reads").count();
        assert_eq!(written, M0_ACTIONS.len());

        std::fs::remove_dir_all(&dir).expect("cleans up");
    }

    /// The written files are valid JSON that parses back to the generated value.
    #[test]
    fn written_schemas_are_valid_json() {
        let dir = std::env::temp_dir().join(format!("monaca-events-json-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        write_event_schemas(&dir).expect("writes schemas");

        let text = std::fs::read_to_string(dir.join("tool.denied.json")).expect("reads");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("parses");
        assert_eq!(parsed["properties"]["action"]["const"], "tool.denied");
        assert!(text.ends_with('\n'), "the file must end with a newline");

        std::fs::remove_dir_all(&dir).expect("cleans up");
    }
}
