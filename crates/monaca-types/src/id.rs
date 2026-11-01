//! Typed external identifiers — docs/contracts/m0.md §5.2.
//!
//! Encoded form is `<prefix>_<suffix>`. The suffix is the TypeID v0.3 suffix encoding of the
//! 16 UUIDv7 bytes: treat the UUID as a 128-bit big-endian integer, prepend two zero bits
//! (130 bits) and emit 26 symbols of 5 bits each from the lowercase Crockford base32 alphabet
//! (no `i l o u`, no padding). The two extra zero bits are why the first symbol is always
//! `0`–`7`.
//!
//! `data-encoding`'s built-in base32 encodings use a different bit alignment, so the loop below
//! is written by hand over a `u128`; `packages/core`'s TypeScript side does the same over a
//! `bigint`. Both must pass the vectors in §5.2.
//!
//! Decoding is total: a wrong length, a symbol outside the alphabet, a first symbol above `7`,
//! an unknown prefix or a non-v7 version nibble is an error, never a default.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::{Uuid, Version};

/// Number of base32 symbols in a suffix: 130 bits / 5 bits, rounded up.
const SUFFIX_LEN: usize = 26;

/// Lowercase Crockford base32, minus `i`, `l`, `o` and `u` — the TypeID v0.3 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Why a typed identifier could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypedIdError {
    /// The string has no `_`, or an empty prefix or suffix.
    #[error("typed id must have the form <prefix>_<suffix>")]
    Shape,
    /// The prefix is not one of the prefixes in §5.2.
    #[error("unknown typed id prefix `{0}`")]
    UnknownPrefix(String),
    /// The prefix is known but belongs to a different entity type.
    #[error("expected prefix `{expected}`, got `{found}`")]
    WrongPrefix { expected: String, found: String },
    /// The suffix is not exactly 26 symbols.
    #[error("typed id suffix must be exactly 26 characters, got {0}")]
    Length(usize),
    /// The suffix contains a symbol outside the Crockford base32 alphabet.
    #[error("invalid base32 symbol `{0}` in typed id suffix")]
    Alphabet(char),
    /// The first symbol is above `7`, i.e. the two padding bits were not zero.
    #[error("typed id suffix has non-zero padding bits")]
    Padding,
    /// The decoded UUID's version nibble is not 7.
    #[error("typed id must wrap a UUIDv7, got version {0}")]
    NotV7(u8),
    /// The UUID could not be parsed at all.
    #[error("typed id does not wrap a valid UUID")]
    NotUuid,
}

/// A typed identifier over a UUIDv7 primary key.
///
/// The prefix is fixed per entity type; [`TypedId::from_uuid`] is the only infallible
/// constructor because it cannot produce a prefix mismatch.
pub trait TypedId: Copy + Clone + PartialEq + Eq + std::hash::Hash + Send + Sync + 'static {
    /// The §5.2 prefix, without the trailing underscore.
    const PREFIX: &'static str;

    /// Wrap an already-validated UUIDv7.
    fn from_uuid(uuid: Uuid) -> Self;

    /// The wrapped UUID.
    fn as_uuid(&self) -> Uuid;

    /// The `<prefix>_<suffix>` wire form.
    fn to_typed_string(self) -> String
    where
        Self: Sized,
    {
        format!("{}_{}", Self::PREFIX, encode_suffix(self.as_uuid()))
    }

    /// Decode a typed string, rejecting a wrong or unknown prefix, any malformed suffix, and a
    /// UUID that is not a v7 primary key.
    fn parse(input: &str) -> Result<Self, TypedIdError>
    where
        Self: Sized,
    {
        let (prefix, suffix) = split(input)?;
        if prefix != Self::PREFIX {
            return Err(TypedIdError::WrongPrefix {
                expected: Self::PREFIX.to_owned(),
                found: prefix.to_owned(),
            });
        }
        let uuid = decode_suffix(suffix)?;
        // §5.2: "a non-v7 version nibble is an error, never a default". This check sits here
        // rather than in `decode_suffix` so that the codec stays a total, reversible
        // 26-symbol <-> UUID mapping — the §5.2 vectors include the all-zeros and all-ones
        // UUIDs, which are versions Nil and Max and are not valid keys.
        match uuid.get_version() {
            Some(Version::SortRand) => Ok(Self::from_uuid(uuid)),
            Some(other) => Err(TypedIdError::NotV7(other as u8)),
            None => Err(TypedIdError::NotV7(0)),
        }
    }
}

/// Encode a UUID as the 26-symbol TypeID v0.3 suffix.
pub fn encode_suffix(uuid: Uuid) -> String {
    let mut value = uuid.as_u128();
    let mut out = [0u8; SUFFIX_LEN];
    // Least-significant symbol first, so the two padding bits at the top are consumed by the
    // final iteration and every symbol is `value & 0x1f`.
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 0x1f) as usize];
        value >>= 5;
    }
    // 26 * 5 = 130 bits, so the top three symbols' high bits are padding. A u128 shifted right
    // 130 times is zero, and the loop above only reads 26 * 5 = 130 bits out of a 128-bit value,
    // which is exactly the TypeID encoding.
    std::str::from_utf8(&out)
        .expect("the alphabet is ASCII")
        .to_owned()
}

/// Decode a 26-symbol TypeID v0.3 suffix into its UUID.
///
/// This is a pure, total 26-symbol <-> 16-byte mapping and deliberately does not require the
/// UUID to be v7: §5.2's own vectors include the all-zeros and all-ones UUIDs, which are
/// versions `Nil` and `Max`. The v7 requirement is enforced at the typed-ID boundary
/// ([`TypedId::parse`]).
pub fn decode_suffix(suffix: &str) -> Result<Uuid, TypedIdError> {
    let bytes = suffix.as_bytes();
    if bytes.len() != SUFFIX_LEN {
        return Err(TypedIdError::Length(bytes.len()));
    }
    let mut value: u128 = 0;
    for (index, byte) in bytes.iter().enumerate() {
        let digit = alphabet_index(*byte).ok_or(TypedIdError::Alphabet(*byte as char))?;
        // The first symbol carries only three significant bits: 130 bits total minus 128 bits of
        // UUID leaves two zero padding bits on top, so a first symbol above 7 overflows.
        if index == 0 && digit > 7 {
            return Err(TypedIdError::Padding);
        }
        value = (value << 5) | u128::from(digit);
    }
    Ok(Uuid::from_u128(value))
}

fn alphabet_index(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

fn split(input: &str) -> Result<(&str, &str), TypedIdError> {
    let (prefix, suffix) = input.split_once('_').ok_or(TypedIdError::Shape)?;
    if prefix.is_empty() || suffix.is_empty() {
        return Err(TypedIdError::Shape);
    }
    if !is_known_prefix(prefix) {
        return Err(TypedIdError::UnknownPrefix(prefix.to_owned()));
    }
    Ok((prefix, suffix))
}

fn is_known_prefix(prefix: &str) -> bool {
    matches!(
        prefix,
        "ten"
            | "org"
            | "acc"
            | "agt"
            | "akey"
            | "grt"
            | "cli"
            | "ses"
            | "evt"
            | "dlg"
            | "apr"
            | "int"
            | "key"
            | "pky"
            | "mfd"
            | "rol"
            | "res"
            | "inv"
            | "whk"
            | "dlv"
    )
}

/// Declares one identifier newtype. `$prefix` must be the §5.2 prefix.
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// Wrap a UUIDv7. The caller is responsible for it being a v7.
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Generate a fresh UUIDv7 identifier.
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// The wrapped UUID, as stored in the database.
            pub fn uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl TypedId for $name {
            const PREFIX: &'static str = $prefix;

            fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_typed_string())
            }
        }

        impl FromStr for $name {
            type Err = TypedIdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <Self as TypedId>::parse(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = TypedIdError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                <Self as TypedId>::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_typed_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                <Self as TypedId>::parse(&raw).map_err(D::Error::custom)
            }
        }
    };
}

typed_id!(
    /// Tenant (`ten_…`).
    TenantId,
    "ten"
);
typed_id!(
    /// Organization (`org_…`).
    OrgId,
    "org"
);
typed_id!(
    /// Account (`acc_…`).
    AccountId,
    "acc"
);
typed_id!(
    /// Agent (`agt_…`).
    AgentId,
    "agt"
);
typed_id!(
    /// Agent key (`akey_…`).
    AgentKeyId,
    "akey"
);
typed_id!(
    /// Grant (`grt_…`).
    GrantId,
    "grt"
);
typed_id!(
    /// Client row (`cli_…`). The protocol `client_id` is a separate string column.
    ClientId,
    "cli"
);
typed_id!(
    /// Session (`ses_…`).
    SessionId,
    "ses"
);
typed_id!(
    /// Audit event (`evt_…`).
    EventId,
    "evt"
);
typed_id!(
    /// Delegation (`dlg_…`).
    DelegationId,
    "dlg"
);
typed_id!(
    /// Approval (`apr_…`).
    ApprovalId,
    "apr"
);
typed_id!(
    /// Interaction (`int_…`): the authorize → auth-ui handshake.
    InteractionId,
    "int"
);
typed_id!(
    /// Tenant signing key (`key_…`); this value is the JWS `kid`.
    KeyId,
    "key"
);
typed_id!(
    /// Passkey credential (`pky_…`); the raw WebAuthn credential id is a separate column.
    PasskeyId,
    "pky"
);
typed_id!(
    /// Trusted MFA device (`mfd_…`): a browser remembered past the second factor.
    TrustedDeviceId,
    "mfd"
);
typed_id!(
    /// RBAC role (`rol_…`): a named set of permission scopes.
    RoleId,
    "rol"
);
typed_id!(
    /// API resource (`res_…`): a registered resource indicator and the scopes it defines.
    ResourceId,
    "res"
);
typed_id!(
    /// Organization invitation (`inv_…`): an email address invited to join an organization.
    OrgInvitationId,
    "inv"
);
typed_id!(
    /// Webhook (`whk_…`): a tenant's outbound event subscription.
    WebhookId,
    "whk"
);
typed_id!(
    /// Webhook delivery (`dlv_…`): one attempt summary under a subscription.
    WebhookDeliveryId,
    "dlv"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// §5.2's vectors. Both implementations (this one and `packages/core`'s `bigint` loop)
    /// must pass them, so they are asserted here verbatim.
    const VECTORS: &[(&str, &str)] = &[
        (
            "00000000-0000-0000-0000-000000000000",
            "00000000000000000000000000",
        ),
        (
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "01h455vb4pex5vsknk084sn02q",
        ),
        (
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "7zzzzzzzzzzzzzzzzzzzzzzzzz",
        ),
    ];

    #[test]
    fn suffix_matches_the_contract_vectors() {
        for (uuid, suffix) in VECTORS {
            let parsed = Uuid::parse_str(uuid).expect("vector uuid parses");
            assert_eq!(&encode_suffix(parsed), suffix, "encode {uuid}");
        }
    }

    #[test]
    fn suffix_round_trips_every_vector() {
        for (uuid, suffix) in VECTORS {
            let parsed = Uuid::parse_str(uuid).expect("vector uuid parses");
            assert_eq!(
                decode_suffix(suffix).expect("vector suffix decodes"),
                parsed
            );
        }
    }

    #[test]
    fn typed_id_round_trips() {
        let id = TenantId::new();
        let text = id.to_typed_string();
        assert!(text.starts_with("ten_"), "got {text}");
        assert_eq!(text.len(), "ten_".len() + SUFFIX_LEN);
        assert_eq!(TenantId::parse(&text).expect("parses"), id);
        assert_eq!(text.parse::<TenantId>().expect("FromStr parses"), id);
    }

    #[test]
    fn display_and_serde_agree_with_the_wire_form() {
        let id = AccountId::from_uuid(
            Uuid::parse_str("01890a5d-ac96-774b-bcce-b302099a8057").expect("uuid"),
        );
        assert_eq!(id.to_string(), "acc_01h455vb4pex5vsknk084sn02q");
        let json = serde_json::to_string(&id).expect("serializes");
        assert_eq!(json, "\"acc_01h455vb4pex5vsknk084sn02q\"");
        let back: AccountId = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, id);
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let id = TenantId::new();
        let text = id.to_typed_string();
        let err = OrgId::parse(&text).expect_err("prefix mismatch must fail");
        assert_eq!(
            err,
            TypedIdError::WrongPrefix {
                expected: "org".to_owned(),
                found: "ten".to_owned()
            }
        );
    }

    #[test]
    fn unknown_prefix_is_rejected() {
        let err = TenantId::parse("nope_01h455vb4pex5vsknk084sn02q").expect_err("unknown prefix");
        assert_eq!(err, TypedIdError::UnknownPrefix("nope".to_owned()));
    }

    #[test]
    fn malformed_suffixes_are_rejected() {
        // Wrong length.
        assert_eq!(
            TenantId::parse("ten_abc").expect_err("short"),
            TypedIdError::Length(3)
        );
        // A symbol outside the alphabet (`i`, `l`, `o`, `u` are excluded on purpose).
        assert_eq!(
            TenantId::parse("ten_i1h455vb4pex5vsknk084sn02q").expect_err("bad symbol"),
            TypedIdError::Alphabet('i')
        );
        // First symbol above 7 sets padding bits.
        assert_eq!(
            TenantId::parse("ten_z1h455vb4pex5vsknk084sn02q").expect_err("padding"),
            TypedIdError::Padding
        );
        // No separator at all.
        assert_eq!(
            TenantId::parse("ten").expect_err("shape"),
            TypedIdError::Shape
        );
        assert_eq!(
            TenantId::parse("_x").expect_err("empty prefix"),
            TypedIdError::Shape
        );
    }

    #[test]
    fn non_v7_uuid_is_rejected_by_parse() {
        // A v4 UUID encodes to a valid 26-symbol suffix, but §5.2 requires a v7 primary key,
        // so the typed-ID boundary must reject it even though the codec accepts it.
        let v4 = Uuid::parse_str("a1a2a3a4-b1b2-41c2-d1d2-d3d4d5d6d7d8").expect("uuid");
        let suffix = encode_suffix(v4);
        assert_eq!(decode_suffix(&suffix).expect("codec is total"), v4);
        match TenantId::parse(&format!("ten_{suffix}")) {
            Err(TypedIdError::NotV7(4)) => {}
            other => panic!("expected NotV7(4), got {other:?}"),
        }
    }

    #[test]
    fn the_all_zeros_and_all_ones_vectors_are_not_valid_keys() {
        // §5.2's vectors round-trip through the codec, but neither UUID is a v7, so neither may
        // be accepted as an identifier. The third vector is a real v7 and stays valid — it is
        // covered by `suffix_round_trips_every_vector` and `typed_id_round_trips`.
        for (uuid, suffix) in [
            (
                "00000000-0000-0000-0000-000000000000",
                "00000000000000000000000000",
            ),
            (
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "7zzzzzzzzzzzzzzzzzzzzzzzzz",
            ),
        ] {
            let parsed = Uuid::parse_str(uuid).expect("vector uuid parses");
            assert_eq!(decode_suffix(suffix).expect("codec is total"), parsed);
            assert!(
                TenantId::parse(&format!("ten_{suffix}")).is_err(),
                "{suffix} must not decode to a v7 identifier"
            );
        }
    }

    #[test]
    fn suffix_length_is_exact() {
        assert_eq!(encode_suffix(Uuid::nil()).len(), SUFFIX_LEN);
        assert_eq!(encode_suffix(Uuid::max()).len(), SUFFIX_LEN);
    }

    #[test]
    fn all_prefixes_round_trip() {
        fn check<T: TypedId>(expected_prefix: &str) {
            let text = T::from_uuid(Uuid::now_v7()).to_typed_string();
            assert!(text.starts_with(expected_prefix), "got {text}");
            assert!(T::parse(&text).is_ok(), "round trip failed for {text}");
        }
        check::<TenantId>("ten_");
        check::<OrgId>("org_");
        check::<AccountId>("acc_");
        check::<AgentId>("agt_");
        check::<AgentKeyId>("akey_");
        check::<GrantId>("grt_");
        check::<ClientId>("cli_");
        check::<SessionId>("ses_");
        check::<EventId>("evt_");
        check::<DelegationId>("dlg_");
        check::<ApprovalId>("apr_");
        check::<InteractionId>("int_");
        check::<KeyId>("key_");
        check::<PasskeyId>("pky_");
        check::<ResourceId>("res_");
        check::<WebhookId>("whk_");
        check::<WebhookDeliveryId>("dlv_");
    }
}
