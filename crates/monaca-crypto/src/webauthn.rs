//! WebAuthn server-side verification for passkeys.
//!
//! Only the parts a passkey ceremony needs are implemented: a registration with the `none`
//! attestation format and an assertion over an ES256 credential. Supporting more attestation
//! formats would mean trusting vendor roots, which a hosted login page does not need — it asks the
//! browser for `attestation: "none"` and verifies what came back.
//!
//! The wire format is CBOR (attestation object and COSE public key) and base64url (what the browser
//! serialises into JSON). Everything is parsed here rather than in the server so a handler never
//! touches attacker-controlled bytes without these checks:
//!
//! * the client data names the ceremony this code expects (`webauthn.create` / `webauthn.get`),
//! * its challenge is the one this server generated,
//! * its origin is this deployment's sign-in origin,
//! * the authenticator data hashes the expected RP id,
//! * and the assertion signature verifies over `authData || SHA-256(clientDataJSON)`.
//!
//! Replaying a registration or an assertion needs a *new* challenge: the challenge is the replay
//! defence, so the caller must delete it from its pending state before this function runs.

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::CryptoError;

/// The authenticator-data flag that marks user presence.
const FLAG_USER_PRESENT: u8 = 0x01;
/// The authenticator-data flag that marks user verification (PIN, biometrics).
const FLAG_USER_VERIFIED: u8 = 0x04;
/// The authenticator-data flag that says attested credential data follows.
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;

/// The longest credential id the WebAuthn spec permits.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// The length of a generated challenge, in bytes. 256 bits of entropy is what every library uses.
const CHALLENGE_LEN: usize = 32;

/// A credential the registration ceremony proved control of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// The raw credential id the authenticator chose (the `rawId` the browser reports).
    pub credential_id: Vec<u8>,
    /// The COSE public key, exactly as the authenticator embedded it. Sealed before storage.
    pub public_key: Vec<u8>,
    /// The authenticator's counter at registration; `0` means it does not count.
    pub sign_count: u64,
    /// The authenticator's model id, when it reports one other than all zeros.
    pub aaguid: Option<Uuid>,
}

/// A fresh challenge for one ceremony.
pub fn generate_challenge() -> Vec<u8> {
    let mut bytes = vec![0u8; CHALLENGE_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Base64url (no padding), the encoding WebAuthn JSON uses for binary values.
pub fn encode_base64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// Decode a base64url value, tolerating the padding some clients add.
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, CryptoError> {
    let value = value.trim_end_matches('=');
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|err| malformed(format!("not base64url: {err}")))
}

/// Verify a `navigator.credentials.create()` result and extract the credential.
///
/// `challenge` is the value this server generated and returned in the creation options; `rp_id`
/// is the bare host the origin belongs to (no scheme, no port).
pub fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
) -> Result<RegisteredCredential, CryptoError> {
    let client = parse_client_data(client_data_json)?;
    if client.typ != "webauthn.create" {
        return Err(malformed("client data is not a registration"));
    }
    check_client(&client, challenge, origin)?;
    if client.cross_origin {
        return Err(malformed("cross-origin registration is not accepted"));
    }

    let Cbor::Map(entries) = parse_cbor(attestation_object)? else {
        return Err(malformed("attestation object is not a CBOR map"));
    };
    let fmt = map_text(&entries, "fmt")?;
    let auth_data = map_bytes(&entries, "authData")?;
    // The page requests `attestation: "none"`, so a statement here would be either an unexpected
    // authenticator behaviour or a forged response; neither is verifiable without vendor roots.
    if fmt != "none" {
        return Err(CryptoError::BadSignature(format!(
            "unsupported attestation format `{fmt}`"
        )));
    }

    let auth = parse_authenticator_data(auth_data)?;
    check_rp_id(&auth, rp_id)?;
    let Some(credential) = auth.credential else {
        return Err(malformed("registration carries no attested credential"));
    };

    // The COSE key must be an ES256 P-256 key; parsing it now also rejects a key the assertion
    // path could never verify with, instead of storing an unusable passkey.
    let _key = cose_to_sec1(credential.public_key)?;

    Ok(RegisteredCredential {
        credential_id: credential.credential_id.to_vec(),
        public_key: credential.public_key.to_vec(),
        sign_count: auth.sign_count,
        aaguid: (credential.aaguid != [0u8; 16]).then(|| Uuid::from_bytes(credential.aaguid)),
    })
}

/// Verify a `navigator.credentials.get()` result and return the authenticator's new counter.
///
/// `public_key` is the COSE key stored at registration, after unsealing. A `0` counter in either
/// place means the authenticator does not implement one, so the caller must not enforce monotonicity
/// when it is zero.
pub fn verify_assertion(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
) -> Result<u64, CryptoError> {
    let client = parse_client_data(client_data_json)?;
    if client.typ != "webauthn.get" {
        return Err(malformed("client data is not an assertion"));
    }
    check_client(&client, challenge, origin)?;
    if client.cross_origin {
        return Err(malformed("cross-origin assertion is not accepted"));
    }

    let auth = parse_authenticator_data(authenticator_data)?;
    check_rp_id(&auth, rp_id)?;
    if auth.flags & FLAG_USER_PRESENT == 0 {
        return Err(CryptoError::BadSignature(
            "the authenticator did not assert user presence".to_owned(),
        ));
    }
    if auth.credential.is_some() {
        return Err(malformed(
            "an assertion must not carry attested credential data",
        ));
    }

    let sec1 = cose_to_sec1(public_key)?;
    let verifying = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|err| malformed(format!("unusable passkey public key: {err}")))?;

    // WebAuthn's ES256 signature covers the authenticator data and the *hash* of the client data.
    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&Sha256::digest(client_data_json));

    let raw = normalize_signature(signature)?;
    let signature = Signature::from_slice(&raw)
        .map_err(|err| malformed(format!("malformed ECDSA signature: {err}")))?;
    verifying.verify(&message, &signature).map_err(|_| {
        CryptoError::BadSignature("the assertion signature does not verify".to_owned())
    })?;

    Ok(auth.sign_count)
}

/// Whether the assertion's user-verification flag says a PIN or biometrics were used.
pub fn assertion_user_verified(authenticator_data: &[u8]) -> bool {
    authenticator_data
        .get(32)
        .is_some_and(|flags| flags & FLAG_USER_VERIFIED != 0)
}

/// The JSON the browser puts in `response.clientDataJSON`.
#[derive(Debug, serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

fn parse_client_data(bytes: &[u8]) -> Result<ClientData, CryptoError> {
    serde_json::from_slice(bytes).map_err(|err| malformed(format!("malformed client data: {err}")))
}

fn check_client(client: &ClientData, challenge: &[u8], origin: &str) -> Result<(), CryptoError> {
    if !challenge_matches(&client.challenge, challenge) {
        return Err(CryptoError::BadSignature(
            "the challenge does not match this ceremony".to_owned(),
        ));
    }
    if client.origin.trim_end_matches('/') != origin.trim_end_matches('/') {
        return Err(CryptoError::BadSignature(
            "the client origin does not match this deployment".to_owned(),
        ));
    }
    Ok(())
}

fn challenge_matches(encoded: &str, expected: &[u8]) -> bool {
    decode_base64url(encoded).is_ok_and(|bytes| bytes == expected)
}

fn check_rp_id(auth: &AuthenticatorData<'_>, rp_id: &str) -> Result<(), CryptoError> {
    let expected = Sha256::digest(rp_id.as_bytes());
    if auth.rp_id_hash != &expected[..] {
        return Err(CryptoError::BadSignature(
            "the authenticator data is bound to another RP id".to_owned(),
        ));
    }
    Ok(())
}

/// The parsed authenticator data both ceremonies share.
struct AuthenticatorData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u64,
    credential: Option<AttestedCredential<'a>>,
}

struct AttestedCredential<'a> {
    aaguid: [u8; 16],
    credential_id: &'a [u8],
    public_key: &'a [u8],
}

fn parse_authenticator_data(bytes: &[u8]) -> Result<AuthenticatorData<'_>, CryptoError> {
    if bytes.len() < 37 {
        return Err(malformed("authenticator data is truncated"));
    }
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]) as u64;

    let credential = if flags & FLAG_ATTESTED_CREDENTIAL != 0 {
        if bytes.len() < 55 {
            return Err(malformed("attested credential data is truncated"));
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&bytes[37..53]);
        let id_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID_LEN {
            return Err(malformed("credential id has an unusable length"));
        }
        let id_start: usize = 55;
        let id_end = id_start
            .checked_add(id_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed("credential id runs past the authenticator data"))?;
        Some(AttestedCredential {
            aaguid,
            credential_id: &bytes[id_start..id_end],
            public_key: &bytes[id_end..],
        })
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash: &bytes[..32],
        flags,
        sign_count,
        credential,
    })
}

/// Turn a COSE `EC2` key into the SEC1 uncompressed point `p256` verifies with.
///
/// The point is one `0x04` prefix plus two 32-byte coordinates — 65 bytes, the only length
/// `VerifyingKey::from_sec1_bytes` accepts for P-256.
fn cose_to_sec1(bytes: &[u8]) -> Result<[u8; 65], CryptoError> {
    let Cbor::Map(entries) = parse_cbor(bytes)? else {
        return Err(malformed("credential public key is not a COSE map"));
    };

    // COSE key parameters: kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x and y coordinates.
    if map_int(&entries, 1)? != 2 {
        return Err(malformed("credential public key is not an EC2 key"));
    }
    if map_int(&entries, 3)? != -7 {
        return Err(malformed("credential public key is not ES256"));
    }
    if map_int(&entries, -1)? != 1 {
        return Err(malformed("credential public key is not on P-256"));
    }
    let x = map_int_bytes(&entries, -2)?;
    let y = map_int_bytes(&entries, -3)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(malformed(
            "credential public key coordinates are not 32 bytes",
        ));
    }

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..].copy_from_slice(y);
    Ok(sec1)
}

fn map_text<'a>(entries: &'a [(Cbor, Cbor)], key: &str) -> Result<&'a str, CryptoError> {
    entries
        .iter()
        .find(|(candidate, _)| candidate == &Cbor::Text(key.to_owned()))
        .and_then(|(_, value)| match value {
            Cbor::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .ok_or_else(|| malformed(format!("`{key}` is missing from the CBOR map")))
}

fn map_bytes<'a>(entries: &'a [(Cbor, Cbor)], key: &str) -> Result<&'a [u8], CryptoError> {
    entries
        .iter()
        .find(|(candidate, _)| candidate == &Cbor::Text(key.to_owned()))
        .and_then(|(_, value)| match value {
            Cbor::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| malformed(format!("`{key}` is missing from the CBOR map")))
}

fn map_int_bytes<'a>(entries: &'a [(Cbor, Cbor)], key: i64) -> Result<&'a [u8], CryptoError> {
    let wanted = int_key(key);
    entries
        .iter()
        .find(|(candidate, _)| candidate == &wanted)
        .and_then(|(_, value)| match value {
            Cbor::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| malformed(format!("`{key}` is missing from the COSE key")))
}

fn map_int(entries: &[(Cbor, Cbor)], key: i64) -> Result<i64, CryptoError> {
    let wanted = int_key(key);
    entries
        .iter()
        .find(|(candidate, _)| candidate == &wanted)
        .and_then(|(_, value)| match value {
            Cbor::Unsigned(number) => i64::try_from(*number).ok(),
            Cbor::Negative(number) => Some(*number),
            _ => None,
        })
        .ok_or_else(|| malformed(format!("`{key}` is missing from the COSE key")))
}

/// The CBOR representation of an integer map key, which COSE keys are.
fn int_key(key: i64) -> Cbor {
    if key < 0 {
        Cbor::Negative(key)
    } else {
        Cbor::Unsigned(key as u64)
    }
}

fn malformed(detail: impl Into<String>) -> CryptoError {
    CryptoError::Malformed(format!("webauthn: {}", detail.into()))
}

// ---------------------------------------------------------------------------------------------
// A CBOR reader for the two shapes WebAuthn returns.
//
// A full CBOR implementation would be a dependency; a passkey needs integers, byte strings, text
// strings, arrays and maps, and nothing else. Unknown simple values are represented as `Other` and
// skipped, which is enough to walk past extension data without interpreting it.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Cbor {
    Unsigned(u64),
    /// Already negated: CBOR encodes `-1` as major type 1 with argument `0`.
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Other,
}

fn parse_cbor(bytes: &[u8]) -> Result<Cbor, CryptoError> {
    let mut reader = CborReader { bytes, pos: 0 };
    reader.item(0)
}

struct CborReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    /// The initial byte split into its major type and argument.
    fn head(&mut self) -> Result<(u8, u64), CryptoError> {
        let initial = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| malformed("CBOR value is truncated"))?;
        self.pos += 1;
        let major = initial >> 5;
        let argument = match initial & 0x1f {
            value @ 0..=23 => u64::from(value),
            24 => u64::from(self.take(1)?[0]),
            25 => {
                let bytes = self.take(2)?;
                u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            26 => {
                let bytes = self.take(4)?;
                u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            27 => {
                let bytes = self.take(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
            _ => return Err(malformed("reserved CBOR length encoding")),
        };
        Ok((major, argument))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CryptoError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed("CBOR value is truncated"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CryptoError> {
        // Bound the recursion: a hostile attestation object must not be able to exhaust the stack.
        if depth > 8 {
            return Err(malformed("CBOR nesting is too deep"));
        }
        let (major, argument) = self.head()?;
        match major {
            0 => Ok(Cbor::Unsigned(argument)),
            1 => {
                let magnitude = i64::try_from(argument)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| malformed("CBOR negative integer is out of range"))?;
                Ok(Cbor::Negative(-magnitude))
            }
            2 | 3 => {
                let len =
                    usize::try_from(argument).map_err(|_| malformed("CBOR string is too long"))?;
                let bytes = self.take(len)?;
                if major == 2 {
                    Ok(Cbor::Bytes(bytes.to_vec()))
                } else {
                    String::from_utf8(bytes.to_vec())
                        .map(Cbor::Text)
                        .map_err(|_| malformed("CBOR text is not UTF-8"))
                }
            }
            4 => {
                let len =
                    usize::try_from(argument).map_err(|_| malformed("CBOR array is too long"))?;
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let len =
                    usize::try_from(argument).map_err(|_| malformed("CBOR map is too long"))?;
                let mut entries = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Cbor::Map(entries))
            }
            // Tags are transparent here: the tagged value is what the caller inspects.
            6 => self.item(depth + 1),
            7 => match argument {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                _ => Ok(Cbor::Other),
            },
            _ => Err(malformed("unknown CBOR major type")),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Signature encoding.
//
// Browsers send an ASN.1 DER ECDSA signature; Node's WebCrypto (used by the acceptance script's
// software authenticator) sends the raw r || s pair. Both are accepted and normalised to raw.

fn normalize_signature(signature: &[u8]) -> Result<[u8; 64], CryptoError> {
    if signature.len() == 64 {
        let mut raw = [0u8; 64];
        raw.copy_from_slice(signature);
        return Ok(raw);
    }

    if signature.len() < 4 || signature[0] != 0x30 {
        return Err(malformed("signature is neither raw nor DER"));
    }
    // `SEQUENCE` length: WebAuthn signatures always fit the short form, but a long form with one
    // length byte is still legal.
    let mut offset = 2;
    if signature[1] & 0x80 != 0 {
        let count = usize::from(signature[1] & 0x7f);
        if count != 1 {
            return Err(malformed("unsupported DER length encoding"));
        }
        offset += count;
    }

    let (r_start, r_len) = der_integer(signature, offset)?;
    let r_end = r_start
        .checked_add(r_len)
        .filter(|end| *end <= signature.len())
        .ok_or_else(|| malformed("DER signature is truncated"))?;
    if signature.get(r_end) != Some(&0x02) {
        return Err(malformed("DER signature has no second integer"));
    }
    let s_len = usize::from(
        signature
            .get(r_end + 1)
            .copied()
            .ok_or_else(|| malformed("DER signature is truncated"))?,
    );
    let s_end = r_end
        .checked_add(2 + s_len)
        .filter(|end| *end <= signature.len())
        .ok_or_else(|| malformed("DER signature is truncated"))?;

    let mut raw = [0u8; 64];
    copy_integer(&signature[r_start..r_end], &mut raw[..32])?;
    copy_integer(&signature[r_end + 2..s_end], &mut raw[32..])?;
    Ok(raw)
}

/// Locate the first `INTEGER` at `offset`, returning its payload offset and length.
fn der_integer(signature: &[u8], offset: usize) -> Result<(usize, usize), CryptoError> {
    let tag = signature
        .get(offset)
        .copied()
        .ok_or_else(|| malformed("DER signature is truncated"))?;
    if tag != 0x02 {
        return Err(malformed("DER signature does not start with an integer"));
    }
    let len = usize::from(
        signature
            .get(offset + 1)
            .copied()
            .ok_or_else(|| malformed("DER signature is truncated"))?,
    );
    Ok((offset + 2, len))
}

/// Copy a DER integer payload into a fixed 32-byte slot, dropping leading zero padding bytes.
fn copy_integer(payload: &[u8], slot: &mut [u8]) -> Result<(), CryptoError> {
    let mut bytes = payload;
    while bytes.first() == Some(&0) && bytes.len() > 1 {
        bytes = &bytes[1..];
    }
    if bytes.len() > slot.len() {
        return Err(malformed("DER integer is too large for P-256"));
    }
    let start = slot.len() - bytes.len();
    slot[start..].copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_are_random_and_256_bits() {
        let first = generate_challenge();
        assert_eq!(first.len(), CHALLENGE_LEN);
        assert_ne!(first, generate_challenge());
    }

    #[test]
    fn base64url_round_trips_with_and_without_padding() {
        let bytes = [0xfb, 0xff, 0x00, 0x01];
        let encoded = encode_base64url(&bytes);
        assert!(!encoded.contains('='));
        assert_eq!(decode_base64url(&encoded).expect("decodes"), bytes);
        assert_eq!(
            decode_base64url(&format!("{encoded}=")).expect("padded decodes"),
            bytes
        );
        assert!(decode_base64url("!!").is_err());
    }

    #[test]
    fn the_cbor_reader_handles_the_web_authn_subset() {
        assert_eq!(parse_cbor(&[0x01]).expect("unsigned"), Cbor::Unsigned(1));
        // Major type 1, argument 0 is -1.
        assert_eq!(parse_cbor(&[0x20]).expect("negative"), Cbor::Negative(-1));
        assert_eq!(
            parse_cbor(&[0x43, 0x01, 0x02, 0x03]).expect("bytes"),
            Cbor::Bytes(vec![1, 2, 3])
        );
        assert_eq!(
            parse_cbor(&[0x63, b'a', b'b', b'c']).expect("text"),
            Cbor::Text("abc".to_owned())
        );
        assert!(parse_cbor(&[0x63, b'a']).is_err());
        assert!(parse_cbor(&[0xbf, 0x01]).is_err());
    }

    #[test]
    fn a_map_is_read_by_its_key() {
        // {1: 2, -1: 1, "fmt": "none"}
        let mut bytes = vec![0xa3, 0x01, 0x02, 0x20, 0x01, 0x63];
        bytes.extend_from_slice(b"fmt");
        bytes.push(0x64);
        bytes.extend_from_slice(b"none");
        let Cbor::Map(entries) = parse_cbor(&bytes).expect("map") else {
            panic!("expected a map");
        };
        assert_eq!(map_int(&entries, 1).expect("kty"), 2);
        assert_eq!(map_int(&entries, -1).expect("crv"), 1);
        assert_eq!(map_text(&entries, "fmt").expect("fmt"), "none");
        assert!(map_text(&entries, "missing").is_err());
    }

    #[test]
    fn a_cose_ec2_key_becomes_a_65_byte_sec1_point() {
        // {1: 2, 3: -7, -1: 1, -2: <32 bytes>, -3: <32 bytes>}
        let mut bytes = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        bytes.extend_from_slice(&[0x11u8; 32]);
        bytes.extend_from_slice(&[0x22, 0x58, 0x20]);
        bytes.extend_from_slice(&[0x22u8; 32]);
        let sec1 = cose_to_sec1(&bytes).expect("a valid COSE key");
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &[0x11u8; 32]);
        assert_eq!(&sec1[33..], &[0x22u8; 32]);
    }

    #[test]
    fn client_data_must_name_the_expected_ceremony() {
        let data =
            br#"{"type":"webauthn.get","challenge":"AAAA","origin":"http://localhost:5174"}"#;
        let client = parse_client_data(data).expect("parses");
        assert_eq!(client.typ, "webauthn.get");
        assert!(!client.cross_origin);
        // "AAAA" decodes to three zero bytes, so a different challenge must not match.
        assert!(!challenge_matches(&client.challenge, &[0, 0, 0, 0]));
        assert!(challenge_matches(&client.challenge, &[0, 0, 0]));

        let error = verify_assertion(
            data,
            &[0u8; 37],
            &[0u8; 64],
            &[0u8; 65],
            &[0, 0, 0],
            "localhost",
            "http://localhost:5174",
        )
        .expect_err("a placeholder assertion must not verify");
        assert!(matches!(
            error,
            CryptoError::Malformed(_) | CryptoError::BadSignature(_)
        ));
    }

    #[test]
    fn der_signatures_normalise_to_raw() {
        // SEQUENCE(30 26) INTEGER(02 01 01) INTEGER(02 21 00 <32 bytes starting 0x80>)
        // The second integer carries a leading zero because its top bit is set; dropping it must
        // leave exactly 32 bytes instead of overflowing the slot.
        let mut s = vec![0x80u8];
        s.extend(std::iter::repeat_n(0x02u8, 31));
        let mut der = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
        der.extend_from_slice(&s);
        let raw = normalize_signature(&der).expect("normalises");
        assert_eq!(&raw[..32], &{
            let mut r = [0u8; 32];
            r[31] = 1;
            r
        });
        assert_eq!(&raw[32..], &s[..]);

        let mut short = [0x11u8; 64];
        short[0] = 0xaa;
        assert_eq!(normalize_signature(&short).expect("raw accepted"), short);
        assert!(normalize_signature(&[0x30, 0x01]).is_err());
    }
}
