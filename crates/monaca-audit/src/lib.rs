//! The per-organization audit hash chain — docs/contracts/m0.md §8.
//!
//! Each organization has one chain. An event's digest is
//!
//! ```text
//! hash = hex(sha256(prev_hash_bytes || jcs_bytes))
//! ```
//!
//! where `prev_hash_bytes` is the raw 32 bytes of the previous digest (not its hex) and
//! `jcs_bytes` is the UTF-8 RFC 8785 output of the event object minus its chain fields. Genesis
//! is 32 zero bytes.
//!
//! This crate is the pure primitive: canonical bytes, the digest, and a verifier that recomputes
//! a chain from its rows. It opens no database and takes no lock — §8.3's `FOR UPDATE` on the
//! chain-head row happens in `monaca-store`, in the same transaction as the business write.
//! Keeping the arithmetic here means the append path and the verifier path cannot drift, and it
//! lets `proptest` in M0's acceptance suite exercise tamper detection without PostgreSQL.
//!
//! M1 adds checkpoint signing; M3 adds batched Merkle sealing to relieve the head-row lock.

mod chain;
mod event;
mod verify;

pub use chain::{CHAIN_FIELDS, GENESIS_HASH, canonical_bytes, chain_hash, hash_hex};
pub use event::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject, ChainFields};
pub use verify::{ChainHead, StoredEvent, VerifyReason, VerifyReport, VerifyStop, verify_chain};
