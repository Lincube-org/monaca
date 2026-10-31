//! Typed external identifiers, request contexts, the RFC 9457 problem model and the clock
//! abstraction.
//!
//! Every identifier that crosses the API boundary is a typed string `<prefix>_<suffix>`
//! (docs/contracts/m0.md §5.2): the prefix names the entity, the suffix is the TypeID v0.3
//! encoding of the row's UUIDv7 primary key. The database stores the bare `uuid`; only the
//! wire form carries the prefix.
//!
//! M0 ships the identifier types, [`TenantCtx`] / [`OrgCtx`], [`Problem`] and [`Clock`].
//! M1 adds the same types for the client/console pages and moves the problem model into the
//! shared error taxonomy.

mod clock;
mod ctx;
mod id;
mod problem;

pub use clock::{Clock, FixedClock, SystemClock};
pub use ctx::{OrgCtx, Principal, TenantCtx};
pub use id::{
    AccountId, AgentId, AgentKeyId, ApprovalId, ClientId, DelegationId, EventId, GrantId,
    InteractionId, KeyId, OrgId, PasskeyId, SessionId, TenantId, TrustedDeviceId, TypedId,
    TypedIdError, decode_suffix, encode_suffix,
};
pub use problem::{Problem, ProblemKind};
