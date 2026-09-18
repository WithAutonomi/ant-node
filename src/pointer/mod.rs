//! Pointers — paid mutable references with an immutable owner.
//!
//! Implements `docs/adr/ADR-0015-pointers-immutable-owner.md`.
//!
//! A pointer is a mutable, owner-signed reference stored at an address derived
//! from the owner's public key. Ownership is fixed at creation: there is no
//! transfer, no lineage, no certificates and no key rotation. That choice is
//! what lets the design be this small — the owner key is inlined in the
//! record, so validating a pointer needs nothing but the pointer.
//!
//! # What lives here
//!
//! The record itself is a **wire type** and lives in
//! [`ant_protocol::pointer`]: its encoding, identifiers and merge rule are
//! things the client and the node must agree on byte for byte. This module is
//! the node's half.
//!
//! - [`store`] — durable storage with merge-on-put, which is the part the
//!   immutable chunk store cannot do.
//! - [`service`] — the request handler: validate, check payment, merge.
//!
//! # The two identifiers
//!
//! | Name | Derivation | Job |
//! |---|---|---|
//! | `A` | `BLAKE3(domain \|\| owner)` | routes, and decides which nodes are responsible |
//! | `state_id` | `BLAKE3(domain \|\| body)` | names the state, and is what a quote is paid against |
//!
//! They are separate because `A` must be stable for the pointer's life while
//! the paid identifier must change with every update, or updates after the
//! first would be free — the 1.0 defect this design exists to fix.
//!
//! # Why the merge rule ignores signature bytes
//!
//! ML-DSA signing in `saorsa-pqc` is randomized and exposes no deterministic
//! mode, so one authenticated state has unboundedly many valid encodings. A
//! merge rule that ordered record *bytes* would let an owner sign one paid
//! state repeatedly, sort worst-first, and have every submission win —
//! unbounded storage, replication and Merkle-rebuild work for a single
//! payment. So equal state never replaces, and replicas may legitimately hold
//! different encodings of one state. Nothing compares record bytes across
//! replicas; `state_id` is compared instead.

pub mod service;
pub mod store;

pub use ant_protocol::pointer::{
    pointer_address, state_id_for_body, ParsedPointer, Pointer, PointerError, PointerState,
    PointerTarget, PointerTargetKind, DATA_TYPE_POINTER, POINTER_BODY_LEN, POINTER_FORMAT_VERSION,
    POINTER_WIRE_LEN, TARGET_WIRE_LEN,
};
pub use service::PointerService;
pub use store::{Inspected, PointerStore, PutOutcome};
