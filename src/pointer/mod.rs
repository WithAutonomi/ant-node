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
//! # The three identifiers
//!
//! | Name | Derivation | Job |
//! |---|---|---|
//! | `A` | `BLAKE3(domain \|\| owner)` | routes, and decides which nodes are responsible |
//! | `state_id` | `BLAKE3(domain \|\| body)` | names the authenticated state: sync hints, and what a quote is paid against |
//! | `bytes_hash` | `BLAKE3(record)` | what *this* node's storage commitment binds |
//!
//! `A` and `state_id` are separate because `A` must be stable for the pointer's
//! life while the paid identifier must change with every update, or updates
//! after the first would be free — which is exactly the 1.0 defect this design
//! exists to fix. There is deliberately no fourth name hashed from `state_id`:
//! it is already a domain-separated, owner-bound identifier for exactly one
//! signed state.
//!
//! `bytes_hash` is per-storer rather than per-state, because two replicas may
//! hold one state under different signatures. That is fine: a storage
//! commitment is built and signed by one node and audited against that node's
//! own bytes, so it never has to agree with a peer's.
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
    cmp_merge, merge, pointer_address, state_id_for_body, MergeRank, ParsedPointer, Pointer,
    PointerError, PointerState, PointerTarget, PointerTargetKind, DATA_TYPE_POINTER,
    POINTER_BODY_LEN, POINTER_FORMAT_VERSION, POINTER_WIRE_LEN, TARGET_WIRE_LEN,
};
pub use service::PointerService;
pub use store::{Inspected, PointerStore, PutOutcome};
