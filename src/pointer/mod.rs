//! Pointers — paid mutable references with an immutable owner.
//!
//! Implements `docs/adr/ADR-0016-pointers-immutable-owner.md`.
//!
//! A pointer is a mutable, owner-signed reference stored at an address derived
//! from the owner's public key. The owner key is fixed at creation: there is no
//! lineage, no certificates and no key rotation. That choice is what lets the
//! design be this small — the owner key is inlined in the record, so
//! validating a pointer needs nothing but the pointer.
//!
//! What the address resolves to can still be handed over for good
//! (`docs/adr/ADR-0018-pointer-transfer-by-final-redirection.md`): a state at
//! the final counter is replaced by nothing, so an owner who signs one pointing
//! at the new owner's pointer has no move left. The store gets that from the
//! merge rule; the service adds one look at the close group before taking a
//! final state, so a second one cannot land on a node that had not heard of
//! the first.
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
//! | `A` | `derive_key("autonomi.pointer.address.v1", owner)` | routes, and decides which nodes are responsible |
//! | `state_id` | `derive_key("autonomi.pointer.state.v1", body)` | names the state, and is what a quote is paid against |
//!
//! BLAKE3's derive-key mode, not a hash of a prefix and the input. A chunk is
//! addressed by a plain hash of its content, so a prefix would put both of
//! these inside the chunk address space for anyone who could write the
//! preimage — squatting an address before its owner used it, or buying a
//! pointer and a chunk with one payment. The two modes still share a 32-byte
//! range; what changed is that crossing it is a preimage problem.
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
    PointerTarget, PointerTargetKind, DATA_TYPE_POINTER, FINAL_COUNTER, POINTER_BODY_LEN,
    POINTER_FORMAT_VERSION, POINTER_WIRE_LEN, TARGET_WIRE_LEN,
};
pub use service::{FinalStateWitness, PointerService};
pub use store::{PointerStore, PutOutcome};
