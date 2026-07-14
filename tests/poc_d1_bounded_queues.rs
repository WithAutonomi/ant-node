//! Proof-of-concept regression test for finding **D1** (unbounded replication
//! queues → OOM + reflective amplification, then honest-replication starvation
//! — from a single routing-table peer).
//!
//! ## The vulnerability (pre-fix)
//!
//! `ReplicationQueues::pending_verify` (`HashMap`) and `fetch_queue`
//! (`BinaryHeap`) had **no capacity bound** — the source even carried the
//! project's own `TODO`. `handle_neighbor_sync_request` documents "No
//! per-request hint count limit"; the only gate is `sender_in_rt`. A peer
//! floods `NeighborSyncRequest` messages (each capped only by
//! `MAX_REPLICATION_MESSAGE_SIZE` ≈ 10 MiB → ~320k 32-byte hints) and grows
//! these structures 1:1 → memory exhaustion + an outbound request storm.
//!
//! ## The fix
//!
//! `add_pending_verify` / `enqueue_fetch` reject once
//! `MAX_PENDING_VERIFY` / `MAX_FETCH_QUEUE` is reached. Pending verification
//! intentionally has no per-peer cap: legitimate peers may advertise a full
//! store, and corroborated hints are prioritised by source count. Source
//! provenance is retained so routing-table removal can discard orphaned hints.
//!
//! The global limit is an emergency memory backstop, not the normal flow-control
//! mechanism.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use ant_node::replication::scheduling::{ReplicationQueues, MAX_FETCH_QUEUE, MAX_PENDING_VERIFY};
use ant_node::replication::types::{HintPipeline, VerificationEntry, VerificationState};
use saorsa_core::identity::PeerId;
use std::collections::HashSet;
use std::time::Instant;

fn peer_id_from_byte(b: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = b;
    PeerId::from_bytes(bytes)
}

/// Distinct 32-byte key per index (attacker can grind these freely).
fn unique_xorname(i: u32) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..4].copy_from_slice(&i.to_le_bytes());
    x
}

fn entry_from(sender: PeerId) -> VerificationEntry {
    let now = Instant::now();
    VerificationEntry {
        state: VerificationState::PendingVerify,
        pipeline: HintPipeline::Replica,
        verified_sources: Vec::new(),
        tried_sources: HashSet::new(),
        created_at: now,
        next_verify_at: now,
        hint_sources: HashSet::from([sender]),
        replica_hint_sources: HashSet::from([sender]),
    }
}

/// D1a — `pending_verify` is globally memory-bounded.
#[test]
fn poc_d1_pending_verify_is_globally_bounded() {
    let mut queues = ReplicationQueues::new();

    let sender = peer_id_from_byte(0xAA);
    let target = (MAX_PENDING_VERIFY as u32).saturating_add(20_000);
    for i in 0..target {
        queues.add_pending_verify(unique_xorname(i), entry_from(sender));
    }

    assert!(
        queues.pending_count() <= MAX_PENDING_VERIFY,
        "pending_verify must never exceed MAX_PENDING_VERIFY ({MAX_PENDING_VERIFY}); got {}",
        queues.pending_count()
    );
    assert_eq!(
        queues.pending_count(),
        MAX_PENDING_VERIFY,
        "global memory backstop clamps exactly at the cap"
    );
}

/// D1b — `fetch_queue` global memory backstop holds.
#[test]
fn poc_d1_fetch_queue_is_capacity_bounded() {
    let mut queues = ReplicationQueues::new();
    let sources = vec![peer_id_from_byte(0x02)];

    let flood: u32 = (MAX_FETCH_QUEUE as u32).saturating_add(50_000);
    for i in 0..flood {
        let key = unique_xorname(i);
        queues.enqueue_fetch(key, key, sources.clone());
    }

    assert!(
        queues.fetch_queue_count() <= MAX_FETCH_QUEUE,
        "fetch_queue must never exceed MAX_FETCH_QUEUE ({MAX_FETCH_QUEUE}); got {}",
        queues.fetch_queue_count()
    );
    assert_eq!(queues.fetch_queue_count(), MAX_FETCH_QUEUE);
}

/// D1c — a legitimate peer can advertise a large store without hitting an
/// arbitrary per-peer quota.
#[test]
fn poc_d1_large_single_peer_working_set_is_admitted() {
    let mut queues = ReplicationQueues::new();
    let peer = peer_id_from_byte(0xBB);
    for i in 0..10_000u32 {
        assert!(queues
            .add_pending_verify(unique_xorname(i), entry_from(peer))
            .admitted());
    }
    assert_eq!(queues.pending_count(), 10_000);
}

/// D1d — the bounds do not break legitimate small working sets or dedup.
#[test]
fn poc_d1_bound_preserves_legitimate_entries() {
    let mut queues = ReplicationQueues::new();
    let peer = peer_id_from_byte(0xDD);

    for i in 0..1_000u32 {
        assert!(
            queues
                .add_pending_verify(unique_xorname(i), entry_from(peer))
                .admitted(),
            "legitimate entries well under the global cap are always admitted"
        );
    }
    assert_eq!(queues.pending_count(), 1_000);

    // Cross-queue dedup still holds (existing key is not re-admitted).
    assert!(!queues
        .add_pending_verify(unique_xorname(0), entry_from(peer))
        .admitted());
    assert_eq!(
        queues.pending_count(),
        1_000,
        "no spurious growth from dedup"
    );
}

/// D1e — advancing an entry's state preserves its pipeline and membership.
#[test]
fn poc_d1_set_pending_state_preserves_entry() {
    let mut queues = ReplicationQueues::new();
    let peer = peer_id_from_byte(0xEE);
    let key = unique_xorname(1);

    assert!(queues.add_pending_verify(key, entry_from(peer)).admitted());
    assert_eq!(queues.pending_count(), 1);

    // Exactly what run_verification_cycle does: advance the FSM state.
    let pipeline = queues
        .set_pending_state(&key, VerificationState::QuorumVerified)
        .expect("entry must be present");
    assert_eq!(pipeline, HintPipeline::Replica, "pipeline preserved");

    assert_eq!(queues.pending_count(), 1);

    // And removal still correctly releases exactly one slot.
    assert!(queues.remove_pending(&key).is_some());
    assert_eq!(queues.pending_count(), 0);
}
