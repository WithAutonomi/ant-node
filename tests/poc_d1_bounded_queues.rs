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
//! ## The fix (two layers)
//!
//! 1. **Global memory backstop** — `add_pending_verify` / `enqueue_fetch`
//!    reject once `MAX_PENDING_VERIFY` / `MAX_FETCH_QUEUE` is reached.
//! 2. **Per-source fairness (the real D1 defence)** — each pending entry is
//!    accounted to its `hint_sender`; a single peer may hold at most
//!    `MAX_PENDING_VERIFY_PER_PEER` entries. A flooding peer can exhaust only
//!    its own quota and can **never** deny slots to honest peers. Without
//!    layer 2, a blind global cap merely converts the memory DoS into a
//!    *worse* silent honest-replication starvation DoS (a single ~4 MB
//!    message every <30 min permanently rejects all honest hints).
//!
//! Each test states what it would do pre-fix. The starvation test in
//! particular FAILS against a global-cap-only fix and only passes with the
//! per-source quota — it is the test that proves D1 is actually closed, not
//! merely reshaped.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::doc_markdown
)]

use ant_node::replication::scheduling::{
    ReplicationQueues, MAX_FETCH_QUEUE, MAX_PENDING_VERIFY, MAX_PENDING_VERIFY_PER_PEER,
};
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
    VerificationEntry {
        state: VerificationState::PendingVerify,
        pipeline: HintPipeline::Replica,
        verified_sources: Vec::new(),
        tried_sources: HashSet::new(),
        created_at: Instant::now(),
        hint_sender: sender,
    }
}

/// D1a — `pending_verify` is globally memory-bounded: a flood spread across
/// many distinct sources (so the per-peer quota never bites) still cannot
/// grow the map past `MAX_PENDING_VERIFY`.
#[test]
fn poc_d1_pending_verify_is_globally_bounded() {
    let mut queues = ReplicationQueues::new();

    // Spread the flood across enough sources that per-peer quota is not the
    // limiter — isolating the global memory backstop.
    let per_peer = MAX_PENDING_VERIFY_PER_PEER;
    let mut i: u32 = 0;
    let mut sender: u32 = 0;
    let target = (MAX_PENDING_VERIFY as u32).saturating_add(20_000);
    while i < target {
        // PeerId space here is just sender index spread over 4 bytes.
        let mut pid = [0u8; 32];
        pid[..4].copy_from_slice(&sender.to_le_bytes());
        let s = PeerId::from_bytes(pid);
        for _ in 0..per_peer {
            if i >= target {
                break;
            }
            queues.add_pending_verify(unique_xorname(i), entry_from(s));
            i += 1;
        }
        sender += 1;
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

/// D1c — **the critical test**: a single flooding peer CANNOT starve an
/// honest peer. Pre-fix (and against a global-cap-only fix) the attacker
/// fills the whole queue and every honest hint is rejected. With per-source
/// fairness the attacker is clamped to its own quota and the honest peer's
/// hints are still admitted.
#[test]
fn poc_d1_flooding_peer_cannot_starve_honest_peer() {
    let mut queues = ReplicationQueues::new();

    let attacker = peer_id_from_byte(0xAA);
    let honest = peer_id_from_byte(0xBB);

    // Attacker floods far beyond any single-peer budget.
    let attacker_flood: u32 = (MAX_PENDING_VERIFY_PER_PEER as u32).saturating_add(500_000);
    let mut attacker_admitted = 0usize;
    for i in 0..attacker_flood {
        if queues.add_pending_verify(unique_xorname(i), entry_from(attacker)) {
            attacker_admitted += 1;
        }
    }

    // The attacker is clamped to exactly its per-source quota...
    assert_eq!(
        attacker_admitted, MAX_PENDING_VERIFY_PER_PEER,
        "a single peer can occupy at most MAX_PENDING_VERIFY_PER_PEER slots"
    );
    assert_eq!(
        queues.pending_count_for_sender(&attacker),
        MAX_PENDING_VERIFY_PER_PEER,
        "per-source accounting matches"
    );
    // ...and crucially the global map is NOT full (attacker can't monopolise).
    assert!(
        queues.pending_count() < MAX_PENDING_VERIFY,
        "one flooding peer must not be able to fill the global queue; \
         pending_count={} cap={MAX_PENDING_VERIFY}",
        queues.pending_count()
    );

    // The honest peer's hints are still admitted despite the ongoing flood.
    // (Use a disjoint key range so dedup is not the reason for admission.)
    let mut honest_admitted = 0usize;
    for j in 0..2_000u32 {
        let key = unique_xorname(10_000_000 + j);
        if queues.add_pending_verify(key, entry_from(honest)) {
            honest_admitted += 1;
        }
    }
    assert_eq!(
        honest_admitted, 2_000,
        "every honest hint is admitted — the flooding peer cannot starve it. \
         (This assertion FAILS against a global-cap-only fix.)"
    );
}

/// D1d — per-source counter stays consistent across remove and stale eviction
/// (so freed quota is actually reusable and there is no counter leak/desync).
#[test]
fn poc_d1_per_sender_counter_is_consistent() {
    let mut queues = ReplicationQueues::new();
    let peer = peer_id_from_byte(0xCC);

    for i in 0..100u32 {
        assert!(queues.add_pending_verify(unique_xorname(i), entry_from(peer)));
    }
    assert_eq!(queues.pending_count_for_sender(&peer), 100);

    // Removing entries frees the peer's quota.
    for i in 0..40u32 {
        assert!(queues.remove_pending(&unique_xorname(i)).is_some());
    }
    assert_eq!(
        queues.pending_count_for_sender(&peer),
        60,
        "remove_pending decrements the per-source counter in lockstep"
    );

    // Stale eviction also frees quota (max_age = 0 → everything is stale).
    queues.evict_stale(std::time::Duration::from_secs(0));
    assert_eq!(queues.pending_count(), 0, "all entries evicted as stale");
    assert_eq!(
        queues.pending_count_for_sender(&peer),
        0,
        "evict_stale releases per-source slots; the freed quota is reusable \
         and the per-sender map is pruned (no leak/desync)"
    );

    // Quota fully reusable after release.
    assert!(queues.add_pending_verify(unique_xorname(999), entry_from(peer)));
    assert_eq!(queues.pending_count_for_sender(&peer), 1);
}

/// D1e — the bounds do not break legitimate small working sets or dedup.
#[test]
fn poc_d1_bound_preserves_legitimate_entries() {
    let mut queues = ReplicationQueues::new();
    let peer = peer_id_from_byte(0xDD);

    for i in 0..1_000u32 {
        assert!(
            queues.add_pending_verify(unique_xorname(i), entry_from(peer)),
            "legitimate entries well under both caps are always admitted"
        );
    }
    assert_eq!(queues.pending_count(), 1_000);

    // Cross-queue dedup still holds (existing key not re-admitted, no
    // double-count of the per-source quota).
    assert!(!queues.add_pending_verify(unique_xorname(0), entry_from(peer)));
    assert_eq!(
        queues.pending_count(),
        1_000,
        "no spurious growth from dedup"
    );
    assert_eq!(
        queues.pending_count_for_sender(&peer),
        1_000,
        "dedup must not double-count the per-source quota"
    );
}

/// D1f — mutating an entry via `get_pending_mut` (the real pipeline path:
/// advancing `state`) must not desync the per-source quota counter. Guards
/// the documented `get_pending_mut` invariant.
#[test]
fn poc_d1_get_pending_mut_state_change_keeps_counter_consistent() {
    let mut queues = ReplicationQueues::new();
    let peer = peer_id_from_byte(0xEE);
    let key = unique_xorname(1);

    assert!(queues.add_pending_verify(key, entry_from(peer)));
    assert_eq!(queues.pending_count_for_sender(&peer), 1);

    // Exactly what run_verification_cycle does: advance the FSM state.
    let entry = queues.get_pending_mut(&key).expect("entry must be present");
    entry.state = VerificationState::QuorumVerified;

    // Counter unchanged by a state mutation (it tracks membership, not state).
    assert_eq!(
        queues.pending_count_for_sender(&peer),
        1,
        "get_pending_mut state change must not touch the per-source counter"
    );

    // And removal still correctly releases exactly one slot.
    assert!(queues.remove_pending(&key).is_some());
    assert_eq!(
        queues.pending_count_for_sender(&peer),
        0,
        "removal after a state mutation releases the slot exactly once"
    );
}
