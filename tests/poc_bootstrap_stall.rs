//! Proof-of-concept regression test for the **bootstrap stall** attack
//! against the neighbour-sync admission / drain detector.
//!
//! ## The attack (no fix yet)
//!
//! While a node is bootstrapping, every inbound `NeighborSyncRequest`
//! whose admission overflows `MAX_PENDING_VERIFY_PER_PEER` (the per-peer
//! cap is the first to bite for any single peer) calls
//! `bootstrap::note_capacity_rejected(source)`. The drain check in
//! `bootstrap::check_bootstrap_drained` then refuses to complete
//! bootstrap while the set is non-empty:
//!
//! ```ignore
//! if !state.capacity_rejected_sources.is_empty() {
//!     return false; // "not yet drained"
//! }
//! ```
//!
//! The set entry for `source` is cleared only when **the same source**
//! later completes an admission cycle with zero rejections. A single
//! peer that keeps sending over-cap hints faster than the verification
//! queue drains never has a "clean cycle" — so it is **permanently**
//! in `capacity_rejected_sources`, and bootstrap **never completes**.
//!
//! ## Why this matters
//!
//! While `is_bootstrapping == true`:
//! - **Audits are paused** (`replication::audit::audit_tick` returns
//!   `Idle` if `is_bootstrapping`, see `audit.rs` Invariant 19). A
//!   victim stuck in bootstrap mode is effectively a node that does no
//!   auditing — bad nodes around it accrue no trust penalties.
//! - Other replication invariants gated on `bootstrap_drained` (paid
//!   list repair flow, prune confirmation paths) also stay off.
//!
//! A single Byzantine peer in the victim's routing table can therefore
//! disable the entire reputation system on that victim, for free,
//! using nothing but well-formed `NeighborSyncRequest` messages that
//! the victim's admission path accepts as legitimate.
//!
//! ## What this test proves
//!
//! Drives the in-process pieces (`ReplicationQueues`, `BootstrapState`,
//! `bootstrap::note_capacity_rejected` /
//! `bootstrap::check_bootstrap_drained`) end-to-end through the same
//! call sequence that the live replication loop runs when handling an
//! over-cap `NeighborSyncRequest`. With no fix this test passes — i.e.
//! it documents the buggy behaviour by asserting the victim never
//! drains. The fix (whatever shape it takes — per-source rate limits,
//! capacity-reject decay, trust-event escalation, ...) will need a
//! follow-up test asserting drain happens within a bounded number of
//! over-cap cycles.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::significant_drop_tightening
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use ant_node::replication::bootstrap::{
    check_bootstrap_drained, clear_capacity_rejected, note_capacity_rejected,
};
use ant_node::replication::scheduling::{
    AdmissionResult, ReplicationQueues, MAX_PENDING_VERIFY_PER_PEER,
};
use ant_node::replication::types::{
    BootstrapState, HintPipeline, VerificationEntry, VerificationState,
};
use saorsa_core::identity::PeerId;

fn peer(b: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = b;
    PeerId::from_bytes(bytes)
}

fn entry(sender: PeerId) -> VerificationEntry {
    VerificationEntry {
        state: VerificationState::PendingVerify,
        pipeline: HintPipeline::Replica,
        verified_sources: Vec::new(),
        tried_sources: HashSet::new(),
        created_at: Instant::now(),
        hint_sender: sender,
    }
}

fn unique_key(i: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_le_bytes());
    k
}

/// Simulates one inbound `NeighborSyncRequest` from `source` carrying
/// `hint_count` hints — returns the number of admissions that capacity-
/// rejected (i.e. what `AdmissionOutcome::capacity_rejected_count` would
/// be in the live loop), and as a side effect mutates `queues` and the
/// bootstrap-state in exactly the same way the live `admit_and_queue_hints`
/// followed by the bootstrap-drain accounting do.
async fn simulate_inbound_sync(
    queues: &Arc<RwLock<ReplicationQueues>>,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    source: PeerId,
    key_offset: u32,
    hint_count: u32,
) -> usize {
    let mut capacity_rejected_count: usize = 0;

    {
        let mut q = queues.write().await;
        for i in 0..hint_count {
            let result = q.add_pending_verify(unique_key(key_offset + i), entry(source));
            match result {
                AdmissionResult::Admitted | AdmissionResult::AlreadyPresent => {}
                AdmissionResult::CapacityRejected => {
                    capacity_rejected_count += 1;
                }
            }
        }
    }

    // Mirror replication/mod.rs:1391-1400: while bootstrapping, note or
    // clear capacity rejection for this source based on the outcome.
    if capacity_rejected_count > 0 {
        note_capacity_rejected(bootstrap_state, source).await;
    } else {
        clear_capacity_rejected(bootstrap_state, &source).await;
    }

    capacity_rejected_count
}

/// **The attack.** A single peer keeps the victim's bootstrap permanently
/// undrained by always sending one more hint than the per-peer pending
/// quota can accept. The victim's `capacity_rejected_sources` set stays
/// non-empty forever, so `check_bootstrap_drained` never returns `true`.
///
/// Pre-fix behaviour: this test passes (the attack succeeds — drain never
/// completes). The presence of this test is the regression marker.
///
/// Post-fix behaviour: the fix MUST cause `check_bootstrap_drained` to
/// return `true` within a bounded number of cycles regardless of attacker
/// flood pattern. A follow-up test should assert that bound.
#[tokio::test]
async fn poc_bootstrap_stall_via_persistent_per_peer_overflow() {
    let queues = Arc::new(RwLock::new(ReplicationQueues::new()));
    let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));

    let attacker = peer(0xAA);

    // Round 1: attacker sends per-peer-cap + 1 hints. The first
    // MAX_PENDING_VERIFY_PER_PEER admit; the last over-cap one rejects.
    // After this round, `capacity_rejected_sources` contains the attacker.
    let mut next_key: u32 = 0;
    #[allow(clippy::cast_possible_truncation)]
    let flood = MAX_PENDING_VERIFY_PER_PEER as u32 + 1;
    let rejected =
        simulate_inbound_sync(&queues, &bootstrap_state, attacker, next_key, flood).await;
    next_key += flood;
    assert!(
        rejected >= 1,
        "round 1 must over-cap (got {rejected} rejections); test is mis-sized"
    );

    // Victim has nothing else outstanding: no other pending peer requests,
    // no other pending keys discovered. The ONLY thing preventing drain
    // is `capacity_rejected_sources` containing the attacker.
    let drained_before_attack_continues = {
        let q = queues.read().await;
        check_bootstrap_drained(&bootstrap_state, &q).await
    };
    assert!(
        !drained_before_attack_continues,
        "bootstrap must NOT drain while attacker has outstanding capacity-rejected hints"
    );

    // Round 2..N: attacker keeps sending one more over-cap hint each
    // round. In the live loop, the victim's verification cycle would
    // drain a few entries between rounds, but the attacker just sends
    // more hints than fit. Here we simulate that pattern by NEVER
    // draining queues between attacker rounds: this is the worst-case
    // for the victim and matches an attacker who paces hints to keep
    // pending_per_sender[attacker] always at the cap.
    for round in 0..32 {
        let r = simulate_inbound_sync(&queues, &bootstrap_state, attacker, next_key, 1).await;
        next_key += 1;
        // Each round must keep capacity-rejecting (per-peer cap still hit
        // because we never freed slots for this sender).
        assert!(
            r >= 1,
            "round {round}: attacker hint must continue to capacity-reject \
             (per-peer cap still full); got {r}"
        );

        let drained = {
            let q = queues.read().await;
            check_bootstrap_drained(&bootstrap_state, &q).await
        };
        assert!(
            !drained,
            "round {round}: bootstrap drained despite attacker still capacity-rejecting"
        );
    }

    // After 32 rounds (could be 32 million) the attacker is STILL in
    // `capacity_rejected_sources`. The victim is permanently in
    // bootstrap mode. This is the bug.
    let state = bootstrap_state.read().await;
    assert!(
        state.capacity_rejected_sources.contains(&attacker),
        "attacker peer is still in capacity_rejected_sources after the flood — \
         this is the documented stall: the victim has no mechanism to retire \
         the attacker without the attacker's cooperation (a 'clean' admission \
         cycle), so a hostile peer can stall bootstrap indefinitely"
    );
    assert_eq!(
        state.capacity_rejected_sources.len(),
        1,
        "only the attacker is outstanding; honest peers are unaffected — \
         which is exactly what makes this a single-peer DoS"
    );
}

/// Honest peers are unaffected: the per-source quota means a flood from
/// the attacker cannot starve an honest peer's hints. The honest peer's
/// "clean" cycle correctly clears its bootstrap entry. This test
/// confirms the per-source isolation that the bounded-queues defence
/// (`poc_d1_bounded_queues`) already established — included so a future
/// fix doesn't accidentally break it.
#[tokio::test]
async fn honest_peer_drains_normally_alongside_attacker() {
    let queues = Arc::new(RwLock::new(ReplicationQueues::new()));
    let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));

    let attacker = peer(0xAA);
    let honest = peer(0x01);

    // Attacker over-caps.
    #[allow(clippy::cast_possible_truncation)]
    let flood = MAX_PENDING_VERIFY_PER_PEER as u32 + 1;
    let r_atk = simulate_inbound_sync(&queues, &bootstrap_state, attacker, 0, flood).await;
    assert!(r_atk >= 1);

    // Honest peer sends a small clean batch.
    let r_honest = simulate_inbound_sync(&queues, &bootstrap_state, honest, flood + 100, 16).await;
    assert_eq!(
        r_honest, 0,
        "honest peer's small batch must NOT capacity-reject — per-source quota isolates them"
    );

    let state = bootstrap_state.read().await;
    assert!(
        state.capacity_rejected_sources.contains(&attacker),
        "attacker is outstanding"
    );
    assert!(
        !state.capacity_rejected_sources.contains(&honest),
        "honest peer is NOT outstanding; its clean cycle cleared (or never created) its entry"
    );
}
