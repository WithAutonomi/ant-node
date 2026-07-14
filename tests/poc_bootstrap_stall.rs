//! Regression tests for bootstrap cleanup when a hint source permanently
//! leaves the routing table.
//!
//! Capacity rejection records and pending hints are both source-indexed. Peer
//! removal must retire the rejection record, remove that peer from every hint,
//! and discard hints that have no remaining live source. Once that work is
//! gone, the normal bootstrap drain check can complete.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use ant_node::replication::bootstrap::{
    check_bootstrap_drained, clear_capacity_rejected, note_capacity_rejected, track_discovered_keys,
};
use ant_node::replication::scheduling::ReplicationQueues;
use ant_node::replication::types::{
    BootstrapState, HintPipeline, VerificationEntry, VerificationState,
};
use saorsa_core::identity::PeerId;
use tokio::sync::RwLock;

fn peer(byte: u8) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    PeerId::from_bytes(bytes)
}

fn entry(sources: HashSet<PeerId>) -> VerificationEntry {
    let now = Instant::now();
    VerificationEntry {
        state: VerificationState::PendingVerify,
        pipeline: HintPipeline::Replica,
        verified_sources: Vec::new(),
        tried_sources: HashSet::new(),
        created_at: now,
        next_verify_at: now,
        hint_sources: sources.clone(),
        replica_hint_sources: sources,
    }
}

#[tokio::test]
async fn peer_removal_retires_rejection_and_orphaned_hint_then_drains() {
    let queues = Arc::new(RwLock::new(ReplicationQueues::new()));
    let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));
    let departed = peer(0xAA);
    let key = [7; 32];

    queues
        .write()
        .await
        .add_pending_verify(key, entry(HashSet::from([departed])));
    track_discovered_keys(&bootstrap_state, &HashSet::from([key])).await;
    note_capacity_rejected(&bootstrap_state, departed).await;

    {
        let queues = queues.read().await;
        assert!(!check_bootstrap_drained(&bootstrap_state, &queues).await);
    }

    let orphaned = queues.write().await.remove_hint_source(&departed);
    clear_capacity_rejected(&bootstrap_state, &departed).await;
    bootstrap_state
        .write()
        .await
        .pending_keys
        .retain(|key| !orphaned.contains(key));

    let queues = queues.read().await;
    assert!(check_bootstrap_drained(&bootstrap_state, &queues).await);
    assert_eq!(orphaned, vec![key]);
}

#[tokio::test]
async fn peer_removal_preserves_hint_with_another_live_source() {
    let mut queues = ReplicationQueues::new();
    let departed = peer(0xAA);
    let remaining = peer(0xBB);
    let key = [9; 32];

    queues.add_pending_verify(key, entry(HashSet::from([departed, remaining])));
    assert!(queues.remove_hint_source(&departed).is_empty());

    let pending = queues.remove_pending(&key).expect("hint remains pending");
    assert_eq!(pending.hint_sources, HashSet::from([remaining]));
    assert_eq!(pending.replica_hint_sources, HashSet::from([remaining]));
}
