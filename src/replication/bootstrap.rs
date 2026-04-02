//! New-node bootstrap logic (Section 16).
//!
//! A joining node performs active sync to discover and verify keys it should
//! hold, then transitions to normal operation once all bootstrap work drains.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use saorsa_core::DhtNetworkEvent;

use crate::ant_protocol::XorName;
use crate::replication::scheduling::ReplicationQueues;
use crate::replication::types::BootstrapState;

// ---------------------------------------------------------------------------
// DHT bootstrap gate
// ---------------------------------------------------------------------------

/// Outcome of waiting for the `DhtNetworkEvent::BootstrapComplete` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapGateResult {
    /// The event was received — routing table is populated.
    Received,
    /// Timed out or channel error — proceed anyway (bootstrap node scenario).
    TimedOut,
    /// Shutdown was requested while waiting.
    Shutdown,
}

/// Wait for saorsa-core's `DhtNetworkEvent::BootstrapComplete` before
/// returning.
///
/// The caller must supply a pre-subscribed `dht_events` receiver. This is
/// critical: the subscription must be created **before**
/// `P2PNode::start()` so the `BootstrapComplete` event is not missed.
///
/// Returns [`BootstrapGateResult::Received`] on success,
/// [`BootstrapGateResult::TimedOut`] if the timeout elapses (e.g. a
/// bootstrap node with no peers), or [`BootstrapGateResult::Shutdown`] if
/// cancellation is signalled.
pub async fn wait_for_bootstrap_complete(
    mut dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>,
    timeout_secs: u64,
    shutdown: &CancellationToken,
) -> BootstrapGateResult {
    let timeout = Duration::from_secs(timeout_secs);

    let result = tokio::select! {
        () = shutdown.cancelled() => {
            debug!("Bootstrap sync: shutdown during BootstrapComplete wait");
            BootstrapGateResult::Shutdown
        }
        () = tokio::time::sleep(timeout) => {
            warn!(
                "Bootstrap sync: timed out after {timeout_secs}s waiting for \
                 BootstrapComplete — proceeding (likely a bootstrap node with no peers)",
            );
            BootstrapGateResult::TimedOut
        }
        gate = async {
            loop {
                match dht_events.recv().await {
                    Ok(DhtNetworkEvent::BootstrapComplete { num_peers }) => {
                        info!(
                            "Bootstrap sync: DHT bootstrap complete \
                             with {num_peers} peers in routing table"
                        );
                        break BootstrapGateResult::Received;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "Bootstrap sync: DHT event channel error: {e}, \
                             proceeding without gate"
                        );
                        break BootstrapGateResult::TimedOut;
                    }
                }
            }
        } => gate,
    };
    drop(dht_events);
    result
}

// ---------------------------------------------------------------------------
// Bootstrap sync
// ---------------------------------------------------------------------------

// `snapshot_close_neighbors` is defined in `neighbor_sync` and re-used here.

/// Mark bootstrap as complete, updating the shared state.
pub async fn mark_bootstrap_drained(bootstrap_state: &Arc<RwLock<BootstrapState>>) {
    let mut state = bootstrap_state.write().await;
    state.drained = true;
    info!("Bootstrap explicitly marked as drained");
}

/// Check if bootstrap is drained and update state if so.
///
/// Bootstrap is drained when:
/// 1. All bootstrap peer requests have completed.
/// 2. All bootstrap-discovered keys have left the pipeline (no longer in
///    `PendingVerify`, `FetchQueue`, or `InFlightFetch`).
///
/// Returns `true` if bootstrap is (now) drained.
pub async fn check_bootstrap_drained(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    queues: &ReplicationQueues,
) -> bool {
    let mut state = bootstrap_state.write().await;
    if state.drained {
        return true;
    }

    if state.pending_peer_requests > 0 {
        return false;
    }

    if queues.is_bootstrap_work_empty(&state.pending_keys) {
        state.drained = true;
        info!("Bootstrap drained: all peer requests completed and work queues empty");
        true
    } else {
        false
    }
}

/// Record a set of discovered keys into the bootstrap state for drain tracking.
#[allow(clippy::implicit_hasher)]
pub async fn track_discovered_keys(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    keys: &HashSet<XorName>,
) {
    let mut state = bootstrap_state.write().await;
    state.pending_keys.extend(keys);
    debug!(
        "Bootstrap tracking {} total discovered keys",
        state.pending_keys.len()
    );
}

/// Increment the pending peer request counter.
pub async fn increment_pending_requests(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    count: usize,
) {
    let mut state = bootstrap_state.write().await;
    state.pending_peer_requests += count;
}

/// Decrement the pending peer request counter (saturating).
pub async fn decrement_pending_requests(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    count: usize,
) {
    let mut state = bootstrap_state.write().await;
    state.pending_peer_requests = state.pending_peer_requests.saturating_sub(count);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use std::time::Instant;

    use super::*;
    use crate::replication::scheduling::ReplicationQueues;
    use crate::replication::types::{
        BootstrapState, HintPipeline, VerificationEntry, VerificationState,
    };

    fn xor_name_from_byte(b: u8) -> XorName {
        [b; 32]
    }

    #[tokio::test]
    async fn check_drained_when_already_drained() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: true,
            pending_peer_requests: 5,
            pending_keys: HashSet::new(),
        }));
        let queues = ReplicationQueues::new();

        assert!(
            check_bootstrap_drained(&state, &queues).await,
            "should be drained when flag is already set"
        );
    }

    #[tokio::test]
    async fn check_drained_blocked_by_pending_requests() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: false,
            pending_peer_requests: 2,
            pending_keys: HashSet::new(),
        }));
        let queues = ReplicationQueues::new();

        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "should not drain with pending requests"
        );
    }

    #[tokio::test]
    async fn check_drained_transitions_when_all_work_done() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: false,
            pending_peer_requests: 0,
            pending_keys: std::iter::once(xor_name_from_byte(0x01)).collect(),
        }));
        let queues = ReplicationQueues::new();

        // Key 0x01 is not in any queue, so bootstrap should drain.
        assert!(check_bootstrap_drained(&state, &queues).await);
        assert!(state.read().await.drained, "drained flag should be set");
    }

    #[tokio::test]
    async fn check_drained_blocked_by_queued_key() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: false,
            pending_peer_requests: 0,
            pending_keys: std::iter::once(xor_name_from_byte(0x01)).collect(),
        }));
        let mut queues = ReplicationQueues::new();

        // Put the bootstrap key into the pending-verify queue.
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            pipeline: HintPipeline::Replica,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            hint_sender: saorsa_core::identity::PeerId::from_bytes([0u8; 32]),
        };
        queues.add_pending_verify(xor_name_from_byte(0x01), entry);

        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "should not drain while bootstrap key is still in pipeline"
        );
    }

    #[tokio::test]
    async fn mark_bootstrap_drained_sets_flag() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        mark_bootstrap_drained(&state).await;
        assert!(state.read().await.drained);
    }

    #[tokio::test]
    async fn track_discovered_keys_accumulates() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let set_a: HashSet<XorName> = [xor_name_from_byte(0x01), xor_name_from_byte(0x02)]
            .into_iter()
            .collect();
        let set_b: HashSet<XorName> = [xor_name_from_byte(0x02), xor_name_from_byte(0x03)]
            .into_iter()
            .collect();

        track_discovered_keys(&state, &set_a).await;
        track_discovered_keys(&state, &set_b).await;

        let s = state.read().await;
        assert_eq!(s.pending_keys.len(), 3, "should deduplicate across calls");
    }

    #[tokio::test]
    async fn increment_and_decrement_pending_requests() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));

        increment_pending_requests(&state, 5).await;
        assert_eq!(state.read().await.pending_peer_requests, 5);

        decrement_pending_requests(&state, 3).await;
        assert_eq!(state.read().await.pending_peer_requests, 2);

        // Saturating subtraction.
        decrement_pending_requests(&state, 10).await;
        assert_eq!(
            state.read().await.pending_peer_requests,
            0,
            "should saturate at zero"
        );
    }
}
