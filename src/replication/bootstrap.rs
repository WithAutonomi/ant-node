//! New-node bootstrap logic (Section 16).
//!
//! A joining node performs active sync to discover and verify keys it should
//! hold, then transitions to normal operation once all bootstrap work drains.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::logging::{debug, info, warn};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

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

    // (d) Overall force-drain backstop — unconditional ceiling. Placed first
    // so it fires regardless of pending peer requests, capacity-rejected
    // sources, or undiscovered keys. Bounds total bootstrap stall even when
    // per-source expiry alone would not resolve the wedge (e.g. multiple
    // coordinated over-cap sources, or a `pending_keys` path that never
    // empties after a disk-full restart). Aligned with `PENDING_VERIFY_MAX_AGE`
    // so by the deadline stale `pending_verify` entries have already been
    // evicted, leaving minimal genuine residual work.
    let now = Instant::now();
    if now.duration_since(state.bootstrap_started_at) >= state.bootstrap_drain_deadline {
        warn!(
            "Bootstrap force-drain: {:?} stall ceiling reached, draining with \
             possibly-outstanding work (rejects={}, pending_peer_requests={}, pending_keys={})",
            state.bootstrap_drain_deadline,
            state.capacity_rejected_sources.len(),
            state.pending_peer_requests,
            state.pending_keys.len(),
        );
        // The deadline deliberately abandons bootstrap accounting debt. Clear
        // that debt as one atomic state transition so post-bootstrap
        // verification and cleanup are not still gated by stale request
        // counters or bootstrap-only key tracking. Queue contents are left
        // intact and continue through the normal verification pipeline.
        state.pending_peer_requests = 0;
        state.pending_keys.clear();
        state.capacity_rejected_sources.clear();
        state.drained = true;
        return true;
    }

    if state.pending_peer_requests > 0 {
        return false;
    }

    // Hints rejected at capacity, or displaced when another sender reclaims a
    // borrowed slot, must be re-delivered by the originating source before
    // drain can be claimed; otherwise we'd silently mark ourselves complete
    // with outstanding work the source still owes us.
    // Entries retire per-source as each source's next admission cycle
    // completes with zero rejections — see `clear_capacity_rejected` — or
    // expire once the source has been silent past the re-delivery TTL — see
    // `expire_capacity_rejected`.
    if !state.capacity_rejected_sources.is_empty() {
        let n = state.capacity_rejected_sources.len();
        debug!("Bootstrap NOT drained: {n} source(s) have outstanding capacity-rejected hints");
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

/// Record that `source` had one or more hints rejected at capacity this cycle.
///
/// Tracks each source's **first** rejection time, not a counter and not the
/// most recent time: a repeat rejection re-asserts the debt but does not
/// restart the expiry clock (see
/// [`BootstrapState::capacity_rejected_sources`]). Bootstrap cannot drain
/// while this source has an entry; cleared by [`clear_capacity_rejected`] when
/// the same source's next admission cycle completes with zero rejections (i.e.
/// the source successfully re-delivered everything that previously
/// overflowed), or expired by [`expire_capacity_rejected`] once the debt has
/// stood past the re-delivery TTL.
pub async fn note_capacity_rejected(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    source: saorsa_core::identity::PeerId,
) {
    let mut state = bootstrap_state.write().await;
    if state.drained {
        return;
    }
    if state.note_capacity_rejected(source, Instant::now()) {
        let n = state.capacity_rejected_sources.len();
        debug!(
            "Bootstrap: source {source} now has outstanding capacity-rejected hints \
             ({n} sources outstanding)"
        );
    }
}

/// Mark `source`'s outstanding capacity rejections as cleared.
///
/// Called whenever `source` completes an admission cycle with zero
/// capacity rejections: the source successfully re-delivered any hints
/// that previously overflowed, so its contribution to "bootstrap not
/// drained" is retired. Returns whether an outstanding entry was removed.
pub async fn clear_capacity_rejected(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    source: &saorsa_core::identity::PeerId,
) -> bool {
    let mut state = bootstrap_state.write().await;
    if state.capacity_rejected_sources.remove(source).is_some() {
        let n = state.capacity_rejected_sources.len();
        debug!(
            "Bootstrap: cleared outstanding capacity rejections for {source} \
             ({n} sources still outstanding)"
        );
        true
    } else {
        false
    }
}

/// Expire capacity-rejection records whose most recent rejection is older
/// than `max_age`, returning how many sources were expired.
///
/// A source that has not re-delivered within `max_age` has abandoned its
/// owed re-hints — or departed in a race with its own `PeerRemoved` cleanup,
/// leaving a record that no admission cycle or removal event can ever clear.
/// Expiry forfeits the keys that source still owed so bootstrap can drain;
/// the post-bootstrap neighbor-sync and audit/repair pipeline recover them
/// (see `BootstrapState::capacity_rejected_sources`).
pub async fn expire_capacity_rejected(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    max_age: Duration,
) -> usize {
    let now = Instant::now();
    let mut state = bootstrap_state.write().await;
    let before = state.capacity_rejected_sources.len();
    state
        .capacity_rejected_sources
        .retain(|source, rejected_at| {
            let expired = now.duration_since(*rejected_at) >= max_age;
            if expired {
                warn!(
                    "Bootstrap: expiring capacity-rejection record for {source} — the source \
                 abandoned re-delivery (or departed mid-admission) and the hints it still \
                 owed are forfeited"
                );
            }
            !expired
        });
    before - state.capacity_rejected_sources.len()
}

/// Record a set of discovered keys into the bootstrap state for drain tracking.
#[allow(clippy::implicit_hasher)]
pub async fn track_discovered_keys(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    keys: &HashSet<XorName>,
) {
    let mut state = bootstrap_state.write().await;
    if state.drained {
        return;
    }
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
    if state.drained {
        return;
    }
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
    use super::*;

    fn xor_name_from_byte(b: u8) -> XorName {
        [b; 32]
    }

    #[tokio::test]
    async fn check_drained_when_already_drained() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: true,
            pending_peer_requests: 5,
            pending_keys: HashSet::new(),
            capacity_rejected_sources: std::collections::HashMap::new(),
            bootstrap_started_at: Instant::now(),
            bootstrap_drain_deadline: Duration::from_secs(1800),
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
            capacity_rejected_sources: std::collections::HashMap::new(),
            bootstrap_started_at: Instant::now(),
            bootstrap_drain_deadline: Duration::from_secs(1800),
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
            capacity_rejected_sources: std::collections::HashMap::new(),
            bootstrap_started_at: Instant::now(),
            bootstrap_drain_deadline: Duration::from_secs(1800),
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
            capacity_rejected_sources: std::collections::HashMap::new(),
            bootstrap_started_at: Instant::now(),
            bootstrap_drain_deadline: Duration::from_secs(1800),
        }));
        let mut queues = ReplicationQueues::new();

        // Put the bootstrap key into the pending-verify queue.
        let now = Instant::now();
        let entry = crate::replication::types::VerificationEntry {
            state: crate::replication::types::VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: now,
            next_verify_at: now,
            hint_sources: HashSet::from([saorsa_core::identity::PeerId::from_bytes([0u8; 32])]),
            replica_hint_sources: HashSet::from([saorsa_core::identity::PeerId::from_bytes(
                [0u8; 32],
            )]),
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

    #[tokio::test]
    async fn drained_state_ignores_new_bootstrap_accounting() {
        let source = saorsa_core::identity::PeerId::from_bytes([7; 32]);
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        mark_bootstrap_drained(&state).await;

        increment_pending_requests(&state, 3).await;
        track_discovered_keys(&state, &HashSet::from([xor_name_from_byte(0x01)])).await;
        note_capacity_rejected(&state, source).await;

        let state = state.read().await;
        assert_eq!(state.pending_peer_requests, 0);
        assert!(state.pending_keys.is_empty());
        assert!(state.capacity_rejected_sources.is_empty());
    }

    /// Round-3 regression: a source that previously had capacity-rejected
    /// hints must be retired from the "not yet drained" list when it
    /// completes a later admission cycle with zero rejections, otherwise
    /// `check_bootstrap_drained` is permanently wedged after a single
    /// rejection.
    #[tokio::test]
    async fn capacity_rejected_clears_on_clean_cycle() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = ReplicationQueues::new();
        let source = saorsa_core::identity::PeerId::from_bytes([7u8; 32]);

        // First cycle: this source overflowed, drain blocked.
        note_capacity_rejected(&state, source).await;
        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "drain must be blocked while a source has outstanding capacity rejections"
        );

        // Second cycle from the SAME source: zero rejections → clear it.
        clear_capacity_rejected(&state, &source).await;
        assert!(
            check_bootstrap_drained(&state, &queues).await,
            "drain must complete once the source's outstanding rejections are cleared"
        );
    }

    /// Per-source granularity: one source's clean cycle must NOT clear a
    /// different source's outstanding rejections.
    #[tokio::test]
    async fn capacity_rejected_is_per_source() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = ReplicationQueues::new();
        let source_a = saorsa_core::identity::PeerId::from_bytes([0xAA; 32]);
        let source_b = saorsa_core::identity::PeerId::from_bytes([0xBB; 32]);

        note_capacity_rejected(&state, source_a).await;
        note_capacity_rejected(&state, source_b).await;
        assert!(!check_bootstrap_drained(&state, &queues).await);

        // Only A clears; B still owes us re-hints.
        clear_capacity_rejected(&state, &source_a).await;
        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "B's outstanding rejections must keep drain blocked"
        );

        clear_capacity_rejected(&state, &source_b).await;
        assert!(check_bootstrap_drained(&state, &queues).await);
    }

    /// A source rejected within the TTL still blocks drain: expiry must not
    /// forfeit re-delivery the source may legitimately still perform.
    #[tokio::test]
    async fn capacity_rejected_within_ttl_still_blocks_drain() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = ReplicationQueues::new();
        let source = saorsa_core::identity::PeerId::from_bytes([0xC1; 32]);

        note_capacity_rejected(&state, source).await;
        assert_eq!(
            expire_capacity_rejected(&state, Duration::from_secs(3600)).await,
            0,
            "a fresh rejection must survive expiry with a generous max_age"
        );
        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "a within-TTL rejection must keep drain blocked"
        );
    }

    /// The orphaned-entry escape hatch: once a source's rejection record
    /// expires, drain is no longer blocked by it.
    #[tokio::test]
    async fn capacity_rejected_expiry_unblocks_drain() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = ReplicationQueues::new();
        let source = saorsa_core::identity::PeerId::from_bytes([0xC2; 32]);

        note_capacity_rejected(&state, source).await;
        assert!(!check_bootstrap_drained(&state, &queues).await);

        assert_eq!(expire_capacity_rejected(&state, Duration::ZERO).await, 1);
        assert!(
            check_bootstrap_drained(&state, &queues).await,
            "drain must complete once the abandoned rejection expires"
        );
    }

    /// Expiry is per-source: dropping a stale source must not forfeit a
    /// fresh source's owed re-delivery.
    #[tokio::test]
    async fn capacity_rejected_expiry_is_per_source() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = ReplicationQueues::new();
        let stale_source = saorsa_core::identity::PeerId::from_bytes([0xC3; 32]);
        let fresh_source = saorsa_core::identity::PeerId::from_bytes([0xC4; 32]);
        let max_age = Duration::from_secs(60);
        let stale_rejected_at = Instant::now().checked_sub(max_age * 2).unwrap();

        state
            .write()
            .await
            .capacity_rejected_sources
            .insert(stale_source, stale_rejected_at);
        note_capacity_rejected(&state, fresh_source).await;

        assert_eq!(expire_capacity_rejected(&state, max_age).await, 1);
        assert!(
            state
                .read()
                .await
                .capacity_rejected_sources
                .contains_key(&fresh_source),
            "the fresh source must survive another source's expiry"
        );
        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "the fresh source must still block drain"
        );
    }

    /// A repeat rejection re-asserts the debt but must NOT restart the expiry
    /// clock.
    ///
    /// Refreshing on every rejection is what wedged bootstrap open: a source
    /// that keeps overflowing the queue keeps its own record permanently
    /// fresh, `check_bootstrap_drained` never returns true, and auditing stays
    /// off for the lifetime of the pressure (Invariant 19).
    #[tokio::test]
    async fn repeat_capacity_rejection_does_not_refresh_timestamp() {
        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let source = saorsa_core::identity::PeerId::from_bytes([0xC5; 32]);
        let max_age = Duration::from_secs(60);
        let first_rejected_at = Instant::now().checked_sub(max_age * 2).unwrap();

        state
            .write()
            .await
            .capacity_rejected_sources
            .insert(source, first_rejected_at);
        note_capacity_rejected(&state, source).await;

        let recorded_at = state
            .read()
            .await
            .capacity_rejected_sources
            .get(&source)
            .copied()
            .unwrap();
        assert_eq!(
            recorded_at, first_rejected_at,
            "a repeat rejection must leave the first-seen time alone"
        );
        assert_eq!(
            expire_capacity_rejected(&state, max_age).await,
            1,
            "an aged debt must still expire even though the source keeps \
             re-overflowing the queue"
        );
    }

    /// Sustained pressure cannot hold bootstrap open past the TTL.
    ///
    /// Drives the production accounting shape — repeated rejections arriving
    /// faster than the TTL — and asserts the node still drains.
    #[tokio::test]
    async fn sustained_capacity_rejection_still_drains_after_ttl() {
        const REJECTION_ROUNDS: usize = 8;

        let state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = ReplicationQueues::new();
        let source = saorsa_core::identity::PeerId::from_bytes([0xC6; 32]);
        let max_age = Duration::from_secs(60);

        for _ in 0..REJECTION_ROUNDS {
            note_capacity_rejected(&state, source).await;
            assert!(
                !check_bootstrap_drained(&state, &queues).await,
                "an outstanding debt must block drain while it is inside the TTL"
            );
        }

        // Age the (unrefreshed) first-seen stamp past the TTL.
        let aged = Instant::now().checked_sub(max_age * 2).unwrap();
        state
            .write()
            .await
            .capacity_rejected_sources
            .insert(source, aged);

        assert_eq!(
            expire_capacity_rejected(&state, max_age).await,
            1,
            "the debt must expire once the FIRST rejection is older than the TTL"
        );
        assert!(
            check_bootstrap_drained(&state, &queues).await,
            "bootstrap must drain once the expired debt is forfeited"
        );
    }

    /// (d) Force-drain backstop: past the overall drain deadline, drain is
    /// forced even with outstanding peer requests, capacity-rejected sources,
    /// and pending keys. This is the unconditional ceiling that bounds total
    /// bootstrap stall regardless of any per-source or per-key state.
    #[tokio::test]
    async fn force_drain_after_overall_deadline() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: false,
            pending_peer_requests: 3,
            pending_keys: std::iter::once(xor_name_from_byte(0x01)).collect(),
            capacity_rejected_sources: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    saorsa_core::identity::PeerId::from_bytes([0xAA; 32]),
                    Instant::now(),
                );
                m
            },
            // Backdate bootstrap start past the 60s deadline.
            bootstrap_started_at: Instant::now()
                .checked_sub(Duration::from_secs(61))
                .expect("test duration must fit in Instant"),
            bootstrap_drain_deadline: Duration::from_secs(60),
        }));
        let queues = ReplicationQueues::new();

        assert!(
            check_bootstrap_drained(&state, &queues).await,
            "force-drain must fire after the overall deadline despite all outstanding work"
        );
        assert!(
            state.read().await.drained,
            "drained flag must be set by force-drain"
        );
        let state = state.read().await;
        assert_eq!(state.pending_peer_requests, 0);
        assert!(state.pending_keys.is_empty());
        assert!(state.capacity_rejected_sources.is_empty());
    }

    /// (d) Within the deadline, outstanding state still blocks drain: the
    /// force-drain ceiling must NOT fire early and mask genuine in-progress
    /// bootstrap work.
    #[tokio::test]
    async fn force_drain_does_not_fire_within_deadline() {
        let state = Arc::new(RwLock::new(BootstrapState {
            drained: false,
            pending_peer_requests: 1,
            pending_keys: HashSet::new(),
            capacity_rejected_sources: std::collections::HashMap::new(),
            bootstrap_started_at: Instant::now(),
            bootstrap_drain_deadline: Duration::from_secs(1800),
        }));
        let queues = ReplicationQueues::new();

        assert!(
            !check_bootstrap_drained(&state, &queues).await,
            "within the deadline, pending peer requests must still block drain"
        );
        assert!(
            !state.read().await.drained,
            "force-drain must not fire before the deadline"
        );
    }
}
