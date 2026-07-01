//! Replication subsystem for the Autonomi network.
//!
//! Implements Kademlia-style replication with:
//! - Fresh replication with `PoP` verification
//! - Neighbor sync with round-robin cycle management
//! - Batched quorum verification
//! - Storage audit protocol (anti-outsourcing)
//! - `PaidForList` persistence and convergence
//! - Responsibility pruning with hysteresis

// The replication engine intentionally holds `RwLock` read guards across await
// boundaries (e.g. reading sync_history while calling audit_tick). Clippy's
// nursery lint `significant_drop_tightening` flags these, but the guards must
// remain live for the duration of the call.
#![allow(clippy::significant_drop_tightening)]

pub mod admission;
pub mod audit;
pub mod bootstrap;
pub mod commitment;
pub mod commitment_state;
pub mod config;
pub mod fresh;
pub mod neighbor_sync;
pub mod paid_list;
pub mod possession;
pub mod protocol;
pub mod pruning;
pub mod quorum;
pub mod recent_provers;
pub mod scheduling;
pub mod storage_commitment_audit;
pub mod subtree;
pub mod types;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::pin::Pin;

use crate::logging::{debug, error, info, warn};
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use rand::Rng;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, Notify, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::payment::{PaymentVerifier, VerificationContext};
use crate::replication::audit::AuditTickResult;
use crate::replication::commitment::{commitment_hash, StorageCommitment};
use crate::replication::commitment_state::{PeerCommitmentRecord, ResponderCommitmentState};
use crate::replication::config::{
    max_parallel_fetch, storage_admission_width, ReplicationConfig, MAX_AUDIT_RESPONSES_PER_PEER,
    MAX_CONCURRENT_AUDIT_RESPONSES, MAX_CONCURRENT_REPLICATION_SENDS,
    MAX_VERIFICATION_KEYS_PER_REQUEST, REPLICATION_PROTOCOL_ID,
};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    FreshReplicationResponse, NeighborSyncResponse, ReplicationMessage, ReplicationMessageBody,
    VerificationResponse,
};
use crate::replication::quorum::KeyVerificationOutcome;
use crate::replication::recent_provers::RecentProvers;
use crate::replication::scheduling::ReplicationQueues;
use crate::replication::types::{
    AuditFailureReason, BootstrapClaimObservation, BootstrapState, FailureEvidence, HintPipeline,
    NeighborSyncState, PeerSyncRecord, RepairProofs, VerificationEntry, VerificationState,
};
use crate::storage::LmdbStorage;
use saorsa_core::identity::{NodeIdentity, PeerId};
use saorsa_core::{DhtNetworkEvent, P2PEvent, P2PNode, TrustEvent};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix used by saorsa-core's request-response mechanism.
const RR_PREFIX: &str = "/rr/";

fn fresh_offer_payment_context() -> VerificationContext {
    VerificationContext::ClientPut
}

fn paid_notify_payment_context() -> VerificationContext {
    VerificationContext::PaidListAdmission
}

/// Boxed future type for in-flight fetch tasks.
type FetchFuture = Pin<Box<dyn Future<Output = (XorName, Option<FetchOutcome>)> + Send>>;

/// Shared dependencies for one verification worker cycle.
struct VerificationCycleContext<'a> {
    p2p_node: &'a Arc<P2PNode>,
    paid_list: &'a Arc<PaidList>,
    storage: &'a Arc<LmdbStorage>,
    queues: &'a Arc<RwLock<ReplicationQueues>>,
    config: &'a ReplicationConfig,
    bootstrap_state: &'a Arc<RwLock<BootstrapState>>,
    is_bootstrapping: &'a Arc<RwLock<bool>>,
    bootstrap_complete_notify: &'a Arc<Notify>,
    /// v12 §6 holder-eligibility inputs. The verifier downgrades a
    /// peer's Present claim to Unresolved unless they're a credited
    /// holder of the key (i.e. they recently passed a commitment-bound
    /// audit on it under their currently-credited commitment hash).
    last_commitment_by_peer: &'a Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &'a Arc<RwLock<HashSet<PeerId>>>,
    recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// Fetch worker polling interval in milliseconds.
const FETCH_WORKER_POLL_MS: u64 = 100;

/// Verification worker polling interval in milliseconds.
const VERIFICATION_WORKER_POLL_MS: u64 = 250;

/// Verification cycle duration that is worth surfacing at info level.
const VERIFICATION_CYCLE_SLOW_LOG_MS: u128 = 500;

/// Standard trust event weight for per-operation success/failure signals.
///
/// Used for individual replication fetch outcomes, integrity check failures,
/// and bootstrap claim abuse. Distinct from `AUDIT_FAILURE_TRUST_WEIGHT` which
/// is reserved for confirmed audit failures.
const REPLICATION_TRUST_WEIGHT: f64 = 1.0;

/// Bootstrap drain check interval in seconds.
const BOOTSTRAP_DRAIN_CHECK_SECS: u64 = 5;

/// How often the responder rebuilds + rotates its storage commitment.
///
/// Each rebuild scans LMDB to compute leaf hashes; for ~10k keys this is
/// sub-100ms (BLAKE3 + tree build). Retention is gossip-anchored, NOT
/// rotation-anchored: the responder stays answerable for the current
/// commitment plus the last `RETAINED_GOSSIPED_COMMITMENTS` (= 2) it
/// actually gossiped, each kept for `GOSSIP_ANSWERABILITY_TTL` (3 h) after
/// its last emission (see `commitment_state`). So the rotation cadence does
/// not by itself bound answerability — a gossiped commitment stays
/// answerable across rotations until its gossip TTL lapses.
///
/// Default: 1 hour, aligned with the worst-case neighbor-sync cooldown
/// (`NEIGHBOR_SYNC_COOLDOWN_SECS = 3600`). Because the gossip TTL (3 h)
/// comfortably exceeds the gap between our rotation and the next gossip
/// arrival at a remote peer, this prevents the "unknown commitment hash" ->
/// Idle audit-skip pattern from being the common case.
///
/// Why not faster: the v12 pin is bound to a specific point-in-time
/// commitment, so rotation isn't security-critical for pin freshness —
/// only for keeping the committed key set current as the responder
/// writes new keys. 1 hour is plenty for that, and slow enough that
/// honest auditors mostly hit `current` or `previous` rather than the
/// "rotated past" case.
const COMMITMENT_ROTATION_INTERVAL_SECS: u64 = 3600;

/// Minimum interval between commitment signature verifications for a
/// single peer (v10/v12 §2 step 3 + §11 `DoS`).
///
/// A sybil that bypasses the routing-table gate (e.g. by transient
/// bucket pollution) could otherwise force one ML-DSA-65 verify (~1 ms)
/// per gossip message. This rate limit caps the verify-per-peer rate
/// at 1/min, which is comfortably above the legitimate gossip cadence
/// (the 10-20 min neighbor-sync round on each peer).
const COMMITMENT_SIG_VERIFY_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on the size of `last_commitment_by_peer`.
///
/// Bounds the per-process memory cost of the auditor's per-peer
/// commitment cache. Each entry holds a `StorageCommitment`
/// (~5 KiB: 1952-byte pubkey + 3293-byte signature + small fields).
/// At 4096 entries the cache is ~20 MiB, which comfortably covers a
/// realistic close-group neighborhood. When the cap is hit, one
/// arbitrary existing entry is evicted on insert (`HashMap` iteration
/// order is unspecified; we do not track insertion order). The
/// `PeerRemoved` handler proactively drops entries as the DHT
/// detects departures, and `ingest_peer_commitment` only admits
/// commitments from peers currently in the routing table — together
/// the cap is the third line of defence against sybil/churn flooding.
const MAX_LAST_COMMITMENT_BY_PEER: usize = 4096;

/// Cap on the sticky `ever_capable_peers` set. Bounds memory so a
/// long-running bootstrap node cannot have the set grow without limit
/// from peer-id churn. Sized at 4x `MAX_LAST_COMMITMENT_BY_PEER` so
/// the set comfortably outlives normal LRU churn but still caps the
/// blast radius of identity-rotation attacks. Once full we refuse new
/// inserts (no eviction) — keeps the historic set stable; new v12
/// peers above the cap are treated as legacy on rejoin, which matches
/// the behaviour before this set existed, not a security regression.
const MAX_EVER_CAPABLE_PEERS: usize = 4 * MAX_LAST_COMMITMENT_BY_PEER;

// ---------------------------------------------------------------------------
// ReplicationEngine
// ---------------------------------------------------------------------------

/// The replication engine manages all replication background tasks and state.
pub struct ReplicationEngine {
    /// Replication configuration (shared across spawned tasks).
    config: Arc<ReplicationConfig>,
    /// P2P networking node.
    p2p_node: Arc<P2PNode>,
    /// Local chunk storage.
    storage: Arc<LmdbStorage>,
    /// Persistent paid-for-list.
    paid_list: Arc<PaidList>,
    /// Payment verifier for `PoP` validation.
    payment_verifier: Arc<PaymentVerifier>,
    /// Replication pipeline queues.
    queues: Arc<RwLock<ReplicationQueues>>,
    /// Neighbor sync cycle state.
    sync_state: Arc<RwLock<NeighborSyncState>>,
    /// Per-peer sync history (for `RepairOpportunity`).
    ///
    /// This map grows with peer churn and is intentionally unbounded: entries
    /// are lightweight (`PeerSyncRecord` is two fields) and peer IDs are
    /// naturally bounded by the routing table's k-bucket capacity.
    sync_history: Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    /// Per-peer cooldown for gossip-triggered subtree audits (ADR-0002).
    ///
    /// Records when each peer was last audited so a burst of gossiped
    /// commitment changes cannot spawn back-to-back audits of the same peer.
    /// Bounded by routing-table membership and cleaned on `PeerRemoved`.
    audit_on_gossip_cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Completed local neighbor-sync cycle epoch for proof maturity.
    sync_cycle_epoch: Arc<RwLock<u64>>,
    /// Per-key repair proof tracking for audit eligibility.
    repair_proofs: Arc<RwLock<RepairProofs>>,
    /// Bootstrap state tracking.
    bootstrap_state: Arc<RwLock<BootstrapState>>,
    /// Whether this node is currently bootstrapping.
    is_bootstrapping: Arc<RwLock<bool>>,
    /// Trigger for early neighbor sync (signalled on topology changes).
    sync_trigger: Arc<Notify>,
    /// Notified when `is_bootstrapping` transitions from `true` to `false`.
    bootstrap_complete_notify: Arc<Notify>,
    /// Node identity (for signing storage commitments).
    ///
    /// Phase 3 of the v12 storage-bound audit design. The responder
    /// uses this to sign its periodically-built `StorageCommitment`.
    identity: Arc<NodeIdentity>,
    /// Responder-side commitment state (two-slot atomic rotation).
    ///
    /// Periodically rebuilt from the live LMDB key set; gossiped on
    /// outbound `NeighborSyncRequest`/`Response`; consulted by the
    /// commitment-bound audit handler.
    commitment_state: Arc<ResponderCommitmentState>,
    /// Auditor-side per-peer commitment record (last known commitment +
    /// sticky `commitment_capable` flag).
    ///
    /// Populated whenever an inbound gossip carries a verified
    /// commitment from the sender. Used by `audit_tick` to snapshot
    /// `expected_commitment_hash` into outbound challenges, and by
    /// holder-eligibility (§6) to decide whether a peer's `recent_provers`
    /// proof should be honoured. The sticky `commitment_capable` flag
    /// flips true on first successful ingest and never reverts (§2
    /// step 5).
    last_commitment_by_peer: Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    /// Sticky set of peer IDs we have EVER seen carrying a v12
    /// commitment, independent of whether their commitment bytes are
    /// still in `last_commitment_by_peer`. The §6 holder-eligibility
    /// closure consults this set to keep treating churned-out
    /// previously-v12 peers as v12-capable (rather than degrading them
    /// to "legacy" credit-unconditionally) when they re-appear on the
    /// network before their next gossip arrives. Bounded growth: even
    /// at one million peers seen over the node's lifetime, the set is
    /// 32 MB.
    ever_capable_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Auditor-side holder-eligibility cache (v12 §6).
    ///
    /// Recorded on successful commitment-bound audit; read by future
    /// quorum / paid-list eligibility checks (phase-3 stretch).
    recent_provers: Arc<RwLock<RecentProvers>>,
    /// Per-peer last sig-verify attempt timestamp for the §2 step 3 /
    /// §11 `DoS` rate limit. Bumped on EVERY verify attempt (success or
    /// failure) so a peer we've never successfully verified can't burn
    /// CPU on a flood of structurally-plausible-but-invalid gossips.
    /// Lives separately from `last_commitment_by_peer` because that
    /// map's records only exist after a successful verify.
    sig_verify_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Limits concurrent outbound replication sends to prevent bandwidth
    /// saturation on home broadband connections.
    send_semaphore: Arc<Semaphore>,
    /// Bounds concurrent IN-FLIGHT audit-responder tasks (subtree round 1 +
    /// byte round 2). Those are spawned off the serial message loop so disk
    /// reads don't block replication; the semaphore restores a global
    /// backpressure ceiling so the node can't fan out unbounded `get_raw` reads
    /// / multi-MiB byte serves.
    audit_responder_semaphore: Arc<Semaphore>,
    /// Per-source in-flight audit-responder counts, capped at
    /// [`MAX_AUDIT_RESPONSES_PER_PEER`]. The GLOBAL semaphore alone is not
    /// flood-fair: one peer spamming challenges could occupy every slot and
    /// starve honest auditors, whose dropped challenges then convert to
    /// audit timeouts against HONEST peers (codex-r2 A). This
    /// per-peer cap guarantees no single source can hold more than its share,
    /// so a flood self-throttles without denying service to everyone else.
    audit_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Receiver for fresh-write events from the chunk PUT handler.
    ///
    /// When present, `start()` spawns a drainer task that calls
    /// `replicate_fresh` for each event.
    fresh_write_rx: Option<mpsc::UnboundedReceiver<fresh::FreshWriteEvent>>,
    /// Sender for delayed possession-check events (ADR-0003). The fresh-write
    /// drainer pushes the responsible close-group peers here after each fresh
    /// replication; the possession-check scheduler drains the paired receiver.
    possession_check_tx: mpsc::UnboundedSender<possession::PossessionCheckEvent>,
    /// Receiver paired with `possession_check_tx`; taken by the scheduler task.
    possession_check_rx: Option<mpsc::UnboundedReceiver<possession::PossessionCheckEvent>>,
    /// Shutdown token.
    shutdown: CancellationToken,
    /// Background task handles.
    task_handles: Vec<JoinHandle<()>>,
}

impl ReplicationEngine {
    /// Create a new replication engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the `PaidList` LMDB environment cannot be opened
    /// or if the configuration fails validation.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: ReplicationConfig,
        p2p_node: Arc<P2PNode>,
        storage: Arc<LmdbStorage>,
        payment_verifier: Arc<PaymentVerifier>,
        identity: Arc<NodeIdentity>,
        root_dir: &Path,
        fresh_write_rx: mpsc::UnboundedReceiver<fresh::FreshWriteEvent>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        config.validate().map_err(Error::Config)?;

        let paid_list = Arc::new(
            PaidList::new(root_dir)
                .await
                .map_err(|e| Error::Storage(format!("Failed to open PaidList: {e}")))?,
        );

        let initial_neighbors = NeighborSyncState::new_cycle(Vec::new());
        let config = Arc::new(config);
        let (possession_check_tx, possession_check_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config: Arc::clone(&config),
            p2p_node,
            storage,
            paid_list,
            payment_verifier,
            queues: Arc::new(RwLock::new(ReplicationQueues::new())),
            sync_state: Arc::new(RwLock::new(initial_neighbors)),
            sync_history: Arc::new(RwLock::new(HashMap::new())),
            audit_on_gossip_cooldown: Arc::new(RwLock::new(HashMap::new())),
            sync_cycle_epoch: Arc::new(RwLock::new(0)),
            repair_proofs: Arc::new(RwLock::new(RepairProofs::new())),
            bootstrap_state: Arc::new(RwLock::new(BootstrapState::new())),
            is_bootstrapping: Arc::new(RwLock::new(true)),
            sync_trigger: Arc::new(Notify::new()),
            bootstrap_complete_notify: Arc::new(Notify::new()),
            identity,
            commitment_state: Arc::new(ResponderCommitmentState::new()),
            last_commitment_by_peer: Arc::new(RwLock::new(HashMap::new())),
            ever_capable_peers: Arc::new(RwLock::new(HashSet::new())),
            recent_provers: Arc::new(RwLock::new(RecentProvers::new())),
            sig_verify_attempts: Arc::new(RwLock::new(HashMap::new())),
            send_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REPLICATION_SENDS)),
            audit_responder_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES)),
            audit_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            fresh_write_rx: Some(fresh_write_rx),
            possession_check_tx,
            possession_check_rx: Some(possession_check_rx),
            shutdown,
            task_handles: Vec::new(),
        })
    }

    /// Get a reference to the `PaidList`.
    #[must_use]
    pub fn paid_list(&self) -> &Arc<PaidList> {
        &self.paid_list
    }

    /// Get a reference to the responder's commitment state. Used by audit
    /// handlers to look up commitments by hash; used by the rotation tick
    /// to install fresh ones.
    #[must_use]
    pub fn commitment_state(&self) -> &Arc<ResponderCommitmentState> {
        &self.commitment_state
    }

    /// Get a reference to the auditor's last-commitment-by-peer table.
    #[must_use]
    pub fn last_commitment_by_peer(&self) -> &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>> {
        &self.last_commitment_by_peer
    }

    /// Get a reference to the holder-eligibility cache. Phase-3 stretch:
    /// will be read by quorum / paid-list eligibility checks.
    #[must_use]
    pub fn recent_provers(&self) -> &Arc<RwLock<RecentProvers>> {
        &self.recent_provers
    }

    /// Test-only: rebuild + rotate this node's storage commitment now over its
    /// current key set (normally on a 1h timer). Lets a test commit to chunks it
    /// just stored without waiting for the rotation cadence.
    ///
    /// # Errors
    ///
    /// Propagates any error from reading the local key set or building/signing
    /// the commitment.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn rebuild_commitment_now(&self) -> Result<()> {
        rebuild_and_rotate_commitment(
            &self.storage,
            &self.identity,
            &self.commitment_state,
            &self.p2p_node,
            &self.config,
        )
        .await
    }

    /// Test-only: directly seed this node's cached commitment for `peer`,
    /// simulating "we received `peer`'s gossiped commitment" without depending
    /// on neighbor-sync propagation timing. Lets a two-node audit test pin the
    /// peer's commitment deterministically.
    #[cfg(any(feature = "test-utils", test))]
    pub async fn inject_peer_commitment_for_test(
        &self,
        peer: &PeerId,
        commitment: StorageCommitment,
    ) {
        let now = Instant::now();
        self.last_commitment_by_peer
            .write()
            .await
            .insert(*peer, PeerCommitmentRecord::from_verified(commitment, now));
        self.ever_capable_peers.write().await.insert(*peer);
    }

    /// Test-only: run ONE subtree audit against `peer` right now, pinned to the
    /// commitment this node has cached for it (from gossip), over the live wire.
    /// Returns the audit outcome so tests can assert honest-pass / adversary-fail
    /// in a real two-node setting without waiting for the gossip cadence.
    ///
    /// Returns `AuditTickResult::Idle` if we have no cached commitment for the
    /// peer yet (gossip hasn't reached us). Gated to test builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn audit_peer_now(&self, peer: &PeerId) -> audit::AuditTickResult {
        let target = {
            let map = self.last_commitment_by_peer.read().await;
            map.get(peer)
                .and_then(PeerCommitmentRecord::last_commitment)
                .and_then(|c| commitment_hash(c).map(|h| (h, c.key_count)))
        };
        let Some((pin, key_count)) = target else {
            return audit::AuditTickResult::Idle;
        };
        let credit = storage_commitment_audit::AuditCredit {
            recent_provers: &self.recent_provers,
        };
        storage_commitment_audit::run_subtree_audit(
            &self.p2p_node,
            &self.config,
            peer,
            pin,
            key_count,
            Some(&credit),
        )
        .await
    }

    /// Test-only: run the possession check immediately for `key` against
    /// `peers`, bypassing the scheduler's randomised 5-15 minute settle delay.
    ///
    /// Penalises any peer that does not hold `key` at `AuditChallenge`
    /// severity (ADR-0003). Lets e2e tests assert the detection+penalty path
    /// deterministically without waiting for the scheduled check.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn run_possession_check_now(&self, key: XorName, peers: Vec<PeerId>) {
        possession::run_possession_check(
            key,
            peers,
            &self.p2p_node,
            &self.storage,
            &self.config,
            &self.sync_state,
            &self.shutdown,
        )
        .await;
    }

    /// Start all background tasks.
    ///
    /// `dht_events` must be subscribed **before** `P2PNode::start()` so that
    /// the `BootstrapComplete` event emitted during DHT bootstrap is not
    /// missed by the bootstrap-sync gate.
    pub fn start(&mut self, dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>) {
        if !self.task_handles.is_empty() {
            error!("ReplicationEngine::start() called while already running — ignoring");
            return;
        }
        info!("Starting replication engine");

        self.start_message_handler();
        self.start_neighbor_sync_loop();
        self.start_self_lookup_loop();
        // Audit #2 (responsible-chunk): periodic tick auditing peers for the
        // chunks they SHOULD store (responsibility + prior hint).
        self.start_audit_loop();
        // Audit #1 (storage-commitment) is gossip-triggered in the message
        // handler when a peer's commitment is ingested, not on a periodic tick.
        self.start_commitment_rotation_loop();
        self.start_fetch_worker();
        self.start_verification_worker();
        self.start_bootstrap_sync(dht_events);
        self.start_fresh_write_drainer();
        self.start_possession_check_scheduler();

        info!(
            "Replication engine started with {} background tasks",
            self.task_handles.len()
        );
    }

    /// Returns `true` if the node is still in the replication bootstrap phase.
    ///
    /// During bootstrap, audit challenges return `Bootstrapping` instead of
    /// digests, and neighbor sync responses carry `bootstrapping: true`.
    pub async fn is_bootstrapping(&self) -> bool {
        *self.is_bootstrapping.read().await
    }

    /// Wait until the replication bootstrap phase completes.
    ///
    /// Returns immediately if bootstrap has already completed. Useful for
    /// readiness probes, health checks, and test harnesses that need the
    /// node to be fully operational before proceeding.
    ///
    /// Returns `true` if bootstrap completed within the timeout, `false`
    /// if the timeout elapsed first.
    pub async fn wait_for_bootstrap_complete(&self, timeout: Duration) -> bool {
        // Register the notification future *before* checking the flag so that
        // a transition between the read and the await is not missed.
        let notified = self.bootstrap_complete_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if !*self.is_bootstrapping.read().await {
            return true;
        }

        tokio::time::timeout(timeout, notified).await.is_ok()
    }

    /// Cancel all background tasks and wait for them to terminate.
    ///
    /// This must be awaited before dropping the engine when the caller needs
    /// the `Arc<LmdbStorage>` references held by background tasks to be
    /// released (e.g. before reopening the same LMDB environment).
    pub async fn shutdown(&mut self) {
        self.shutdown.cancel();
        for (i, mut handle) in self.task_handles.drain(..).enumerate() {
            match tokio::time::timeout(std::time::Duration::from_secs(10), &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_cancelled() => {}
                Ok(Err(e)) => warn!("Replication task {i} panicked during shutdown: {e}"),
                Err(_) => {
                    warn!("Replication task {i} did not stop within 10s, aborting");
                    handle.abort();
                }
            }
        }
    }

    /// Trigger an early neighbor sync round.
    ///
    /// Useful after topology changes (new nodes joining, network heal after
    /// partition) when the caller wants replication to converge faster than
    /// the regular 10-20 minute cadence.
    pub fn trigger_neighbor_sync(&self) {
        self.sync_trigger.notify_one();
    }

    /// Execute fresh replication for a newly stored record, then schedule the
    /// delayed possession check for the responsible close-group peers
    /// (ADR-0003). The production PUT path schedules via the fresh-write
    /// drainer; this direct entry point schedules here so callers (and tests)
    /// that drive replication directly still get the possession check.
    pub async fn replicate_fresh(&self, key: &XorName, data: &[u8], proof_of_payment: &[u8]) {
        let peers = fresh::replicate_fresh(
            key,
            data,
            proof_of_payment,
            &self.p2p_node,
            &self.paid_list,
            &self.config,
            &self.send_semaphore,
        )
        .await;
        if !peers.is_empty() {
            let _ = self
                .possession_check_tx
                .send(possession::PossessionCheckEvent { key: *key, peers });
        }
    }

    // =======================================================================
    // Background task launchers
    // =======================================================================

    /// Spawn a task that drains the fresh-write channel and triggers
    /// replication for each newly-stored chunk.
    fn start_fresh_write_drainer(&mut self) {
        let Some(mut rx) = self.fresh_write_rx.take() else {
            return;
        };
        let p2p = Arc::clone(&self.p2p_node);
        let paid_list = Arc::clone(&self.paid_list);
        let config = Arc::clone(&self.config);
        let send_semaphore = Arc::clone(&self.send_semaphore);
        let possession_tx = self.possession_check_tx.clone();
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        let peers = fresh::replicate_fresh(
                            &event.key,
                            &event.data,
                            &event.payment_proof,
                            &p2p,
                            &paid_list,
                            &config,
                            &send_semaphore,
                        )
                        .await;
                        // Schedule the delayed possession check (ADR-0003) for
                        // the responsible close-group peers. A closed receiver
                        // (engine shutting down) is ignored.
                        if !peers.is_empty() {
                            let _ = possession_tx.send(possession::PossessionCheckEvent {
                                key: event.key,
                                peers,
                            });
                        }
                    }
                }
            }
            debug!("Fresh-write drainer shut down");
        });
        self.task_handles.push(handle);
    }

    /// Spawn the possession-check scheduler (ADR-0003).
    ///
    /// Drains scheduled possession-check events and, for each, waits a
    /// randomised 5-15 minute settle delay before probing every responsible
    /// peer for actual possession. A peer that cryptographically fails to prove
    /// possession, including by timeout, is penalised at `AuditChallenge`
    /// severity.
    fn start_possession_check_scheduler(&mut self) {
        let Some(mut rx) = self.possession_check_rx.take() else {
            return;
        };
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let sync_state = Arc::clone(&self.sync_state);
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        // Spawn a per-chunk delayed check so the drain loop
                        // keeps pace with the write rate. Each check sleeps the
                        // randomised settle delay, then probes every peer.
                        let p2p = Arc::clone(&p2p);
                        let storage = Arc::clone(&storage);
                        let config = Arc::clone(&config);
                        let sync_state = Arc::clone(&sync_state);
                        let shutdown = shutdown.clone();
                        let delay_min = config.possession_check_delay_min;
                        let delay_max = config.possession_check_delay_max;
                        tokio::spawn(async move {
                            let delay = possession::random_delay(delay_min, delay_max);
                            tokio::select! {
                                () = shutdown.cancelled() => {}
                                () = tokio::time::sleep(delay) => {
                                    possession::run_possession_check(
                                        event.key,
                                        event.peers,
                                        &p2p,
                                        &storage,
                                        &config,
                                        &sync_state,
                                        &shutdown,
                                    )
                                    .await;
                                }
                            }
                        });
                    }
                }
            }
            debug!("Possession-check scheduler shut down");
        });
        self.task_handles.push(handle);
    }

    #[allow(clippy::too_many_lines)]
    fn start_message_handler(&mut self) {
        let mut p2p_events = self.p2p_node.subscribe_events();
        let mut dht_events = self.p2p_node.dht_manager().subscribe_events();
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let payment_verifier = Arc::clone(&self.payment_verifier);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let my_commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let recent_provers = Arc::clone(&self.recent_provers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);
        let audit_on_gossip_cooldown = Arc::clone(&self.audit_on_gossip_cooldown);
        let sync_state = Arc::clone(&self.sync_state);
        let audit_responder_semaphore = Arc::clone(&self.audit_responder_semaphore);
        let audit_responder_inflight = Arc::clone(&self.audit_responder_inflight);

        // ADR-0002 gossip-audit trigger: bundled state so an ingested *changed*
        // commitment can spawn a probabilistic, cooldown-gated subtree audit.
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&p2p),
            config: Arc::clone(&config),
            recent_provers: Arc::clone(&recent_provers),
            sync_state: Arc::clone(&sync_state),
            cooldown: Arc::clone(&audit_on_gossip_cooldown),
        };

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = p2p_events.recv() => {
                        let Ok(event) = event else { continue };
                        if let P2PEvent::Message {
                            topic,
                            source: Some(source),
                            data,
                            ..
                        } = event {
                            // Determine if this is a replication message
                            // and whether it arrived via the /rr/ request-response
                            // path (which wraps payloads in RequestResponseEnvelope).
                            let rr_info = if topic == REPLICATION_PROTOCOL_ID {
                                Some((data.clone(), None))
                            } else if topic.starts_with(RR_PREFIX)
                                && &topic[RR_PREFIX.len()..] == REPLICATION_PROTOCOL_ID
                            {
                                P2PNode::parse_request_envelope(&data)
                                    .filter(|(_, is_resp, _)| !is_resp)
                                    .map(|(msg_id, _, payload)| (payload, Some(msg_id)))
                            } else {
                                None
                            };
                            if let Some((payload, rr_message_id)) = rr_info {
                                match handle_replication_message(
                                    &source,
                                    &payload,
                                    &p2p,
                                    &storage,
                                    &paid_list,
                                    &payment_verifier,
                                    &queues,
                                    &config,
                                    &is_bootstrapping,
                                    &bootstrap_state,
                                    &sync_history,
                                    &sync_cycle_epoch,
                                    &repair_proofs,
                                    &last_commitment_by_peer,
                                    &ever_capable_peers,
                                    &sig_verify_attempts,
                                    &my_commitment_state,
                                    &gossip_audit,
                                    &audit_responder_semaphore,
                                    &audit_responder_inflight,
                                    rr_message_id.as_deref(),
                                ).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        debug!(
                                            "Replication message from {source} error: {e}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Gap 4: Topology churn handling (Section 13).
                    //
                    // The DHT routing table emits KClosestPeersChanged when the
                    // K-closest peer set actually changes, which is the precise
                    // signal for triggering neighbor sync. This replaces the
                    // previous approach of checking every PeerConnected /
                    // PeerDisconnected event against the close group.
                    dht_event = dht_events.recv() => {
                        let dht_event = match dht_event {
                            Ok(event) => event,
                            Err(RecvError::Lagged(missed)) => {
                                // Under heavy churn the broadcast buffer can overflow
                                // and drop routing-table events — the moment
                                // convergence matters most. A dropped
                                // KClosestPeersChanged means its entrants were never
                                // queued, so draining priority_order cannot recover
                                // them. Resync from ground truth instead: snapshot the
                                // current close-peer set and queue every member. Dedup
                                // (queue_priority_peers) and per-peer cooldown
                                // (select_next_sync_peer) drop peers already queued or
                                // recently synced, so only genuine entrants surface.
                                warn!(
                                    "Missed {missed} DHT routing events (broadcast lag); resynchronizing close-peer set for neighbor sync"
                                );
                                let self_id = *p2p.peer_id();
                                let neighbors = neighbor_sync::snapshot_close_neighbors(
                                    &p2p,
                                    &self_id,
                                    config.neighbor_sync_scope,
                                )
                                .await;
                                let requeued = {
                                    let mut state = sync_state.write().await;
                                    state.queue_priority_peers(neighbors)
                                };
                                if requeued > 0 {
                                    debug!(
                                        "Resync after broadcast lag queued {requeued} close peers for priority neighbor sync"
                                    );
                                    sync_trigger.notify_one();
                                }
                                continue;
                            }
                            Err(RecvError::Closed) => continue,
                        };
                        match dht_event {
                            DhtNetworkEvent::KClosestPeersChanged { old, new } => {
                                let old_peers = old
                                    .iter()
                                    .take(config.neighbor_sync_scope)
                                    .copied()
                                    .collect::<HashSet<_>>();
                                let new_scoped = new
                                    .iter()
                                    .take(config.neighbor_sync_scope)
                                    .copied()
                                    .collect::<Vec<_>>();
                                let new_peers =
                                    new_scoped.iter().copied().collect::<HashSet<_>>();
                                let entrants = new_scoped
                                    .iter()
                                    .copied()
                                    .filter(|peer| !old_peers.contains(peer))
                                    .collect::<Vec<_>>();
                                let entrant_count = entrants.len();
                                let (priority_insertions, sync_removals) = {
                                    let mut state = sync_state.write().await;
                                    let sync_removals = state.retain_sync_peers(&new_peers);
                                    let priority_insertions = state.queue_priority_peers(entrants);
                                    (priority_insertions, sync_removals)
                                };
                                if priority_insertions > 0 {
                                    debug!(
                                        "K-closest peers changed, queued {priority_insertions}/{entrant_count} new close peers for priority neighbor sync and pruned {sync_removals} departed pending sync entries"
                                    );
                                } else {
                                    debug!(
                                        "K-closest peers changed, no additional close peers queued, pruned {sync_removals} departed pending sync entries, triggering early neighbor sync"
                                    );
                                }
                                sync_trigger.notify_one();
                            }
                            DhtNetworkEvent::PeerRemoved { peer_id } => {
                                sync_state.write().await.remove_peer(&peer_id);
                                repair_proofs.write().await.remove_peer(&peer_id);
                                // v12: drop the commitment bytes and the
                                // recent-prover credit so a churn / sybil
                                // attacker cannot leave behind one
                                // StorageCommitment per identity in
                                // `last_commitment_by_peer`. Also drop the
                                // sig-verify rate-limit timestamp.
                                last_commitment_by_peer.write().await.remove(&peer_id);
                                recent_provers.write().await.forget_peer(&peer_id);
                                sig_verify_attempts.write().await.remove(&peer_id);
                                // Same for the gossip-audit cooldown (ADR-0002).
                                audit_on_gossip_cooldown.write().await.remove(&peer_id);
                                // The sticky `commitment_capable` flag is
                                // preserved orthogonally via
                                // `ever_capable_peers` — even after this
                                // removal, a re-joining peer continues to
                                // be treated as v12-capable rather than
                                // legacy (§3 shield).
                            }
                            _ => {}
                        }
                    }
                }
            }
            debug!("Replication message handler shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_neighbor_sync_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let sync_state = Arc::clone(&self.sync_state);
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);
        // ADR-0002: a peer's commitment also arrives on the sync RESPONSE path
        // (we initiated, they piggybacked theirs). Carry a gossip-audit trigger
        // here too so a peer that only ever answers — never initiates sync —
        // is still audited; otherwise it could fully evade auditing.
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&p2p),
            config: Arc::clone(&config),
            recent_provers: Arc::clone(&self.recent_provers),
            sync_state: Arc::clone(&sync_state),
            cooldown: Arc::clone(&self.audit_on_gossip_cooldown),
        };

        let handle = tokio::spawn(async move {
            loop {
                // Park for the periodic tick or an explicit trigger ONLY when no
                // priority (topology-change) peers are queued. `sync_trigger` is a
                // coalescing `Notify`, so a churn burst that queues many entrants
                // produces a single wakeup; parking after draining one batch would
                // leave the rest waiting up to a full periodic tick. `priority_order`
                // is the durable record of pending work, so drain it back-to-back —
                // each round removes the peers it selects (`select_next_sync_peer`),
                // so the drain terminates once the queue empties.
                if !sync_state.read().await.has_priority_peers() {
                    let interval = config.random_neighbor_sync_interval();
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(interval) => {}
                        () = sync_trigger.notified() => {
                            debug!("Neighbor sync triggered by topology change");
                        }
                    }
                }
                // Wrap the sync round in a select so shutdown cancels
                // in-progress network operations rather than waiting for
                // the full round to complete.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = run_neighbor_sync_round(
                        &p2p,
                        &storage,
                        &paid_list,
                        &queues,
                        &config,
                        &sync_state,
                        &sync_history,
                        &sync_cycle_epoch,
                        &repair_proofs,
                        &is_bootstrapping,
                        &bootstrap_state,
                        &commitment_state,
                        &last_commitment_by_peer,
                        &ever_capable_peers,
                        &sig_verify_attempts,
                        &gossip_audit,
                    ) => {}
                }
            }
            debug!("Neighbor sync loop shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_self_lookup_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                let interval = config.random_self_lookup_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        if let Err(e) = p2p.dht_manager().trigger_self_lookup().await {
                            debug!("Self-lookup failed: {e}");
                        }
                    }
                }
            }
            debug!("Self-lookup loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodic responsible-chunk audit loop (audit #2): every
    /// [`ReplicationConfig::random_audit_tick_interval`] (~10-20 min), audit one
    /// eligible close peer for the chunks it *should* be storing (by
    /// responsibility and prior repair hint), independent of the gossip-triggered
    /// storage-commitment audit. Waits for bootstrap to drain, then runs one tick
    /// immediately and periodically thereafter.
    fn start_audit_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let sync_state = Arc::clone(&self.sync_state);

        let handle = tokio::spawn(async move {
            // Invariant 19: wait for bootstrap to drain before starting audits.
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(
                        std::time::Duration::from_secs(BOOTSTRAP_DRAIN_CHECK_SECS)
                    ) => {
                        if bootstrap_state.read().await.is_drained() {
                            break;
                        }
                    }
                }
            }

            // Run one audit tick immediately after bootstrap drain.
            {
                let bootstrapping = *is_bootstrapping.read().await;
                let result = {
                    let history = sync_history.read().await;
                    let current_sync_epoch = *sync_cycle_epoch.read().await;
                    audit::audit_tick_with_repair_proofs(
                        &p2p,
                        &storage,
                        &config,
                        &history,
                        &repair_proofs,
                        current_sync_epoch,
                        bootstrapping,
                    )
                    .await
                };
                handle_audit_result(&result, &p2p, &sync_state, &config).await;
            }

            // Then run periodically.
            loop {
                let interval = config.random_audit_tick_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        let bootstrapping = *is_bootstrapping.read().await;
                        let result = {
                            let history = sync_history.read().await;
                            let current_sync_epoch = *sync_cycle_epoch.read().await;
                            audit::audit_tick_with_repair_proofs(
                                &p2p,
                                &storage,
                                &config,
                                &history,
                                &repair_proofs,
                                current_sync_epoch,
                                bootstrapping,
                            )
                            .await
                        };
                        handle_audit_result(&result, &p2p, &sync_state, &config).await;
                    }
                }
            }
            debug!("Audit loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically rebuild + sign + rotate the responder's storage
    /// commitment.
    ///
    /// Phase 3 of the v12 storage-bound audit. Once per
    /// [`COMMITMENT_ROTATION_INTERVAL_SECS`], the responder reads the
    /// current LMDB key set, builds a Merkle tree (for content-addressed
    /// chunks `bytes_hash == key`, so no chunk re-read is needed), signs
    /// the root with the node's `MlDsaSecretKey`, and rotates the result
    /// into `commitment_state`. Old `previous` slot is dropped by the
    /// rotate (per `ResponderCommitmentState::rotate`).
    ///
    /// Skips if the key set is empty (no commitment to make) — the
    /// auditor side falls back to the legacy plain-digest path for
    /// peers that have never gossiped a commitment.
    fn start_commitment_rotation_loop(&mut self) {
        let storage = Arc::clone(&self.storage);
        let identity = Arc::clone(&self.identity);
        let commitment_state = Arc::clone(&self.commitment_state);
        let shutdown = self.shutdown.clone();
        let p2p = Arc::clone(&self.p2p_node);
        let config = Arc::clone(&self.config);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let recent_provers = Arc::clone(&self.recent_provers);

        let handle = tokio::spawn(async move {
            // Build the first commitment immediately on startup so a
            // restarted node can answer commitment-bound audits right
            // away — otherwise current() stays None for a full rotation
            // interval and audits silently fall back to legacy.
            //
            // After the first build, trigger an immediate neighbor-sync
            // round so the new commitment gossips out within seconds.
            // Without this, after a restart remote auditors keep pinning
            // the pre-restart (rotated-away) hash until their normal
            // sync cadence elapses — up to 1 h in the worst case,
            // during which time commitment-bound audits hit "unknown
            // commitment hash" -> Idle no-ops.
            // ML-DSA signatures are randomized so we cannot reproduce
            // the pre-restart hash; the only honest path to recovery
            // is fast re-gossip.
            if let Err(e) =
                rebuild_and_rotate_commitment(&storage, &identity, &commitment_state, &p2p, &config)
                    .await
            {
                warn!("Initial commitment build failed: {e}");
            } else {
                sync_trigger.notify_one();
            }
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(
                        std::time::Duration::from_secs(COMMITMENT_ROTATION_INTERVAL_SECS)
                    ) => {
                        if let Err(e) = rebuild_and_rotate_commitment(
                            &storage,
                            &identity,
                            &commitment_state,
                            &p2p,
                            &config,
                        ).await {
                            warn!("Commitment rotation failed: {e}");
                        }
                        // Piggyback a sweep of expired recent_provers
                        // entries on the rotation tick (same cadence,
                        // 1 h). is_credited_holder already honours the
                        // TTL on read, but the sweep reclaims memory
                        // for entries we'll never re-read.
                        let dropped = recent_provers.write().await.sweep_expired(
                            std::time::Instant::now()
                        );
                        if dropped > 0 {
                            debug!("recent_provers: swept {dropped} expired entries");
                        }
                    }
                }
            }
            debug!("Commitment rotation loop shut down");
        });
        self.task_handles.push(handle);
    }

    #[allow(clippy::too_many_lines, clippy::option_if_let_else)]
    fn start_fetch_worker(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let concurrency = max_parallel_fetch();

        info!("Fetch worker concurrency set to {concurrency} (hardware threads)");

        let handle = tokio::spawn(async move {
            // Each in-flight future yields (key, Option<FetchOutcome>) so we
            // always recover the key — even if the inner task panics.
            let mut in_flight = FuturesUnordered::<FetchFuture>::new();

            loop {
                // Fill up to `concurrency` slots from the queue.
                {
                    let mut q = queues.write().await;
                    while in_flight.len() < concurrency {
                        let Some(candidate) = q.dequeue_fetch() else {
                            break;
                        };
                        let Some(&source) = candidate.sources.first() else {
                            warn!(
                                "Fetch candidate {} has no sources — dropping",
                                hex::encode(candidate.key)
                            );
                            continue;
                        };
                        q.start_fetch_with_retry(
                            candidate.key,
                            source,
                            candidate.sources.clone(),
                            candidate.retry_verification,
                        );

                        let p2p = Arc::clone(&p2p);
                        let storage = Arc::clone(&storage);
                        let config = Arc::clone(&config);
                        let token = shutdown.clone();
                        let fetch_key = candidate.key;
                        in_flight.push(Box::pin(async move {
                            let handle = tokio::spawn(async move {
                                // Cancel-aware: abort when the engine shuts down.
                                tokio::select! {
                                    () = token.cancelled() => FetchOutcome {
                                        key: fetch_key,
                                        result: FetchResult::SourceFailed,
                                    },
                                    outcome = execute_single_fetch(
                                        p2p, storage, config, fetch_key, source,
                                    ) => outcome,
                                }
                            });
                            match handle.await {
                                Ok(outcome) => (outcome.key, Some(outcome)),
                                Err(e) => {
                                    error!(
                                        "Fetch task for {} panicked: {e}",
                                        hex::encode(fetch_key)
                                    );
                                    (fetch_key, None)
                                }
                            }
                        }));
                    }
                } // release queues write lock

                if in_flight.is_empty() {
                    // No work — wait for new items or shutdown.
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(
                            std::time::Duration::from_millis(FETCH_WORKER_POLL_MS)
                        ) => continue,
                    }
                }

                // Wait for the next fetch to complete and process the result.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    Some((key, maybe_outcome)) = in_flight.next() => {
                        let mut q = queues.write().await;
                        let terminal = if let Some(outcome) = maybe_outcome {
                            match outcome.result {
                                FetchResult::Stored => {
                                    q.complete_fetch(&key);
                                    true
                                }
                                FetchResult::IntegrityFailed | FetchResult::SourceFailed => {
                                    if let Some(next_peer) = q.retry_fetch(&key) {
                                        // Spawn a new fetch task for the next source.
                                        let p2p = Arc::clone(&p2p);
                                        let storage = Arc::clone(&storage);
                                        let config = Arc::clone(&config);
                                        let token = shutdown.clone();
                                        let fetch_key = key;
                                        in_flight.push(Box::pin(async move {
                                            let handle = tokio::spawn(async move {
                                                tokio::select! {
                                                    () = token.cancelled() => FetchOutcome {
                                                        key: fetch_key,
                                                        result: FetchResult::SourceFailed,
                                                    },
                                                    outcome = execute_single_fetch(
                                                        p2p, storage, config, fetch_key, next_peer,
                                                    ) => outcome,
                                                }
                                            });
                                            match handle.await {
                                                Ok(outcome) => (outcome.key, Some(outcome)),
                                                Err(e) => {
                                                    error!(
                                                        "Fetch task for {} panicked: {e}",
                                                        hex::encode(fetch_key)
                                                    );
                                                    (fetch_key, None)
                                                }
                                            }
                                        }));
                                        false
                                    } else {
                                        !q.requeue_fetch_for_verification(
                                            &key,
                                            config.verification_request_timeout,
                                        )
                                    }
                                }
                            }
                        } else {
                            // Task panicked — retry verification when this was
                            // a verified repair, otherwise reclaim the slot.
                            !q.requeue_fetch_for_verification(
                                &key,
                                config.verification_request_timeout,
                            )
                        };

                        // Shrink bootstrap pending set on terminal exit.
                        if terminal {
                            drop(q); // release queues lock before acquiring bootstrap_state
                            if !bootstrap_state.read().await.is_drained() {
                                bootstrap_state.write().await.remove_key(&key);
                                let q = queues.read().await;
                                if bootstrap::check_bootstrap_drained(
                                    &bootstrap_state,
                                    &q,
                                )
                                .await
                                {
                                    complete_bootstrap(
                                        &is_bootstrapping,
                                        &bootstrap_complete_notify,
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }

            // Cancel and drain remaining in-flight fetches on shutdown.
            // The CancellationToken is already cancelled by this point, so
            // spawned tasks will see cancellation via their select! branches.
            while in_flight.next().await.is_some() {}
            debug!("Fetch worker shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_verification_worker(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let queues = Arc::clone(&self.queues);
        let paid_list = Arc::clone(&self.paid_list);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let recent_provers = Arc::clone(&self.recent_provers);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(
                        std::time::Duration::from_millis(VERIFICATION_WORKER_POLL_MS)
                    ) => {
                        let ctx = VerificationCycleContext {
                            p2p_node: &p2p,
                            paid_list: &paid_list,
                            storage: &storage,
                            queues: &queues,
                            config: &config,
                            bootstrap_state: &bootstrap_state,
                            is_bootstrapping: &is_bootstrapping,
                            bootstrap_complete_notify: &bootstrap_complete_notify,
                            last_commitment_by_peer: &last_commitment_by_peer,
                            ever_capable_peers: &ever_capable_peers,
                            recent_provers: &recent_provers,
                        };
                        run_verification_cycle(ctx).await;
                    }
                }
            }
            debug!("Verification worker shut down");
        });
        self.task_handles.push(handle);
    }

    /// Gap 3: Run a one-shot bootstrap sync on startup.
    ///
    /// Waits for saorsa-core to emit `DhtNetworkEvent::BootstrapComplete`
    /// (indicating the routing table is populated) before snapshotting
    /// close neighbors. Falls back after a timeout so bootstrap nodes
    /// (which have no peers and therefore never receive the event) still
    /// proceed.
    ///
    /// After the gate, finds close neighbors, syncs with each in
    /// round-robin batches, admits returned hints into the verification
    /// pipeline, and tracks discovered keys for bootstrap drain detection.
    #[allow(clippy::too_many_lines)]
    fn start_bootstrap_sync(
        &mut self,
        dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>,
    ) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let my_commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);

        let handle = tokio::spawn(async move {
            // Wait for DHT bootstrap to complete before snapshotting
            // neighbors. The routing table is empty until saorsa-core
            // finishes its FIND_NODE rounds and bucket refreshes.
            let gate = bootstrap::wait_for_bootstrap_complete(
                dht_events,
                config.bootstrap_complete_timeout_secs,
                &shutdown,
            )
            .await;

            if gate == bootstrap::BootstrapGateResult::Shutdown {
                return;
            }

            let self_id = *p2p.peer_id();
            let neighbors =
                neighbor_sync::snapshot_close_neighbors(&p2p, &self_id, config.neighbor_sync_scope)
                    .await;

            if neighbors.is_empty() {
                info!("Bootstrap sync: no close neighbors found, marking drained");
                bootstrap::mark_bootstrap_drained(&bootstrap_state).await;
                complete_bootstrap(&is_bootstrapping, &bootstrap_complete_notify).await;
                return;
            }

            let neighbor_count = neighbors.len();
            info!("Bootstrap sync: syncing with {neighbor_count} close neighbors");

            // Process neighbors in batches of NEIGHBOR_SYNC_PEER_COUNT.
            for batch in neighbors.chunks(config.neighbor_sync_peer_count) {
                if shutdown.is_cancelled() {
                    break;
                }

                let mut hints_by_peer = neighbor_sync::build_sync_hints_for_peers(
                    batch,
                    &storage,
                    &paid_list,
                    &p2p,
                    config.close_group_size,
                    config.paid_list_close_group_size,
                )
                .await;

                for peer in batch {
                    if shutdown.is_cancelled() {
                        break;
                    }

                    // Re-read on each iteration so peers see current state.
                    let bootstrapping = *is_bootstrapping.read().await;

                    bootstrap::increment_pending_requests(&bootstrap_state, 1).await;

                    let hints = hints_by_peer.remove(peer).unwrap_or_default();
                    let outcome = neighbor_sync::sync_with_peer_with_hints(
                        peer,
                        &p2p,
                        &config,
                        bootstrapping,
                        hints,
                        // Atomically snapshot + mark-gossiped: emitted in the
                        // bootstrap-sync request, so we stay answerable for it
                        // (ADR-0002). One critical section avoids a TOCTOU where a
                        // concurrent retire/rotate drops the slot between read and
                        // mark.
                        my_commitment_state
                            .current_for_gossip()
                            .map(|b| b.commitment().clone()),
                    )
                    .await;

                    bootstrap::decrement_pending_requests(&bootstrap_state, 1).await;

                    if let Some(outcome) = outcome {
                        // Ingest the peer's piggybacked commitment from the
                        // response (same verification as the request path).
                        // Bootstrap is the FIRST gossip we receive from most
                        // peers, so this populates last_commitment_by_peer.
                        //
                        // We intentionally do NOT trigger a gossip-audit here:
                        // during bootstrap this node may itself still be
                        // bootstrapping (audits are gated on that), and the
                        // close-group/RT view is not yet stable. The peer is
                        // audited on the first STEADY-STATE neighbor-sync round
                        // after bootstrap drains (request + response paths both
                        // trigger), which is within one sync cycle — so caching
                        // the commitment here is sufficient and there is no
                        // coverage gap (ADR-0002).
                        ingest_peer_commitment(
                            peer,
                            outcome.response.commitment.as_ref(),
                            &p2p,
                            &last_commitment_by_peer,
                            &ever_capable_peers,
                            &sig_verify_attempts,
                        )
                        .await; // sig_verify_attempts in scope from line ~1080

                        if !outcome.response.bootstrapping {
                            record_sent_replica_hints(
                                peer,
                                &outcome.sent_replica_hints,
                                &repair_proofs,
                                &sync_cycle_epoch,
                            )
                            .await;
                            // Admit hints into verification pipeline.
                            let outcome = admit_and_queue_hints(
                                &self_id,
                                peer,
                                &outcome.response.replica_hints,
                                &outcome.response.paid_hints,
                                &p2p,
                                &config,
                                &storage,
                                &paid_list,
                                &queues,
                            )
                            .await;

                            // Track discovered keys for drain detection.
                            if !outcome.discovered.is_empty() {
                                bootstrap::track_discovered_keys(
                                    &bootstrap_state,
                                    &outcome.discovered,
                                )
                                .await;
                            }

                            // Record / retire capacity rejections so the
                            // drain check correctly reflects whether each
                            // source still owes us re-hinted work after
                            // queue overflow.
                            if outcome.capacity_rejected_count > 0 {
                                bootstrap::note_capacity_rejected(&bootstrap_state, *peer).await;
                            } else {
                                bootstrap::clear_capacity_rejected(&bootstrap_state, peer).await;
                            }
                        }
                    }
                }
            }

            // Check drain condition.
            {
                let q = queues.read().await;
                if bootstrap::check_bootstrap_drained(&bootstrap_state, &q).await {
                    complete_bootstrap(&is_bootstrapping, &bootstrap_complete_notify).await;
                }
            }

            info!("Bootstrap sync completed");
        });
        self.task_handles.push(handle);
    }
}

// ===========================================================================
// Free functions for background tasks
// ===========================================================================

/// RAII admission for one audit-responder task: holds the GLOBAL permit and,
/// on drop, decrements the PER-PEER in-flight count. Moving this into the
/// spawned task ties both bounds to the task's exact lifetime — no manual
/// decrement to forget on an early return or panic.
struct AuditResponderGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    peer: PeerId,
}

impl Drop for AuditResponderGuard {
    fn drop(&mut self) {
        // Decrement (and prune to keep the map bounded) without blocking the
        // async runtime: a short lock on a tiny map.
        //
        // Fast path: if the (uncontended, tiny) lock is free, decrement inline
        // with no spawn. Otherwise defer to a task — but only if a runtime is
        // actually current, so `Drop` during shutdown (no runtime) can never
        // panic. A missed decrement at shutdown is harmless: the whole map is
        // being dropped with the engine.
        let peer = self.peer;
        if let Ok(mut map) = self.inflight.try_write() {
            if let Some(n) = map.get_mut(&peer) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&peer);
                }
            }
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inflight = Arc::clone(&self.inflight);
            handle.spawn(async move {
                let mut map = inflight.write().await;
                if let Some(n) = map.get_mut(&peer) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        map.remove(&peer);
                    }
                }
            });
        }
    }
}

/// Try to admit one audit-responder task for `source`: take a global permit AND
/// a per-peer slot (both bounded). Returns `None` (caller drops the challenge,
/// leaving the remote auditor to apply that audit path's timeout policy) if
/// either ceiling is hit, so one flooder can neither exhaust the global pool's
/// effect on others nor exceed its own per-peer share (codex-r2 A).
async fn admit_audit_responder(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    source: &PeerId,
) -> Option<AuditResponderGuard> {
    // Per-peer cap first (cheap, and the fairness-critical bound), committed
    // under the write lock so concurrent challenges from the same peer can't
    // both slip past the cap.
    {
        let mut map = inflight.write().await;
        let entry = map.entry(*source).or_insert(0);
        if *entry >= MAX_AUDIT_RESPONSES_PER_PEER {
            return None;
        }
        *entry += 1;
    }
    // Then the global ceiling. If it's exhausted, give back the per-peer slot we
    // just claimed so it isn't leaked.
    let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() else {
        let mut map = inflight.write().await;
        if let Some(n) = map.get_mut(source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(source);
            }
        }
        return None;
    };
    Some(AuditResponderGuard {
        _permit: permit,
        inflight: Arc::clone(inflight),
        peer: *source,
    })
}

/// Handle an incoming replication protocol message.
///
/// When `rr_message_id` is `Some`, the request arrived via the `/rr/`
/// request-response path and the response must be sent via `send_response`
/// so saorsa-core can route it back to the waiting `send_request` caller.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_replication_message(
    source: &PeerId,
    data: &[u8],
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    my_commitment_state: &Arc<ResponderCommitmentState>,
    gossip_audit: &GossipAuditTrigger,
    audit_responder_semaphore: &Arc<Semaphore>,
    audit_responder_inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let msg = ReplicationMessage::decode(data)
        .map_err(|e| Error::Protocol(format!("Failed to decode replication message: {e}")))?;

    match msg.body {
        ReplicationMessageBody::FreshReplicationOffer(ref offer) => {
            handle_fresh_offer(
                source,
                offer,
                storage,
                paid_list,
                payment_verifier,
                p2p_node,
                config,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::PaidNotify(ref notify) => {
            handle_paid_notify(
                source,
                notify,
                paid_list,
                payment_verifier,
                p2p_node,
                config,
            )
            .await
        }
        ReplicationMessageBody::NeighborSyncRequest(ref request) => {
            let bootstrapping = *is_bootstrapping.read().await;
            // Phase-3 storage-bound audit: store the sender's
            // commitment for use as `expected_commitment_hash` in
            // future audits. Verify signature before storing so a peer
            // cannot inject a forged commitment for someone else.
            if let Some(target) = ingest_peer_commitment(
                source,
                request.commitment.as_ref(),
                p2p_node,
                last_commitment_by_peer,
                ever_capable_peers,
                sig_verify_attempts,
            )
            .await
            {
                maybe_trigger_gossip_audit(gossip_audit, source, target).await;
            }
            handle_neighbor_sync_request(
                source,
                request,
                p2p_node,
                storage,
                paid_list,
                queues,
                config,
                bootstrapping,
                bootstrap_state,
                sync_history,
                sync_cycle_epoch,
                repair_proofs,
                // Atomically snapshot + mark-gossiped: emitted in the sync
                // response, so we must stay answerable for it (ADR-0002).
                my_commitment_state
                    .current_for_gossip()
                    .map(|b| b.commitment().clone()),
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::VerificationRequest(ref request) => {
            handle_verification_request(
                source,
                request,
                storage,
                paid_list,
                p2p_node,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::FetchRequest(ref request) => {
            handle_fetch_request(
                source,
                request,
                storage,
                p2p_node,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::AuditChallenge(challenge) => {
            // Responsible-chunk audit (audit #2) responder: answer with per-key
            // possession digests. This same handler also answers the
            // prune-confirmation audit, which sends the same `AuditChallenge`
            // wire message.
            //
            // Answering digests the stored bytes of every challenged key, so —
            // like the subtree/byte audits below — run it on a detached task off
            // this serial message loop. Handling it inline lets one challenge
            // block all other replication traffic until its digests complete
            // (head-of-line blocking). The same flood-fair admission applies: a
            // global ceiling AND a per-peer cap, dropping the challenge if either
            // is hit. Responsible/prune audit timeouts are penalised by the
            // caller, so the caps must remain high enough for honest audit load;
            // the per-peer share still prevents one flooder from starving others.
            let Some(guard) =
                admit_audit_responder(audit_responder_semaphore, audit_responder_inflight, source)
                    .await
            else {
                warn!(
                    "Audit challenge reply not sent: kind=responsible response=dropped \
                     source={source} (audit-responder capacity reached)"
                );
                return Ok(());
            };
            let bootstrapping = *is_bootstrapping.read().await;
            let storage = Arc::clone(storage);
            let p2p_node = Arc::clone(p2p_node);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            tokio::spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                if let Err(e) = handle_audit_challenge_msg(
                    &source,
                    &challenge,
                    &storage,
                    &p2p_node,
                    bootstrapping,
                    request_id,
                    rr_message_id.as_deref(),
                )
                .await
                {
                    debug!("Audit challenge from {source} error: {e}");
                }
            });
            Ok(())
        }
        ReplicationMessageBody::SubtreeAuditChallenge(challenge) => {
            // Gossip-triggered storage-bound subtree audit (ADR-0002). The
            // responder rebuilds the WHOLE nonce-selected subtree, reading every
            // leaf's bytes from disk (`get_raw` × ~sqrt(N) leaves). Run it on a
            // detached task so this serial message loop is never blocked on disk
            // I/O — otherwise one audit stalls all replication traffic (§5).
            //
            // A bounded, flood-fair admission restores backpressure (codex#1 +
            // codex-r2 A): a global ceiling AND a per-peer cap. If either is hit
            // we drop this challenge. Subtree auditors grace timeout
            // non-responses, so capacity drops throttle flooders without turning
            // into trust penalties (and one source cannot starve other peers,
            // since its share is capped per-peer).
            info!(
                "Audit challenge received: kind=subtree source={source} request_response={}",
                rr_message_id.is_some(),
            );
            let Some(guard) =
                admit_audit_responder(audit_responder_semaphore, audit_responder_inflight, source)
                    .await
            else {
                warn!(
                    "Audit challenge reply not sent: kind=subtree response=dropped \
                     source={source} (audit-responder capacity reached)"
                );
                return Ok(());
            };
            let bootstrapping = *is_bootstrapping.read().await;
            let storage = Arc::clone(storage);
            let p2p_node = Arc::clone(p2p_node);
            let my_commitment_state = Arc::clone(my_commitment_state);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            tokio::spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                let response = storage_commitment_audit::handle_subtree_challenge(
                    &challenge,
                    &storage,
                    p2p_node.peer_id(),
                    bootstrapping,
                    Some(&my_commitment_state),
                )
                .await;
                let response_kind = subtree_audit_response_kind(&response);
                let sent = send_replication_response_checked(
                    &source,
                    &p2p_node,
                    request_id,
                    ReplicationMessageBody::SubtreeAuditResponse(response),
                    rr_message_id.as_deref(),
                )
                .await;
                if sent {
                    info!(
                        "Audit challenge reply sent: kind=subtree response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                } else {
                    warn!(
                        "Audit challenge reply not sent: kind=subtree response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                }
            });
            Ok(())
        }
        ReplicationMessageBody::SubtreeByteChallenge(challenge) => {
            // Round 2 of the storage audit (ADR-0002): serve the original bytes
            // for the auditor's spot-check keys, or signal `Absent` for a
            // committed key we can no longer produce. Reads chunk bytes from
            // disk, so likewise spawned off the serial loop (§5) under the same
            // flood-fair admission (codex#1 + codex-r2 A).
            info!(
                "Audit challenge received: kind=byte source={source} request_response={}",
                rr_message_id.is_some(),
            );
            let Some(guard) =
                admit_audit_responder(audit_responder_semaphore, audit_responder_inflight, source)
                    .await
            else {
                warn!(
                    "Audit challenge reply not sent: kind=byte response=dropped \
                     source={source} (audit-responder capacity reached)"
                );
                return Ok(());
            };
            let bootstrapping = *is_bootstrapping.read().await;
            let storage = Arc::clone(storage);
            let p2p_node = Arc::clone(p2p_node);
            let my_commitment_state = Arc::clone(my_commitment_state);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            tokio::spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                let response = storage_commitment_audit::handle_subtree_byte_challenge(
                    &challenge,
                    &storage,
                    p2p_node.peer_id(),
                    bootstrapping,
                    Some(&my_commitment_state),
                )
                .await;
                let response_kind = subtree_byte_response_kind(&response);
                let sent = send_replication_response_checked(
                    &source,
                    &p2p_node,
                    request_id,
                    ReplicationMessageBody::SubtreeByteResponse(response),
                    rr_message_id.as_deref(),
                )
                .await;
                if sent {
                    info!(
                        "Audit challenge reply sent: kind=byte response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                } else {
                    warn!(
                        "Audit challenge reply not sent: kind=byte response={response_kind} \
                         source={source} request_response={}",
                        rr_message_id.is_some(),
                    );
                }
            });
            Ok(())
        }
        // Response messages are handled by their respective request initiators.
        ReplicationMessageBody::FreshReplicationResponse(_)
        | ReplicationMessageBody::NeighborSyncResponse(_)
        | ReplicationMessageBody::VerificationResponse(_)
        | ReplicationMessageBody::FetchResponse(_)
        | ReplicationMessageBody::AuditResponse(_)
        | ReplicationMessageBody::SubtreeAuditResponse(_)
        | ReplicationMessageBody::SubtreeByteResponse(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Per-message-type handlers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_fresh_offer(
    source: &PeerId,
    offer: &protocol::FreshReplicationOffer,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // Rule 5: reject if PoP is missing.
    if offer.proof_of_payment.is_empty() {
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: "Missing proof of payment".to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Enforce chunk size invariant: the normal PUT path rejects data larger
    // than MAX_CHUNK_SIZE; the replication receive path must do the same to
    // prevent peers from pushing oversized records through replication.
    if offer.data.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
        warn!(
            "Rejecting fresh offer for key {}: data size {} exceeds MAX_CHUNK_SIZE {}",
            hex::encode(offer.key),
            offer.data.len(),
            crate::ant_protocol::MAX_CHUNK_SIZE,
        );
        p2p_node
            .report_trust_event(
                source,
                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
            )
            .await;
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: format!(
                    "Data size {} exceeds maximum chunk size {}",
                    offer.data.len(),
                    crate::ant_protocol::MAX_CHUNK_SIZE,
                ),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Mirror the normal PUT path: the advertised key must be the content
    // address of the supplied bytes before any expensive payment verification.
    let computed_key = crate::client::compute_address(&offer.data);
    if computed_key != offer.key {
        warn!(
            "Rejecting fresh offer for key {}: content address mismatch, computed {}",
            hex::encode(offer.key),
            hex::encode(computed_key),
        );
        p2p_node
            .report_trust_event(
                source,
                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
            )
            .await;
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: format!(
                    "Content address mismatch: expected {}, computed {}",
                    hex::encode(offer.key),
                    hex::encode(computed_key),
                ),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Rule 7: check storage admission. Fresh chunk receivers accept across the
    // paid-close-group neighbourhood (`paid_list_close_group_size`, = K_BUCKET_SIZE,
    // the same width client PUTs use), not just the close group plus a small
    // margin (ADR-0003). During full-node shunning a healthy replica's routing
    // table may still list closer full nodes it hasn't evicted yet, ranking it
    // outside the narrow window in its own view; the wider accept window absorbs
    // that transient skew so the chunk still lands. Retention (pruning) stays at
    // `storage_admission_width`, so steady-state replication is unchanged.
    if !admission::is_responsible(
        &self_id,
        &offer.key,
        p2p_node,
        config.paid_list_close_group_size,
    )
    .await
    {
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: "Not in storage-admission range for this key".to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Disk-space pre-check — mirror the PUT handler (V2-411). A full node can
    // never store this record, so reject it before the expensive payment
    // verification (EVM on-chain query / merkle pool work) rather than verifying
    // and only then failing at `storage.put` below. Reuses the cached capacity
    // check (passing results only, so freed space is detected promptly), and the
    // store path keeps its own check as defence-in-depth.
    if let Err(e) = storage.check_capacity() {
        info!(
            target: "ant_node::storage::disk_precheck",
            key = %hex::encode(offer.key),
            "Rejecting fresh replication offer before payment verification: {e}"
        );
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: e.to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Gap 1: Validate PoP via PaymentVerifier. Fresh replication is still
    // part of the immediate write fan-out: this receiver is about to store the
    // record as if the client had PUT it here directly. Storage admission
    // was checked above before proof work. ClientPut verification applies
    // store-strength cache semantics, paid-quote issuer K-closeness and local
    // price floor checks for single-node proofs, and merkle candidate
    // closeness for merkle proofs.
    match payment_verifier
        .verify_payment(
            &offer.key,
            Some(&offer.proof_of_payment),
            fresh_offer_payment_context(),
        )
        .await
    {
        Ok(status) if status.can_store() => {
            debug!(
                "PoP validated for fresh offer key {}",
                hex::encode(offer.key)
            );
        }
        Ok(_) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: offer.key,
                        reason: "Payment verification failed: payment required".to_string(),
                    },
                ),
                rr_message_id,
            )
            .await;
            return Ok(());
        }
        Err(e) => {
            warn!(
                "PoP verification error for key {}: {e}",
                hex::encode(offer.key)
            );
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: offer.key,
                        reason: format!("Payment verification error: {e}"),
                    },
                ),
                rr_message_id,
            )
            .await;
            return Ok(());
        }
    }

    // Rule 6: add to PaidForList.
    if let Err(e) = paid_list.insert(&offer.key).await {
        warn!("Failed to add key to PaidForList: {e}");
    }

    // Store the record.
    match storage.put(&offer.key, &offer.data).await {
        Ok(_) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Accepted { key: offer.key },
                ),
                rr_message_id,
            )
            .await;
        }
        Err(e) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: offer.key,
                        reason: e.to_string(),
                    },
                ),
                rr_message_id,
            )
            .await;
        }
    }

    Ok(())
}

async fn handle_paid_notify(
    _source: &PeerId,
    notify: &protocol::PaidNotify,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // Rule 3: validate PoP presence before adding.
    if notify.proof_of_payment.is_empty() {
        return Ok(());
    }

    // Check if we're in PaidCloseGroup for this key.
    if !admission::is_in_paid_close_group(
        &self_id,
        &notify.key,
        p2p_node,
        config.paid_list_close_group_size,
    )
    .await
    {
        return Ok(());
    }

    // Gap 1: Validate PoP via PaymentVerifier. PaidNotify admits fresh
    // paid-list metadata, so local paid-list close-group membership was checked
    // above before proof work. The verifier then runs the same payment proof
    // checks as ClientPut while writing a paid-list-strength cache entry.
    match payment_verifier
        .verify_payment(
            &notify.key,
            Some(&notify.proof_of_payment),
            paid_notify_payment_context(),
        )
        .await
    {
        Ok(status) if status.can_store() => {
            debug!(
                "PoP validated for paid notify key {}",
                hex::encode(notify.key)
            );
        }
        Ok(_) => {
            warn!(
                "Paid notify rejected: payment required for key {}",
                hex::encode(notify.key)
            );
            return Ok(());
        }
        Err(e) => {
            warn!(
                "PoP verification error for paid notify key {}: {e}",
                hex::encode(notify.key)
            );
            return Ok(());
        }
    }

    if let Err(e) = paid_list.insert(&notify.key).await {
        warn!("Failed to add paid notify key to PaidForList: {e}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_neighbor_sync_request(
    source: &PeerId,
    request: &protocol::NeighborSyncRequest,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    my_commitment: Option<StorageCommitment>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // No per-request hint count limit: the wire message size limit
    // (MAX_REPLICATION_MESSAGE_SIZE) already caps the payload. Unlike audit
    // challenges, sync hints don't drive expensive computation — they just
    // enter the verification queue. A per-request limit here would break
    // bootstrap replication for newly-joined nodes with 0 stored chunks.

    // Build response (outbound hints).
    let (response, sent_replica_hints, sender_in_rt) =
        neighbor_sync::handle_sync_request_with_proofs(
            source,
            request,
            p2p_node,
            storage,
            paid_list,
            config,
            is_bootstrapping,
            my_commitment.clone(),
        )
        .await;

    // Send response.
    let response_sent = send_replication_response_checked(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::NeighborSyncResponse(response),
        rr_message_id,
    )
    .await;

    // Process inbound hints only if sender is in LocalRT (Rule 4-6).
    if !sender_in_rt {
        return Ok(());
    }

    // Update sync history for this peer before recording repair proofs so a
    // same-tick audit cannot combine a fresh key proof with stale peer maturity.
    {
        let mut history = sync_history.write().await;
        let record = history.entry(*source).or_insert(PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        });
        record.last_sync = Some(Instant::now());
        record.cycles_since_sync = 0;
    }

    if response_sent && !request.bootstrapping {
        record_sent_replica_hints(source, &sent_replica_hints, repair_proofs, sync_cycle_epoch)
            .await;
    }

    // Admit inbound hints and queue for verification.
    let outcome = admit_and_queue_hints(
        &self_id,
        source,
        &request.replica_hints,
        &request.paid_hints,
        p2p_node,
        config,
        storage,
        paid_list,
        queues,
    )
    .await;

    // Track discovered keys for bootstrap drain detection so that hints
    // admitted via inbound sync requests are not missed. Capacity-rejected
    // hints keep this source on the "not yet drained" list until its next
    // sync re-admits them; a clean cycle clears the source.
    if is_bootstrapping {
        if !outcome.discovered.is_empty() {
            bootstrap::track_discovered_keys(bootstrap_state, &outcome.discovered).await;
        }
        if outcome.capacity_rejected_count > 0 {
            bootstrap::note_capacity_rejected(bootstrap_state, *source).await;
        } else {
            bootstrap::clear_capacity_rejected(bootstrap_state, source).await;
        }
    }

    Ok(())
}

async fn handle_verification_request(
    source: &PeerId,
    request: &protocol::VerificationRequest,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    #[derive(Clone, Copy)]
    enum CachedPaidLookup {
        NotChecked,
        Checked(Option<bool>),
    }

    #[derive(Clone, Copy)]
    struct CachedVerificationLookup {
        present: Option<bool>,
        paid: CachedPaidLookup,
    }

    let requested_keys = if request.keys.len() > MAX_VERIFICATION_KEYS_PER_REQUEST {
        warn!(
            "Verification request from {source} has {} keys, exceeding max {MAX_VERIFICATION_KEYS_PER_REQUEST}; answering capped prefix",
            request.keys.len(),
        );
        &request.keys[..MAX_VERIFICATION_KEYS_PER_REQUEST]
    } else {
        request.keys.as_slice()
    };

    if request.paid_list_check_indices.len() > request.keys.len() {
        warn!(
            "Verification request from {source} has {} paid-list indices for {} keys; rejecting batch",
            request.paid_list_check_indices.len(),
            request.keys.len(),
        );
        send_verification_results(source, p2p_node, request_id, Vec::new(), rr_message_id).await;
        return Ok(());
    }

    let keys_len = u32::try_from(requested_keys.len()).unwrap_or(u32::MAX);
    let paid_check_set: HashSet<u32> = request
        .paid_list_check_indices
        .iter()
        .copied()
        .filter(|&idx| {
            if idx >= keys_len {
                warn!(
                    "Verification request from {source}: paid_list_check_index {idx} out of bounds (keys.len() = {})",
                    requested_keys.len(),
                );
                false
            } else {
                true
            }
        })
        .collect();

    let mut results = Vec::with_capacity(requested_keys.len());
    let mut lookup_cache: HashMap<XorName, CachedVerificationLookup> = HashMap::new();
    for (i, key) in requested_keys.iter().enumerate() {
        let needs_paid = paid_check_set.contains(&u32::try_from(i).unwrap_or(u32::MAX));
        let cached = lookup_cache.entry(*key).or_insert_with(|| {
            let present = match storage.exists(key) {
                Ok(present) => Some(present),
                Err(e) => {
                    warn!(
                        "Verification request from {source}: failed to check storage for {}: {e}",
                        hex::encode(key)
                    );
                    None
                }
            };
            CachedVerificationLookup {
                present,
                paid: CachedPaidLookup::NotChecked,
            }
        });

        if needs_paid && matches!(cached.paid, CachedPaidLookup::NotChecked) {
            cached.paid = CachedPaidLookup::Checked(match paid_list.contains(key) {
                Ok(paid) => Some(paid),
                Err(e) => {
                    warn!(
                        "Verification request from {source}: failed to check paid-list for {}: {e}",
                        hex::encode(key)
                    );
                    None
                }
            });
        }

        let paid = if needs_paid {
            match cached.paid {
                CachedPaidLookup::Checked(paid) => paid,
                CachedPaidLookup::NotChecked => None,
            }
        } else {
            None
        };

        if cached.present.is_none() && paid.is_none() {
            continue;
        }

        results.push(protocol::KeyVerificationResult {
            key: *key,
            present: cached.present.unwrap_or(false),
            paid,
        });
    }

    send_verification_results(source, p2p_node, request_id, results, rr_message_id).await;

    Ok(())
}

async fn send_verification_results(
    source: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    results: Vec<protocol::KeyVerificationResult>,
    rr_message_id: Option<&str>,
) {
    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::VerificationResponse(VerificationResponse { results }),
        rr_message_id,
    )
    .await;
}

async fn handle_fetch_request(
    source: &PeerId,
    request: &protocol::FetchRequest,
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let response = match storage.get(&request.key).await {
        Ok(Some(data)) => protocol::FetchResponse::Success {
            key: request.key,
            data,
        },
        Ok(None) => protocol::FetchResponse::NotFound { key: request.key },
        Err(e) => protocol::FetchResponse::Error {
            key: request.key,
            reason: format!("{e}"),
        },
    };

    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::FetchResponse(response),
        rr_message_id,
    )
    .await;

    Ok(())
}

/// Responder for an incoming `AuditChallenge` (responsible-chunk audit #2, and
/// the prune-confirmation audit, which reuses the same wire message): reply with
/// per-key possession digests.
async fn handle_audit_challenge_msg(
    source: &PeerId,
    challenge: &protocol::AuditChallenge,
    storage: &Arc<LmdbStorage>,
    p2p_node: &Arc<P2PNode>,
    is_bootstrapping: bool,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let stored_chunks = storage.current_chunks().map_or(0, |c| c as usize);
    info!(
        "Audit challenge received: kind=responsible keys={} bootstrapping={} request_response={}",
        challenge.keys.len(),
        is_bootstrapping,
        rr_message_id.is_some(),
    );

    let response = audit::handle_audit_challenge(
        challenge,
        storage,
        p2p_node.peer_id(),
        is_bootstrapping,
        stored_chunks,
    )
    .await;
    let response_kind = audit_response_kind(&response);

    let sent = send_replication_response_checked(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::AuditResponse(response),
        rr_message_id,
    )
    .await;
    if sent {
        info!(
            "Audit challenge reply sent: kind=responsible response={} keys={} request_response={}",
            response_kind,
            challenge.keys.len(),
            rr_message_id.is_some(),
        );
    } else {
        warn!(
            "Audit challenge reply not sent: kind=responsible response={} keys={} request_response={}",
            response_kind,
            challenge.keys.len(),
            rr_message_id.is_some(),
        );
    }

    Ok(())
}

fn audit_response_kind(response: &protocol::AuditResponse) -> &'static str {
    match response {
        protocol::AuditResponse::Digests { .. } => "digests",
        protocol::AuditResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::AuditResponse::Rejected { .. } => "rejected",
    }
}

fn subtree_audit_response_kind(response: &protocol::SubtreeAuditResponse) -> &'static str {
    match response {
        protocol::SubtreeAuditResponse::Proof { .. } => "proof",
        protocol::SubtreeAuditResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::SubtreeAuditResponse::Rejected { .. } => "rejected",
    }
}

fn subtree_byte_response_kind(response: &protocol::SubtreeByteResponse) -> &'static str {
    match response {
        protocol::SubtreeByteResponse::Items { .. } => "items",
        protocol::SubtreeByteResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::SubtreeByteResponse::Rejected { .. } => "rejected",
    }
}

// ---------------------------------------------------------------------------
// Message sending helper
// ---------------------------------------------------------------------------

/// Send a replication response message as a best-effort reply.
///
/// Encode and send failures are logged by the checked helper. Most response
/// paths do not need to branch on send success, so this wrapper keeps those
/// call sites explicit about their best-effort behavior.
async fn send_replication_response(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    body: ReplicationMessageBody,
    rr_message_id: Option<&str>,
) {
    let _ =
        send_replication_response_checked(peer, p2p_node, request_id, body, rr_message_id).await;
}

/// Send a replication response message and report whether it was accepted.
///
/// Returns `true` after the message is encoded and accepted by the P2P send
/// path. Returns `false` after logging an encode or send failure. Repair-proof
/// recording uses this to avoid trusting hints that were not actually sent.
///
/// When `rr_message_id` is `Some`, the response is sent via the `/rr/`
/// request-response path so saorsa-core can route it back to the caller's
/// `send_request` future. Otherwise it is sent as a plain message.
async fn send_replication_response_checked(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    body: ReplicationMessageBody,
    rr_message_id: Option<&str>,
) -> bool {
    let msg = ReplicationMessage { request_id, body };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode replication response: {e}");
            return false;
        }
    };
    let result = if let Some(msg_id) = rr_message_id {
        p2p_node
            .send_response(peer, REPLICATION_PROTOCOL_ID, msg_id, encoded)
            .await
    } else {
        p2p_node
            .send_message(peer, REPLICATION_PROTOCOL_ID, encoded, &[])
            .await
    };
    if let Err(e) = result {
        debug!("Failed to send replication response to {peer}: {e}");
        return false;
    }
    true
}

async fn record_sent_replica_hints(
    peer: &PeerId,
    hints: &[neighbor_sync::SentReplicaHint],
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
) {
    if hints.is_empty() {
        return;
    }

    let hinted_at_epoch = *sync_cycle_epoch.read().await;
    let mut proofs = repair_proofs.write().await;
    for hint in hints {
        if proofs.record_replica_hint_sent(*peer, hint.key, &hint.close_peers, hinted_at_epoch) {
            debug!(
                "Recorded repair hint proof for peer {peer} and key {}",
                hex::encode(hint.key)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Neighbor sync round
// ---------------------------------------------------------------------------

/// Run one neighbor sync round.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_neighbor_sync_round(
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    commitment_state: &Arc<ResponderCommitmentState>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    gossip_audit: &GossipAuditTrigger,
) {
    let self_id = *p2p_node.peer_id();
    let bootstrapping = *is_bootstrapping.read().await;

    // Check if cycle is complete; start new one if needed.
    // We check under a read lock, then release it before the expensive
    // prune pass and DHT snapshot so other tasks are not starved.
    let cycle_complete = sync_state.read().await.is_cycle_complete();
    if cycle_complete {
        // A completed local neighbor-sync cycle advances the epoch component
        // of repair-proof maturity. The per-key wall-clock minimum age is
        // checked when audits are selected.
        {
            let mut history = sync_history.write().await;
            for record in history.values_mut() {
                record.cycles_since_sync = record.cycles_since_sync.saturating_add(1);
            }
        }
        let current_sync_epoch = {
            let mut epoch = sync_cycle_epoch.write().await;
            *epoch = epoch.saturating_add(1);
            *epoch
        };

        // Post-cycle pruning (Section 11) — runs without holding sync_state.
        // Remote prune-confirmation audits are storage-proof audits and only
        // run after bootstrap has drained.
        let allow_remote_prune_audits = !bootstrapping && bootstrap_state.read().await.is_drained();
        pruning::run_prune_pass_with_context(pruning::PrunePassContext {
            self_id: &self_id,
            storage,
            paid_list,
            p2p_node,
            config,
            sync_state,
            repair_proofs,
            current_sync_epoch,
            #[cfg(any(test, feature = "test-utils"))]
            repair_proof_now: None,
            allow_remote_prune_audits,
            commitment_state: Some(commitment_state),
        })
        .await;

        // Take fresh close-neighbor snapshot (DHT query, no lock held).
        let neighbors =
            neighbor_sync::snapshot_close_neighbors(p2p_node, &self_id, config.neighbor_sync_scope)
                .await;

        // Now re-acquire write lock and re-check before swapping cycle.
        let mut state = sync_state.write().await;
        if state.is_cycle_complete() {
            // Preserve cooldown and bootstrap-claim tracking across cycles.
            // Claims have a 24h lifecycle vs 10-20 min cycles — dropping them
            // would reset the abuse detection timer every cycle.
            let old_sync_times = std::mem::take(&mut state.last_sync_times);
            let old_bootstrap_claims = std::mem::take(&mut state.bootstrap_claims);
            let old_bootstrap_claim_history = std::mem::take(&mut state.bootstrap_claim_history);
            let old_prune_cursor = state.prune_cursor;
            *state = NeighborSyncState::new_cycle(neighbors);
            state.last_sync_times = old_sync_times;
            state.bootstrap_claims = old_bootstrap_claims;
            state.bootstrap_claim_history = old_bootstrap_claim_history;
            state.prune_cursor = old_prune_cursor;
        }
    }

    // Select batch of peers.
    let batch = {
        let mut state = sync_state.write().await;
        neighbor_sync::select_sync_batch(
            &mut state,
            config.neighbor_sync_peer_count,
            config.neighbor_sync_cooldown,
        )
    };

    if batch.is_empty() {
        return;
    }

    debug!("Neighbor sync: syncing with {} peers", batch.len());

    // Snapshot our current commitment once per round so all peers in
    // this batch see the same thing (gossip is the responder's attestation;
    // same value across the batch is fine and reduces RwLock churn). Atomically
    // snapshot + mark-gossiped so we stay answerable for exactly what we emit
    // (ADR-0002 retention), with no TOCTOU vs a concurrent retire/rotate.
    let my_commitment = commitment_state
        .current_for_gossip()
        .map(|b| b.commitment().clone());

    let mut hints_by_peer = neighbor_sync::build_sync_hints_for_peers(
        &batch,
        storage,
        paid_list,
        p2p_node,
        config.close_group_size,
        config.paid_list_close_group_size,
    )
    .await;

    // Sync with each peer in the batch.
    for peer in &batch {
        let hints = hints_by_peer.remove(peer).unwrap_or_default();
        let outcome = neighbor_sync::sync_with_peer_with_hints(
            peer,
            p2p_node,
            config,
            bootstrapping,
            hints,
            my_commitment.clone(),
        )
        .await;

        if let Some(outcome) = outcome {
            handle_sync_response(
                &self_id,
                peer,
                &outcome.response,
                &outcome.sent_replica_hints,
                p2p_node,
                config,
                bootstrapping,
                bootstrap_state,
                storage,
                paid_list,
                queues,
                sync_state,
                sync_history,
                sync_cycle_epoch,
                repair_proofs,
                last_commitment_by_peer,
                ever_capable_peers,
                sig_verify_attempts,
                gossip_audit,
            )
            .await;
        } else {
            // Sync failed -- remove peer and try to fill slot.
            let replacement = {
                let mut state = sync_state.write().await;
                neighbor_sync::handle_sync_failure(&mut state, peer, config.neighbor_sync_cooldown)
            };

            // Attempt sync with the replacement peer (if one was found).
            if let Some(replacement_peer) = replacement {
                let mut replacement_hints = neighbor_sync::build_sync_hints_for_peers(
                    std::slice::from_ref(&replacement_peer),
                    storage,
                    paid_list,
                    p2p_node,
                    config.close_group_size,
                    config.paid_list_close_group_size,
                )
                .await;
                let hints = replacement_hints
                    .remove(&replacement_peer)
                    .unwrap_or_default();
                let replacement_outcome = neighbor_sync::sync_with_peer_with_hints(
                    &replacement_peer,
                    p2p_node,
                    config,
                    bootstrapping,
                    hints,
                    my_commitment.clone(),
                )
                .await;

                if let Some(outcome) = replacement_outcome {
                    handle_sync_response(
                        &self_id,
                        &replacement_peer,
                        &outcome.response,
                        &outcome.sent_replica_hints,
                        p2p_node,
                        config,
                        bootstrapping,
                        bootstrap_state,
                        storage,
                        paid_list,
                        queues,
                        sync_state,
                        sync_history,
                        sync_cycle_epoch,
                        repair_proofs,
                        last_commitment_by_peer,
                        ever_capable_peers,
                        sig_verify_attempts,
                        gossip_audit,
                    )
                    .await;
                }
            }
        }
    }
}

/// Process a successful neighbor sync response: record the sync, check for
/// bootstrap claim abuse, and admit inbound hints.
#[allow(clippy::too_many_arguments)]
async fn handle_sync_response(
    self_id: &PeerId,
    peer: &PeerId,
    resp: &NeighborSyncResponse,
    sent_replica_hints: &[neighbor_sync::SentReplicaHint],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    bootstrapping: bool,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    gossip_audit: &GossipAuditTrigger,
) {
    // Ingest the peer's commitment if they piggybacked one on the response.
    // Same verification as the request path (peer-id binding + signature);
    // forged commitments are dropped at the edge. A *changed* commitment here
    // is a gossip-audit trigger just like on the request path — so a peer that
    // only ever answers sync (never initiates) is still audited (ADR-0002).
    if let Some(target) = ingest_peer_commitment(
        peer,
        resp.commitment.as_ref(),
        p2p_node,
        last_commitment_by_peer,
        ever_capable_peers,
        sig_verify_attempts,
    )
    .await
    {
        maybe_trigger_gossip_audit(gossip_audit, peer, target).await;
    }

    // Record successful sync.
    {
        let mut state = sync_state.write().await;
        neighbor_sync::record_successful_sync(&mut state, peer);
    }
    {
        let mut history = sync_history.write().await;
        let record = history.entry(*peer).or_insert(PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        });
        record.last_sync = Some(Instant::now());
        record.cycles_since_sync = 0;
    }

    // Process inbound hints from response (skip if peer is bootstrapping).
    if resp.bootstrapping {
        // Gap 6: BootstrapClaimAbuse grace period enforcement.
        // Separate state mutation from network I/O to avoid holding the
        // write lock across report_trust_event.
        let should_report = {
            let now = Instant::now();
            let mut state = sync_state.write().await;
            match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period) {
                BootstrapClaimObservation::WithinGrace { .. } => false,
                BootstrapClaimObservation::PastGrace { first_seen } => {
                    warn!(
                        "Peer {peer} has been claiming bootstrap for {:?}, \
                         exceeding grace period of {:?} — reporting abuse",
                        now.duration_since(first_seen),
                        config.bootstrap_claim_grace_period,
                    );
                    true
                }
                BootstrapClaimObservation::Repeated { first_seen } => {
                    warn!(
                        "Peer {peer} repeated bootstrap claim after previously stopping; \
                         first claim was {:?} ago — reporting abuse",
                        now.duration_since(first_seen),
                    );
                    true
                }
            }
        };
        if should_report {
            p2p_node
                .report_trust_event(
                    peer,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
    } else {
        // Peer is not claiming bootstrap; clear active claim while retaining
        // history so the peer cannot start a second grace window later.
        {
            let mut state = sync_state.write().await;
            state.clear_active_bootstrap_claim(peer);
        }
        record_sent_replica_hints(peer, sent_replica_hints, repair_proofs, sync_cycle_epoch).await;
        let outcome = admit_and_queue_hints(
            self_id,
            peer,
            &resp.replica_hints,
            &resp.paid_hints,
            p2p_node,
            config,
            storage,
            paid_list,
            queues,
        )
        .await;

        // Track discovered keys for bootstrap drain detection so that hints
        // admitted via regular neighbor sync are not missed. Capacity-
        // rejected hints keep this source on the "not yet drained" list
        // until its next sync replays them; a clean cycle clears it.
        if bootstrapping {
            if !outcome.discovered.is_empty() {
                bootstrap::track_discovered_keys(bootstrap_state, &outcome.discovered).await;
            }
            if outcome.capacity_rejected_count > 0 {
                bootstrap::note_capacity_rejected(bootstrap_state, *peer).await;
            } else {
                bootstrap::clear_capacity_rejected(bootstrap_state, peer).await;
            }
        }
    }
}

/// Admit hints and queue them for verification, returning newly-discovered keys.
///
/// Shared by neighbor-sync request handling, response handling, and bootstrap
/// sync so that admission + queueing logic lives in one place.
#[allow(clippy::too_many_arguments)]
/// Outcome of [`admit_and_queue_hints`].
///
/// `capacity_rejected_count` is non-zero when one or more legitimately
/// admissible hints were dropped because `pending_verify`'s global or
/// per-source bound was hit. Callers that care about completeness
/// (bootstrap drain accounting) MUST NOT treat their work as complete while
/// this is > 0 — the source will need to re-hint after capacity frees up.
struct AdmissionOutcome {
    discovered: HashSet<XorName>,
    capacity_rejected_count: usize,
}

#[allow(clippy::too_many_arguments)]
async fn admit_and_queue_hints(
    self_id: &PeerId,
    source_peer: &PeerId,
    replica_hints: &[XorName],
    paid_hints: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    storage: &Arc<LmdbStorage>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
) -> AdmissionOutcome {
    let pending_keys: HashSet<XorName> = {
        let q = queues.read().await;
        q.pending_keys().into_iter().collect()
    };

    let admitted = admission::admit_hints(
        self_id,
        replica_hints,
        paid_hints,
        p2p_node,
        config,
        storage,
        paid_list,
        &pending_keys,
    )
    .await;

    let mut discovered = HashSet::new();
    let mut capacity_rejected_count: usize = 0;
    let mut q = queues.write().await;
    let now = Instant::now();

    for key in admitted.replica_keys {
        if !storage.exists(&key).unwrap_or(false) {
            let result = q.add_pending_verify(
                key,
                VerificationEntry {
                    state: VerificationState::PendingVerify,
                    pipeline: HintPipeline::Replica,
                    verified_sources: Vec::new(),
                    tried_sources: HashSet::new(),
                    created_at: now,
                    next_verify_at: now,
                    hint_sender: *source_peer,
                },
            );
            match result {
                crate::replication::scheduling::AdmissionResult::Admitted => {
                    discovered.insert(key);
                }
                crate::replication::scheduling::AdmissionResult::AlreadyPresent => {}
                crate::replication::scheduling::AdmissionResult::CapacityRejected => {
                    capacity_rejected_count += 1;
                }
            }
        }
    }

    for key in admitted.paid_only_keys {
        let result = q.add_pending_verify(
            key,
            VerificationEntry {
                state: VerificationState::PendingVerify,
                pipeline: HintPipeline::PaidOnly,
                verified_sources: Vec::new(),
                tried_sources: HashSet::new(),
                created_at: now,
                next_verify_at: now,
                hint_sender: *source_peer,
            },
        );
        match result {
            crate::replication::scheduling::AdmissionResult::Admitted => {
                discovered.insert(key);
            }
            crate::replication::scheduling::AdmissionResult::AlreadyPresent => {}
            crate::replication::scheduling::AdmissionResult::CapacityRejected => {
                capacity_rejected_count += 1;
            }
        }
    }

    if capacity_rejected_count > 0 {
        debug!(
            "admit_and_queue_hints from {source_peer}: {capacity_rejected_count} hints \
             rejected at queue capacity; source will need to re-hint after pending_verify drains"
        );
    }

    AdmissionOutcome {
        discovered,
        capacity_rejected_count,
    }
}

// ---------------------------------------------------------------------------
// Verification cycle
// ---------------------------------------------------------------------------

/// Run one verification cycle: process pending keys through quorum checks.
#[allow(clippy::too_many_lines)]
async fn run_verification_cycle(ctx: VerificationCycleContext<'_>) {
    let cycle_started = Instant::now();
    let VerificationCycleContext {
        p2p_node,
        paid_list,
        storage,
        queues,
        config,
        bootstrap_state,
        is_bootstrapping,
        bootstrap_complete_notify,
        last_commitment_by_peer,
        ever_capable_peers,
        recent_provers,
    } = ctx;

    // Evict stale entries that have been pending too long (e.g. unreachable
    // verification targets during a network partition).
    let stale_pending_keys = {
        let mut q = queues.write().await;
        q.evict_stale(config::PENDING_VERIFY_MAX_AGE)
    };
    if !stale_pending_keys.is_empty() {
        update_bootstrap_after_verification(
            &stale_pending_keys,
            bootstrap_state,
            queues,
            is_bootstrapping,
            bootstrap_complete_notify,
        )
        .await;
    }

    let pending_keys = {
        let q = queues.read().await;
        q.ready_pending_keys(Instant::now())
    };

    if pending_keys.is_empty() {
        return;
    }
    let initial_pending_count = pending_keys.len();

    let self_id = *p2p_node.peer_id();

    // Step 1: Check local PaidForList for fast-path authorization (Section 9,
    // step 4).
    let mut local_paid_presence_probe_keys = Vec::new();
    let mut local_paid_paid_only_keys = Vec::new();
    let mut keys_needing_network = Vec::new();
    let mut terminal_keys: Vec<XorName> = Vec::new();
    {
        let mut q = queues.write().await;
        for key in &pending_keys {
            if paid_list.contains(key).unwrap_or(false) {
                if let Some(pipeline) =
                    q.set_pending_state(key, VerificationState::PaidListVerified)
                {
                    match pipeline {
                        HintPipeline::PaidOnly => {
                            // Paid-only + local paid state needs one more
                            // storage-admission check outside this lock: if we
                            // are also in the close group plus storage margin,
                            // the hint can repair a missing replica.
                            local_paid_paid_only_keys.push(*key);
                        }
                        HintPipeline::Replica => {
                            // Local paid-list membership authorizes the key.
                            // We still need a presence probe to discover fetch
                            // sources, but we must not require remote paid
                            // majority or presence quorum.
                            local_paid_presence_probe_keys.push(*key);
                        }
                    }
                }
            } else {
                keys_needing_network.push(*key);
            }
        }
    }

    if !local_paid_paid_only_keys.is_empty() {
        let mut terminal_paid_only = Vec::new();
        for key in local_paid_paid_only_keys {
            if storage.exists(&key).unwrap_or(false) {
                terminal_paid_only.push(key);
            } else if admission::is_responsible(
                &self_id,
                &key,
                p2p_node,
                storage_admission_width(config.close_group_size),
            )
            .await
            {
                local_paid_presence_probe_keys.push(key);
            } else {
                terminal_paid_only.push(key);
            }
        }

        if !terminal_paid_only.is_empty() {
            let mut q = queues.write().await;
            for key in terminal_paid_only {
                q.remove_pending(&key);
                terminal_keys.push(key);
            }
        }
    }

    let local_paid_probe_count = local_paid_presence_probe_keys.len();
    let keys_needing_network_count = keys_needing_network.len();

    // Step 1b: Local paid-list hit for fetch-eligible keys. Per Section 9
    // step 4, authorization succeeds immediately; run a presence-only probe
    // to find any holder we can fetch from.
    if !local_paid_presence_probe_keys.is_empty() {
        let targets = quorum::compute_presence_targets(
            &local_paid_presence_probe_keys,
            p2p_node,
            config,
            &self_id,
        )
        .await;
        let evidence = quorum::run_verification_round(
            &local_paid_presence_probe_keys,
            &targets,
            p2p_node,
            config,
        )
        .await;

        let mut q = queues.write().await;
        for key in local_paid_presence_probe_keys {
            if storage.exists(&key).unwrap_or(false) {
                q.remove_pending(&key);
                terminal_keys.push(key);
                continue;
            }
            let mut sources = evidence.get(&key).map_or_else(Vec::new, |ev| {
                quorum::present_sources_for_key(&key, ev, &targets)
            });
            let replica_hint_sender = q.get_pending(&key).and_then(|entry| {
                (entry.pipeline == HintPipeline::Replica).then_some(entry.hint_sender)
            });
            if let Some(hint_sender) = replica_hint_sender {
                add_replica_hint_sender_source(&mut sources, HintPipeline::Replica, hint_sender);
            }
            if sources.is_empty() {
                warn!(
                    "Locally paid key {} has no responding holders yet; deferring retry",
                    hex::encode(key)
                );
                q.defer_pending(&key, config.verification_request_timeout);
            } else {
                let distance = crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                // Atomic remove+enqueue: if fetch_queue is at capacity, the
                // pending entry is preserved and retried next cycle (no
                // silent drop of verified replica-repair work).
                let _ = q.promote_pending_to_fetch(key, distance, sources);
            }
        }
    }

    // Steps 2-5: Network verification (skipped if all keys resolved locally).
    if !keys_needing_network.is_empty() {
        // Step 2: Compute targets and run network verification round.
        let targets =
            quorum::compute_verification_targets(&keys_needing_network, p2p_node, config, &self_id)
                .await;

        let evidence =
            quorum::run_verification_round(&keys_needing_network, &targets, p2p_node, config).await;

        // Step 3: Evaluate results — collect outcomes without holding the write
        // lock across paid-list I/O.
        //
        // v12 §6 holder-eligibility: snapshot the per-peer last-commitment
        // table and recent_provers cache up front so the synchronous
        // evaluate_key_evidence_with_holder_check predicate can consult
        // them without awaiting. The predicate downgrades a Present
        // claim to Unresolved unless the peer is credited for that key.
        // Snapshot per-peer commitment data. We need two views:
        //   - `commitment_by_peer_snapshot`: peers that currently have
        //     a verified commitment record on file (used to look up
        //     their current hash).
        //   - `capable_peer_snapshot`: the sticky "ever v12-capable"
        //     set. Sourced from a separate set rather than the
        //     commitment map so eviction (PeerRemoved cleanup, sybil
        //     cap at `MAX_LAST_COMMITMENT_BY_PEER`) does NOT downgrade
        //     a previously-v12 peer to "legacy" credit-unconditionally.
        //     Legacy / pre-v12 peers that have never sent a commitment
        //     remain absent from the set and are credited via the
        //     legacy path so mixed-version networks stay live.
        let commitment_by_peer_snapshot: HashMap<PeerId, [u8; 32]> = {
            let map = last_commitment_by_peer.read().await;
            map.iter()
                // Read the CACHED hash (§13) — no per-cycle re-serialize/re-hash
                // of every peer's ~5 KiB commitment.
                .filter_map(|(p, rec)| rec.commitment_hash().map(|h| (*p, h)))
                .collect()
        };
        let capable_peer_snapshot: HashSet<PeerId> = ever_capable_peers.read().await.clone();
        // Take a full snapshot of recent_provers under the read lock,
        // then release. The cache is bounded (16/key × keys), so the
        // clone is cheap.
        let provers_snapshot = recent_provers.read().await.clone();
        // For the replica-fetch path, we need to know whether THIS
        // node already holds the key being verified. The v12 §6
        // holder-credit gate is meant to prevent uncredited Present
        // claims from contributing to paid-list / reward quorum for
        // keys we DO hold (and could audit ourselves). For keys we
        // are trying to FETCH (i.e. not in local storage), there is
        // no possible local audit credit, and gating the presence
        // quorum on credit would deadlock replica-repair in a
        // fully v12-capable close group.
        let mut locally_held: HashSet<XorName> = HashSet::new();
        for key in &keys_needing_network {
            if storage.exists(key).unwrap_or(false) {
                locally_held.insert(*key);
            }
        }
        let holder_credit = |peer: &PeerId, key: &XorName| -> bool {
            if !locally_held.contains(key) {
                // Replica-fetch path: we don't hold this key, so we
                // cannot have collected audit credit for it. Trust
                // Present claims to drive fetch-source promotion;
                // chunk-PUT payment_verifier is the security backstop
                // when the bytes actually arrive.
                return true;
            }
            if !capable_peer_snapshot.contains(peer) {
                // Pre-v12 / legacy peer that has never gossiped a
                // commitment. The v12 §6 holder-eligibility check
                // doesn't apply: their Present evidence comes through
                // the legacy path and we credit it unconditionally
                // so a mixed-version network stays live during
                // transition.
                return true;
            }
            let Some(hash) = commitment_by_peer_snapshot.get(peer) else {
                // Peer is commitment_capable (sticky) but currently
                // has no live commitment record on file (e.g. their
                // last gossip was evicted from the LRU cache, or it
                // failed verification). Withhold credit until they
                // re-prove storage under a fresh commitment.
                return false;
            };
            provers_snapshot.is_credited_holder(key, peer, hash)
        };

        let mut evaluated: Vec<(XorName, KeyVerificationOutcome, HintPipeline, PeerId)> =
            Vec::new();
        {
            let q = queues.read().await;
            for key in &keys_needing_network {
                let Some(ev) = evidence.get(key) else {
                    continue;
                };
                let Some(entry) = q.get_pending(key) else {
                    continue;
                };
                let outcome = quorum::evaluate_key_evidence_with_holder_check(
                    key,
                    ev,
                    &targets,
                    config,
                    holder_credit,
                );
                evaluated.push((*key, outcome, entry.pipeline, entry.hint_sender));
            }
        } // read lock released

        // Step 4: Insert verified keys into PaidForList (no lock held).
        let mut paid_insert_keys: Vec<XorName> = Vec::new();
        for (key, outcome, _, _) in &evaluated {
            if matches!(
                outcome,
                KeyVerificationOutcome::QuorumVerified { .. }
                    | KeyVerificationOutcome::PaidListVerified { .. }
            ) {
                paid_insert_keys.push(*key);
            }
        }
        for key in &paid_insert_keys {
            if let Err(e) = paid_list.insert(key).await {
                warn!("Failed to add verified key to PaidForList: {e}");
            }
        }

        // Paid-only hints normally update PaidForList only. If this node is
        // also within the storage-admission group for the key, a verified
        // paid-only hint can safely repair a missing replica using sources
        // from the same verification round.
        let mut paid_only_fetch_keys: HashSet<XorName> = HashSet::new();
        for (key, outcome, pipeline, _) in &evaluated {
            if *pipeline == HintPipeline::PaidOnly
                && matches!(
                    outcome,
                    KeyVerificationOutcome::QuorumVerified { .. }
                        | KeyVerificationOutcome::PaidListVerified { .. }
                )
                && !storage.exists(key).unwrap_or(false)
                && admission::is_responsible(
                    &self_id,
                    key,
                    p2p_node,
                    storage_admission_width(config.close_group_size),
                )
                .await
            {
                paid_only_fetch_keys.insert(*key);
            }
        }

        // Step 5: Update queues with the evaluated outcomes.
        let mut q = queues.write().await;
        for (key, outcome, pipeline, hint_sender) in evaluated {
            match outcome {
                KeyVerificationOutcome::QuorumVerified { sources }
                | KeyVerificationOutcome::PaidListVerified { sources } => {
                    let mut fetch_sources = sources;
                    add_replica_hint_sender_source(&mut fetch_sources, pipeline, hint_sender);
                    let fetch_eligible =
                        pipeline == HintPipeline::Replica || paid_only_fetch_keys.contains(&key);
                    if fetch_eligible && !fetch_sources.is_empty() {
                        let distance =
                            crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                        // Atomic remove+enqueue: on fetch_queue capacity miss
                        // the pending entry is preserved so this verified key
                        // is retried on the next cycle (no silent drop).
                        let _ = q.promote_pending_to_fetch(key, distance, fetch_sources);
                        // Not terminal — either moved to fetch queue, or
                        // retained as pending until queue drains.
                    } else if fetch_eligible && fetch_sources.is_empty() {
                        warn!(
                            "Verified storage-admitted key {} has no holders yet; deferring retry",
                            hex::encode(key)
                        );
                        q.defer_pending(&key, config.verification_request_timeout);
                    } else {
                        q.remove_pending(&key);
                        terminal_keys.push(key);
                    }
                }
                KeyVerificationOutcome::QuorumFailed => {
                    q.remove_pending(&key);
                    terminal_keys.push(key);
                }
                KeyVerificationOutcome::QuorumInconclusive => {
                    q.set_pending_state(&key, VerificationState::QuorumInconclusive);
                    q.defer_pending(&key, config.verification_request_timeout);
                }
            }
        }
    }

    // Step 6: Remove terminal keys from bootstrap pending set and re-check
    // the drain condition.
    update_bootstrap_after_verification(
        &terminal_keys,
        bootstrap_state,
        queues,
        is_bootstrapping,
        bootstrap_complete_notify,
    )
    .await;

    let (pending_after, fetch_after, in_flight_after) = {
        let q = queues.read().await;
        (
            q.pending_count(),
            q.fetch_queue_count(),
            q.in_flight_count(),
        )
    };
    let terminal_key_count = terminal_keys.len();
    let elapsed_ms = cycle_started.elapsed().as_millis();

    if elapsed_ms >= VERIFICATION_CYCLE_SLOW_LOG_MS {
        info!(
            target: "ant_node::replication::verification",
            "Slow replication verification cycle: pending_start={initial_pending_count}, local_paid_probe={local_paid_probe_count}, network_verify={keys_needing_network_count}, terminal={terminal_key_count}, pending_after={pending_after}, fetch_after={fetch_after}, in_flight_after={in_flight_after}, elapsed_ms={elapsed_ms}",
        );
    } else {
        debug!(
            target: "ant_node::replication::verification",
            "Replication verification cycle: pending_start={initial_pending_count}, local_paid_probe={local_paid_probe_count}, network_verify={keys_needing_network_count}, terminal={terminal_key_count}, pending_after={pending_after}, fetch_after={fetch_after}, in_flight_after={in_flight_after}, elapsed_ms={elapsed_ms}",
        );
    }
}

fn add_replica_hint_sender_source(
    sources: &mut Vec<PeerId>,
    pipeline: HintPipeline,
    hint_sender: PeerId,
) {
    if pipeline == HintPipeline::Replica && !sources.contains(&hint_sender) {
        sources.push(hint_sender);
    }
}

/// Post-verification bootstrap bookkeeping: remove terminal keys from the
/// bootstrap pending set and transition out of bootstrapping when drained.
async fn update_bootstrap_after_verification(
    terminal_keys: &[XorName],
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    if terminal_keys.is_empty() || bootstrap_state.read().await.is_drained() {
        return;
    }
    {
        let mut bs = bootstrap_state.write().await;
        for key in terminal_keys {
            bs.remove_key(key);
        }
    }
    let q = queues.read().await;
    if bootstrap::check_bootstrap_drained(bootstrap_state, &q).await {
        complete_bootstrap(is_bootstrapping, bootstrap_complete_notify).await;
    }
}

/// Set `is_bootstrapping` to `false` and wake all waiters.
async fn complete_bootstrap(
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    *is_bootstrapping.write().await = false;
    bootstrap_complete_notify.notify_waiters();
    info!("Replication bootstrap complete");
}

// ---------------------------------------------------------------------------
// Fetch types and single-fetch executor
// ---------------------------------------------------------------------------

/// Result classification for a single fetch attempt.
enum FetchResult {
    /// Data fetched, integrity-checked, and stored successfully.
    Stored,
    /// Content-address integrity check failed — do not retry.
    IntegrityFailed,
    /// Source failed (network error or non-success response) — retryable.
    SourceFailed,
}

/// Outcome produced by [`execute_single_fetch`] and consumed by the fetch
/// worker loop to update queue state.
struct FetchOutcome {
    key: XorName,
    result: FetchResult,
}

#[allow(clippy::too_many_lines)]
/// Execute a single fetch request against `source` for `key`.
///
/// Handles encoding, network I/O, integrity checking, storage, and trust
/// event reporting.  Returns a [`FetchOutcome`] so the caller can update
/// queue state without holding any locks during the network round-trip.
async fn execute_single_fetch(
    p2p_node: Arc<P2PNode>,
    storage: Arc<LmdbStorage>,
    config: Arc<ReplicationConfig>,
    key: XorName,
    source: PeerId,
) -> FetchOutcome {
    let request = protocol::FetchRequest { key };
    let msg = ReplicationMessage {
        request_id: rand::thread_rng().gen::<u64>(),
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode fetch request: {e}");
            return FetchOutcome {
                key,
                result: FetchResult::SourceFailed,
            };
        }
    };

    let result = p2p_node
        .send_request(
            &source,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.fetch_request_timeout,
        )
        .await;

    match result {
        Ok(response) => {
            let Ok(resp_msg) = ReplicationMessage::decode(&response.data) else {
                p2p_node
                    .report_trust_event(
                        &source,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
                return FetchOutcome {
                    key,
                    result: FetchResult::SourceFailed,
                };
            };

            match resp_msg.body {
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::Success {
                    key: resp_key,
                    data,
                }) => {
                    // Validate the response key matches the requested key.
                    // A malicious peer could serve valid data for a different
                    // key, passing integrity checks while the requested key
                    // is falsely marked as fetched.
                    if resp_key != key {
                        warn!(
                            "Fetch response key mismatch: requested {}, got {}",
                            hex::encode(key),
                            hex::encode(resp_key)
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Enforce chunk size invariant on fetched data.
                    // Checked before the content-address hash to avoid
                    // hashing up to 10 MiB of oversized junk data.
                    if data.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
                        warn!(
                            "Fetched record {} exceeds MAX_CHUNK_SIZE ({} > {})",
                            hex::encode(resp_key),
                            data.len(),
                            crate::ant_protocol::MAX_CHUNK_SIZE,
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Content-address integrity check.
                    let computed = crate::client::compute_address(&data);
                    if computed != resp_key {
                        warn!(
                            "Fetched record integrity check failed: expected {}, got {}",
                            hex::encode(resp_key),
                            hex::encode(computed)
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    if let Err(e) = storage.put(&resp_key, &data).await {
                        warn!(
                            "Failed to store fetched record {}: {e}",
                            hex::encode(resp_key)
                        );
                        return FetchOutcome {
                            key,
                            result: FetchResult::SourceFailed,
                        };
                    }

                    FetchOutcome {
                        key,
                        result: FetchResult::Stored,
                    }
                }
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::NotFound {
                    ..
                }) => {
                    // This peer was selected as a fetch source because it
                    // recently answered `Present` during verification. A
                    // subsequent NotFound is evidence of a stale/false claim
                    // or chunk wiping, so penalize lightly and try another
                    // verified source.
                    warn!(
                        "Fetch: verified source {source} returned NotFound for {}",
                        hex::encode(key)
                    );
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::Error {
                    reason,
                    ..
                }) => {
                    warn!(
                        "Fetch: peer {source} returned error for {}: {reason}",
                        hex::encode(key)
                    );
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
                _ => {
                    // Unexpected message type — treat as malformed.
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
            }
        }
        Err(e) => {
            debug!("Fetch request to {source} failed: {e}");
            // No ApplicationFailure here — P2PNode::send_request() already
            // reports ConnectionTimeout / ConnectionFailed to the TrustEngine.
            FetchOutcome {
                key,
                result: FetchResult::SourceFailed,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit result handler
// ---------------------------------------------------------------------------

/// Format the first confirmed-failed key as a 16-hex-char label.
///
/// Pairs with `challenged_peer` to form a stable cross-host correlation
/// handle in the audit-failure log line, e.g.
///
/// ```text
/// Audit failure for <peer>: …, `first_failed_key=0x18878f1d2d9e0612`
/// ```
///
/// Falls back to `"0x"` when the list is empty so the log line never
/// contains a misleading default.
fn first_failed_key_label(confirmed_failed_keys: &[XorName]) -> String {
    confirmed_failed_keys.first().map_or_else(
        || "0x".to_string(),
        |k| format!("0x{}", hex::encode(&k[..8])),
    )
}

/// Execute the side effects for a subtree storage-commitment audit failure.
///
/// Subtree timeouts are fully graced: the multi-round, multi-chunk challenge can
/// legitimately time out on slow or loaded honest peers, so it never touches the
/// responsible-chunk audit path or its timeout accounting. Confirmed subtree
/// failures still penalise immediately and revoke holder credit.
async fn handle_subtree_failed_audit(
    challenged_peer: &PeerId,
    confirmed_failed_key_count: usize,
    reason: &AuditFailureReason,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    recent_provers: &Arc<RwLock<RecentProvers>>,
) {
    if matches!(reason, AuditFailureReason::Timeout) {
        debug!(
            "Audit timeout for {challenged_peer} fully graced \
             (subtree audit does not evict on timeout)"
        );
        return;
    }

    // The caller already logged the rich failure line with reason + per-category
    // summary; avoid a redundant second error log here.
    let _ = confirmed_failed_key_count;
    {
        let mut state = sync_state.write().await;
        state.clear_active_bootstrap_claim(challenged_peer);
    }
    {
        let mut provers_guard = recent_provers.write().await;
        apply_audit_failure_credit_revocation(&mut provers_guard, challenged_peer, reason);
    }
    p2p_node
        .report_trust_event(
            challenged_peer,
            TrustEvent::ApplicationFailure(config::AUDIT_FAILURE_TRUST_WEIGHT),
        )
        .await;
}

/// Handle audit result: log findings and emit trust events.
async fn handle_subtree_audit_result(
    result: &AuditTickResult,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    recent_provers: &Arc<RwLock<RecentProvers>>,
    config: &ReplicationConfig,
) {
    match result {
        AuditTickResult::Passed {
            challenged_peer,
            keys_checked,
        } => {
            debug!("Audit passed for {challenged_peer} ({keys_checked} keys)");
            // Peer responded normally — clear the active bootstrap claim while
            // retaining history so a later claim is treated as repeated abuse.
            {
                let mut state = sync_state.write().await;
                state.clear_active_bootstrap_claim(challenged_peer);
            }
            p2p_node
                .report_trust_event(
                    challenged_peer,
                    TrustEvent::ApplicationSuccess(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        AuditTickResult::Failed { evidence } => {
            if let FailureEvidence::AuditFailure {
                challenged_peer,
                confirmed_failed_keys,
                summary,
                reason,
                ..
            } = evidence
            {
                // Rich diagnostics (from main's audit-failure logging) + the
                // first-failed-key correlation handle.
                let first_failed_key = first_failed_key_label(confirmed_failed_keys);
                error!(
                    "Audit failure for {challenged_peer}: reason={reason:?}, confirmed_failed_keys={}, challenged_keys={}, absent_keys={}, digest_mismatch_keys={}, first_failed_key={first_failed_key}",
                    confirmed_failed_keys.len(),
                    summary.challenged_keys,
                    summary.absent_keys,
                    summary.digest_mismatch_keys,
                );
                // Route the side effects through the subtree-only failure path.
                // Responsible-chunk `AuditChallenge` handling intentionally uses
                // its own old immediate-penalty handler below.
                handle_subtree_failed_audit(
                    challenged_peer,
                    confirmed_failed_keys.len(),
                    reason,
                    p2p_node,
                    sync_state,
                    recent_provers,
                )
                .await;
            }
        }
        AuditTickResult::BootstrapClaim { peer } => {
            // Gap 6: BootstrapClaimAbuse grace period in audit path.
            // Separate state mutation from network I/O to avoid holding the
            // write lock across report_trust_event.
            let should_report = {
                let now = Instant::now();
                let mut state = sync_state.write().await;
                match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period)
                {
                    BootstrapClaimObservation::WithinGrace { .. } => {
                        debug!("Audit: peer {peer} claims bootstrapping (within grace period)");
                        false
                    }
                    BootstrapClaimObservation::PastGrace { first_seen } => {
                        warn!(
                            "Audit: peer {peer} claiming bootstrap past grace period \
                             ({:?} > {:?}), reporting abuse",
                            now.duration_since(first_seen),
                            config.bootstrap_claim_grace_period,
                        );
                        true
                    }
                    BootstrapClaimObservation::Repeated { first_seen } => {
                        warn!(
                            "Audit: peer {peer} repeated bootstrap claim after previously \
                             stopping; first claim was {:?} ago, reporting abuse",
                            now.duration_since(first_seen),
                        );
                        true
                    }
                }
            };
            if should_report {
                p2p_node
                    .report_trust_event(
                        peer,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::Idle | AuditTickResult::InsufficientKeys => {}
    }
}

/// Whether a confirmed audit failure with this reason clears the peer's active
/// bootstrap claim. A `Timeout` does not (the peer may still be legitimately
/// bootstrapping); every confirmed storage-integrity reason does.
///
/// Responsible-chunk `AuditChallenge` failures use this directly: timeouts keep
/// the bootstrap claim but are still reported as audit failures, matching the
/// pre-ADR-0002 behaviour.
fn audit_failure_clears_bootstrap_claim(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

/// Handle the result of a responsible-chunk audit tick (audit #2): emit trust
/// events and manage bootstrap-claim state.
///
/// This is intentionally separate from the subtree audit result handler. A
/// responsible-chunk `AuditChallenge` `Failed` result reports
/// `ApplicationFailure` immediately for every reason, including `Timeout`,
/// restoring the pre-ADR-0002 behaviour.
async fn handle_audit_result(
    result: &AuditTickResult,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    config: &ReplicationConfig,
) {
    match result {
        AuditTickResult::Passed {
            challenged_peer,
            keys_checked,
        } => {
            debug!("Audit passed for {challenged_peer} ({keys_checked} keys)");
            {
                let mut state = sync_state.write().await;
                state.clear_active_bootstrap_claim(challenged_peer);
            }
            p2p_node
                .report_trust_event(
                    challenged_peer,
                    TrustEvent::ApplicationSuccess(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        AuditTickResult::Failed { evidence } => {
            if let FailureEvidence::AuditFailure {
                challenged_peer,
                confirmed_failed_keys,
                summary,
                reason,
                ..
            } = evidence
            {
                let first_failed_key = first_failed_key_label(confirmed_failed_keys);
                error!(
                    "Audit failure for {challenged_peer}: reason={reason:?}, confirmed_failed_keys={}, challenged_keys={}, absent_keys={}, digest_mismatch_keys={}, first_failed_key={first_failed_key}",
                    confirmed_failed_keys.len(),
                    summary.challenged_keys,
                    summary.absent_keys,
                    summary.digest_mismatch_keys,
                );
                if audit_failure_clears_bootstrap_claim(reason) {
                    let mut state = sync_state.write().await;
                    state.clear_active_bootstrap_claim(challenged_peer);
                } else {
                    debug!("Audit timeout for {challenged_peer}; retaining active bootstrap claim");
                }
                p2p_node
                    .report_trust_event(
                        challenged_peer,
                        TrustEvent::ApplicationFailure(config::AUDIT_FAILURE_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::BootstrapClaim { peer } => {
            let should_report = {
                let now = Instant::now();
                let mut state = sync_state.write().await;
                match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period)
                {
                    BootstrapClaimObservation::WithinGrace { .. } => {
                        debug!("Audit: peer {peer} claims bootstrapping (within grace period)");
                        false
                    }
                    BootstrapClaimObservation::PastGrace { first_seen } => {
                        warn!(
                            "Audit: peer {peer} claiming bootstrap past grace period \
                             ({:?} > {:?}), reporting abuse",
                            now.duration_since(first_seen),
                            config.bootstrap_claim_grace_period,
                        );
                        true
                    }
                    BootstrapClaimObservation::Repeated { first_seen } => {
                        warn!(
                            "Audit: peer {peer} repeated bootstrap claim after previously \
                             stopping; first claim was {:?} ago, reporting abuse",
                            now.duration_since(first_seen),
                        );
                        true
                    }
                }
            };
            if should_report {
                p2p_node
                    .report_trust_event(
                        peer,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::Idle | AuditTickResult::InsufficientKeys => {}
    }
}

/// Whether a confirmed audit failure with this reason should revoke the
/// peer's `recent_provers` holder credit immediately (v12 §6).
///
/// `true` for any reason where the peer actually answered (or admitted
/// it cannot): `DigestMismatch`, `KeyAbsent`, `Rejected` ("missing
/// bytes for committed key"), `MalformedResponse` — these prove the
/// peer no longer holds what it committed to, so it must not keep
/// holder credit for the proof TTL. `false` for `Timeout`: a single
/// dropped packet must not strip an honest peer; the 40-min TTL is the
/// deliberate liveness cushion there.
fn audit_failure_revokes_holder_credit(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

/// Apply the holder-credit revocation decision for a confirmed audit
/// failure. Pure over `RecentProvers` so the handler wiring is unit-
/// testable without a live `P2PNode`: the production `Failed` arm of
/// `handle_subtree_audit_result` calls exactly this.
fn apply_audit_failure_credit_revocation(
    provers: &mut RecentProvers,
    challenged_peer: &PeerId,
    reason: &AuditFailureReason,
) {
    if audit_failure_revokes_holder_credit(reason) {
        provers.forget_peer(challenged_peer);
    }
}

// `admit_bootstrap_hints` was consolidated into `admit_and_queue_hints`.

// ---------------------------------------------------------------------------
// Storage-bound audit (ADR-0002) — gossip trigger + auditor-side ingestion
// ---------------------------------------------------------------------------

/// State the gossip-audit trigger needs to spawn an audit. Bundled so the
/// message handler passes one value instead of a long argument list; all
/// fields are cheap `Arc` clones.
#[derive(Clone)]
struct GossipAuditTrigger {
    p2p_node: Arc<P2PNode>,
    config: Arc<ReplicationConfig>,
    recent_provers: Arc<RwLock<RecentProvers>>,
    sync_state: Arc<RwLock<NeighborSyncState>>,
    cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
}

/// What a gossip ingest yields for the audit trigger: the commitment hash to
/// pin and the `key_count` needed to size the response deadline from the actual
/// `ceil(sqrt(N))` subtree (ADR-0002). Returned on every VALID gossip (changed
/// or not) so a stable-keyset node stays auditable — not just on its first
/// commitment.
#[derive(Debug, Clone, Copy)]
struct AuditTarget {
    pin_hash: [u8; 32],
    key_count: u32,
}

/// Per-peer audit cooldown check-and-stamp (ADR-0002 "occasional surprise
/// exams, keeps load low"). Returns `true` if `peer` may be audited now (and
/// stamps `now`), `false` if it was audited within
/// `AUDIT_ON_GOSSIP_COOLDOWN_SECS`. Bounds the map under a flood of distinct
/// peers. Pure over the passed map so the flood/cooldown behaviour is testable
/// without a live node: a burst of gossips from one peer yields at most one
/// `true` per cooldown window.
fn cooldown_allows_audit(map: &mut HashMap<PeerId, Instant>, peer: &PeerId, now: Instant) -> bool {
    let cooldown = Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS);
    let known = match map.get(peer) {
        Some(&last) => {
            if now.saturating_duration_since(last) < cooldown {
                return false;
            }
            true
        }
        None => false,
    };
    // Bound the map under churn like its siblings (drop the oldest stamp) before
    // admitting a brand-new peer.
    if !known && map.len() >= MAX_LAST_COMMITMENT_BY_PEER {
        if let Some(victim) = map.iter().min_by_key(|(_, &ts)| ts).map(|(p, _)| *p) {
            map.remove(&victim);
        }
    }
    map.insert(*peer, now);
    true
}

/// The gossip-audit launch decision in ONE place so the ordering is shared
/// between production and its test (ADR-0002 "occasional surprise exams").
///
/// Order matters and is the security-relevant property: the per-peer cooldown is
/// checked-and-stamped FIRST, THEN the probability lottery (`lottery_wins`) is
/// applied. If the lottery were sampled first, a gossip flood would re-roll it on
/// every message until one won, multiplying audits. Because the cooldown is
/// stamped before the lottery is consulted, a LOSING ticket still consumes the
/// window — so each peer gets at most one audit lottery per cooldown window
/// regardless of how often it gossips. Production calls this with
/// `lottery_wins = gen_bool(AUDIT_ON_GOSSIP_PROBABILITY)`; the test calls it with
/// a deterministic `lottery_wins`, so a reorder regression here fails the test.
fn audit_launch_decision(
    map: &mut HashMap<PeerId, Instant>,
    peer: &PeerId,
    now: Instant,
    lottery_wins: bool,
) -> bool {
    // Gate 1: cooldown check-and-stamp (consumes the window even on a loss).
    if !cooldown_allows_audit(map, peer, now) {
        return false;
    }
    // Gate 2: the probability lottery.
    lottery_wins
}

/// On a peer's *changed* gossiped commitment, maybe launch a subtree audit
/// (ADR-0002): fire with probability `AUDIT_ON_GOSSIP_PROBABILITY`, subject to a
/// per-peer cooldown, pinned to the just-ingested root. Detached so gossip
/// handling is never blocked on a network round-trip.
async fn maybe_trigger_gossip_audit(
    trigger: &GossipAuditTrigger,
    peer: &PeerId,
    target: AuditTarget,
) {
    // The launch decision (cooldown-then-lottery ordering) lives in the pure
    // `audit_launch_decision` so the ordering is shared with its test. Sample
    // the lottery here, then let the helper apply it AFTER the cooldown stamp.
    let now = Instant::now();
    let lottery_wins = rand::thread_rng().gen_bool(config::AUDIT_ON_GOSSIP_PROBABILITY);
    {
        let mut map = trigger.cooldown.write().await;
        if !audit_launch_decision(&mut map, peer, now, lottery_wins) {
            return;
        }
    }

    let trigger = trigger.clone();
    let peer = *peer;
    tokio::spawn(async move {
        let credit = storage_commitment_audit::AuditCredit {
            recent_provers: &trigger.recent_provers,
        };
        let result = storage_commitment_audit::run_subtree_audit(
            &trigger.p2p_node,
            &trigger.config,
            &peer,
            target.pin_hash,
            target.key_count,
            Some(&credit),
        )
        .await;
        handle_subtree_audit_result(
            &result,
            &trigger.p2p_node,
            &trigger.sync_state,
            &trigger.recent_provers,
            &trigger.config,
        )
        .await;
    });
}

/// Atomic check-and-stamp of the per-peer commitment sig-verify rate limit.
///
/// Returns `true` if a signature verify is allowed now (and stamps the attempt
/// time), `false` if the peer is within [`COMMITMENT_SIG_VERIFY_MIN_INTERVAL`]
/// of its last attempt. Holds one write lock across the decision so two
/// concurrent ingests from the same peer cannot both pass. Stamps BEFORE the
/// caller's expensive verify so a slow/failed verify still rate-limits the next
/// message. Bounds the map under a flood of distinct peer ids.
async fn sig_verify_rate_limit_ok(
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    source: &PeerId,
    now: Instant,
) -> bool {
    let mut attempts = sig_verify_attempts.write().await;
    if let Some(&last) = attempts.get(source) {
        if now.saturating_duration_since(last) < COMMITMENT_SIG_VERIFY_MIN_INTERVAL {
            return false;
        }
    }
    if attempts.len() >= MAX_LAST_COMMITMENT_BY_PEER && !attempts.contains_key(source) {
        if let Some(victim) = attempts.iter().min_by_key(|(_, &ts)| ts).map(|(p, _)| *p) {
            attempts.remove(&victim);
        }
    }
    attempts.insert(*source, now);
    true
}

/// Verify + store an inbound commitment from a gossip peer.
///
/// Called from the inbound `NeighborSyncRequest`/`Response` handlers and
/// the bootstrap-sync loop. Drops the commitment unless all five gates
/// pass:
///   1. `source` is in our DHT routing table (sybil/churn cap).
///   2. `commitment.sender_peer_id == source.as_bytes()` (peer-id
///      binding to the authenticated transport peer).
///   3. `BLAKE3(commitment.sender_public_key) == commitment.sender_peer_id`
///      (the embedded pubkey actually belongs to the claimed identity —
///      saorsa-core derives `PeerId = BLAKE3(pubkey)`).
///   4. `verify_commitment_signature(commitment)` succeeds against the
///      embedded public key. The signed payload binds the pubkey, so an
///      adversary cannot swap the key while keeping the body.
///   5. The cache has room or this is an update for an existing entry
///      (sybil cap, `MAX_LAST_COMMITMENT_BY_PEER`).
///
/// On all-pass, the commitment is stored as the auditor's per-peer
/// "last known commitment" for use as `expected_commitment_hash` in
/// future audits.
///
/// Failures (no commitment / mismatched peer id / bad signature) are
/// silent drops — gossip is best-effort and a malformed commitment from
/// one peer should not affect anything else.
///
/// Returns `Some(AuditTarget)` whenever a VALID commitment was stored (whether
/// or not its root changed), so the caller can run a probabilistic,
/// cooldown-gated subtree audit. Returning on *every* valid gossip — not only
/// changed ones — is deliberate (ADR-0002): a node with a stable key set keeps
/// being auditable, so it cannot pass one audit and then delete data while
/// re-gossiping the same root forever. The cooldown + probability bound the
/// audit frequency. Returns `None` only if the commitment was dropped (failed a
/// gate) or there is nothing to pin.
///
/// Handle a capable peer gossiping `None` (a commitment downgrade).
///
/// A capable peer that previously gossiped a commitment but now gossips `None`
/// is trying to drop off the audit path. Within the answerability window we keep
/// the cached commitment pinned AND return it as an audit target so this gossip
/// still schedules a subtree audit against the peer's last known commitment — if
/// it genuinely dropped the data, the audit fails (there is no periodic tick, so
/// the trigger MUST fire here or the downgrade is never re-challenged).
///
/// But this only holds within the SAME `GOSSIP_ANSWERABILITY_TTL` the responder
/// honours for its own retired commitment: once that elapses since we last
/// received the peer's commitment, an honest peer has legitimately retired that
/// root (its responder side `retire_current`s and lets it age out) and can no
/// longer answer a pin on it. Auditing it past the TTL would manufacture a false
/// failure, so we then forget the cached commitment (keeping the sticky
/// `commitment_capable` bit) and stop pinning it.
async fn handle_commitment_downgrade(
    source: &PeerId,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
) -> Option<AuditTarget> {
    let now = Instant::now();
    let cached = {
        let map = last_commitment_by_peer.read().await;
        map.get(source).and_then(|rec| {
            if !rec.commitment_capable {
                return None;
            }
            let last = rec.last_commitment()?;
            let pin = rec.commitment_hash()?;
            let fresh = now.saturating_duration_since(rec.received_at)
                < crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
            Some((pin, last.key_count, fresh))
        })
    };
    match cached {
        Some((pin, key_count, true)) => {
            warn!(
                "ingest_peer_commitment: commitment-capable peer {source} sent None \
                 (downgrade attempt); auditing against its last cached commitment"
            );
            Some(AuditTarget {
                pin_hash: pin,
                key_count,
            })
        }
        Some((_, _, false)) => {
            // Cached commitment has aged past the answerability window — forget
            // it so we stop pinning a root the peer is no longer obliged to
            // answer. Keep `commitment_capable` (sticky). Re-check freshness
            // UNDER the write lock (compare-and-clear): a concurrent valid gossip
            // from this peer may have refreshed `received_at` in the gap between
            // our read and write locks; if so, leave its fresh commitment intact.
            if let Some(rec) = last_commitment_by_peer.write().await.get_mut(source) {
                let still_stale = now.saturating_duration_since(rec.received_at)
                    >= crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
                if still_stale {
                    rec.clear_commitment();
                    debug!(
                        "ingest_peer_commitment: capable peer {source} sent None and its cached \
                         commitment aged past the answerability TTL; forgetting it"
                    );
                }
            }
            None
        }
        None => None,
    }
}

async fn ingest_peer_commitment(
    source: &PeerId,
    commitment: Option<&StorageCommitment>,
    p2p_node: &Arc<P2PNode>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
) -> Option<AuditTarget> {
    let Some(c) = commitment else {
        return handle_commitment_downgrade(source, last_commitment_by_peer).await;
    };
    // RT-membership gate: only accept commitments from peers in our
    // routing table. Off-RT senders (sybils, drive-by relays) cannot
    // populate the cache, which closes the hole where a flood of
    // off-RT identities could fill the cap and evict honest
    // peers. The neighbor-sync request handler applies the same gate
    // before admitting inbound replication hints (see neighbor_sync.rs
    // `sender_in_rt`); we mirror that policy here for the commitment
    // piggyback.
    if !p2p_node.dht_manager().is_in_routing_table(source).await {
        debug!("ingest_peer_commitment: source {source} not in routing table (dropped)");
        return None;
    }
    // Peer-id binding: the commitment's claimed sender must match the
    // authenticated transport peer (`source`). Defeats relay/replay
    // and also pins which embedded public key we are about to verify
    // against — the verify itself trusts the embedded key, so the
    // peer-id binding is the link to a real identity.
    if &c.sender_peer_id != source.as_bytes() {
        warn!(
            "ingest_peer_commitment: sender_peer_id mismatch from {source} \
             (dropped, possible relay attempt)"
        );
        return None;
    }
    // Peer-id to embedded-pubkey binding: saorsa-core derives PeerId as
    // BLAKE3(pubkey_bytes). Without this check, a responder could sign
    // with a throwaway key they own and lie about which identity it
    // belongs to (the embedded-key signature would verify trivially).
    let derived_peer_id = *blake3::hash(&c.sender_public_key).as_bytes();
    if derived_peer_id != c.sender_peer_id {
        warn!(
            "ingest_peer_commitment: embedded pubkey does not hash to claimed peer_id for \
             {source} (dropped, throwaway-key attack)"
        );
        return None;
    }
    // §2 step 3 + §11 DoS: rate-limit per-peer to at most one ML-DSA
    // signature verify per `COMMITMENT_SIG_VERIFY_MIN_INTERVAL`. A
    // sybil/RT-membership-bypassing peer that flooded valid-looking
    // gossip would otherwise burn CPU on every message. The rate
    // limit is checked AFTER cheap structural gates (RT, peer-id
    // binding, pubkey-binding) and BEFORE the expensive sig verify.
    //
    // Tracked in `sig_verify_attempts` (separate from
    // last_commitment_by_peer) so EVERY attempt — successful or not —
    // bumps the rate-limit clock. Reading only from PeerCommitmentRecord
    // would skip the cap for peers we've never successfully verified,
    // letting a flood of invalid-but-structurally-plausible gossips
    // burn CPU.
    let now = Instant::now();
    if !sig_verify_rate_limit_ok(sig_verify_attempts, source, now).await {
        debug!(
            "ingest_peer_commitment: rate-limited sig verify from {source} \
             (< {COMMITMENT_SIG_VERIFY_MIN_INTERVAL:?} since last attempt); dropped"
        );
        return None;
    }
    // Signature verify, using the public key embedded in the commitment
    // itself. The pubkey is bound by the signature payload (see
    // commitment_signed_payload) so an adversary cannot keep the body
    // and swap the key to one they hold the secret for.
    if !crate::replication::commitment::verify_commitment_signature(c) {
        warn!(
            "ingest_peer_commitment: signature did not verify under embedded key for {source} \
             (dropped, forged commitment)"
        );
        return None;
    }
    // The new commitment's hash, used to store and to pin for the audit target.
    let new_hash = commitment_hash(c);
    let mut map = last_commitment_by_peer.write().await;
    // Sybil/churn cap: if we're at the hard cap AND this is a new peer,
    // evict an arbitrary existing entry to make room. Updates for peers
    // already in the map are always accepted (they replace, not grow).
    if map.len() >= MAX_LAST_COMMITMENT_BY_PEER && !map.contains_key(source) {
        // Drop one arbitrary entry. HashMap iter order is random which
        // is fine — over time PeerRemoved cleanup keeps the working set
        // anchored on the real RT membership; this cap only fires under
        // active flooding attempts.
        if let Some(victim) = map.keys().next().copied() {
            map.remove(&victim);
            warn!(
                "ingest_peer_commitment: cache full ({MAX_LAST_COMMITMENT_BY_PEER}); \
                 evicted {victim} to admit {source}"
            );
        }
    }
    // Preserve sticky commitment_capable across updates — once true,
    // always true. New entries start with capable = true (we just
    // verified a valid commitment from this peer).
    map.entry(*source)
        .and_modify(|r| {
            // set_commitment refreshes the cached hash (§13) alongside the
            // commitment + received_at so they never drift.
            r.set_commitment(c.clone(), now);
            r.last_sig_verify_at = now;
            r.commitment_capable = true; // sticky-redundant but explicit
        })
        .or_insert_with(|| PeerCommitmentRecord::from_verified(c.clone(), now));
    drop(map);
    // Record the sticky "ever v12-capable" bit in a set independent of
    // `last_commitment_by_peer` (whose entries can be evicted by
    // `PeerRemoved` and the sybil cap). This is what the §3 audit
    // shield and the §6 holder-eligibility closure consult to decide
    // whether the peer is expected to speak v12.
    //
    // Capped at `MAX_EVER_CAPABLE_PEERS` to bound memory under
    // identity-rotation attacks: once full, new entries are refused.
    // Refusal degrades over-cap peers to the behaviour before this set
    // existed (treated as legacy on rejoin), which is not a security
    // regression and preserves the historic set stable.
    {
        let mut set = ever_capable_peers.write().await;
        if set.contains(source) || set.len() < MAX_EVER_CAPABLE_PEERS {
            set.insert(*source);
        } else {
            warn!(
                "ingest_peer_commitment: ever_capable_peers at cap \
                 ({MAX_EVER_CAPABLE_PEERS}); refusing to record {source} as sticky-capable"
            );
        }
    }
    // Return an audit target for EVERY valid stored commitment (changed or
    // not), so the caller's cooldown+probability-gated trigger keeps a
    // stable-keyset peer auditable over time (ADR-0002). Only a serialization
    // failure (new_hash == None, unreachable for a real commitment) yields None.
    new_hash.map(|pin_hash| AuditTarget {
        pin_hash,
        key_count: c.key_count,
    })
}

// ---------------------------------------------------------------------------
// Storage-bound audit (v12) — responder commitment rotation
// ---------------------------------------------------------------------------

/// Read the current LMDB key set, build + sign a fresh
/// `StorageCommitment`, and rotate it into `state` as the new `current`.
/// The prior `current` is demoted to `previous`; the prior `previous` is
/// dropped (per `ResponderCommitmentState::rotate`).
///
/// For content-addressed chunks (Autonomi's chunk store), `address ==
/// BLAKE3(content)`, so `bytes_hash := key` and we don't have to
/// re-read each chunk's bytes to compute the leaf hash.
///
/// Skips (returns `Ok(())`) if the key set is empty — no commitment to
/// rotate. The auditor side handles "no commitment for this peer" by
/// falling back to the legacy plain-digest audit path.
async fn rebuild_and_rotate_commitment(
    storage: &Arc<LmdbStorage>,
    identity: &Arc<NodeIdentity>,
    state: &Arc<ResponderCommitmentState>,
    p2p: &Arc<P2PNode>,
    config: &Arc<ReplicationConfig>,
) -> Result<()> {
    use saorsa_pqc::api::sig::{MlDsaSecretKey, MlDsaVariant};

    let stored_keys = storage
        .all_keys()
        .await
        .map_err(|e| Error::Storage(format!("commitment build: read keys: {e}")))?;

    // Commit only to keys we are still RESPONSIBLE for ("want-to-hold"), not
    // everything currently on disk ("hold"). This is the half of the retention
    // contract that lets out-of-range chunks age out: a key that has left our
    // close group is excluded from the NEXT commitment, so within at most
    // RETAINED_GOSSIPED_COMMITMENTS gossip rotations it falls out of the
    // last-2-gossiped window, `ResponderCommitmentState::is_held` goes false,
    // and the pruner (which until then vetoes its deletion) reclaims it. Without
    // this filter the pruner's reprieve would keep re-committing stale keys
    // forever (the rebuild reads all_keys, so a retained-on-disk key would be
    // re-committed and re-gossiped every rotation — a permanent pin).
    let storage_empty = stored_keys.is_empty();
    let self_id = *p2p.peer_id();
    let mut keys = Vec::with_capacity(stored_keys.len());
    for k in stored_keys {
        if admission::is_responsible(&self_id, &k, p2p, config.close_group_size).await {
            keys.push(k);
        }
    }

    if keys.is_empty() {
        if storage_empty {
            // Storage is genuinely empty — there is nothing to answer for, so
            // drop the previously advertised commitment immediately. Keeping it
            // would leave remote auditors pinning a hash we can never satisfy
            // again (the bytes are gone).
            if state.retained_slot_count() > 0 {
                debug!("Commitment rotation: storage empty, clearing retained slots");
                state.clear_all();
            }
            return Ok(());
        }
        // Bytes are still on disk but no key is currently in range. We must NOT
        // clear retention here: a peer may still be pinning a root we gossiped
        // moments ago and could demand its bytes in a round-2 challenge, which
        // we can still answer (the bytes are present). But we must STOP
        // advertising the stale commitment: retire it so `current()` returns
        // `None` and the gossip-emit sites stop re-emitting and re-stamping it.
        // The retired slot then ages out by its gossip-answerability TTL while
        // remaining answerable for in-flight pins until then. Once it ages out,
        // `is_held` flips false and the pruner reclaims the now-uncommitted,
        // out-of-range chunks. (Calling `age_out` alone would leave `current()`
        // pointing at the stale root, which the gossip loop would keep
        // re-stamping — pinning its keys forever.)
        debug!(
            "Commitment rotation: no responsible keys to commit to; retiring current commitment \
             (stays answerable until its gossip TTL lapses, bytes still on disk)"
        );
        state.retire_current();
        return Ok(());
    }

    // Cap to MAX_COMMITMENT_KEY_COUNT for v12 (responder must not commit
    // to more than the protocol limit; auditor would reject the
    // commitment otherwise).
    let cap = commitment::MAX_COMMITMENT_KEY_COUNT as usize;
    if keys.len() > cap {
        warn!(
            "Commitment rotation: key set ({}) exceeds MAX_COMMITMENT_KEY_COUNT ({}); \
             truncating — investigate as this likely means a misconfiguration",
            keys.len(),
            cap
        );
    }

    // INVARIANT: this module is only used with CONTENT-ADDRESSED chunks,
    // where `key == BLAKE3(content)`, so `bytes_hash := key` and we skip a
    // full chunk re-read per rotation.
    //
    // Consequence to be precise about: because the leaf is `(key, key)`,
    // the Merkle root commits to the SET OF KEYS, not to the bytes. The
    // commitment therefore binds "which keys I claim to hold"; it does NOT
    // by itself prove byte possession. Byte possession is enforced by the
    // audit-verify path, which recomputes `bytes_hash == BLAKE3(local_bytes)`
    // and the per-key digest against the AUDITOR'S OWN local copy of the
    // bytes — so a responder that holds the key list but dropped the bytes
    // still fails (`missing bytes for committed key` / digest mismatch).
    // This is sound ONLY while keys are content addresses. If this module
    // is ever reused for non-content-addressed records (`bytes_hash != key`),
    // the `(k, k)` shortcut would let a byte-less node forge a valid root and
    // MUST be replaced with `(key, BLAKE3(bytes))` computed from real bytes.
    let entries: Vec<_> = keys.into_iter().take(cap).map(|k| (k, k)).collect();

    // No-op-rotation guard: compute just the Merkle root from `entries`
    // and compare against the currently-advertised commitment's root.
    // If they match, the key set is unchanged and a new rotation would
    // only swap a randomized ML-DSA signature for a fresh one — same
    // content, different commitment_hash. That invalidates every
    // outstanding `recent_provers` credit on this node across the
    // close group with no security benefit, breaking steady-state
    // quorum liveness on large nodes that can't re-audit every key
    // every rotation interval. Skip the rotation entirely when the
    // tree is unchanged.
    // Build the tree ONCE here (moving `entries`): it serves both the no-op
    // root check below and, if we proceed, the signed commitment via
    // `build_from_tree` (§11 — previously the tree was built here and AGAIN
    // inside `BuiltCommitment::build`).
    let candidate_tree = commitment::MerkleTree::build(entries)
        .map_err(|e| Error::Crypto(format!("commitment tree build: {e}")))?;
    let candidate_root = candidate_tree.root();
    if let Some(current) = state.current() {
        if current.commitment().root == candidate_root {
            debug!(
                "Commitment rotation: key set unchanged (root={}); skipping no-op re-sign",
                hex::encode(candidate_root)
            );
            // Even though we skip re-signing (to avoid invalidating holder
            // credit), retention must still advance on the wall clock: a
            // previously-gossiped commitment that holds a now-out-of-range key
            // must be able to age out of the answerability window even when the
            // committed key set is frozen here for many rotations. Without this,
            // the no-op guard would pin a stale slot — and its key — forever.
            state.age_out();
            return Ok(());
        }
    }

    let sk_bytes = identity.secret_key_bytes().to_vec();
    let sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .map_err(|e| Error::Crypto(format!("commitment build: load sk: {e}")))?;
    let pk_bytes = identity.public_key().as_bytes().to_vec();
    let peer_id_bytes = *p2p.peer_id().as_bytes();

    let built = commitment_state::BuiltCommitment::build_from_tree(
        candidate_tree,
        &peer_id_bytes,
        &sk,
        &pk_bytes,
    )
    .map_err(|e| Error::Crypto(format!("commitment build: {e}")))?;

    let hash = hex::encode(built.hash());
    let key_count = built.commitment().key_count;
    state.rotate(built);
    info!("Storage commitment rotated: hash={hash} key_count={key_count}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        add_replica_hint_sender_source, apply_audit_failure_credit_revocation,
        audit_failure_clears_bootstrap_claim, audit_failure_revokes_holder_credit,
        audit_launch_decision, config, cooldown_allows_audit, first_failed_key_label,
        fresh_offer_payment_context, paid_notify_payment_context,
    };
    use crate::payment::VerificationContext;
    use crate::replication::recent_provers::RecentProvers;
    use crate::replication::types::{AuditFailureReason, HintPipeline};
    use saorsa_core::identity::PeerId;
    use std::collections::HashMap;
    use std::time::Duration;
    use std::time::Instant;

    fn test_peer(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    fn test_key(b: u8) -> crate::ant_protocol::XorName {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    #[test]
    fn fresh_offer_runs_client_put_payment_checks() {
        assert_eq!(
            fresh_offer_payment_context(),
            VerificationContext::ClientPut
        );
    }

    #[test]
    fn paid_notify_uses_paid_list_admission_payment_checks() {
        assert_eq!(
            paid_notify_payment_context(),
            VerificationContext::PaidListAdmission
        );
    }

    #[test]
    fn replica_hint_sender_is_added_as_fallback_fetch_source() {
        const EXISTING_SOURCE_ID: u8 = 1;
        const HINT_SENDER_ID: u8 = 2;
        const PAID_ONLY_SENDER_ID: u8 = 3;

        let existing_source = test_peer(EXISTING_SOURCE_ID);
        let hint_sender = test_peer(HINT_SENDER_ID);
        let paid_only_sender = test_peer(PAID_ONLY_SENDER_ID);
        let mut sources = vec![existing_source];

        add_replica_hint_sender_source(&mut sources, HintPipeline::Replica, hint_sender);
        add_replica_hint_sender_source(&mut sources, HintPipeline::Replica, hint_sender);
        add_replica_hint_sender_source(&mut sources, HintPipeline::PaidOnly, paid_only_sender);

        assert_eq!(sources, vec![existing_source, hint_sender]);
    }

    #[test]
    fn audit_timeout_preserves_active_bootstrap_claim() {
        assert!(!audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::Timeout
        ));
    }

    fn strike_peer(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    // ADR-0002: "occasional surprise exams, keeps load low" — the per-peer
    // cooldown must collapse a gossip flood into at most one audit per window.

    #[test]
    fn gossip_flood_yields_at_most_one_audit_per_cooldown_window() {
        let peer = strike_peer(1);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        // First gossip in the window passes; a burst of further gossips at the
        // same instant are all suppressed.
        assert!(cooldown_allows_audit(&mut map, &peer, t0));
        let mut passed = 1;
        for _ in 0..100 {
            if cooldown_allows_audit(&mut map, &peer, t0) {
                passed += 1;
            }
        }
        assert_eq!(
            passed, 1,
            "a flood at one instant must trigger exactly one audit"
        );
    }

    // ADR-0002 ordering invariant: `maybe_trigger_gossip_audit` stamps the
    // per-peer cooldown BEFORE the probability lottery, so a LOSING ticket still
    // consumes the window. This is the property the isolated cooldown tests above
    // cannot see: they never sample the lottery, so a regression that reordered
    // the gates (sample probability first, only stamp the cooldown on a win)
    // would still pass them while breaking flood-resistance: a flood would then
    // re-roll the lottery on EVERY message until one won, multiplying audits.
    //
    // We model the exact production gate order (cooldown-then-lottery) with a
    // lottery driven by a fixed outcome instead of `gen_bool(..)`. The first
    // message LOSES the lottery; the remaining flood messages all WIN. With the
    // production order, the losing first ticket burns the window and every later
    // winner in the same window is blocked, so there are 0 audits this window. If
    // the gates were flipped, the second message's winning ticket would slip
    // through. The window only reopens after the cooldown elapses.
    //
    // FLIPS IF: the lottery is sampled before `cooldown_allows_audit` (a losing
    // ticket no longer consumes the window), re-enabling a flood-amplified audit
    // storm.
    #[test]
    fn losing_lottery_still_consumes_cooldown_window() {
        // Faithful re-implementation of the two gates in
        // `maybe_trigger_gossip_audit`, with the lottery outcome made
        // deterministic instead of `rand::thread_rng().gen_bool(..)`.
        // Calls the SHIPPED `audit_launch_decision` (the same function
        // `maybe_trigger_gossip_audit` uses), so a reorder of the two gates in
        // production fails this test — not a local reimplementation.
        let peer = strike_peer(3);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();

        // First flooded message at t0 LOSES the lottery, but the cooldown is
        // stamped BEFORE the lottery is consulted, so the window is now consumed.
        assert!(
            !audit_launch_decision(&mut map, &peer, t0, false),
            "a losing ticket launches no audit"
        );

        // 99 more flooded messages at the same instant would all WIN the lottery,
        // yet every one must be blocked by the cooldown the loser already stamped.
        // (If production sampled the lottery FIRST, these would each get a fresh
        // roll and audits would multiply — this assertion catches that reorder.)
        let mut audits = 0;
        for _ in 0..99 {
            if audit_launch_decision(&mut map, &peer, t0, true) {
                audits += 1;
            }
        }
        assert_eq!(
            audits, 0,
            "a losing first ticket must consume the window so no later flooded \
             message in the same window can audit"
        );

        // The window only reopens after the cooldown elapses; the next winning
        // ticket then launches exactly one audit.
        let after = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1);
        assert!(
            audit_launch_decision(&mut map, &peer, after, true),
            "after the cooldown a winning ticket audits again"
        );
    }

    #[test]
    fn cooldown_lets_audit_through_after_the_window() {
        let peer = strike_peer(2);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        assert!(cooldown_allows_audit(&mut map, &peer, t0));
        // Within the window: suppressed.
        let within = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS - 1);
        assert!(!cooldown_allows_audit(&mut map, &peer, within));
        // Past the window: allowed again.
        let after = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1);
        assert!(cooldown_allows_audit(&mut map, &peer, after));
    }

    #[test]
    fn cooldown_is_per_peer_independent() {
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        // Different peers each get their own first-audit pass at the same instant.
        for i in 0..20u8 {
            assert!(
                cooldown_allows_audit(&mut map, &strike_peer(i), t0),
                "peer {i} should be auditable independently"
            );
        }
    }

    #[test]
    fn audit_on_gossip_constants_match_adr() {
        // Tripwire on the ADR-locked tunables. The spot-check count sits at the
        // top of the auditor's 3..=5 band (the auditor clamps to that band, so
        // values above 5 would silently never be requested).
        assert_eq!(config::AUDIT_SPOTCHECK_COUNT, 5);
        assert!((config::AUDIT_ON_GOSSIP_PROBABILITY - 0.2).abs() < f64::EPSILON);
        assert_eq!(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS, 30 * 60);
    }

    // (d) A confirmed storage-integrity failure penalizes immediately and
    // revokes credit; it is not a timeout.
    #[test]
    fn digest_mismatch_is_not_a_timeout_and_penalizes_immediately() {
        assert!(audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::DigestMismatch
        ));
        assert!(audit_failure_revokes_holder_credit(
            &AuditFailureReason::DigestMismatch
        ));
    }

    /// The exact decision the `Failed` arm of `handle_subtree_audit_result`
    /// uses: confirmed failures revoke credit, `Timeout` does not.
    #[test]
    fn confirmed_failures_revoke_credit_timeout_does_not() {
        for reason in [
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_revokes_holder_credit(&reason),
                "confirmed failure {reason:?} must revoke holder credit"
            );
        }
        assert!(
            !audit_failure_revokes_holder_credit(&AuditFailureReason::Timeout),
            "Timeout must NOT revoke credit (single dropped packet != storage loss)"
        );
    }

    /// Wiring test for the security fix: the helper the handler calls
    /// actually strips a credited peer on a confirmed failure
    /// (`DigestMismatch`), and actually RETAINS credit on `Timeout`.
    /// Records genuine credit first so neither assertion is vacuous;
    /// this fails if `forget_peer` stops being called, or if the
    /// `Timeout` exclusion is dropped (both verified by mutation).
    #[test]
    fn apply_revocation_strips_on_digest_mismatch_retains_on_timeout() {
        let peer = test_peer(0xAB);
        let key = test_key(1);
        let hash = [0xCD; 32];

        // Confirmed failure -> credit revoked.
        let mut provers = RecentProvers::new();
        provers.record_proof(key, peer, hash, Instant::now());
        assert!(
            provers.is_credited_holder(&key, &peer, &hash),
            "precondition: peer credited before failure"
        );
        apply_audit_failure_credit_revocation(
            &mut provers,
            &peer,
            &AuditFailureReason::DigestMismatch,
        );
        assert!(
            !provers.is_credited_holder(&key, &peer, &hash),
            "DigestMismatch must strip the peer's holder credit"
        );

        // Timeout -> credit retained.
        let mut provers_timeout = RecentProvers::new();
        provers_timeout.record_proof(key, peer, hash, Instant::now());
        apply_audit_failure_credit_revocation(
            &mut provers_timeout,
            &peer,
            &AuditFailureReason::Timeout,
        );
        assert!(
            provers_timeout.is_credited_holder(&key, &peer, &hash),
            "Timeout must retain holder credit (deliberate liveness cushion)"
        );
    }

    #[test]
    fn decoded_audit_failures_clear_active_bootstrap_claim() {
        for reason in [
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_clears_bootstrap_claim(&reason),
                "decoded non-bootstrap failure {reason:?} should clear active claim"
            );
        }
    }

    #[test]
    fn first_failed_key_label_truncates_to_16_hex_chars() {
        // The high-order 8 bytes of the XorName determine the label so an
        // operator can group audit-failures on the same chunk prefix.
        let mut key = [0u8; 32];
        key[0] = 0x18;
        key[7] = 0xff;
        // Low-order bytes (positions 8..32) are deliberately set to 0xAA
        // to verify they are NOT included in the label.
        for byte in &mut key[8..] {
            *byte = 0xAA;
        }
        let label = first_failed_key_label(&[key]);
        // Only the first 8 bytes are encoded, low-order bytes are dropped.
        assert_eq!(label, "0x18000000000000ff");
        assert_eq!(label.len(), "0x".len() + 16);
    }

    #[test]
    fn first_failed_key_label_falls_back_when_empty() {
        // Should never happen in production (audit failure handling rejects
        // empty sets), but the formatter must still produce a valid label
        // so the log line doesn't contain a misleading default.
        assert_eq!(first_failed_key_label(&[]), "0x");
    }

    #[test]
    fn first_failed_key_label_uses_first_key_only() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        assert_eq!(
            first_failed_key_label(&[first, second]),
            format!("0x{}", hex::encode(&first[..8]))
        );
    }
}
