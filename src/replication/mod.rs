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
pub mod config;
pub mod fresh;
pub mod neighbor_sync;
pub mod paid_list;
pub mod protocol;
pub mod pruning;
pub mod quorum;
pub mod scheduling;
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
use tokio::sync::{mpsc, Notify, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::payment::PaymentVerifier;
use crate::replication::audit::AuditTickResult;
use crate::replication::config::{
    max_parallel_fetch, ReplicationConfig, MAX_CONCURRENT_REPLICATION_SENDS,
    REPLICATION_PROTOCOL_ID,
};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    FreshReplicationResponse, NeighborSyncResponse, ReplicationMessage, ReplicationMessageBody,
    VerificationResponse,
};
use crate::replication::quorum::KeyVerificationOutcome;
use crate::replication::scheduling::ReplicationQueues;
use crate::replication::types::{
    AuditFailureReason, BootstrapClaimObservation, BootstrapState, FailureEvidence, HintPipeline,
    NeighborSyncState, PeerSyncRecord, RepairProofs, VerificationEntry, VerificationState,
};
use crate::storage::LmdbStorage;
use saorsa_core::identity::PeerId;
use saorsa_core::{DhtNetworkEvent, P2PEvent, P2PNode, TrustEvent};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix used by saorsa-core's request-response mechanism.
const RR_PREFIX: &str = "/rr/";

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
}

/// Fetch worker polling interval in milliseconds.
const FETCH_WORKER_POLL_MS: u64 = 100;

/// Verification worker polling interval in milliseconds.
const VERIFICATION_WORKER_POLL_MS: u64 = 250;

/// Bootstrap drain check interval in seconds.
const BOOTSTRAP_DRAIN_CHECK_SECS: u64 = 5;

/// Standard trust event weight for per-operation success/failure signals.
///
/// Used for individual replication fetch outcomes, integrity check failures,
/// and bootstrap claim abuse. Distinct from `AUDIT_FAILURE_TRUST_WEIGHT` which
/// is reserved for confirmed audit failures.
const REPLICATION_TRUST_WEIGHT: f64 = 1.0;

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
    /// Limits concurrent outbound replication sends to prevent bandwidth
    /// saturation on home broadband connections.
    send_semaphore: Arc<Semaphore>,
    /// Receiver for fresh-write events from the chunk PUT handler.
    ///
    /// When present, `start()` spawns a drainer task that calls
    /// `replicate_fresh` for each event.
    fresh_write_rx: Option<mpsc::UnboundedReceiver<fresh::FreshWriteEvent>>,
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
    pub async fn new(
        config: ReplicationConfig,
        p2p_node: Arc<P2PNode>,
        storage: Arc<LmdbStorage>,
        payment_verifier: Arc<PaymentVerifier>,
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

        Ok(Self {
            config: Arc::clone(&config),
            p2p_node,
            storage,
            paid_list,
            payment_verifier,
            queues: Arc::new(RwLock::new(ReplicationQueues::new())),
            sync_state: Arc::new(RwLock::new(initial_neighbors)),
            sync_history: Arc::new(RwLock::new(HashMap::new())),
            sync_cycle_epoch: Arc::new(RwLock::new(0)),
            repair_proofs: Arc::new(RwLock::new(RepairProofs::new())),
            bootstrap_state: Arc::new(RwLock::new(BootstrapState::new())),
            is_bootstrapping: Arc::new(RwLock::new(true)),
            sync_trigger: Arc::new(Notify::new()),
            bootstrap_complete_notify: Arc::new(Notify::new()),
            send_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REPLICATION_SENDS)),
            fresh_write_rx: Some(fresh_write_rx),
            shutdown,
            task_handles: Vec::new(),
        })
    }

    /// Get a reference to the `PaidList`.
    #[must_use]
    pub fn paid_list(&self) -> &Arc<PaidList> {
        &self.paid_list
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
        self.start_audit_loop();
        self.start_fetch_worker();
        self.start_verification_worker();
        self.start_bootstrap_sync(dht_events);
        self.start_fresh_write_drainer();

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

    /// Execute fresh replication for a newly stored record.
    pub async fn replicate_fresh(&self, key: &XorName, data: &[u8], proof_of_payment: &[u8]) {
        fresh::replicate_fresh(
            key,
            data,
            proof_of_payment,
            &self.p2p_node,
            &self.paid_list,
            &self.config,
            &self.send_semaphore,
        )
        .await;
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
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        fresh::replicate_fresh(
                            &event.key,
                            &event.data,
                            &event.payment_proof,
                            &p2p,
                            &paid_list,
                            &config,
                            &send_semaphore,
                        )
                        .await;
                    }
                }
            }
            debug!("Fresh-write drainer shut down");
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
                        let Ok(dht_event) = dht_event else { continue };
                        match dht_event {
                            DhtNetworkEvent::KClosestPeersChanged { .. } => {
                                debug!(
                                    "K-closest peers changed, triggering early neighbor sync"
                                );
                                sync_trigger.notify_one();
                            }
                            DhtNetworkEvent::PeerRemoved { peer_id } => {
                                repair_proofs.write().await.remove_peer(&peer_id);
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

        let handle = tokio::spawn(async move {
            loop {
                let interval = config.random_neighbor_sync_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {}
                    () = sync_trigger.notified() => {
                        debug!("Neighbor sync triggered by topology change");
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
                        q.start_fetch(candidate.key, source, candidate.sources.clone());

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
                                        q.complete_fetch(&key);
                                        true
                                    }
                                }
                            }
                        } else {
                            // Task panicked — reclaim the in-flight slot.
                            q.complete_fetch(&key);
                            true
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

                for peer in batch {
                    if shutdown.is_cancelled() {
                        break;
                    }

                    // Re-read on each iteration so peers see current state.
                    let bootstrapping = *is_bootstrapping.read().await;

                    bootstrap::increment_pending_requests(&bootstrap_state, 1).await;

                    let outcome = neighbor_sync::sync_with_peer_with_outcome(
                        peer,
                        &p2p,
                        &storage,
                        &paid_list,
                        &config,
                        bootstrapping,
                    )
                    .await;

                    bootstrap::decrement_pending_requests(&bootstrap_state, 1).await;

                    if let Some(outcome) = outcome {
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

/// Handle an incoming replication protocol message.
///
/// When `rr_message_id` is `Some`, the request arrived via the `/rr/`
/// request-response path and the response must be sent via `send_response`
/// so saorsa-core can route it back to the waiting `send_request` caller.
#[allow(clippy::too_many_arguments)]
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
        ReplicationMessageBody::AuditChallenge(ref challenge) => {
            let bootstrapping = *is_bootstrapping.read().await;
            handle_audit_challenge_msg(
                source,
                challenge,
                storage,
                p2p_node,
                bootstrapping,
                msg.request_id,
                rr_message_id,
            )
            .await
        }
        // Response messages are handled by their respective request initiators.
        ReplicationMessageBody::FreshReplicationResponse(_)
        | ReplicationMessageBody::NeighborSyncResponse(_)
        | ReplicationMessageBody::VerificationResponse(_)
        | ReplicationMessageBody::FetchResponse(_)
        | ReplicationMessageBody::AuditResponse(_) => Ok(()),
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

    // Rule 7: check responsibility.
    if !admission::is_responsible(&self_id, &offer.key, p2p_node, config.close_group_size).await {
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: offer.key,
                reason: "Not responsible for this key".to_string(),
            }),
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Gap 1: Validate PoP via PaymentVerifier.
    match payment_verifier
        .verify_payment(&offer.key, Some(&offer.proof_of_payment))
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
                        reason: format!("Storage error: {e}"),
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

    // Gap 1: Validate PoP via PaymentVerifier.
    match payment_verifier
        .verify_payment(&notify.key, Some(&notify.proof_of_payment))
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
    // No per-request key count limit: the wire message size limit
    // (MAX_REPLICATION_MESSAGE_SIZE) already caps the payload. Verification
    // does cheap storage lookups per key, not expensive computation like
    // audit digest generation.

    #[allow(clippy::cast_possible_truncation)]
    let keys_len = request.keys.len() as u32;
    let paid_check_set: HashSet<u32> = request
        .paid_list_check_indices
        .iter()
        .copied()
        .filter(|&idx| {
            if idx >= keys_len {
                warn!(
                    "Verification request from {source}: paid_list_check_index {idx} out of bounds (keys.len() = {})",
                    request.keys.len(),
                );
                false
            } else {
                true
            }
        })
        .collect();

    let mut results = Vec::with_capacity(request.keys.len());
    for (i, key) in request.keys.iter().enumerate() {
        let present = storage.exists(key).unwrap_or(false);
        let paid = if paid_check_set.contains(&u32::try_from(i).unwrap_or(u32::MAX)) {
            Some(paid_list.contains(key).unwrap_or(false))
        } else {
            None
        };
        results.push(protocol::KeyVerificationResult {
            key: *key,
            present,
            paid,
        });
    }

    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::VerificationResponse(VerificationResponse { results }),
        rr_message_id,
    )
    .await;

    Ok(())
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
    let response = audit::handle_audit_challenge(
        challenge,
        storage,
        p2p_node.peer_id(),
        is_bootstrapping,
        stored_chunks,
    )
    .await;

    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::AuditResponse(response),
        rr_message_id,
    )
    .await;

    Ok(())
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
) {
    let self_id = *p2p_node.peer_id();
    let bootstrapping = *is_bootstrapping.read().await;

    // Check if cycle is complete; start new one if needed.
    // We check under a read lock, then release it before the expensive
    // prune pass and DHT snapshot so other tasks are not starved.
    let cycle_complete = sync_state.read().await.is_cycle_complete();
    if cycle_complete {
        // A completed local neighbor-sync cycle matures key-specific repair
        // proofs recorded in earlier epochs.
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
            allow_remote_prune_audits,
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

    // Sync with each peer in the batch.
    for peer in &batch {
        let outcome = neighbor_sync::sync_with_peer_with_outcome(
            peer,
            p2p_node,
            storage,
            paid_list,
            config,
            bootstrapping,
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
                let replacement_outcome = neighbor_sync::sync_with_peer_with_outcome(
                    &replacement_peer,
                    p2p_node,
                    storage,
                    paid_list,
                    config,
                    bootstrapping,
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
) {
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
    let VerificationCycleContext {
        p2p_node,
        paid_list,
        storage,
        queues,
        config,
        bootstrap_state,
        is_bootstrapping,
        bootstrap_complete_notify,
    } = ctx;

    // Evict stale entries that have been pending too long (e.g. unreachable
    // verification targets during a network partition).
    {
        let mut q = queues.write().await;
        q.evict_stale(config::PENDING_VERIFY_MAX_AGE);
    }

    let pending_keys = {
        let q = queues.read().await;
        q.pending_keys()
    };

    if pending_keys.is_empty() {
        return;
    }

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
                            // responsibility check outside this lock: if we
                            // are also in the storage close group, the hint
                            // can repair a missing replica.
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
            } else if admission::is_responsible(&self_id, &key, p2p_node, config.close_group_size)
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
            let sources = evidence.get(&key).map_or_else(Vec::new, |ev| {
                quorum::present_sources_for_key(&key, ev, &targets)
            });
            if sources.is_empty() {
                // Terminal failure: remove pending and report. No fetch path.
                q.remove_pending(&key);
                warn!(
                    "Locally paid key {} has no responding holders (possible data loss)",
                    hex::encode(key)
                );
                terminal_keys.push(key);
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
        let mut evaluated: Vec<(XorName, KeyVerificationOutcome, HintPipeline)> = Vec::new();
        {
            let q = queues.read().await;
            for key in &keys_needing_network {
                let Some(ev) = evidence.get(key) else {
                    continue;
                };
                let Some(entry) = q.get_pending(key) else {
                    continue;
                };
                let outcome = quorum::evaluate_key_evidence(key, ev, &targets, config);
                evaluated.push((*key, outcome, entry.pipeline));
            }
        } // read lock released

        // Step 4: Insert verified keys into PaidForList (no lock held).
        let mut paid_insert_keys: Vec<XorName> = Vec::new();
        for (key, outcome, _) in &evaluated {
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
        // also storage-responsible for the key, a verified paid-only hint can
        // safely repair a missing replica using sources from the same
        // verification round.
        let mut paid_only_fetch_keys: HashSet<XorName> = HashSet::new();
        for (key, outcome, pipeline) in &evaluated {
            if *pipeline == HintPipeline::PaidOnly
                && matches!(
                    outcome,
                    KeyVerificationOutcome::QuorumVerified { .. }
                        | KeyVerificationOutcome::PaidListVerified { .. }
                )
                && !storage.exists(key).unwrap_or(false)
                && admission::is_responsible(&self_id, key, p2p_node, config.close_group_size).await
            {
                paid_only_fetch_keys.insert(*key);
            }
        }

        // Step 5: Update queues with the evaluated outcomes.
        let mut q = queues.write().await;
        for (key, outcome, pipeline) in evaluated {
            match outcome {
                KeyVerificationOutcome::QuorumVerified { sources }
                | KeyVerificationOutcome::PaidListVerified { sources } => {
                    let fetch_eligible =
                        pipeline == HintPipeline::Replica || paid_only_fetch_keys.contains(&key);
                    if fetch_eligible && !sources.is_empty() {
                        let distance =
                            crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                        // Atomic remove+enqueue: on fetch_queue capacity miss
                        // the pending entry is preserved so this verified key
                        // is retried on the next cycle (no silent drop).
                        let _ = q.promote_pending_to_fetch(key, distance, sources);
                        // Not terminal — either moved to fetch queue, or
                        // retained as pending until queue drains.
                    } else if fetch_eligible && sources.is_empty() {
                        warn!(
                            "Verified responsible key {} has no holders (possible data loss)",
                            hex::encode(key)
                        );
                        q.remove_pending(&key);
                        terminal_keys.push(key);
                    } else {
                        q.remove_pending(&key);
                        terminal_keys.push(key);
                    }
                }
                KeyVerificationOutcome::QuorumFailed
                | KeyVerificationOutcome::QuorumInconclusive => {
                    q.remove_pending(&key);
                    terminal_keys.push(key);
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

/// Handle audit result: log findings and emit trust events.
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
                reason,
                ..
            } = evidence
            {
                error!(
                    "Audit failure for {challenged_peer}: {} confirmed failed keys",
                    confirmed_failed_keys.len()
                );
                if audit_failure_clears_bootstrap_claim(reason) {
                    // Peer returned a non-bootstrap response — clear the active
                    // claim while retaining claim history.
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

fn audit_failure_clears_bootstrap_claim(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

// `admit_bootstrap_hints` was consolidated into `admit_and_queue_hints`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::audit_failure_clears_bootstrap_claim;
    use crate::replication::types::AuditFailureReason;

    #[test]
    fn audit_timeout_preserves_active_bootstrap_claim() {
        assert!(!audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::Timeout
        ));
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
}
