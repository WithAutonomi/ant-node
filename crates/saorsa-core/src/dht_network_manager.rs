// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! DHT Network Manager
//!
//! This module provides the integration layer between the DHT system and the network layer,
//! enabling real P2P operations with Kademlia routing over transport protocols.

#![allow(missing_docs)]

use crate::{
    P2PError, PeerId, Result,
    adaptive::TrustEngine,
    adaptive::trust::DEFAULT_NEUTRAL_TRUST,
    address::MultiAddr,
    dht::core_engine::{AtomicInstant, NodeInfo},
    dht::{AdmissionResult, DhtCoreEngine, DhtKey, Key, RoutingTableEvent},
    error::{DhtError, IdentityError, NetworkError},
    network::NodeConfig,
};
use anyhow::Context as _;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Notify, RwLock, Semaphore, broadcast, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

/// Minimum concurrent operations for semaphore backpressure
const MIN_CONCURRENT_OPERATIONS: usize = 10;

/// Maximum candidate nodes queue size to prevent memory exhaustion attacks.
/// Candidates are sorted by XOR distance to the lookup target (closest first).
/// When at capacity, a closer newcomer evicts the farthest existing candidate.
const MAX_CANDIDATE_NODES: usize = 200;

/// Maximum size for incoming DHT messages (64 KB) to prevent memory exhaustion DoS
/// Messages larger than this are rejected before deserialization
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Request timeout for DHT message handlers (10 seconds)
/// Prevents long-running handlers from starving the semaphore permit pool
/// SEC-001: DoS mitigation via timeout enforcement on concurrent operations
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Reliability score assigned to the local node in K-closest results.
/// The local node is always considered fully reliable for its own lookups.
const SELF_RELIABILITY_SCORE: f64 = 1.0;

/// Defensive upper bound on the wait for a freshly-dialled peer's
/// TLS-authenticated identity to be registered.
///
/// Since identity is now derived synchronously from the TLS-handshake
/// SPKI by the connection lifecycle monitor, this wait completes within
/// a scheduler tick of `connect_peer` returning. The 2 s budget exists
/// only as a safety net for the lifecycle monitor being wedged or the
/// peer presenting an unparseable SPKI. The effective wait remains
/// `min(request_timeout, this)`.
const IDENTITY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum time to wait for a stale peer's ping response during admission contention.
const STALE_REVALIDATION_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum concurrent stale revalidation passes across all buckets.
const MAX_CONCURRENT_REVALIDATIONS: usize = 8;

/// Maximum concurrent pings within a single stale revalidation pass.
const MAX_CONCURRENT_REVALIDATION_PINGS: usize = 4;

/// Duration after which a bucket without activity is considered stale.
const STALE_BUCKET_THRESHOLD: Duration = Duration::from_secs(3600); // 1 hour

/// Minimum self-lookup interval (randomized between min and max).
const SELF_LOOKUP_INTERVAL_MIN: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum self-lookup interval.
const SELF_LOOKUP_INTERVAL_MAX: Duration = Duration::from_secs(600); // 10 minutes

/// Periodic refresh cadence for stale k-buckets.
const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

/// Routing table size below which automatic re-bootstrap is triggered.
const AUTO_REBOOTSTRAP_THRESHOLD: usize = 3;

/// Maximum number of distinct referrers stored per discovered peer during an
/// iterative DHT lookup. The list is ranked at dial-time to pick the best
/// hole-punch coordinator candidate (see [`DhtNetworkManager::rank_referrers_for_target`]).
///
/// Bound exists to cap per-lookup memory; in practice 4 is more than enough
/// because Kademlia typically converges before any peer is referred more than
/// 2-3 times within a single lookup. Compile-time asserted >= 2 because
/// collecting only one referrer would defeat the purpose of ranking.
const MAX_REFERRERS_PER_TARGET: usize = 4;
const _: () = assert!(
    MAX_REFERRERS_PER_TARGET >= 2,
    "MAX_REFERRERS_PER_TARGET must be >= 2 for ranking to matter"
);

/// Minimum time between consecutive auto re-bootstrap attempts.
const REBOOTSTRAP_COOLDOWN: Duration = Duration::from_secs(300); // 5 minutes

/// DHT node representation for network operations.
///
/// The `addresses` field stores one or more typed [`MultiAddr`] values.
/// Peers may be multi-homed or reachable via NAT traversal at several
/// endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNode {
    pub peer_id: PeerId,
    pub addresses: Vec<MultiAddr>,
    pub distance: Option<Vec<u8>>,
    pub reliability: f64,
}

/// Alias for serialization compatibility
pub type SerializableDHTNode = DHTNode;

/// DHT Network Manager Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkConfig {
    /// This node's peer ID
    pub peer_id: PeerId,
    /// Network node configuration (includes DHT settings via `NodeConfig.dht_config`)
    pub node_config: NodeConfig,
    /// Request timeout for DHT operations
    pub request_timeout: Duration,
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Enable enhanced security features
    pub enable_security: bool,
    /// Trust score below which a peer is eligible for swap-out from the
    /// routing table when a better candidate is available.
    /// Default: 0.0 (disabled).
    pub swap_threshold: f64,
}

/// DHT network operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkOperation {
    /// Find nodes closest to a key
    FindNode { key: Key },
    /// Ping a node to check availability
    Ping,
    /// Join the DHT network
    Join,
    /// Leave the DHT network gracefully
    Leave,
    /// Publish the sender's preferred routable addresses (e.g., relay address).
    /// Receiving nodes update their routing table for the sender. Sent once
    /// after relay setup to K closest peers, not on every message.
    PublishAddress { addresses: Vec<crate::MultiAddr> },
}

/// DHT network operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkResult {
    /// Nodes found for FIND_NODE or iterative lookup
    NodesFound {
        key: Key,
        nodes: Vec<SerializableDHTNode>,
    },
    /// Ping response
    PongReceived {
        responder: PeerId,
        latency: Duration,
    },
    /// Join confirmation
    JoinSuccess {
        assigned_key: Key,
        bootstrap_peers: usize,
    },
    /// Leave confirmation
    LeaveSuccess,
    /// The remote peer has rejected us — do not penalise their trust score
    PeerRejected,
    /// Acknowledgement of a PublishAddress request
    PublishAddressAck,
    /// Operation failed
    Error { operation: String, error: String },
}

/// DHT message envelope for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkMessage {
    /// Message ID for request/response correlation
    pub message_id: String,
    /// Source peer ID
    pub source: PeerId,
    /// Target peer ID (optional for broadcast)
    pub target: Option<PeerId>,
    /// Message type
    pub message_type: DhtMessageType,
    /// DHT operation payload (for requests)
    pub payload: DhtNetworkOperation,
    /// DHT operation result (for responses)
    pub result: Option<DhtNetworkResult>,
    /// Timestamp when message was created
    pub timestamp: u64,
    /// TTL for message forwarding
    pub ttl: u8,
    /// Hop count for routing
    pub hop_count: u8,
}

/// DHT message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageType {
    /// Request message
    Request,
    /// Response message
    Response,
    /// Broadcast message
    Broadcast,
    /// Error response
    Error,
}

/// Main DHT Network Manager
///
/// This manager handles DHT operations (peer discovery, routing) but does
/// **not** own the transport lifecycle. The caller that supplies the
/// [`TransportHandle`](crate::transport_handle::TransportHandle) is responsible for
/// starting listeners and stopping the transport. For example, when `P2PNode` creates
/// the manager it starts transport listeners first, then starts this manager, and
/// stops transport after `DhtNetworkManager::stop()`.
pub struct DhtNetworkManager {
    /// DHT instance
    dht: Arc<RwLock<DhtCoreEngine>>,
    /// Transport handle for QUIC connections, peer registry, and message I/O
    transport: Arc<crate::transport_handle::TransportHandle>,
    /// EigenTrust engine for reputation management (optional)
    trust_engine: Option<Arc<TrustEngine>>,
    /// Configuration
    config: DhtNetworkConfig,
    /// Active DHT operations
    active_operations: Arc<Mutex<HashMap<String, DhtOperationContext>>>,
    /// Network message broadcaster
    event_tx: broadcast::Sender<DhtNetworkEvent>,
    /// Operation statistics
    stats: Arc<RwLock<DhtNetworkStats>>,
    /// Semaphore for limiting concurrent message handlers (backpressure)
    message_handler_semaphore: Arc<Semaphore>,
    /// Global semaphore limiting concurrent stale revalidation passes.
    /// Prevents a flood of revalidation attempts from consuming excessive
    /// resources when many buckets have stale peers simultaneously.
    revalidation_semaphore: Arc<Semaphore>,
    /// Per-bucket revalidation state: tracks active revalidation to prevent
    /// concurrent revalidation passes on the same bucket.
    /// Uses `parking_lot::Mutex` (not tokio) because it is never held across
    /// `.await` and its `Drop`-based guard cleanup requires synchronous locking.
    bucket_revalidation_active: Arc<parking_lot::Mutex<HashSet<usize>>>,
    /// Shutdown token for background tasks
    shutdown: CancellationToken,
    /// Handle for the network event handler task
    event_handler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Handle for the periodic self-lookup background task
    self_lookup_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Handle for the periodic bucket refresh background task
    bucket_refresh_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Timestamp of the last automatic re-bootstrap attempt, guarded by a
    /// cooldown to avoid hammering bootstrap peers during transient churn.
    last_rebootstrap: tokio::sync::Mutex<Option<Instant>>,
    /// Per-peer dial coalescing.
    ///
    /// When [`Self::send_dht_request`] needs to dial a peer that no other
    /// task is already dialling, it inserts a fresh `Notify` here and runs
    /// the dial inline. Concurrent callers targeting the same peer find an
    /// existing entry, await `notified()`, and then re-check whether the
    /// peer is now connected. This prevents N parallel iterative lookups
    /// from each kicking off their own coordinator-rotation cascade against
    /// the same peer — under symmetric NAT that cascade is what produced
    /// the "duplicate" connection-close storm during identity exchange.
    ///
    /// Entries are removed by the dialing task as soon as the dial returns
    /// (success or failure), so the map only ever holds peers that have a
    /// dial actively in progress.
    inflight_dials: Arc<DashMap<PeerId, Arc<Notify>>>,
}

/// One observation of a peer being referred during an iterative DHT lookup.
///
/// When peer R answers a `FindNode` query and returns peer T, R becomes a
/// referrer for T: R has T in its routing table and presumably has (or
/// recently had) a connection to T, making R a good candidate to coordinate
/// hole-punching to T.
///
/// During a single iterative lookup we collect up to
/// [`MAX_REFERRERS_PER_TARGET`] referrers per discovered peer and rank them
/// at dial-time via [`DhtNetworkManager::rank_referrers_for_target`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReferrerInfo {
    /// Peer ID of the referring node (used for trust score lookup and tiebreak).
    peer_id: PeerId,
    /// Dialable socket address of the referring node — what we hand to
    /// saorsa-transport as the preferred coordinator.
    addr: SocketAddr,
    /// 0-based iteration round in which this referral was observed.
    /// Higher round = closer to the lookup target in XOR space = more likely
    /// to actually have a live connection to the target.
    round_observed: u32,
}

/// DHT operation context
///
/// Uses oneshot channel for response delivery to eliminate TOCTOU races.
/// The sender is stored here; the receiver is held by wait_for_response().
struct DhtOperationContext {
    /// Operation type
    operation: DhtNetworkOperation,
    /// Target app-level peer ID (authentication identity, not transport channel)
    peer_id: PeerId,
    /// Start time
    started_at: Instant,
    /// Timeout
    timeout: Duration,
    /// Contacted app-level peer IDs (for response source validation)
    contacted_nodes: Vec<PeerId>,
    /// Oneshot sender for delivering the response
    /// None if response already sent (channel consumed)
    response_tx: Option<oneshot::Sender<(PeerId, DhtNetworkResult)>>,
}

impl std::fmt::Debug for DhtOperationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtOperationContext")
            .field("operation", &self.operation)
            .field("peer_id", &self.peer_id)
            .field("started_at", &self.started_at)
            .field("timeout", &self.timeout)
            .field("contacted_nodes", &self.contacted_nodes)
            .field("response_tx", &self.response_tx.is_some())
            .finish()
    }
}

/// DHT network events
#[derive(Debug, Clone)]
pub enum DhtNetworkEvent {
    /// New DHT peer discovered
    PeerDiscovered { peer_id: PeerId, dht_key: Key },
    /// DHT peer disconnected
    PeerDisconnected { peer_id: PeerId },
    /// The K-closest peers to this node's own address have changed.
    ///
    /// Emitted after routing table mutations (peer added, removed, or evicted)
    /// when the set of K-closest peers differs from the previous snapshot.
    /// Callers implementing replication can use this to detect close-group
    /// topology changes and trigger neighbor-sync or responsibility
    /// recomputation.
    KClosestPeersChanged {
        /// K-closest peer IDs before the mutation.
        old: Vec<PeerId>,
        /// K-closest peer IDs after the mutation.
        new: Vec<PeerId>,
    },
    /// New peer added to the routing table.
    PeerAdded { peer_id: PeerId },
    /// Peer removed from the routing table (swap-out, eviction, or departure).
    PeerRemoved { peer_id: PeerId },
    /// Bootstrap process completed.
    BootstrapComplete { num_peers: usize },
    /// DHT operation completed
    OperationCompleted {
        operation: String,
        success: bool,
        duration: Duration,
    },
    /// DHT network status changed
    NetworkStatusChanged {
        connected_peers: usize,
        routing_table_size: usize,
    },
    /// Error occurred
    Error { error: String },
}

/// DHT network statistics
#[derive(Debug, Clone, Default)]
pub struct DhtNetworkStats {
    /// Total operations performed
    pub total_operations: u64,
    /// Successful operations
    pub successful_operations: u64,
    /// Failed operations
    pub failed_operations: u64,
    /// Average operation latency
    pub avg_operation_latency: Duration,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Connected transport peers (all authenticated peers, including Client-mode)
    pub connected_peers: usize,
    /// DHT routing table size (Node-mode peers only)
    pub routing_table_size: usize,
}

/// RAII guard that removes a bucket index from the per-bucket revalidation set
/// on drop, ensuring the slot is released even if the revalidation panics or
/// returns early.
struct BucketRevalidationGuard {
    active: Arc<parking_lot::Mutex<HashSet<usize>>>,
    bucket_idx: usize,
}

impl Drop for BucketRevalidationGuard {
    fn drop(&mut self) {
        self.active.lock().remove(&self.bucket_idx);
    }
}

/// RAII guard for the dial-coalescing slot owned by a single
/// [`DhtNetworkManager::dial_or_await_inflight`] caller.
///
/// On drop the inflight entry is removed and `notify_waiters()` is called,
/// so any concurrent callers awaiting on `notified()` are unblocked even if
/// the owning caller's dial future panicked or was cancelled. Without this
/// guard, a panic inside `dial_addresses` would leave waiters blocked
/// indefinitely, because they have no timeout of their own.
struct InflightDialGuard {
    inflight: Arc<DashMap<PeerId, Arc<Notify>>>,
    peer_id: PeerId,
    notify: Arc<Notify>,
}

impl Drop for InflightDialGuard {
    fn drop(&mut self) {
        // Remove the inflight entry first so any waiter that re-enters
        // `dial_or_await_inflight` after waking sees a clean state.
        self.inflight.remove(&self.peer_id);
        self.notify.notify_waiters();
    }
}

impl DhtNetworkManager {
    fn new_from_components(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<TrustEngine>>,
        config: DhtNetworkConfig,
    ) -> Result<Self> {
        let mut dht_instance = DhtCoreEngine::new(
            config.peer_id,
            config.node_config.dht_config.k_value,
            config.node_config.allow_loopback,
            config.swap_threshold,
        )
        .map_err(|e| P2PError::Dht(DhtError::OperationFailed(e.to_string().into())))?;

        // Propagate IP diversity settings from the node config into the DHT
        // core engine so diversity overrides take effect on routing table
        // insertion, not just bootstrap discovery.
        if let Some(diversity) = &config.node_config.diversity_config {
            dht_instance.set_ip_diversity_config(diversity.clone());
        }

        let dht = Arc::new(RwLock::new(dht_instance));

        let (event_tx, _) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let message_handler_semaphore = Arc::new(Semaphore::new(
            config
                .max_concurrent_operations
                .max(MIN_CONCURRENT_OPERATIONS),
        ));

        Ok(Self {
            dht,
            transport,
            trust_engine,
            config,
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            stats: Arc::new(RwLock::new(DhtNetworkStats::default())),
            message_handler_semaphore,
            revalidation_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REVALIDATIONS)),
            bucket_revalidation_active: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            shutdown: CancellationToken::new(),
            event_handler_handle: Arc::new(RwLock::new(None)),
            self_lookup_handle: Arc::new(RwLock::new(None)),
            bucket_refresh_handle: Arc::new(RwLock::new(None)),
            last_rebootstrap: tokio::sync::Mutex::new(None),
            inflight_dials: Arc::new(DashMap::new()),
        })
    }

    /// Kademlia K parameter — bucket size and lookup count.
    /// Get the configured Kademlia K value (bucket size / close group size).
    pub fn k_value(&self) -> usize {
        self.config.node_config.dht_config.k_value
    }

    /// Handle a FindNode request by returning the closest nodes from the local routing table.
    async fn handle_find_node_request(
        &self,
        key: &Key,
        requester: &PeerId,
    ) -> Result<DhtNetworkResult> {
        trace!(
            "FIND_NODE: resolving closer nodes for key {}",
            hex::encode(key)
        );

        let candidate_nodes = self.find_closest_nodes_local(key, self.k_value()).await;
        let closer_nodes = Self::filter_response_nodes(candidate_nodes, requester);

        // Log addresses being returned in FIND_NODE response
        for node in &closer_nodes {
            let addrs: Vec<String> = node.addresses.iter().map(|a| format!("{}", a)).collect();
            debug!(
                "FIND_NODE response: peer={} addresses={:?}",
                node.peer_id.to_hex(),
                addrs
            );
        }

        Ok(DhtNetworkResult::NodesFound {
            key: *key,
            nodes: closer_nodes,
        })
    }

    /// Create a new DHT Network Manager using an existing transport handle.
    ///
    /// The caller is responsible for the transport lifecycle and must stop
    /// transport after stopping this manager.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<TrustEngine>>,
        mut config: DhtNetworkConfig,
    ) -> Result<Self> {
        let transport_app_peer_id = transport.peer_id();
        if config.peer_id == PeerId::from_bytes([0u8; 32]) {
            config.peer_id = transport_app_peer_id;
        } else if config.peer_id != transport_app_peer_id {
            warn!(
                "DHT config peer_id ({}) differs from transport peer_id ({}); using config value",
                config.peer_id.to_hex(),
                transport_app_peer_id.to_hex()
            );
        }

        info!(
            "Creating attached DHT Network Manager for peer: {}",
            config.peer_id.to_hex()
        );
        let manager = Self::new_from_components(transport, trust_engine, config)?;

        info!("Attached DHT Network Manager created successfully");
        Ok(manager)
    }

    /// Start the DHT network manager.
    ///
    /// This manager does not manage the transport lifecycle. If transport listeners
    /// are already running, startup reconciles currently connected peers after event
    /// subscription is established.
    ///
    /// Note: This method requires `self` to be wrapped in an `Arc` so that
    /// background tasks can hold references to the manager.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        info!("Starting DHT Network Manager...");

        // Subscribe to transport events before DHT background work starts.
        self.start_network_event_handler(Arc::clone(self)).await?;

        // Reconcile peers that may have connected before event subscription.
        self.reconcile_connected_peers().await;

        // Spawn periodic maintenance background tasks.
        self.spawn_self_lookup_task().await;
        self.spawn_bucket_refresh_task().await;

        info!("DHT Network Manager started successfully");
        Ok(())
    }

    /// Spawn the periodic self-lookup background task.
    ///
    /// Runs an iterative FIND_NODE(self) at a randomised interval between
    /// [`SELF_LOOKUP_INTERVAL_MIN`] and [`SELF_LOOKUP_INTERVAL_MAX`] to keep
    /// the close neighbourhood fresh and discover newly joined peers.
    async fn spawn_self_lookup_task(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let shutdown = self.shutdown.clone();
        let handle_slot = Arc::clone(&self.self_lookup_handle);

        let handle = tokio::spawn(async move {
            loop {
                let interval =
                    Self::randomised_interval(SELF_LOOKUP_INTERVAL_MIN, SELF_LOOKUP_INTERVAL_MAX);

                tokio::select! {
                    () = tokio::time::sleep(interval) => {}
                    () = shutdown.cancelled() => break,
                }

                if let Err(e) = this.trigger_self_lookup().await {
                    warn!("Periodic self-lookup failed: {e}");
                }

                // Evict any stale K-closest peers that fail to respond.
                this.revalidate_stale_k_closest().await;

                // Check if routing table is depleted after the self-lookup.
                this.maybe_rebootstrap().await;
            }
        });
        *handle_slot.write().await = Some(handle);
    }

    /// Spawn the periodic bucket refresh background task.
    ///
    /// Every [`BUCKET_REFRESH_INTERVAL`], finds stale buckets (not refreshed
    /// within [`STALE_BUCKET_THRESHOLD`]) and performs a FIND_NODE lookup for
    /// a random key in each stale bucket's range. This populates stale buckets
    /// with fresh peers.
    async fn spawn_bucket_refresh_task(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let shutdown = self.shutdown.clone();
        let handle_slot = Arc::clone(&self.bucket_refresh_handle);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(BUCKET_REFRESH_INTERVAL) => {}
                    () = shutdown.cancelled() => break,
                }

                let stale_indices = this
                    .dht
                    .read()
                    .await
                    .stale_bucket_indices(STALE_BUCKET_THRESHOLD)
                    .await;

                if stale_indices.is_empty() {
                    trace!("Bucket refresh: no stale buckets");
                    continue;
                }

                debug!("Bucket refresh: {} stale buckets", stale_indices.len());
                let k = this.k_value();

                for bucket_idx in stale_indices {
                    let random_key = {
                        let dht = this.dht.read().await;
                        dht.generate_random_key_for_bucket(bucket_idx)
                    };
                    let Some(key) = random_key else {
                        continue;
                    };

                    let key_bytes: Key = *key.as_bytes();
                    match this.find_closest_nodes_network(&key_bytes, k).await {
                        Ok(nodes) => {
                            trace!(
                                "Bucket refresh[{bucket_idx}]: discovered {} peers",
                                nodes.len()
                            );
                            for dht_node in nodes {
                                if dht_node.peer_id == this.config.peer_id {
                                    continue;
                                }
                                this.dial_addresses(&dht_node.peer_id, &dht_node.addresses, &[])
                                    .await;
                            }
                        }
                        Err(e) => {
                            debug!("Bucket refresh[{bucket_idx}] lookup failed: {e}");
                        }
                    }
                }

                // Check if routing table is depleted after refresh.
                this.maybe_rebootstrap().await;
            }
        });
        *handle_slot.write().await = Some(handle);
    }

    /// Trigger an immediate self-lookup to refresh the close neighborhood.
    ///
    /// Performs an iterative FIND_NODE for this node's own key and attempts to
    /// admit any newly discovered peers into the routing table.
    pub async fn trigger_self_lookup(&self) -> Result<()> {
        let self_id = self.config.peer_id;
        let self_key: Key = *self_id.as_bytes();
        let k = self.k_value();

        match self.find_closest_nodes_network(&self_key, k).await {
            Ok(nodes) => {
                debug!("Self-lookup discovered {} peers", nodes.len());
                for dht_node in nodes {
                    if dht_node.peer_id == self_id {
                        continue;
                    }
                    // Dial if not already connected — try every advertised
                    // address, not just the first, so a stale NAT binding on
                    // one entry doesn't kill the dial. Routed through the
                    // coalescing helper so a concurrent self-lookup and
                    // send_dht_request to the same peer share one dial.
                    self.dial_or_await_inflight(&dht_node.peer_id, &dht_node.addresses, &[])
                        .await;
                }
                Ok(())
            }
            Err(e) => {
                debug!("Self-lookup failed: {e}");
                Err(e)
            }
        }
    }

    /// Trigger automatic re-bootstrap if the routing table has fallen below
    /// [`AUTO_REBOOTSTRAP_THRESHOLD`] and the cooldown has elapsed.
    ///
    /// Uses currently connected peers as bootstrap seeds. The cooldown prevents
    /// hammering bootstrap nodes during transient network partitions.
    async fn maybe_rebootstrap(&self) {
        let rt_size = self.get_routing_table_size().await;
        if rt_size >= AUTO_REBOOTSTRAP_THRESHOLD {
            return;
        }

        // Enforce cooldown to avoid bootstrap storms.
        {
            let mut guard = self.last_rebootstrap.lock().await;
            if let Some(last) = *guard
                && last.elapsed() < REBOOTSTRAP_COOLDOWN
            {
                trace!(
                    "Auto re-bootstrap skipped: cooldown ({:?} remaining)",
                    REBOOTSTRAP_COOLDOWN.saturating_sub(last.elapsed())
                );
                return;
            }
            *guard = Some(Instant::now());
        }

        info!(
            "Auto re-bootstrap: routing table size ({rt_size}) below threshold ({})",
            AUTO_REBOOTSTRAP_THRESHOLD
        );

        // Collect currently connected peers to use as bootstrap seeds.
        let connected = self.transport.connected_peers().await;
        if connected.is_empty() {
            debug!("Auto re-bootstrap: no connected peers to bootstrap from");
            return;
        }

        match self.bootstrap_from_peers(&connected).await {
            Ok(discovered) => {
                info!("Auto re-bootstrap discovered {discovered} peers");
            }
            Err(e) => {
                warn!("Auto re-bootstrap failed: {e}");
            }
        }
    }

    /// Compute a randomised duration between `min` and `max`.
    ///
    /// Uses [`PeerId::random()`] as a cheap entropy source to avoid the `gen`
    /// keyword reserved in Rust edition 2024. This is not cryptographically
    /// secure but sufficient for jittering maintenance timers.
    fn randomised_interval(min: Duration, max: Duration) -> Duration {
        let range_secs = max.as_secs().saturating_sub(min.as_secs());
        if range_secs == 0 {
            return min;
        }
        let random_bytes = PeerId::random();
        let bytes = random_bytes.to_bytes();
        let random_value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let jitter = Duration::from_secs(random_value % (range_secs + 1));
        min + jitter
    }

    /// Return `[0, len)` in a per-call shuffled order using a Fisher-Yates
    /// pass driven by [`PeerId::random()`] entropy.
    ///
    /// Used to randomise the order in which we visit a fixed input slice
    /// (e.g. the bootstrap peer list in [`Self::bootstrap_from_peers`]) so
    /// that across a fleet of nodes the load on any individual element of
    /// the input is statistically uniform rather than concentrated on
    /// `input[0]`.
    ///
    /// For `len <= 1` this returns a trivial unshuffled vector — there is
    /// nothing to randomise. The entropy source is not cryptographically
    /// secure but is more than sufficient for load distribution.
    fn shuffled_indices(len: usize) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..len).collect();
        if len <= 1 {
            return indices;
        }
        // Build a 32-byte entropy buffer per call. PeerId::random() gives us
        // 32 bytes, which covers ~16 two-byte swap decisions — well above
        // the bootstrap-list sizes we expect (typically 2-5).
        let entropy_owner = PeerId::random();
        let entropy = entropy_owner.to_bytes();
        let entropy_len = entropy.len();
        // Fisher-Yates: for i from len-1 down to 1, swap indices[i] with
        // indices[j] where j is uniform in [0, i].
        for i in (1..len).rev() {
            // Draw a 16-bit window (two bytes) instead of one byte. With a
            // single byte the modulo bias `byte % (i + 1)` slightly
            // over-represents low values whenever `(i + 1)` does not
            // divide 256 — at i = 4 the bias on slot 0 is ~0.4%, which is
            // exactly the opposite of the load-spreading goal. A 16-bit
            // window cuts the bias to ~1/65536 for any realistic list
            // size at zero added complexity.
            let idx = (len - 1 - i) * 2;
            let byte = ((entropy[idx % entropy_len] as usize) << 8)
                | (entropy[(idx + 1) % entropy_len] as usize);
            let j = byte % (i + 1);
            indices.swap(i, j);
        }
        indices
    }

    /// Perform DHT peer discovery from already-connected bootstrap peers.
    ///
    /// Sends FIND_NODE(self) to each peer using the DHT postcard protocol,
    /// then dials any newly-discovered candidates. Returns the total number
    /// of new peers discovered.
    ///
    /// **Coordinator selection note**: previously this function pinned the
    /// bootstrap peer's socket address as the preferred hole-punch
    /// coordinator for every peer it returned. That concentrated load on
    /// the small handful of bootstrap nodes (since every cold-starting node
    /// queried the same ones). The pinning is removed: subsequent
    /// iterative DHT lookups via `find_closest_nodes_network` collect
    /// referrers across multiple rounds and rank them via
    /// [`Self::rank_referrers_for_target`], naturally de-preferring round-0
    /// bootstrap referrers as the routing table grows.
    ///
    /// **Iteration order**: bootstrap peers are visited in a per-call
    /// shuffled order (PeerId-derived entropy) so that in a fleet of N
    /// nodes with M bootstrap peers, each bootstrap is the "first asked"
    /// by ~N/M peers rather than all N hitting `peers[0]`.
    pub async fn bootstrap_from_peers(&self, peers: &[PeerId]) -> Result<usize> {
        let key = *self.config.peer_id.as_bytes();
        let mut seen = HashSet::new();
        let visit_order = Self::shuffled_indices(peers.len());
        for &idx in &visit_order {
            // `shuffled_indices(peers.len())` is guaranteed to return values
            // in `[0, peers.len())`, so this `.get()` always succeeds. We
            // use `.get()` rather than direct indexing to keep this code
            // panic-free even if the contract changes in future.
            let Some(peer_id) = peers.get(idx) else {
                continue;
            };
            let op = DhtNetworkOperation::FindNode { key };
            match self.send_dht_request(peer_id, op, None).await {
                Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                    for node in &nodes {
                        let dialable = Self::dialable_addresses(&node.addresses);
                        debug!(
                            "DHT bootstrap: peer={} num_addresses={} dialable={}",
                            node.peer_id.to_hex(),
                            node.addresses.len(),
                            dialable.len()
                        );
                        if seen.insert(node.peer_id) && !dialable.is_empty() {
                            // Pass an empty referrer list: the bootstrap
                            // peer is no longer hard-pinned as the
                            // hole-punch coordinator for these freshly-
                            // discovered peers. The next iterative lookup
                            // will populate proper referrers via the
                            // round-aware ranking.
                            self.dial_or_await_inflight(&node.peer_id, &node.addresses, &[])
                                .await;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Bootstrap FIND_NODE to {} failed: {}", peer_id.to_hex(), e);
                }
            }
        }

        // Emit BootstrapComplete event with the current routing table size.
        let rt_size = self.get_routing_table_size().await;
        if self.event_tx.receiver_count() > 0 {
            let _ = self
                .event_tx
                .send(DhtNetworkEvent::BootstrapComplete { num_peers: rt_size });
        }
        info!("Bootstrap complete: routing table has {rt_size} peers");

        Ok(seen.len())
    }

    /// Stop the DHT network manager.
    ///
    /// Sends leave messages to connected peers and shuts down DHT operations.
    /// The caller is responsible for stopping the transport after this returns.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DHT Network Manager...");

        // Send leave messages to connected peers before shutting down tasks
        self.leave_network().await?;

        // Signal all background tasks to stop
        self.shutdown.cancel();

        // Signal background tasks to stop
        self.dht.read().await.signal_shutdown();

        // Join all background tasks
        async fn join_task(name: &str, slot: &RwLock<Option<tokio::task::JoinHandle<()>>>) {
            if let Some(handle) = slot.write().await.take() {
                match handle.await {
                    Ok(()) => debug!("{name} task stopped cleanly"),
                    Err(e) if e.is_cancelled() => debug!("{name} task was cancelled"),
                    Err(e) => warn!("{name} task panicked: {e}"),
                }
            }
        }
        join_task("event handler", &self.event_handler_handle).await;
        join_task("self-lookup", &self.self_lookup_handle).await;
        join_task("bucket refresh", &self.bucket_refresh_handle).await;

        info!("DHT Network Manager stopped");
        Ok(())
    }

    /// Backwards-compatible API that performs a full iterative lookup.
    pub async fn find_closest_nodes(&self, key: &Key, count: usize) -> Result<Vec<DHTNode>> {
        self.find_closest_nodes_network(key, count).await
    }

    /// Find nodes closest to a key using iterative network lookup
    pub async fn find_node(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Finding nodes closest to key: {}", hex::encode(key));

        let closest_nodes = self.find_closest_nodes_network(key, self.k_value()).await?;
        let serializable_nodes: Vec<SerializableDHTNode> = closest_nodes.into_iter().collect();

        info!(
            "Found {} nodes closest to key: {}",
            serializable_nodes.len(),
            hex::encode(key)
        );
        Ok(DhtNetworkResult::NodesFound {
            key: *key,
            nodes: serializable_nodes,
        })
    }

    /// Ping a specific node
    pub async fn ping(&self, peer_id: &PeerId) -> Result<DhtNetworkResult> {
        info!("Pinging peer: {}", peer_id.to_hex());

        let start_time = Instant::now();
        let operation = DhtNetworkOperation::Ping;

        match self.send_dht_request(peer_id, operation, None).await {
            Ok(DhtNetworkResult::PongReceived { responder, .. }) => {
                let latency = start_time.elapsed();
                info!("Received pong from {} in {:?}", responder, latency);
                Ok(DhtNetworkResult::PongReceived { responder, latency })
            }
            Ok(result) => {
                warn!("Unexpected ping result: {:?}", result);
                Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Unexpected ping response".to_string().into(),
                )))
            }
            Err(e) => {
                warn!("Ping failed to {}: {}", peer_id.to_hex(), e);
                Err(e)
            }
        }
    }

    /// Leave the DHT network gracefully
    async fn leave_network(&self) -> Result<()> {
        // No-op: peers detect disconnection via transport-level connection loss.
        // Explicit leave messages added latency to shutdown without meaningful benefit.
        Ok(())
    }

    // =========================================================================
    // FIND CLOSEST NODES API
    // =========================================================================
    //
    // Two functions for finding closest nodes to a key:
    //
    // 1. find_closest_nodes_local() - Routing table lookup
    //    - Only checks the local Kademlia routing table
    //    - No network requests, safe to call from request handlers
    //    - Returns security-validated DHT participants only
    //
    // 2. find_closest_nodes_network() - Iterative network lookup
    //    - Starts with routing table knowledge, then queries the network
    //    - Asks known nodes for their closest nodes, then queries those
    //    - Continues until convergence (same answers or worse quality)
    //    - Full Kademlia-style iterative lookup
    // =========================================================================

    /// Find closest nodes to a key using ONLY the local routing table.
    ///
    /// No network requests are made — safe to call from request handlers.
    /// Only returns peers that passed the `is_dht_participant` security gate
    /// and were added to the Kademlia routing table.
    ///
    /// Results are sorted by XOR distance to the key.
    pub async fn find_closest_nodes_local(&self, key: &Key, count: usize) -> Vec<DHTNode> {
        debug!(
            "[LOCAL] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let dht_guard = self.dht.read().await;
        match dht_guard.find_nodes(&DhtKey::from_bytes(*key), count).await {
            Ok(nodes) => nodes
                .into_iter()
                .filter(|node| !self.is_local_peer_id(&node.id))
                .map(|node| DHTNode {
                    peer_id: node.id,
                    addresses: node.addresses,
                    distance: None,
                    reliability: SELF_RELIABILITY_SCORE,
                })
                .collect(),
            Err(e) => {
                warn!("find_nodes failed for key {}: {e}", hex::encode(key));
                Vec::new()
            }
        }
    }

    /// Find closest nodes to a key using the local routing table, including
    /// the local node itself in the candidate set.
    ///
    /// This is the self-inclusive variant of [`find_closest_nodes_local`] and
    /// corresponds to `SelfInclusiveRT(N)` in replication designs — the local
    /// routing table plus the local node. It allows callers to compute
    /// `IsResponsible(self, K)` by checking whether self appears in the
    /// top-N results.
    ///
    /// Results are sorted by XOR distance to the key and truncated to `count`.
    pub async fn find_closest_nodes_local_with_self(
        &self,
        key: &Key,
        count: usize,
    ) -> Vec<DHTNode> {
        // Get `count` routing-table peers, append self, sort, and truncate
        // back to `count`. Self may displace the farthest peer.
        let mut nodes = self.find_closest_nodes_local(key, count).await;

        nodes.push(self.local_dht_node().await);

        let key_peer = PeerId::from_bytes(*key);
        nodes.sort_by(|a, b| {
            let da = a.peer_id.xor_distance(&key_peer);
            let db = b.peer_id.xor_distance(&key_peer);
            da.cmp(&db)
        });
        nodes.truncate(count);
        nodes
    }

    /// Find closest nodes to a key using iterative network lookup.
    ///
    /// This implements Kademlia-style iterative lookup:
    /// 1. Start with nodes from local address book
    /// 2. Query those nodes for their closest nodes to the key
    /// 3. Query the returned nodes, repeat
    /// 4. Stop when converged (same or worse answers)
    ///
    /// This makes network requests and should NOT be called from request handlers.
    pub async fn find_closest_nodes_network(
        &self,
        key: &Key,
        count: usize,
    ) -> Result<Vec<DHTNode>> {
        const MAX_ITERATIONS: usize = 20;
        const ALPHA: usize = 3; // Parallel queries per iteration

        debug!(
            "[NETWORK] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let target_key = DhtKey::from_bytes(*key);
        let mut queried_nodes: HashSet<PeerId> = HashSet::new();
        let mut best_nodes: Vec<DHTNode> = Vec::new();
        // Track every peer that referred us to each discovered peer. When
        // node R responds to FindNode with node T, R has T in its routing
        // table and presumably has a connection to T — making R a candidate
        // hole-punch coordinator for T.
        //
        // We collect up to MAX_REFERRERS_PER_TARGET observations and rank
        // them at dial-time via `rank_referrers_for_target`. The ranking prefers
        // referrers seen in later iteration rounds (closer to the target in
        // XOR space) over earlier rounds, which naturally de-prefers the
        // round-0 bootstrap referrers without any explicit bootstrap
        // tagging.
        let mut referrers: HashMap<PeerId, Vec<ReferrerInfo>> = HashMap::new();

        // Kademlia correctness: the local node must compete on distance in the
        // final K-closest result, but we must never send an RPC to ourselves.
        // Seed best_nodes with self and mark self as "queried" so the iterative
        // loop never tries to contact us.
        best_nodes.push(self.local_dht_node().await);
        self.mark_self_queried(&mut queried_nodes);

        // Candidates sorted by XOR distance to target (closest first).
        // Composite key (distance, peer_id) ensures uniqueness when two peers
        // share the same distance.
        let mut candidates: BTreeMap<(Key, PeerId), DHTNode> = BTreeMap::new();

        // Start with local knowledge
        let initial = self.find_closest_nodes_local(key, count).await;
        for node in initial {
            if !queried_nodes.contains(&node.peer_id) {
                let dist = node.peer_id.distance(&target_key);
                candidates.entry((dist, node.peer_id)).or_insert(node);
            }
        }

        // Snapshot of the top-K peer IDs from the previous iteration.
        // Stagnation = the entire top-K set is unchanged AND no unqueried
        // candidate is closer than the current worst member of top-K.
        let mut previous_top_k: Vec<PeerId> = Vec::new();

        for iteration in 0..MAX_ITERATIONS {
            if candidates.is_empty() {
                debug!(
                    "[NETWORK] No more candidates after {} iterations",
                    iteration
                );
                break;
            }

            // Select up to ALPHA closest unqueried nodes to query.
            // BTreeMap is sorted by (distance, peer_id), so first_entry()
            // always yields the closest candidate.
            let mut batch: Vec<DHTNode> = Vec::new();
            while batch.len() < ALPHA {
                let Some(entry) = candidates.first_entry() else {
                    break;
                };
                let node = entry.remove();
                if queried_nodes.contains(&node.peer_id) {
                    continue;
                }
                batch.push(node);
            }

            if batch.is_empty() {
                debug!(
                    "[NETWORK] All candidates queried after {} iterations",
                    iteration
                );
                break;
            }

            info!(
                "[NETWORK] Iteration {}: querying {} nodes",
                iteration,
                batch.len()
            );

            // Query nodes in parallel
            // saorsa-transport connection multiplexing lets us keep a single transport socket
            // while still querying multiple peers concurrently.
            let query_futures: Vec<_> = batch
                .iter()
                .map(|node| {
                    let peer_id = node.peer_id;
                    let addresses = node.addresses.clone();
                    // Build the full ranked list of preferred coordinators
                    // for this target. saorsa-transport rotates through
                    // them in order with a short per-attempt timeout for
                    // all but the final candidate, so handing over the
                    // full list (instead of just the best) lets the
                    // hole-punch loop fall through busy or unreachable
                    // referrers without waiting on the strategy timeout.
                    let referrer_list =
                        self.rank_referrers_for_target(referrers.get(&peer_id).map(Vec::as_slice));
                    let op = DhtNetworkOperation::FindNode { key: *key };
                    async move {
                        // Try every dialable address, not just the first.
                        // If at least one succeeds the peer is connected and
                        // `send_dht_request` will reuse that channel; if all
                        // fail, `send_dht_request`'s own fallback will retry
                        // with the routing-table addresses. The coalescing
                        // helper ensures the parallel iterative-lookup batch
                        // shares one dial per peer rather than racing.
                        self.dial_or_await_inflight(&peer_id, &addresses, &referrer_list)
                            .await;
                        let address_hint = Self::first_dialable_address(&addresses);
                        (
                            peer_id,
                            self.send_dht_request(&peer_id, op, address_hint.as_ref())
                                .await,
                        )
                    }
                })
                .collect();

            let results = futures::future::join_all(query_futures).await;

            for (peer_id, result) in results {
                queried_nodes.insert(peer_id);

                match result {
                    Ok(DhtNetworkResult::NodesFound { mut nodes, .. }) => {
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }

                        // Track this peer as a referrer for all nodes it returned.
                        let referrer_addr = batch
                            .iter()
                            .find(|n| n.peer_id == peer_id)
                            .and_then(|n| Self::first_dialable_address(&n.addresses))
                            .and_then(|a| a.dialable_socket_addr());

                        // Truncate response to K closest to the lookup key to
                        // limit amplification from a single response and bound
                        // per-iteration memory growth.
                        nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
                        nodes.truncate(self.k_value());
                        for node in nodes {
                            if queried_nodes.contains(&node.peer_id)
                                || self.is_local_peer_id(&node.peer_id)
                            {
                                continue;
                            }
                            // Append this referrer to the candidate list for
                            // the discovered peer. We keep up to
                            // MAX_REFERRERS_PER_TARGET observations and rank
                            // them at dial-time, so we no longer pin the
                            // first-seen referrer.
                            //
                            // When the slot table is full, we still want to
                            // accept a *strictly later round* observation by
                            // evicting the lowest-round entry. Otherwise a
                            // burst of round-0 referrers (e.g. several
                            // bootstraps all returning the same hot peer)
                            // would lock out the higher-round referrers we
                            // actually prefer at dial-time, defeating the
                            // round-aware ranking in exactly the case we
                            // care about.
                            if let Some(ref_addr) = referrer_addr {
                                let entry = referrers.entry(node.peer_id).or_default();
                                Self::merge_referrer_observation(
                                    entry,
                                    ReferrerInfo {
                                        peer_id,
                                        addr: ref_addr,
                                        round_observed: iteration as u32,
                                    },
                                    &node.peer_id,
                                );
                            }
                            let dist = node.peer_id.distance(&target_key);
                            let cand_key = (dist, node.peer_id);
                            if candidates.contains_key(&cand_key) {
                                continue;
                            }
                            if candidates.len() >= MAX_CANDIDATE_NODES {
                                // At capacity — evict the farthest candidate if the
                                // new one is closer, otherwise drop the new one.
                                let farthest_key = candidates.keys().next_back().copied();
                                match farthest_key {
                                    Some(fk) if cand_key < fk => {
                                        candidates.remove(&fk);
                                    }
                                    _ => {
                                        trace!(
                                            "[NETWORK] Candidate queue at capacity ({}), dropping {}",
                                            MAX_CANDIDATE_NODES,
                                            node.peer_id.to_hex()
                                        );
                                        continue;
                                    }
                                }
                            }
                            candidates.insert(cand_key, node);
                        }
                    }
                    Ok(DhtNetworkResult::PeerRejected) => {
                        // Remote peer rejected us (e.g. older node with blocking) —
                        // remove them from our routing table (no point retrying) but
                        // do NOT penalise their trust score; the rejection is an
                        // honest signal, not misbehaviour.
                        info!(
                            "[NETWORK] Peer {} rejected us — removing from routing table",
                            peer_id.to_hex()
                        );
                        let mut dht = self.dht.write().await;
                        let rt_events = dht.remove_node_by_id(&peer_id).await;
                        drop(dht);
                        self.broadcast_routing_events(&rt_events);
                        let _ = self.transport.disconnect_peer(&peer_id).await;
                    }
                    Ok(_) => {
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                    }
                    Err(e) => {
                        trace!("[NETWORK] Query to {} failed: {}", peer_id.to_hex(), e);
                        // Trust failure is recorded inside send_dht_request —
                        // no additional recording needed here.
                    }
                }
            }

            // Sort, deduplicate, and truncate once per iteration instead of per result
            best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
            best_nodes.dedup_by_key(|n| n.peer_id);
            best_nodes.truncate(count);

            // Stagnation: compare the entire top-K set, not just closest distance.
            let current_top_k: Vec<PeerId> = best_nodes.iter().map(|n| n.peer_id).collect();
            if current_top_k == previous_top_k {
                // If we haven't filled K slots yet, any remaining candidate
                // could improve the result — keep going.
                if best_nodes.len() < count && !candidates.is_empty() {
                    previous_top_k = current_top_k;
                    continue;
                }
                // Top-K didn't change, but don't stop if a queued candidate is
                // closer than the farthest member of top-K — it could still
                // improve the result once queried.
                let has_promising_candidate = best_nodes.last().is_some_and(|worst| {
                    let worst_dist = worst.peer_id.distance(&target_key);
                    candidates
                        .keys()
                        .next()
                        .is_some_and(|(dist, _)| *dist < worst_dist)
                });
                if !has_promising_candidate {
                    info!(
                        "[NETWORK] {}: Top-K converged after {} iterations",
                        self.config.peer_id.to_hex(),
                        iteration + 1
                    );
                    break;
                }
            }
            previous_top_k = current_top_k;
        }

        best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        best_nodes.dedup_by_key(|n| n.peer_id);
        best_nodes.truncate(count);

        info!(
            "[NETWORK] Found {} closest nodes: {:?}",
            best_nodes.len(),
            best_nodes
                .iter()
                .map(|n| {
                    let h = n.peer_id.to_hex();
                    h[..8.min(h.len())].to_string()
                })
                .collect::<Vec<_>>()
        );

        Ok(best_nodes)
    }

    /// Compare two nodes by their XOR distance to a target key.
    fn compare_node_distance(a: &DHTNode, b: &DHTNode, key: &Key) -> std::cmp::Ordering {
        let target_key = DhtKey::from_bytes(*key);
        a.peer_id
            .distance(&target_key)
            .cmp(&b.peer_id.distance(&target_key))
    }

    /// Return the K-closest candidate nodes, excluding the requester.
    ///
    /// Per Kademlia, a FindNode response should contain the K closest nodes
    /// the responder knows about — regardless of whether they are closer or
    /// farther than the responder itself. The requester is excluded because
    /// it already knows its own address.
    fn filter_response_nodes(
        candidate_nodes: Vec<DHTNode>,
        requester_peer_id: &PeerId,
    ) -> Vec<DHTNode> {
        candidate_nodes
            .into_iter()
            .filter(|node| node.peer_id != *requester_peer_id)
            .collect()
    }

    /// Build a `DHTNode` representing the local node for inclusion in
    /// K-closest results. The local node always participates in distance
    /// ranking but is never queried over the network.
    ///
    /// The published address list is sourced from:
    ///
    /// 1. The transport's externally-observed reflexive address (set by
    ///    OBSERVED_ADDRESS frames received from peers). This is the only
    ///    authoritative source for a NAT'd node — it is the actual post-NAT
    ///    address that remote peers see the connection arrive from.
    /// 2. The transport's runtime-bound `listen_addrs`, but **only when the
    ///    bind address has a specific (non-wildcard) IP**. Wildcard binds
    ///    (`0.0.0.0` / `[::]`) are bind-side concepts meaning "any interface"
    ///    and are not dialable, so we skip them entirely and rely on (1).
    ///
    /// If neither source produces an address, the returned `DHTNode` has an
    /// empty `addresses` vec. This is the right answer at the publish layer:
    /// it tells consumers "I don't know how to be reached yet" rather than
    /// lying with a bind-side wildcard or a guessed LAN IP that won't work
    /// from the public internet. The empty window closes naturally once the
    /// first peer connects to us and OBSERVED_ADDRESS flows.
    async fn local_dht_node(&self) -> DHTNode {
        let mut addresses: Vec<MultiAddr> = Vec::new();

        // 1. Observed external addresses — the post-NAT addresses peers
        //    actually see, learned from QUIC OBSERVED_ADDRESS frames.
        //    Empty until at least one peer has observed us. On a
        //    multi-homed host this can return multiple addresses (one per
        //    local interface that has an observation), and we publish all
        //    of them so peers reaching us via any interface can dial back.
        for observed in self.transport.observed_external_addresses() {
            let resolved = MultiAddr::quic(observed);
            if !addresses.contains(&resolved) {
                addresses.push(resolved);
            }
        }

        // 2. Runtime-bound listen addresses with specific IPs only. Wildcards
        //    and zero ports are pre-bind placeholders or all-interface
        //    bindings — neither is dialable.
        for la in self.transport.listen_addrs().await {
            let Some(sa) = la.dialable_socket_addr() else {
                continue;
            };
            if sa.port() == 0 || sa.ip().is_unspecified() {
                continue;
            }
            let resolved = MultiAddr::quic(sa);
            if !addresses.contains(&resolved) {
                addresses.push(resolved);
            }
        }

        DHTNode {
            peer_id: self.config.peer_id,
            addresses,
            distance: None,
            reliability: SELF_RELIABILITY_SCORE,
        }
    }

    /// Add the local app-level peer ID to `queried` so that iterative lookups
    /// never send RPCs to the local node.
    fn mark_self_queried(&self, queried: &mut HashSet<PeerId>) {
        queried.insert(self.config.peer_id);
    }

    /// Return all dialable addresses from a list of [`MultiAddr`] values.
    ///
    /// Only QUIC addresses are considered dialable. Unspecified (`0.0.0.0`)
    /// addresses are rejected. Loopback addresses are accepted for local/test
    /// use.
    fn dialable_addresses(addresses: &[MultiAddr]) -> Vec<MultiAddr> {
        addresses
            .iter()
            .filter(|addr| {
                let Some(sa) = addr.dialable_socket_addr() else {
                    trace!("Skipping non-dialable address: {addr}");
                    return false;
                };
                if sa.ip().is_unspecified() {
                    warn!("Rejecting unspecified address: {addr}");
                    return false;
                }
                if sa.ip().is_loopback() {
                    trace!("Accepting loopback address (local/test): {addr}");
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Return the first dialable address from a list of [`MultiAddr`] values.
    fn first_dialable_address(addresses: &[MultiAddr]) -> Option<MultiAddr> {
        Self::dialable_addresses(addresses).into_iter().next()
    }

    /// Rank a slice of referrer observations into an ordered list of
    /// hole-punch coordinator addresses, best-first, using this manager's
    /// [`TrustEngine`] (or default neutral trust when none is configured).
    ///
    /// Thin wrapper around the pure function [`Self::rank_referrers`] —
    /// see that for the actual ranking logic. The returned `Vec` is what
    /// gets handed to
    /// [`crate::transport::saorsa_transport_adapter::SaorsaDualStackTransport::set_hole_punch_preferred_coordinators`]
    /// so the transport's hole-punch loop can rotate through coordinators
    /// in order.
    fn rank_referrers_for_target(&self, referrers: Option<&[ReferrerInfo]>) -> Vec<SocketAddr> {
        let trust_for = |peer_id: &PeerId| -> f64 {
            self.trust_engine
                .as_ref()
                .map(|engine| engine.score(peer_id))
                .unwrap_or(DEFAULT_NEUTRAL_TRUST)
        };
        Self::rank_referrers(referrers, trust_for)
    }

    /// Pure ranking function that sorts a slice of referrer observations
    /// into a best-first list of coordinator addresses.
    ///
    /// Ranking (highest priority first):
    /// 1. **`round_observed` DESC** — referrers seen in later iteration
    ///    rounds are by XOR-distance closer to the lookup target and so
    ///    much more likely to actually have a live connection to it. This
    ///    naturally de-prefers round-0 bootstrap referrers without any
    ///    explicit bootstrap tagging, which is exactly the load-shedding
    ///    behaviour we want.
    /// 2. **trust score DESC** — when two referrers were observed in the
    ///    same round, prefer the one with the higher trust score returned
    ///    by `trust_for`.
    /// 3. **deterministic hash tiebreak** — when round and trust both tie,
    ///    prefer the referrer whose `peer_id` byte 0 is **larger**. Using
    ///    a pure peer-id ordering instead of a random RNG keeps the choice
    ///    reproducible across runs (useful for tests) while still
    ///    spreading load across coordinators because different targets
    ///    see different referrer sets.
    ///
    /// Returns an empty `Vec` when the slice is empty or `None` itself,
    /// so the caller can pass-through directly to
    /// `set_hole_punch_preferred_coordinators` (which treats an empty
    /// list as "remove the entry").
    ///
    /// Pure function (no `&self`) so it can be unit-tested without
    /// constructing a full [`DhtNetworkManager`].
    fn rank_referrers(
        referrers: Option<&[ReferrerInfo]>,
        trust_for: impl Fn(&PeerId) -> f64,
    ) -> Vec<SocketAddr> {
        let Some(list) = referrers else {
            return Vec::new();
        };
        if list.is_empty() {
            return Vec::new();
        }

        // Pre-compute trust scores once per referrer so the comparator
        // doesn't re-invoke the closure repeatedly during sort.
        let mut scored: Vec<(f64, &ReferrerInfo)> =
            list.iter().map(|r| (trust_for(&r.peer_id), r)).collect();

        scored.sort_by(|a, b| {
            // Primary: higher round wins → reverse so DESC sort.
            b.1.round_observed
                .cmp(&a.1.round_observed)
                // Secondary: higher trust wins (total_cmp sidesteps NaN
                // issues — score is bounded but total_cmp is safe
                // regardless). Reverse for DESC.
                .then_with(|| b.0.total_cmp(&a.0))
                // Tertiary: deterministic tiebreak — larger peer_id
                // byte 0 wins. Reverse for DESC.
                .then_with(|| b.1.peer_id.to_bytes()[0].cmp(&a.1.peer_id.to_bytes()[0]))
        });

        scored.into_iter().map(|(_, r)| r.addr).collect()
    }

    /// Merge a single referrer observation into the per-target slot table,
    /// preserving the round-aware ranking invariant.
    ///
    /// Behaviour:
    /// - Duplicate referrer (same `peer_id` already present): no-op.
    /// - Slot table not yet full: append.
    /// - Slot table full AND `new.round_observed` is strictly greater than
    ///   the current minimum round in the table: evict the lowest-round
    ///   entry and replace it with `new`.
    /// - Slot table full AND `new.round_observed <= min(table.rounds)`:
    ///   drop `new` (it would lose the dial-time ranking against every
    ///   existing entry anyway).
    ///
    /// The eviction path exists so that a burst of round-0 referrers (e.g.
    /// every bootstrap returning the same hot peer in the first DHT round)
    /// cannot lock out the higher-round referrers we actually prefer at
    /// dial-time. Without this, the slot cap silently degrades the
    /// round-aware ranking in exactly the case the PR is targeting.
    ///
    /// Pure function (no `&self`) so it can be unit-tested directly.
    fn merge_referrer_observation(
        entry: &mut Vec<ReferrerInfo>,
        new: ReferrerInfo,
        target_peer_id: &PeerId,
    ) {
        if entry.iter().any(|r| r.peer_id == new.peer_id) {
            return;
        }
        if entry.len() < MAX_REFERRERS_PER_TARGET {
            info!(
                "find_closest_nodes_network: peer {} referred by {} ({}) round {}",
                hex::encode(&target_peer_id.to_bytes()[..8]),
                hex::encode(&new.peer_id.to_bytes()[..8]),
                new.addr,
                new.round_observed,
            );
            entry.push(new);
            return;
        }
        // Slot full — evict the lowest-round entry only if `new` is
        // strictly later.
        if let Some((min_idx, min_referrer)) = entry
            .iter()
            .enumerate()
            .min_by_key(|(_, r)| r.round_observed)
            && min_referrer.round_observed < new.round_observed
        {
            info!(
                "find_closest_nodes_network: peer {} referrer slot full — evicting round {} entry ({}) for round {} entry from {} ({})",
                hex::encode(&target_peer_id.to_bytes()[..8]),
                min_referrer.round_observed,
                min_referrer.addr,
                new.round_observed,
                hex::encode(&new.peer_id.to_bytes()[..8]),
                new.addr,
            );
            entry[min_idx] = new;
        }
    }

    /// Try dialing each dialable address in `addresses` in order until one
    /// succeeds. Returns the channel ID of the first successful dial, or
    /// `None` if every address was rejected, failed, or timed out.
    ///
    /// This is the multi-address counterpart of [`Self::dial_candidate`]
    /// and is the right entry point for any code path that has been handed
    /// a `DHTNode` (or any peer entry that exposes multiple addresses) —
    /// using only the first dialable address means a stale NAT binding,
    /// failed relay, or unreachable family kills the connection attempt
    /// even when other published addresses would have worked.
    async fn dial_addresses(
        &self,
        peer_id: &PeerId,
        addresses: &[MultiAddr],
        referrers: &[SocketAddr],
    ) -> Option<String> {
        let dialable = Self::dialable_addresses(addresses);
        if dialable.is_empty() {
            debug!(
                "dial_addresses: no dialable addresses for {}",
                peer_id.to_hex()
            );
            return None;
        }
        for addr in &dialable {
            if let Some(channel_id) = self.dial_candidate(peer_id, addr, referrers).await {
                return Some(channel_id);
            }
        }
        debug!(
            "dial_addresses: all {} address(es) failed for {}",
            dialable.len(),
            peer_id.to_hex()
        );
        None
    }

    async fn record_peer_failure(&self, peer_id: &PeerId) {
        if let Some(ref engine) = self.trust_engine {
            engine.update_node_stats(
                peer_id,
                crate::adaptive::NodeStatisticsUpdate::FailedResponse,
            );
        }
    }

    /// Dial coalescing: ensure at most one in-flight `dial_addresses` per
    /// `peer_id` across all concurrent `send_dht_request` calls.
    ///
    /// # Outcome shape
    ///
    /// Returns `Ok(Some(channel_id))` when this call (or a coalesced
    /// predecessor) successfully established a channel to `peer_id`.
    /// Returns `Ok(None)` when the dial attempt completed without yielding
    /// a usable channel (the peer is unreachable on every candidate
    /// address). Returns `Err` only if the underlying transport call panics
    /// out of the dial future — the dial path itself swallows individual
    /// connect errors and surfaces them as `Ok(None)`.
    ///
    /// # Coalescing semantics
    ///
    /// 1. The first caller to a peer inserts a fresh `Notify` into
    ///    `inflight_dials`, runs the dial inline, removes the entry, and
    ///    finally calls `notify_waiters()` to wake every secondary caller
    ///    blocked on the same peer.
    /// 2. Secondary callers find an existing entry, await `notified()`
    ///    *before* re-checking, and then ask the transport whether the
    ///    peer is now connected. They do **not** receive the channel_id
    ///    from the first caller — saorsa-transport's connection map is the
    ///    canonical source, and querying it after the wake handles every
    ///    success path uniformly (direct connect, hole-punch, relay).
    /// 3. If the first caller fails, secondary callers see no live
    ///    connection after their re-check and propagate the same `None`
    ///    result rather than starting their own racing dial. They will
    ///    retry on the *next* `send_dht_request` call, which is the right
    ///    granularity for backoff.
    ///
    /// This eliminates the racing-dial cascade that previously caused N
    /// concurrent DHT lookups against the same peer to each issue their
    /// own coordinator-rotation pass, producing the "duplicate connection"
    /// close storm under symmetric NAT.
    async fn dial_or_await_inflight(
        &self,
        peer_id: &PeerId,
        addresses: &[MultiAddr],
        referrers: &[SocketAddr],
    ) -> Option<String> {
        // Fast path: peer is already connected — no dial needed.
        if self.transport.is_peer_connected(peer_id).await {
            return self
                .transport
                .channels_for_peer(peer_id)
                .await
                .into_iter()
                .next();
        }

        // Try to claim the dial slot for this peer. The DashMap entry API
        // is the single point of mutual exclusion: exactly one caller
        // observes `Vacant` and proceeds to dial; everyone else observes
        // `Occupied` and falls into the wait branch below.
        enum Slot {
            Owner(Arc<Notify>),
            Waiter(Arc<Notify>),
        }
        let slot = match self.inflight_dials.entry(*peer_id) {
            dashmap::mapref::entry::Entry::Vacant(v) => {
                let notify = Arc::new(Notify::new());
                v.insert(Arc::clone(&notify));
                Slot::Owner(notify)
            }
            dashmap::mapref::entry::Entry::Occupied(o) => Slot::Waiter(Arc::clone(o.get())),
        };

        match slot {
            Slot::Owner(notify) => {
                // RAII guard ensures the inflight entry is removed and
                // waiters are notified even if `dial_addresses` panics or
                // the future is cancelled. Without this, a panic in the
                // dial path would leave waiters blocked on `notified()`
                // forever, since they have no timeout of their own.
                let _guard = InflightDialGuard {
                    inflight: Arc::clone(&self.inflight_dials),
                    peer_id: *peer_id,
                    notify: Arc::clone(&notify),
                };
                self.dial_addresses(peer_id, addresses, referrers).await
            }
            Slot::Waiter(notify) => {
                debug!(
                    peer = %peer_id.to_hex(),
                    "Dial coalescing: awaiting in-flight dial",
                );
                notify.notified().await;
                // The owning caller's dial has finished. If it succeeded,
                // the peer is now connected and we can pick up its channel
                // from the transport. If it failed, we return None and let
                // the caller surface the failure exactly as it would have
                // for a direct dial.
                if self.transport.is_peer_connected(peer_id).await {
                    self.transport
                        .channels_for_peer(peer_id)
                        .await
                        .into_iter()
                        .next()
                } else {
                    None
                }
            }
        }
    }

    /// Remove expired operations from `active_operations`.
    ///
    /// Uses a 2x timeout multiplier as safety margin. Called at the start of
    /// `send_dht_request` to clean up orphaned entries from dropped futures.
    fn sweep_expired_operations(&self) {
        let mut ops = match self.active_operations.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "active_operations mutex poisoned in sweep_expired_operations, recovering"
                );
                poisoned.into_inner()
            }
        };
        let now = Instant::now();
        ops.retain(|id, ctx| {
            let expired = now.duration_since(ctx.started_at) > ctx.timeout * 2;
            if expired {
                warn!(
                    "Sweeping expired DHT operation {id} (age {:?}, timeout {:?})",
                    now.duration_since(ctx.started_at),
                    ctx.timeout
                );
            }
            !expired
        });
    }

    /// Send a DHT request to a specific peer.
    ///
    /// When `address_hint` is provided (e.g. from a `DHTNode` in an iterative
    /// lookup), it is used directly for dialling without a routing-table lookup.
    async fn send_dht_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
        address_hint: Option<&MultiAddr>,
    ) -> Result<DhtNetworkResult> {
        // Sweep stale entries left by dropped futures before adding a new one
        self.sweep_expired_operations();

        let message_id = Uuid::new_v4().to_string();

        let message = DhtNetworkMessage {
            message_id: message_id.clone(),
            source: self.config.peer_id,
            target: Some(*peer_id),
            message_type: DhtMessageType::Request,
            payload: operation,
            result: None, // Requests don't have results
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: 10,
            hop_count: 0,
        };

        // Serialize message
        let message_data = postcard::to_stdvec(&message)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Create oneshot channel for response delivery
        // This eliminates TOCTOU races - no polling, no shared mutable state
        let (response_tx, response_rx) = oneshot::channel();

        // Only track app-level peer IDs. Transport IDs identify communication
        // channels, not peers — multiple peers may share one transport in the future.
        let contacted_nodes = vec![*peer_id];

        // Create operation context for tracking
        let operation_context = DhtOperationContext {
            operation: message.payload.clone(),
            peer_id: *peer_id,
            started_at: Instant::now(),
            timeout: self.config.request_timeout,
            contacted_nodes,
            response_tx: Some(response_tx),
        };

        if let Ok(mut ops) = self.active_operations.lock() {
            ops.insert(message_id.clone(), operation_context);
        }

        // Send message via network layer, reconnecting on demand if needed.
        let peer_hex = peer_id.to_hex();
        let local_hex = self.config.peer_id.to_hex();
        info!(
            "[STEP 1] {} -> {}: Sending {:?} request (msg_id: {})",
            local_hex, peer_hex, message.payload, message_id
        );

        // Ensure we have an open channel to the peer before sending.
        // A fresh dial establishes a QUIC connection but the app-level
        // `peer_to_channel` mapping is only populated after the asynchronous
        // identity-exchange handshake completes. Without waiting, the
        // subsequent `send_message` would fail with `PeerNotFound`.
        //
        // Build the candidate address list: caller's hint first (if any),
        // then the peer's addresses from the routing table. Trying every
        // candidate — instead of stopping at the first — protects against
        // stale NAT bindings, single-IP-family failures, and recently-relayed
        // peers whose direct address is no longer reachable.
        let candidate_addresses: Vec<MultiAddr> = if self.transport.is_peer_connected(peer_id).await
        {
            Vec::new()
        } else {
            let mut addrs = Vec::new();
            if let Some(hint) = address_hint {
                addrs.push(hint.clone());
            }
            for addr in self.peer_addresses_for_dial(peer_id).await {
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
            addrs
        };

        if !candidate_addresses.is_empty() {
            info!(
                "[STEP 1b] {} -> {}: No open channel, trying {} dialable address(es)",
                local_hex,
                peer_hex,
                candidate_addresses.len()
            );
            if let Some(channel_id) = self
                .dial_or_await_inflight(peer_id, &candidate_addresses, &[])
                .await
            {
                let identity_timeout = self.config.request_timeout.min(IDENTITY_EXCHANGE_TIMEOUT);
                match self
                    .transport
                    .wait_for_peer_identity(&channel_id, identity_timeout)
                    .await
                {
                    Ok(authenticated) => {
                        if &authenticated != peer_id {
                            warn!(
                                "[STEP 1b] {} -> {}: identity MISMATCH — authenticated as {}. \
                                 Routing table entry may be stale.",
                                local_hex,
                                peer_hex,
                                authenticated.to_hex()
                            );
                            if let Ok(mut ops) = self.active_operations.lock() {
                                ops.remove(&message_id);
                            }
                            return Err(P2PError::Identity(IdentityError::IdentityMismatch {
                                expected: peer_hex.into(),
                                actual: authenticated.to_hex().into(),
                            }));
                        }
                        debug!(
                            "[STEP 1b] {} -> {}: identity confirmed ({})",
                            local_hex,
                            peer_hex,
                            authenticated.to_hex()
                        );
                    }
                    Err(e) => {
                        warn!(
                            "[STEP 1b] {} -> {}: identity exchange failed, disconnecting channel: {}",
                            local_hex, peer_hex, e
                        );
                        self.transport.disconnect_channel(&channel_id).await;
                        if let Ok(mut ops) = self.active_operations.lock() {
                            ops.remove(&message_id);
                        }
                        self.record_peer_failure(peer_id).await;
                        return Err(P2PError::Network(NetworkError::ProtocolError(
                            format!("identity exchange with {} failed: {}", peer_hex, e).into(),
                        )));
                    }
                }
            } else {
                warn!(
                    "[STEP 1b] {} -> {}: dial failed for all {} candidate address(es)",
                    local_hex,
                    peer_hex,
                    candidate_addresses.len()
                );
                if let Ok(mut ops) = self.active_operations.lock() {
                    ops.remove(&message_id);
                }
                self.record_peer_failure(peer_id).await;
                return Err(P2PError::Network(NetworkError::PeerNotFound(
                    format!(
                        "failed to dial {} at any of {} candidate address(es)",
                        peer_hex,
                        candidate_addresses.len()
                    )
                    .into(),
                )));
            }
        }

        let result = match self
            .transport
            .send_message(peer_id, "/dht/1.0.0", message_data)
            .await
        {
            Ok(_) => {
                info!(
                    "[STEP 2] {} -> {}: Message sent successfully, waiting for response...",
                    local_hex, peer_hex
                );

                // Wait for response via oneshot channel with timeout
                let result = self
                    .wait_for_response(&message_id, response_rx, peer_id)
                    .await;
                match &result {
                    Ok(r) => info!(
                        "[STEP 6] {} <- {}: Got response: {:?}",
                        local_hex,
                        peer_hex,
                        std::mem::discriminant(r)
                    ),
                    Err(e) => warn!(
                        "[STEP 6 FAILED] {} <- {}: Response error: {}",
                        local_hex, peer_hex, e
                    ),
                }
                result
            }
            Err(e) => {
                warn!(
                    "[STEP 1 FAILED] Failed to send DHT request to {}: {}",
                    peer_hex, e
                );
                Err(e)
            }
        };

        // Explicit cleanup — no Drop guard, no tokio::spawn required
        if let Ok(mut ops) = self.active_operations.lock() {
            ops.remove(&message_id);
        }

        // Record trust failure at the RPC level so every failed request
        // (send error, response timeout, etc.) is counted exactly once.
        if result.is_err() {
            self.record_peer_failure(peer_id).await;
        }

        result
    }

    /// Check whether `peer_id` refers to this node.
    fn is_local_peer_id(&self, peer_id: &PeerId) -> bool {
        *peer_id == self.config.peer_id
    }

    /// Resolve any peer identifier to a canonical app-level peer ID.
    ///
    /// For signed messages the event `source` is already the app-level peer ID
    /// (set by `parse_protocol_message`), so `is_known_app_peer_id` succeeds
    /// directly. For unsigned connections the channel ID itself is used as
    /// identity (e.g. in tests).
    async fn canonical_app_peer_id(&self, peer_id: &PeerId) -> Option<PeerId> {
        // Check if this is a known app-level peer ID
        if self.transport.is_known_app_peer_id(peer_id).await {
            return Some(*peer_id);
        }
        // Fallback: connected transport peer (unsigned connections)
        if self.transport.is_peer_connected(peer_id).await {
            return Some(*peer_id);
        }
        None
    }

    /// Attempt to connect to a candidate peer with a timeout derived from the node config.
    ///
    /// All iterative lookups share the same saorsa-transport connection pool, so reusing the node's
    /// connection timeout keeps behavior consistent with the transport while still letting
    /// us parallelize lookups safely.
    ///
    /// Returns the transport channel ID on a successful QUIC connection, or
    /// `None` when the dial fails or is skipped. Callers that need to send
    /// messages immediately should pass the channel ID to
    /// [`TransportHandle::wait_for_peer_identity`] before sending, because
    /// the app-level `peer_to_channel` mapping is only populated after the
    /// asynchronous identity-exchange handshake completes.
    async fn dial_candidate(
        &self,
        peer_id: &PeerId,
        address: &MultiAddr,
        referrers: &[std::net::SocketAddr],
    ) -> Option<String> {
        let peer_hex = peer_id.to_hex();

        if self.transport.is_peer_connected(peer_id).await {
            debug!("dial_candidate: peer {} already connected", peer_hex);
            return None;
        }

        // Reject unspecified addresses before attempting the connection.
        if address.ip().is_some_and(|ip| ip.is_unspecified()) {
            debug!(
                "dial_candidate: rejecting unspecified address for {}: {}",
                peer_hex, address
            );
            return None;
        }
        // Set the target peer ID for this specific address so the hole-punch
        // PUNCH_ME_NOW can route by peer identity. Keyed by address to avoid
        // races when multiple concurrent dials share the same transport.
        if let Some(socket_addr) = address.dialable_socket_addr() {
            let pid_bytes = *peer_id.to_bytes();
            info!(
                "dial_candidate: setting hole_punch_target_peer_id for {} = {}",
                socket_addr,
                hex::encode(&pid_bytes[..8])
            );
            self.transport
                .set_hole_punch_target_peer_id(socket_addr, pid_bytes)
                .await;
        }

        // Hand the full ranked list of referrers to saorsa-transport so its
        // hole-punch loop can rotate through them in order. The first
        // `K - 1` get a short per-attempt timeout (~1.5s) so a busy or
        // unreachable referrer is abandoned quickly; the final entry gets
        // the strategy's full hole-punch timeout to give it time to
        // actually complete the punch. An empty list removes any prior
        // preference for this target — see
        // [`Self::rank_referrers_for_target`].
        if let Some(socket_addr) = address.dialable_socket_addr() {
            info!(
                "dial_candidate: setting {} preferred coordinator(s) for {} (DHT referrers): {:?}",
                referrers.len(),
                socket_addr,
                referrers
            );
            self.transport
                .set_hole_punch_preferred_coordinators(socket_addr, referrers.to_vec())
                .await;
        }

        let dial_timeout = self
            .transport
            .connection_timeout()
            .min(self.config.request_timeout);
        match tokio::time::timeout(dial_timeout, self.transport.connect_peer(address)).await {
            Ok(Ok(channel_id)) => {
                debug!(
                    "dial_candidate: connected to {} at {} (channel {})",
                    peer_hex, address, channel_id
                );
                Some(channel_id)
            }
            Ok(Err(e)) => {
                debug!(
                    "dial_candidate: failed to connect to {} at {}: {}",
                    peer_hex, address, e
                );
                None
            }
            Err(_) => {
                debug!(
                    "dial_candidate: timeout connecting to {} at {} (>{:?})",
                    peer_hex, address, dial_timeout
                );
                None
            }
        }
    }

    /// Look up connectable addresses for `peer_id`.
    ///
    /// Checks the DHT routing table first (source of truth for DHT peer
    /// addresses), then falls back to the transport layer for connected peers.
    /// Returns an empty vec when the peer is unknown or has no addresses.
    pub(crate) async fn peer_addresses_for_dial(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        // 1. Routing table — filter to dialable QUIC addresses (the table
        //    can hold unspecified or non-QUIC entries from peer announcements).
        let addrs = self.dht.read().await.get_node_addresses(peer_id).await;
        let filtered = Self::dialable_addresses(&addrs);
        if !filtered.is_empty() {
            return filtered;
        }

        // 2. Transport layer — for connected peers not yet in the routing table
        if let Some(info) = self.transport.peer_info(peer_id).await {
            return Self::dialable_addresses(&info.addresses);
        }

        Vec::new()
    }

    /// Wait for DHT network response via oneshot channel with timeout
    ///
    /// Uses oneshot channel instead of polling to eliminate TOCTOU races entirely.
    /// The channel is created in send_dht_request and the sender is stored in the
    /// operation context. When handle_dht_response receives a response, it sends
    /// through the channel. This function awaits on the receiver with timeout.
    ///
    /// When the oneshot sender is dropped, the receiver gets a `RecvError`
    /// and we return a `ProtocolError`.
    ///
    /// Note: cleanup of `active_operations` is handled by explicit removal in the
    /// caller (`send_dht_request`), so this method does not remove entries itself.
    async fn wait_for_response(
        &self,
        _message_id: &str,
        response_rx: oneshot::Receiver<(PeerId, DhtNetworkResult)>,
        _peer_id: &PeerId,
    ) -> Result<DhtNetworkResult> {
        let response_timeout = self.config.request_timeout;

        // Wait for response with timeout - no polling, no TOCTOU race
        match tokio::time::timeout(response_timeout, response_rx).await {
            Ok(Ok((_source, result))) => Ok(result),
            Ok(Err(_recv_error)) => {
                // Channel closed without response (sender dropped).
                Err(P2PError::Network(NetworkError::ProtocolError(
                    "Response channel closed unexpectedly".into(),
                )))
            }
            Err(_timeout) => Err(P2PError::Network(NetworkError::Timeout)),
        }
    }

    /// Handle incoming DHT message
    pub async fn handle_dht_message(
        &self,
        data: &[u8],
        sender: &PeerId,
    ) -> Result<Option<Vec<u8>>> {
        // SEC: Reject oversized messages before deserialization to prevent memory exhaustion
        if data.len() > MAX_MESSAGE_SIZE {
            warn!(
                "Rejecting oversized DHT message from {sender}: {} bytes (max: {MAX_MESSAGE_SIZE})",
                data.len()
            );
            return Err(P2PError::Validation(
                format!(
                    "Message size {} bytes exceeds maximum allowed size of {MAX_MESSAGE_SIZE} bytes",
                    data.len()
                )
                .into(),
            ));
        }

        // Deserialize message
        let message: DhtNetworkMessage = postcard::from_bytes(data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        debug!(
            "[STEP 3] {}: Received {:?} from {} (msg_id: {})",
            self.config.peer_id.to_hex(),
            message.message_type,
            sender,
            message.message_id
        );

        // Update peer info
        self.update_peer_info(*sender, &message).await;

        match message.message_type {
            DhtMessageType::Request => {
                debug!(
                    "[STEP 3a] {}: Processing {:?} request from {}",
                    self.config.peer_id.to_hex(),
                    message.payload,
                    sender
                );
                let result = self.handle_dht_request(&message, sender).await?;
                debug!(
                    "[STEP 4] {}: Sending response {:?} back to {} (msg_id: {})",
                    self.config.peer_id.to_hex(),
                    std::mem::discriminant(&result),
                    sender,
                    message.message_id
                );
                let response = self.create_response_message(&message, result)?;
                Ok(Some(postcard::to_stdvec(&response).map_err(|e| {
                    P2PError::Serialization(e.to_string().into())
                })?))
            }
            DhtMessageType::Response => {
                debug!(
                    "[STEP 5] {}: Received response from {} (msg_id: {})",
                    self.config.peer_id.to_hex(),
                    sender,
                    message.message_id
                );
                self.handle_dht_response(&message, sender).await?;
                Ok(None)
            }
            DhtMessageType::Broadcast => {
                self.handle_dht_broadcast(&message).await?;
                Ok(None)
            }
            DhtMessageType::Error => {
                warn!("Received DHT error message: {:?}", message);
                Ok(None)
            }
        }
    }

    /// Handle DHT request message.
    ///
    /// `authenticated_sender` is the transport-authenticated peer ID, used
    /// instead of the self-reported `message.source` for any security-sensitive
    /// decisions (e.g. filtering nodes in lookup responses).
    async fn handle_dht_request(
        &self,
        message: &DhtNetworkMessage,
        authenticated_sender: &PeerId,
    ) -> Result<DhtNetworkResult> {
        match &message.payload {
            DhtNetworkOperation::FindNode { key } => {
                debug!("Handling FIND_NODE request for key: {}", hex::encode(key));
                self.handle_find_node_request(key, authenticated_sender)
                    .await
            }
            DhtNetworkOperation::Ping => {
                debug!("Handling PING request from: {}", authenticated_sender);
                Ok(DhtNetworkResult::PongReceived {
                    responder: self.config.peer_id,
                    latency: Duration::from_millis(0), // Local response
                })
            }
            DhtNetworkOperation::Join => {
                debug!("Handling JOIN request from: {}", authenticated_sender);
                let dht_key = *authenticated_sender.as_bytes();

                // Node will be added to routing table through normal DHT operations
                debug!("Node {} joined the network", authenticated_sender);

                Ok(DhtNetworkResult::JoinSuccess {
                    assigned_key: dht_key,
                    bootstrap_peers: 1,
                })
            }
            DhtNetworkOperation::Leave => {
                debug!("Handling LEAVE request from: {}", authenticated_sender);
                Ok(DhtNetworkResult::LeaveSuccess)
            }
            DhtNetworkOperation::PublishAddress { addresses } => {
                info!(
                    "Handling PUBLISH_ADDRESS from {}: {} addresses",
                    authenticated_sender,
                    addresses.len()
                );
                let dht = self.dht.read().await;
                for addr in addresses {
                    dht.touch_node_typed(
                        authenticated_sender,
                        Some(addr),
                        crate::dht::AddressType::Relay,
                    )
                    .await;
                }
                Ok(DhtNetworkResult::PublishAddressAck)
            }
        }
    }

    /// Send a DHT request directly to a peer.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
    ) -> Result<DhtNetworkResult> {
        self.send_dht_request(peer_id, operation, None).await
    }

    /// Handle DHT response message
    ///
    /// Delivers the response via oneshot channel to the waiting request coroutine.
    /// Uses oneshot channel instead of shared Vec to eliminate TOCTOU races.
    ///
    /// Security: Resolves the sender to an authenticated app-level peer ID and
    /// verifies it matches a contacted peer. Transport IDs identify channels,
    /// not peers, so they are never used for authorization.
    async fn handle_dht_response(
        &self,
        message: &DhtNetworkMessage,
        sender: &PeerId,
    ) -> Result<()> {
        let message_id = &message.message_id;
        debug!("Handling DHT response for message_id: {message_id}");

        // Get the result from the response message
        let result = match &message.result {
            Some(r) => r.clone(),
            None => {
                warn!("DHT response message {message_id} has no result field");
                return Ok(());
            }
        };

        // Resolve sender to app-level identity. Transport IDs identify channels,
        // not peers, so unauthenticated senders are rejected outright.
        let Some(sender_app_id) = self.canonical_app_peer_id(sender).await else {
            warn!(
                "Rejecting DHT response for {message_id}: sender {} has no authenticated app identity",
                sender
            );
            return Ok(());
        };

        // Find the active operation and send response via oneshot channel
        let Ok(mut ops) = self.active_operations.lock() else {
            warn!("active_operations mutex poisoned");
            return Ok(());
        };
        if let Some(context) = ops.get_mut(message_id) {
            // Authenticate solely on app-level peer ID.
            let source_authorized = context.peer_id == sender_app_id
                || context.contacted_nodes.contains(&sender_app_id);

            if !source_authorized {
                warn!(
                    "Rejecting DHT response for {message_id}: sender app_id {} \
                     (transport={}) not in contacted peers (expected {} or one of {:?})",
                    sender_app_id.to_hex(),
                    sender,
                    context.peer_id.to_hex(),
                    context
                        .contacted_nodes
                        .iter()
                        .map(PeerId::to_hex)
                        .collect::<Vec<_>>()
                );
                return Ok(());
            }

            // Take the sender out of the context (can only send once)
            if let Some(tx) = context.response_tx.take() {
                debug!(
                    "[STEP 5a] {}: Delivering response for msg_id {} to waiting request",
                    self.config.peer_id.to_hex(),
                    message_id
                );
                // Send the transport-authenticated sender identity, not the
                // self-reported message.source which could be spoofed.
                if tx.send((sender_app_id, result)).is_err() {
                    warn!(
                        "[STEP 5a FAILED] {}: Response channel closed for msg_id {} (receiver timed out)",
                        self.config.peer_id.to_hex(),
                        message_id
                    );
                }
            } else {
                debug!(
                    "Response already delivered for message_id: {message_id}, ignoring duplicate"
                );
            }
        } else {
            warn!(
                "[STEP 5 FAILED] {}: No active operation found for msg_id {} (may have timed out)",
                self.config.peer_id.to_hex(),
                message_id
            );
        }

        Ok(())
    }

    /// Handle DHT broadcast message
    async fn handle_dht_broadcast(&self, _message: &DhtNetworkMessage) -> Result<()> {
        // Handle broadcast messages (for network-wide announcements)
        debug!("DHT broadcast handling not fully implemented yet");
        Ok(())
    }

    /// Create response message
    fn create_response_message(
        &self,
        request: &DhtNetworkMessage,
        result: DhtNetworkResult,
    ) -> Result<DhtNetworkMessage> {
        // Create a minimal payload that echoes the original operation type
        // Each variant explicitly extracts its key to avoid silent fallbacks
        let payload = match &result {
            DhtNetworkResult::NodesFound { key, .. } => DhtNetworkOperation::FindNode { key: *key },
            DhtNetworkResult::PongReceived { .. } => DhtNetworkOperation::Ping,
            DhtNetworkResult::JoinSuccess { .. } => DhtNetworkOperation::Join,
            DhtNetworkResult::LeaveSuccess => DhtNetworkOperation::Leave,
            // Use Ping as a lightweight ack — avoids echoing the full
            // PublishAddress payload (which contains the address list).
            DhtNetworkResult::PublishAddressAck => DhtNetworkOperation::Ping,
            DhtNetworkResult::PeerRejected => request.payload.clone(),
            DhtNetworkResult::Error { .. } => {
                return Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Cannot create response for error result".to_string().into(),
                )));
            }
        };

        Ok(DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: self.config.peer_id,
            target: Some(request.source),
            message_type: DhtMessageType::Response,
            payload,
            result: Some(result),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count.saturating_add(1),
        })
    }

    /// Update routing-table liveness (and address) for a peer on successful
    /// message exchange.
    ///
    /// Standard Kademlia: any successful RPC proves liveness. We touch the
    /// routing table entry to move it to the tail of its k-bucket and refresh
    /// the stored address so that `FindNode` responses stay current when a peer
    /// reconnects from a different endpoint.
    async fn update_peer_info(&self, peer_id: PeerId, _message: &DhtNetworkMessage) {
        let Some(app_peer_id) = self.canonical_app_peer_id(&peer_id).await else {
            debug!(
                "Ignoring DHT peer update for unauthenticated transport peer {}",
                peer_id
            );
            return;
        };

        // Transport-layer address is tagged as Direct. The typed merge
        // ensures it never displaces a Relay address at the front.
        // NATted addresses (from NAT connections) are handled separately
        // by the DHT bridge which tags them explicitly.
        let transport_addr = self
            .transport
            .peer_info(&app_peer_id)
            .await
            .and_then(|info| Self::first_dialable_address(&info.addresses));

        let dht = self.dht.read().await;
        if dht
            .touch_node_typed(
                &app_peer_id,
                transport_addr.as_ref(),
                crate::dht::AddressType::Direct,
            )
            .await
        {
            trace!("Touched routing table entry for {}", app_peer_id.to_hex());
        }
    }

    /// Reconcile already-connected peers into DHT bookkeeping/routing.
    ///
    /// Looks up each peer's actual user agent from the transport layer.
    /// Peers whose user agent is not yet known (e.g. identity announce still
    /// in flight) are skipped — they will be handled by the normal
    /// `PeerConnected` event path once authentication completes.
    async fn reconcile_connected_peers(&self) {
        let connected = self.transport.connected_peers().await;
        if connected.is_empty() {
            return;
        }

        info!(
            "Reconciling {} already-connected peers for DHT state",
            connected.len()
        );
        let mut skipped = 0u32;
        for peer_id in connected {
            if let Some(ua) = self.transport.peer_user_agent(&peer_id).await {
                self.handle_peer_connected(peer_id, &ua).await;
            } else {
                skipped += 1;
                debug!(
                    "Skipping reconciliation for peer {} — user agent not yet known",
                    peer_id.to_hex()
                );
            }
        }
        if skipped > 0 {
            info!(
                "Skipped {} peers during reconciliation (user agent unknown, will arrive via PeerConnected)",
                skipped
            );
        }
    }

    /// Handle an authenticated peer connection event.
    ///
    /// The `node_id` is the authenticated app-level [`PeerId`] — no
    /// `canonical_app_peer_id()` lookup is needed because `PeerConnected`
    /// only fires after identity verification.
    async fn handle_peer_connected(&self, node_id: PeerId, user_agent: &str) {
        let app_peer_id_hex = node_id.to_hex();

        // The first `PeerConnected` event for a peer is emitted by the
        // lifecycle monitor at TLS-handshake time, when the peer's identity
        // is known but no signed application message has arrived yet — so
        // its user-agent string is empty. Routing-table classification
        // requires `is_dht_participant(user_agent)`, which would
        // misclassify every peer as ephemeral on this first call. Defer
        // until the shard consumer re-emits `PeerConnected` with the
        // user-agent extracted from the first signed message (typically a
        // DHT ping or find_node within one round trip of the handshake).
        if user_agent.is_empty() {
            debug!(
                "DHT peer connected (TLS handshake): app_id={} — deferring routing classification until user_agent learned",
                app_peer_id_hex
            );
            return;
        }

        info!(
            "DHT peer connected: app_id={}, user_agent={}",
            app_peer_id_hex, user_agent
        );
        let dht_key = *node_id.as_bytes();

        // peer_info() resolves app-level IDs internally via peer_to_channel.
        // Collect all dialable addresses — peers may be multi-homed or
        // reachable via multiple NAT traversal endpoints.
        let addresses = if let Some(info) = self.transport.peer_info(&node_id).await {
            Self::dialable_addresses(&info.addresses)
        } else {
            warn!("peer_info unavailable for app_peer_id {}", app_peer_id_hex);
            Vec::new()
        };

        // Skip peers with no addresses — they cannot be used for DHT routing.
        if addresses.is_empty() {
            warn!(
                "Peer {} has no valid addresses, skipping DHT routing table addition",
                app_peer_id_hex
            );
            return;
        }

        // Only add full nodes to the DHT routing table. Ephemeral clients
        // (user_agent not starting with "node/") are excluded to prevent stale
        // addresses from polluting peer discovery after the client disconnects.
        if !crate::network::is_dht_participant(user_agent) {
            info!(
                "Skipping DHT routing table for ephemeral peer {} (user_agent={})",
                app_peer_id_hex, user_agent
            );
        } else {
            let address_types = vec![crate::dht::AddressType::Direct; addresses.len()];
            let node_info = NodeInfo {
                id: node_id,
                addresses,
                address_types,
                last_seen: AtomicInstant::now(),
            };

            let trust_fn = |peer_id: &PeerId| -> f64 {
                self.trust_engine
                    .as_ref()
                    .map(|engine| engine.score(peer_id))
                    .unwrap_or(DEFAULT_NEUTRAL_TRUST)
            };
            let add_result = self.dht.write().await.add_node(node_info, &trust_fn).await;
            match add_result {
                Ok(AdmissionResult::Admitted(rt_events)) => {
                    info!("Added peer {} to DHT routing table", app_peer_id_hex);
                    self.broadcast_routing_events(&rt_events);
                }
                Ok(AdmissionResult::StaleRevalidationNeeded {
                    candidate,
                    candidate_ips,
                    candidate_bucket_idx,
                    stale_peers,
                }) => {
                    debug!(
                        "Peer {} admission deferred: {} stale peers need revalidation",
                        app_peer_id_hex,
                        stale_peers.len()
                    );
                    match self
                        .revalidate_and_retry_admission(
                            candidate,
                            candidate_ips,
                            candidate_bucket_idx,
                            stale_peers,
                            &trust_fn,
                        )
                        .await
                    {
                        Ok(rt_events) => {
                            info!(
                                "Added peer {} to DHT routing table after stale revalidation",
                                app_peer_id_hex
                            );
                            self.broadcast_routing_events(&rt_events);
                        }
                        Err(e) => {
                            warn!(
                                "Stale revalidation for peer {} failed: {}",
                                app_peer_id_hex, e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to add peer {} to DHT routing table: {}",
                        app_peer_id_hex, e
                    );
                }
            }
        }

        if self.event_tx.receiver_count() > 0 {
            let _ = self.event_tx.send(DhtNetworkEvent::PeerDiscovered {
                peer_id: node_id,
                dht_key,
            });
        }
    }

    /// Start network event handler
    async fn start_network_event_handler(&self, self_arc: Arc<Self>) -> Result<()> {
        info!("Starting network event handler...");

        // Subscribe to network events from transport layer
        let mut events = self.transport.subscribe_events();

        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        info!("Network event handler shutting down");
                        break;
                    }
                    recv = events.recv() => {
                        match recv {
                            Ok(event) => match event {
                                crate::network::P2PEvent::PeerConnected(peer_id, ref user_agent) => {
                                    self_arc.handle_peer_connected(peer_id, user_agent).await;
                                }
                                crate::network::P2PEvent::PeerDisconnected(peer_id) => {
                                    // peer_id IS the authenticated app-level PeerId.
                                    // PeerDisconnected only fires when all channels for
                                    // this peer have closed — no multi-channel check needed.
                                    info!(
                                        "DHT peer fully disconnected: app_id={}",
                                        peer_id.to_hex()
                                    );

                                    if self_arc.event_tx.receiver_count() > 0
                                        && let Err(e) = self_arc
                                            .event_tx
                                            .send(DhtNetworkEvent::PeerDisconnected {
                                                peer_id,
                                            })
                                    {
                                        warn!(
                                            "Failed to send PeerDisconnected event: {}",
                                            e
                                        );
                                    }
                                }
                                crate::network::P2PEvent::Message {
                                    topic,
                                    source,
                                    data,
                                } => {
                                    trace!(
                                        "  [EVENT] Message received: topic={}, source={:?}, {} bytes",
                                        topic,
                                        source,
                                        data.len()
                                    );
                                    if topic == "/dht/1.0.0" {
                                        // DHT messages must be authenticated.
                                        let Some(source_peer) = source else {
                                            warn!("Ignoring unsigned DHT message");
                                            continue;
                                        };
                                        trace!("  [EVENT] Processing DHT message from {}", source_peer);
                                        // Process the DHT message with backpressure via semaphore
                                        let manager_clone = Arc::clone(&self_arc);
                                        let semaphore = Arc::clone(&self_arc.message_handler_semaphore);
                                        tokio::spawn(async move {
                                            // Acquire permit for backpressure - limits concurrent handlers
                                            let _permit = match semaphore.acquire().await {
                                                Ok(permit) => permit,
                                                Err(_) => {
                                                    warn!("Message handler semaphore closed");
                                                    return;
                                                }
                                            };

                                            // SEC-001: Wrap handle_dht_message with timeout to prevent DoS via long-running handlers
                                            // This ensures permits are released even if a handler gets stuck
                                            match tokio::time::timeout(
                                                REQUEST_TIMEOUT,
                                                manager_clone.handle_dht_message(&data, &source_peer),
                                            )
                                            .await
                                            {
                                                Ok(Ok(Some(response))) => {
                                                    // Send response back to the source peer
                                                    if let Err(e) = manager_clone
                                                        .transport
                                                        .send_message(&source_peer, "/dht/1.0.0", response)
                                                        .await
                                                    {
                                                        warn!(
                                                            "Failed to send DHT response to {}: {}",
                                                            source_peer, e
                                                        );
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    // No response needed (e.g., for response messages)
                                                }
                                                Ok(Err(e)) => {
                                                    warn!(
                                                        "Failed to handle DHT message from {}: {}",
                                                        source_peer, e
                                                    );
                                                }
                                                Err(_) => {
                                                    // Timeout occurred - log warning and release permit
                                                    warn!(
                                                        "DHT message handler timed out after {:?} for peer {}: potential DoS attempt or slow processing",
                                                        REQUEST_TIMEOUT, source_peer
                                                    );
                                                }
                                            }
                                            // _permit dropped here, releasing semaphore slot
                                        });
                                    }
                                }
                            },
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!("Network event handler lagged, skipped {} events", skipped);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                info!("Network event channel closed, stopping event handler");
                                break;
                            }
                        }
                    }
                }
            }
        });

        *self.event_handler_handle.write().await = Some(handle);

        Ok(())
    }

    /// Attempt stale peer revalidation and retry admission for a candidate.
    ///
    /// Called when `add_node` returns [`AdmissionResult::StaleRevalidationNeeded`].
    /// Pings stale peers (with the DHT write lock released), evicts non-responders,
    /// and re-evaluates the candidate for admission.
    ///
    /// Concurrency is bounded by a global semaphore ([`MAX_CONCURRENT_REVALIDATIONS`])
    /// and per-bucket tracking to prevent concurrent revalidation of the same bucket.
    async fn revalidate_and_retry_admission(
        &self,
        candidate: NodeInfo,
        candidate_ips: Vec<IpAddr>,
        bucket_idx: usize,
        stale_peers: Vec<(PeerId, usize)>,
        trust_fn: &impl Fn(&PeerId) -> f64,
    ) -> anyhow::Result<Vec<RoutingTableEvent>> {
        if stale_peers.is_empty() {
            return Err(anyhow::anyhow!("no stale peers to revalidate"));
        }

        // Try acquire global semaphore (non-blocking to avoid stalling the caller).
        let _permit = self
            .revalidation_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("global revalidation limit reached"))?;

        // Try acquire per-bucket slot to prevent concurrent revalidation.
        // Note: guards only the candidate's target bucket, not all buckets in
        // stale_peers (which may span multiple buckets after routing-neighborhood
        // merge). The DHT write lock provides correctness; this guard only
        // prevents redundant ping work on the same bucket.
        {
            let mut active = self.bucket_revalidation_active.lock();
            if active.contains(&bucket_idx) {
                return Err(anyhow::anyhow!(
                    "revalidation already in progress for bucket {bucket_idx}"
                ));
            }
            active.insert(bucket_idx);
        }

        // Ensure the per-bucket slot is released on all exit paths.
        let _bucket_guard = BucketRevalidationGuard {
            active: self.bucket_revalidation_active.clone(),
            bucket_idx,
        };

        // --- Ping stale peers concurrently with DHT write lock released ---
        // Process in chunks to bound concurrent pings while still parallelising
        // within each chunk (total wall time: chunks * STALE_REVALIDATION_TIMEOUT
        // instead of stale_peers.len() * STALE_REVALIDATION_TIMEOUT).
        let mut evicted_peers = Vec::new();
        let mut retained_peers = Vec::new();

        for chunk in stale_peers.chunks(MAX_CONCURRENT_REVALIDATION_PINGS) {
            let results = futures::future::join_all(chunk.iter().map(|(peer_id, _)| async {
                let responded =
                    tokio::time::timeout(STALE_REVALIDATION_TIMEOUT, self.ping_peer(peer_id))
                        .await
                        .is_ok_and(|r| r.is_ok());
                (*peer_id, responded)
            }))
            .await;

            for (peer_id, responded) in results {
                if responded {
                    retained_peers.push(peer_id);
                } else {
                    evicted_peers.push(peer_id);
                }
            }
        }

        // Failure recording is handled by send_dht_request (via
        // record_peer_failure) — no success recording needed since core
        // only hands out penalties.

        if evicted_peers.is_empty() {
            return Err(anyhow::anyhow!(
                "all stale peers responded — no room for candidate"
            ));
        }

        // --- Re-acquire write lock: evict non-responders and retry admission ---
        let mut dht = self.dht.write().await;
        let mut all_events = Vec::new();

        for peer_id in &evicted_peers {
            let removal_events = dht.remove_node_by_id(peer_id).await;
            all_events.extend(removal_events);
        }

        let admission_events = dht
            .re_evaluate_admission(candidate, &candidate_ips, trust_fn)
            .await?;
        all_events.extend(admission_events);

        Ok(all_events)
    }

    /// Ping a peer to check liveness.
    ///
    /// Reuses the existing [`send_dht_request`](Self::send_dht_request) flow
    /// which handles serialization, connection setup, and response tracking.
    /// Used during stale peer revalidation to determine which peers should
    /// be evicted.
    async fn ping_peer(&self, peer_id: &PeerId) -> anyhow::Result<()> {
        self.send_dht_request(peer_id, DhtNetworkOperation::Ping, None)
            .await
            .map(|_| ())
            .context("ping failed")
    }

    /// Revalidate stale K-closest peers by pinging them and evicting non-responders.
    ///
    /// Piggybacked on the periodic self-lookup to avoid a dedicated background
    /// worker. Ensures offline close-group members are evicted promptly rather
    /// than lingering until admission contention triggers revalidation.
    async fn revalidate_stale_k_closest(&self) {
        let stale_peers = {
            let dht = self.dht.read().await;
            dht.stale_k_closest().await
        };

        if stale_peers.is_empty() {
            return;
        }

        debug!("Revalidating {} stale K-closest peer(s)", stale_peers.len());

        // Ping concurrently in chunks, reusing the same concurrency limit as
        // admission-triggered revalidation.
        let mut non_responders = Vec::new();

        for chunk in stale_peers.chunks(MAX_CONCURRENT_REVALIDATION_PINGS) {
            let results = futures::future::join_all(chunk.iter().map(|peer_id| async {
                let responded =
                    tokio::time::timeout(STALE_REVALIDATION_TIMEOUT, self.ping_peer(peer_id))
                        .await
                        .is_ok_and(|r| r.is_ok());
                (*peer_id, responded)
            }))
            .await;

            for (peer_id, responded) in results {
                if !responded {
                    non_responders.push(peer_id);
                }
            }
        }

        if non_responders.is_empty() {
            debug!("All stale K-closest peers responded — no evictions");
            return;
        }

        // Evict non-responders under the write lock, then broadcast events
        // after releasing it.
        let all_events = {
            let mut dht = self.dht.write().await;
            let mut events = Vec::new();
            for peer_id in &non_responders {
                events.extend(dht.remove_node_by_id(peer_id).await);
            }
            events
        };

        self.broadcast_routing_events(&all_events);
        info!("Evicted {} offline K-closest peer(s)", non_responders.len());
    }

    /// Translate core engine routing table events into network events and broadcast them.
    fn broadcast_routing_events(&self, events: &[RoutingTableEvent]) {
        if self.event_tx.receiver_count() == 0 {
            return;
        }
        for event in events {
            match event {
                RoutingTableEvent::PeerAdded(id) => {
                    let _ = self
                        .event_tx
                        .send(DhtNetworkEvent::PeerAdded { peer_id: *id });
                }
                RoutingTableEvent::PeerRemoved(id) => {
                    let _ = self
                        .event_tx
                        .send(DhtNetworkEvent::PeerRemoved { peer_id: *id });
                }
                RoutingTableEvent::KClosestPeersChanged { old, new } => {
                    let _ = self.event_tx.send(DhtNetworkEvent::KClosestPeersChanged {
                        old: old.clone(),
                        new: new.clone(),
                    });
                }
            }
        }
    }

    /// Get current statistics
    /// Update a node's address in the DHT routing table.
    ///
    /// Called when a peer advertises a new reachable address (e.g., relay).
    pub async fn touch_node(&self, peer_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let dht = self.dht.read().await;
        dht.touch_node(peer_id, address).await
    }

    /// Update a node's address with an explicit type tag.
    ///
    /// Prefer over [`Self::touch_node`] when the address class is known
    /// (e.g., `AddressType::Relay` for relay addresses so they are stored
    /// at the front of the address list).
    pub async fn touch_node_typed(
        &self,
        peer_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: crate::dht::AddressType,
    ) -> bool {
        let dht = self.dht.read().await;
        dht.touch_node_typed(peer_id, address, addr_type).await
    }

    pub async fn get_stats(&self) -> DhtNetworkStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to DHT network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<DhtNetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get currently connected peers from the transport layer.
    pub async fn get_connected_peers(&self) -> Vec<PeerId> {
        self.transport.connected_peers().await
    }

    /// Get DHT routing table size (Node-mode peers only).
    pub async fn get_routing_table_size(&self) -> usize {
        self.dht.read().await.routing_table_size().await
    }

    /// Check whether a peer is present in the DHT routing table.
    ///
    /// Only peers that passed the `is_dht_participant` gate are added
    /// to the routing table.
    pub async fn is_in_routing_table(&self, peer_id: &PeerId) -> bool {
        let dht_guard = self.dht.read().await;
        dht_guard.has_node(peer_id).await
    }

    /// Return every peer currently in the DHT routing table.
    ///
    /// Only peers that passed the `is_dht_participant` security gate are
    /// included. Useful for diagnostics and for callers that need the full
    /// `LocalRT(self)` set (e.g. replication hint construction).
    ///
    /// The routing table holds at most `256 * k_value` entries, so
    /// collecting them is inexpensive.
    pub async fn routing_table_peers(&self) -> Vec<DHTNode> {
        let dht_guard = self.dht.read().await;
        let nodes = dht_guard.all_nodes().await;
        drop(dht_guard);
        nodes
            .into_iter()
            .map(|node| {
                let reliability = self
                    .trust_engine
                    .as_ref()
                    .map(|engine| engine.score(&node.id))
                    .unwrap_or(DEFAULT_NEUTRAL_TRUST);
                DHTNode {
                    peer_id: node.id,
                    addresses: node.addresses,
                    distance: None,
                    reliability,
                }
            })
            .collect()
    }

    /// Get this node's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.config.peer_id
    }

    /// Send a PublishAddress request to a list of peers, telling them to
    /// store the given addresses for this node in their routing tables.
    /// Used after relay setup to propagate the relay address to K closest peers.
    pub async fn publish_address_to_peers(
        &self,
        addresses: Vec<crate::MultiAddr>,
        peers: &[DHTNode],
    ) {
        let op = DhtNetworkOperation::PublishAddress {
            addresses: addresses.clone(),
        };
        for peer in peers {
            if peer.peer_id == self.config.peer_id {
                continue; // Skip self
            }
            match self
                .send_dht_request(
                    &peer.peer_id,
                    op.clone(),
                    Self::first_dialable_address(&peer.addresses).as_ref(),
                )
                .await
            {
                Ok(_) => {
                    info!("Published address to peer {}", peer.peer_id.to_hex());
                }
                Err(e) => {
                    debug!(
                        "Failed to publish address to peer {}: {}",
                        peer.peer_id.to_hex(),
                        e
                    );
                }
            }
        }
    }

    /// Get the local listen address of this node's P2P network
    ///
    /// Returns the address other nodes can use to connect to this node.
    pub fn local_addr(&self) -> Option<MultiAddr> {
        self.transport.local_addr()
    }

    /// Connect to a specific peer by address.
    ///
    /// This is useful for manually building network topology in tests.
    pub async fn connect_to_peer(&self, address: &MultiAddr) -> Result<String> {
        self.transport.connect_peer(address).await
    }

    /// Get the transport handle for direct transport-level operations.
    pub fn transport(&self) -> &Arc<crate::transport_handle::TransportHandle> {
        &self.transport
    }

    /// Get the optional trust engine used by this manager.
    pub fn trust_engine(&self) -> Option<Arc<TrustEngine>> {
        self.trust_engine.clone()
    }
}

/// Default request timeout for outbound DHT operations (seconds).
///
/// Governs `wait_for_response` and the upper bound of `dial_candidate`'s
/// dial timeout (`min(connection_timeout, request_timeout)`). Must stay
/// above the relay stage (~10s) so it never truncates the NAT traversal
/// cascade.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;

/// Default maximum concurrent DHT operations
const DEFAULT_MAX_CONCURRENT_OPS: usize = 100;

impl Default for DhtNetworkConfig {
    fn default() -> Self {
        Self {
            peer_id: PeerId::from_bytes([0u8; 32]),
            node_config: NodeConfig::default(),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_concurrent_operations: DEFAULT_MAX_CONCURRENT_OPS,
            enable_security: true,
            swap_threshold: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_dialable_address_skips_non_ip_when_ip_address_exists() {
        let ble = MultiAddr::new(crate::address::TransportAddr::Ble {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            psm: 0x0025,
        });
        let quic = MultiAddr::quic("127.0.0.1:9000".parse().unwrap());

        let selected = DhtNetworkManager::first_dialable_address(&[ble, quic.clone()]);

        assert_eq!(
            selected,
            Some(quic),
            "address selection should prefer a dialable IP transport over a preceding non-IP entry"
        );
    }

    #[test]
    fn test_first_dialable_address_returns_none_for_all_non_dialable() {
        let ble = MultiAddr::new(crate::address::TransportAddr::Ble {
            mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            psm: 128,
        });
        let tcp = MultiAddr::tcp("10.0.0.1:80".parse().unwrap());
        let lora = MultiAddr::new(crate::address::TransportAddr::LoRa {
            dev_addr: [0xDE, 0xAD, 0xBE, 0xEF],
            freq_hz: 868_000_000,
        });

        assert_eq!(
            DhtNetworkManager::first_dialable_address(&[ble, tcp, lora]),
            None,
            "should return None when no QUIC address is present"
        );
    }

    #[test]
    fn test_first_dialable_address_rejects_unspecified_ip() {
        let unspecified = MultiAddr::quic("0.0.0.0:9000".parse().unwrap());

        assert_eq!(
            DhtNetworkManager::first_dialable_address(&[unspecified]),
            None,
            "should reject unspecified (0.0.0.0) addresses"
        );
    }

    #[test]
    fn test_first_dialable_address_returns_none_for_empty_slice() {
        assert_eq!(
            DhtNetworkManager::first_dialable_address(&[]),
            None,
            "should return None for empty address list"
        );
    }

    #[test]
    fn test_peer_rejected_round_trips_through_serialization() {
        let result = DhtNetworkResult::PeerRejected;
        let bytes = postcard::to_stdvec(&result).expect("serialization should succeed");
        let deserialized: DhtNetworkResult =
            postcard::from_bytes(&bytes).expect("deserialization should succeed");
        assert!(
            matches!(deserialized, DhtNetworkResult::PeerRejected),
            "round-tripped result should be PeerRejected, got: {deserialized:?}"
        );
    }

    #[test]
    fn test_bootstrap_complete_event_construction() {
        let event = DhtNetworkEvent::BootstrapComplete { num_peers: 42 };
        assert!(
            matches!(event, DhtNetworkEvent::BootstrapComplete { num_peers: 42 }),
            "BootstrapComplete event should carry the peer count"
        );
    }

    #[test]
    fn test_k_closest_changed_event_uses_old_new_naming() {
        let old = vec![PeerId::random(), PeerId::random()];
        let new = vec![PeerId::random()];
        let event = DhtNetworkEvent::KClosestPeersChanged {
            old: old.clone(),
            new: new.clone(),
        };
        match event {
            DhtNetworkEvent::KClosestPeersChanged {
                old: got_old,
                new: got_new,
            } => {
                assert_eq!(got_old, old);
                assert_eq!(got_new, new);
            }
            _ => panic!("expected KClosestPeersChanged"),
        }
    }

    #[tokio::test]
    async fn inflight_dial_guard_releases_slot_and_wakes_waiters_on_drop() {
        // Verify the InflightDialGuard's RAII semantics: dropping the
        // guard (which happens whether the owning future returns
        // normally, panics, or is cancelled) must remove the inflight
        // entry AND wake every blocked waiter. Without this, a panic in
        // the dial path would leave secondary callers blocked on
        // `notified()` forever.
        let inflight: Arc<DashMap<PeerId, Arc<Notify>>> = Arc::new(DashMap::new());
        let peer = PeerId::random();
        let notify = Arc::new(Notify::new());
        inflight.insert(peer, Arc::clone(&notify));

        let waiter_inflight = Arc::clone(&inflight);
        let waiter_notify = Arc::clone(&notify);
        let waiter = tokio::spawn(async move {
            waiter_notify.notified().await;
            // After the wake, the entry must be gone so the waiter that
            // re-enters the dial path sees a clean state.
            assert!(
                !waiter_inflight.contains_key(&peer),
                "inflight entry should be removed before notify_waiters fires",
            );
        });

        // Give the waiter task a chance to register with the Notify.
        tokio::task::yield_now().await;

        // Drop the guard — this is what `dial_or_await_inflight`'s Owner
        // branch does on every exit path (success, error, panic, cancel).
        let guard = InflightDialGuard {
            inflight: Arc::clone(&inflight),
            peer_id: peer,
            notify: Arc::clone(&notify),
        };
        drop(guard);

        // The waiter should wake immediately and complete its assertion.
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter must wake within 1s of guard drop")
            .expect("waiter task should not panic");

        assert!(
            !inflight.contains_key(&peer),
            "guard drop must remove the inflight entry",
        );
    }

    #[test]
    fn test_peer_rejected_response_message_preserves_request_payload() {
        let request = DhtNetworkMessage {
            message_id: "test-123".to_string(),
            source: PeerId::random(),
            target: Some(PeerId::random()),
            message_type: DhtMessageType::Request,
            payload: DhtNetworkOperation::Ping,
            result: None,
            timestamp: 0,
            ttl: 10,
            hop_count: 0,
        };

        // Serialize & deserialize the full response message to verify
        // PeerRejected survives a wire round-trip inside a DhtNetworkMessage.
        let response = DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: PeerId::random(),
            target: Some(request.source),
            message_type: DhtMessageType::Response,
            payload: request.payload.clone(),
            result: Some(DhtNetworkResult::PeerRejected),
            timestamp: 0,
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count.saturating_add(1),
        };

        let bytes = postcard::to_stdvec(&response).expect("serialize response");
        let decoded: DhtNetworkMessage =
            postcard::from_bytes(&bytes).expect("deserialize response");

        assert!(
            matches!(decoded.result, Some(DhtNetworkResult::PeerRejected)),
            "response result should be PeerRejected"
        );
        assert!(
            matches!(decoded.payload, DhtNetworkOperation::Ping),
            "response should echo the request's Ping payload"
        );
    }

    // ---- Tier 1.2 + 1.4: hole-punch coordinator selection ----

    /// Helper: build a [`ReferrerInfo`] with a deterministic peer_id whose
    /// byte 0 is set to `tag`. The remaining bytes come from
    /// [`PeerId::random()`] so the IDs collide on byte 0 but stay
    /// otherwise unique.
    fn make_referrer(tag: u8, addr_octet: u8, round: u32) -> ReferrerInfo {
        let mut bytes = *PeerId::random().to_bytes();
        bytes[0] = tag;
        ReferrerInfo {
            peer_id: PeerId::from_bytes(bytes),
            addr: SocketAddr::from(([10, 0, 0, addr_octet], 9000)),
            round_observed: round,
        }
    }

    fn neutral_trust(_: &PeerId) -> f64 {
        DEFAULT_NEUTRAL_TRUST
    }

    #[test]
    fn rank_referrers_returns_empty_for_empty_or_missing() {
        assert!(
            DhtNetworkManager::rank_referrers(None, neutral_trust).is_empty(),
            "None input must yield an empty list"
        );
        assert!(
            DhtNetworkManager::rank_referrers(Some(&[]), neutral_trust).is_empty(),
            "empty slice must yield an empty list"
        );
    }

    #[test]
    fn rank_referrers_single_referrer_returned() {
        let only = make_referrer(0x01, 1, 0);
        let ranked = DhtNetworkManager::rank_referrers(Some(&[only]), neutral_trust);
        assert_eq!(ranked, vec![only.addr]);
    }

    #[test]
    fn rank_referrers_prefers_later_round_over_earlier() {
        // Round 0 (bootstrap-equivalent) vs round 3 (deep iteration).
        // Round 3 must come first regardless of input order or trust.
        let round_zero = make_referrer(0xFF, 1, 0);
        let round_three = make_referrer(0x01, 2, 3);

        let ranked_a =
            DhtNetworkManager::rank_referrers(Some(&[round_zero, round_three]), neutral_trust);
        let ranked_b =
            DhtNetworkManager::rank_referrers(Some(&[round_three, round_zero]), neutral_trust);

        assert_eq!(
            ranked_a,
            vec![round_three.addr, round_zero.addr],
            "later round must come first regardless of input order"
        );
        assert_eq!(
            ranked_b,
            vec![round_three.addr, round_zero.addr],
            "later round must come first regardless of input order (reversed)"
        );
    }

    #[test]
    fn rank_referrers_tiebreaks_round_with_trust() {
        // Same round, different trust. Higher-trust comes first.
        let low_trust = make_referrer(0x55, 1, 2);
        let high_trust = make_referrer(0xAA, 2, 2);
        let trust_for = |peer_id: &PeerId| -> f64 {
            if peer_id.to_bytes()[0] == 0xAA {
                0.95
            } else {
                0.10
            }
        };

        let ranked = DhtNetworkManager::rank_referrers(Some(&[low_trust, high_trust]), trust_for);
        assert_eq!(
            ranked,
            vec![high_trust.addr, low_trust.addr],
            "higher trust must come first when rounds tie"
        );
    }

    #[test]
    fn rank_referrers_tiebreaks_round_and_trust_with_peer_id_byte_zero() {
        // Same round, same (neutral) trust. The referrer with the larger
        // byte-0 comes first deterministically.
        let small = make_referrer(0x01, 1, 1);
        let large = make_referrer(0xF0, 2, 1);

        let ranked_a = DhtNetworkManager::rank_referrers(Some(&[small, large]), neutral_trust);
        let ranked_b = DhtNetworkManager::rank_referrers(Some(&[large, small]), neutral_trust);

        assert_eq!(
            ranked_a,
            vec![large.addr, small.addr],
            "larger peer_id byte 0 must come first via tertiary tiebreak"
        );
        assert_eq!(
            ranked_b,
            vec![large.addr, small.addr],
            "tiebreak must be order-independent"
        );
    }

    #[test]
    fn rank_referrers_full_list_is_sorted_best_first() {
        // Mixed rounds and trust scores: verify the entire list is sorted
        // correctly, not just the head.
        let r0 = make_referrer(0x01, 1, 0); // round 0
        let r1 = make_referrer(0x02, 2, 1); // round 1
        let r2_low = make_referrer(0x03, 3, 2); // round 2, low trust
        let r2_high = make_referrer(0x04, 4, 2); // round 2, high trust
        let trust_for = |peer_id: &PeerId| -> f64 {
            if peer_id.to_bytes()[0] == 0x04 {
                0.9
            } else {
                0.5
            }
        };
        let ranked = DhtNetworkManager::rank_referrers(Some(&[r0, r1, r2_low, r2_high]), trust_for);
        assert_eq!(
            ranked,
            vec![r2_high.addr, r2_low.addr, r1.addr, r0.addr],
            "full list must be sorted (round DESC, trust DESC) end-to-end"
        );
    }

    // ---- merge_referrer_observation ----

    fn dummy_target() -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xCC;
        PeerId::from_bytes(bytes)
    }

    #[test]
    fn merge_referrer_observation_appends_until_full() {
        let mut entry: Vec<ReferrerInfo> = Vec::new();
        let target = dummy_target();
        for i in 0..MAX_REFERRERS_PER_TARGET as u8 {
            DhtNetworkManager::merge_referrer_observation(
                &mut entry,
                make_referrer(0x10 + i, i + 1, 0),
                &target,
            );
        }
        assert_eq!(
            entry.len(),
            MAX_REFERRERS_PER_TARGET,
            "first MAX_REFERRERS_PER_TARGET observations must all land in the slot table"
        );
    }

    #[test]
    fn merge_referrer_observation_drops_duplicate_peer() {
        let mut entry: Vec<ReferrerInfo> = Vec::new();
        let target = dummy_target();
        let original = make_referrer(0x42, 1, 0);
        DhtNetworkManager::merge_referrer_observation(&mut entry, original, &target);
        // True duplicate: identical peer_id, different addr and round.
        // (`make_referrer` randomises bytes 1..32 per call, so we cannot
        // produce a duplicate by re-tagging — we have to reuse the
        // original peer_id directly.)
        let duplicate = ReferrerInfo {
            peer_id: original.peer_id,
            addr: SocketAddr::from(([10, 0, 0, 99], 9000)),
            round_observed: 5,
        };
        DhtNetworkManager::merge_referrer_observation(&mut entry, duplicate, &target);
        assert_eq!(
            entry.len(),
            1,
            "duplicate referrer (same peer_id) must not consume an additional slot"
        );
        assert_eq!(
            entry[0].addr, original.addr,
            "duplicate must NOT overwrite — first observation wins for the same peer"
        );
    }

    #[test]
    fn merge_referrer_observation_evicts_lowest_round_when_full_and_new_is_later() {
        // Fill all 4 slots with round-0 referrers — the worst case the
        // reviewer flagged: 4+ bootstraps all returning the same hot peer
        // in round 0 would otherwise lock out later-round referrers.
        let mut entry: Vec<ReferrerInfo> = Vec::new();
        let target = dummy_target();
        for i in 0..MAX_REFERRERS_PER_TARGET as u8 {
            DhtNetworkManager::merge_referrer_observation(
                &mut entry,
                make_referrer(0x10 + i, i + 1, 0),
                &target,
            );
        }
        assert_eq!(entry.len(), MAX_REFERRERS_PER_TARGET);
        assert!(
            entry.iter().all(|r| r.round_observed == 0),
            "all 4 slots should hold round-0 referrers"
        );

        // A round-3 referrer arrives — must evict one round-0 entry.
        let later = make_referrer(0xAA, 99, 3);
        DhtNetworkManager::merge_referrer_observation(&mut entry, later, &target);

        assert_eq!(
            entry.len(),
            MAX_REFERRERS_PER_TARGET,
            "table size must remain at the cap after eviction"
        );
        assert!(
            entry.iter().any(|r| r.peer_id == later.peer_id),
            "the new round-3 referrer must be present in the slot table"
        );
        // Exactly one round-0 entry was evicted, three remain.
        let round_zero_count = entry.iter().filter(|r| r.round_observed == 0).count();
        assert_eq!(
            round_zero_count,
            MAX_REFERRERS_PER_TARGET - 1,
            "exactly one round-0 entry must have been evicted"
        );
    }

    #[test]
    fn merge_referrer_observation_does_not_evict_when_new_is_same_or_lower_round() {
        // Fill all 4 slots with round-2 referrers, then submit a round-2
        // and a round-0 referrer. Neither should evict — both would tie
        // or lose against the existing entries at dial-time anyway.
        let mut entry: Vec<ReferrerInfo> = Vec::new();
        let target = dummy_target();
        for i in 0..MAX_REFERRERS_PER_TARGET as u8 {
            DhtNetworkManager::merge_referrer_observation(
                &mut entry,
                make_referrer(0x10 + i, i + 1, 2),
                &target,
            );
        }
        let snapshot: Vec<ReferrerInfo> = entry.clone();

        // Same-round arrival: must NOT evict (strictly-greater check).
        DhtNetworkManager::merge_referrer_observation(
            &mut entry,
            make_referrer(0x80, 50, 2),
            &target,
        );
        assert_eq!(
            entry, snapshot,
            "same-round referrer must not evict the existing slot table"
        );

        // Earlier-round arrival: must NOT evict.
        DhtNetworkManager::merge_referrer_observation(
            &mut entry,
            make_referrer(0x90, 60, 0),
            &target,
        );
        assert_eq!(
            entry, snapshot,
            "lower-round referrer must not evict the existing slot table"
        );
    }

    #[test]
    fn shuffled_indices_empty_and_singleton_are_identity() {
        assert_eq!(
            DhtNetworkManager::shuffled_indices(0),
            Vec::<usize>::new(),
            "len 0 must yield an empty vec"
        );
        assert_eq!(
            DhtNetworkManager::shuffled_indices(1),
            vec![0],
            "len 1 must yield [0] unchanged"
        );
    }

    #[test]
    fn shuffled_indices_returns_valid_permutation() {
        // For a wider input, every call must produce a permutation of
        // [0, len) — same set, possibly different order.
        const LEN: usize = 10;
        let result = DhtNetworkManager::shuffled_indices(LEN);
        assert_eq!(result.len(), LEN, "permutation must have the right length");
        let mut sorted = result.clone();
        sorted.sort_unstable();
        let expected: Vec<usize> = (0..LEN).collect();
        assert_eq!(
            sorted, expected,
            "shuffled output must be a permutation of [0, len)"
        );
    }

    #[test]
    fn shuffled_indices_distributes_across_calls() {
        // Run many shuffles and assert the position-0 element is not
        // always the same. With true randomisation across calls, the
        // probability that 100 calls all return position-0 == 0 for a
        // 5-element shuffle is negligible.
        const TRIALS: usize = 100;
        const LEN: usize = 5;
        let mut first_positions = std::collections::HashSet::new();
        for _ in 0..TRIALS {
            let result = DhtNetworkManager::shuffled_indices(LEN);
            first_positions.insert(result[0]);
            if first_positions.len() >= 2 {
                return; // pass — we observed at least two distinct positions
            }
        }
        panic!(
            "shuffled_indices(5) returned the same first element across {TRIALS} \
             calls — entropy source is broken"
        );
    }
}
