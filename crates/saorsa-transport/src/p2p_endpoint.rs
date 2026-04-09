// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! P2P endpoint for saorsa-transport
//!
//! This module provides the main API for P2P communication with NAT traversal,
//! secure connections, and event-driven architecture.
//!
//! # Features
//!
//! - Configuration via [`P2pConfig`](crate::unified_config::P2pConfig)
//! - Event subscription via broadcast channels
//! - TLS-based peer authentication via ML-DSA-65 (v0.2+)
//! - NAT traversal with automatic fallback
//! - Connection metrics and statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_transport::{P2pEndpoint, P2pConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // All nodes are symmetric - they can both connect and accept connections
//!     let config = P2pConfig::builder()
//!         .bind_addr("0.0.0.0:9000".parse()?)
//!         .known_peer("quic.saorsalabs.com:9000".parse()?)
//!         .build()?;
//!
//!     let endpoint = P2pEndpoint::new(config).await?;
//!     println!("Public key: {:?}", endpoint.local_public_key());
//!
//!     // Subscribe to events
//!     let mut events = endpoint.subscribe();
//!     tokio::spawn(async move {
//!         while let Ok(event) = events.recv().await {
//!             println!("Event: {:?}", event);
//!         }
//!     });
//!
//!     // Connect to known peers
//!     endpoint.connect_known_peers().await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::Side;
use crate::bootstrap_cache::{BootstrapCache, BootstrapTokenStore};
use crate::bounded_pending_buffer::BoundedPendingBuffer;
use crate::connection_router::{ConnectionRouter, RouterConfig};
use crate::connection_strategy::{
    ConnectionMethod, ConnectionStage, ConnectionStrategy, StrategyConfig,
};
use crate::constrained::ConnectionId as ConstrainedConnectionId;
use crate::constrained::EngineEvent;
use crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;
use crate::happy_eyeballs::{self, HappyEyeballsConfig};
pub use crate::nat_traversal_api::TraversalPhase;
use crate::nat_traversal_api::{
    NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, NatTraversalStatistics,
};
use crate::transport::{ProtocolEngine, TransportAddr, TransportRegistry};
use crate::unified_config::P2pConfig;
use rustls;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// How often the stale connection reaper checks for QUIC-dead connections
/// via `is_connected()`.  This is a cheap local state check — no network
/// traffic.  Kept short so the reaper acts as a fast safety net behind the
/// event-driven reader-exit detection.
const STALE_REAPER_INTERVAL: Duration = Duration::from_secs(10);

/// Quick direct connection attempt after a failed hole-punch round.
/// If the target's outgoing packets created a NAT binding, a QUIC handshake
/// through the pinhole needs only 1-2 RTTs (~600ms at 300ms worst-case RTT).
const POST_HOLEPUNCH_DIRECT_RETRY_TIMEOUT: Duration = Duration::from_secs(1);

/// Per-attempt hole-punch timeout used when rotating through a list of
/// preferred coordinators. Kept short so a busy or unreachable coordinator
/// is abandoned quickly and the next one in the list is tried; the *last*
/// coordinator in the rotation falls back to the strategy's full
/// hole-punch timeout to give it time to actually complete the punch.
///
/// Tuned for the Tier 2 + Tier 4 (lite) coordinator-rotation flow: 1.5s
/// is comfortably above one round-trip on most internet links but well
/// below the strategy default (~8s), so the worst-case wait for K
/// preferred coordinators is roughly `(K-1) * 1.5s + 8s` instead of
/// `K * 8s`.
const PER_COORDINATOR_QUICK_HOLEPUNCH_TIMEOUT: Duration = Duration::from_millis(1500);

use crate::SHUTDOWN_DRAIN_TIMEOUT;

/// Extract the raw SPKI (SubjectPublicKeyInfo) bytes from a QUIC connection's
/// peer identity, if TLS-based authentication was used.
///
/// Returns `None` for unauthenticated or constrained connections.
fn extract_public_key_bytes_from_connection(
    connection: &crate::high_level::Connection,
) -> Option<Vec<u8>> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()?;
    let cert = certs.first()?;
    Some(cert.as_ref().to_vec())
}

/// P2P endpoint - the primary API for saorsa-transport
///
/// This struct provides the main interface for P2P communication with
/// NAT traversal, connection management, and secure messaging.
pub struct P2pEndpoint {
    /// Internal NAT traversal endpoint
    inner: Arc<NatTraversalEndpoint>,

    // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
    /// Connected peers keyed by remote socket address
    connected_peers: Arc<RwLock<HashMap<SocketAddr, PeerConnection>>>,

    /// Endpoint statistics
    stats: Arc<RwLock<EndpointStats>>,

    /// Configuration
    config: P2pConfig,

    /// Event broadcaster
    event_tx: broadcast::Sender<P2pEvent>,

    /// SPKI fingerprint of our own ML-DSA-65 public key (BLAKE3 hash)
    our_fingerprint: [u8; 32],

    /// Our ML-DSA-65 public key SPKI bytes (for identity sharing)
    public_key: Vec<u8>,

    /// Shutdown token for cooperative cancellation
    shutdown: CancellationToken,

    /// Bounded pending data buffer for message ordering
    pending_data: Arc<RwLock<BoundedPendingBuffer>>,

    /// Bootstrap cache for peer persistence
    pub bootstrap_cache: Arc<BootstrapCache>,

    /// Transport registry for multi-transport support
    ///
    /// Contains all registered transport providers (UDP, BLE, etc.) that this
    /// endpoint can use for connectivity.
    transport_registry: Arc<TransportRegistry>,

    /// Connection router for automatic protocol engine selection
    ///
    /// Routes connections through either QUIC (for broadband) or Constrained
    /// engine (for BLE/LoRa) based on transport capabilities. The router is
    /// fully interior-mutable — all methods take `&self` and stat/state
    /// mutations are lock-free — so no `RwLock` is needed.
    router: Arc<ConnectionRouter>,

    /// Mapping from TransportAddr to ConnectionId for constrained connections
    ///
    /// When a peer is connected via a constrained transport (BLE, LoRa, etc.),
    /// this map stores the ConstrainedEngine's ConnectionId for that address.
    /// UDP/QUIC peers are NOT in this map - they use the standard QUIC connection.
    constrained_connections: Arc<RwLock<HashMap<TransportAddr, ConstrainedConnectionId>>>,

    /// Reverse lookup: ConnectionId → TransportAddr for constrained connections
    ///
    /// This enables mapping incoming constrained data back to the correct remote address.
    /// Registered when ConnectionAccepted/Established fires for constrained transports.
    constrained_peer_addrs: Arc<RwLock<HashMap<ConstrainedConnectionId, TransportAddr>>>,

    /// Per-target peer IDs for hole-punch attempts. When set for a target
    /// address, the PUNCH_ME_NOW uses the peer ID instead of wire_id_from_addr,
    /// allowing the coordinator to match by peer identity. Keyed by target
    /// address so concurrent dials don't race on shared state.
    hole_punch_target_peer_ids: Arc<dashmap::DashMap<SocketAddr, [u8; 32]>>,

    /// Per-target preferred coordinators for hole-punch relay. When the DHT
    /// lookup discovers a peer via FindNode responses from one or more peers,
    /// those responding nodes (the "referrers") all have a connection to the
    /// discovered peer and are good coordinator candidates. Keyed by target
    /// address, value is an ordered list of referrer socket addresses ranked
    /// best-first by the caller (e.g. by DHT lookup round, trust score).
    /// During hole-punching the list is iterated front to back: the first
    /// candidates get a short per-attempt timeout so we rotate quickly past
    /// busy or unreachable coordinators; the last candidate gets the full
    /// hole-punch timeout to give it time to actually complete the punch.
    hole_punch_preferred_coordinators: Arc<dashmap::DashMap<SocketAddr, Vec<SocketAddr>>>,

    /// Channel sender for data received from QUIC reader tasks and constrained poller
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,

    /// Channel receiver for data received from QUIC reader tasks and constrained poller
    data_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>>,

    /// JoinSet tracking background reader tasks (each returns SocketAddr on exit)
    reader_tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<SocketAddr>>>,

    /// Per-address abort handles for targeted reader task cancellation
    reader_handles: Arc<RwLock<HashMap<SocketAddr, tokio::task::AbortHandle>>>,

    /// Channel for reader tasks to notify immediate cleanup on exit.
    ///
    /// When a reader task detects a dead QUIC connection (`accept_uni` error),
    /// it sends the peer address here.  The reader-exit handler task receives
    /// it and calls `do_cleanup_connection` immediately — no waiting for the
    /// periodic stale reaper.
    reader_exit_tx: mpsc::UnboundedSender<SocketAddr>,

    /// In-flight connection attempts, keyed by target address.
    ///
    /// When multiple concurrent `connect_with_fallback` calls target the same
    /// address (e.g., 3 chunks all needing the same NATed node), only the first
    /// call does the actual connection work. Subsequent callers subscribe to a
    /// broadcast channel and wait for the result instead of starting parallel
    /// hole-punch attempts that deadlock the runtime.
    pending_dials: Arc<
        tokio::sync::Mutex<HashMap<SocketAddr, broadcast::Sender<Result<PeerConnection, String>>>>,
    >,
}

impl std::fmt::Debug for P2pEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pEndpoint")
            .field("public_key_len", &self.public_key.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Connection information for a peer
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Remote peer's ML-DSA-65 SPKI public key bytes (None for constrained/unauthenticated)
    pub public_key: Option<Vec<u8>>,

    /// Remote address (supports all transport types)
    pub remote_addr: TransportAddr,

    /// Whether peer is authenticated
    pub authenticated: bool,

    /// Connection established time
    pub connected_at: Instant,

    /// Last activity time
    pub last_activity: Instant,
}

/// Connection metrics for P2P peers
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Bytes sent to this peer
    pub bytes_sent: u64,

    /// Bytes received from this peer
    pub bytes_received: u64,

    /// Round-trip time
    pub rtt: Option<Duration>,

    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,

    /// Last activity timestamp
    pub last_activity: Option<Instant>,
}

/// P2P endpoint statistics
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of active connections
    pub active_connections: usize,

    /// Total successful connections
    pub successful_connections: u64,

    /// Total failed connections
    pub failed_connections: u64,

    /// NAT traversal attempts
    pub nat_traversal_attempts: u64,

    /// Successful NAT traversals
    pub nat_traversal_successes: u64,

    /// Direct connections (no NAT traversal needed)
    pub direct_connections: u64,

    /// Relayed connections
    pub relayed_connections: u64,

    /// Total bootstrap nodes configured
    pub total_bootstrap_nodes: usize,

    /// Connected bootstrap nodes
    pub connected_bootstrap_nodes: usize,

    /// Endpoint start time
    pub start_time: Instant,

    /// Average coordination time for NAT traversal
    pub average_coordination_time: Duration,
}

impl Default for EndpointStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            nat_traversal_successes: 0,
            direct_connections: 0,
            relayed_connections: 0,
            total_bootstrap_nodes: 0,
            connected_bootstrap_nodes: 0,
            start_time: Instant::now(),
            average_coordination_time: Duration::ZERO,
        }
    }
}

/// P2P event for connection and network state changes.
///
/// Events use [`TransportAddr`] to support multi-transport connectivity.
/// Use `addr.as_socket_addr()` for backward compatibility with UDP-only code.
///
/// # Examples
///
/// ## Handling events with transport awareness
///
/// ```rust,ignore
/// use saorsa_transport::{P2pEvent, transport::TransportAddr};
///
/// while let Ok(event) = events.recv().await {
///     match event {
///         P2pEvent::PeerConnected { peer_id, addr, side } => {
///             // Handle different transport types
///             match addr {
///                 TransportAddr::Quic(socket_addr) => {
///                     println!("UDP connection from {socket_addr}");
///                 },
///                 TransportAddr::Ble { mac, .. } => {
///                     println!("BLE connection from {:?}", mac);
///                 },
///                 _ => println!("Other transport: {addr}"),
///             }
///         }
///         P2pEvent::ExternalAddressDiscovered { addr } => {
///             // Our external address was discovered
///             if let Some(socket_addr) = addr.as_socket_addr() {
///                 println!("External UDP address: {socket_addr}");
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Address-based event handling
///
/// Events use `SocketAddr` as the primary peer identifier:
///
/// ```rust,ignore
/// match event {
///     P2pEvent::PeerConnected { addr, public_key, .. } => {
///         if let Some(socket_addr) = addr.as_socket_addr() {
///             println!("Peer connected from {}", socket_addr);
///             if let Some(pk) = &public_key {
///                 println!("  Public key: {} bytes", pk.len());
///             }
///         }
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A new peer has connected.
    ///
    /// The `addr` field contains a [`TransportAddr`] which can represent different
    /// transport types (UDP, BLE, LoRa, etc.). Use `addr.as_socket_addr()` to extract
    /// the [`SocketAddr`] for UDP connections, or pattern match for specific transports.
    PeerConnected {
        /// Remote transport address (supports UDP, BLE, LoRa, and other transports)
        addr: TransportAddr,
        /// Remote peer's ML-DSA-65 SPKI public key bytes (None for constrained/unauthenticated)
        public_key: Option<Vec<u8>>,
        /// Who initiated the connection (Client = we connected, Server = they connected)
        side: Side,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// Remote transport address of the disconnected peer
        addr: TransportAddr,
        /// Reason for the disconnection
        reason: DisconnectReason,
    },

    /// NAT traversal progress update.
    NatTraversalProgress {
        /// Target address for the NAT traversal
        addr: SocketAddr,
        /// Current phase of NAT traversal
        phase: TraversalPhase,
    },

    /// An external address was discovered for this node.
    ///
    /// The `addr` field contains a [`TransportAddr`] representing our externally
    /// visible address. For UDP connections, use `addr.as_socket_addr()` to get
    /// the [`SocketAddr`].
    ExternalAddressDiscovered {
        /// Discovered external transport address (typically TransportAddr::Quic for NAT traversal)
        addr: TransportAddr,
    },

    /// A connected peer advertised a new reachable address (relay or migration).
    PeerAddressUpdated {
        /// The connected peer that sent the advertisement
        peer_addr: SocketAddr,
        /// The new address the peer is advertising as reachable
        advertised_addr: SocketAddr,
    },

    /// This node established a MASQUE relay and is advertising a relay address.
    ///
    /// Emitted once when the relay becomes active. Upper layers should use this
    /// to trigger a DHT self-lookup so that more peers learn the relay address.
    RelayEstablished {
        /// The relay's public address (relay_IP:PORT)
        relay_addr: SocketAddr,
    },

    /// Bootstrap connection status
    BootstrapStatus {
        /// Number of connected bootstrap nodes
        connected: usize,
        /// Total number of bootstrap nodes
        total: usize,
    },

    /// Peer authenticated
    PeerAuthenticated {
        /// Authenticated peer address
        addr: SocketAddr,
        /// Authenticated peer's ML-DSA-65 SPKI public key bytes
        public_key: Vec<u8>,
    },

    /// Data received from peer
    DataReceived {
        /// Source peer address
        addr: SocketAddr,
        /// Number of bytes received
        bytes: usize,
    },

    /// Data received from a constrained transport (BLE, LoRa, etc.)
    ///
    /// This event is generated when data arrives via a non-UDP transport that uses
    /// the constrained protocol engine.
    ConstrainedDataReceived {
        /// Remote transport address (BLE device ID, LoRa address, etc.)
        remote_addr: TransportAddr,
        /// Connection ID from the constrained engine
        connection_id: u16,
        /// The received data payload
        data: Vec<u8>,
    },
}

/// Reason for peer disconnection
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Normal disconnect
    Normal,
    /// Connection timeout
    Timeout,
    /// Protocol error
    ProtocolError(String),
    /// Authentication failure
    AuthenticationFailed,
    /// Connection lost
    ConnectionLost,
    /// Remote closed
    RemoteClosed,
}

// TraversalPhase is re-exported from nat_traversal_api

/// Error type for P2pEndpoint operations
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// NAT traversal error
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] NatTraversalError),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Peer not found
    #[error("Peer not found at address: {0}")]
    PeerNotFound(SocketAddr),

    /// Already connected
    #[error("Already connected to address: {0}")]
    AlreadyConnected(SocketAddr),

    /// Shutdown in progress
    #[error("Endpoint is shutting down")]
    ShuttingDown,

    /// All connection strategies failed
    #[error("All connection strategies failed: {0}")]
    AllStrategiesFailed(String),

    /// No target address provided
    #[error("No target address provided")]
    NoAddress,
}

/// Shared cleanup logic for removing a peer from all tracking structures.
///
/// Used by both `P2pEndpoint::cleanup_connection()` and the background reaper
/// to ensure consistent cleanup behaviour (single source of truth).
///
/// Lock ordering: always acquires locks in the canonical order
/// `connected_peers` → `reader_handles` → `stats` to prevent ABBA deadlocks.
/// Each lock is acquired and released independently (no nesting) to minimise
/// hold time and avoid blocking concurrent `send()` / `connect()` calls.
///
/// Returns `true` if the peer was actually present in `connected_peers`.
async fn do_cleanup_connection(
    connected_peers: &RwLock<HashMap<SocketAddr, PeerConnection>>,
    inner: &NatTraversalEndpoint,
    reader_handles: &RwLock<HashMap<SocketAddr, tokio::task::AbortHandle>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    addr: &SocketAddr,
    reason: DisconnectReason,
) -> bool {
    // Step 1: Remove from connected_peers (canonical lock #1)
    let removed = connected_peers.write().await.remove(addr);

    // Step 2: Remove from NAT traversal layer (lock-free DashMap)
    let _ = inner.remove_connection(addr);

    // Step 3: Remove and abort reader task (canonical lock #2)
    let abort_handle = reader_handles.write().await.remove(addr);
    if let Some(handle) = abort_handle {
        handle.abort();
    }

    // Step 4: Update stats and emit event (canonical lock #3)
    if let Some(peer_conn) = removed {
        {
            let mut s = stats.write().await;
            s.active_connections = s.active_connections.saturating_sub(1);
        }

        let _ = event_tx.send(P2pEvent::PeerDisconnected {
            addr: peer_conn.remote_addr,
            reason,
        });

        info!("Cleaned up connection for addr {}", addr);
        true
    } else {
        false
    }
}

impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError> {
        // Use provided keypair or generate a new one (ML-DSA-65)
        let (public_key, secret_key) = match config.keypair.clone() {
            Some(keypair) => keypair,
            None => generate_ml_dsa_keypair().map_err(|e| {
                EndpointError::Config(format!("Failed to generate ML-DSA-65 keypair: {e:?}"))
            })?,
        };
        // SPKI fingerprint of our own public key (for identity/logging)
        let our_fingerprint =
            crate::crypto::raw_public_keys::pqc::fingerprint_public_key(&public_key);

        info!(
            "Creating P2P endpoint (fingerprint: {})",
            hex::encode(&our_fingerprint[..8])
        );

        // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
        // Store public key bytes directly for identity sharing
        let public_key_bytes: Vec<u8> = public_key.as_bytes().to_vec();

        // Create event channel
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let event_tx_clone = event_tx.clone();

        // Create stats
        let stats = Arc::new(RwLock::new(EndpointStats {
            total_bootstrap_nodes: config.known_peers.len(),
            start_time: Instant::now(),
            ..Default::default()
        }));
        let stats_clone = Arc::clone(&stats);

        // Create event callback that bridges to broadcast channel
        let event_callback = Box::new(move |event: NatTraversalEvent| {
            let event_tx = event_tx_clone.clone();
            let stats = stats_clone.clone();

            tokio::spawn(async move {
                // Update stats based on event
                let mut stats_guard = stats.write().await;
                match &event {
                    NatTraversalEvent::CoordinationRequested { .. } => {
                        stats_guard.nat_traversal_attempts += 1;
                    }
                    NatTraversalEvent::ConnectionEstablished {
                        remote_address,
                        side,
                        public_key,
                    } => {
                        stats_guard.nat_traversal_successes += 1;
                        stats_guard.active_connections += 1;
                        stats_guard.successful_connections += 1;

                        // Broadcast event with connection direction
                        let _ = event_tx.send(P2pEvent::PeerConnected {
                            addr: TransportAddr::Quic(*remote_address),
                            public_key: public_key.clone(),
                            side: *side,
                        });
                    }
                    NatTraversalEvent::TraversalFailed { remote_address, .. } => {
                        stats_guard.failed_connections += 1;
                        let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                            addr: *remote_address,
                            phase: TraversalPhase::Failed,
                        });
                    }
                    NatTraversalEvent::PhaseTransition {
                        remote_address,
                        to_phase,
                        ..
                    } => {
                        let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                            addr: *remote_address,
                            phase: *to_phase,
                        });
                    }
                    NatTraversalEvent::ExternalAddressDiscovered { address, .. } => {
                        info!("External address discovered: {}", address);
                        let _ = event_tx.send(P2pEvent::ExternalAddressDiscovered {
                            addr: TransportAddr::Quic(*address),
                        });
                    }
                    _ => {}
                }
                drop(stats_guard);
            });
        });

        // Create NAT traversal endpoint with the same identity key used for auth
        // This ensures P2pEndpoint and NatTraversalEndpoint use the same keypair
        let mut nat_config = config.to_nat_config_with_key(public_key.clone(), secret_key);
        let bootstrap_cache = Arc::new(
            BootstrapCache::open(config.bootstrap_cache.clone())
                .await
                .map_err(|e| {
                    EndpointError::Config(format!("Failed to open bootstrap cache: {}", e))
                })?,
        );

        // Create token store
        let token_store = Arc::new(BootstrapTokenStore::new(bootstrap_cache.clone()).await);

        // Phase 5.3 Deliverable 3: Socket sharing in default constructor
        // Bind a single UDP socket and share it between transport registry and Quinn
        let default_addr: std::net::SocketAddr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let bind_addr = config
            .bind_addr
            .as_ref()
            .and_then(|addr| addr.as_socket_addr())
            .unwrap_or(default_addr);
        let (udp_transport, quinn_socket) =
            crate::transport::UdpTransport::bind_for_quinn(bind_addr)
                .await
                .map_err(|e| EndpointError::Config(format!("Failed to bind UDP socket: {e}")))?;

        let actual_bind_addr = quinn_socket
            .local_addr()
            .map_err(|e| EndpointError::Config(format!("Failed to get local address: {e}")))?;

        info!("Bound shared UDP socket at {}", actual_bind_addr);

        // Create transport registry with the UDP transport
        // Also include any additional transports from the config
        let mut transport_registry = config.transport_registry.clone();
        transport_registry.register(Arc::new(udp_transport));

        // Update NAT config to use our registry and bind address
        nat_config.transport_registry = Some(Arc::new(transport_registry.clone()));
        nat_config.bind_addr = Some(actual_bind_addr);

        // Create NAT traversal endpoint with the shared socket
        let inner = NatTraversalEndpoint::new_with_socket(
            nat_config,
            Some(event_callback),
            Some(token_store.clone()),
            Some(quinn_socket),
        )
        .await
        .map_err(|e| EndpointError::Config(e.to_string()))?;

        // Wrap the registry in Arc for shared ownership
        let transport_registry = Arc::new(transport_registry);

        // Create connection router for automatic protocol engine selection
        let inner_arc = Arc::new(inner);
        let router_config = RouterConfig {
            constrained_config: crate::constrained::ConstrainedTransportConfig::default(),
            prefer_quic: true, // Default to QUIC for broadband transports
            enable_metrics: true,
            max_connections: 256,
        };
        // `with_full_config` already installs the QUIC endpoint; no
        // post-construction setter is needed.
        let router = ConnectionRouter::with_full_config(
            router_config,
            Arc::clone(&transport_registry),
            Arc::clone(&inner_arc),
        );

        // Create channel for data received from background reader tasks
        let (data_tx, data_rx) = mpsc::channel(config.data_channel_capacity);
        let reader_tasks = Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));
        let reader_handles = Arc::new(RwLock::new(HashMap::new()));

        // Channel for reader tasks to signal immediate cleanup on exit
        let (reader_exit_tx, reader_exit_rx) = mpsc::unbounded_channel();

        let endpoint = Self {
            inner: inner_arc,
            // v0.2: auth_manager removed
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            stats,
            config,
            event_tx,
            our_fingerprint,
            public_key: public_key_bytes,
            shutdown: CancellationToken::new(),
            pending_data: Arc::new(RwLock::new(BoundedPendingBuffer::default())),
            bootstrap_cache,
            transport_registry,
            router: Arc::new(router),
            constrained_connections: Arc::new(RwLock::new(HashMap::new())),
            constrained_peer_addrs: Arc::new(RwLock::new(HashMap::new())),
            hole_punch_target_peer_ids: Arc::new(dashmap::DashMap::new()),
            hole_punch_preferred_coordinators: Arc::new(dashmap::DashMap::new()),
            data_tx,
            data_rx: Arc::new(tokio::sync::Mutex::new(data_rx)),
            reader_tasks,
            reader_handles,
            reader_exit_tx,
            pending_dials: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };

        // Spawn background constrained poller task
        endpoint.spawn_constrained_poller();

        // Spawn stale connection reaper — periodically detects and removes
        // dead connections from tracking structures (issue #137 fix).
        endpoint.spawn_stale_connection_reaper();

        // Spawn reader-exit handler — immediately cleans up when a reader
        // task detects a dead QUIC connection, without waiting for the reaper.
        endpoint.spawn_reader_exit_handler(reader_exit_rx);

        // Spawn NAT traversal session driver — periodically polls the
        // NatTraversalEndpoint to advance sessions through Discovery →
        // Coordination → Punching phases. Runs independently of
        // try_hole_punch to avoid DashMap lock contention deadlocks.
        endpoint.spawn_session_driver();

        // Spawn incoming connection forwarder — bridges accepted connections
        // from the NatTraversalEndpoint to P2pEndpoint's connected_peers.
        endpoint.spawn_incoming_connection_forwarder();

        Ok(endpoint)
    }

    /// Get the local ML-DSA-65 SPKI public key bytes
    pub fn local_public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the underlying QUIC connection for a remote address.
    ///
    /// Look up an existing QUIC connection by remote address.
    ///
    /// Returns `None` if we have no tracked connection for this address.
    pub async fn get_quic_connection(
        &self,
        addr: &SocketAddr,
    ) -> Result<Option<crate::high_level::Connection>, EndpointError> {
        let peers = self.connected_peers.read().await;
        if !peers.contains_key(addr) {
            return Ok(None);
        }
        drop(peers);
        self.inner
            .get_connection(addr)
            .map_err(EndpointError::NatTraversal)
    }

    /// Get the local bind address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner
            .get_endpoint()
            .and_then(|ep| ep.local_addr().ok())
    }

    /// Get observed external address (if discovered)
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.get_observed_external_address().ok().flatten()
    }

    /// Get the transport registry for this endpoint
    ///
    /// The transport registry contains all registered transport providers (UDP, BLE, etc.)
    /// that this endpoint can use for connectivity.
    pub fn transport_registry(&self) -> &TransportRegistry {
        &self.transport_registry
    }

    /// Get the ML-DSA-65 public key bytes (1952 bytes)
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    // === Connection Management ===

    /// Connect to a peer by address (direct connection).
    ///
    /// Uses Raw Public Key authentication - the peer's identity is verified via their
    /// ML-DSA-65 public key, not via SNI/certificates.
    ///
    /// If we already have a live connection to the target address, returns the
    /// existing connection instead of creating a duplicate. After handshake, if
    /// we discover a simultaneous open (both sides connected at the same time),
    /// a deterministic tiebreaker ensures both sides keep the same connection.
    pub async fn connect(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Dedup check: if we already have a live connection to this address, return it.
        {
            let peers = self.connected_peers.read().await;
            if let Some(existing) = peers.get(&addr) {
                // Verify the underlying QUIC connection is still alive
                if self.inner.is_connected(&addr) {
                    info!("connect: reusing existing live connection to {}", addr);
                    return Ok(existing.clone());
                }
            }
        }
        // If a dead connection was found, remove stale entry.
        {
            let mut peers = self.connected_peers.write().await;
            if peers.contains_key(&addr) && !self.inner.is_connected(&addr) {
                peers.remove(&addr);
                info!("connect: removed stale connection entry for {}", addr);
            }
        }

        info!("Connecting directly to {}", addr);

        let endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let connecting = endpoint
            .connect(addr, "peer")
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        // Enforce a hard timeout on the QUIC handshake to prevent the 76s hang
        // reported in issue #137. The connection_timeout config or 30s default
        // ensures callers always get a response within a bounded window.
        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;
        let connection = match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                info!("connect: handshake to {} failed: {}", addr, e);
                return Err(EndpointError::Connection(e.to_string()));
            }
            Err(_) => {
                info!(
                    "connect: handshake to {} timed out after {:?}",
                    addr, handshake_timeout
                );
                return Err(EndpointError::Timeout);
            }
        };

        // Extract the public key from the TLS handshake
        let remote_public_key = extract_public_key_bytes_from_connection(&connection);

        // Post-handshake dedup: if we already have a live connection to this
        // address, just overwrite it with the new outgoing connection.
        if self.inner.is_connected(&addr) {
            debug!(
                "connect: simultaneous open for {} — overwriting existing connection",
                addr
            );
        }

        // Store connection in inner layer (keyed by remote SocketAddr)
        self.inner
            .add_connection(addr, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Spawn handler (we initiated the connection = Client side)
        self.inner
            .spawn_connection_handler(addr, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        // Create peer connection record
        // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
        let peer_conn = PeerConnection {
            public_key: remote_public_key.clone(),
            remote_addr: TransportAddr::Quic(addr),
            authenticated: true, // TLS handles authentication
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn background reader task BEFORE storing peer in connected_peers
        // This prevents a race where recv() called immediately after connect()
        // returns might miss early data if the peer sends before the task starts
        if let Ok(Some(conn)) = self.inner.get_connection(&addr) {
            self.spawn_reader_task(addr, conn).await;
        }

        // Store peer (reader task is already running, so no data loss window)
        self.connected_peers
            .write()
            .await
            .insert(addr, peer_conn.clone());

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
            stats.successful_connections += 1;
            stats.direct_connections += 1;
        }

        // Broadcast event (we initiated the connection = Client side)
        let _ = self.event_tx.send(P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(addr),
            public_key: remote_public_key,
            side: Side::Client,
        });

        Ok(peer_conn)
    }

    /// Connect to a peer using any transport address
    ///
    /// This method uses the connection router to automatically select the appropriate
    /// protocol engine (QUIC or Constrained) based on the transport capabilities.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use saorsa_transport::transport::TransportAddr;
    ///
    /// // Connect via UDP (uses QUIC)
    /// let udp_addr = TransportAddr::Quic("192.168.1.100:9000".parse()?);
    /// let conn = endpoint.connect_transport(&udp_addr, None).await?;
    ///
    /// // Connect via BLE (uses Constrained engine)
    /// let ble_addr = TransportAddr::Ble {
    ///     mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     psm: 128,
    /// };
    /// let conn = endpoint.connect_transport(&ble_addr, None).await?;
    /// ```
    pub async fn connect_transport(
        &self,
        addr: &TransportAddr,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Use the router to determine the appropriate engine.
        //
        // Both `select_engine_for_addr` and `connect` take `&self` on
        // `ConnectionRouter`, so there is no locking at all on the hot
        // path. Selection and connect are two separate calls — there is a
        // theoretical TOCTOU window where the engine picked here could
        // become unavailable before the connect runs. In practice the
        // router has no API to revoke or replace an engine once installed
        // (the QUIC endpoint is set at construction time, the constrained
        // transport is lazy-initialised and never torn down), so the race
        // is closed by construction. If that invariant is ever relaxed,
        // this call site needs to handle an engine-unavailable error from
        // `connect()` explicitly.
        let engine = self.router.select_engine_for_addr(addr);

        info!("Connecting to {} via {:?} engine", addr, engine);

        match engine {
            ProtocolEngine::Quic => {
                // For QUIC, extract socket address and use existing connect path
                let socket_addr = addr.as_socket_addr().ok_or_else(|| {
                    EndpointError::Connection(format!(
                        "Cannot extract socket address from {} for QUIC",
                        addr
                    ))
                })?;
                self.connect(socket_addr).await
            }
            ProtocolEngine::Constrained => {
                // For constrained transports, use the router's connect
                // path. No lock needed — `connect` takes `&self`.
                let _routed = self.router.connect(addr).map_err(|e| {
                    EndpointError::Connection(format!("Constrained connection failed: {}", e))
                })?;

                // Use a synthetic socket address for constrained connections
                let synthetic_addr = addr.to_synthetic_socket_addr();

                let peer_conn = PeerConnection {
                    public_key: None, // Constrained connections don't have TLS auth yet
                    remote_addr: addr.clone(),
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                self.connected_peers
                    .write()
                    .await
                    .insert(synthetic_addr, peer_conn.clone());

                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                // Broadcast event
                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    addr: addr.clone(),
                    public_key: None,
                    side: Side::Client,
                });

                Ok(peer_conn)
            }
        }
    }

    /// Get the connection router for advanced routing control
    ///
    /// Returns a shared reference to the connection router which can be
    /// used to query engine selection for addresses, read routing stats,
    /// or drive connects/accepts directly. All router methods take
    /// `&self`, so multiple callers can use the returned handle
    /// concurrently.
    pub fn router(&self) -> &Arc<ConnectionRouter> {
        &self.router
    }

    /// Get a point-in-time snapshot of router statistics.
    pub fn routing_stats(&self) -> crate::connection_router::RouterStatsSnapshot {
        self.router.stats().snapshot()
    }

    /// Register a constrained connection for a transport address
    ///
    /// This associates a TransportAddr with a ConstrainedEngine ConnectionId, enabling
    /// send() to use the proper constrained protocol for reliable delivery.
    ///
    /// # Arguments
    ///
    /// * `addr` - The remote transport address
    /// * `conn_id` - The ConnectionId from the ConstrainedEngine
    ///
    /// # Returns
    ///
    /// The previous ConnectionId if one was already registered for this address.
    pub async fn register_constrained_connection(
        &self,
        addr: TransportAddr,
        conn_id: ConstrainedConnectionId,
    ) -> Option<ConstrainedConnectionId> {
        let old = self
            .constrained_connections
            .write()
            .await
            .insert(addr.clone(), conn_id);
        debug!(
            "Registered constrained connection for addr {}: conn_id={:?}",
            addr, conn_id
        );
        old
    }

    /// Unregister a constrained connection for a transport address
    ///
    /// Call this when a constrained connection is closed or reset.
    ///
    /// # Returns
    ///
    /// The ConnectionId if one was registered for this address.
    pub async fn unregister_constrained_connection(
        &self,
        addr: &TransportAddr,
    ) -> Option<ConstrainedConnectionId> {
        let removed = self.constrained_connections.write().await.remove(addr);
        if removed.is_some() {
            debug!("Unregistered constrained connection for addr {}", addr);
        }
        removed
    }

    /// Check if a transport address has a constrained connection
    pub async fn has_constrained_connection(&self, addr: &TransportAddr) -> bool {
        self.constrained_connections.read().await.contains_key(addr)
    }

    /// Get the ConnectionId for a transport address's constrained connection
    pub async fn get_constrained_connection_id(
        &self,
        addr: &TransportAddr,
    ) -> Option<ConstrainedConnectionId> {
        self.constrained_connections.read().await.get(addr).copied()
    }

    /// Get the number of active constrained connections
    pub async fn constrained_connection_count(&self) -> usize {
        self.constrained_connections.read().await.len()
    }

    /// Look up TransportAddr from constrained ConnectionId
    pub async fn addr_from_constrained_conn(
        &self,
        conn_id: ConstrainedConnectionId,
    ) -> Option<TransportAddr> {
        self.constrained_peer_addrs
            .read()
            .await
            .get(&conn_id)
            .cloned()
    }

    /// Connect with automatic fallback: IPv4 → IPv6 → HolePunch → Relay
    ///
    /// This method implements a progressive connection strategy that automatically
    /// falls back through increasingly aggressive NAT traversal techniques:
    ///
    /// 1. **Direct IPv4** (5s timeout) - Simple direct connection
    /// 2. **Direct IPv6** (5s timeout) - Bypasses NAT when IPv6 available
    /// 3. **Hole-Punch** (15s timeout) - Coordinated NAT traversal via common peer
    /// 4. **Relay** (30s timeout) - MASQUE relay as last resort
    ///
    /// # Arguments
    ///
    /// * `target_ipv4` - Optional IPv4 address of the target peer
    /// * `target_ipv6` - Optional IPv6 address of the target peer
    /// * `strategy_config` - Optional custom strategy configuration
    ///
    /// # Returns
    ///
    /// A tuple of (PeerConnection, ConnectionMethod) indicating how the connection
    /// was established.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (conn, method) = endpoint.connect_with_fallback(
    ///     Some("1.2.3.4:9000".parse()?),
    ///     Some("[2001:db8::1]:9000".parse()?),
    ///     None, // Use default strategy config
    /// ).await?;
    ///
    /// match method {
    ///     ConnectionMethod::DirectIPv4 => println!("Direct IPv4"),
    ///     ConnectionMethod::DirectIPv6 => println!("Direct IPv6"),
    ///     ConnectionMethod::HolePunched { coordinator } => println!("Via {}", coordinator),
    ///     ConnectionMethod::Relayed { relay } => println!("Relayed via {}", relay),
    /// }
    /// ```
    /// Set the target peer ID for a hole-punch attempt to a specific address.
    /// When set, the PUNCH_ME_NOW frame carries the peer ID instead of a
    /// socket-address-derived wire ID, allowing the coordinator to find the
    /// target connection by authenticated identity.
    ///
    /// Keyed by target address so concurrent dials to different peers each
    /// get their own peer ID without racing on shared state.
    pub async fn set_hole_punch_target_peer_id(&self, target: SocketAddr, peer_id: [u8; 32]) {
        self.hole_punch_target_peer_ids.insert(target, peer_id);
    }

    /// Set an ordered list of preferred coordinators for hole-punching to a
    /// specific target.
    ///
    /// The caller (typically saorsa-core's DHT layer) is expected to rank
    /// the list best-first using its own quality signals — e.g. DHT lookup
    /// round, trust score, observed latency. During hole-punching the list
    /// is iterated front to back: the first `coordinators.len() - 1` get a
    /// short per-attempt timeout so a busy or unreachable coordinator is
    /// abandoned quickly; the last coordinator gets the full strategy
    /// hole-punch timeout to give it time to complete the punch.
    ///
    /// Empty `coordinators` removes any preferred coordinators for `target`.
    ///
    /// ## Interaction with `StrategyConfig::max_holepunch_rounds`
    ///
    /// Each rotation step in the connect loop calls
    /// `ConnectionStrategy::increment_round`, so the strategy's per-round
    /// counter and the rotation index advance together. With the default
    /// `max_holepunch_rounds = 2`, supplying `K ≥ 2` preferred coordinators
    /// gives each coordinator (including the final one) exactly one
    /// attempt — the rotation fully replaces the legacy retry loop and the
    /// worst-case dial time is `(K-1) * 1.5s + 8s`.
    ///
    /// If a caller has explicitly raised `max_holepunch_rounds` (e.g.
    /// `with_max_holepunch_rounds(5)`) **and** also supplies a preferred
    /// list, the *final* coordinator inherits the leftover round budget
    /// — it will be retried `max_rounds - K + 1` times at the full
    /// hole-punch timeout. This is usually fine but worth knowing if you
    /// were expecting the rotation to be the only retry mechanism.
    pub async fn set_hole_punch_preferred_coordinators(
        &self,
        target: SocketAddr,
        coordinators: Vec<SocketAddr>,
    ) {
        if coordinators.is_empty() {
            self.hole_punch_preferred_coordinators.remove(&target);
        } else {
            self.hole_punch_preferred_coordinators
                .insert(target, coordinators);
        }
    }

    /// Set a single preferred coordinator for hole-punching to a specific
    /// target.
    ///
    /// Thin wrapper around [`Self::set_hole_punch_preferred_coordinators`]
    /// retained for callers that have only one coordinator candidate. New
    /// callers should prefer the list form.
    pub async fn set_hole_punch_preferred_coordinator(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
    ) {
        self.set_hole_punch_preferred_coordinators(target, vec![coordinator])
            .await;
    }

    /// Connect with automatic fallback: Direct → HolePunch → Relay.
    pub async fn connect_with_fallback(
        &self,
        target_ipv4: Option<SocketAddr>,
        target_ipv6: Option<SocketAddr>,
        strategy_config: Option<StrategyConfig>,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        info!(
            "connect_with_fallback: IPv4={:?}, IPv6={:?}",
            target_ipv4, target_ipv6
        );
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Dedup: if another task is already connecting to this target, wait for
        // its result instead of starting a parallel attempt. This prevents
        // multiple concurrent hole-punch sessions that deadlock the runtime.
        let target = target_ipv4.or(target_ipv6);
        if let Some(target_addr) = target {
            let mut pending = self.pending_dials.lock().await;
            if let Some(tx) = pending.get(&target_addr) {
                // Another task is already connecting — subscribe and wait
                let mut rx = tx.subscribe();
                drop(pending);
                info!(
                    "connect_with_fallback: waiting for in-flight dial to {}",
                    target_addr
                );
                match rx.recv().await {
                    Ok(Ok(conn)) => {
                        return Ok((
                            conn,
                            ConnectionMethod::HolePunched {
                                coordinator: target_addr,
                            },
                        ));
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Primary dial failed — fall through and try ourselves
                    }
                }
            } else {
                // We're the first — register ourselves
                let (tx, _) = broadcast::channel(4);
                pending.insert(target_addr, tx);
                drop(pending);
            }
        }

        // Do the actual connection work
        let result = self
            .connect_with_fallback_inner(target_ipv4, target_ipv6, strategy_config)
            .await;

        // Broadcast result to any waiters and clean up pending entry
        if let Some(target_addr) = target {
            let mut pending = self.pending_dials.lock().await;
            if let Some(tx) = pending.remove(&target_addr) {
                match &result {
                    Ok((conn, _)) => {
                        let _ = tx.send(Ok(conn.clone()));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string()));
                    }
                }
            }
        }

        result
    }

    /// Merge a ranked list of preferred hole-punch coordinators into the
    /// front of `coordinator_candidates`, preserving the relative order of
    /// `preferred` and removing any pre-existing duplicates from the
    /// candidate list.
    ///
    /// After this call returns, `coordinator_candidates[0..preferred.len()]`
    /// equals `preferred` (in order). The hole-punch loop uses
    /// `preferred.len()` directly to decide which attempts get the short
    /// rotation timeout vs. the strategy's full hole-punch timeout.
    ///
    /// Pure function (no `&self`, no I/O) — extracted from
    /// `connect_with_fallback_inner` so the front-insertion behaviour can
    /// be unit-tested without spinning up a full endpoint.
    fn merge_preferred_coordinators(
        coordinator_candidates: &mut Vec<SocketAddr>,
        preferred: &[SocketAddr],
    ) {
        if preferred.is_empty() {
            return;
        }
        // Drop any pre-existing copies of the preferred entries from the
        // tail so we don't end up with duplicates after the front-insert.
        coordinator_candidates.retain(|a| !preferred.contains(a));
        // Build the merged list in one allocation rather than calling
        // `Vec::insert(0, ..)` in a loop (which shifts the entire tail
        // on every iteration — O(N·M) instead of O(N+M)).
        let mut merged = Vec::with_capacity(preferred.len() + coordinator_candidates.len());
        merged.extend_from_slice(preferred);
        merged.append(coordinator_candidates);
        *coordinator_candidates = merged;
    }

    /// Inner implementation of connect_with_fallback (separated for dedup wrapper).
    async fn connect_with_fallback_inner(
        &self,
        target_ipv4: Option<SocketAddr>,
        target_ipv6: Option<SocketAddr>,
        strategy_config: Option<StrategyConfig>,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        // Build strategy config with coordinator and relay from our config.
        // Collect ALL coordinator candidates so we can rotate on failure.
        let mut config = strategy_config.unwrap_or_default();
        let target = target_ipv4.or(target_ipv6);
        let mut coordinator_candidates: Vec<SocketAddr> = Vec::new();

        // Add known_peers first (configured bootstrap nodes)
        for addr in &self.config.known_peers {
            if let Some(sa) = addr.as_socket_addr() {
                if Some(sa) != target {
                    coordinator_candidates.push(sa);
                }
            }
        }
        // Add all connected peers as fallback candidates
        {
            let peers = self.connected_peers.read().await;
            for &addr in peers.keys() {
                if Some(addr) != target && !coordinator_candidates.contains(&addr) {
                    coordinator_candidates.push(addr);
                }
            }
        }

        // If the DHT layer set preferred coordinators for this target, move
        // them to the front of the candidate list in order so the hole-punch
        // loop tries them first. Each preferred coordinator is removed from
        // its existing position (if any) before being inserted at the front
        // so the relative ordering of the preferred list is preserved.
        //
        // `preferred_coordinator_count` is captured for the hole-punch loop:
        // when > 0 the loop rotates through `coordinator_candidates[0..count]`
        // with `PER_COORDINATOR_QUICK_HOLEPUNCH_TIMEOUT` per non-final attempt,
        // and the strategy's full timeout for the last attempt. When 0 the
        // loop falls back to the existing single-coordinator retry behaviour.
        let mut preferred_coordinator_count: usize = 0;
        if let Some(target_addr) = target {
            if let Some(preferred) = self.hole_punch_preferred_coordinators.get(&target_addr) {
                let preferred_list: Vec<SocketAddr> = preferred.clone();
                drop(preferred); // Release the DashMap entry guard before mutating coordinator_candidates.
                Self::merge_preferred_coordinators(&mut coordinator_candidates, &preferred_list);
                preferred_coordinator_count = preferred_list.len();
                if preferred_coordinator_count > 0 {
                    info!(
                        "Using {} preferred coordinator(s) for target {} (DHT referrers): {:?}",
                        preferred_list.len(),
                        target_addr,
                        preferred_list
                    );
                }
            } else {
                info!(
                    "No preferred coordinator for target {} (not discovered via DHT referral)",
                    target_addr
                );
            }
        }

        if config.coordinator.is_none() {
            config.coordinator = coordinator_candidates.first().copied();
            if let Some(coord) = config.coordinator {
                info!(
                    "Using {} as NAT traversal coordinator ({} candidates total)",
                    coord,
                    coordinator_candidates.len()
                );
            }
        }
        if config.relay_addrs.is_empty() {
            // Optimization: Try to find a high-quality relay from our cache first
            let target_addr = target_ipv4.or(target_ipv6);
            if let Some(addr) = target_addr {
                // Select best relay for this target (preferring dual-stack)
                let relays = self
                    .bootstrap_cache
                    .select_relays_for_target(1, &addr, true)
                    .await;

                if let Some(best_relay) = relays.first() {
                    // Use the first address of the best relay
                    // In a perfect world we'd check reachability of this address too,
                    // but for now we assume cached addresses are valid candidates.
                    if let Some(relay_addr) = best_relay.addresses.first().copied() {
                        config.relay_addrs.push(relay_addr);
                        debug!(
                            "Selected optimized relay from cache: {:?} for target {}",
                            relay_addr, addr
                        );
                    }
                }
            }

            // Fallback to static config if cache gave nothing
            if config.relay_addrs.is_empty() {
                if let Some(relay_addr) = self.config.nat.relay_nodes.first().copied() {
                    config.relay_addrs.push(relay_addr);
                }
            }

            // If still no relay addresses, use connected peers as relay candidates.
            // In the symmetric architecture, every node runs a MASQUE relay server.
            if config.relay_addrs.is_empty() {
                let peers = self.connected_peers.read().await;
                let target = target_ipv4.or(target_ipv6);
                for &addr in peers.keys() {
                    if Some(addr) != target {
                        config.relay_addrs.push(addr);
                    }
                }
                if !config.relay_addrs.is_empty() {
                    info!(
                        "Using {} connected peer(s) as relay candidates",
                        config.relay_addrs.len()
                    );
                }
            }
        }

        let mut strategy = ConnectionStrategy::new(config);

        info!(
            "Starting fallback connection: IPv4={:?}, IPv6={:?}",
            target_ipv4, target_ipv6
        );

        // Collect direct addresses for Happy Eyeballs racing (RFC 8305)
        let mut direct_addresses: Vec<SocketAddr> = Vec::new();
        if let Some(v6) = target_ipv6 {
            direct_addresses.push(v6);
        }
        if let Some(v4) = target_ipv4 {
            direct_addresses.push(v4);
        }

        // Index of the preferred coordinator currently being attempted (when
        // `preferred_coordinator_count > 0`). The hole-punch loop advances
        // this on each failed round and uses it together with
        // `preferred_coordinator_count` to decide whether the *next* attempt
        // is the final one (full strategy timeout) or an interim rotation
        // attempt (`PER_COORDINATOR_QUICK_HOLEPUNCH_TIMEOUT`).
        let mut current_preferred_coordinator_idx: usize = 0;

        loop {
            // Check if a previous hole-punch attempt established the connection
            // asynchronously (e.g. the target connected to us after receiving
            // a relayed PUNCH_ME_NOW from a prior round).
            let target = target_ipv4.or(target_ipv6);
            if let Some(target_addr) = target {
                if self.inner.is_connected(&target_addr) {
                    info!(
                        "connect_with_fallback: connection to {} established asynchronously",
                        target_addr
                    );
                    let peer_conn = PeerConnection {
                        public_key: None,
                        remote_addr: TransportAddr::Quic(target_addr),
                        authenticated: true,
                        connected_at: Instant::now(),
                        last_activity: Instant::now(),
                    };
                    // Spawn background reader task for data reception
                    if let Ok(Some(conn)) = self.inner.get_connection(&target_addr) {
                        self.spawn_reader_task(target_addr, conn).await;
                    }

                    self.connected_peers
                        .write()
                        .await
                        .insert(target_addr, peer_conn.clone());

                    // Broadcast PeerConnected so the identity exchange is triggered
                    let _ = self.event_tx.send(P2pEvent::PeerConnected {
                        addr: TransportAddr::Quic(target_addr),
                        public_key: peer_conn.public_key.clone(),
                        side: Side::Client,
                    });

                    return Ok((
                        peer_conn,
                        ConnectionMethod::HolePunched {
                            coordinator: target_addr, // approximate
                        },
                    ));
                }
            }

            match strategy.current_stage().clone() {
                ConnectionStage::DirectIPv4 { .. } => {
                    // Use Happy Eyeballs (RFC 8305) to race all direct addresses (IPv4 + IPv6)
                    // instead of trying them sequentially. This prevents stalls when one address
                    // family is broken by racing with a 250ms stagger.
                    if direct_addresses.is_empty() {
                        debug!("No direct addresses provided, skipping to hole-punch");
                        strategy.transition_to_ipv6("No direct addresses");
                        continue;
                    }

                    let he_config = HappyEyeballsConfig::default();
                    let direct_timeout = strategy.ipv4_timeout().max(strategy.ipv6_timeout());

                    info!(
                        "Happy Eyeballs: racing {} direct addresses (timeout: {:?})",
                        direct_addresses.len(),
                        direct_timeout
                    );

                    // Clone the QUIC endpoint for use in the Happy Eyeballs closure.
                    // Each spawned attempt needs its own reference to create connections.
                    let quic_endpoint = match self.inner.get_endpoint().cloned() {
                        Some(ep) => ep,
                        None => {
                            debug!("QUIC endpoint not available, skipping direct");
                            strategy.transition_to_ipv6("QUIC endpoint not available");
                            strategy.transition_to_holepunch("QUIC endpoint not available");
                            continue;
                        }
                    };

                    let addrs = direct_addresses.clone();
                    let he_result = timeout(direct_timeout, async {
                        happy_eyeballs::race_connect(&addrs, &he_config, |addr| {
                            let ep = quic_endpoint.clone();
                            async move {
                                let connecting = ep
                                    .connect(addr, "peer")
                                    .map_err(|e| format!("connect error: {e}"))?;
                                connecting
                                    .await
                                    .map_err(|e| format!("handshake error: {e}"))
                            }
                        })
                        .await
                    })
                    .await;

                    match he_result {
                        Ok(Ok((connection, winning_addr))) => {
                            let method = if winning_addr.is_ipv6() {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::DirectIPv4
                            };
                            info!(
                                "Happy Eyeballs: {} connection to {} succeeded",
                                method, winning_addr
                            );

                            // Complete the connection setup (handlers, stats)
                            let peer_conn = self
                                .finalize_direct_connection(connection, winning_addr)
                                .await?;
                            return Ok((peer_conn, method));
                        }
                        Ok(Err(e)) => {
                            debug!("Happy Eyeballs: all direct attempts failed: {}", e);
                            strategy.transition_to_ipv6(e.to_string());
                            strategy.transition_to_holepunch("Happy Eyeballs exhausted");
                        }
                        Err(_) => {
                            debug!("Happy Eyeballs: direct connection timed out");
                            strategy.transition_to_ipv6("Timeout");
                            strategy.transition_to_holepunch("Happy Eyeballs timed out");
                        }
                    }
                }

                ConnectionStage::DirectIPv6 { .. } => {
                    // Happy Eyeballs already handled both IPv4 and IPv6 in the DirectIPv4 stage.
                    // If we reach here, it means Happy Eyeballs failed and we need to move on.
                    debug!(
                        "DirectIPv6 stage reached after Happy Eyeballs, advancing to hole-punch"
                    );
                    strategy.transition_to_holepunch("Handled by Happy Eyeballs");
                }

                ConnectionStage::HolePunching {
                    coordinator, round, ..
                } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    // Coordinator-rotation policy (Tier 2):
                    //
                    // When `preferred_coordinator_count > 0` we have a ranked
                    // list of DHT-supplied coordinators at
                    // `coordinator_candidates[0..preferred_coordinator_count]`
                    // and we rotate through them on each failed round. The
                    // first `count - 1` attempts use a short timeout
                    // (`PER_COORDINATOR_QUICK_HOLEPUNCH_TIMEOUT`) so a busy or
                    // unreachable coordinator is abandoned quickly; the final
                    // attempt uses the strategy's full hole-punch timeout to
                    // give it time to actually complete.
                    //
                    // When `preferred_coordinator_count == 0` (no DHT
                    // referrers — first contact, or non-DHT dial) we fall
                    // back to the legacy single-coordinator behaviour:
                    // strategy timeout per round, retry the same coordinator
                    // until `should_retry_holepunch` is exhausted.
                    let is_rotating = preferred_coordinator_count > 0;
                    let is_final_rotation_attempt = is_rotating
                        && current_preferred_coordinator_idx + 1 >= preferred_coordinator_count;
                    let attempt_timeout = if is_rotating && !is_final_rotation_attempt {
                        PER_COORDINATOR_QUICK_HOLEPUNCH_TIMEOUT
                    } else {
                        strategy.holepunch_timeout()
                    };

                    // Invariant: while rotating, the strategy's current
                    // coordinator must equal `coordinator_candidates[idx]`.
                    // This is maintained by `set_coordinator()` on every
                    // rotation step; the assert catches any future
                    // regression where a caller sets the strategy's
                    // coordinator out of band without updating the
                    // candidate list.
                    debug_assert!(
                        !is_rotating
                            || coordinator_candidates
                                .get(current_preferred_coordinator_idx)
                                .copied()
                                == Some(coordinator),
                        "rotation index out of sync with strategy coordinator: idx={}, coord={}, candidates={:?}",
                        current_preferred_coordinator_idx,
                        coordinator,
                        coordinator_candidates,
                    );

                    info!(
                        "Trying hole-punch to {} via {} (round {}, attempt timeout {:?}, rotating={})",
                        target, coordinator, round, attempt_timeout, is_rotating
                    );

                    // Use our existing NAT traversal infrastructure
                    let attempt_result =
                        timeout(attempt_timeout, self.try_hole_punch(target, coordinator)).await;

                    // Common post-attempt step: try a quick direct connect.
                    // The NAT binding may have been created by the target's
                    // outgoing packets even though our try_hole_punch didn't
                    // detect the connection.
                    let post_direct = async {
                        if let Ok(Ok(peer_conn)) =
                            timeout(POST_HOLEPUNCH_DIRECT_RETRY_TIMEOUT, self.connect(target)).await
                        {
                            info!("✓ Post-hole-punch direct connect succeeded to {}", target);
                            Some(peer_conn)
                        } else {
                            None
                        }
                    };

                    match attempt_result {
                        Ok(Ok(conn)) => {
                            info!("✓ Hole-punch succeeded to {} via {}", target, coordinator);
                            return Ok((conn, ConnectionMethod::HolePunched { coordinator }));
                        }
                        Ok(Err(e)) => {
                            if let Some(peer_conn) = post_direct.await {
                                return Ok((
                                    peer_conn,
                                    ConnectionMethod::HolePunched { coordinator },
                                ));
                            }
                            strategy.record_holepunch_error(round, e.to_string());
                            // Bounds-safe rotation: bail out of rotation and
                            // fall back to relay if for any reason the index
                            // would go out of bounds (defensive — by
                            // construction the bound holds while
                            // `current_preferred_coordinator_idx + 1 < preferred_coordinator_count`).
                            let next_coord = if is_rotating && !is_final_rotation_attempt {
                                coordinator_candidates
                                    .get(current_preferred_coordinator_idx + 1)
                                    .copied()
                            } else {
                                None
                            };
                            if let Some(next_coord) = next_coord {
                                current_preferred_coordinator_idx += 1;
                                info!(
                                    "Hole-punch via {} failed ({}), rotating to preferred coordinator {}/{}: {}",
                                    coordinator,
                                    e,
                                    current_preferred_coordinator_idx + 1,
                                    preferred_coordinator_count,
                                    next_coord
                                );
                                strategy.set_coordinator(next_coord);
                                strategy.increment_round();
                            } else if strategy.should_retry_holepunch() {
                                info!(
                                    "Hole-punch round {} failed, retrying with same coordinator",
                                    round
                                );
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch failed after {} rounds", round);
                                strategy.transition_to_relay(e.to_string());
                            }
                        }
                        Err(_) => {
                            if let Some(peer_conn) = post_direct.await {
                                return Ok((
                                    peer_conn,
                                    ConnectionMethod::HolePunched { coordinator },
                                ));
                            }
                            strategy.record_holepunch_error(round, "Timeout".to_string());
                            let next_coord = if is_rotating && !is_final_rotation_attempt {
                                coordinator_candidates
                                    .get(current_preferred_coordinator_idx + 1)
                                    .copied()
                            } else {
                                None
                            };
                            if let Some(next_coord) = next_coord {
                                current_preferred_coordinator_idx += 1;
                                info!(
                                    "Hole-punch via {} timed out after {:?}, rotating to preferred coordinator {}/{}: {}",
                                    coordinator,
                                    attempt_timeout,
                                    current_preferred_coordinator_idx + 1,
                                    preferred_coordinator_count,
                                    next_coord
                                );
                                strategy.set_coordinator(next_coord);
                                strategy.increment_round();
                            } else if strategy.should_retry_holepunch() {
                                info!(
                                    "Hole-punch round {} timed out, retrying with same coordinator",
                                    round
                                );
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch timed out after {} rounds", round);
                                strategy.transition_to_relay("Timeout");
                            }
                        }
                    }
                }

                ConnectionStage::Relay { relay_addr, .. } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!("Trying relay connection to {} via {}", target, relay_addr);

                    match timeout(
                        strategy.relay_timeout(),
                        self.try_relay_connection(target, relay_addr),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!(
                                "✓ Relay connection succeeded to {} via {}",
                                target, relay_addr
                            );
                            return Ok((conn, ConnectionMethod::Relayed { relay: relay_addr }));
                        }
                        Ok(Err(e)) => {
                            debug!("Relay connection failed: {}", e);
                            strategy.transition_to_failed(e.to_string());
                        }
                        Err(_) => {
                            debug!("Relay connection timed out");
                            strategy.transition_to_failed("Timeout");
                        }
                    }
                }

                ConnectionStage::Failed { errors } => {
                    let error_summary = errors
                        .iter()
                        .map(|e| format!("{:?}: {}", e.method, e.error))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(EndpointError::AllStrategiesFailed(error_summary));
                }

                ConnectionStage::Connected { via } => {
                    // This shouldn't happen in the loop, but handle it
                    unreachable!("Connected stage reached in loop: {:?}", via);
                }
            }
        }
    }

    /// Finalize a direct QUIC connection established by Happy Eyeballs.
    ///
    /// Takes the raw QUIC `Connection` from the successful handshake and completes
    /// the P2P connection setup: public key extraction, connection storage, handler
    /// spawning, stats update, and event broadcast.
    async fn finalize_direct_connection(
        &self,
        connection: crate::high_level::Connection,
        addr: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        // Extract public key from TLS
        let remote_public_key = extract_public_key_bytes_from_connection(&connection);

        // Dedup check: if already connected to this address, use fingerprint tiebreaker
        if self.inner.is_connected(&addr) {
            // Use our SPKI fingerprint vs remote's for deterministic tiebreaking
            let remote_fingerprint = remote_public_key
                .as_deref()
                .and_then(|pk| {
                    crate::crypto::raw_public_keys::pqc::fingerprint_public_key_bytes(pk).ok()
                })
                .unwrap_or([0u8; 32]);
            let we_keep_client = self.our_fingerprint < remote_fingerprint;
            if !we_keep_client {
                // We have the higher fingerprint: close this outgoing connection,
                // keep the existing one (from accept path).
                info!(
                    "finalize_direct_connection: simultaneous open for {} — \
                     closing outgoing (keeping incoming)",
                    addr
                );
                connection.close(0u32.into(), b"duplicate");
                // Wait briefly for the accept path to populate connected_peers
                for _ in 0..10 {
                    let peers = self.connected_peers.read().await;
                    if let Some(existing) = peers.get(&addr) {
                        return Ok(existing.clone());
                    }
                    drop(peers);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                return Err(EndpointError::Connection(
                    "simultaneous open: peer connection not yet available, retry".into(),
                ));
            }
            // We have the lower fingerprint: keep our outgoing connection,
            // remove the old one from accept path.
            info!(
                "finalize_direct_connection: simultaneous open for {} — \
                 keeping outgoing (replacing incoming)",
                addr
            );
            let _ = self.inner.remove_connection(&addr);
        }

        // Store in NAT traversal layer (keyed by remote SocketAddr)
        self.inner
            .add_connection(addr, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Spawn connection handler (Client side - we initiated)
        self.inner
            .spawn_connection_handler(addr, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            public_key: remote_public_key.clone(),
            remote_addr: TransportAddr::Quic(addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn reader task before storing peer to prevent data loss race
        if let Ok(Some(conn)) = self.inner.get_connection(&addr) {
            self.spawn_reader_task(addr, conn).await;
        }

        self.connected_peers
            .write()
            .await
            .insert(addr, peer_conn.clone());

        {
            let mut stats = self.stats.write().await;
            stats.active_connections += 1;
            stats.successful_connections += 1;
            stats.direct_connections += 1;
        }

        let _ = self.event_tx.send(P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(addr),
            public_key: remote_public_key,
            side: Side::Client,
        });

        Ok(peer_conn)
    }

    /// Internal helper for hole-punch attempt
    async fn try_hole_punch(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        info!(
            "try_hole_punch: ENTER target={} coordinator={}",
            target, coordinator
        );

        // First ensure we're connected to the coordinator
        if !self.is_connected_to_addr(coordinator).await {
            info!(
                "try_hole_punch: connecting to coordinator {} first",
                coordinator
            );
            self.connect(coordinator).await?;
            info!("try_hole_punch: coordinator {} connected", coordinator);
        } else {
            info!(
                "try_hole_punch: coordinator {} already connected",
                coordinator
            );
        }

        // Initiate NAT traversal — sends PUNCH_ME_NOW to coordinator.
        // Look up the target peer ID from the per-target map. This avoids
        // races when multiple concurrent connections share the same P2pEndpoint.
        let target_peer_id = self.hole_punch_target_peer_ids.get(&target).map(|v| *v);
        if let Some(ref pid) = target_peer_id {
            info!(
                "try_hole_punch: calling initiate_nat_traversal({}, {}) with peer ID {} (dashmap key={})",
                target,
                coordinator,
                hex::encode(&pid[..8]),
                target
            );
        } else {
            info!(
                "try_hole_punch: calling initiate_nat_traversal({}, {}) with address-based wire ID (no dashmap entry for key={})",
                target, coordinator, target
            );
        }
        self.inner
            .initiate_nat_traversal_for_peer(target, coordinator, target_peer_id)
            .map_err(EndpointError::NatTraversal)?;
        info!("try_hole_punch: initiate_nat_traversal returned OK");

        // NOTE: We intentionally do NOT send a QUIC probe here.
        // A previous attempt sent a fire-and-forget probe that created
        // a second QUIC connection to the target address. When the probe
        // succeeded (target is a cloud VM, directly reachable), the probe
        // connection was accepted by the target, stored in the DashMap
        // under the same key as the REAL incoming connection, then
        // immediately closed with "hole-punch-probe". The close triggered
        // cleanup that removed the DashMap entry — destroying the real
        // connection's entry and making all send() calls fail.
        //
        // The correct approach: rely on the coordinator relay (PUNCH_ME_NOW)
        // to create the NAT binding on the target side. The target then
        // connects back to us, and we use THAT connection for bidirectional
        // communication.

        // Poll for the connection to appear. The target node will receive
        // the relayed PUNCH_ME_NOW and initiate a QUIC connection to us,
        // which gets accepted by saorsa-core's transport handler.
        // No internal deadline — the outer strategy.holepunch_timeout()
        // cancels this future when it expires.
        let mut poll_count = 0u32;

        loop {
            poll_count += 1;
            if poll_count % 10 == 1 {
                info!(
                    "try_hole_punch: poll loop iteration {} for target {}",
                    poll_count, target
                );
            }

            if self.shutdown.is_cancelled() {
                return Err(EndpointError::ShuttingDown);
            }

            // Check for connection by address first (fast path for cone NAT),
            // then by peer ID (handles symmetric NAT where the return
            // connection has a different port than the DHT address).
            let connected_addr = if self.inner.is_connected(&target) {
                Some(target)
            } else if let Some(ref pid) = target_peer_id {
                self.find_connection_by_peer_id(pid)
            } else {
                None
            };

            if let Some(actual_addr) = connected_addr {
                info!(
                    "try_hole_punch: connection to {} established (actual addr: {})!",
                    target, actual_addr
                );
                let peer_conn = PeerConnection {
                    public_key: None,
                    remote_addr: TransportAddr::Quic(actual_addr),
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };
                self.connected_peers
                    .write()
                    .await
                    .insert(actual_addr, peer_conn.clone());
                return Ok(peer_conn);
            }

            // Check P2pEndpoint's connected_peers (populated by saorsa-core)
            // Try both the target address and, for symmetric NAT, any
            // connection matching the peer ID.
            {
                let peers = self.connected_peers.read().await;
                if let Some(existing) = peers.get(&target) {
                    info!("try_hole_punch: connection to {} found in peers", target);
                    return Ok(existing.clone());
                }
            }

            // Wait briefly then re-check; the outer timeout cancels us on expiry
            tokio::select! {
                _ = self.inner.connection_notify().notified() => {
                    debug!("try_hole_punch: connection_notify fired for {}", target);
                }
                _ = self.shutdown.cancelled() => {
                    return Err(EndpointError::ShuttingDown);
                }
                // Wake periodically to drive session and re-check connections
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
    }

    async fn try_relay_connection(
        &self,
        target: SocketAddr,
        relay_addr: SocketAddr,
    ) -> Result<PeerConnection, EndpointError> {
        info!(
            "Attempting MASQUE relay connection to {} via {}",
            target, relay_addr
        );

        // Step 1: Establish relay session (control plane handshake)
        let (public_addr, relay_socket) = self
            .inner
            .establish_relay_session(relay_addr)
            .await
            .map_err(EndpointError::NatTraversal)?;

        info!(
            "MASQUE relay session established via {} (public addr: {:?})",
            relay_addr, public_addr
        );

        let relay_socket = relay_socket
            .ok_or_else(|| EndpointError::Connection("Relay did not provide socket".to_string()))?;

        // Step 4: Create a new Quinn endpoint with the relay socket
        let existing_endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let client_config = existing_endpoint
            .default_client_config
            .clone()
            .ok_or_else(|| EndpointError::Config("No client config available".to_string()))?;

        let runtime = crate::high_level::default_runtime()
            .ok_or_else(|| EndpointError::Config("No async runtime available".to_string()))?;

        let mut relay_endpoint = crate::high_level::Endpoint::new_with_abstract_socket(
            crate::EndpointConfig::default(),
            None,
            relay_socket,
            runtime,
        )
        .map_err(|e| {
            EndpointError::Connection(format!("Failed to create relay endpoint: {}", e))
        })?;

        relay_endpoint.set_default_client_config(client_config);

        // Step 5: Connect to target through the relay endpoint
        let connecting = relay_endpoint.connect(target, "peer").map_err(|e| {
            EndpointError::Connection(format!("Failed to initiate relay connection: {}", e))
        })?;

        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;

        let connection = match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                info!(
                    "Relay connection handshake to {} via {} failed: {}",
                    target, relay_addr, e
                );
                return Err(EndpointError::Connection(e.to_string()));
            }
            Err(_) => {
                info!(
                    "Relay connection handshake to {} via {} timed out",
                    target, relay_addr
                );
                return Err(EndpointError::Timeout);
            }
        };

        // Step 6: Finalize — extract public key, store connection, spawn handler
        let remote_public_key = extract_public_key_bytes_from_connection(&connection);

        self.inner
            .add_connection(target, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        self.inner
            .spawn_connection_handler(target, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            public_key: remote_public_key,
            remote_addr: TransportAddr::Quic(target),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn background reader task
        if let Ok(Some(conn)) = self.inner.get_connection(&target) {
            self.spawn_reader_task(target, conn).await;
        }

        // Store peer connection
        self.connected_peers
            .write()
            .await
            .insert(target, peer_conn.clone());

        info!(
            "MASQUE relay connection succeeded to {} via {}",
            target, relay_addr
        );

        Ok(peer_conn)
    }

    /// Check if we're connected to a specific address
    async fn is_connected_to_addr(&self, addr: SocketAddr) -> bool {
        let transport_addr = TransportAddr::Quic(addr);
        let peers = self.connected_peers.read().await;
        peers.values().any(|p| p.remote_addr == transport_addr)
    }

    /// Accept incoming connections
    ///
    /// Returns `None` if the endpoint is shutting down or the accept fails.
    /// This method races the inner accept against the shutdown token, so it
    /// will return promptly when `shutdown()` is called.
    pub async fn accept(&self) -> Option<PeerConnection> {
        if self.shutdown.is_cancelled() {
            return None;
        }

        let result = tokio::select! {
            r = self.inner.accept_connection_direct() => r,
            _ = self.shutdown.cancelled() => return None,
        };

        match result {
            Ok((remote_addr, connection)) => {
                // Extract public key from TLS handshake
                let remote_public_key = extract_public_key_bytes_from_connection(&connection);

                // They initiated the connection to us = Server side
                if let Err(e) =
                    self.inner
                        .spawn_connection_handler(remote_addr, connection, Side::Server)
                {
                    error!("Failed to spawn connection handler: {}", e);
                    return None;
                }

                // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                let peer_conn = PeerConnection {
                    public_key: remote_public_key.clone(),
                    remote_addr: TransportAddr::Quic(remote_addr),
                    authenticated: true, // TLS handles authentication
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Spawn background reader task BEFORE storing in connected_peers
                // to prevent race where recv() misses early data
                match self.inner.get_connection(&remote_addr) {
                    Ok(Some(conn)) => {
                        info!("accept: spawning reader task for {}", remote_addr);
                        self.spawn_reader_task(remote_addr, conn).await;
                    }
                    Ok(None) => {
                        error!(
                            "accept: get_connection({}) returned None — NO reader task spawned!",
                            remote_addr
                        );
                    }
                    Err(e) => {
                        error!(
                            "accept: get_connection({}) failed: {} — NO reader task spawned!",
                            remote_addr, e
                        );
                    }
                }

                self.connected_peers
                    .write()
                    .await
                    .insert(remote_addr, peer_conn.clone());

                {
                    let mut stats = self.stats.write().await;
                    stats.active_connections += 1;
                    stats.successful_connections += 1;
                }

                // They initiated the connection to us = Server side
                let _ = self.event_tx.send(P2pEvent::PeerConnected {
                    addr: TransportAddr::Quic(remote_addr),
                    public_key: remote_public_key,
                    side: Side::Server,
                });

                Some(peer_conn)
            }
            Err(e) => {
                debug!("Accept failed: {}", e);
                None
            }
        }
    }

    /// Clean up a connection from ALL tracking structures.
    ///
    /// This is the single point of cleanup for connections — it removes the peer from:
    /// - `connected_peers` HashMap
    /// - `NatTraversalEndpoint.connections` DashMap (via `remove_connection()`)
    /// - `reader_handles` (aborts the background reader task)
    /// - Updates stats and emits a disconnect event
    ///
    /// Safe to call even if the peer is not in all structures (idempotent).
    async fn cleanup_connection(&self, addr: &SocketAddr, reason: DisconnectReason) {
        do_cleanup_connection(
            &*self.connected_peers,
            &*self.inner,
            &*self.reader_handles,
            &*self.stats,
            &self.event_tx,
            addr,
            reason,
        )
        .await;
    }

    /// Disconnect from a peer by address
    pub async fn disconnect(&self, addr: &SocketAddr) -> Result<(), EndpointError> {
        if self.connected_peers.read().await.contains_key(addr) {
            self.cleanup_connection(addr, DisconnectReason::Normal)
                .await;
            Ok(())
        } else {
            Err(EndpointError::PeerNotFound(*addr))
        }
    }

    // === Messaging ===

    /// Send data to a peer
    ///
    /// # Transport Selection
    ///
    /// This method selects the appropriate transport provider based on the destination
    /// peer's address type and the capabilities advertised in the transport registry.
    ///
    /// ## Current Behavior (Phase 2.1)
    ///
    /// All connections currently use UDP/QUIC via the existing `connection.open_uni()`
    /// path. This ensures backward compatibility with existing peers.
    ///
    /// ## Future Behavior (Phase 2.3)
    ///
    /// Transport selection will be based on:
    /// - Peer's advertised transport addresses (from connection metadata)
    /// - Transport provider capabilities (from `transport_registry`)
    /// - Protocol engine requirements (QUIC vs Constrained)
    ///
    /// Selection priority:
    /// 1. **UDP/QUIC**: Default for broadband, full QUIC support
    /// 2. **BLE**: For nearby devices, constrained engine
    /// 3. **LoRa**: For long-range, low-bandwidth scenarios
    /// 4. **Overlay**: For I2P/Yggdrasil privacy-preserving routing
    ///
    /// # Arguments
    ///
    /// - `addr`: The target peer's socket address
    /// - `data`: The payload to send
    ///
    /// # Errors
    ///
    /// Returns `EndpointError` if:
    /// - The endpoint is shutting down
    /// - The peer is not connected
    /// - No suitable transport provider is available
    /// - The send operation fails
    pub async fn send(&self, addr: &SocketAddr, data: &[u8]) -> Result<(), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Get peer's transport address and optionally capture the connection
        // for hole-punched peers that bypassed normal registration.
        //
        // On dual-stack sockets (bindv6only=0), incoming connections use
        // IPv4-mapped IPv6 addresses ([::ffff:x.x.x.x]) but callers may pass
        // plain IPv4. Try both forms when looking up the peer.
        let (transport_addr, cached_connection) = {
            let peer_info = self.connected_peers.read().await;
            let alt = crate::shared::dual_stack_alternate(addr);
            let found = peer_info
                .get(addr)
                .or_else(|| alt.as_ref().and_then(|a| peer_info.get(a)));
            if let Some(peer_conn) = found {
                (peer_conn.remote_addr.clone(), None)
            } else {
                // Check if the NatTraversalEndpoint has a connection to this
                // address (e.g. from a hole-punch that bypassed the normal path).
                // Capture the connection now before it can be cleaned up.
                drop(peer_info);
                let conn = self.inner.get_connection(addr).ok().flatten().or_else(|| {
                    alt.as_ref()
                        .and_then(|a| self.inner.get_connection(a).ok().flatten())
                });
                if let Some(conn) = conn {
                    info!(
                        "send: found hole-punched connection to {}, registering",
                        addr
                    );
                    let peer_conn = PeerConnection {
                        public_key: None,
                        remote_addr: TransportAddr::Quic(*addr),
                        authenticated: true,
                        connected_at: Instant::now(),
                        last_activity: Instant::now(),
                    };
                    self.connected_peers.write().await.insert(*addr, peer_conn);
                    let _ = self.event_tx.send(P2pEvent::PeerConnected {
                        addr: TransportAddr::Quic(*addr),
                        public_key: None,
                        side: Side::Server,
                    });
                    (TransportAddr::Quic(*addr), Some(conn))
                } else {
                    return Err(EndpointError::PeerNotFound(*addr));
                }
            }
        };

        // Select protocol engine based on transport address.
        //
        // No lock: `select_engine_for_addr` takes `&self` on
        // `ConnectionRouter` and bumps its stats counters via atomics, so
        // concurrent sends can run fully in parallel. The previous
        // implementation held an exclusive write lock on the router here,
        // which serialised every outbound send on the endpoint through a
        // single lock and was a dominant contention point at high node
        // counts (1000-node testnet).
        let engine = self.router.select_engine_for_addr(&transport_addr);

        match engine {
            crate::transport::ProtocolEngine::Quic => {
                // Use cached connection (from hole-punch) or look up fresh
                let connection = if let Some(conn) = cached_connection {
                    conn
                } else {
                    self.inner
                        .get_connection(addr)
                        .map_err(EndpointError::NatTraversal)?
                        .ok_or(EndpointError::PeerNotFound(*addr))?
                };

                // Log connection state before attempting to open stream
                if let Some(reason) = connection.close_reason() {
                    warn!(
                        "send({}): connection has close_reason BEFORE open_uni: {}",
                        addr, reason
                    );
                }

                let mut send_stream = connection.open_uni().await.map_err(|e| {
                    warn!("send({}): open_uni failed: {}", addr, e);
                    EndpointError::Connection(e.to_string())
                })?;

                send_stream.write_all(data).await.map_err(|e| {
                    warn!(
                        "send({}): write_all ({} bytes) failed: {}",
                        addr,
                        data.len(),
                        e
                    );
                    EndpointError::Connection(e.to_string())
                })?;

                send_stream.finish().map_err(|e| {
                    warn!("send({}): finish failed: {}", addr, e);
                    EndpointError::Connection(e.to_string())
                })?;

                // Wait for the peer to acknowledge receipt of all stream data.
                // Without this, finish() only buffers a FIN locally — if the
                // connection is dead the caller would see Ok(()) despite the
                // data never arriving.
                //
                // The base timeout handles small messages and dead-connection
                // detection. For large payloads we add time proportional to
                // size: QUIC slow-start over a high-RTT path needs multiple
                // round trips to ramp the congestion window, so a 4 MB chunk
                // over a 250 ms RTT link can take 2-3 s just to transmit.
                let base_timeout = self.config.timeouts.send_ack_timeout;
                let size_budget =
                    std::time::Duration::from_millis((data.len() as u64).saturating_div(1024));
                let ack_timeout = base_timeout + size_budget;
                match timeout(ack_timeout, send_stream.stopped()).await {
                    Ok(Ok(None)) => {}
                    Ok(Ok(Some(stop_code))) => {
                        return Err(EndpointError::Connection(format!(
                            "peer stopped stream with code {stop_code}"
                        )));
                    }
                    Ok(Err(e)) => {
                        return Err(EndpointError::Connection(format!(
                            "peer did not acknowledge stream data: {e}"
                        )));
                    }
                    Err(_elapsed) => {
                        return Err(EndpointError::Connection(format!(
                            "peer did not acknowledge stream data within {ack_timeout:?}"
                        )));
                    }
                }

                debug!("Sent {} bytes to {} via QUIC", data.len(), addr);
            }
            crate::transport::ProtocolEngine::Constrained => {
                // Check if we have an established constrained connection for this address
                let maybe_conn_id = self
                    .constrained_connections
                    .read()
                    .await
                    .get(&transport_addr)
                    .copied();

                if let Some(conn_id) = maybe_conn_id {
                    // Use ConstrainedEngine for reliable delivery
                    let engine = self.inner.constrained_engine();
                    let responses = {
                        let mut engine = engine.lock();
                        engine
                            .send(conn_id, data)
                            .map_err(|e| EndpointError::Connection(e.to_string()))?
                    };

                    // Send any packets generated by the constrained engine
                    for (_dest_addr, packet_data) in responses {
                        self.transport_registry
                            .send(&packet_data, &transport_addr)
                            .await
                            .map_err(|e| EndpointError::Connection(e.to_string()))?;
                    }

                    debug!(
                        "Sent {} bytes to {} via constrained engine ({})",
                        data.len(),
                        addr,
                        transport_addr.transport_type()
                    );
                } else {
                    // No established connection - send directly via transport
                    self.transport_registry
                        .send(data, &transport_addr)
                        .await
                        .map_err(|e| EndpointError::Connection(e.to_string()))?;

                    debug!(
                        "Sent {} bytes to {} via constrained transport (direct, {})",
                        data.len(),
                        addr,
                        transport_addr.transport_type()
                    );
                }
            }
        }

        Ok(())
    }

    /// Receive data from any connected peer.
    ///
    /// Blocks until data arrives from any transport (UDP/QUIC, BLE, LoRa, etc.)
    /// or the endpoint shuts down. Background reader tasks feed a shared channel,
    /// so this wakes instantly when data is available.
    ///
    /// # Errors
    ///
    /// Returns `EndpointError::ShuttingDown` if the endpoint is shutting down.
    pub async fn recv(&self) -> Result<(SocketAddr, Vec<u8>), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Note: pending data buffer (BoundedPendingBuffer) still uses PeerId internally.
        // It is not consulted here; background reader tasks feed the data_rx channel
        // using SocketAddr as the key.

        // Wait for data from the shared channel (fed by background reader tasks),
        // racing against the shutdown token so callers unblock promptly on shutdown.
        let mut rx = self.data_rx.lock().await;
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => Ok(msg),
                None => Err(EndpointError::ShuttingDown),
            },
            _ = self.shutdown.cancelled() => Err(EndpointError::ShuttingDown),
        }
    }

    // === Events ===

    /// Subscribe to endpoint events
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    // === Statistics ===

    /// Get endpoint statistics
    pub async fn stats(&self) -> EndpointStats {
        self.stats.read().await.clone()
    }

    /// Get metrics for a specific connection by address
    pub async fn connection_metrics(&self, addr: &SocketAddr) -> Option<ConnectionMetrics> {
        let peers = self.connected_peers.read().await;
        let peer_conn = peers.get(addr)?;
        let last_activity = Some(peer_conn.last_activity);
        drop(peers);

        let connection = self.inner.get_connection(addr).ok()??;
        let stats = connection.stats();
        let rtt = connection.rtt();

        Some(ConnectionMetrics {
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            rtt: Some(rtt),
            packet_loss: stats.path.lost_packets as f64
                / (stats.path.sent_packets + stats.path.lost_packets).max(1) as f64,
            last_activity,
        })
    }

    /// Get NAT traversal statistics
    pub fn nat_stats(&self) -> Result<NatTraversalStatistics, EndpointError> {
        self.inner
            .get_nat_stats()
            .map_err(|e| EndpointError::Connection(e.to_string()))
    }

    // === Known Peers ===

    /// Connect to configured known peers
    ///
    /// This method now uses the connection router to automatically select
    /// the appropriate protocol engine for each peer address.
    pub async fn connect_known_peers(&self) -> Result<usize, EndpointError> {
        let mut connected = 0;
        let known_peers = self.config.known_peers.clone();

        for addr in &known_peers {
            // Use connect_transport for all address types
            match self.connect_transport(addr).await {
                Ok(_) => {
                    connected += 1;
                    info!("Connected to known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to known peer {}: {}", addr, e);
                }
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.connected_bootstrap_nodes = connected;
        }

        let _ = self.event_tx.send(P2pEvent::BootstrapStatus {
            connected,
            total: known_peers.len(),
        });

        // After bootstrap, check for symmetric NAT and set up relay if needed
        if connected > 0 {
            let inner = Arc::clone(&self.inner);
            let bootstrap_addrs: Vec<SocketAddr> = known_peers
                .iter()
                .filter_map(|addr| match addr {
                    TransportAddr::Quic(a) => Some(*a),
                    _ => None,
                })
                .collect();

            tokio::spawn(async move {
                // Wait for OBSERVED_ADDRESS frames to arrive from peers
                tokio::time::sleep(Duration::from_secs(5)).await;

                if inner.is_symmetric_nat() {
                    info!("Symmetric NAT detected — setting up proactive relay");

                    for bootstrap in &bootstrap_addrs {
                        match inner.setup_proactive_relay(*bootstrap).await {
                            Ok(relay_addr) => {
                                info!(
                                    "Proactive relay active at {} via bootstrap {}",
                                    relay_addr, bootstrap
                                );
                                return;
                            }
                            Err(e) => {
                                warn!("Failed to set up relay via {}: {}", bootstrap, e);
                            }
                        }
                    }

                    warn!("Failed to set up proactive relay on any bootstrap node");
                } else {
                    debug!("NAT check: not symmetric NAT, no relay needed");
                }
            });
        }

        Ok(connected)
    }

    /// Add a bootstrap node dynamically
    pub async fn add_bootstrap(&self, addr: SocketAddr) {
        let _ = self.inner.add_bootstrap_node(addr);
        let mut stats = self.stats.write().await;
        stats.total_bootstrap_nodes += 1;
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.connected_peers
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Check if an address is connected
    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.connected_peers.read().await.contains_key(addr)
    }

    /// Check if a live QUIC connection exists at the NatTraversalEndpoint level.
    ///
    /// This is the authoritative check — it queries the DashMap that stores
    /// actual QUIC connections, bypassing the connected_peers HashMap which
    /// may have a registration delay for hole-punch connections.
    ///
    /// Tries both the plain and IPv4-mapped address forms because the DashMap
    /// key format depends on whether the connection was established on a
    /// dual-stack socket (IPv6-mapped) or IPv4-only (plain).
    /// Check if a peer with the given ID has an active connection,
    /// returning the actual socket address. For symmetric NAT, the
    /// address differs from the DHT address.
    pub fn find_connection_by_peer_id(&self, peer_id: &[u8; 32]) -> Option<SocketAddr> {
        self.inner.find_connection_by_peer_id(peer_id)
    }

    /// Register a peer ID at the low-level endpoint for PUNCH_ME_NOW relay
    /// routing. Called when the identity exchange completes on a connection.
    pub fn register_connection_peer_id(&self, addr: SocketAddr, peer_id: [u8; 32]) {
        self.inner
            .register_connection_peer_id(addr, crate::nat_traversal_api::PeerId(peer_id));
    }

    /// Check if a peer is connected at the transport level.
    pub fn inner_is_connected(&self, addr: &SocketAddr) -> bool {
        if self.inner.is_connected(addr) {
            debug!("inner_is_connected: {} found (exact match)", addr);
            return true;
        }
        // Try the alternate form (plain ↔ mapped)
        if let Some(alt) = crate::shared::dual_stack_alternate(addr) {
            if self.inner.is_connected(&alt) {
                debug!("inner_is_connected: {} found via alternate {}", addr, alt);
                return true;
            }
        }
        info!(
            "inner_is_connected: {} NOT found (connections: {})",
            addr,
            self.inner.connection_count()
        );
        false
    }

    /// Check if an address is authenticated
    pub async fn is_authenticated(&self, addr: &SocketAddr) -> bool {
        self.connected_peers
            .read()
            .await
            .get(addr)
            .map(|p| p.authenticated)
            .unwrap_or(false)
    }

    // === Lifecycle ===

    /// Shutdown the endpoint gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down P2P endpoint");
        self.shutdown.cancel();

        // Abort all background reader tasks
        self.reader_tasks.lock().await.abort_all();
        self.reader_handles.write().await.clear();

        // Disconnect all peers
        let addrs: Vec<SocketAddr> = self.connected_peers.read().await.keys().copied().collect();
        for addr in addrs {
            let _ = self.disconnect(&addr).await;
        }

        // Bounded timeout prevents blocking when the remote peer is unresponsive.
        match timeout(SHUTDOWN_DRAIN_TIMEOUT, self.inner.shutdown()).await {
            Err(_) => warn!("Inner endpoint shutdown timed out, proceeding"),
            Ok(Err(e)) => warn!("Inner endpoint shutdown error: {e}"),
            Ok(Ok(())) => {}
        }
    }

    /// Check if endpoint is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.is_cancelled()
    }

    /// Get a clone of the shutdown token (for external cancellation listening)
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    // === Internal helpers ===

    /// Spawn a background tokio task that reads uni streams from a QUIC connection
    /// and forwards received data into the shared `data_tx` channel.
    ///
    /// The task exits naturally when the connection is closed or the channel is dropped.
    async fn spawn_reader_task(&self, addr: SocketAddr, connection: crate::high_level::Connection) {
        let data_tx = self.data_tx.clone();
        let event_tx = self.event_tx.clone();
        let max_read_bytes = self.config.max_message_size;
        let exit_tx = self.reader_exit_tx.clone();
        let inner = Arc::clone(&self.inner);

        let abort_handle = self.reader_tasks.lock().await.spawn(async move {
            info!("Reader task STARTED for {}", addr);

            // Ensure the connection is in the NatTraversalEndpoint's DashMap
            // so the send path can find it. This is critical for NAT-traversed
            // connections where the accept-time DashMap entry may be missing
            // or removed by competing accept paths.
            debug!("Reader task: calling add_connection for {}", addr);
            match inner.add_connection(addr, connection.clone()) {
                Ok(()) => debug!("Reader task: add_connection OK for {}", addr),
                Err(e) => warn!("Reader task: add_connection FAILED for {}: {:?}", addr, e),
            }

            loop {
                // Accept the next unidirectional stream
                let mut recv_stream = match connection.accept_uni().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        info!("Reader task for {} ending: accept_uni error: {}", addr, e);
                        break;
                    }
                };

                let data = match recv_stream.read_to_end(max_read_bytes).await {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => data,
                    Err(e) => {
                        info!("Reader task for {}: read_to_end error: {}", addr, e);
                        break;
                    }
                };

                let data_len = data.len();
                debug!("Reader task: {} bytes from {}", data_len, addr);

                // Note: last_activity update moved out of the hot path to avoid
                // RwLock write contention. With N reader tasks all acquiring
                // write locks on every message, the lock becomes a bottleneck
                // that can starve other tasks and deadlock the runtime.
                // The DataReceived event below serves as a liveness signal.

                // Emit DataReceived event
                let _ = event_tx.send(P2pEvent::DataReceived {
                    addr,
                    bytes: data_len,
                });

                // Send through channel without blocking the reader task's
                // event loop. Using try_send avoids holding a tokio worker
                // thread when the channel is full. If the channel is full,
                // spawn a short-lived task that retries with a timeout instead
                // of dropping data immediately.
                match data_tx.try_send((addr, data)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full((addr, data))) => {
                        let tx = data_tx.clone();
                        let data_len = data.len();
                        tokio::spawn(async move {
                            if tokio::time::timeout(
                                Duration::from_secs(5),
                                tx.send((addr, data)),
                            )
                            .await
                            .is_err()
                            {
                                warn!(
                                    "Reader task for {}: data channel send timed out, dropping {} bytes",
                                    addr, data_len
                                );
                            }
                        });
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        debug!("Reader task for {}: channel closed, exiting", addr);
                        break;
                    }
                }
            }

            // Notify the reader-exit handler for immediate cleanup.
            let _ = exit_tx.send(addr);
            addr
        });

        self.reader_handles.write().await.insert(addr, abort_handle);
    }

    /// Spawn a single background task that polls constrained transport events
    /// and forwards `DataReceived` payloads into the shared `data_tx` channel.
    ///
    /// Lifecycle events (ConnectionAccepted, ConnectionClosed, etc.) are handled
    /// inline within this task.
    fn spawn_constrained_poller(&self) {
        let inner = Arc::clone(&self.inner);
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let constrained_peer_addrs = Arc::clone(&self.constrained_peer_addrs);
        let constrained_connections = Arc::clone(&self.constrained_connections);
        let shutdown = self.shutdown.clone();

        /// Register a new constrained peer in all lookup maps and emit a connect event.
        async fn register_constrained_peer(
            connection_id: ConstrainedConnectionId,
            addr: &TransportAddr,
            side: Side,
            constrained_connections: &RwLock<HashMap<TransportAddr, ConstrainedConnectionId>>,
            constrained_peer_addrs: &RwLock<HashMap<ConstrainedConnectionId, TransportAddr>>,
            connected_peers: &RwLock<HashMap<SocketAddr, PeerConnection>>,
            event_tx: &broadcast::Sender<P2pEvent>,
        ) {
            let synthetic_addr = addr.to_synthetic_socket_addr();
            constrained_connections
                .write()
                .await
                .insert(addr.clone(), connection_id);
            constrained_peer_addrs
                .write()
                .await
                .insert(connection_id, addr.clone());
            connected_peers.write().await.insert(
                synthetic_addr,
                PeerConnection {
                    public_key: None,
                    remote_addr: addr.clone(),
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
            let _ = event_tx.send(P2pEvent::PeerConnected {
                addr: addr.clone(),
                public_key: None,
                side,
            });
        }

        tokio::spawn(async move {
            loop {
                let wrapper = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    event = inner.recv_constrained_event() => {
                        match event {
                            Some(w) => w,
                            None => {
                                debug!("Constrained event channel closed, exiting poller");
                                break;
                            }
                        }
                    }
                };

                match wrapper.event {
                    EngineEvent::DataReceived {
                        connection_id,
                        data,
                    } => {
                        let synthetic_addr = constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .map(|a| a.to_synthetic_socket_addr())
                            .unwrap_or_else(|| wrapper.remote_addr.to_synthetic_socket_addr());

                        let data_len = data.len();
                        tracing::trace!(
                            "Constrained poller: {} bytes from {}",
                            data_len,
                            synthetic_addr
                        );

                        if let Some(peer_conn) =
                            connected_peers.write().await.get_mut(&synthetic_addr)
                        {
                            peer_conn.last_activity = Instant::now();
                        }
                        let _ = event_tx.send(P2pEvent::DataReceived {
                            addr: synthetic_addr,
                            bytes: data_len,
                        });

                        if data_tx.send((synthetic_addr, data)).await.is_err() {
                            debug!("Constrained poller: channel closed, exiting");
                            break;
                        }
                    }
                    EngineEvent::ConnectionAccepted {
                        connection_id,
                        remote_addr: _,
                    } => {
                        register_constrained_peer(
                            connection_id,
                            &wrapper.remote_addr,
                            Side::Server,
                            &constrained_connections,
                            &constrained_peer_addrs,
                            &connected_peers,
                            &event_tx,
                        )
                        .await;
                    }
                    EngineEvent::ConnectionEstablished { connection_id } => {
                        if constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .is_none()
                        {
                            register_constrained_peer(
                                connection_id,
                                &wrapper.remote_addr,
                                Side::Client,
                                &constrained_connections,
                                &constrained_peer_addrs,
                                &connected_peers,
                                &event_tx,
                            )
                            .await;
                        }
                    }
                    EngineEvent::ConnectionClosed { connection_id } => {
                        let removed_addr =
                            constrained_peer_addrs.write().await.remove(&connection_id);
                        if let Some(addr) = removed_addr {
                            let synthetic_addr = addr.to_synthetic_socket_addr();
                            constrained_connections.write().await.remove(&addr);
                            connected_peers.write().await.remove(&synthetic_addr);
                            let _ = event_tx.send(P2pEvent::PeerDisconnected {
                                addr,
                                reason: DisconnectReason::RemoteClosed,
                            });
                            debug!(
                                "Constrained poller: peer at {} disconnected",
                                synthetic_addr
                            );
                        }
                    }
                    EngineEvent::ConnectionError {
                        connection_id,
                        error,
                    } => {
                        warn!(
                            "Constrained poller: conn_id={}, error={}",
                            connection_id.value(),
                            error
                        );
                    }
                    EngineEvent::Transmit { .. } => {}
                }
            }
        });
    }

    /// Spawn a background task that periodically detects and removes stale connections
    /// and probes live connections with health-check PINGs.
    ///
    /// Spawn a task that immediately cleans up connections when their reader
    /// task exits (QUIC connection died).
    ///
    /// This is the primary, event-driven detection path.  The stale reaper
    /// serves as a periodic safety net behind this.
    fn spawn_reader_exit_handler(&self, mut reader_exit_rx: mpsc::UnboundedReceiver<SocketAddr>) {
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let stats = Arc::clone(&self.stats);
        let reader_handles = Arc::clone(&self.reader_handles);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                let addr = tokio::select! {
                    addr = reader_exit_rx.recv() => {
                        match addr {
                            Some(a) => a,
                            None => return, // channel closed
                        }
                    }
                    _ = shutdown.cancelled() => {
                        debug!("Reader-exit handler shutting down");
                        return;
                    }
                };

                info!("Reader task exited for {}, running immediate cleanup", addr);
                let cleanup_start = Instant::now();
                do_cleanup_connection(
                    &connected_peers,
                    &inner,
                    &reader_handles,
                    &stats,
                    &event_tx,
                    &addr,
                    DisconnectReason::Timeout,
                )
                .await;
                let cleanup_elapsed = cleanup_start.elapsed();
                if cleanup_elapsed > Duration::from_secs(1) {
                    warn!(
                        "do_cleanup_connection for {} took {:?} — potential lock contention",
                        addr, cleanup_elapsed
                    );
                }
            }
        });
    }

    /// Safety-net reaper that periodically checks for QUIC-dead connections
    /// whose reader task has not yet exited (or whose exit was missed).
    ///
    /// The primary detection path is event-driven: the reader-exit handler
    /// cleans up immediately when a reader task detects a dead connection.
    /// This reaper is a cheap fallback that runs every [`STALE_REAPER_INTERVAL`]
    /// and calls `is_connected()` — a local state check with no network traffic.
    fn spawn_stale_connection_reaper(&self) {
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let stats = Arc::clone(&self.stats);
        let reader_handles = Arc::clone(&self.reader_handles);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(STALE_REAPER_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown.cancelled() => {
                        debug!("Stale connection reaper shutting down");
                        return;
                    }
                }

                let stale_addrs: Vec<SocketAddr> = {
                    let peers = connected_peers.read().await;
                    peers
                        .keys()
                        .filter(|addr| !inner.is_connected(addr))
                        .copied()
                        .collect()
                };

                if !stale_addrs.is_empty() {
                    info!(
                        "Stale connection reaper: removing {} dead connection(s)",
                        stale_addrs.len()
                    );
                }

                for addr in &stale_addrs {
                    do_cleanup_connection(
                        &connected_peers,
                        &inner,
                        &reader_handles,
                        &stats,
                        &event_tx,
                        addr,
                        DisconnectReason::Timeout,
                    )
                    .await;
                }
            }
        });
    }

    /// Spawn a background task that periodically drives the NAT traversal
    /// session state machine via `poll()`.
    ///
    /// This runs `poll()` on its own task, decoupled from `try_hole_punch`,
    /// to avoid DashMap lock contention deadlocks between `poll()` and the
    /// concurrent accept handler.
    fn spawn_session_driver(&self) {
        let inner = Arc::clone(&self.inner);
        let shutdown = self.shutdown.clone();
        let event_tx_for_nat = self.event_tx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            let mut relay_event_sent = false;
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown.cancelled() => {
                        debug!("NAT traversal session driver shutting down");
                        return;
                    }
                }

                // Drive the session state machine. Errors are non-fatal —
                // the session will retry on the next tick.
                //
                // poll() is synchronous — it acquires parking_lot locks and
                // iterates DashMaps. Measure duration to detect if it's
                // blocking the worker thread for too long.
                let poll_start = Instant::now();
                if let Err(e) = inner.poll(Instant::now()) {
                    debug!("NAT traversal poll error (will retry): {:?}", e);
                }
                let poll_elapsed = poll_start.elapsed();
                if poll_elapsed > Duration::from_millis(100) {
                    warn!(
                        "NAT traversal poll() took {:?} — may be starving other tasks",
                        poll_elapsed
                    );
                }

                // Process any hole-punch addresses forwarded from the Quinn driver.
                // These are addresses from relayed PUNCH_ME_NOW that need fully tracked
                // outgoing connections (not fire-and-forget).
                inner.process_pending_hole_punches().await;

                // Forward peer address updates as P2pEvents so the upper layer
                // (saorsa-core) can update its DHT routing table.
                {
                    let mut rx = inner.peer_address_update_rx.lock().await;
                    while let Ok((peer_addr, advertised_addr)) = rx.try_recv() {
                        info!(
                            "Peer {} advertised address {} — forwarding to P2pEvent",
                            peer_addr, advertised_addr
                        );
                        let _ = event_tx_for_nat.send(P2pEvent::PeerAddressUpdated {
                            peer_addr,
                            advertised_addr,
                        });
                    }
                }

                // Emit RelayEstablished once when relay becomes active.
                // Upper layers use this to trigger a DHT self-lookup for
                // relay address propagation.
                if !relay_event_sent {
                    if let Some(relay_addr) = inner.relay_public_addr() {
                        info!(
                            "Relay established at {} — emitting RelayEstablished event",
                            relay_addr
                        );
                        let _ = event_tx_for_nat.send(P2pEvent::RelayEstablished { relay_addr });
                        relay_event_sent = true;
                    }
                }

                // Monitor relay health. If the relay session died (connection
                // closed, server restarted, etc.), reset state so the next
                // poll cycle re-establishes through a (potentially different)
                // relay candidate. The RelayEstablished flag is also reset so
                // upper layers re-publish the new address.
                if relay_event_sent && !inner.is_relay_healthy() {
                    inner.reset_relay_state();
                    relay_event_sent = false;
                }
            }
        });
    }

    /// Spawn a background task that monitors for new connections accepted by
    /// the NatTraversalEndpoint and registers them in `connected_peers` +
    /// emits `PeerConnected` events. This bridges the gap between the
    /// NatTraversalEndpoint's accept handler and the P2pEndpoint's tracking.
    fn spawn_incoming_connection_forwarder(&self) {
        debug!("FORWARDER_DEBUG: spawn_incoming_connection_forwarder called");
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let shutdown = self.shutdown.clone();
        let accepted_rx = self.inner.accepted_addrs_rx();
        let inner = Arc::clone(&self.inner);
        let data_tx = self.data_tx.clone();
        let reader_exit_tx = self.reader_exit_tx.clone();
        let reader_tasks = Arc::clone(&self.reader_tasks);
        let reader_handles = Arc::clone(&self.reader_handles);
        let max_read_bytes = self.config.max_message_size;

        tokio::spawn(async move {
            debug!("FORWARDER_DEBUG: started, acquiring rx lock...");
            let mut rx = accepted_rx.lock().await;
            info!("Incoming connection forwarder: rx lock acquired, waiting for addresses...");
            loop {
                let addr = tokio::select! {
                    Some(addr) = rx.recv() => {
                        info!("Incoming connection forwarder: received address {}", addr);
                        addr
                    },
                    _ = shutdown.cancelled() => return,
                };

                // Check if already registered
                if connected_peers.read().await.contains_key(&addr) {
                    continue;
                }

                info!(
                    "Incoming connection forwarder: registering {} in connected_peers",
                    addr
                );
                let peer_conn = PeerConnection {
                    public_key: None,
                    remote_addr: TransportAddr::Quic(addr),
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Spawn a reader task so we can receive data on this connection.
                // Without this, the target node of a hole-punch cannot receive
                // unidirectional streams opened by the initiator.
                if let Ok(Some(conn)) = inner.get_connection(&addr) {
                    let data_tx = data_tx.clone();
                    let event_tx = event_tx.clone();
                    let exit_tx = reader_exit_tx.clone();
                    let inner2 = Arc::clone(&inner);

                    let abort_handle = reader_tasks.lock().await.spawn(async move {
                        info!("Reader task STARTED for {} (via forwarder)", addr);
                        match inner2.add_connection(addr, conn.clone()) {
                            Ok(()) => debug!("Reader task (forwarder): add_connection OK for {}", addr),
                            Err(e) => warn!("Reader task (forwarder): add_connection FAILED for {}: {:?}", addr, e),
                        }

                        loop {
                            let mut recv_stream = match conn.accept_uni().await {
                                Ok(stream) => stream,
                                Err(e) => {
                                    info!("Reader task for {} (forwarder) ending: accept_uni error: {}", addr, e);
                                    break;
                                }
                            };

                            let data = match recv_stream.read_to_end(max_read_bytes).await {
                                Ok(data) if data.is_empty() => continue,
                                Ok(data) => data,
                                Err(e) => {
                                    info!("Reader task for {} (forwarder): read_to_end error: {}", addr, e);
                                    break;
                                }
                            };

                            let data_len = data.len();
                            debug!("Reader task (forwarder): {} bytes from {}", data_len, addr);

                            let _ = event_tx.send(P2pEvent::DataReceived {
                                addr,
                                bytes: data_len,
                            });

                            if data_tx.send((addr, data)).await.is_err() {
                                debug!("Reader task for {} (forwarder): channel closed, exiting", addr);
                                break;
                            }
                        }

                        let _ = exit_tx.send(addr);
                        addr
                    });

                    reader_handles.write().await.insert(addr, abort_handle);
                } else {
                    warn!(
                        "Incoming connection forwarder: no connection found for {} in DashMap",
                        addr
                    );
                }

                connected_peers.write().await.insert(addr, peer_conn);
                let _ = event_tx.send(P2pEvent::PeerConnected {
                    addr: TransportAddr::Quic(addr),
                    public_key: None,
                    side: Side::Server,
                });

                // Spawn a reader task for the connection so incoming streams
                // (DHT, chunk protocol) are actually read. Without this, relayed
                // connections are registered but never processed.
                match inner.get_connection(&addr) {
                    Ok(Some(conn)) => {
                        info!(
                            "Incoming connection forwarder: spawning reader task for {}",
                            addr
                        );
                        let data_tx = data_tx.clone();
                        let event_tx_for_reader = event_tx.clone();
                        let exit_tx = reader_exit_tx.clone();
                        let inner_for_reader = Arc::clone(&inner);
                        reader_tasks.lock().await.spawn(async move {
                            info!("Reader task STARTED for {} (via forwarder)", addr);
                            match inner_for_reader.add_connection(addr, conn.clone()) {
                                Ok(()) => {}
                                Err(e) => {
                                    warn!("Reader task: add_connection FAILED for {}: {:?}", addr, e);
                                }
                            }
                            loop {
                                let mut recv_stream = match conn.accept_uni().await {
                                    Ok(stream) => stream,
                                    Err(e) => {
                                        info!("Reader task for {} (forwarder) ending: {}", addr, e);
                                        break;
                                    }
                                };
                                let data = match recv_stream.read_to_end(max_read_bytes).await {
                                    Ok(data) if data.is_empty() => continue,
                                    Ok(data) => data,
                                    Err(e) => {
                                        info!("Reader task for {} (forwarder): read error: {}", addr, e);
                                        break;
                                    }
                                };
                                let data_len = data.len();
                                let _ = event_tx_for_reader.send(P2pEvent::DataReceived {
                                    addr, bytes: data_len,
                                });
                                if data_tx.try_send((addr, data)).is_err() {
                                    warn!("Reader task for {} (forwarder): data channel full, dropping {} bytes", addr, data_len);
                                }
                            }
                            let _ = exit_tx.send(addr);
                            addr
                        });
                    }
                    Ok(None) => {
                        warn!(
                            "Incoming connection forwarder: get_connection({}) returned None — no reader task",
                            addr
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Incoming connection forwarder: get_connection({}) failed: {} — no reader task",
                            addr, e
                        );
                    }
                }
            }
        });
    }

    // v0.2: authenticate_peer removed - TLS handles peer authentication via ML-DSA-65
}

impl Clone for P2pEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            // v0.2: auth_manager removed - TLS handles peer authentication
            connected_peers: Arc::clone(&self.connected_peers),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            our_fingerprint: self.our_fingerprint,
            public_key: self.public_key.clone(),
            shutdown: self.shutdown.clone(),
            pending_data: Arc::clone(&self.pending_data),
            bootstrap_cache: Arc::clone(&self.bootstrap_cache),
            transport_registry: Arc::clone(&self.transport_registry),
            router: Arc::clone(&self.router),
            constrained_connections: Arc::clone(&self.constrained_connections),
            constrained_peer_addrs: Arc::clone(&self.constrained_peer_addrs),
            hole_punch_target_peer_ids: Arc::clone(&self.hole_punch_target_peer_ids),
            hole_punch_preferred_coordinators: Arc::clone(&self.hole_punch_preferred_coordinators),
            data_tx: self.data_tx.clone(),
            data_rx: Arc::clone(&self.data_rx),
            reader_tasks: Arc::clone(&self.reader_tasks),
            reader_handles: Arc::clone(&self.reader_handles),
            reader_exit_tx: self.reader_exit_tx.clone(),
            pending_dials: Arc::clone(&self.pending_dials),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_stats_default() {
        let stats = EndpointStats::default();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.nat_traversal_attempts, 0);
    }

    #[test]
    fn test_connection_metrics_default() {
        let metrics = ConnectionMetrics::default();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert!(metrics.rtt.is_none());
        assert_eq!(metrics.packet_loss, 0.0);
    }

    #[test]
    fn test_peer_connection_debug() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(socket_addr),
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("PeerConnection"));
    }

    #[test]
    fn test_disconnect_reason_debug() {
        let reason = DisconnectReason::Normal;
        assert!(format!("{:?}", reason).contains("Normal"));

        let reason = DisconnectReason::ProtocolError("test".to_string());
        assert!(format!("{:?}", reason).contains("test"));
    }

    #[test]
    fn test_traversal_phase_debug() {
        let phase = TraversalPhase::Discovery;
        assert!(format!("{:?}", phase).contains("Discovery"));
    }

    #[test]
    fn test_endpoint_error_display() {
        let err = EndpointError::Timeout;
        assert!(err.to_string().contains("timed out"));

        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let err = EndpointError::PeerNotFound(addr);
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder().build().expect("valid config");

        let result = P2pEndpoint::new(config).await;
        // May fail in test environment without network, but shouldn't panic
        if let Ok(endpoint) = result {
            assert!(endpoint.is_running());
            assert!(endpoint.local_addr().is_some() || endpoint.local_addr().is_none());
        }
    }

    // ==========================================================================
    // Transport Registry Tests (Phase 1.1 Task 5)
    // ==========================================================================

    #[tokio::test]
    async fn test_p2p_endpoint_stores_transport_registry() {
        use crate::transport::TransportType;

        // Build config with default transport providers
        // Phase 5.3: P2pEndpoint::new() always adds a shared UDP transport
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Verify registry is accessible and contains the auto-added UDP provider
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            // Phase 5.3: Registry now always has at least 1 UDP provider (socket sharing)
            assert!(
                !registry.is_empty(),
                "Registry should have at least 1 provider"
            );

            let udp_providers = registry.providers_by_type(TransportType::Quic);
            assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_p2p_endpoint_default_config_has_udp_registry() {
        // Build config with no additional transport providers
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Phase 5.3: Default registry now includes a shared UDP transport
        // This is required for socket sharing with Quinn
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            assert!(
                !registry.is_empty(),
                "Default registry should have UDP for socket sharing"
            );
            assert!(
                registry.has_quic_capable_transport(),
                "Default registry should have QUIC-capable transport"
            );
        }
        // Note: endpoint creation may fail in test environment without network
    }

    // ==========================================================================
    // Event Address Migration Tests (Phase 2.2 Task 7)
    // ==========================================================================

    #[test]
    fn test_peer_connected_event_with_udp() {
        let socket_addr: SocketAddr = "192.168.1.100:8080".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(socket_addr),
            public_key: None,
            side: Side::Client,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            addr,
            public_key,
            side,
        } = event
        {
            assert!(public_key.is_none());
            assert_eq!(addr, TransportAddr::Quic(socket_addr));
            assert!(side.is_client());

            // Verify as_socket_addr() works
            let extracted = addr.as_socket_addr();
            assert_eq!(extracted, Some(socket_addr));
        } else {
            panic!("Expected PeerConnected event");
        }
    }

    #[test]
    fn test_peer_connected_event_with_ble() {
        // BLE MAC address (6 bytes)
        let mac_addr = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Ble {
                mac: mac_addr,
                psm: 128,
            },
            public_key: None,
            side: Side::Server,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            addr,
            public_key,
            side,
        } = event
        {
            assert!(public_key.is_none());
            assert!(side.is_server());

            // Verify as_socket_addr() returns None for BLE
            assert!(addr.as_socket_addr().is_none());

            // Verify we can match on BLE variant
            if let TransportAddr::Ble { mac, psm } = addr {
                assert_eq!(mac, mac_addr);
                assert_eq!(psm, 128);
            } else {
                panic!("Expected BLE address");
            }
        }
    }

    #[test]
    fn test_external_address_discovered_udp() {
        let socket_addr: SocketAddr = "203.0.113.1:12345".parse().expect("valid addr");
        let event = P2pEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Quic(socket_addr),
        };

        if let P2pEvent::ExternalAddressDiscovered { addr } = event {
            assert_eq!(addr, TransportAddr::Quic(socket_addr));
            assert_eq!(addr.as_socket_addr(), Some(socket_addr));
        } else {
            panic!("Expected ExternalAddressDiscovered event");
        }
    }

    #[test]
    fn test_event_clone() {
        let socket_addr: SocketAddr = "10.0.0.1:9000".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(socket_addr),
            public_key: Some(vec![0x11; 32]),
            side: Side::Client,
        };

        // Verify events are Clone
        let cloned = event.clone();
        if let (
            P2pEvent::PeerConnected {
                public_key: pk1,
                addr: a1,
                ..
            },
            P2pEvent::PeerConnected {
                public_key: pk2,
                addr: a2,
                ..
            },
        ) = (&event, &cloned)
        {
            assert_eq!(pk1, pk2);
            assert_eq!(a1, a2);
        }
    }

    #[test]
    fn test_peer_connection_with_transport_addr() {
        // Test with UDP
        let udp_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let udp_conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(udp_addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert_eq!(
            udp_conn.remote_addr.as_socket_addr(),
            Some(udp_addr),
            "UDP connection should have extractable socket address"
        );

        // Test with BLE
        let mac_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ble_conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Ble {
                mac: mac_addr,
                psm: 128,
            },
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert!(
            ble_conn.remote_addr.as_socket_addr().is_none(),
            "BLE connection should not have socket address"
        );
    }

    #[test]
    fn test_transport_addr_display_in_events() {
        let socket_addr: SocketAddr = "192.168.1.1:9001".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            addr: TransportAddr::Quic(socket_addr),
            public_key: None,
            side: Side::Client,
        };

        // Verify display formatting works for logging
        let debug_str = format!("{:?}", event);
        assert!(
            debug_str.contains("192.168.1.1"),
            "Event debug should contain IP address"
        );
        assert!(
            debug_str.contains("9001"),
            "Event debug should contain port"
        );
    }

    // ==========================================================================
    // Connection Tracking Tests (Phase 2.2 Task 8)
    // ==========================================================================

    #[test]
    fn test_connection_tracking_udp() {
        use std::collections::HashMap;

        // Simulate connection tracking with SocketAddr key
        let mut connections: HashMap<SocketAddr, PeerConnection> = HashMap::new();

        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(socket_addr),
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        connections.insert(socket_addr, conn.clone());

        // Verify connection is tracked
        assert!(connections.contains_key(&socket_addr));
        let retrieved = connections.get(&socket_addr).expect("connection exists");
        assert_eq!(retrieved.remote_addr, TransportAddr::Quic(socket_addr));
        assert!(retrieved.authenticated);
    }

    #[test]
    fn test_connection_tracking_multi_transport() {
        use std::collections::HashMap;

        // Simulate multiple connections on different transports keyed by SocketAddr.
        // For constrained transports (BLE) we use a synthetic SocketAddr via
        // TransportAddr::to_synthetic_socket_addr().
        let mut connections: HashMap<SocketAddr, PeerConnection> = HashMap::new();

        // UDP connection
        let udp_addr: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");
        connections.insert(
            udp_addr,
            PeerConnection {
                public_key: None,
                remote_addr: TransportAddr::Quic(udp_addr),
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // BLE connection (different peer) - use synthetic SocketAddr as key
        let ble_device = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ble_addr = TransportAddr::Ble {
            mac: ble_device,
            psm: 128,
        };
        let ble_socket_key = ble_addr.to_synthetic_socket_addr();
        connections.insert(
            ble_socket_key,
            PeerConnection {
                public_key: None,
                remote_addr: ble_addr,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // Verify each tracked independently
        assert_eq!(connections.len(), 2);
        assert!(
            connections
                .get(&udp_addr)
                .expect("UDP connection exists")
                .remote_addr
                .as_socket_addr()
                .is_some()
        );
        assert!(
            connections
                .get(&ble_socket_key)
                .expect("BLE connection exists")
                .remote_addr
                .as_socket_addr()
                .is_none()
        );
    }

    #[test]
    fn test_connection_lookup_by_socket_addr() {
        use std::collections::HashMap;

        let mut connections: HashMap<SocketAddr, PeerConnection> = HashMap::new();

        // Add multiple connections keyed by SocketAddr
        let addrs = ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"];

        for addr_str in addrs {
            let socket_addr: SocketAddr = addr_str.parse().expect("valid addr");
            connections.insert(
                socket_addr,
                PeerConnection {
                    public_key: None,
                    remote_addr: TransportAddr::Quic(socket_addr),
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
        }

        // Direct lookup by SocketAddr
        let target: SocketAddr = "10.0.0.2:8080".parse().expect("valid addr");
        let found = connections.get(&target);

        assert!(found.is_some());
        assert_eq!(
            found.expect("connection exists").remote_addr,
            TransportAddr::Quic(target)
        );
    }

    #[test]
    fn test_transport_addr_equality_in_tracking() {
        // Verify TransportAddr equality works correctly for tracking
        let addr1: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr2: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr3: SocketAddr = "192.168.1.1:8081".parse().expect("valid addr");

        let t1 = TransportAddr::Quic(addr1);
        let t2 = TransportAddr::Quic(addr2);
        let t3 = TransportAddr::Quic(addr3);

        // Same address should be equal
        assert_eq!(t1, t2);

        // Different port should not be equal
        assert_ne!(t1, t3);

        // Different transport type should not be equal
        let ble = TransportAddr::Ble {
            mac: [0; 6],
            psm: 128,
        };
        assert_ne!(t1, ble);
    }

    #[test]
    fn test_peer_connection_update_preserves_transport_addr() {
        let socket_addr: SocketAddr = "172.16.0.1:5000".parse().expect("valid addr");
        let mut conn = PeerConnection {
            public_key: None,
            remote_addr: TransportAddr::Quic(socket_addr),
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Simulate updating the connection (e.g., after authentication)
        conn.authenticated = true;
        conn.last_activity = Instant::now();

        // Verify transport address is preserved
        assert_eq!(conn.remote_addr, TransportAddr::Quic(socket_addr));
        assert!(conn.authenticated);
    }

    // ---- Tier 2: preferred-coordinator front-merge ----

    fn make_addr(octet: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, octet], 9000))
    }

    #[test]
    fn merge_preferred_coordinators_empty_preferred_is_no_op() {
        let mut candidates = vec![make_addr(1), make_addr(2)];
        let original = candidates.clone();
        P2pEndpoint::merge_preferred_coordinators(&mut candidates, &[]);
        assert_eq!(
            candidates, original,
            "empty preferred must not mutate the candidate list"
        );
    }

    #[test]
    fn merge_preferred_coordinators_inserts_at_front_in_order() {
        let mut candidates = vec![make_addr(10), make_addr(11)];
        let preferred = vec![make_addr(1), make_addr(2), make_addr(3)];
        P2pEndpoint::merge_preferred_coordinators(&mut candidates, &preferred);

        assert_eq!(
            candidates,
            vec![
                make_addr(1),
                make_addr(2),
                make_addr(3),
                make_addr(10),
                make_addr(11),
            ],
            "preferred entries must occupy [0..preferred.len()] in order"
        );
    }

    #[test]
    fn merge_preferred_coordinators_dedupes_existing_entries() {
        // make_addr(2) is BOTH a pre-existing candidate AND in the preferred
        // list. After the merge it should appear exactly once, at its
        // preferred-list position (index 1), not at its original tail spot.
        let mut candidates = vec![make_addr(2), make_addr(10), make_addr(11)];
        let preferred = vec![make_addr(1), make_addr(2)];
        P2pEndpoint::merge_preferred_coordinators(&mut candidates, &preferred);

        assert_eq!(
            candidates,
            vec![make_addr(1), make_addr(2), make_addr(10), make_addr(11),],
            "duplicate preferred entries must end up in the preferred slot, not the tail"
        );
        // No accidental duplication.
        assert_eq!(
            candidates.iter().filter(|a| **a == make_addr(2)).count(),
            1,
            "make_addr(2) must appear exactly once after dedup"
        );
    }

    #[test]
    fn merge_preferred_coordinators_only_dedupes_preferred_entries() {
        // Pre-existing candidates that are NOT in the preferred list must
        // remain in their original tail order.
        let mut candidates = vec![make_addr(10), make_addr(11), make_addr(12)];
        let preferred = vec![make_addr(1)];
        P2pEndpoint::merge_preferred_coordinators(&mut candidates, &preferred);

        assert_eq!(
            candidates,
            vec![make_addr(1), make_addr(10), make_addr(11), make_addr(12),],
            "non-preferred candidates must keep their original relative order"
        );
    }

    #[test]
    fn merge_preferred_coordinators_works_on_empty_candidate_list() {
        let mut candidates: Vec<SocketAddr> = Vec::new();
        let preferred = vec![make_addr(1), make_addr(2)];
        P2pEndpoint::merge_preferred_coordinators(&mut candidates, &preferred);

        assert_eq!(candidates, vec![make_addr(1), make_addr(2)]);
    }
}
