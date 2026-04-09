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

//! Network module
//!
//! This module provides core networking functionality for the P2P Foundation.
//! It handles peer connections, network events, and node lifecycle management.

use crate::PeerId;
use crate::adaptive::trust::{TrustRecord, TrustSnapshot};
use crate::adaptive::{AdaptiveDHT, AdaptiveDhtConfig, TrustEngine, TrustEvent};
use crate::bootstrap::cache::{CachedCloseGroupPeer, CloseGroupCache};
use crate::bootstrap::{BootstrapConfig, BootstrapManager};
use crate::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use crate::error::{IdentityError, NetworkError, P2PError, P2pResult as Result};

use crate::MultiAddr;
use crate::identity::node_identity::{NodeIdentity, peer_id_from_public_key};
use crate::quantum_crypto::saorsa_transport_integration::{MlDsaPublicKey, MlDsaSignature};
use parking_lot::Mutex as ParkingMutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as TokioMutex, RwLock, broadcast};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

/// Wire protocol message format for P2P communication.
///
/// Serialized with postcard for compact binary encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireMessage {
    /// Protocol/topic identifier
    pub(crate) protocol: String,
    /// Raw payload bytes
    pub(crate) data: Vec<u8>,
    /// Sender's peer ID (verified against transport-level identity)
    pub(crate) from: PeerId,
    /// Unix timestamp in seconds
    pub(crate) timestamp: u64,
    /// User agent string identifying the sender's software.
    ///
    /// Convention: `"node/<version>"` for full DHT participants,
    /// `"client/<version>"` or `"<app>/<version>"` for ephemeral clients.
    /// Included in the signed bytes — tamper-proof.
    #[serde(default)]
    pub(crate) user_agent: String,
    /// Sender's ML-DSA-65 public key (1952 bytes). Empty if unsigned.
    #[serde(default)]
    pub(crate) public_key: Vec<u8>,
    /// ML-DSA-65 signature over the signable bytes. Empty if unsigned.
    #[serde(default)]
    pub(crate) signature: Vec<u8>,
}

/// Operating mode of a P2P node.
///
/// Determines the default user agent and DHT participation behavior.
/// `Node` peers participate in the DHT routing table; `Client` peers
/// are treated as ephemeral and excluded from routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NodeMode {
    /// Full DHT-participant node that maintains routing state and routes messages.
    #[default]
    Node,
    /// Ephemeral client that connects to perform operations without joining the DHT.
    Client,
}

/// Internal listen mode controlling which network interfaces the node binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenMode {
    /// Bind to all interfaces (`0.0.0.0` / `::`).
    Public,
    /// Bind to loopback only (`127.0.0.1` / `::1`).
    Local,
}

/// Returns the default user agent string for the given mode.
///
/// - `Node` → `"node/<saorsa-core-version>"`
/// - `Client` → `"client/<saorsa-core-version>"`
pub fn user_agent_for_mode(mode: NodeMode) -> String {
    let prefix = match mode {
        NodeMode::Node => "node",
        NodeMode::Client => "client",
    };
    format!("{prefix}/{}", env!("CARGO_PKG_VERSION"))
}

/// Returns `true` if the user agent identifies a full DHT participant (prefix `"node/"`).
pub fn is_dht_participant(user_agent: &str) -> bool {
    user_agent.starts_with("node/")
}

/// Capacity of the internal channel used by the message receiving system.
pub(crate) const MESSAGE_RECV_CHANNEL_CAPACITY: usize = 256;

/// Maximum number of concurrent in-flight request/response operations.
pub(crate) const MAX_ACTIVE_REQUESTS: usize = 256;

/// Maximum allowed timeout for a single request (5 minutes).
pub(crate) const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Default listen port for the P2P node.
const DEFAULT_LISTEN_PORT: u16 = 9000;

/// Default maximum number of concurrent connections.
const DEFAULT_MAX_CONNECTIONS: usize = 10_000;

/// Default connection timeout in seconds.
///
/// Derived from the sum of connection strategy stages: direct (2s) +
/// 2 × hole-punch rounds (3s + 1s retry each) + relay (10s) = ~20s.
/// 25s provides margin for handshake jitter.
const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 25;

/// Number of cached bootstrap peers to retrieve.
const BOOTSTRAP_PEER_BATCH_SIZE: usize = 20;

/// Defensive upper bound on the wait for a bootstrap peer's
/// TLS-authenticated identity to be registered after `connect_peer`.
///
/// Since identity is now derived synchronously from the TLS-handshake
/// SPKI inside the connection lifecycle monitor, the typical wait is a
/// scheduler tick. This timeout only fires if the lifecycle monitor is
/// wedged (e.g. broadcast lag) or the peer presented an SPKI that fails
/// the saorsa-pqc parse — both cases that should be loud test failures
/// rather than silent stalls. 2 s is generous and still well below any
/// outer caller timeout, so this constant exists purely as a safety net.
const BOOTSTRAP_IDENTITY_TIMEOUT_SECS: u64 = 2;

/// Serde helper — returns `true`.
const fn default_true() -> bool {
    true
}

/// Configuration for a P2P node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Bind to loopback only (`127.0.0.1` / `::1`).
    ///
    /// When `true`, the node listens on loopback addresses suitable for
    /// local development and testing. When `false` (the default), the node
    /// listens on all interfaces (`0.0.0.0` / `::`).
    #[serde(default)]
    pub local: bool,

    /// Listen port. `0` means OS-assigned ephemeral port.
    #[serde(default)]
    pub port: u16,

    /// Enable IPv6 dual-stack binding.
    ///
    /// When `true` (the default), both an IPv4 and an IPv6 address are
    /// bound. When `false`, only IPv4 is used.
    #[serde(default = "default_true")]
    pub ipv6: bool,

    /// Bootstrap peers to connect to on startup.
    pub bootstrap_peers: Vec<crate::MultiAddr>,

    // MCP removed; will be redesigned later
    /// Connection timeout duration
    pub connection_timeout: Duration,

    /// Maximum number of concurrent connections
    pub max_connections: usize,

    /// DHT configuration
    pub dht_config: DHTConfig,

    /// Bootstrap cache configuration
    pub bootstrap_cache_config: Option<BootstrapConfig>,

    /// Optional IP diversity configuration for Sybil protection tuning.
    ///
    /// When set, this configuration is used by bootstrap peer discovery and
    /// other diversity-enforcing subsystems. If `None`, defaults are used.
    pub diversity_config: Option<crate::security::IPDiversityConfig>,

    /// Optional override for the maximum application-layer message size.
    ///
    /// When `None`, the underlying saorsa-transport default is used.
    #[serde(default)]
    pub max_message_size: Option<usize>,

    /// Optional node identity for app-level message signing.
    ///
    /// When set, outgoing messages are signed with the node's ML-DSA-65 key
    /// and incoming signed messages are verified at the transport layer.
    #[serde(skip)]
    pub node_identity: Option<Arc<NodeIdentity>>,

    /// Operating mode of this node.
    ///
    /// Determines the default user agent and DHT participation:
    /// - `Node` → user agent `"node/<version>"`, added to DHT routing tables.
    /// - `Client` → user agent `"client/<version>"`, treated as ephemeral.
    #[serde(default)]
    pub mode: NodeMode,

    /// Optional custom user agent override.
    ///
    /// When `Some`, this value is used instead of the mode-derived default.
    /// When `None`, the user agent is derived from [`NodeConfig::mode`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_user_agent: Option<String>,

    /// Allow loopback addresses (127.0.0.1, ::1) in the transport layer.
    ///
    /// In production, loopback addresses are rejected because they are not
    /// routable. Enable this for local devnets and testnets where all nodes
    /// run on the same machine.
    ///
    /// Default: `false`
    #[serde(default)]
    pub allow_loopback: bool,

    /// Adaptive DHT configuration (trust-based swap-out).
    ///
    /// Controls whether peers with low trust scores are eligible for
    /// swap-out from the routing table when better candidates arrive. Use
    /// `NodeConfigBuilder::trust_enforcement` for a simple on/off toggle.
    ///
    /// Default: enabled with a swap threshold of 0.35.
    #[serde(default)]
    pub adaptive_dht_config: AdaptiveDhtConfig,

    /// Optional path for persisting the close group cache.
    ///
    /// Directory for persisting the close group cache.
    ///
    /// When set, the node saves its close group peers and their trust
    /// scores to `{dir}/close_group_cache.json` on shutdown and after
    /// bootstrap. On startup, cached peers are loaded and contacted
    /// first, preserving close group consistency across restarts.
    ///
    /// When `None`, no close group cache is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_group_cache_dir: Option<PathBuf>,
}

/// DHT-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTConfig {
    /// Kademlia K parameter (bucket size)
    pub k_value: usize,

    /// Kademlia alpha parameter (parallelism)
    pub alpha_value: usize,

    /// DHT refresh interval
    pub refresh_interval: Duration,
}

// ============================================================================
// Address Construction Helpers
// ============================================================================

/// Build QUIC listen addresses based on port, IPv6 preference, and listen mode.
///
/// All returned addresses use the QUIC transport — the only transport
/// currently supported for dialing. When additional transports are added,
/// extend this function to produce addresses for those transports as well.
///
/// `ListenMode::Public` uses unspecified (all-interface) addresses;
/// `ListenMode::Local` uses loopback addresses.
#[inline]
fn build_listen_addrs(port: u16, ipv6_enabled: bool, mode: ListenMode) -> Vec<MultiAddr> {
    let mut addrs = Vec::with_capacity(if ipv6_enabled { 2 } else { 1 });

    let (v4, v6) = match mode {
        ListenMode::Public => (
            std::net::Ipv4Addr::UNSPECIFIED,
            std::net::Ipv6Addr::UNSPECIFIED,
        ),
        ListenMode::Local => (std::net::Ipv4Addr::LOCALHOST, std::net::Ipv6Addr::LOCALHOST),
    };

    if ipv6_enabled {
        addrs.push(MultiAddr::quic(std::net::SocketAddr::new(
            std::net::IpAddr::V6(v6),
            port,
        )));
    }

    addrs.push(MultiAddr::quic(std::net::SocketAddr::new(
        std::net::IpAddr::V4(v4),
        port,
    )));

    addrs
}

impl NodeConfig {
    /// Returns the effective user agent string.
    ///
    /// If a custom user agent was set, returns that. Otherwise, derives
    /// the user agent from the node's [`NodeMode`].
    pub fn user_agent(&self) -> String {
        self.custom_user_agent
            .clone()
            .unwrap_or_else(|| user_agent_for_mode(self.mode))
    }

    /// Compute the listen addresses from the configuration fields.
    ///
    /// The returned addresses are derived from [`local`](Self::local),
    /// [`port`](Self::port), and [`ipv6`](Self::ipv6).
    pub fn listen_addrs(&self) -> Vec<MultiAddr> {
        let mode = if self.local {
            ListenMode::Local
        } else {
            ListenMode::Public
        };
        build_listen_addrs(self.port, self.ipv6, mode)
    }

    /// Create a new NodeConfig with default values
    ///
    /// # Errors
    ///
    /// Returns an error if default addresses cannot be parsed
    pub fn new() -> Result<Self> {
        Ok(Self::default())
    }

    /// Create a builder for customized NodeConfig construction
    pub fn builder() -> NodeConfigBuilder {
        NodeConfigBuilder::default()
    }
}

// ============================================================================
// NodeConfig Builder Pattern
// ============================================================================

/// Builder for constructing [`NodeConfig`] with a transport-aware fluent API.
///
/// Defaults are chosen for quick local development:
/// - QUIC on a random free port (`0`)
/// - IPv6 enabled (dual-stack)
/// - All interfaces (not local-only)
///
/// # Examples
///
/// ```rust,ignore
/// // Simplest — QUIC on random port, IPv6 on, all interfaces
/// let config = NodeConfig::builder().build()?;
///
/// // Local dev/test mode (loopback, auto-enables allow_loopback)
/// let config = NodeConfig::builder()
///     .local(true)
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct NodeConfigBuilder {
    port: u16,
    ipv6: bool,
    local: bool,
    bootstrap_peers: Vec<crate::MultiAddr>,
    max_connections: Option<usize>,
    connection_timeout: Option<Duration>,
    dht_config: Option<DHTConfig>,
    max_message_size: Option<usize>,
    mode: NodeMode,
    custom_user_agent: Option<String>,
    allow_loopback: Option<bool>,
    adaptive_dht_config: Option<AdaptiveDhtConfig>,
    close_group_cache_dir: Option<PathBuf>,
}

impl Default for NodeConfigBuilder {
    fn default() -> Self {
        Self {
            port: 0,
            ipv6: true,
            local: false,
            bootstrap_peers: Vec::new(),
            max_connections: None,
            connection_timeout: None,
            dht_config: None,
            max_message_size: None,
            mode: NodeMode::default(),
            custom_user_agent: None,
            allow_loopback: None,
            adaptive_dht_config: None,
            close_group_cache_dir: None,
        }
    }
}

impl NodeConfigBuilder {
    /// Set the listen port. Default: `0` (random free port).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Enable or disable IPv6 dual-stack. Default: `true`.
    pub fn ipv6(mut self, enabled: bool) -> Self {
        self.ipv6 = enabled;
        self
    }

    /// Bind to loopback only (`true`) or all interfaces (`false`).
    ///
    /// When `true`, automatically enables `allow_loopback` unless explicitly
    /// overridden via [`Self::allow_loopback`].
    ///
    /// Default: `false` (all interfaces).
    pub fn local(mut self, local: bool) -> Self {
        self.local = local;
        self
    }

    /// Add a bootstrap peer.
    pub fn bootstrap_peer(mut self, addr: crate::MultiAddr) -> Self {
        self.bootstrap_peers.push(addr);
        self
    }

    /// Set maximum connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Set connection timeout.
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = Some(timeout);
        self
    }

    /// Set DHT configuration.
    pub fn dht_config(mut self, config: DHTConfig) -> Self {
        self.dht_config = Some(config);
        self
    }

    /// Set maximum application-layer message size in bytes.
    ///
    /// If this method is not called, saorsa-transport's built-in default is used.
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.max_message_size = Some(max_message_size);
        self
    }

    /// Set the operating mode (Node or Client).
    pub fn mode(mut self, mode: NodeMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set a custom user agent string, overriding the mode-derived default.
    pub fn custom_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.custom_user_agent = Some(user_agent.into());
        self
    }

    /// Explicitly control whether loopback addresses are allowed in the
    /// transport layer. When not called, `local(true)` auto-enables this;
    /// `local(false)` defaults to `false`.
    pub fn allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = Some(allow);
        self
    }

    /// Enable or disable trust-based peer swap-out.
    ///
    /// When `false`, peers are never swapped out of the routing table
    /// based on trust scores. Trust scores are still tracked but have
    /// no enforcement effect.
    ///
    /// When `true` (the default), peers whose trust score falls below the
    /// swap threshold (0.35) become eligible for replacement when a
    /// better candidate arrives.
    ///
    /// For fine-grained control over the threshold, use
    /// [`adaptive_dht_config`](Self::adaptive_dht_config) instead.
    pub fn trust_enforcement(mut self, enabled: bool) -> Self {
        let threshold = if enabled {
            AdaptiveDhtConfig::default().swap_threshold
        } else {
            0.0
        };
        self.adaptive_dht_config = Some(AdaptiveDhtConfig {
            swap_threshold: threshold,
        });
        self
    }

    /// Set the full adaptive DHT configuration.
    ///
    /// Overrides any previous call to [`trust_enforcement`](Self::trust_enforcement).
    pub fn adaptive_dht_config(mut self, config: AdaptiveDhtConfig) -> Self {
        self.adaptive_dht_config = Some(config);
        self
    }

    /// Set the directory for persisting the close group cache.
    ///
    /// The node writes `close_group_cache.json` inside this directory on
    /// shutdown and after bootstrap, and loads it on startup.
    pub fn close_group_cache_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.close_group_cache_dir = Some(path.into());
        self
    }

    /// Build the [`NodeConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if address construction fails.
    pub fn build(self) -> Result<NodeConfig> {
        // local mode auto-enables allow_loopback unless explicitly overridden
        let allow_loopback = self.allow_loopback.unwrap_or(self.local);

        Ok(NodeConfig {
            local: self.local,
            port: self.port,
            ipv6: self.ipv6,
            bootstrap_peers: self.bootstrap_peers,
            connection_timeout: self
                .connection_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS)),
            max_connections: self.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            dht_config: self.dht_config.unwrap_or_default(),
            bootstrap_cache_config: None,
            diversity_config: None,
            max_message_size: self.max_message_size,
            node_identity: None,
            mode: self.mode,
            custom_user_agent: self.custom_user_agent,
            allow_loopback,
            adaptive_dht_config: self.adaptive_dht_config.unwrap_or_default(),
            close_group_cache_dir: self.close_group_cache_dir,
        })
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            local: false,
            port: DEFAULT_LISTEN_PORT,
            ipv6: true,
            bootstrap_peers: Vec::new(),
            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            dht_config: DHTConfig::default(),
            bootstrap_cache_config: None,
            diversity_config: None,
            max_message_size: None,
            node_identity: None,
            mode: NodeMode::default(),
            custom_user_agent: None,
            allow_loopback: false,
            adaptive_dht_config: AdaptiveDhtConfig::default(),
            close_group_cache_dir: None,
        }
    }
}

impl DHTConfig {
    /// Default K value (bucket size) for Kademlia routing.
    pub const DEFAULT_K_VALUE: usize = 20;
    const DEFAULT_ALPHA_VALUE: usize = 3;
    const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 600;
    /// Minimum k_value — values below this produce degenerate routing behavior.
    const MIN_K_VALUE: usize = 4;

    /// Validate parameter safety constraints (Section 4 points 1-13).
    ///
    /// Returns `Err` if any constraint is violated.
    pub fn validate(&self) -> Result<()> {
        if self.k_value < Self::MIN_K_VALUE {
            return Err(P2PError::Validation(
                format!(
                    "k_value must be >= {} (got {}), values below {} produce degenerate behavior",
                    Self::MIN_K_VALUE,
                    self.k_value,
                    Self::MIN_K_VALUE,
                )
                .into(),
            ));
        }
        if self.alpha_value < 1 {
            return Err(P2PError::Validation(
                format!("alpha_value must be >= 1 (got {})", self.alpha_value).into(),
            ));
        }
        if self.refresh_interval.is_zero() {
            return Err(P2PError::Validation("refresh_interval must be > 0".into()));
        }
        Ok(())
    }
}

impl Default for DHTConfig {
    fn default() -> Self {
        Self {
            k_value: Self::DEFAULT_K_VALUE,
            alpha_value: Self::DEFAULT_ALPHA_VALUE,
            refresh_interval: Duration::from_secs(Self::DEFAULT_REFRESH_INTERVAL_SECS),
        }
    }
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Transport-level channel identifier (internal use only).
    #[allow(dead_code)]
    pub(crate) channel_id: String,

    /// Peer's addresses
    pub addresses: Vec<MultiAddr>,

    /// Connection timestamp
    pub connected_at: Instant,

    /// Last seen timestamp
    pub last_seen: Instant,

    /// Connection status
    pub status: ConnectionStatus,

    /// Supported protocols
    pub protocols: Vec<String>,

    /// Number of heartbeats received
    pub heartbeat_count: u64,
}

/// Connection status for a peer
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    /// Connection is being established
    Connecting,
    /// Connection is established and active
    Connected,
    /// Connection is being closed
    Disconnecting,
    /// Connection is closed
    Disconnected,
    /// Connection failed
    Failed(String),
}

/// Network events that can occur in the P2P system
///
/// Events are broadcast to all listeners and provide real-time
/// notifications of network state changes and message arrivals.
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// Message received from a peer on a specific topic
    Message {
        /// Topic or channel the message was sent on
        topic: String,
        /// For signed messages this is the authenticated app-level [`PeerId`];
        /// `None` for unsigned messages.
        source: Option<PeerId>,
        /// Raw message data payload
        data: Vec<u8>,
    },
    /// An authenticated peer has connected (first signed message verified on any channel).
    /// The `user_agent` identifies the remote software (e.g. `"node/0.12.1"`, `"client/1.0"`).
    PeerConnected(PeerId, String),
    /// An authenticated peer has fully disconnected (all channels closed).
    PeerDisconnected(PeerId),
}

/// Response from a peer to a request sent via [`P2PNode::send_request`].
///
/// Contains the response payload along with metadata about the responder
/// and round-trip latency.
#[derive(Debug, Clone)]
pub struct PeerResponse {
    /// The peer that sent the response.
    pub peer_id: PeerId,
    /// Raw response payload bytes.
    pub data: Vec<u8>,
    /// Round-trip latency from request to response.
    pub latency: Duration,
}

/// Wire format for request/response correlation.
///
/// Wraps application payloads with a message ID and direction flag
/// so the receive loop can route responses back to waiting callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RequestResponseEnvelope {
    /// Unique identifier to correlate request ↔ response.
    pub(crate) message_id: String,
    /// `false` for requests, `true` for responses.
    pub(crate) is_response: bool,
    /// Application payload.
    pub(crate) payload: Vec<u8>,
}

/// An in-flight request awaiting a response from a specific peer.
pub(crate) struct PendingRequest {
    /// Oneshot sender for delivering the response payload.
    pub(crate) response_tx: tokio::sync::oneshot::Sender<Vec<u8>>,
    /// The peer we expect the response from (for origin validation).
    pub(crate) expected_peer: PeerId,
}

/// Maximum time to wait for identity exchange during a reconnect-on-send dial.
const RECONNECT_IDENTITY_TIMEOUT: Duration = Duration::from_secs(5);

/// Short grace period after closing stale QUIC connections before re-dialing.
///
/// `disconnect_channel` is async and waits for the QUIC close, but the
/// transport endpoint may need a moment to fully release internal state.
/// Only applied when stale channels were actually disconnected.
const QUIC_TEARDOWN_GRACE: Duration = Duration::from_millis(100);

/// Main P2P network node that manages connections, routing, and communication
///
/// This struct represents a complete P2P network participant that can:
/// - Connect to other peers via QUIC transport
/// - Participate in distributed hash table (DHT) operations
/// - Send and receive messages through various protocols
/// - Handle network events and peer lifecycle
///
/// Transport concerns (connections, messaging, events) are delegated to
/// `TransportHandle`.
pub struct P2PNode {
    /// Node configuration
    config: NodeConfig,

    /// Our peer ID
    peer_id: PeerId,

    /// Transport handle owning all QUIC / peer / event state
    transport: Arc<crate::transport_handle::TransportHandle>,

    /// Node start time
    start_time: Instant,

    /// Shutdown token — cancelled when the node should stop
    shutdown: CancellationToken,

    /// Adaptive DHT layer — owns both the DHT manager and the trust engine.
    /// All DHT operations and trust signals go through this component.
    adaptive_dht: AdaptiveDHT,

    /// Bootstrap cache manager for peer discovery
    bootstrap_manager: Option<Arc<RwLock<BootstrapManager>>>,

    /// Bootstrap state tracking - indicates whether peer discovery has completed
    is_bootstrapped: Arc<AtomicBool>,

    /// Whether `start()` has been called (and `stop()` has not yet completed)
    is_started: Arc<AtomicBool>,

    /// Per-peer locks that serialise reconnect attempts so concurrent sends
    /// to the same stale peer don't race to dial.  Entries accumulate over
    /// the node's lifetime; each is a lightweight `Arc<TokioMutex<()>>`.
    reconnect_locks: ParkingMutex<HashMap<PeerId, Arc<TokioMutex<()>>>>,
}

/// Normalize wildcard bind addresses to localhost loopback addresses
///
/// saorsa-transport correctly rejects "unspecified" addresses (0.0.0.0 and [::]) for remote connections
/// because you cannot connect TO an unspecified address - these are only valid for BINDING.
///
/// This function converts wildcard addresses to appropriate loopback addresses for local connections:
/// - IPv6 [::]:port → ::1:port (IPv6 loopback)
/// - IPv4 0.0.0.0:port → 127.0.0.1:port (IPv4 loopback)
/// - All other addresses pass through unchanged
///
/// # Arguments
/// * `addr` - The SocketAddr to normalize
///
/// # Returns
/// * Normalized SocketAddr suitable for remote connections
pub(crate) fn normalize_wildcard_to_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if addr.ip().is_unspecified() {
        // Convert unspecified addresses to loopback
        let loopback_ip = match addr {
            std::net::SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST), // ::1
            std::net::SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST), // 127.0.0.1
        };
        std::net::SocketAddr::new(loopback_ip, addr.port())
    } else {
        // Not a wildcard address, pass through unchanged
        addr
    }
}

impl P2PNode {
    /// Create a new P2P node with the given configuration
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Ensure a cryptographic identity exists — generate one if not provided.
        let node_identity = match config.node_identity.clone() {
            Some(identity) => identity,
            None => Arc::new(NodeIdentity::generate()?),
        };

        // Derive the canonical peer ID from the cryptographic identity.
        let peer_id = *node_identity.peer_id();

        // Validate parameter safety constraints (Section 4 points 1-13).
        // Reject invalid config early, before any resources are allocated.
        config.dht_config.validate()?;
        if let Some(ref diversity) = config.diversity_config {
            diversity
                .validate()
                .map_err(|e| P2PError::Validation(format!("IP diversity config: {e}").into()))?;
        }

        // Initialize bootstrap cache manager
        let bootstrap_config = config.bootstrap_cache_config.clone().unwrap_or_default();
        let bootstrap_manager =
            match BootstrapManager::with_node_config(bootstrap_config, &config).await {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    warn!("Failed to initialize bootstrap manager: {e}, continuing without cache");
                    None
                }
            };

        // Build transport handle with all transport-level concerns
        let transport_config = crate::transport_handle::TransportConfig::from_node_config(
            &config,
            crate::DEFAULT_EVENT_CHANNEL_CAPACITY,
            node_identity.clone(),
        );
        let transport =
            Arc::new(crate::transport_handle::TransportHandle::new(transport_config).await?);

        // Initialize AdaptiveDHT — creates the trust engine and DHT manager
        let dht_manager_config = DhtNetworkConfig {
            peer_id,
            node_config: config.clone(),
            request_timeout: config.connection_timeout,
            max_concurrent_operations: MAX_ACTIVE_REQUESTS,
            enable_security: true,
            swap_threshold: 0.0, // Set by AdaptiveDHT::new() from AdaptiveDhtConfig
        };
        let adaptive_dht = AdaptiveDHT::new(
            transport.clone(),
            dht_manager_config,
            config.adaptive_dht_config.clone(),
        )
        .await?;

        let node = Self {
            config,
            peer_id,
            transport,
            start_time: Instant::now(),
            shutdown: CancellationToken::new(),
            adaptive_dht,
            bootstrap_manager,
            is_bootstrapped: Arc::new(AtomicBool::new(false)),
            is_started: Arc::new(AtomicBool::new(false)),
            reconnect_locks: ParkingMutex::new(HashMap::new()),
        };
        info!(
            "Created P2P node with peer ID: {} (call start() to begin networking)",
            node.peer_id
        );

        Ok(node)
    }

    /// Get the peer ID of this node.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get the transport handle for sharing with other components.
    pub fn transport(&self) -> &Arc<crate::transport_handle::TransportHandle> {
        &self.transport
    }

    pub fn local_addr(&self) -> Option<MultiAddr> {
        self.transport.local_addr()
    }

    /// Check if the node has completed the initial bootstrap process
    ///
    /// Returns `true` if the node has successfully connected to at least one
    /// bootstrap peer and performed peer discovery (FIND_NODE).
    pub fn is_bootstrapped(&self) -> bool {
        self.is_bootstrapped.load(Ordering::SeqCst)
    }

    /// Manually trigger re-bootstrap (useful for recovery or network rejoin)
    ///
    /// This clears the bootstrapped state and attempts to reconnect to
    /// bootstrap peers and discover new peers.
    pub async fn re_bootstrap(&self) -> Result<()> {
        self.is_bootstrapped.store(false, Ordering::SeqCst);
        self.connect_bootstrap_peers(None).await
    }

    // =========================================================================
    // Trust API — delegates to AdaptiveDHT
    // =========================================================================

    /// Get the trust engine for advanced use cases
    pub fn trust_engine(&self) -> Arc<TrustEngine> {
        self.adaptive_dht.trust_engine().clone()
    }

    /// Report a trust event for a peer.
    ///
    /// Core only records penalties (connection failures). Positive trust
    /// signals are the consumer's responsibility via [`TrustEvent::ApplicationSuccess`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use saorsa_core::adaptive::TrustEvent;
    ///
    /// node.report_trust_event(&peer_id, TrustEvent::ApplicationSuccess(1.0)).await;
    /// node.report_trust_event(&peer_id, TrustEvent::ConnectionFailed).await;
    /// ```
    pub async fn report_trust_event(&self, peer_id: &PeerId, event: TrustEvent) {
        self.adaptive_dht.report_trust_event(peer_id, event).await;
    }

    /// Get the current trust score for a peer (0.0 to 1.0).
    ///
    /// Returns 0.5 (neutral) for unknown peers.
    pub fn peer_trust(&self, peer_id: &PeerId) -> f64 {
        self.adaptive_dht.peer_trust(peer_id)
    }

    /// Get the AdaptiveDHT component for direct access
    pub fn adaptive_dht(&self) -> &AdaptiveDHT {
        &self.adaptive_dht
    }

    // =========================================================================
    // Request/Response API — Automatic Trust Feedback
    // =========================================================================

    /// Send a request to a peer and wait for a response with automatic trust penalty reporting.
    ///
    /// Unlike fire-and-forget `send_message()`, this method:
    /// 1. Wraps the payload in a `RequestResponseEnvelope` with a unique message ID
    /// 2. Sends it on the `/rr/<protocol>` protocol prefix
    /// 3. Waits for a matching response (or timeout)
    /// 4. Automatically reports failure to the trust engine (success is the expected baseline)
    ///
    /// The remote peer's handler should call `send_response()` with the
    /// incoming message ID to route the response back.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Target peer
    /// * `protocol` - Application protocol name (e.g. `"peer_info"`)
    /// * `data` - Request payload bytes
    /// * `timeout` - Maximum time to wait for a response
    ///
    /// # Returns
    ///
    /// A `PeerResponse` on success, or an error on timeout / connection failure.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let response = node.send_request(&peer_id, "peer_info", request_data, Duration::from_secs(10)).await?;
    /// println!("Got {} bytes from {}", response.data.len(), response.peer_id);
    /// ```
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<PeerResponse> {
        match self
            .transport
            .send_request(peer_id, protocol, data, timeout)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(e) => {
                let event = if matches!(&e, P2PError::Timeout(_)) {
                    TrustEvent::ConnectionTimeout
                } else {
                    TrustEvent::ConnectionFailed
                };
                self.report_trust_event(peer_id, event).await;
                Err(e)
            }
        }
    }

    pub async fn send_response(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        message_id: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        self.transport
            .send_response(peer_id, protocol, message_id, data)
            .await
    }

    pub fn parse_request_envelope(data: &[u8]) -> Option<(String, bool, Vec<u8>)> {
        crate::transport_handle::TransportHandle::parse_request_envelope(data)
    }

    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        self.transport.subscribe(topic).await
    }

    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        self.transport.publish(topic, data).await
    }

    /// Get the node configuration
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Start the P2P node
    pub async fn start(&self) -> Result<()> {
        info!("Starting P2P node...");

        // Start bootstrap manager background tasks
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let mut manager = bootstrap_manager.write().await;
            manager
                .start_maintenance()
                .map_err(|e| protocol_error(format!("Failed to start bootstrap manager: {e}")))?;
            info!("Bootstrap cache manager started");
        }

        // Start transport listeners and message receiving
        self.transport.start_network_listeners().await?;

        // Start the adaptive DHT layer (DHT manager + trust engine)
        self.adaptive_dht.start().await?;

        // Log current listen addresses
        let listen_addrs = self.transport.listen_addrs().await;
        info!("P2P node started on addresses: {:?}", listen_addrs);

        // NOTE: Message receiving is now integrated into the accept loop in start_network_listeners()
        // The old start_message_receiving_system() is no longer needed as it competed with the accept
        // loop for incoming connections, causing messages to be lost.

        // Load close group cache and import trust scores before connecting to peers.
        // This ensures trust scores are available when peers are added to the routing table.
        let close_group_cache = if let Some(ref dir) = self.config.close_group_cache_dir {
            match CloseGroupCache::load_from_dir(dir).await {
                Ok(Some(cache)) => {
                    // Filter out peers with non-finite trust scores (NaN/Inf)
                    // that could corrupt trust engine state or sort ordering.
                    let original_count = cache.peers.len();
                    let cache = CloseGroupCache {
                        peers: cache
                            .peers
                            .into_iter()
                            .filter(|p| p.trust.score.is_finite())
                            .collect(),
                        ..cache
                    };
                    let filtered_count = original_count - cache.peers.len();
                    if filtered_count > 0 {
                        warn!(
                            "Filtered {filtered_count} peers with non-finite trust scores from close group cache"
                        );
                    }

                    let trust_snapshot = TrustSnapshot {
                        peers: cache
                            .peers
                            .iter()
                            .map(|p| (p.peer_id, p.trust.clone()))
                            .collect(),
                    };
                    self.adaptive_dht
                        .trust_engine()
                        .import_snapshot(&trust_snapshot);
                    info!(
                        "Loaded {} peers from close group cache (trust scores imported)",
                        cache.peers.len()
                    );
                    Some(cache)
                }
                Ok(None) => {
                    debug!(
                        "No close group cache found in {}, fresh start",
                        dir.display()
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        "Failed to load close group cache from {}: {e}",
                        dir.display()
                    );
                    None
                }
            }
        } else {
            None
        };

        // Connect to bootstrap peers
        self.connect_bootstrap_peers(close_group_cache.as_ref())
            .await?;

        // Spawn background task to forward peer address updates to the DHT.
        //
        // Two event streams are bridged from the transport layer onto DHT
        // routing-table mutations:
        //
        //  - **Relay established**: when THIS node sets up a MASQUE relay,
        //    perform a DHT self-lookup so the transport's re-advertisement
        //    loop can ADD_ADDRESS the new relay address to the K closest
        //    peers — propagating it beyond peers we already happen to be
        //    connected to.
        //  - **Peer address update**: when a connected peer advertises a new
        //    reachable address via ADD_ADDRESS (typically its relay), update
        //    the DHT routing table so future lookups return that address.
        //
        // Both are handled in a `tokio::select!` against the receiver
        // futures so updates propagate immediately. The previous
        // implementation polled both queues on a 1-second interval, which
        // opened a race window in which a freshly-established relay was
        // invisible to outbound DHT queries until the next tick — causing
        // the first peers to dial direct (and fail) before learning about
        // the relay.
        //
        // **Slow work isolation**: the relay-propagation path runs an
        // iterative DHT lookup (`find_closest_nodes_network`) which can
        // take many seconds. Doing it inline in the select loop would
        // starve the peer-address-update branch and back up the bounded
        // forwarder mpsc into drop territory. Instead, the lookup +
        // publish is detached into its own task per relay event, so the
        // select loop keeps polling both branches.
        {
            let transport = Arc::clone(&self.transport);
            let dht = self.adaptive_dht.dht_manager().clone();
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break,
                        relay = transport.recv_relay_established() => {
                            let Some(relay_addr) = relay else { break };
                            // Normalize IPv6-mapped addresses to IPv4 so the
                            // published address is dialable by IPv4-only clients.
                            let normalized = saorsa_transport::shared::normalize_socket_addr(relay_addr);
                            let relay_multi = crate::MultiAddr::quic(normalized);
                            info!(
                                "DHT_BRIDGE: relay established at {} — spawning self-lookup + PublishAddress",
                                relay_addr
                            );
                            // Detach the slow work so the select loop is
                            // free to keep polling peer-address updates.
                            let dht_for_propagation = dht.clone();
                            tokio::spawn(async move {
                                let own_key = *dht_for_propagation.peer_id().to_bytes();
                                match dht_for_propagation
                                    .find_closest_nodes_network(&own_key, dht_for_propagation.k_value())
                                    .await
                                {
                                    Ok(nodes) => {
                                        info!(
                                            "DHT_BRIDGE: self-lookup found {} nodes — sending PublishAddress",
                                            nodes.len()
                                        );
                                        dht_for_propagation
                                            .publish_address_to_peers(vec![relay_multi], &nodes)
                                            .await;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "DHT_BRIDGE: self-lookup for relay propagation failed: {}",
                                            e
                                        );
                                    }
                                }
                            });
                        }
                        update = transport.recv_peer_address_update() => {
                            let Some((peer_addr, advertised_addr)) = update else { break };
                            info!(
                                "DHT_BRIDGE: processing update peer={} addr={} same_ip={}",
                                peer_addr,
                                advertised_addr,
                                peer_addr.ip() == advertised_addr.ip()
                            );
                            // Only update DHT when the advertised IP differs
                            // from the peer's connection IP. Same-IP updates
                            // are just different NATted ports (useless for
                            // symmetric NAT); different-IP means a relay.
                            if peer_addr.ip() == advertised_addr.ip() {
                                continue;
                            }
                            // Look up peer ID by address (tries both IPv4 and
                            // IPv4-mapped IPv6 forms via dual_stack_alternate).
                            // For symmetric NAT, this may fail because the
                            // connection's channel key uses a different NATted port.
                            if let Some(peer_id) = transport.peer_id_for_addr(&peer_addr).await {
                                let normalized_adv =
                                    saorsa_transport::shared::normalize_socket_addr(advertised_addr);
                                let multi_addr = crate::MultiAddr::quic(normalized_adv);
                                info!(
                                    "Updating DHT: peer {} relay address {} (connection was {})",
                                    peer_id, advertised_addr, peer_addr
                                );
                                dht.touch_node_typed(
                                    &peer_id,
                                    Some(&multi_addr),
                                    crate::dht::AddressType::Relay,
                                )
                                .await;
                            }
                        }
                    }
                }
            });
        }

        self.is_started
            .store(true, std::sync::atomic::Ordering::Release);

        Ok(())
    }

    // start_network_listeners and start_message_receiving_system
    // are now implemented in TransportHandle

    /// Run the P2P node (blocks until shutdown)
    pub async fn run(&self) -> Result<()> {
        if !self.is_running() {
            self.start().await?;
        }

        info!("P2P node running...");

        // Block until shutdown is signalled. All background work (connection
        // lifecycle, DHT maintenance, EigenTrust) runs in dedicated tasks.
        self.shutdown.cancelled().await;

        info!("P2P node stopped");
        Ok(())
    }

    /// Stop the P2P node
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping P2P node...");

        // Save close group cache before tearing down the DHT and transport layers.
        if let Some(ref dir) = self.config.close_group_cache_dir
            && let Err(e) = self.save_close_group_cache(dir).await
        {
            warn!("Failed to save close group cache on shutdown: {e}");
        }

        // Signal the run loop to exit
        self.shutdown.cancel();

        // Stop DHT layer first so leave messages can be sent while transport is still active.
        self.adaptive_dht.stop().await?;

        // Stop the transport layer (shutdown endpoints, join tasks, disconnect peers)
        self.transport.stop().await?;

        self.is_started
            .store(false, std::sync::atomic::Ordering::Release);

        info!("P2P node stopped");
        Ok(())
    }

    /// Graceful shutdown alias for tests
    pub async fn shutdown(&self) -> Result<()> {
        self.stop().await
    }

    /// Check if the node is running
    pub fn is_running(&self) -> bool {
        self.is_started.load(std::sync::atomic::Ordering::Acquire) && !self.shutdown.is_cancelled()
    }

    /// Get the current listen addresses
    pub async fn listen_addrs(&self) -> Vec<MultiAddr> {
        self.transport.listen_addrs().await
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.transport.connected_peers().await
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.transport.peer_count().await
    }

    /// Get peer info
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.transport.peer_info(peer_id).await
    }

    /// Get the channel ID for a given address, if connected (internal only).
    #[allow(dead_code)]
    pub(crate) async fn get_channel_id_by_address(&self, addr: &MultiAddr) -> Option<String> {
        self.transport.get_channel_id_by_address(addr).await
    }

    /// List all active transport-level connections (internal only).
    #[allow(dead_code)]
    pub(crate) async fn list_active_connections(&self) -> Vec<(String, Vec<MultiAddr>)> {
        self.transport.list_active_connections().await
    }

    /// Remove a channel from the peers map (internal only).
    #[allow(dead_code)]
    pub(crate) async fn remove_channel(&self, channel_id: &str) -> bool {
        self.transport.remove_channel(channel_id).await
    }

    /// Close a channel's QUIC connection and remove it from all tracking maps.
    ///
    /// Use when a transport-level connection was established but identity
    /// exchange failed, so no [`PeerId`] is available for [`disconnect_peer`].
    pub(crate) async fn disconnect_channel(&self, channel_id: &str) {
        self.transport.disconnect_channel(channel_id).await;
    }

    /// Check if an authenticated peer is connected (has at least one active channel).
    pub async fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.transport.is_peer_connected(peer_id).await
    }

    /// Connect to a peer, returning the transport-level channel ID.
    ///
    /// The returned channel ID is **not** the app-level [`PeerId`]. To obtain
    /// the authenticated peer identity, call
    /// [`wait_for_peer_identity`](Self::wait_for_peer_identity) with the
    /// returned channel ID.
    pub async fn connect_peer(&self, address: &MultiAddr) -> Result<String> {
        self.transport.connect_peer(address).await
    }

    /// Wait for the identity exchange on `channel_id` to complete, returning
    /// the authenticated [`PeerId`].
    ///
    /// Use this after [`connect_peer`](Self::connect_peer) to bridge the gap
    /// between the transport-level channel ID and the app-level peer identity
    /// required by [`send_message`](Self::send_message).
    pub async fn wait_for_peer_identity(
        &self,
        channel_id: &str,
        timeout: Duration,
    ) -> Result<PeerId> {
        self.transport
            .wait_for_peer_identity(channel_id, timeout)
            .await
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        self.transport.disconnect_peer(peer_id).await
    }

    /// Check if a connection to a peer is active (internal only).
    #[allow(dead_code)]
    pub(crate) async fn is_connection_active(&self, channel_id: &str) -> bool {
        self.transport.is_connection_active(channel_id).await
    }

    /// Send a message to an authenticated peer, reconnecting on demand.
    ///
    /// Tries the existing connection first. If the send fails (stale QUIC
    /// session, peer not found, etc.), resolves a dial address from:
    ///
    /// 1. Caller-provided `addrs` (highest priority)
    /// 2. Addresses cached in the transport layer (snapshotted before the
    ///    send attempt, since stale-channel cleanup removes them)
    /// 3. DHT routing table
    ///
    /// Then dials, waits for identity exchange, and retries the send exactly
    /// once on the fresh connection.  Concurrent reconnects to the same peer
    /// are serialised so only one dial is attempted at a time.
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        addrs: &[MultiAddr],
    ) -> Result<()> {
        // Snapshot channel IDs before the send attempt — transport.send_message
        // prunes dead channels from bookkeeping but does NOT close the
        // underlying QUIC connection.  We need the original IDs for
        // disconnect_channel later.
        let existing_channels = self.transport.channels_for_peer(peer_id).await;

        // No existing connection — serialise so concurrent sends to the same
        // unconnected peer don't each open their own QUIC connection.
        if existing_channels.is_empty() {
            let lock = self.reconnect_lock_for(peer_id);
            let _guard = lock.lock().await;

            // Another sender may have connected while we waited for the lock.
            if self.transport.is_peer_connected(peer_id).await {
                return self.transport.send_message(peer_id, protocol, data).await;
            }

            return self
                .reconnect_and_send(peer_id, protocol, data, addrs, &[], &[])
                .await;
        }

        // Snapshot addresses before the send attempt — transport.send_message
        // prunes stale channels, which removes peer_info.
        let saved_addrs: Vec<MultiAddr> = self
            .transport
            .peer_info(peer_id)
            .await
            .map(|info| info.addresses)
            .unwrap_or_default();

        // Clone data for retry — transport.send_message consumes the Vec,
        // so we need a copy if the first attempt fails.
        let retry_data = data.clone();

        // Fast path: try existing connection.
        match self.transport.send_message(peer_id, protocol, data).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(
                    peer = %peer_id.to_hex(),
                    error = %e,
                    "send failed, attempting reconnect",
                );
            }
        }

        // Serialise reconnect attempts so concurrent sends to the same
        // stale peer don't race to dial.
        let lock = self.reconnect_lock_for(peer_id);
        let _guard = lock.lock().await;

        // Another sender may have reconnected while we waited for the lock.
        if self.transport.is_peer_connected(peer_id).await {
            // Close stale QUIC connections that remove_channel (called inside
            // transport.send_message on failure) didn't tear down — it only
            // removes bookkeeping, not the underlying QUIC session.
            for channel_id in &existing_channels {
                self.transport.disconnect_channel(channel_id).await;
            }
            return self
                .transport
                .send_message(peer_id, protocol, retry_data)
                .await;
        }

        self.reconnect_and_send(
            peer_id,
            protocol,
            retry_data,
            addrs,
            &saved_addrs,
            &existing_channels,
        )
        .await
    }

    /// Tear down stale channels, reconnect to a peer, and send a message.
    async fn reconnect_and_send(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        addrs: &[MultiAddr],
        saved_addrs: &[MultiAddr],
        stale_channels: &[String],
    ) -> Result<()> {
        // Resolve a dial address: caller-provided > saved > DHT.
        let address = self
            .resolve_dial_address(peer_id, addrs, saved_addrs)
            .await
            .ok_or_else(|| {
                P2PError::Network(NetworkError::PeerNotFound(peer_id.to_hex().into()))
            })?;

        // Tear down stale QUIC connections using their actual channel IDs.
        // transport.send_message only removes bookkeeping (peer_to_channel,
        // peers, active_connections) — it does NOT close the underlying QUIC
        // connection.  We must use the real channel IDs, not the resolved
        // dial address, because NAT / port migration can make them differ.
        if !stale_channels.is_empty() {
            for channel_id in stale_channels {
                self.transport.disconnect_channel(channel_id).await;
            }
            tokio::time::sleep(QUIC_TEARDOWN_GRACE).await;
        }

        // Dial and wait for identity exchange.
        let channel_id = self.transport.connect_peer(&address).await?;
        let authenticated = match self
            .transport
            .wait_for_peer_identity(&channel_id, RECONNECT_IDENTITY_TIMEOUT)
            .await
        {
            Ok(peer) => peer,
            Err(e) => {
                // Close the freshly-dialed QUIC connection so it doesn't
                // linger as a zombie until idle timeout.
                self.transport.disconnect_channel(&channel_id).await;
                return Err(e);
            }
        };

        if &authenticated != peer_id {
            self.transport.disconnect_channel(&channel_id).await;
            return Err(P2PError::Identity(IdentityError::IdentityMismatch {
                expected: peer_id.to_hex().into(),
                actual: authenticated.to_hex().into(),
            }));
        }

        // Send on the fresh connection.
        self.transport.send_message(peer_id, protocol, data).await
    }

    /// Resolve a dial address for `peer_id`, preferring caller-provided
    /// addresses over cached/DHT sources.
    ///
    /// Returns the first dialable (QUIC, non-unspecified) address found, or
    /// `None` when no address is available.
    async fn resolve_dial_address(
        &self,
        peer_id: &PeerId,
        caller_addrs: &[MultiAddr],
        saved_addrs: &[MultiAddr],
    ) -> Option<MultiAddr> {
        // 1. Caller-provided addresses (highest priority).
        if let Some(addr) = Self::first_dialable(caller_addrs) {
            return Some(addr);
        }

        // 2. Addresses snapshotted from the transport layer before the send
        //    attempt cleaned them up.
        if let Some(addr) = Self::first_dialable(saved_addrs) {
            return Some(addr);
        }

        // 3. DHT routing table — apply the same dialability filter.
        let dht_addrs = self.adaptive_dht.peer_addresses_for_dial(peer_id).await;
        Self::first_dialable(&dht_addrs)
    }

    /// Return the first dialable QUIC address from a slice, skipping
    /// non-QUIC and unspecified (`0.0.0.0` / `::`) addresses.
    fn first_dialable(addrs: &[MultiAddr]) -> Option<MultiAddr> {
        addrs
            .iter()
            .find(|a| {
                let dialable = a
                    .dialable_socket_addr()
                    .is_some_and(|sa| !sa.ip().is_unspecified());
                if !dialable {
                    trace!(address = %a, "skipping non-dialable address");
                }
                dialable
            })
            .cloned()
    }

    /// Get or create a per-peer reconnect lock.
    fn reconnect_lock_for(&self, peer_id: &PeerId) -> Arc<TokioMutex<()>> {
        self.reconnect_locks
            .lock()
            .entry(*peer_id)
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone()
    }
}

/// Parse a postcard-encoded protocol message into a `P2PEvent::Message`.
///
/// Returns `None` if the bytes cannot be deserialized as a valid `WireMessage`.
///
/// The `from` field is a required part of the wire protocol but is **not**
/// used as the event source. Instead, `source` — the transport-level peer ID
/// derived from the authenticated QUIC connection — is used so that consumers
/// can pass it directly to `send_message()`. This eliminates a spoofing
/// vector where a peer could claim an arbitrary identity via the payload.
///
/// Maximum allowed clock skew for message timestamps (5 minutes).
/// This is intentionally lenient for initial deployment to accommodate nodes with
/// misconfigured clocks or high-latency network conditions. Can be tightened (e.g., to 60s)
/// once the network stabilizes and node clock synchronization improves.
const MAX_MESSAGE_AGE_SECS: u64 = 300;
/// Maximum allowed future timestamp (30 seconds to account for clock drift)
const MAX_FUTURE_SECS: u64 = 30;

/// Convenience constructor for `P2PError::Network(NetworkError::ProtocolError(...))`.
fn protocol_error(msg: impl std::fmt::Display) -> P2PError {
    P2PError::Network(NetworkError::ProtocolError(msg.to_string().into()))
}

/// Helper to send an event via a broadcast sender, logging at trace level if no receivers.
pub(crate) fn broadcast_event(tx: &broadcast::Sender<P2PEvent>, event: P2PEvent) {
    if let Err(e) = tx.send(event) {
        tracing::trace!("Event broadcast has no receivers: {e}");
    }
}

/// Result of parsing a protocol message, including optional authenticated identity.
pub(crate) struct ParsedMessage {
    /// The P2P event to broadcast.
    pub(crate) event: P2PEvent,
    /// If the message was signed and verified, the authenticated app-level [`PeerId`].
    pub(crate) authenticated_node_id: Option<PeerId>,
    /// The sender's user agent string from the wire message.
    pub(crate) user_agent: String,
}

pub(crate) fn parse_protocol_message(bytes: &[u8], source: &str) -> Option<ParsedMessage> {
    let message: WireMessage = postcard::from_bytes(bytes).ok()?;

    // Validate timestamp to prevent replay attacks
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Reject messages that are too old (potential replay)
    if message.timestamp < now.saturating_sub(MAX_MESSAGE_AGE_SECS) {
        tracing::warn!(
            "Rejecting stale message from {} (timestamp {} is {} seconds old)",
            source,
            message.timestamp,
            now.saturating_sub(message.timestamp)
        );
        return None;
    }

    // Reject messages too far in the future (clock manipulation)
    if message.timestamp > now + MAX_FUTURE_SECS {
        tracing::warn!(
            "Rejecting future-dated message from {} (timestamp {} is {} seconds ahead)",
            source,
            message.timestamp,
            message.timestamp.saturating_sub(now)
        );
        return None;
    }

    // Verify app-level signature if present
    let authenticated_node_id = if !message.signature.is_empty() {
        match verify_message_signature(&message) {
            Ok(peer_id) => {
                debug!(
                    "Message from {} authenticated as app-level NodeId {}",
                    source, peer_id
                );
                Some(peer_id)
            }
            Err(e) => {
                warn!(
                    "Rejecting message from {}: signature verification failed: {}",
                    source, e
                );
                return None;
            }
        }
    } else {
        None
    };

    debug!(
        "Parsed P2PEvent::Message - topic: {}, source: {:?} (transport: {}, logical: {}), payload_len: {}",
        message.protocol,
        authenticated_node_id,
        source,
        message.from,
        message.data.len()
    );

    Some(ParsedMessage {
        event: P2PEvent::Message {
            topic: message.protocol,
            source: authenticated_node_id,
            data: message.data,
        },
        authenticated_node_id,
        user_agent: message.user_agent,
    })
}

/// Verify the ML-DSA-65 signature on a WireMessage and return the authenticated [`PeerId`].
///
/// Besides verifying the cryptographic signature, this also checks that the
/// self-asserted `from` field matches the [`PeerId`] derived from the public
/// key. This prevents a sender from signing with their real key while
/// claiming a different identity in the `from` field.
fn verify_message_signature(message: &WireMessage) -> std::result::Result<PeerId, String> {
    let pubkey = MlDsaPublicKey::from_bytes(&message.public_key)
        .map_err(|e| format!("invalid public key: {e:?}"))?;

    let peer_id = peer_id_from_public_key(&pubkey);

    // Validate that the self-asserted `from` field matches the public key.
    if message.from != peer_id {
        return Err(format!(
            "from field mismatch: message claims '{}' but public key derives '{}'",
            message.from, peer_id
        ));
    }

    let signable = postcard::to_stdvec(&(
        &message.protocol,
        &message.data as &[u8],
        &message.from,
        message.timestamp,
        &message.user_agent,
    ))
    .map_err(|e| format!("failed to serialize signable bytes: {e}"))?;

    let sig = MlDsaSignature::from_bytes(&message.signature)
        .map_err(|e| format!("invalid signature: {e:?}"))?;

    let valid = crate::quantum_crypto::ml_dsa_verify(&pubkey, &signable, &sig)
        .map_err(|e| format!("verification error: {e}"))?;

    if valid {
        Ok(peer_id)
    } else {
        Err("signature is invalid".to_string())
    }
}

impl P2PNode {
    /// Subscribe to network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.transport.subscribe_events()
    }

    /// Backwards-compat event stream accessor for tests
    pub fn events(&self) -> broadcast::Receiver<P2PEvent> {
        self.subscribe_events()
    }

    /// Get node uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    // MCP removed: all MCP tool/service methods removed

    // /// Handle MCP remote tool call with network integration

    // /// List tools available on a specific remote peer

    // /// Get MCP server statistics

    // Background tasks (connection_lifecycle_monitor, keepalive, periodic_maintenance)
    // are now implemented in TransportHandle.

    /// Check system health
    pub async fn health_check(&self) -> Result<()> {
        let peer_count = self.peer_count().await;
        if peer_count > self.config.max_connections {
            Err(protocol_error(format!(
                "Too many connections: {peer_count}"
            )))
        } else {
            Ok(())
        }
    }

    /// Get the attached DHT manager.
    pub fn dht_manager(&self) -> &Arc<DhtNetworkManager> {
        self.adaptive_dht.dht_manager()
    }

    /// Backwards-compatible alias for `dht_manager()`.
    pub fn dht(&self) -> &Arc<DhtNetworkManager> {
        self.dht_manager()
    }

    /// Add a discovered peer to the bootstrap cache
    pub async fn add_discovered_peer(
        &self,
        _peer_id: PeerId,
        addresses: Vec<MultiAddr>,
    ) -> Result<()> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            let socket_addresses: Vec<std::net::SocketAddr> = addresses
                .iter()
                .filter_map(|addr| addr.socket_addr())
                .collect();
            if let Some(&primary) = socket_addresses.first() {
                manager
                    .add_peer(&primary, socket_addresses)
                    .await
                    .map_err(|e| {
                        protocol_error(format!("Failed to add peer to bootstrap cache: {e}"))
                    })?;
            }
        }
        Ok(())
    }

    /// Update connection metrics for a peer in the bootstrap cache
    pub async fn update_peer_metrics(
        &self,
        addr: &MultiAddr,
        success: bool,
        latency_ms: Option<u64>,
        _error: Option<String>,
    ) -> Result<()> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager
            && let Some(sa) = addr.socket_addr()
        {
            let manager = bootstrap_manager.read().await;
            if success {
                let rtt_ms = latency_ms.unwrap_or(0) as u32;
                manager.record_success(&sa, rtt_ms).await;
            } else {
                manager.record_failure(&sa).await;
            }
        }
        Ok(())
    }

    /// Get bootstrap cache statistics
    pub async fn get_bootstrap_cache_stats(
        &self,
    ) -> Result<Option<crate::bootstrap::BootstrapStats>> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            Ok(Some(manager.stats().await))
        } else {
            Ok(None)
        }
    }

    /// Get the number of cached bootstrap peers
    pub async fn cached_peer_count(&self) -> usize {
        if let Some(ref _bootstrap_manager) = self.bootstrap_manager
            && let Ok(Some(stats)) = self.get_bootstrap_cache_stats().await
        {
            return stats.total_peers;
        }
        0
    }

    /// Connect to bootstrap peers and perform initial peer discovery.
    ///
    /// If a `close_group_cache` was loaded on startup, its peers are injected
    /// as the highest-priority addresses (before configured and cached bootstrap
    /// peers). Their trust scores were already imported into the `TrustEngine`
    /// before this method is called.
    async fn connect_bootstrap_peers(
        &self,
        close_group_cache: Option<&CloseGroupCache>,
    ) -> Result<()> {
        // Each entry is a list of addresses for a single peer.
        let mut bootstrap_addr_sets: Vec<Vec<MultiAddr>> = Vec::new();
        let mut used_cache = false;
        let mut seen_addresses = std::collections::HashSet::new();

        // Priority 0: Cached close group peers (pre-trusted, highest priority).
        // These peers had trust scores loaded into the TrustEngine earlier in start(),
        // so they are already known-good when added to the routing table.
        // Sorted by trust score (highest first), then XOR distance (closest first)
        // as tiebreaker so we reconnect to the most trusted, closest peers first.
        if let Some(cache) = close_group_cache {
            let mut sorted_peers: Vec<&CachedCloseGroupPeer> = cache.peers.iter().collect();
            sorted_peers.sort_by(|a, b| {
                // NaN-safe comparison: push NaN scores to the back instead
                // of treating them as equal (which would silently promote
                // corrupted entries to the front of the reconnection queue).
                let score_ord = match b.trust.score.partial_cmp(&a.trust.score) {
                    Some(ord) => ord,
                    None => {
                        if a.trust.score.is_nan() {
                            std::cmp::Ordering::Greater // a is NaN, push to back
                        } else {
                            std::cmp::Ordering::Less // b is NaN, push b to back
                        }
                    }
                };
                score_ord.then_with(|| {
                    let da = self.peer_id.xor_distance(&a.peer_id);
                    let db = self.peer_id.xor_distance(&b.peer_id);
                    da.cmp(&db)
                })
            });

            let mut added_from_close_group = 0usize;
            for peer in &sorted_peers {
                let new_addresses: Vec<MultiAddr> = peer
                    .addresses
                    .iter()
                    .filter(|a| {
                        a.dialable_socket_addr()
                            .is_some_and(|sa| !seen_addresses.contains(&sa))
                    })
                    .cloned()
                    .collect();

                if !new_addresses.is_empty() {
                    for addr in &new_addresses {
                        if let Some(sa) = addr.socket_addr() {
                            seen_addresses.insert(sa);
                        }
                    }
                    bootstrap_addr_sets.push(new_addresses);
                    added_from_close_group += 1;
                }
            }
            if added_from_close_group > 0 {
                info!(
                    "Added {} close group cache peers (highest trust first)",
                    added_from_close_group
                );
            }
        }

        // Priority 1: Configured bootstrap peers.
        if !self.config.bootstrap_peers.is_empty() {
            info!(
                "Using {} configured bootstrap peers (priority)",
                self.config.bootstrap_peers.len()
            );
            for multiaddr in &self.config.bootstrap_peers {
                let Some(socket_addr) = multiaddr.dialable_socket_addr() else {
                    warn!("Skipping non-QUIC bootstrap peer: {}", multiaddr);
                    continue;
                };
                seen_addresses.insert(socket_addr);
                bootstrap_addr_sets.push(vec![multiaddr.clone()]);
            }
        }

        // Supplement with cached bootstrap peers (after CLI peers)
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            let cached_peers = manager.select_peers(BOOTSTRAP_PEER_BATCH_SIZE).await;
            if !cached_peers.is_empty() {
                let mut added_from_cache = 0;
                for cached in cached_peers {
                    let mut addrs = vec![cached.primary_address];
                    addrs.extend(cached.addresses);
                    // Only add addresses we haven't seen from CLI peers
                    let new_addresses: Vec<MultiAddr> = addrs
                        .into_iter()
                        .filter(|a| !seen_addresses.contains(a))
                        .map(MultiAddr::quic)
                        .collect();

                    if !new_addresses.is_empty() {
                        for addr in &new_addresses {
                            if let Some(sa) = addr.socket_addr() {
                                seen_addresses.insert(sa);
                            }
                        }
                        bootstrap_addr_sets.push(new_addresses);
                        added_from_cache += 1;
                    }
                }
                if added_from_cache > 0 {
                    info!(
                        "Added {} cached bootstrap peers (supplementing CLI peers)",
                        added_from_cache
                    );
                    used_cache = true;
                }
            }
        }

        if bootstrap_addr_sets.is_empty() {
            info!("No bootstrap peers configured and no cached peers available");
            return Ok(());
        }

        // Connect to bootstrap peers, wait for identity exchange, then
        // perform DHT peer discovery using the real cryptographic PeerIds.
        let identity_timeout = Duration::from_secs(BOOTSTRAP_IDENTITY_TIMEOUT_SECS);
        let mut successful_connections = 0;
        let mut connected_peer_ids: Vec<PeerId> = Vec::new();

        for addrs in &bootstrap_addr_sets {
            for addr in addrs {
                match self.connect_peer(addr).await {
                    Ok(channel_id) => {
                        // Wait for the remote peer's signed identity announce
                        // so we get a real cryptographic PeerId.
                        match self
                            .transport
                            .wait_for_peer_identity(&channel_id, identity_timeout)
                            .await
                        {
                            Ok(real_peer_id) => {
                                successful_connections += 1;
                                connected_peer_ids.push(real_peer_id);

                                // Update bootstrap cache with successful connection
                                if let Some(ref bootstrap_manager) = self.bootstrap_manager {
                                    let manager = bootstrap_manager.read().await;
                                    if let Some(sa) = addr.socket_addr() {
                                        manager.record_success(&sa, 100).await;
                                    }
                                }
                                break; // Successfully connected, move to next peer
                            }
                            Err(e) => {
                                warn!(
                                    "Timeout waiting for identity from bootstrap peer {}: {}, \
                                     closing channel {}",
                                    addr, e, channel_id
                                );
                                self.disconnect_channel(&channel_id).await;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to connect to bootstrap peer {}: {}", addr, e);

                        // Update bootstrap cache with failed connection
                        if used_cache && let Some(ref bootstrap_manager) = self.bootstrap_manager {
                            let manager = bootstrap_manager.read().await;
                            if let Some(sa) = addr.socket_addr() {
                                manager.record_failure(&sa).await;
                            }
                        }
                    }
                }
            }
        }

        if successful_connections == 0 {
            // Outbound connections failed — but for nodes behind symmetric NAT,
            // the bootstrap peer may have already connected INBOUND to us.
            // Wait briefly and check if we have any transport-level connections.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let transport_peers = self.transport.connected_peers().await;
            if !transport_peers.is_empty() {
                info!(
                    "No outbound bootstrap succeeded, but {} inbound peer(s) connected — proceeding with DHT bootstrap",
                    transport_peers.len()
                );
                connected_peer_ids = transport_peers;
                successful_connections = connected_peer_ids.len();
            } else {
                if !used_cache {
                    warn!("Failed to connect to any bootstrap peers");
                }
                // Starting a node should not be gated on immediate bootstrap connectivity.
                // Keep running and allow background discovery / retries to populate peers later.
                return Ok(());
            }
        }

        info!(
            "Successfully connected to {} bootstrap peers",
            successful_connections
        );

        // Perform DHT peer discovery from connected bootstrap peers.
        match self
            .dht_manager()
            .bootstrap_from_peers(&connected_peer_ids)
            .await
        {
            Ok(count) => info!("DHT peer discovery found {} peers", count),
            Err(e) => warn!("DHT peer discovery failed: {}", e),
        }

        // Perform two consecutive self-lookups to fully refresh the close
        // neighborhood. The second lookup may discover peers that joined or
        // became reachable during the first lookup (Section 11.2 step 5).
        const SELF_LOOKUP_ROUNDS: u8 = 2;
        for i in 1..=SELF_LOOKUP_ROUNDS {
            if let Err(e) = self.dht_manager().trigger_self_lookup().await {
                warn!("Post-bootstrap self-lookup {i}/{SELF_LOOKUP_ROUNDS} failed: {e}");
            } else {
                debug!("Post-bootstrap self-lookup {i}/{SELF_LOOKUP_ROUNDS} completed");
            }
        }

        // Mark node as bootstrapped - we have connected to bootstrap peers
        // and initiated peer discovery
        self.is_bootstrapped.store(true, Ordering::SeqCst);
        info!(
            "Bootstrap complete: connected to {} peers, initiated {} discovery requests",
            successful_connections,
            connected_peer_ids.len()
        );

        // Save close group cache after initial bootstrap so a crash before
        // graceful shutdown still preserves the newly-discovered close group.
        if let Some(ref dir) = self.config.close_group_cache_dir
            && let Err(e) = self.save_close_group_cache(dir).await
        {
            warn!("Failed to save close group cache after bootstrap: {e}");
        }

        Ok(())
    }

    /// Persist the current close group peers and their trust scores to disk.
    async fn save_close_group_cache(&self, dir: &Path) -> anyhow::Result<()> {
        let key: crate::dht::Key = *self.peer_id.as_bytes();
        let k_value = self.config.dht_config.k_value;
        let close_group = self
            .dht_manager()
            .find_closest_nodes_local(&key, k_value)
            .await;

        if close_group.is_empty() {
            debug!("No close group peers to save");
            return Ok(());
        }

        let trust_engine = self.adaptive_dht.trust_engine();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let peers: Vec<CachedCloseGroupPeer> = close_group
            .into_iter()
            .filter_map(|dht_node| {
                let score = trust_engine.score(&dht_node.peer_id);
                // Guard against NaN/Infinity — serde_json cannot round-trip
                // non-finite f64 values, which would corrupt the cache file.
                if !score.is_finite() {
                    return None;
                }
                Some(CachedCloseGroupPeer {
                    peer_id: dht_node.peer_id,
                    addresses: dht_node.addresses,
                    trust: TrustRecord {
                        score,
                        last_updated_epoch_secs: now_epoch,
                    },
                })
            })
            .collect();

        let peer_count = peers.len();
        let cache = CloseGroupCache {
            peers,
            saved_at_epoch_secs: now_epoch,
        };

        cache.save_to_dir(dir).await?;
        info!(
            "Saved {} close group peers to cache in {}",
            peer_count,
            dir.display()
        );
        Ok(())
    }

    // disconnect_all_peers and periodic_tasks are now in TransportHandle
}

/// Network sender trait for sending messages
#[async_trait::async_trait]
#[allow(dead_code)]
pub trait NetworkSender: Send + Sync {
    /// Send a message to an authenticated peer.
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()>;

    /// Get our local peer ID (cryptographic identity).
    fn local_peer_id(&self) -> PeerId;
}

// P2PNetworkSender removed — NetworkSender is now implemented directly on TransportHandle.
// NodeBuilder removed — use NodeConfigBuilder + P2PNode::new() instead.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod diversity_tests {
    use super::*;
    use crate::security::IPDiversityConfig;

    async fn build_bootstrap_manager_like_prod(config: &NodeConfig) -> BootstrapManager {
        // Use a temp dir to avoid conflicts with cached files from old format
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let mut bootstrap_config = config.bootstrap_cache_config.clone().unwrap_or_default();
        bootstrap_config.cache_dir = temp_dir.path().to_path_buf();

        BootstrapManager::with_node_config(bootstrap_config, config)
            .await
            .expect("bootstrap manager")
    }

    #[tokio::test]
    async fn test_nodeconfig_diversity_config_used_for_bootstrap() {
        let config = NodeConfig {
            diversity_config: Some(IPDiversityConfig::testnet()),
            ..Default::default()
        };

        let manager = build_bootstrap_manager_like_prod(&config).await;
        // Verify testnet config has permissive IP limits
        assert_eq!(manager.diversity_config().max_per_ip, Some(usize::MAX));
        assert_eq!(manager.diversity_config().max_per_subnet, Some(usize::MAX));
    }
}

/// Helper function to register a new channel
pub(crate) async fn register_new_channel(
    peers: &Arc<RwLock<HashMap<String, PeerInfo>>>,
    channel_id: &str,
    remote_addr: &MultiAddr,
) {
    let mut peers_guard = peers.write().await;
    let peer_info = PeerInfo {
        channel_id: channel_id.to_owned(),
        addresses: vec![remote_addr.clone()],
        connected_at: tokio::time::Instant::now(),
        last_seen: tokio::time::Instant::now(),
        status: ConnectionStatus::Connected,
        protocols: vec!["p2p-core/1.0.0".to_string()],
        heartbeat_count: 0,
    };
    peers_guard.insert(channel_id.to_owned(), peer_info);
}

#[cfg(test)]
mod tests {
    use super::*;
    // MCP removed from tests
    use std::time::Duration;
    use tokio::time::timeout;

    /// 2 MiB — used in builder tests to verify max_message_size configuration.
    const TEST_MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

    // Test tool handler for network tests

    // MCP removed

    /// Helper function to create a test node configuration
    fn create_test_node_config() -> NodeConfig {
        NodeConfig {
            local: true,
            port: 0,
            ipv6: true,
            bootstrap_peers: vec![],
            connection_timeout: Duration::from_secs(2),
            max_connections: 100,
            dht_config: DHTConfig::default(),
            bootstrap_cache_config: None,
            diversity_config: None,
            max_message_size: None,
            node_identity: None,
            mode: NodeMode::default(),
            custom_user_agent: None,
            allow_loopback: true,
            adaptive_dht_config: AdaptiveDhtConfig::default(),
            close_group_cache_dir: None,
        }
    }

    /// Helper function to create a test tool
    // MCP removed: test tool helper deleted

    #[tokio::test]
    async fn test_node_config_default() {
        let config = NodeConfig::default();

        assert_eq!(config.listen_addrs().len(), 2); // IPv4 + IPv6
        assert_eq!(config.max_connections, 10000);
        assert_eq!(config.connection_timeout, Duration::from_secs(25));
    }

    #[tokio::test]
    async fn test_dht_config_default() {
        let config = DHTConfig::default();

        assert_eq!(config.k_value, 20);
        assert_eq!(config.alpha_value, 3);
        assert_eq!(config.refresh_interval, Duration::from_secs(600));
    }

    #[test]
    fn test_connection_status_variants() {
        let connecting = ConnectionStatus::Connecting;
        let connected = ConnectionStatus::Connected;
        let disconnecting = ConnectionStatus::Disconnecting;
        let disconnected = ConnectionStatus::Disconnected;
        let failed = ConnectionStatus::Failed("test error".to_string());

        assert_eq!(connecting, ConnectionStatus::Connecting);
        assert_eq!(connected, ConnectionStatus::Connected);
        assert_eq!(disconnecting, ConnectionStatus::Disconnecting);
        assert_eq!(disconnected, ConnectionStatus::Disconnected);
        assert_ne!(connecting, connected);

        if let ConnectionStatus::Failed(msg) = failed {
            assert_eq!(msg, "test error");
        } else {
            panic!("Expected Failed status");
        }
    }

    #[tokio::test]
    async fn test_node_creation() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // PeerId is derived from the cryptographic identity (32-byte BLAKE3 hash)
        assert_eq!(node.peer_id().to_hex().len(), 64);
        assert!(!node.is_running());
        assert_eq!(node.peer_count().await, 0);
        assert!(node.connected_peers().await.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_node_lifecycle() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Initially not running
        assert!(!node.is_running());

        // Start the node
        node.start().await?;
        assert!(node.is_running());

        // Check listen addresses were set (at least one)
        let listen_addrs = node.listen_addrs().await;
        assert!(
            !listen_addrs.is_empty(),
            "Expected at least one listening address"
        );

        // Stop the node
        node.stop().await?;
        assert!(!node.is_running());

        Ok(())
    }

    #[tokio::test]
    async fn test_peer_connection() -> Result<()> {
        let config1 = create_test_node_config();
        let config2 = create_test_node_config();

        let node1 = P2PNode::new(config1).await?;
        let node2 = P2PNode::new(config2).await?;

        node1.start().await?;
        node2.start().await?;

        let node2_addr = node2
            .listen_addrs()
            .await
            .into_iter()
            .find(|a| a.is_ipv4())
            .ok_or_else(|| {
                P2PError::Network(crate::error::NetworkError::InvalidAddress(
                    "Node 2 did not expose an IPv4 listen address".into(),
                ))
            })?;

        // Connect to a real peer (unsigned — no node_identity configured).
        // connect_peer returns a transport-level channel ID (String), not a PeerId.
        let channel_id = node1.connect_peer(&node2_addr).await?;

        // Unauthenticated connections don't appear in the app-level peer maps.
        // Verify transport-level tracking via is_connection_active / peers map.
        assert!(node1.is_connection_active(&channel_id).await);

        // Get peer info from the transport-level peers map (keyed by channel ID)
        let peer_info = node1.transport.peer_info_by_channel(&channel_id).await;
        assert!(peer_info.is_some());
        let info = peer_info.expect("Peer info should exist after connect");
        assert_eq!(info.channel_id, channel_id);
        assert_eq!(info.status, ConnectionStatus::Connected);
        assert!(info.protocols.contains(&"p2p-foundation/1.0".to_string()));

        // Disconnect the channel
        node1.remove_channel(&channel_id).await;
        assert!(!node1.is_connection_active(&channel_id).await);

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_connect_peer_rejects_tcp_multiaddr() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let tcp_addr: MultiAddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let result = node.connect_peer(&tcp_addr).await;

        assert!(
            matches!(
                result,
                Err(P2PError::Network(
                    crate::error::NetworkError::InvalidAddress(_)
                ))
            ),
            "TCP multiaddrs should be rejected before a QUIC dial is attempted, got: {:?}",
            result
        );

        Ok(())
    }

    // TODO(windows): Investigate QUIC connection issues on Windows CI
    // This test consistently fails on Windows GitHub Actions runners with
    // "All connect attempts failed" even with IPv4-only config, long delays,
    // and multiple retry attempts. The underlying saorsa-transport library may have
    // issues on Windows that need investigation.
    // See: https://github.com/dirvine/saorsa-core/issues/TBD
    #[cfg_attr(target_os = "windows", ignore)]
    #[tokio::test]
    async fn test_event_subscription() -> Result<()> {
        // PeerConnected/PeerDisconnected only fire for authenticated peers
        // (nodes with node_identity that send signed messages).
        // Configure both nodes with identities so the event subscription test works.
        let identity1 =
            Arc::new(NodeIdentity::generate().expect("should generate identity for test node1"));
        let identity2 =
            Arc::new(NodeIdentity::generate().expect("should generate identity for test node2"));

        let mut config1 = create_test_node_config();
        config1.ipv6 = false;
        config1.node_identity = Some(identity1);

        let node2_peer_id = *identity2.peer_id();
        let mut config2 = create_test_node_config();
        config2.ipv6 = false;
        config2.node_identity = Some(identity2);

        let node1 = P2PNode::new(config1).await?;
        let node2 = P2PNode::new(config2).await?;

        node1.start().await?;
        node2.start().await?;

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Subscribe to node2's events (node2 will receive the signed message)
        let mut events = node2.subscribe_events();

        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect node1 → node2
        let mut channel_id = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
            match timeout(Duration::from_secs(2), node1.connect_peer(&node2_addr)).await {
                Ok(Ok(id)) => {
                    channel_id = Some(id);
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        let channel_id = channel_id.expect("Failed to connect after 3 attempts");

        // Wait for identity exchange to complete via wait_for_peer_identity.
        let target_peer_id = node1
            .wait_for_peer_identity(&channel_id, Duration::from_secs(2))
            .await?;
        assert_eq!(target_peer_id, node2_peer_id);

        // node1 sends a signed message → node2 authenticates → PeerConnected fires on node2
        node1
            .send_message(&target_peer_id, "test-topic", b"hello".to_vec(), &[])
            .await?;

        // Check for PeerConnected event on node2
        let event = timeout(Duration::from_secs(2), async {
            loop {
                match events.recv().await {
                    Ok(P2PEvent::PeerConnected(id, _)) => return Ok(id),
                    Ok(P2PEvent::Message { .. }) => continue, // skip messages
                    Ok(_) => continue,
                    Err(e) => return Err(e),
                }
            }
        })
        .await;
        assert!(event.is_ok(), "Should receive PeerConnected event");
        let connected_peer_id = event.expect("Timed out").expect("Channel error");
        // The connected peer ID should be node1's app-level ID (a valid PeerId)
        assert!(
            connected_peer_id.0.iter().any(|&b| b != 0),
            "PeerConnected should carry a non-zero peer ID"
        );

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    // TODO(windows): Same QUIC connection issues as test_event_subscription
    #[cfg_attr(target_os = "windows", ignore)]
    #[tokio::test]
    async fn test_message_sending() -> Result<()> {
        // Create two nodes (IPv4-only loopback)
        let mut config1 = create_test_node_config();
        config1.ipv6 = false;
        let node1 = P2PNode::new(config1).await?;
        node1.start().await?;

        let mut config2 = create_test_node_config();
        config2.ipv6 = false;
        let node2 = P2PNode::new(config2).await?;
        node2.start().await?;

        // Wait a bit for nodes to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Get actual listening address of node2
        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect node1 to node2
        let channel_id =
            match timeout(Duration::from_millis(500), node1.connect_peer(&node2_addr)).await {
                Ok(res) => res?,
                Err(_) => return Err(P2PError::Network(NetworkError::Timeout)),
            };

        // Wait for identity exchange via wait_for_peer_identity.
        let target_peer_id = node1
            .wait_for_peer_identity(&channel_id, Duration::from_secs(2))
            .await?;
        assert_eq!(target_peer_id, node2.peer_id().clone());

        // Send a message
        let message_data = b"Hello, peer!".to_vec();
        let result = match timeout(
            Duration::from_millis(500),
            node1.send_message(&target_peer_id, "test-protocol", message_data, &[]),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => return Err(P2PError::Network(NetworkError::Timeout)),
        };
        // For now, we'll just check that we don't get a "not connected" error
        // The actual send might fail due to no handler on the other side
        if let Err(e) = &result {
            assert!(!e.to_string().contains("not connected"), "Got error: {}", e);
        }

        // Try to send to non-existent peer
        let non_existent_peer = PeerId::from_bytes([0xFFu8; 32]);
        let result = node1
            .send_message(&non_existent_peer, "test-protocol", vec![], &[])
            .await;
        assert!(result.is_err(), "Sending to non-existent peer should fail");

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_remote_mcp_operations() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // MCP removed; test reduced to simple start/stop
        node.start().await?;
        node.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_health_check() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Health check should pass with no connections
        let result = node.health_check().await;
        assert!(result.is_ok());

        // Note: We're not actually connecting to real peers here
        // since that would require running bootstrap nodes.
        // The health check should still pass with no connections.

        Ok(())
    }

    #[tokio::test]
    async fn test_node_uptime() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let uptime1 = node.uptime();
        assert!(uptime1 >= Duration::from_secs(0));

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(10)).await;

        let uptime2 = node.uptime();
        assert!(uptime2 > uptime1);

        Ok(())
    }

    #[tokio::test]
    async fn test_node_config_access() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let node_config = node.config();
        assert_eq!(node_config.max_connections, 100);
        // MCP removed

        Ok(())
    }

    #[tokio::test]
    async fn test_mcp_server_access() -> Result<()> {
        let config = create_test_node_config();
        let _node = P2PNode::new(config).await?;

        // MCP removed
        Ok(())
    }

    #[tokio::test]
    async fn test_dht_access() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // DHT is always available
        let _dht = node.dht();

        Ok(())
    }

    #[tokio::test]
    async fn test_node_config_builder() -> Result<()> {
        let bootstrap: MultiAddr = "/ip4/127.0.0.1/udp/9000/quic".parse().unwrap();

        let config = NodeConfig::builder()
            .local(true)
            .ipv6(true)
            .bootstrap_peer(bootstrap)
            .connection_timeout(Duration::from_secs(15))
            .max_connections(200)
            .max_message_size(TEST_MAX_MESSAGE_SIZE)
            .build()?;

        assert_eq!(config.listen_addrs().len(), 2); // IPv4 + IPv6
        assert!(config.local);
        assert!(config.ipv6);
        assert_eq!(config.bootstrap_peers.len(), 1);
        assert_eq!(config.connection_timeout, Duration::from_secs(15));
        assert_eq!(config.max_connections, 200);
        assert_eq!(config.max_message_size, Some(TEST_MAX_MESSAGE_SIZE));
        assert!(config.allow_loopback); // auto-enabled by local(true)

        Ok(())
    }

    #[tokio::test]
    async fn test_bootstrap_peers() -> Result<()> {
        let mut config = create_test_node_config();
        config.bootstrap_peers = vec![
            crate::MultiAddr::from_ipv4(std::net::Ipv4Addr::LOCALHOST, 9200),
            crate::MultiAddr::from_ipv4(std::net::Ipv4Addr::LOCALHOST, 9201),
        ];

        let node = P2PNode::new(config).await?;

        // Start node (which attempts to connect to bootstrap peers)
        node.start().await?;

        // In a test environment, bootstrap peers may not be available
        // The test verifies the node starts correctly with bootstrap configuration
        // Peer count may include local/internal tracking, so we just verify it's reasonable
        let _peer_count = node.peer_count().await;

        node.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_info_structure() {
        let peer_info = PeerInfo {
            channel_id: "test_peer".to_string(),
            addresses: vec!["/ip4/127.0.0.1/tcp/9000".parse::<MultiAddr>().unwrap()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        assert_eq!(peer_info.channel_id, "test_peer");
        assert_eq!(peer_info.addresses.len(), 1);
        assert_eq!(peer_info.status, ConnectionStatus::Connected);
        assert_eq!(peer_info.protocols.len(), 1);
    }

    #[tokio::test]
    async fn test_serialization() -> Result<()> {
        // Test that configs can be serialized/deserialized
        let config = create_test_node_config();
        let serialized = serde_json::to_string(&config)?;
        let deserialized: NodeConfig = serde_json::from_str(&serialized)?;

        assert_eq!(config.local, deserialized.local);
        assert_eq!(config.port, deserialized.port);
        assert_eq!(config.ipv6, deserialized.ipv6);
        assert_eq!(config.bootstrap_peers, deserialized.bootstrap_peers);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_channel_id_by_address_found() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Manually insert a peer for testing
        let test_channel_id = "peer_test_123".to_string();
        let test_address = "192.168.1.100:9000";
        let test_multiaddr = MultiAddr::quic(test_address.parse().unwrap());

        let peer_info = PeerInfo {
            channel_id: test_channel_id.clone(),
            addresses: vec![test_multiaddr],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(test_channel_id.clone(), peer_info)
            .await;

        // Test: Find channel by address
        let lookup_addr = MultiAddr::quic(test_address.parse().unwrap());
        let found_channel_id = node.get_channel_id_by_address(&lookup_addr).await;
        assert_eq!(found_channel_id, Some(test_channel_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_channel_id_by_address_not_found() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: Try to find a channel that doesn't exist
        let unknown_addr = MultiAddr::quic("192.168.1.200:9000".parse().unwrap());
        let result = node.get_channel_id_by_address(&unknown_addr).await;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_channel_id_by_address_invalid_format() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: Non-IP address should return None (no matching socket addr)
        let ble_addr = MultiAddr::new(crate::address::TransportAddr::Ble {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            psm: 0x0025,
        });
        let result = node.get_channel_id_by_address(&ble_addr).await;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_channel_id_by_address_multiple_peers() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add multiple peers with different addresses
        let peer1_id = "peer_1".to_string();
        let peer1_addr_str = "192.168.1.101:9001";
        let peer1_multiaddr = MultiAddr::quic(peer1_addr_str.parse().unwrap());

        let peer2_id = "peer_2".to_string();
        let peer2_addr_str = "192.168.1.102:9002";
        let peer2_multiaddr = MultiAddr::quic(peer2_addr_str.parse().unwrap());

        let peer1_info = PeerInfo {
            channel_id: peer1_id.clone(),
            addresses: vec![peer1_multiaddr],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        let peer2_info = PeerInfo {
            channel_id: peer2_id.clone(),
            addresses: vec![peer2_multiaddr],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(peer1_id.clone(), peer1_info)
            .await;
        node.transport
            .inject_peer(peer2_id.clone(), peer2_info)
            .await;

        // Test: Find each channel by their unique address
        let found_peer1 = node
            .get_channel_id_by_address(&MultiAddr::quic(peer1_addr_str.parse().unwrap()))
            .await;
        let found_peer2 = node
            .get_channel_id_by_address(&MultiAddr::quic(peer2_addr_str.parse().unwrap()))
            .await;

        assert_eq!(found_peer1, Some(peer1_id));
        assert_eq!(found_peer2, Some(peer2_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_list_active_connections_empty() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: No connections initially
        let connections = node.list_active_connections().await;
        assert!(connections.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_list_active_connections_with_peers() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add multiple peers
        let peer1_id = "peer_1".to_string();
        let peer1_addrs = vec![
            MultiAddr::quic("192.168.1.101:9001".parse().unwrap()),
            MultiAddr::quic("192.168.1.101:9002".parse().unwrap()),
        ];

        let peer2_id = "peer_2".to_string();
        let peer2_addrs = vec![MultiAddr::quic("192.168.1.102:9003".parse().unwrap())];

        let peer1_info = PeerInfo {
            channel_id: peer1_id.clone(),
            addresses: peer1_addrs.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        let peer2_info = PeerInfo {
            channel_id: peer2_id.clone(),
            addresses: peer2_addrs.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(peer1_id.clone(), peer1_info)
            .await;
        node.transport
            .inject_peer(peer2_id.clone(), peer2_info)
            .await;

        // Also add to active_connections (list_active_connections iterates over this)
        node.transport
            .inject_active_connection(peer1_id.clone())
            .await;
        node.transport
            .inject_active_connection(peer2_id.clone())
            .await;

        // Test: List all active connections
        let connections = node.list_active_connections().await;
        assert_eq!(connections.len(), 2);

        // Verify peer1 and peer2 are in the list
        let peer1_conn = connections.iter().find(|(id, _)| id == &peer1_id);
        let peer2_conn = connections.iter().find(|(id, _)| id == &peer2_id);

        assert!(peer1_conn.is_some());
        assert!(peer2_conn.is_some());

        // Verify addresses match
        assert_eq!(peer1_conn.unwrap().1, peer1_addrs);
        assert_eq!(peer2_conn.unwrap().1, peer2_addrs);

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_channel_success() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add a peer
        let channel_id = "peer_to_remove".to_string();
        let channel_peer_id = PeerId::from_name(&channel_id);
        let peer_info = PeerInfo {
            channel_id: channel_id.clone(),
            addresses: vec![MultiAddr::quic("192.168.1.100:9000".parse().unwrap())],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(channel_id.clone(), peer_info)
            .await;
        node.transport
            .inject_peer_to_channel(channel_peer_id, channel_id.clone())
            .await;

        // Verify peer exists
        assert!(node.is_peer_connected(&channel_peer_id).await);

        // Remove the channel
        let removed = node.remove_channel(&channel_id).await;
        assert!(removed);

        // Verify peer no longer exists
        assert!(!node.is_peer_connected(&channel_peer_id).await);

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_channel_nonexistent() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Try to remove a channel that doesn't exist
        let removed = node.remove_channel("nonexistent_peer").await;
        assert!(!removed);

        Ok(())
    }

    #[tokio::test]
    async fn test_is_peer_connected() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let channel_id = "test_peer".to_string();
        let channel_peer_id = PeerId::from_name(&channel_id);

        // Initially not connected
        assert!(!node.is_peer_connected(&channel_peer_id).await);

        // Add peer
        let peer_info = PeerInfo {
            channel_id: channel_id.clone(),
            addresses: vec![MultiAddr::quic("192.168.1.100:9000".parse().unwrap())],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(channel_id.clone(), peer_info)
            .await;
        node.transport
            .inject_peer_to_channel(channel_peer_id, channel_id.clone())
            .await;

        // Now connected
        assert!(node.is_peer_connected(&channel_peer_id).await);

        // Remove channel
        node.remove_channel(&channel_id).await;

        // No longer connected
        assert!(!node.is_peer_connected(&channel_peer_id).await);

        Ok(())
    }

    #[test]
    fn test_normalize_ipv6_wildcard() {
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        let wildcard = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080);
        let normalized = normalize_wildcard_to_loopback(wildcard);

        assert_eq!(normalized.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(normalized.port(), 8080);
    }

    #[test]
    fn test_normalize_ipv4_wildcard() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);
        let normalized = normalize_wildcard_to_loopback(wildcard);

        assert_eq!(normalized.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(normalized.port(), 9000);
    }

    #[test]
    fn test_normalize_specific_address_unchanged() {
        let specific: std::net::SocketAddr = "192.168.1.100:3000".parse().unwrap();
        let normalized = normalize_wildcard_to_loopback(specific);

        assert_eq!(normalized, specific);
    }

    #[test]
    fn test_normalize_loopback_unchanged() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5000);
        let normalized_v6 = normalize_wildcard_to_loopback(loopback_v6);
        assert_eq!(normalized_v6, loopback_v6);

        let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let normalized_v4 = normalize_wildcard_to_loopback(loopback_v4);
        assert_eq!(normalized_v4, loopback_v4);
    }

    // ---- parse_protocol_message regression tests ----

    /// Get current Unix timestamp for tests
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Helper to create a postcard-serialized WireMessage for tests
    fn make_wire_bytes(protocol: &str, data: Vec<u8>, from: &str, timestamp: u64) -> Vec<u8> {
        let msg = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: PeerId::from_name(from),
            timestamp,
            user_agent: String::new(),
            public_key: Vec::new(),
            signature: Vec::new(),
        };
        postcard::to_stdvec(&msg).unwrap()
    }

    #[test]
    fn test_parse_protocol_message_uses_transport_peer_id_as_source() {
        // Regression: For unsigned messages, P2PEvent::Message.source must be the
        // transport peer ID, NOT the "from" field from the wire message.
        let transport_id = "abcdef0123456789";
        let logical_id = "spoofed-logical-id";
        let bytes = make_wire_bytes("test/v1", vec![1, 2, 3], logical_id, current_timestamp());

        let parsed =
            parse_protocol_message(&bytes, transport_id).expect("valid message should parse");

        // Unsigned message: no authenticated node ID
        assert!(parsed.authenticated_node_id.is_none());

        match parsed.event {
            P2PEvent::Message {
                topic,
                source,
                data,
            } => {
                assert!(source.is_none(), "unsigned message source must be None");
                assert_eq!(topic, "test/v1");
                assert_eq!(data, vec![1u8, 2, 3]);
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_protocol_message_rejects_invalid_bytes() {
        // Random bytes that are not valid bincode should be rejected
        assert!(parse_protocol_message(b"not valid bincode", "peer-id").is_none());
    }

    #[test]
    fn test_parse_protocol_message_rejects_truncated_message() {
        // A truncated bincode message should fail to deserialize
        let full_bytes = make_wire_bytes("test/v1", vec![1, 2, 3], "sender", current_timestamp());
        let truncated = &full_bytes[..full_bytes.len() / 2];
        assert!(parse_protocol_message(truncated, "peer-id").is_none());
    }

    #[test]
    fn test_parse_protocol_message_empty_payload() {
        let bytes = make_wire_bytes("ping", vec![], "sender", current_timestamp());

        let parsed = parse_protocol_message(&bytes, "transport-peer")
            .expect("valid message with empty data should parse");

        match parsed.event {
            P2PEvent::Message { data, .. } => assert!(data.is_empty()),
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_protocol_message_preserves_binary_payload() {
        // Verify that arbitrary byte values (including 0xFF, 0x00) survive round-trip
        let payload: Vec<u8> = (0..=255).collect();
        let bytes = make_wire_bytes("binary/v1", payload.clone(), "sender", current_timestamp());

        let parsed = parse_protocol_message(&bytes, "peer-id")
            .expect("valid message with full byte range should parse");

        match parsed.event {
            P2PEvent::Message { data, topic, .. } => {
                assert_eq!(topic, "binary/v1");
                assert_eq!(
                    data, payload,
                    "payload must survive bincode round-trip exactly"
                );
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_signed_message_verifies_and_uses_node_id() {
        let identity = NodeIdentity::generate().expect("should generate identity");
        let protocol = "test/signed";
        let data: Vec<u8> = vec![10, 20, 30];
        // The `from` field must match the PeerId derived from the public key.
        let from = *identity.peer_id();
        let timestamp = current_timestamp();
        let user_agent = "test/1.0";

        // Compute signable bytes the same way create_protocol_message does
        let signable =
            postcard::to_stdvec(&(protocol, data.as_slice(), &from, timestamp, user_agent))
                .unwrap();
        let sig = identity.sign(&signable).expect("signing should succeed");

        let msg = WireMessage {
            protocol: protocol.to_string(),
            data: data.clone(),
            from,
            timestamp,
            user_agent: user_agent.to_string(),
            public_key: identity.public_key().as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();

        let parsed =
            parse_protocol_message(&bytes, "transport-xyz").expect("signed message should parse");

        let expected_peer_id = *identity.peer_id();
        assert_eq!(
            parsed.authenticated_node_id.as_ref(),
            Some(&expected_peer_id)
        );

        match parsed.event {
            P2PEvent::Message { source, .. } => {
                assert_eq!(
                    source.as_ref(),
                    Some(&expected_peer_id),
                    "source should be the verified PeerId"
                );
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_message_with_bad_signature_is_rejected() {
        let identity = NodeIdentity::generate().expect("should generate identity");
        let protocol = "test/bad-sig";
        let data: Vec<u8> = vec![1, 2, 3];
        let from = *identity.peer_id();
        let timestamp = current_timestamp();
        let user_agent = "test/1.0";

        // Sign correct signable bytes
        let signable =
            postcard::to_stdvec(&(protocol, data.as_slice(), &from, timestamp, user_agent))
                .unwrap();
        let sig = identity.sign(&signable).expect("signing should succeed");

        // Tamper with the data (signature was over [1,2,3], not [99,99,99])
        let msg = WireMessage {
            protocol: protocol.to_string(),
            data: vec![99, 99, 99],
            from,
            timestamp,
            user_agent: user_agent.to_string(),
            public_key: identity.public_key().as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();

        assert!(
            parse_protocol_message(&bytes, "transport-xyz").is_none(),
            "message with bad signature should be rejected"
        );
    }

    #[test]
    fn test_parse_message_with_mismatched_from_is_rejected() {
        let identity = NodeIdentity::generate().expect("should generate identity");
        let protocol = "test/from-mismatch";
        let data: Vec<u8> = vec![1, 2, 3];
        // Use a `from` field that does NOT match the public key's PeerId.
        let fake_from = PeerId::from_bytes([0xDE; 32]);
        let timestamp = current_timestamp();
        let user_agent = "test/1.0";

        let signable =
            postcard::to_stdvec(&(protocol, data.as_slice(), &fake_from, timestamp, user_agent))
                .unwrap();
        let sig = identity.sign(&signable).expect("signing should succeed");

        let msg = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: fake_from,
            timestamp,
            user_agent: user_agent.to_string(),
            public_key: identity.public_key().as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();

        assert!(
            parse_protocol_message(&bytes, "transport-xyz").is_none(),
            "message with mismatched from field should be rejected"
        );
    }
}
