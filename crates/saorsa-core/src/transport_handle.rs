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

//! Transport handle module
//!
//! Encapsulates transport-level concerns (QUIC connections, peer registry,
//! message I/O, events) extracted from [`P2PNode`] to enable sharing between
//! `P2PNode` and [`DhtNetworkManager`] without coupling to the full node.

use crate::MultiAddr;
use crate::PeerId;
use crate::bgp_geo_provider::BgpGeoProvider;
use crate::error::{NetworkError, P2PError, P2pResult as Result};
use crate::identity::node_identity::{NodeIdentity, peer_id_from_public_key};
use crate::network::{
    ConnectionStatus, MAX_ACTIVE_REQUESTS, MAX_REQUEST_TIMEOUT, MESSAGE_RECV_CHANNEL_CAPACITY,
    NetworkSender, P2PEvent, ParsedMessage, PeerInfo, PeerResponse, PendingRequest,
    RequestResponseEnvelope, WireMessage, broadcast_event, normalize_wildcard_to_loopback,
    parse_protocol_message, register_new_channel,
};
use crate::quantum_crypto::saorsa_transport_integration::MlDsaPublicKey;
use crate::transport::observed_address_cache::ObservedAddressCache;
use crate::transport::saorsa_transport_adapter::{ConnectionEvent, DualStackNetworkNode};
use crate::validation::{RateLimitConfig, RateLimiter};

use saorsa_transport::crypto::raw_public_keys::extract_public_key_from_spki;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Notify, RwLock, broadcast};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

// Test configuration defaults (used by `new_for_tests()` which is available in all builds)
const TEST_EVENT_CHANNEL_CAPACITY: usize = 16;
const TEST_MAX_REQUESTS: u32 = 100;
const TEST_BURST_SIZE: u32 = 100;
const TEST_RATE_LIMIT_WINDOW_SECS: u64 = 1;
const TEST_CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Configuration for transport initialization, derived from [`NodeConfig`](crate::network::NodeConfig).
pub struct TransportConfig {
    /// Addresses to bind on. The transport partitions these into at most
    /// one IPv4 and one IPv6 QUIC endpoint.
    pub listen_addrs: Vec<MultiAddr>,
    /// Connection timeout for outbound dials and sends.
    pub connection_timeout: Duration,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Broadcast channel capacity for P2P events.
    pub event_channel_capacity: usize,
    /// Optional override for the maximum application-layer message size.
    ///
    /// When `None`, saorsa-transport's built-in default is used. Set this to tune
    /// the QUIC stream receive window and the
    /// per-stream read buffer for larger or smaller payloads.
    pub max_message_size: Option<usize>,
    /// Cryptographic node identity (ML-DSA-65). The canonical peer ID is
    /// derived from this identity's public key hash.
    pub node_identity: Arc<NodeIdentity>,
    /// User agent string identifying this node's software.
    pub user_agent: String,
    /// Allow loopback addresses in the transport layer.
    pub allow_loopback: bool,
}

impl TransportConfig {
    /// Build transport config directly from the node's canonical config.
    pub fn from_node_config(
        config: &crate::network::NodeConfig,
        event_channel_capacity: usize,
        node_identity: Arc<NodeIdentity>,
    ) -> Self {
        Self {
            listen_addrs: config.listen_addrs(),
            connection_timeout: config.connection_timeout,
            max_connections: config.max_connections,
            event_channel_capacity,
            max_message_size: config.max_message_size,
            node_identity,
            user_agent: config.user_agent(),
            allow_loopback: config.allow_loopback,
        }
    }
}

/// Encapsulates transport-level concerns: QUIC connections, peer registry,
/// message I/O, and network events.
///
/// Both [`P2PNode`](crate::network::P2PNode) and
/// [`DhtNetworkManager`](crate::dht_network_manager::DhtNetworkManager)
/// hold `Arc<TransportHandle>` so they share the same transport state.
pub struct TransportHandle {
    dual_node: Arc<DualStackNetworkNode>,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    active_connections: Arc<RwLock<HashSet<String>>>,
    event_tx: broadcast::Sender<P2PEvent>,
    listen_addrs: RwLock<Vec<MultiAddr>>,
    rate_limiter: Arc<RateLimiter>,
    active_requests: Arc<RwLock<HashMap<String, PendingRequest>>>,
    // Held to keep the Arc alive for background tasks that captured a clone.
    #[allow(dead_code)]
    geo_provider: Arc<BgpGeoProvider>,
    shutdown: CancellationToken,
    /// Peer address updates from ADD_ADDRESS frames (relay address advertisement).
    ///
    /// Bounded mpsc — see
    /// [`crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY`].
    /// The producer (`spawn_peer_address_update_forwarder`) drops events
    /// rather than blocking when the consumer is slow.
    peer_address_update_rx:
        tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(SocketAddr, SocketAddr)>>,
    /// Relay established events — received when this node sets up a MASQUE relay.
    ///
    /// Bounded mpsc with the same drop semantics as
    /// `peer_address_update_rx`.
    relay_established_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<SocketAddr>>,
    /// Frequency- and recency-aware cache of externally-observed addresses.
    /// Populated by the address-update forwarder from
    /// `P2pEvent::ExternalAddressDiscovered` frames; consulted as a fallback
    /// by [`Self::observed_external_address`] when no live connection has
    /// an observation. Survives connection drops; reset on process restart.
    observed_address_cache: Arc<parking_lot::Mutex<ObservedAddressCache>>,
    connection_timeout: Duration,
    connection_monitor_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    recv_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    listener_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Cryptographic node identity for signing outgoing messages.
    node_identity: Arc<NodeIdentity>,
    /// User agent string included in every outgoing wire message.
    user_agent: String,
    /// Maps app-level [`PeerId`] → set of channel IDs (QUIC, Bluetooth, …).
    ///
    /// A single peer may communicate over multiple channels simultaneously.
    /// Populated synchronously when a `ConnectionEvent::Established` arrives —
    /// the peer's identity is derived from the TLS-authenticated SPKI carried
    /// in the event, so the entry is ready before any application bytes flow.
    peer_to_channel: Arc<RwLock<HashMap<PeerId, HashSet<String>>>>,
    /// Reverse index: channel ID → authenticated app-level [`PeerId`].
    ///
    /// One channel maps to exactly one peer because TLS authenticates a single
    /// identity per QUIC connection. The previous `HashSet<PeerId>` shape was
    /// a vestige of the now-retired identity-announce protocol.
    channel_to_peer: Arc<RwLock<HashMap<String, PeerId>>>,
    /// Maps app-level [`PeerId`] → user agent string received from a signed
    /// application message.
    ///
    /// Lazy: TLS doesn't carry a user-agent string, so this map stays empty
    /// until the first signed wire message from the peer is parsed. Late
    /// subscribers fall back to "node/unknown" until then.
    peer_user_agents: Arc<RwLock<HashMap<PeerId, String>>>,
    /// Wakes [`Self::wait_for_peer_identity`] callers whenever a new
    /// `channel_to_peer` entry is inserted.
    ///
    /// `notify_waiters` is broadcast on every insert; callers re-check the map
    /// after each wake. Inserts happen at the moment a TLS-authenticated
    /// connection is established, so a waiter typically returns within a few
    /// scheduler ticks of the underlying QUIC handshake completing.
    identity_notify: Arc<Notify>,
}

// ============================================================================
// Construction
// ============================================================================

impl TransportHandle {
    /// Create a new transport handle with the given configuration.
    ///
    /// This performs the transport-level initialization that was previously
    /// embedded in `P2PNode::new()`: dual-stack QUIC binding, rate limiter,
    /// GeoIP provider, and a background connection lifecycle monitor.
    pub async fn new(config: TransportConfig) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(config.event_channel_capacity);

        // Initialize dual-stack saorsa-transport nodes
        // Partition listen addresses into first IPv4 and first IPv6 for
        // dual-stack binding. Non-IP addresses are skipped.
        let mut v4_opt: Option<SocketAddr> = None;
        let mut v6_opt: Option<SocketAddr> = None;
        for addr in &config.listen_addrs {
            if let Some(sa) = addr.dialable_socket_addr() {
                match sa.ip() {
                    std::net::IpAddr::V4(_) if v4_opt.is_none() => v4_opt = Some(sa),
                    std::net::IpAddr::V6(_) if v6_opt.is_none() => v6_opt = Some(sa),
                    _ => {} // already have one for this family
                }
            }
        }

        // Install the node's NodeIdentity as the transport's TLS keypair so
        // the SPKI carried in every QUIC handshake authenticates the same
        // peer ID that signs application messages. The lifecycle monitor
        // depends on this equality to register peers synchronously without a
        // separate identity-announce round trip.
        let tls_keypair = config.node_identity.clone_keypair();
        let dual_node = Arc::new(
            DualStackNetworkNode::new_with_options(
                v6_opt,
                v4_opt,
                config.max_connections,
                config.max_message_size,
                config.allow_loopback,
                Some(tls_keypair),
            )
            .await
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::SetupFailed(
                    format!("Failed to create dual-stack network nodes: {}", e).into(),
                ))
            })?,
        );

        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
        let active_connections = Arc::new(RwLock::new(HashSet::new()));
        let geo_provider = Arc::new(BgpGeoProvider::new());
        let peers = Arc::new(RwLock::new(HashMap::new()));

        let shutdown = CancellationToken::new();

        // Cache for externally-observed addresses. The forwarder spawned
        // below feeds this cache from `P2pEvent::ExternalAddressDiscovered`
        // events; the cache becomes the fallback for
        // `observed_external_address()` when no live connection has an
        // observation (see TransportHandle::observed_external_address).
        let observed_address_cache = Arc::new(parking_lot::Mutex::new(ObservedAddressCache::new()));

        // Subscribe to address-related P2pEvents from the transport layer:
        //   - PeerAddressUpdated → mpsc, drained by the DHT bridge
        //   - RelayEstablished → mpsc, drained by the DHT bridge
        //   - ExternalAddressDiscovered → recorded directly into the
        //     observed-address cache above
        let (peer_addr_update_rx, relay_established_rx) =
            dual_node.spawn_peer_address_update_forwarder(Arc::clone(&observed_address_cache));

        // Subscribe to connection events BEFORE spawning the monitor task
        let connection_event_rx = dual_node.subscribe_connection_events();

        let peer_to_channel = Arc::new(RwLock::new(HashMap::new()));
        let channel_to_peer = Arc::new(RwLock::new(HashMap::new()));
        let peer_user_agents: Arc<RwLock<HashMap<PeerId, String>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let identity_notify = Arc::new(Notify::new());
        // (peer_addr_update_tx removed — dedicated forwarder creates its own)

        let connection_monitor_handle = {
            let active_conns = Arc::clone(&active_connections);
            let peers_map = Arc::clone(&peers);
            let event_tx_clone = event_tx.clone();
            let dual_node_clone = Arc::clone(&dual_node);
            let geo_provider_clone = Arc::clone(&geo_provider);
            let shutdown_token = shutdown.clone();
            let p2c = Arc::clone(&peer_to_channel);
            let c2p = Arc::clone(&channel_to_peer);
            let pua = Arc::clone(&peer_user_agents);
            let notify = Arc::clone(&identity_notify);
            let self_peer_id = *config.node_identity.peer_id();

            let handle = tokio::spawn(async move {
                Self::connection_lifecycle_monitor_with_rx(
                    dual_node_clone,
                    connection_event_rx,
                    active_conns,
                    peers_map,
                    event_tx_clone,
                    geo_provider_clone,
                    shutdown_token,
                    p2c,
                    c2p,
                    pua,
                    notify,
                    self_peer_id,
                )
                .await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        Ok(Self {
            dual_node,
            peers,
            active_connections,
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter,
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            geo_provider,
            shutdown,
            peer_address_update_rx: tokio::sync::Mutex::new(peer_addr_update_rx),
            relay_established_rx: tokio::sync::Mutex::new(relay_established_rx),
            observed_address_cache,
            connection_timeout: config.connection_timeout,
            connection_monitor_handle,
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            node_identity: config.node_identity,
            user_agent: config.user_agent,
            peer_to_channel,
            channel_to_peer,
            peer_user_agents,
            identity_notify,
        })
    }

    /// Minimal constructor for tests that avoids real networking.
    pub fn new_for_tests() -> Result<Self> {
        let identity = Arc::new(NodeIdentity::generate().map_err(|e| {
            P2PError::Network(NetworkError::BindError(
                format!("Failed to generate test node identity: {}", e).into(),
            ))
        })?);
        let (event_tx, _) = broadcast::channel(TEST_EVENT_CHANNEL_CAPACITY);
        let dual_node = {
            let v6: Option<SocketAddr> = "[::1]:0"
                .parse()
                .ok()
                .or(Some(SocketAddr::from(([0, 0, 0, 0], 0))));
            let v4: Option<SocketAddr> = "127.0.0.1:0".parse().ok();
            let handle = tokio::runtime::Handle::current();
            let dual_attempt = handle.block_on(DualStackNetworkNode::new(v6, v4));
            let dual = match dual_attempt {
                Ok(d) => d,
                Err(_e1) => {
                    let fallback = handle
                        .block_on(DualStackNetworkNode::new(None, "127.0.0.1:0".parse().ok()));
                    match fallback {
                        Ok(d) => d,
                        Err(e2) => {
                            return Err(P2PError::Network(NetworkError::BindError(
                                format!("Failed to create dual-stack network node: {}", e2).into(),
                            )));
                        }
                    }
                }
            };
            Arc::new(dual)
        };

        Ok(Self {
            dual_node,
            peers: Arc::new(RwLock::new(HashMap::new())),
            active_connections: Arc::new(RwLock::new(HashSet::new())),
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: TEST_MAX_REQUESTS,
                burst_size: TEST_BURST_SIZE,
                window: std::time::Duration::from_secs(TEST_RATE_LIMIT_WINDOW_SECS),
                ..Default::default()
            })),
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            geo_provider: Arc::new(BgpGeoProvider::new()),
            shutdown: CancellationToken::new(),
            peer_address_update_rx: {
                let (_tx, rx) = tokio::sync::mpsc::channel(
                    crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
                );
                tokio::sync::Mutex::new(rx)
            },
            relay_established_rx: {
                let (_tx, rx) = tokio::sync::mpsc::channel(
                    crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
                );
                tokio::sync::Mutex::new(rx)
            },
            observed_address_cache: Arc::new(parking_lot::Mutex::new(ObservedAddressCache::new())),
            connection_timeout: Duration::from_secs(TEST_CONNECTION_TIMEOUT_SECS),
            connection_monitor_handle: Arc::new(RwLock::new(None)),
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            node_identity: identity,
            user_agent: crate::network::user_agent_for_mode(crate::network::NodeMode::Node),
            peer_to_channel: Arc::new(RwLock::new(HashMap::new())),
            channel_to_peer: Arc::new(RwLock::new(HashMap::new())),
            peer_user_agents: Arc::new(RwLock::new(HashMap::new())),
            identity_notify: Arc::new(Notify::new()),
        })
    }
}

// ============================================================================
// Identity & Address Accessors
// ============================================================================

impl TransportHandle {
    /// Get the application-level peer ID (cryptographic identity).
    pub fn peer_id(&self) -> PeerId {
        *self.node_identity.peer_id()
    }

    /// Get the cryptographic node identity.
    pub fn node_identity(&self) -> &Arc<NodeIdentity> {
        &self.node_identity
    }

    /// Get the first listen address as a string.
    pub fn local_addr(&self) -> Option<MultiAddr> {
        self.listen_addrs
            .try_read()
            .ok()
            .and_then(|addrs| addrs.first().cloned())
    }

    /// Get all current listen addresses.
    pub async fn listen_addrs(&self) -> Vec<MultiAddr> {
        self.listen_addrs.read().await.clone()
    }

    /// Returns the node's externally-observed address as reported by peers
    /// (via QUIC `OBSERVED_ADDRESS` frames), or `None` if no peer has ever
    /// observed this node since process start.
    ///
    /// This is the most authoritative source of the node's reflexive
    /// (post-NAT) address — it is the address remote peers actually saw the
    /// connection arrive from. Prefer it over `listen_addrs()` (which only
    /// reflects locally-bound socket addresses) when advertising the node to
    /// the rest of the network.
    ///
    /// ## Resolution order
    ///
    /// 1. **Live**: ask `dual_node.get_observed_external_address()` first.
    ///    This iterates currently-active connections and returns the
    ///    observation from the first one (preferring known/bootstrap peers
    ///    inside saorsa-transport). When at least one connection is up,
    ///    this is always the freshest answer.
    /// 2. **Cache**: if no live connection has an observation (e.g. every
    ///    connection has just dropped during a network blip), fall back to
    ///    the in-memory [`ObservedAddressCache`]. The cache returns the
    ///    most-frequently-observed address among recent entries, breaking
    ///    ties by recency. See `observed_address_cache.rs` for the full
    ///    selection algorithm and rationale.
    ///
    /// The cache is populated by the `ExternalAddressDiscovered` forwarder
    /// spawned in [`Self::new`]; it survives connection drops but is reset
    /// on process restart.
    pub fn observed_external_address(&self) -> Option<SocketAddr> {
        // Prefer the plural accessor's first entry so the single-address
        // path stays consistent with multi-homed publishing.
        self.observed_external_addresses().into_iter().next()
    }

    /// Return **all** externally-observed addresses for this node, one per
    /// local interface that has an observation.
    ///
    /// Resolution order matches [`Self::observed_external_address`]:
    ///
    /// 1. **Live**: query each stack on `dual_node` independently (v4 and
    ///    v6) and collect any address it reports.
    /// 2. **Cache fallback**: for each `(local_bind, observed)` partition
    ///    in the [`ObservedAddressCache`] that has no live observation
    ///    yet, append the cache's per-bind best.
    ///
    /// The returned list is deduped — if the live source and the cache
    /// both report the same address, it appears only once. Order is not
    /// part of the contract; callers that need a specific priority should
    /// sort the result themselves.
    ///
    /// This is the right entry point for publishing the node's self-entry
    /// to the DHT on a multi-homed host: peers reaching the node via any
    /// interface in the returned list will be able to dial back.
    pub fn observed_external_addresses(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self.dual_node.get_observed_external_addresses();
        let cached = self
            .observed_address_cache
            .lock()
            .most_frequent_recent_per_local_bind();
        for addr in cached {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
        out
    }

    /// Returns the cache-only fallback for the observed external address,
    /// bypassing the live `dual_node` read entirely.
    ///
    /// Production code should call [`Self::observed_external_address`]
    /// instead — it prefers the live source and only consults the cache
    /// when no live observation is available. This accessor exists so that
    /// integration tests can poll for cache population without having to
    /// race the periodic poll task in saorsa-transport that drives the
    /// `ExternalAddressDiscovered` event stream.
    pub fn cached_observed_external_address(&self) -> Option<SocketAddr> {
        self.observed_address_cache.lock().most_frequent_recent()
    }

    /// Get the connection timeout duration.
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }
}

// ============================================================================
// Peer Management
// ============================================================================

impl TransportHandle {
    /// Get list of authenticated app-level peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peer_to_channel.read().await.keys().cloned().collect()
    }

    /// Get count of authenticated app-level peers.
    pub async fn peer_count(&self) -> usize {
        self.peer_to_channel.read().await.len()
    }

    /// Get the user agent string for a connected peer, if known.
    pub async fn peer_user_agent(&self, peer_id: &PeerId) -> Option<String> {
        self.peer_user_agents.read().await.get(peer_id).cloned()
    }

    /// Get all active transport-level channel IDs (internal bookkeeping).
    #[allow(dead_code)]
    pub(crate) async fn active_channels(&self) -> Vec<String> {
        self.active_connections
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    /// Get info for a specific peer.
    ///
    /// Resolves the app-level [`PeerId`] to a channel ID via the
    /// `peer_to_channel` mapping, then looks up the channel's [`PeerInfo`].
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        let p2c = self.peer_to_channel.read().await;
        let channel = p2c.get(peer_id).and_then(|chs| chs.iter().next())?;
        let peers = self.peers.read().await;
        peers.get(channel).cloned()
    }

    /// Get info for a transport-level channel by its channel ID (internal only).
    #[allow(dead_code)]
    pub(crate) async fn peer_info_by_channel(&self, channel_id: &str) -> Option<PeerInfo> {
        self.peers.read().await.get(channel_id).cloned()
    }

    /// Get the channel ID for a given address, if connected (internal only).
    #[allow(dead_code)]
    pub(crate) async fn get_channel_id_by_address(&self, addr: &MultiAddr) -> Option<String> {
        let target = addr.socket_addr()?;
        let peers = self.peers.read().await;

        for (channel_id, peer_info) in peers.iter() {
            for peer_addr in &peer_info.addresses {
                if peer_addr.socket_addr() == Some(target) {
                    return Some(channel_id.clone());
                }
            }
        }
        None
    }

    /// List all active connections with peer IDs and addresses (internal only).
    #[allow(dead_code)]
    pub(crate) async fn list_active_connections(&self) -> Vec<(String, Vec<MultiAddr>)> {
        let active = self.active_connections.read().await;
        let peers = self.peers.read().await;

        active
            .iter()
            .map(|peer_id| {
                let addresses = peers
                    .get(peer_id)
                    .map(|info| info.addresses.clone())
                    .unwrap_or_default();
                (peer_id.clone(), addresses)
            })
            .collect()
    }

    /// Remove a channel from the tracking maps (internal only).
    pub(crate) async fn remove_channel(&self, channel_id: &str) -> bool {
        self.active_connections.write().await.remove(channel_id);
        self.remove_channel_mappings(channel_id).await;
        self.peers.write().await.remove(channel_id).is_some()
    }

    /// Close a channel's QUIC connection and remove it from all tracking maps.
    ///
    /// Use this when a transport-level connection was established but the
    /// identity exchange failed, so no [`PeerId`] is available for
    /// [`disconnect_peer`].
    pub(crate) async fn disconnect_channel(&self, channel_id: &str) {
        match channel_id.parse::<SocketAddr>() {
            Ok(addr) => self.dual_node.disconnect_peer_by_addr(&addr).await,
            Err(e) => {
                warn!(
                    channel = %channel_id,
                    error = %e,
                    "Failed to parse channel ID as SocketAddr — QUIC connection will not be closed",
                );
            }
        }
        self.active_connections.write().await.remove(channel_id);
        self.remove_channel_mappings(channel_id).await;
        self.peers.write().await.remove(channel_id);
    }

    /// Look up the peer ID for a given connection address.
    pub async fn peer_id_for_addr(&self, addr: &SocketAddr) -> Option<PeerId> {
        let c2p = self.channel_to_peer.read().await;

        // Try the exact stringified address first.
        let channel_id = addr.to_string();
        if let Some(peer_id) = c2p.get(&channel_id).copied() {
            return Some(peer_id);
        }

        // The channel key may be stored as IPv4-mapped IPv6 (e.g., "[::ffff:1.2.3.4]:PORT")
        // while the lookup address was normalized to IPv4 ("1.2.3.4:PORT"), or vice versa.
        let alt_addr = saorsa_transport::shared::dual_stack_alternate(addr)?;
        let alt_channel_id = alt_addr.to_string();
        c2p.get(&alt_channel_id).copied()
    }

    /// Drain pending peer address updates from ADD_ADDRESS frames.
    ///
    /// Returns (peer_connection_addr, advertised_addr) pairs. The caller
    /// should look up the peer ID and update the DHT routing table.
    pub async fn drain_peer_address_updates(&self) -> Vec<(SocketAddr, SocketAddr)> {
        let mut rx = self.peer_address_update_rx.lock().await;
        let mut updates = Vec::new();
        while let Ok(update) = rx.try_recv() {
            updates.push(update);
        }
        updates
    }

    /// Drain any relay established events. Returns the relay address if this
    /// node has just established a MASQUE relay.
    pub async fn drain_relay_established(&self) -> Option<SocketAddr> {
        let mut rx = self.relay_established_rx.lock().await;
        // Only care about the first one (relay is established once)
        rx.try_recv().ok()
    }

    /// Wait for the next peer-address update from an ADD_ADDRESS frame.
    ///
    /// Returns `(peer_connection_addr, advertised_addr)` when one arrives,
    /// or `None` if the underlying channel has closed (transport shut down).
    ///
    /// Use this in a `tokio::select!` against a shutdown token to react to
    /// address updates immediately instead of polling.
    pub async fn recv_peer_address_update(&self) -> Option<(SocketAddr, SocketAddr)> {
        let mut rx = self.peer_address_update_rx.lock().await;
        rx.recv().await
    }

    /// Wait for the next relay-established event.
    ///
    /// Resolves when this node has just set up a MASQUE relay (yielding
    /// the relay socket address), or `None` if the underlying channel has
    /// closed (transport shut down).
    ///
    /// Use this in a `tokio::select!` against a shutdown token to react to
    /// relay establishment immediately instead of polling.
    pub async fn recv_relay_established(&self) -> Option<SocketAddr> {
        let mut rx = self.relay_established_rx.lock().await;
        rx.recv().await
    }

    /// Check if an authenticated peer is connected (has at least one active
    /// channel).
    pub async fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peer_to_channel.read().await.contains_key(peer_id)
    }

    /// Check if a connection to a peer is active at the transport layer (internal only).
    pub(crate) async fn is_connection_active(&self, channel_id: &str) -> bool {
        self.active_connections.read().await.contains(channel_id)
    }

    /// Remove channel mappings for a disconnected channel.
    ///
    /// Removes the channel from `channel_to_peer` and scrubs it from the
    /// peer's channel set in `peer_to_channel`. When the peer's last channel
    /// is removed, emits `PeerDisconnected`.
    async fn remove_channel_mappings(&self, channel_id: &str) {
        Self::remove_channel_mappings_static(
            channel_id,
            &self.peer_to_channel,
            &self.channel_to_peer,
            &self.peer_user_agents,
            &self.event_tx,
        )
        .await;
    }

    /// Static version of channel mapping removal — usable from background tasks
    /// that don't have `&self`.
    async fn remove_channel_mappings_static(
        channel_id: &str,
        peer_to_channel: &RwLock<HashMap<PeerId, HashSet<String>>>,
        channel_to_peer: &RwLock<HashMap<String, PeerId>>,
        peer_user_agents: &RwLock<HashMap<PeerId, String>>,
        event_tx: &broadcast::Sender<P2PEvent>,
    ) {
        let mut p2c = peer_to_channel.write().await;
        let mut c2p = channel_to_peer.write().await;
        if let Some(app_peer) = c2p.remove(channel_id)
            && let Some(channels) = p2c.get_mut(&app_peer)
        {
            channels.remove(channel_id);
            if channels.is_empty() {
                p2c.remove(&app_peer);
                peer_user_agents.write().await.remove(&app_peer);
                let _ = event_tx.send(P2PEvent::PeerDisconnected(app_peer));
            }
        }
    }
}

// ============================================================================
// Connection Management
// ============================================================================

impl TransportHandle {
    /// Set the target peer ID for a hole-punch attempt to a specific address.
    /// See [`P2pEndpoint::set_hole_punch_target_peer_id`].
    pub async fn set_hole_punch_target_peer_id(&self, target: SocketAddr, peer_id: [u8; 32]) {
        self.dual_node
            .set_hole_punch_target_peer_id(target, peer_id)
            .await;
    }

    /// Set an ordered list of preferred coordinators for hole-punching to a
    /// specific target.
    ///
    /// See [`crate::transport::saorsa_transport_adapter::SaorsaDualStackTransport::set_hole_punch_preferred_coordinators`]
    /// for the rotation semantics.
    pub async fn set_hole_punch_preferred_coordinators(
        &self,
        target: SocketAddr,
        coordinators: Vec<SocketAddr>,
    ) {
        self.dual_node
            .set_hole_punch_preferred_coordinators(target, coordinators)
            .await;
    }

    /// Connect to a peer at the given address.
    ///
    /// Only QUIC [`MultiAddr`] values are accepted. Non-QUIC transports
    /// return [`NetworkError::InvalidAddress`].
    pub async fn connect_peer(&self, address: &MultiAddr) -> Result<String> {
        // Require a dialable (QUIC) transport.
        let socket_addr = address.dialable_socket_addr().ok_or_else(|| {
            P2PError::Network(NetworkError::InvalidAddress(
                format!(
                    "only QUIC transport is supported for connect, got {}: {}",
                    address.transport().kind(),
                    address
                )
                .into(),
            ))
        })?;

        let normalized_addr = normalize_wildcard_to_loopback(socket_addr);
        let addr_list = vec![normalized_addr];

        let peer_id = match tokio::time::timeout(
            self.connection_timeout,
            self.dual_node.connect_happy_eyeballs(&addr_list),
        )
        .await
        {
            Ok(Ok(addr)) => {
                let connected_peer_id = addr.to_string();

                // Prevent self-connections by comparing against all listen
                // addresses (dual-stack nodes may have both IPv4 and IPv6).
                let is_self = {
                    let addrs = self.listen_addrs.read().await;
                    addrs.iter().any(|a| a.socket_addr() == Some(addr))
                };
                if is_self {
                    warn!(
                        "Detected self-connection to own address {} (channel_id: {}), rejecting",
                        address, connected_peer_id
                    );
                    self.dual_node.disconnect_peer_by_addr(&addr).await;
                    return Err(P2PError::Network(NetworkError::InvalidAddress(
                        format!("Cannot connect to self ({})", address).into(),
                    )));
                }

                info!("Successfully connected to channel: {}", connected_peer_id);
                connected_peer_id
            }
            Ok(Err(e)) => {
                warn!("connect_happy_eyeballs failed for {}: {}", address, e);
                return Err(P2PError::Transport(
                    crate::error::TransportError::ConnectionFailed {
                        addr: normalized_addr,
                        reason: e.to_string().into(),
                    },
                ));
            }
            Err(_) => {
                warn!(
                    "connect_happy_eyeballs timed out for {} after {:?}",
                    address, self.connection_timeout
                );
                return Err(P2PError::Timeout(self.connection_timeout));
            }
        };

        let peer_info = PeerInfo {
            channel_id: peer_id.clone(),
            addresses: vec![address.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["p2p-foundation/1.0".to_string()],
            heartbeat_count: 0,
        };

        self.peers.write().await.insert(peer_id.clone(), peer_info);
        self.active_connections
            .write()
            .await
            .insert(peer_id.clone());

        // PeerConnected is emitted later when the peer's identity is
        // authenticated via a signed message — not at transport level.
        Ok(peer_id)
    }

    /// Disconnect from a peer, closing the underlying QUIC connection only
    /// when no other peers share the channel.
    ///
    /// Accepts an app-level [`PeerId`], removes it from the bidirectional
    /// peer/channel maps, and tears down the QUIC transport for any channels
    /// that become orphaned (no remaining peers).
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);

        // Remove this peer from the bidirectional maps. Each channel maps to
        // exactly one peer, so removing a peer always orphans all of its
        // channels — they need to be torn down at the QUIC level too.
        let orphaned_channels = {
            let mut p2c = self.peer_to_channel.write().await;
            let mut c2p = self.channel_to_peer.write().await;

            let channel_ids = match p2c.remove(peer_id) {
                Some(chs) => chs,
                None => {
                    info!(
                        "Peer {} has no tracked channels, nothing to disconnect",
                        peer_id
                    );
                    return Ok(());
                }
            };

            for channel_id in &channel_ids {
                c2p.remove(channel_id);
            }
            channel_ids.into_iter().collect::<Vec<_>>()
        };

        self.peer_user_agents.write().await.remove(peer_id);
        let _ = self.event_tx.send(P2PEvent::PeerDisconnected(*peer_id));

        // Close QUIC connections for channels with no remaining peers.
        for channel_id in &orphaned_channels {
            match channel_id.parse::<SocketAddr>() {
                Ok(addr) => self.dual_node.disconnect_peer_by_addr(&addr).await,
                Err(e) => {
                    warn!(
                        peer = %peer_id,
                        channel = %channel_id,
                        error = %e,
                        "Failed to parse channel ID as SocketAddr — QUIC connection will not be closed",
                    );
                }
            }
            self.active_connections.write().await.remove(channel_id);
            self.peers.write().await.remove(channel_id);
        }

        info!("Disconnected from peer: {}", peer_id);
        Ok(())
    }

    /// Disconnect from all peers.
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peer_ids: Vec<PeerId> = self.peer_to_channel.read().await.keys().cloned().collect();
        for peer_id in &peer_ids {
            self.disconnect_peer(peer_id).await?;
        }
        Ok(())
    }
}

// ============================================================================
// Messaging
// ============================================================================

impl TransportHandle {
    /// Send a message to an authenticated peer (raw, no trust reporting).
    ///
    /// Resolves the app-level [`PeerId`] to transport channels via the
    /// `peer_to_channel` mapping and tries each channel until one succeeds.
    /// Dead channels are pruned during the attempt loop.
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let peer_hex = peer_id.to_hex();
        let channels: Vec<String> = self
            .peer_to_channel
            .read()
            .await
            .get(peer_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();

        if channels.is_empty() {
            return Err(P2PError::Network(NetworkError::PeerNotFound(
                peer_hex.into(),
            )));
        }

        let mut last_err = None;
        for channel_id in &channels {
            match self
                .send_on_channel(channel_id, protocol, data.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        peer = %peer_hex,
                        channel = %channel_id,
                        error = %e,
                        "Channel send failed, removing and trying next",
                    );
                    self.remove_channel(channel_id).await;
                    last_err = Some(e);
                }
            }
        }

        // All channels exhausted — return the last error.
        Err(last_err
            .unwrap_or_else(|| P2PError::Network(NetworkError::PeerNotFound(peer_hex.into()))))
    }

    /// Send a message on a specific transport channel (raw, no trust reporting).
    ///
    /// `channel_id` is the transport-level QUIC connection identifier. Internal
    /// callers (publish, keepalive, etc.) that already have a channel ID use
    /// this method directly to avoid an extra PeerId → channel lookup.
    pub(crate) async fn send_on_channel(
        &self,
        channel_id: &str,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        debug!(
            "Sending message to channel {} on protocol {}",
            channel_id, protocol
        );

        // If the peer isn't in `self.peers`, register it on the fly.
        // Hole-punched connections are accepted at the transport layer and
        // registered in P2pEndpoint::connected_peers, but the event chain
        // to populate TransportHandle::peers may not have completed yet.
        //
        // Uses a single write lock with entry() to avoid a TOCTOU race
        // where a concurrent event handler could insert a fully-populated
        // PeerInfo between a read-check and our write.
        // Double-checked locking: only take a write lock when the channel
        // is not yet registered, avoiding write-lock contention on every send.
        {
            let needs_insert = {
                let peers = self.peers.read().await;
                !peers.contains_key(channel_id)
            };

            if needs_insert {
                let mut peers = self.peers.write().await;
                peers.entry(channel_id.to_string()).or_insert_with(|| {
                    info!(
                        "send_on_channel: registering new channel {} on the fly",
                        channel_id
                    );
                    let addresses = channel_id
                        .parse::<std::net::SocketAddr>()
                        .map(|addr| vec![MultiAddr::quic(addr)])
                        .unwrap_or_default();
                    PeerInfo {
                        channel_id: channel_id.to_string(),
                        addresses,
                        status: ConnectionStatus::Connected,
                        last_seen: Instant::now(),
                        connected_at: Instant::now(),
                        protocols: Vec::new(),
                        heartbeat_count: 0,
                    }
                });
            }
        }

        // NOTE: We no longer *reject* sends based on is_connection_active().
        //
        // Hole-punch and NAT-traversed connections have a registration delay
        // (the ConnectionEvent chain takes ~500ms). During this window, the
        // connection IS live at the QUIC level but not yet in
        // active_connections. Using is_connection_active() as a hard gate
        // here would reject valid sends.
        //
        // Instead, we always attempt the actual QUIC send and let
        // P2pEndpoint::send() return PeerNotFound naturally if the
        // connection doesn't exist. The is_connection_active() check below
        // is used only to opportunistically populate active_connections,
        // not to decide whether we send.
        if !self.is_connection_active(channel_id).await {
            self.active_connections
                .write()
                .await
                .insert(channel_id.to_string());
        }

        let raw_data_len = data.len();
        let message_data = self.create_protocol_message(protocol, data)?;
        info!(
            "Sending {} bytes to channel {} on protocol {} (raw data: {} bytes)",
            message_data.len(),
            channel_id,
            protocol,
            raw_data_len
        );

        let addr: SocketAddr = channel_id.parse().map_err(|e: std::net::AddrParseError| {
            P2PError::Network(NetworkError::PeerNotFound(
                format!("Invalid channel ID address: {e}").into(),
            ))
        })?;
        let send_fut = self.dual_node.send_to_peer_optimized(&addr, &message_data);
        let result = tokio::time::timeout(self.connection_timeout, send_fut)
            .await
            .map_err(|_| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    "Timed out sending message".into(),
                ))
            })?
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    e.to_string().into(),
                ))
            });

        if result.is_ok() {
            info!(
                "Successfully sent {} bytes to channel {}",
                message_data.len(),
                channel_id
            );
        } else {
            warn!("Failed to send message to channel {}", channel_id);
            // Clean up the optimistic active_connections entry so stale
            // entries don't accumulate for unknown channels.
            self.active_connections.write().await.remove(channel_id);
        }

        result
    }

    /// Return all channel IDs for an app-level peer, if known.
    pub async fn channels_for_peer(&self, app_peer_id: &PeerId) -> Vec<String> {
        self.peer_to_channel
            .read()
            .await
            .get(app_peer_id)
            .map(|channels| channels.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get the authenticated app-level peer ID for a channel, if any.
    pub(crate) async fn peer_on_channel(&self, channel_id: &str) -> Option<PeerId> {
        self.channel_to_peer.read().await.get(channel_id).copied()
    }

    /// Return true if `peer_id` is a known authenticated app-level peer ID.
    pub async fn is_known_app_peer_id(&self, peer_id: &PeerId) -> bool {
        self.peer_to_channel.read().await.contains_key(peer_id)
    }

    /// Wait for the channel's TLS-authenticated [`PeerId`] to be available.
    ///
    /// After [`connect_peer`](Self::connect_peer) returns a channel ID, the
    /// `ConnectionEvent::Established` may not yet have been processed by the
    /// background lifecycle monitor — at which point the `channel_to_peer`
    /// map has not yet been populated. This helper does a fast initial
    /// lookup, then `await`s on `identity_notify` for the next insert and
    /// re-checks. The whole flow is event-driven (no polling), so a typical
    /// caller resolves within a few scheduler ticks of the QUIC handshake
    /// completing — far below the supplied `timeout`.
    ///
    /// `timeout` is a defence-in-depth bound for cases where the lifecycle
    /// monitor is slow or the SPKI parse fails (e.g. a non-PQC peer slipped
    /// past the TLS verifier). In normal operation it never fires.
    pub async fn wait_for_peer_identity(
        &self,
        channel_id: &str,
        timeout: Duration,
    ) -> Result<PeerId> {
        let deadline = Instant::now() + timeout;
        loop {
            // Subscribe to the next notification BEFORE the map check.
            //
            // `Notify::notified()` only registers with the underlying
            // `Notify` on first poll, *not* on creation. Without an
            // explicit `enable()` call there is a race window: if the
            // lifecycle monitor inserts the mapping and calls
            // `notify_waiters()` between our `peer_on_channel` read and
            // the subsequent `await`, the wake is missed and we sleep
            // until the timeout.
            //
            // `enable()` synchronously registers the future with the
            // `Notify`, so any `notify_waiters()` after this point reaches
            // us even before the future is polled.
            let notified = self.identity_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(peer_id) = self.peer_on_channel(channel_id).await {
                return Ok(peer_id);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(P2PError::Timeout(timeout));
            }
            match tokio::time::timeout(remaining, notified.as_mut()).await {
                Ok(()) => continue,
                Err(_) => return Err(P2PError::Timeout(timeout)),
            }
        }
    }

    /// Send a request and wait for a response (no trust reporting).
    ///
    /// This is the raw request-response correlation mechanism. Callers that
    /// need trust feedback should wrap this method (as `P2PNode` does).
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<PeerResponse> {
        let timeout = timeout.min(MAX_REQUEST_TIMEOUT);

        validate_protocol_name(protocol)?;

        let message_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let started_at = Instant::now();

        {
            let mut reqs = self.active_requests.write().await;
            if reqs.len() >= MAX_ACTIVE_REQUESTS {
                return Err(P2PError::Transport(
                    crate::error::TransportError::StreamError(
                        format!(
                            "Too many active requests ({MAX_ACTIVE_REQUESTS}); try again later"
                        )
                        .into(),
                    ),
                ));
            }
            reqs.insert(
                message_id.clone(),
                PendingRequest {
                    response_tx: tx,
                    expected_peer: *peer_id,
                },
            );
        }

        let envelope = RequestResponseEnvelope {
            message_id: message_id.clone(),
            is_response: false,
            payload: data,
        };
        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.active_requests.write().await.remove(&message_id);
                return Err(P2PError::Serialization(
                    format!("Failed to serialize request envelope: {e}").into(),
                ));
            }
        };

        let wire_protocol = format!("/rr/{}", protocol);
        if let Err(e) = self
            .send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
        {
            self.active_requests.write().await.remove(&message_id);
            return Err(e);
        }

        let result = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response_bytes)) => {
                let latency = started_at.elapsed();
                Ok(PeerResponse {
                    peer_id: *peer_id,
                    data: response_bytes,
                    latency,
                })
            }
            Ok(Err(_)) => Err(P2PError::Network(NetworkError::ConnectionClosed {
                peer_id: peer_id.to_hex().into(),
            })),
            Err(_) => Err(P2PError::Transport(
                crate::error::TransportError::StreamError(
                    format!(
                        "Request to {} on {} timed out after {:?}",
                        peer_id, protocol, timeout
                    )
                    .into(),
                ),
            )),
        };

        self.active_requests.write().await.remove(&message_id);
        result
    }

    /// Send a response to a previously received request.
    pub async fn send_response(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        message_id: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        validate_protocol_name(protocol)?;

        let envelope = RequestResponseEnvelope {
            message_id: message_id.to_string(),
            is_response: true,
            payload: data,
        };
        let envelope_bytes = postcard::to_allocvec(&envelope).map_err(|e| {
            P2PError::Serialization(format!("Failed to serialize response envelope: {e}").into())
        })?;

        let wire_protocol = format!("/rr/{}", protocol);
        self.send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
    }

    /// Parse a request/response envelope from incoming message bytes.
    pub fn parse_request_envelope(data: &[u8]) -> Option<(String, bool, Vec<u8>)> {
        let envelope: RequestResponseEnvelope = postcard::from_bytes(data).ok()?;
        Some((envelope.message_id, envelope.is_response, envelope.payload))
    }

    /// Create a protocol message wrapper (WireMessage serialized with postcard).
    ///
    /// Signs the message with the node's ML-DSA-65 key.
    fn create_protocol_message(&self, protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let mut message = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: *self.node_identity.peer_id(),
            timestamp: Self::current_timestamp_secs()?,
            user_agent: self.user_agent.clone(),
            public_key: Vec::new(),
            signature: Vec::new(),
        };

        Self::sign_wire_message(&mut message, &self.node_identity)?;

        Self::serialize_wire_message(&message)
    }

    /// Get the current Unix timestamp in seconds.
    fn current_timestamp_secs() -> Result<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| {
                P2PError::Network(NetworkError::ProtocolError(
                    format!("System time error: {e}").into(),
                ))
            })
    }

    /// Sign a `WireMessage` in place using the given identity.
    fn sign_wire_message(message: &mut WireMessage, identity: &NodeIdentity) -> Result<()> {
        let signable = Self::compute_signable_bytes(
            &message.protocol,
            &message.data,
            &message.from,
            message.timestamp,
            &message.user_agent,
        )?;
        let sig = identity.sign(&signable).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to sign message: {e}").into(),
            ))
        })?;
        message.public_key = identity.public_key().as_bytes().to_vec();
        message.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Serialize a `WireMessage` to postcard bytes.
    fn serialize_wire_message(message: &WireMessage) -> Result<Vec<u8>> {
        postcard::to_stdvec(message).map_err(|e| {
            P2PError::Transport(crate::error::TransportError::StreamError(
                format!("Failed to serialize wire message: {e}").into(),
            ))
        })
    }

    /// Compute the canonical bytes to sign/verify for a WireMessage.
    fn compute_signable_bytes(
        protocol: &str,
        data: &[u8],
        from: &PeerId,
        timestamp: u64,
        user_agent: &str,
    ) -> Result<Vec<u8>> {
        postcard::to_stdvec(&(protocol, data, from, timestamp, user_agent)).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to serialize signable bytes: {e}").into(),
            ))
        })
    }
}

// ============================================================================
// Pub/Sub
// ============================================================================

impl TransportHandle {
    /// Subscribe to a topic (currently a no-op stub).
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    /// Publish a message to all connected peers on the given topic.
    ///
    /// De-duplicates by app-level peer: when a peer has multiple channels,
    /// tries each channel until one succeeds (fallback on failure).
    /// Unauthenticated channels (not yet mapped to an app-level peer) are
    /// also included once each.
    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "Publishing message to topic: {} ({} bytes)",
            topic,
            data.len()
        );

        // Collect all channels grouped by authenticated app-level peer,
        // plus any unauthenticated channels.
        let mut peer_channel_groups: Vec<Vec<String>> = Vec::new();
        let mut mapped_channels: HashSet<String> = HashSet::new();
        {
            let p2c = self.peer_to_channel.read().await;
            for channels in p2c.values() {
                let chs: Vec<String> = channels.iter().cloned().collect();
                mapped_channels.extend(chs.iter().cloned());
                if !chs.is_empty() {
                    peer_channel_groups.push(chs);
                }
            }
        }

        // Include unauthenticated channels (single-channel groups, no fallback).
        {
            let peers_guard = self.peers.read().await;
            for channel_id in peers_guard.keys() {
                if !mapped_channels.contains(channel_id) {
                    peer_channel_groups.push(vec![channel_id.clone()]);
                }
            }
        }

        if peer_channel_groups.is_empty() {
            debug!("No peers connected, message will only be sent to local subscribers");
        } else {
            let mut send_count = 0;
            let total = peer_channel_groups.len();
            for channels in &peer_channel_groups {
                let mut sent = false;
                for channel_id in channels {
                    match self.send_on_channel(channel_id, topic, data.to_vec()).await {
                        Ok(()) => {
                            send_count += 1;
                            debug!("Published message via channel: {}", channel_id);
                            sent = true;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                channel = %channel_id,
                                error = %e,
                                "Publish channel failed, removing and trying next",
                            );
                            self.remove_channel(channel_id).await;
                        }
                    }
                }
                if !sent {
                    warn!("All channels exhausted for one peer during publish");
                }
            }
            info!(
                "Published message to {}/{} connected peers",
                send_count, total
            );
        }

        self.send_event(P2PEvent::Message {
            topic: topic.to_string(),
            source: Some(*self.node_identity.peer_id()),
            data: data.to_vec(),
        });

        Ok(())
    }
}

// ============================================================================
// Events
// ============================================================================

impl TransportHandle {
    /// Subscribe to network events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.event_tx.subscribe()
    }

    /// Send an event to all subscribers.
    pub(crate) fn send_event(&self, event: P2PEvent) {
        if let Err(e) = self.event_tx.send(event) {
            tracing::trace!("Event broadcast has no receivers: {e}");
        }
    }
}

// ============================================================================
// Network Listeners & Receive System
// ============================================================================

impl TransportHandle {
    /// Start network listeners on the dual-stack transport.
    pub async fn start_network_listeners(&self) -> Result<()> {
        info!("Starting dual-stack listeners (saorsa-transport)...");
        let socket_addrs = self.dual_node.local_addrs().await.map_err(|e| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Failed to get local addresses: {}", e).into(),
            ))
        })?;
        let addrs: Vec<SocketAddr> = socket_addrs.clone();
        {
            let mut la = self.listen_addrs.write().await;
            *la = socket_addrs.into_iter().map(MultiAddr::quic).collect();
        }

        let peers = self.peers.clone();
        let active_connections = self.active_connections.clone();
        let rate_limiter = self.rate_limiter.clone();
        let dual = self.dual_node.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Some(remote_sock) = dual.accept_any().await else {
                    break;
                };

                if let Err(e) = rate_limiter.check_ip(&remote_sock.ip()) {
                    warn!(
                        "Rate-limited incoming connection from {}: {}",
                        remote_sock, e
                    );
                    continue;
                }

                let channel_id = remote_sock.to_string();
                let remote_addr = MultiAddr::quic(remote_sock);
                // PeerConnected is emitted later when the peer's identity is
                // authenticated via a signed message — not at transport level.
                register_new_channel(&peers, &channel_id, &remote_addr).await;
                active_connections.write().await.insert(channel_id);
            }
        });
        *self.listener_handle.write().await = Some(handle);

        self.start_message_receiving_system().await?;

        info!("Dual-stack listeners active on: {:?}", addrs);
        Ok(())
    }

    /// Spawns per-stack recv tasks and a **sharded** dispatcher that routes
    /// incoming messages across [`MESSAGE_DISPATCH_SHARDS`] parallel consumer
    /// tasks.
    ///
    /// # Why sharded?
    ///
    /// The previous implementation used a single consumer task to drain
    /// every inbound message in the entire node. At 60 peers this kept up
    /// comfortably, but at 1000 peers it became the dominant serialisation
    /// point — every message ran through the same task before the next
    /// could even be looked at, and responses arrived past the caller's
    /// 25 s timeout. Sharding by hash of the source IP gives each shard
    /// its own consumer running in parallel, so per-peer lock contention
    /// is distributed across N simultaneous workers. Messages from the
    /// **same source IP** always route to the **same shard**, preserving
    /// per-source ordering. The dispatcher task is light (hash + channel
    /// send) so it is never the bottleneck.
    ///
    /// Note that since the identity-exchange refactor, the shard consumer
    /// only writes to `active_requests` and `peer_user_agents`. Peer↔channel
    /// registration moved to [`Self::connection_lifecycle_monitor_with_rx`]
    /// where it runs once per QUIC handshake instead of once per message.
    async fn start_message_receiving_system(&self) -> Result<()> {
        info!(
            "Starting message receiving system ({} dispatch shards)",
            MESSAGE_DISPATCH_SHARDS
        );

        let (upstream_tx, mut upstream_rx) =
            tokio::sync::mpsc::channel(MESSAGE_RECV_CHANNEL_CAPACITY);

        let mut handles = self
            .dual_node
            .spawn_recv_tasks(upstream_tx.clone(), self.shutdown.clone());
        drop(upstream_tx);

        // Per-shard capacity so the aggregate buffered depth matches the old
        // single-channel capacity, keeping memory usage comparable. Floor
        // at `MIN_SHARD_CHANNEL_CAPACITY` so each shard retains enough
        // slack for small bursts even if the global capacity is tiny.
        let per_shard_capacity = (MESSAGE_RECV_CHANNEL_CAPACITY / MESSAGE_DISPATCH_SHARDS)
            .max(MIN_SHARD_CHANNEL_CAPACITY);

        let mut shard_txs: Vec<tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>> =
            Vec::with_capacity(MESSAGE_DISPATCH_SHARDS);

        for shard_idx in 0..MESSAGE_DISPATCH_SHARDS {
            let (shard_tx, shard_rx) = tokio::sync::mpsc::channel(per_shard_capacity);
            shard_txs.push(shard_tx);

            let event_tx = self.event_tx.clone();
            let active_requests = Arc::clone(&self.active_requests);
            let peer_user_agents = Arc::clone(&self.peer_user_agents);
            let self_peer_id = *self.node_identity.peer_id();

            handles.push(tokio::spawn(async move {
                Self::run_shard_consumer(
                    shard_idx,
                    shard_rx,
                    event_tx,
                    active_requests,
                    peer_user_agents,
                    self_peer_id,
                )
                .await;
            }));
        }

        // Dispatcher: single task whose only job is to hash `from_addr` and
        // hand the message off to the appropriate shard. The actual heavy
        // lifting happens in parallel in the shard consumers.
        //
        // Failure isolation: a single shard's `try_send` failure must NOT
        // collapse the dispatcher. If a shard channel is full we log and
        // drop the message (incrementing a counter). If a shard task has
        // panicked and its receiver is closed we log and drop, but keep
        // routing to the other healthy shards. The dispatcher only exits
        // when its upstream channel closes (i.e. transport shutdown).
        let drop_counter = Arc::new(AtomicU64::new(0));
        handles.push(tokio::spawn(async move {
            info!(
                "Message dispatcher loop started (sharded across {} consumers)",
                MESSAGE_DISPATCH_SHARDS
            );
            while let Some((from_addr, bytes)) = upstream_rx.recv().await {
                let shard_idx = shard_index_for_addr(&from_addr);
                match shard_txs[shard_idx].try_send((from_addr, bytes)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_dropped)) => {
                        // Backpressure: this shard is overloaded. Drop the
                        // message rather than blocking the dispatcher and
                        // starving the other shards. Per-shard ordering for
                        // this peer is broken for the dropped message but
                        // preserved for everything that does land.
                        let prev = drop_counter.fetch_add(1, Ordering::Relaxed);
                        if prev.is_multiple_of(SHARD_DROP_LOG_INTERVAL) {
                            warn!(
                                shard = shard_idx,
                                from = %from_addr,
                                total_drops = prev + 1,
                                "Dispatcher dropped inbound message: shard channel full"
                            );
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_dropped)) => {
                        // Shard consumer task has exited (likely panic).
                        // Drop this message but keep routing to the other
                        // shards — fault isolation, not cascade failure.
                        let prev = drop_counter.fetch_add(1, Ordering::Relaxed);
                        if prev.is_multiple_of(SHARD_DROP_LOG_INTERVAL) {
                            warn!(
                                shard = shard_idx,
                                from = %from_addr,
                                total_drops = prev + 1,
                                "Dispatcher dropped inbound message: shard consumer closed"
                            );
                        }
                    }
                }
            }
            info!("Message dispatcher loop ended — upstream channel closed");
        }));

        *self.recv_handles.write().await = handles;
        Ok(())
    }

    /// Consumer loop for a single dispatch shard.
    ///
    /// Each shard runs one of these in its own `tokio::spawn` task. Shard
    /// assignment is by hash of the source IP, so messages from the same
    /// peer always go through the same shard (ordering is preserved per
    /// peer). Shared state (`active_requests`, `peer_user_agents`) is
    /// behind `RwLock`s but lock hold times are spread across
    /// [`MESSAGE_DISPATCH_SHARDS`] concurrent consumers.
    ///
    /// The peer↔channel mapping is *not* maintained here — it is established
    /// synchronously by [`Self::connection_lifecycle_monitor_with_rx`] when
    /// the TLS handshake completes. The shard consumer's job is purely
    /// message dispatch: parse the wire frame, route request/response
    /// envelopes, opportunistically refresh the peer's user-agent string,
    /// and broadcast unsolicited messages as `P2PEvent::Message`.
    #[allow(clippy::too_many_arguments)]
    async fn run_shard_consumer(
        shard_idx: usize,
        mut shard_rx: tokio::sync::mpsc::Receiver<(SocketAddr, Vec<u8>)>,
        event_tx: broadcast::Sender<P2PEvent>,
        active_requests: Arc<RwLock<HashMap<String, PendingRequest>>>,
        peer_user_agents: Arc<RwLock<HashMap<PeerId, String>>>,
        self_peer_id: PeerId,
    ) {
        info!("Message dispatch shard {shard_idx} started");
        while let Some((from_addr, bytes)) = shard_rx.recv().await {
            let channel_id = from_addr.to_string();
            trace!(
                shard = shard_idx,
                "Received {} bytes from channel {}",
                bytes.len(),
                channel_id
            );

            match parse_protocol_message(&bytes, &channel_id) {
                Some(ParsedMessage {
                    event,
                    authenticated_node_id,
                    user_agent: peer_user_agent,
                }) => {
                    // Lazily refresh the peer's user-agent string from any
                    // signed message. The peer↔channel mapping is already
                    // populated by the lifecycle monitor at TLS-handshake
                    // time, so we don't touch it here. Skip echoes of our
                    // own identity.
                    //
                    // When the user-agent is learned for the first time (or
                    // changes), re-emit `PeerConnected` so subscribers that
                    // branch on the user-agent — notably the DHT bridge,
                    // which uses `is_dht_participant` to gate routing-table
                    // admission — can re-classify. The original handshake-
                    // time `PeerConnected` is emitted with an empty
                    // user-agent because TLS doesn't carry one; this is the
                    // follow-up that delivers the application-level
                    // capability bits within one signed-message round trip.
                    if let Some(ref app_id) = authenticated_node_id
                        && *app_id != self_peer_id
                        && !peer_user_agent.is_empty()
                    {
                        let mut uas = peer_user_agents.write().await;
                        let changed = match uas.get(app_id) {
                            Some(existing) => existing != &peer_user_agent,
                            None => true,
                        };
                        if changed {
                            uas.insert(*app_id, peer_user_agent.clone());
                            // Drop the lock before emitting so subscribers
                            // re-entering the registry don't deadlock.
                            drop(uas);
                            broadcast_event(
                                &event_tx,
                                P2PEvent::PeerConnected(*app_id, peer_user_agent),
                            );
                        }
                    }

                    if let P2PEvent::Message {
                        ref topic,
                        ref data,
                        ..
                    } = event
                        && topic.starts_with("/rr/")
                        && let Ok(envelope) = postcard::from_bytes::<RequestResponseEnvelope>(data)
                        && envelope.is_response
                    {
                        let mut reqs = active_requests.write().await;
                        let expected_peer = match reqs.get(&envelope.message_id) {
                            Some(pending) => pending.expected_peer,
                            None => {
                                trace!(
                                    message_id = %envelope.message_id,
                                    "Unmatched /rr/ response (likely timed out) — suppressing"
                                );
                                continue;
                            }
                        };
                        // Accept response only if the authenticated app-level
                        // identity matches. Channel IDs identify connections,
                        // not peers, so they are not checked here.
                        if authenticated_node_id.as_ref() != Some(&expected_peer) {
                            warn!(
                                message_id = %envelope.message_id,
                                expected = %expected_peer,
                                actual_channel = %channel_id,
                                authenticated = ?authenticated_node_id,
                                "Response origin mismatch — ignoring"
                            );
                            continue;
                        }
                        if let Some(pending) = reqs.remove(&envelope.message_id) {
                            if pending.response_tx.send(envelope.payload).is_err() {
                                warn!(
                                    message_id = %envelope.message_id,
                                    "Response receiver dropped before delivery"
                                );
                            }
                            continue;
                        }
                        trace!(
                            message_id = %envelope.message_id,
                            "Unmatched /rr/ response (likely timed out) — suppressing"
                        );
                        continue;
                    }
                    broadcast_event(&event_tx, event);
                }
                None => {
                    warn!(
                        shard = shard_idx,
                        "Failed to parse protocol message ({} bytes)",
                        bytes.len()
                    );
                }
            }
        }
        info!("Message dispatch shard {shard_idx} ended — channel closed");
    }
}

/// Number of parallel dispatch shards for inbound messages.
///
/// Messages are routed to a shard by hash of the source IP so each peer's
/// messages are processed by the same consumer (preserving per-peer
/// ordering) while different peers' messages run in parallel. Picked to
/// match typical core counts on deployment hardware — tuning higher helps
/// only if the shared state `RwLock`s are no longer the dominant
/// contention, which is not the case today.
const MESSAGE_DISPATCH_SHARDS: usize = 8;

/// Minimum mpsc capacity for an individual dispatch shard channel.
///
/// The per-shard capacity is normally `MESSAGE_RECV_CHANNEL_CAPACITY /
/// MESSAGE_DISPATCH_SHARDS`, but when that division rounds to something
/// too small for healthy bursts we floor it at this value so each shard
/// retains a reasonable amount of buffering headroom.
const MIN_SHARD_CHANNEL_CAPACITY: usize = 16;

/// Log a warning every Nth dropped message in the dispatcher.
///
/// `try_send` failures (channel full, or shard task closed) increment a
/// global drop counter; logging at every drop would flood the log under
/// sustained backpressure, so we coalesce to one warning per
/// `SHARD_DROP_LOG_INTERVAL` drops. The first drop in a burst is always
/// logged so the operator sees the onset.
const SHARD_DROP_LOG_INTERVAL: u64 = 64;

/// Pick the dispatch shard for an inbound message.
///
/// Hashes by `IpAddr` (not full `SocketAddr`) so a peer re-connecting from
/// a new ephemeral port still lands in the same shard.
///
/// **Ordering caveat:** ordering is preserved per *source IP*, not per
/// authenticated peer. If a peer's public IP changes (NAT rebinding to a
/// new external address, mobile Wi-Fi↔cellular roaming, dual-stack
/// failover) it now hashes to a different shard, and messages from the
/// old IP that are still queued in the old shard may be processed
/// concurrently with new messages from the new IP. Application-layer
/// causality across an IP change is *not* guaranteed by this dispatcher.
fn shard_index_for_addr(addr: &SocketAddr) -> usize {
    let mut hasher = DefaultHasher::new();
    addr.ip().hash(&mut hasher);
    (hasher.finish() as usize) % MESSAGE_DISPATCH_SHARDS
}

// ============================================================================
// Shutdown
// ============================================================================

impl TransportHandle {
    /// Stop the transport layer: shutdown endpoints, join tasks, disconnect peers.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping transport...");

        self.shutdown.cancel();
        self.dual_node.shutdown_endpoints().await;

        // Await recv system tasks
        let handles: Vec<_> = self.recv_handles.write().await.drain(..).collect();
        Self::join_task_handles(handles, "recv").await;
        Self::join_task_slot(&self.listener_handle, "listener").await;
        Self::join_task_slot(&self.connection_monitor_handle, "connection monitor").await;

        self.disconnect_all_peers().await?;

        info!("Transport stopped");
        Ok(())
    }

    async fn join_task_slot(handle_slot: &RwLock<Option<JoinHandle<()>>>, task_name: &str) {
        let handle = handle_slot.write().await.take();
        if let Some(handle) = handle {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handles(handles: Vec<JoinHandle<()>>, task_name: &str) {
        for handle in handles {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handle(handle: JoinHandle<()>, task_name: &str) {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {
                tracing::debug!("{task_name} task was cancelled during shutdown");
            }
            Err(e) if e.is_panic() => {
                tracing::error!("{task_name} task panicked during shutdown: {:?}", e);
            }
            Err(e) => {
                tracing::warn!("{task_name} task join error during shutdown: {:?}", e);
            }
        }
    }
}

// ============================================================================
// Background Tasks (static)
// ============================================================================

impl TransportHandle {
    /// Connection lifecycle monitor — processes saorsa-transport connection events.
    ///
    /// On `ConnectionEvent::Established` the peer's app-level [`PeerId`] is
    /// derived synchronously from the TLS-authenticated SPKI carried in the
    /// event, and the `peer_to_channel` / `channel_to_peer` maps are
    /// populated immediately. This eliminates the asynchronous identity
    /// announce protocol and the 15 s wait window that came with it: by the
    /// time `connect_peer` returns, the peer identity is either already
    /// resolved or will be within a few scheduler ticks.
    #[allow(clippy::too_many_arguments)]
    async fn connection_lifecycle_monitor_with_rx(
        dual_node: Arc<DualStackNetworkNode>,
        mut event_rx: broadcast::Receiver<
            crate::transport::saorsa_transport_adapter::ConnectionEvent,
        >,
        active_connections: Arc<RwLock<HashSet<String>>>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        _geo_provider: Arc<BgpGeoProvider>,
        shutdown: CancellationToken,
        peer_to_channel: Arc<RwLock<HashMap<PeerId, HashSet<String>>>>,
        channel_to_peer: Arc<RwLock<HashMap<String, PeerId>>>,
        peer_user_agents: Arc<RwLock<HashMap<PeerId, String>>>,
        identity_notify: Arc<Notify>,
        self_peer_id: PeerId,
    ) {
        info!("Connection lifecycle monitor started (pre-subscribed receiver)");

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("Connection lifecycle monitor shutting down");
                    break;
                }
                recv = event_rx.recv() => {
                    match recv {
                        Ok(event) => match event {
                            ConnectionEvent::Established {
                                remote_address,
                                public_key,
                            } => {
                                let channel_id = remote_address.to_string();
                                debug!(
                                    "Connection established: channel={}, addr={}",
                                    channel_id, remote_address
                                );

                                active_connections.write().await.insert(channel_id.clone());

                                {
                                    let mut peers_lock = peers.write().await;
                                    if let Some(peer_info) = peers_lock.get_mut(&channel_id) {
                                        peer_info.status = ConnectionStatus::Connected;
                                        peer_info.connected_at = Instant::now();
                                    } else {
                                        debug!("Registering new incoming channel: {}", channel_id);
                                        peers_lock.insert(
                                            channel_id.clone(),
                                            PeerInfo {
                                                channel_id: channel_id.clone(),
                                                addresses: vec![MultiAddr::quic(remote_address)],
                                                status: ConnectionStatus::Connected,
                                                last_seen: Instant::now(),
                                                connected_at: Instant::now(),
                                                protocols: Vec::new(),
                                                heartbeat_count: 0,
                                            },
                                        );
                                    }
                                }

                                // Resolve the peer's app-level identity from the
                                // SPKI bytes carried in the TLS handshake. The
                                // raw-public-key TLS verifier already validated
                                // the signature; here we just decode the same
                                // bytes back into a PeerId.
                                let Some(spki_bytes) = public_key else {
                                    warn!(
                                        channel = %channel_id,
                                        "Connection established without TLS public key — \
                                         channel will not be authenticated and is unusable",
                                    );
                                    continue;
                                };

                                let app_peer_id = match decode_peer_id_from_spki(&spki_bytes) {
                                    Ok(pid) => pid,
                                    Err(e) => {
                                        warn!(
                                            channel = %channel_id,
                                            error = %e,
                                            "Failed to decode peer SPKI into PeerId — \
                                             channel will not be authenticated",
                                        );
                                        continue;
                                    }
                                };

                                if app_peer_id == self_peer_id {
                                    debug!(
                                        channel = %channel_id,
                                        "Skipping self-connection in lifecycle monitor",
                                    );
                                    continue;
                                }

                                // Register peer↔channel mapping immediately,
                                // holding the peer_to_channel lock across the
                                // transport-level peer-id registration so the
                                // app map and the transport addr→peer map are
                                // consistent for any concurrent reader.
                                let is_new_peer;
                                {
                                    let mut p2c = peer_to_channel.write().await;
                                    let mut c2p = channel_to_peer.write().await;
                                    is_new_peer = !p2c.contains_key(&app_peer_id);
                                    p2c.entry(app_peer_id)
                                        .or_default()
                                        .insert(channel_id.clone());
                                    c2p.insert(channel_id.clone(), app_peer_id);
                                    dual_node
                                        .register_connection_peer_id(
                                            remote_address,
                                            *app_peer_id.to_bytes(),
                                        )
                                        .await;
                                }

                                // Wake any wait_for_peer_identity callers
                                // blocked on this channel becoming authenticated.
                                identity_notify.notify_waiters();

                                // Emit PeerConnected for the first sighting.
                                // The user_agent stays empty until the first
                                // signed wire message arrives — see
                                // run_shard_consumer.
                                if is_new_peer {
                                    broadcast_event(
                                        &event_tx,
                                        P2PEvent::PeerConnected(app_peer_id, String::new()),
                                    );
                                }
                            }
                            ConnectionEvent::Lost { remote_address, reason }
                            | ConnectionEvent::Failed { remote_address, reason } => {
                                let channel_id = remote_address.to_string();
                                debug!("Connection lost/failed: channel={channel_id}, reason={reason}");

                                active_connections.write().await.remove(&channel_id);
                                peers.write().await.remove(&channel_id);
                                // Remove channel mappings and emit PeerDisconnected
                                // when the peer's last channel is closed.
                                Self::remove_channel_mappings_static(
                                    &channel_id,
                                    &peer_to_channel,
                                    &channel_to_peer,
                                    &peer_user_agents,
                                    &event_tx,
                                ).await;
                            }
                            ConnectionEvent::PeerAddressUpdated { .. } => {
                                // Handled by dedicated forwarder, not here
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                "Connection event receiver lagged, skipped {} events",
                                skipped
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Connection event channel closed, stopping lifecycle monitor");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Decode a TLS-carried SPKI byte string into the corresponding [`PeerId`].
///
/// The bytes come from saorsa-transport's `extract_public_key_bytes_from_connection`,
/// which returns the contents of the rustls `CertificateDer`. For raw-public-key
/// connections (RFC 7250) those bytes are the X.509 SubjectPublicKeyInfo
/// containing the ML-DSA-65 public key — the same encoding produced by
/// `create_subject_public_key_info`. The TLS verifier already validated the
/// signature; this is purely a byte-to-PeerId derivation.
///
/// Both `extract_public_key_from_spki` and `peer_id_from_public_key` operate
/// on the same `MlDsaPublicKey` type re-exported from `saorsa-transport`, so
/// no intermediate copy through raw bytes is necessary.
fn decode_peer_id_from_spki(spki_bytes: &[u8]) -> Result<PeerId> {
    let public_key: MlDsaPublicKey = extract_public_key_from_spki(spki_bytes).map_err(|e| {
        P2PError::Identity(crate::error::IdentityError::InvalidFormat(
            format!("invalid SPKI bytes from TLS handshake: {e:?}").into(),
        ))
    })?;
    Ok(peer_id_from_public_key(&public_key))
}

// ============================================================================
// Free helper functions
// ============================================================================

/// Validate that a protocol name is non-empty and contains no path separators or null bytes.
fn validate_protocol_name(protocol: &str) -> Result<()> {
    if protocol.is_empty() || protocol.contains(&['/', '\\', '\0'][..]) {
        return Err(P2PError::Transport(
            crate::error::TransportError::StreamError(
                format!("Invalid protocol name: {:?}", protocol).into(),
            ),
        ));
    }
    Ok(())
}

// ============================================================================
// NetworkSender impl
// ============================================================================

#[async_trait::async_trait]
impl NetworkSender for TransportHandle {
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()> {
        TransportHandle::send_message(self, peer_id, protocol, data).await
    }

    fn local_peer_id(&self) -> PeerId {
        self.peer_id()
    }
}

// Test-only helpers for injecting state
#[cfg(test)]
impl TransportHandle {
    /// Insert a peer into the peers map (test helper)
    pub(crate) async fn inject_peer(&self, peer_id: String, info: PeerInfo) {
        self.peers.write().await.insert(peer_id, info);
    }

    /// Insert a channel ID into the active_connections set (test helper)
    pub(crate) async fn inject_active_connection(&self, channel_id: String) {
        self.active_connections.write().await.insert(channel_id);
    }

    /// Map an app-level PeerId to a channel ID in both `peer_to_channel` and
    /// `channel_to_peer` (test helper). The bidirectional mapping ensures
    /// `remove_channel` correctly cleans up both maps. Also fires
    /// `identity_notify` so any blocked `wait_for_peer_identity` callers
    /// observe the new mapping immediately, mirroring the production
    /// lifecycle-monitor path.
    pub(crate) async fn inject_peer_to_channel(&self, peer_id: PeerId, channel_id: String) {
        self.peer_to_channel
            .write()
            .await
            .entry(peer_id)
            .or_default()
            .insert(channel_id.clone());
        self.channel_to_peer
            .write()
            .await
            .insert(channel_id, peer_id);
        self.identity_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `wait_for_peer_identity` must return immediately when the channel
    /// is already populated. This is the fast path after the identity
    /// refactor: TLS-derived peer registration happens synchronously in
    /// the lifecycle monitor, so by the time most callers reach this
    /// helper the mapping is already in place.
    ///
    /// Uses `multi_thread` because `new_for_tests` internally calls
    /// `Handle::current().block_on(...)` and the single-threaded test
    /// runtime forbids nested blocking.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_for_peer_identity_returns_pre_populated_immediately() {
        let handle =
            tokio::task::spawn_blocking(|| TransportHandle::new_for_tests().expect("test handle"))
                .await
                .expect("spawn_blocking must succeed");
        let peer = PeerId::random();
        let channel_id = "127.0.0.1:1234".to_string();

        handle
            .inject_peer_to_channel(peer, channel_id.clone())
            .await;

        let resolved = tokio::time::timeout(
            Duration::from_millis(50),
            handle.wait_for_peer_identity(&channel_id, Duration::from_secs(5)),
        )
        .await
        .expect("must resolve well below timeout")
        .expect("must return Ok for known channel");

        assert_eq!(
            resolved, peer,
            "wait_for_peer_identity must return the injected peer ID",
        );
    }

    /// When a `channel_to_peer` insert lands AFTER the waiter starts but
    /// BEFORE its first poll of `notified()`, the waiter must still wake.
    /// This guards against the `Notify::notified()` registration race
    /// that the previous polling-loop implementation tolerated by accident
    /// and that the new event-driven path must handle correctly via
    /// `Notified::enable()`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_for_peer_identity_wakes_on_concurrent_insert() {
        let handle = Arc::new(
            tokio::task::spawn_blocking(|| TransportHandle::new_for_tests().expect("test handle"))
                .await
                .expect("spawn_blocking must succeed"),
        );
        let peer = PeerId::random();
        let channel_id = "127.0.0.1:5678".to_string();

        let waiter_handle = Arc::clone(&handle);
        let waiter_channel = channel_id.clone();
        let waiter = tokio::spawn(async move {
            waiter_handle
                .wait_for_peer_identity(&waiter_channel, Duration::from_secs(5))
                .await
        });

        // Yield so the waiter has a chance to enter wait_for_peer_identity
        // and reach `notified.as_mut().enable()`.
        tokio::task::yield_now().await;

        handle
            .inject_peer_to_channel(peer, channel_id.clone())
            .await;

        let resolved = tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("waiter must wake within 500ms of insert")
            .expect("waiter task should not panic")
            .expect("waiter should return Ok for the inserted channel");

        assert_eq!(
            resolved, peer,
            "wait_for_peer_identity must return the inserted peer ID",
        );
    }
}
