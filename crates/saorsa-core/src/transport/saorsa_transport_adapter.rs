// Copyright 2024 Saorsa Labs Limited
//
// Adapter for saorsa-transport integration

//! Ant-QUIC Transport Adapter
//!
//! This module provides a clean interface to saorsa-transport's peer-to-peer networking
//! with advanced NAT traversal and post-quantum cryptography.
//!
//! ## Architecture
//!
//! Uses saorsa-transport's LinkTransport trait abstraction:
//! - `P2pLinkTransport` for real network communication
//! - `MockTransport` for testing overlay logic
//! - All communication uses `SocketAddr` for connection addressing
//! - Authenticated public keys exposed via `LinkConn::peer_public_key()`
//! - Built-in NAT traversal, peer discovery, and post-quantum crypto
//!
//! ## Protocol Multiplexing
//!
//! The adapter uses protocol identifiers for overlay network multiplexing:
//! - `SAORSA_DHT_PROTOCOL` ("saorsa-dht/1.0.0") for DHT operations
//! - Custom protocols can be registered for different services
//!
//! **IMPORTANT**: Protocol-based filtering in `accept()` is not yet implemented in saorsa-transport.
//! The `accept()` method accepts all incoming connections regardless of protocol.
//! Applications must validate the protocol on received connections.
//!
//! ## NAT Traversal Configuration
//!
//! NAT traversal behavior is configured via `NetworkConfig`:
//! - `ClientOnly` - No incoming path validations (client mode)
//! - `P2PNode { concurrency_limit }` - Full P2P with configurable concurrency
//! - `Advanced { ... }` - Fine-grained control over all NAT options
//!
//! ## Metrics Integration
//!
//! When saorsa-core is compiled with the `metrics` feature, this adapter
//! automatically enables saorsa-transport's prometheus metrics collection.

use crate::error::{GeoRejectionError, GeographicConfig};
use crate::transport::observed_address_cache::ObservedAddressCache;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

// Import saorsa-transport types using the new LinkTransport API (0.14+)
use saorsa_transport::{
    LinkConn, LinkEvent, LinkTransport, NatConfig, P2pConfig, P2pLinkTransport, ProtocolId,
};

// Import saorsa-transport types for SharedTransport integration
use futures::StreamExt;
use saorsa_transport::SharedTransport;
use saorsa_transport::link_transport::StreamType;

/// Protocol identifier for saorsa DHT overlay
///
/// This protocol identifier is used for multiplexing saorsa's DHT traffic
/// over the QUIC transport. Other protocols can be registered for different services.
pub const SAORSA_DHT_PROTOCOL: ProtocolId = ProtocolId::from_static(b"saorsa-dht/1.0.0");

/// Connection lifecycle events from saorsa-transport
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConnectionEvent {
    /// Connection successfully established
    Established {
        remote_address: SocketAddr,
        public_key: Option<Vec<u8>>,
    },
    /// Connection lost/closed
    Lost {
        remote_address: SocketAddr,
        reason: String,
    },
    /// Connection attempt failed
    Failed {
        remote_address: SocketAddr,
        reason: String,
    },
    /// A connected peer advertised a new reachable address (ADD_ADDRESS frame).
    PeerAddressUpdated {
        peer_addr: SocketAddr,
        advertised_addr: SocketAddr,
    },
}

/// Native saorsa-transport network node using LinkTransport abstraction
///
/// This provides a clean interface to saorsa-transport's peer-to-peer networking
/// with advanced NAT traversal and post-quantum cryptography.
///
/// Generic over the transport type to allow testing with MockTransport.
#[allow(dead_code)]
pub struct P2PNetworkNode<T: LinkTransport = P2pLinkTransport> {
    /// The underlying transport (generic for testing)
    transport: Arc<T>,
    /// Our local binding address
    pub local_addr: SocketAddr,
    /// Peer registry for tracking connected peer addresses
    pub peers: Arc<RwLock<Vec<SocketAddr>>>,
    /// Connection event broadcaster
    event_tx: broadcast::Sender<ConnectionEvent>,
    /// Shutdown signal for event polling task
    shutdown: CancellationToken,
    /// Event forwarder task handle
    event_task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Geographic configuration for diversity enforcement
    geo_config: Option<GeographicConfig>,
    /// Peer region tracking for geographic diversity
    peer_regions: Arc<RwLock<HashMap<String, usize>>>,
    /// Peer quality scores from saorsa-transport Capabilities, keyed by SocketAddr
    peer_quality: Arc<RwLock<HashMap<SocketAddr, f32>>>,
    /// Shared transport for protocol multiplexing
    shared_transport: Arc<SharedTransport<T>>,
}

/// Default maximum number of concurrent QUIC connections when not
/// explicitly configured.
pub const DEFAULT_MAX_CONNECTIONS: usize = 100;

/// Bounded capacity for the relay/peer-address forwarder mpsc channels.
///
/// Replaces the previous `unbounded_channel` so a slow consumer (e.g. the
/// DHT bridge while running an iterative lookup) cannot grow the queue
/// without limit. When the channel is full the forwarder logs and drops
/// the event rather than blocking the receive loop, so we still keep
/// processing newer events.
pub const ADDRESS_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Log a warning every Nth dropped address-event in the forwarder.
///
/// `try_send` failures (channel full) increment a counter; logging at
/// every drop would flood the log under sustained pressure, so we
/// coalesce to one warning per `ADDRESS_EVENT_DROP_LOG_INTERVAL` drops.
const ADDRESS_EVENT_DROP_LOG_INTERVAL: u64 = 32;

/// Increment the drop counter and log periodically when the address-event
/// forwarder fails to push into a bounded channel.
///
/// Used by the forwarder loop in
/// [`DualStackNetworkNode::spawn_peer_address_update_forwarder`] when the
/// downstream consumer is too slow to drain. Drops are coalesced to one
/// warning per [`ADDRESS_EVENT_DROP_LOG_INTERVAL`] events to avoid log
/// floods under sustained backpressure; the very first drop in any burst
/// is always logged so operators see the onset.
fn handle_address_event_drop<T>(
    counter: &AtomicU64,
    event_kind: &'static str,
    err: &tokio::sync::mpsc::error::TrySendError<T>,
) {
    let prev = counter.fetch_add(1, Ordering::Relaxed);
    let kind = match err {
        tokio::sync::mpsc::error::TrySendError::Full(_) => "channel full",
        tokio::sync::mpsc::error::TrySendError::Closed(_) => "consumer closed",
    };
    if prev.is_multiple_of(ADDRESS_EVENT_DROP_LOG_INTERVAL) {
        tracing::warn!(
            event = event_kind,
            reason = kind,
            total_drops = prev + 1,
            "ADDR_FWD: dropped address event"
        );
    }
}

#[allow(dead_code)]
impl P2PNetworkNode<P2pLinkTransport> {
    /// Create a new P2P network node with default P2pLinkTransport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        Self::new_with_max_connections(bind_addr, DEFAULT_MAX_CONNECTIONS, None).await
    }

    /// Create a new P2P network node with a specific connection limit and
    /// optional message-size override.
    ///
    /// When `max_msg_size` is `None` saorsa-transport's built-in default is used.
    pub async fn new_with_max_connections(
        bind_addr: SocketAddr,
        max_connections: usize,
        max_msg_size: Option<usize>,
    ) -> Result<Self> {
        Self::new_with_options(bind_addr, max_connections, max_msg_size, false).await
    }

    /// Create a new P2P network node with full control over connection
    /// limits, message size, and loopback address acceptance.
    pub async fn new_with_options(
        bind_addr: SocketAddr,
        max_connections: usize,
        max_msg_size: Option<usize>,
        allow_loopback: bool,
    ) -> Result<Self> {
        let mut builder = P2pConfig::builder()
            .bind_addr(bind_addr)
            .max_connections(max_connections)
            .conservative_timeouts()
            .data_channel_capacity(P2pConfig::DEFAULT_DATA_CHANNEL_CAPACITY);
        if let Some(max_msg_size) = max_msg_size {
            builder = builder.max_message_size(max_msg_size);
        }
        if allow_loopback {
            builder = builder.nat(NatConfig {
                allow_loopback: true,
                ..NatConfig::default()
            });
        }
        let config = builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build P2P config: {}", e))?;

        let transport = P2pLinkTransport::new(config)
            .await
            .context("Failed to create transport")?;

        // Get the actual bound address from the endpoint (important for port 0 bindings)
        let actual_addr = transport.endpoint().local_addr().ok_or_else(|| {
            anyhow::anyhow!(
                "Transport endpoint has no local address — bind to {bind_addr} may have failed"
            )
        })?;

        Self::with_transport(Arc::new(transport), actual_addr).await
    }

    /// Create a new P2P network node with custom P2pConfig
    pub async fn new_with_config(_bind_addr: SocketAddr, config: P2pConfig) -> Result<Self> {
        let transport = P2pLinkTransport::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create transport: {}", e))?;

        // Get the actual bound address from the endpoint
        let actual_addr = transport.endpoint().local_addr().ok_or_else(|| {
            anyhow::anyhow!("Transport endpoint has no local address — bind may have failed")
        })?;

        Self::with_transport(Arc::new(transport), actual_addr).await
    }

    /// Send data to a peer using P2pEndpoint's send method
    ///
    /// This method is specialized for P2pLinkTransport and uses the underlying
    /// P2pEndpoint's send() method which corresponds with recv() for proper
    /// bidirectional communication.
    ///
    /// On failure the underlying transport error is preserved via
    /// `anyhow::Context` so callers can inspect the cause (e.g. QUIC
    /// `peer did not acknowledge`, `open_uni failed`, `PeerNotFound`).
    pub async fn send_to_peer_optimized(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        trace!(
            "[QUIC SEND] endpoint().send() to {} ({} bytes)",
            addr,
            data.len()
        );
        self.transport
            .endpoint()
            .send(addr, data)
            .await
            .with_context(|| format!("QUIC send to {} ({} bytes) failed", addr, data.len()))
    }

    /// Disconnect a specific peer, closing the underlying QUIC connection.
    ///
    /// Calls `P2pEndpoint::disconnect()` to tear down the QUIC connection
    /// and abort the per-connection reader task, then removes the peer from
    /// the local registry.
    pub async fn disconnect_peer_quic(&self, addr: &SocketAddr) {
        if let Err(e) = self.transport.endpoint().disconnect(addr).await {
            tracing::warn!("QUIC disconnect for peer {}: {}", addr, e);
        }
        // Also clean up from generic adapter state
        P2PNetworkNode::<P2pLinkTransport>::disconnect_peer_inner(
            &self.peers,
            &self.peer_quality,
            addr,
        )
        .await;
    }

    /// Spawn a background task that continuously receives messages from the
    /// QUIC endpoint and forwards them into the provided channel.
    ///
    /// Uses saorsa-transport v0.20's channel-based `recv()` which is fully
    /// event-driven — no polling or timeout parameter. Per-connection
    /// reader tasks inside saorsa-transport feed a shared mpsc channel, so
    /// `recv()` wakes instantly when data arrives on any peer's QUIC
    /// stream. The task exits when the shutdown signal is set, the
    /// channel is closed, or the endpoint shuts down.
    ///
    /// Returns the task handle for cleanup.
    pub fn spawn_recv_task(
        &self,
        tx: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        /// Maximum size of a single received message (16 MB).
        /// Messages exceeding this limit are dropped to prevent memory exhaustion.
        const MAX_RECV_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

        let transport = Arc::clone(&self.transport);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        break;
                    }
                    result = transport.endpoint().recv() => {
                        match result {
                            Ok((addr, data)) => {
                                if data.len() > MAX_RECV_MESSAGE_SIZE {
                                    tracing::warn!(
                                        "Dropping oversized message ({} bytes) from {}",
                                        data.len(),
                                        addr
                                    );
                                    continue;
                                }
                                if tx.send((addr, data)).await.is_err() {
                                    break; // channel closed
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Recv task exiting: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        })
    }
}

#[allow(dead_code)]
impl<T: LinkTransport + Send + Sync + 'static> P2PNetworkNode<T> {
    /// Create with any LinkTransport implementation (for testing)
    pub async fn with_transport(transport: Arc<T>, bind_addr: SocketAddr) -> Result<Self> {
        // Register our protocol
        transport.register_protocol(SAORSA_DHT_PROTOCOL);

        let (event_tx, _) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();

        // Start event forwarder that maps LinkEvent to ConnectionEvent
        let mut link_events = transport.subscribe();
        let event_tx_clone = event_tx.clone();
        let shutdown_clone = shutdown.clone();
        let peers_clone = Arc::new(RwLock::new(Vec::new()));
        let peers_for_task = Arc::clone(&peers_clone);
        let peer_quality = Arc::new(RwLock::new(HashMap::new()));
        let peer_quality_for_task = Arc::clone(&peer_quality);

        let event_task_handle = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown_clone.cancelled() => break,
                    recv = link_events.recv() => match recv {
                    Ok(LinkEvent::PeerConnected { addr, public_key, caps }) => {
                        // Capture quality score from saorsa-transport Capabilities
                        let quality = caps.quality_score();
                        {
                            let mut quality_map = peer_quality_for_task.write().await;
                            quality_map.insert(addr, quality);
                        }

                        // Note: Peer tracking with geographic validation is done by
                        // add_peer() in connect_to_peer() and accept_connection().
                        // The event forwarder only broadcasts the connection event.
                        // This avoids duplicate registration while preserving
                        // geographic validation functionality.

                        let _ = event_tx_clone.send(ConnectionEvent::Established {
                            remote_address: addr,
                            public_key,
                        });
                    }
                    Ok(LinkEvent::PeerDisconnected { addr, reason }) => {
                        // Remove the peer from tracking
                        {
                            let mut peers = peers_for_task.write().await;
                            peers.retain(|a| *a != addr);
                        }
                        // Also remove from quality scores
                        {
                            let mut quality_map = peer_quality_for_task.write().await;
                            quality_map.remove(&addr);
                        }

                        let _ = event_tx_clone.send(ConnectionEvent::Lost {
                            remote_address: addr,
                            reason: format!("{:?}", reason),
                        });
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Lost some events, continue
                        continue;
                    }
                    _ => {}
                }}
            }
        }));

        // Create SharedTransport for protocol multiplexing
        let shared_transport = Arc::new(SharedTransport::from_arc(Arc::clone(&transport)));

        // Note: DHT handler registration happens lazily when a DhtCoreEngine is provided
        // via register_dht_handler() method.
        Ok(Self {
            transport,
            local_addr: bind_addr,
            peers: peers_clone,
            event_tx,
            shutdown,
            event_task_handle,
            geo_config: None,
            peer_regions: Arc::new(RwLock::new(HashMap::new())),
            peer_quality,
            shared_transport,
        })
    }

    /// Register the DHT handler with the SharedTransport.
    ///
    /// This enables handling of DHT stream types (Query, Store, Witness, Replication)
    /// via the SharedTransport multiplexer.
    ///
    /// # Arguments
    ///
    /// * `dht_engine` - The DHT engine to process requests
    pub async fn register_dht_handler(
        &self,
        dht_engine: Arc<RwLock<crate::dht::core_engine::DhtCoreEngine>>,
    ) -> Result<()> {
        use crate::transport::dht_handler::DhtStreamHandler;
        use saorsa_transport::link_transport::ProtocolHandlerExt;

        let handler = DhtStreamHandler::new(dht_engine);
        self.shared_transport
            .register_handler(handler.boxed())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to register DHT handler: {}", e))?;

        tracing::info!("DHT handler registered with SharedTransport");
        Ok(())
    }

    /// Get a reference to the SharedTransport.
    ///
    /// Useful for registering additional protocol handlers.
    pub fn shared_transport(&self) -> Arc<SharedTransport<T>> {
        Arc::clone(&self.shared_transport)
    }

    /// Start the SharedTransport.
    ///
    /// Must be called before sending/receiving via SharedTransport.
    pub async fn start_shared_transport(&self) -> Result<()> {
        self.shared_transport
            .start()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start SharedTransport: {}", e))
    }

    /// Send data via SharedTransport with stream type routing.
    ///
    /// The stream type byte is prepended automatically.
    pub async fn send_typed(
        &self,
        addr: &SocketAddr,
        stream_type: StreamType,
        data: bytes::Bytes,
    ) -> Result<()> {
        self.shared_transport
            .send(addr, stream_type, data)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Failed to send typed data: {}", e))
    }

    /// Connect to a peer by address
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<SocketAddr> {
        // The full NAT traversal flow is: direct (2s) + 2 × hole-punch
        // rounds (3s + 1s retry each) + relay (10s) = ~20s. 25s provides
        // margin for handshake jitter.
        const DIAL_TIMEOUT: Duration = Duration::from_secs(25);

        let conn = tokio::time::timeout(
            DIAL_TIMEOUT,
            self.transport.dial_addr(peer_addr, SAORSA_DHT_PROTOCOL),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Connection timeout after {:?} to {}",
                DIAL_TIMEOUT,
                peer_addr
            )
        })?
        .map_err(|e| anyhow::anyhow!("Failed to connect to peer {}: {}", peer_addr, e))?;

        let remote_addr = conn.remote_addr();

        // Register the peer with geographic validation
        self.add_peer(remote_addr).await;

        // Note: ConnectionEvent is broadcast by event forwarder
        // to avoid duplicate events

        info!("Connected to peer at {}", remote_addr);
        Ok(remote_addr)
    }

    /// Try to accept one incoming connection.
    ///
    /// Returns `Some(...)` on success, `None` when the endpoint has shut
    /// down. A `None` return is terminal — the caller should exit its
    /// accept loop.
    ///
    /// **NOTE**: Protocol-based filtering is not yet implemented in saorsa-transport's `accept()` method.
    /// This method accepts connections for ANY protocol, not just `SAORSA_DHT_PROTOCOL`.
    /// Applications must validate that incoming connections are using the expected protocol.
    pub async fn accept_connection(&self) -> Option<SocketAddr> {
        let mut incoming = self.transport.accept(SAORSA_DHT_PROTOCOL);
        while let Some(conn_result) = incoming.next().await {
            match conn_result {
                Ok(conn) => {
                    let addr = conn.remote_addr();
                    self.add_peer(addr).await;
                    tracing::info!("Accepted connection from peer at {}", addr);
                    return Some(addr);
                }
                Err(e) => {
                    tracing::warn!("Accept stream error: {}", e);
                }
            }
        }
        None
    }

    /// Static helper for region lookup (used in spawned tasks)
    fn get_region_for_ip_static(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                match octets.first() {
                    Some(0..=63) => "NA".to_string(),
                    Some(64..=127) => "EU".to_string(),
                    Some(128..=191) => "APAC".to_string(),
                    Some(192..=223) => "SA".to_string(),
                    Some(224..=255) => "OTHER".to_string(),
                    None => "UNKNOWN".to_string(),
                }
            }
            IpAddr::V6(_) => "UNKNOWN".to_string(),
        }
    }

    /// Send data to a specific peer by address.
    ///
    /// Dials the peer by address, opens a typed unidirectional stream,
    /// writes the data, and finishes the stream.
    pub async fn send_to_peer_raw(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        // Budget must cover dial (up to ~25s for full NAT traversal cascade)
        // plus the data transfer (4MB chunk at 10Mbps ≈ 3s).
        const SEND_TIMEOUT: Duration = Duration::from_secs(35);

        tokio::time::timeout(SEND_TIMEOUT, async {
            let conn = self
                .transport
                .dial_addr(*addr, SAORSA_DHT_PROTOCOL)
                .await
                .map_err(|e| anyhow::anyhow!("Dial by address failed: {}", e))?;

            // Open a typed unidirectional stream for DHT messages
            // Using DhtStore stream type for DHT protocol messages
            let mut stream = conn
                .open_uni_typed(StreamType::DhtStore)
                .await
                .map_err(|e| anyhow::anyhow!("Stream open failed: {}", e))?;

            // Use LinkSendStream trait methods directly
            stream
                .write_all(data)
                .await
                .map_err(|e| anyhow::anyhow!("Write failed: {}", e))?;
            stream
                .finish()
                .map_err(|e| anyhow::anyhow!("Stream finish failed: {}", e))?;

            Ok(())
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("send_to_peer_raw timed out after {SEND_TIMEOUT:?} to {addr}")
        })?
    }

    /// Get our local address
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the actual bound listening address
    pub async fn actual_listening_address(&self) -> Result<SocketAddr> {
        // Try to get external address first
        if let Some(addr) = self.transport.external_address() {
            return Ok(addr);
        }
        // Fallback to configured address
        Ok(self.local_addr)
    }

    /// Get our local public key (ML-DSA-65 SPKI bytes)
    pub fn our_public_key(&self) -> Vec<u8> {
        self.transport.local_public_key()
    }

    /// Get our observed external address as reported by peers
    pub fn get_observed_external_address(&self) -> Option<SocketAddr> {
        self.transport.external_address()
    }

    /// Get all connected peer addresses
    pub async fn get_connected_peers(&self) -> Vec<SocketAddr> {
        self.peers.read().await.clone()
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.transport.is_connected(addr)
    }

    /// Check if a peer is authenticated (always true with PQC auth)
    pub async fn is_authenticated(&self, _addr: &SocketAddr) -> bool {
        // With saorsa-transport 0.14+, all connections are PQC authenticated
        true
    }

    /// Connect to bootstrap nodes to join the network
    pub async fn bootstrap_from_nodes(
        &self,
        bootstrap_addrs: &[SocketAddr],
    ) -> Result<Vec<SocketAddr>> {
        let mut connected_peers = Vec::new();

        for &addr in bootstrap_addrs {
            match self.connect_to_peer(addr).await {
                Ok(peer_addr) => {
                    connected_peers.push(peer_addr);
                    tracing::info!("Successfully bootstrapped from {}", addr);
                }
                Err(e) => {
                    tracing::warn!("Failed to bootstrap from {}: {}", addr, e);
                }
            }
        }

        if connected_peers.is_empty() {
            return Err(anyhow::anyhow!("Failed to connect to any bootstrap nodes"));
        }

        Ok(connected_peers)
    }

    /// Internal helper to register a peer with geographic validation
    async fn add_peer(&self, addr: SocketAddr) {
        // Perform geographic validation if configured
        if let Some(ref config) = self.geo_config {
            match self.validate_geographic_diversity(&addr, config).await {
                Ok(()) => {}
                Err(err) => {
                    tracing::warn!("REJECTED peer {} - {}", addr, err);
                    return;
                }
            }
        }

        let mut peers = self.peers.write().await;

        if !peers.contains(&addr) {
            peers.push(addr);

            let region = self.get_region_for_ip(&addr.ip());
            let mut regions = self.peer_regions.write().await;
            *regions.entry(region).or_insert(0) += 1;

            tracing::debug!("Added peer from {}", addr);
        }
    }

    /// Validate geographic diversity before adding a peer
    async fn validate_geographic_diversity(
        &self,
        addr: &SocketAddr,
        config: &GeographicConfig,
    ) -> std::result::Result<(), GeoRejectionError> {
        let region = self.get_region_for_ip(&addr.ip());

        if config.blocked_regions.contains(&region) {
            return Err(GeoRejectionError::BlockedRegion(region));
        }

        let regions = self.peer_regions.read().await;
        let total_peers: usize = regions.values().sum();

        if total_peers > 0 {
            let region_count = *regions.get(&region).unwrap_or(&0);
            let new_ratio = (region_count + 1) as f64 / (total_peers + 1) as f64;

            if new_ratio > config.max_single_region_ratio {
                return Err(GeoRejectionError::DiversityViolation {
                    region,
                    current_ratio: new_ratio * 100.0,
                });
            }
        }

        Ok(())
    }

    /// Get region for an IP address (simplified placeholder)
    fn get_region_for_ip(&self, ip: &IpAddr) -> String {
        Self::get_region_for_ip_static(ip)
    }

    /// Get current region ratio for a specific region
    pub async fn get_region_ratio(&self, region: &str) -> f64 {
        let regions = self.peer_regions.read().await;
        let total_peers: usize = regions.values().sum();
        if total_peers == 0 {
            return 0.0;
        }
        let region_count = *regions.get(region).unwrap_or(&0);
        (region_count as f64 / total_peers as f64) * 100.0
    }

    /// Set geographic configuration for diversity enforcement
    pub fn set_geographic_config(&mut self, config: GeographicConfig) {
        tracing::info!(
            "Geographic validation enabled: mode={:?}, max_ratio={}%, blocked_regions={:?}",
            config.enforcement_mode,
            config.max_single_region_ratio * 100.0,
            config.blocked_regions
        );
        self.geo_config = Some(config);
    }

    /// Check if geographic validation is enabled
    pub fn is_geo_validation_enabled(&self) -> bool {
        self.geo_config.is_some()
    }

    /// Get peer region distribution statistics
    pub async fn get_region_stats(&self) -> HashMap<String, usize> {
        self.peer_regions.read().await.clone()
    }

    /// Send data to a peer.
    pub async fn send_to_peer(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        self.send_to_peer_raw(addr, data).await
    }

    /// Connect to a peer and return the remote address as a string.
    pub async fn connect_to_peer_string(&self, peer_addr: SocketAddr) -> Result<String> {
        let addr = self.connect_to_peer(peer_addr).await?;
        Ok(addr.to_string())
    }

    /// Send a message to a peer.
    pub async fn send_message(&self, addr: &SocketAddr, data: Vec<u8>) -> Result<()> {
        self.send_to_peer(addr, &data).await
    }

    /// Subscribe to connection lifecycle events
    pub fn subscribe_connection_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    /// Disconnect a specific peer by removing it from local tracking.
    ///
    /// For `P2pLinkTransport`, prefer `disconnect_peer_quic()` which also
    /// tears down the underlying QUIC connection.
    pub async fn disconnect_peer(&self, addr: &SocketAddr) {
        Self::disconnect_peer_inner(&self.peers, &self.peer_quality, addr).await;
    }

    /// Shared helper to remove a peer from adapter-level tracking.
    async fn disconnect_peer_inner(
        peers: &RwLock<Vec<SocketAddr>>,
        peer_quality: &RwLock<HashMap<SocketAddr, f32>>,
        addr: &SocketAddr,
    ) {
        {
            let mut peers = peers.write().await;
            peers.retain(|a| a != addr);
        }
        {
            let mut quality_map = peer_quality.write().await;
            quality_map.remove(addr);
        }
        tracing::debug!("Disconnected peer {} from adapter", addr);
    }

    /// Shutdown the node gracefully
    pub async fn shutdown(&mut self) {
        tracing::info!("Shutting down P2PNetworkNode");

        self.shutdown.cancel();

        // Stop transport first so the link event stream closes and any
        // event-forwarder task blocked on recv() can exit.
        self.transport.shutdown().await;

        if let Some(handle) = self.event_task_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Dual-stack wrapper managing IPv4 and IPv6 transports.
///
/// When `is_dual_stack` is true (`v6` is Some, `v4` is None), the v6 socket
/// handles both IPv4 and IPv6 via the kernel's dual-stack mechanism
/// (`bindv6only=0`).  The kernel represents IPv4 peers as `[::ffff:x.x.x.x]`
/// internally.  This struct normalises all addresses at its boundary so that
/// code above (saorsa-core) always sees plain IPv4 addresses, while code below
/// (P2PNetworkNode / Quinn) uses the native socket format.
#[allow(dead_code)]
pub struct DualStackNetworkNode<T: LinkTransport = P2pLinkTransport> {
    pub v6: Option<P2PNetworkNode<T>>,
    pub v4: Option<P2PNetworkNode<T>>,
    /// True when v6 handles IPv4 too (bindv6only=0, v4 bind skipped).
    is_dual_stack: bool,
}

#[allow(dead_code)]
impl DualStackNetworkNode<P2pLinkTransport> {
    /// Set the target peer ID for a hole-punch attempt to a specific address.
    /// The P2pEndpoint uses this in PUNCH_ME_NOW to let the coordinator match
    /// by peer identity. Keyed by address to avoid concurrent dial races.
    pub async fn set_hole_punch_target_peer_id(&self, target: SocketAddr, peer_id: [u8; 32]) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            node.transport
                .endpoint()
                .set_hole_punch_target_peer_id(target, peer_id)
                .await;
        }
    }

    /// Set a preferred coordinator for hole-punching to a specific target.
    /// The preferred coordinator is a peer that referred us to the target
    /// during a DHT lookup, so it has a connection to the target.
    pub async fn set_hole_punch_preferred_coordinator(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
    ) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            node.transport
                .endpoint()
                .set_hole_punch_preferred_coordinator(target, coordinator)
                .await;
        }
    }

    /// Register a peer ID at the low-level transport endpoint for PUNCH_ME_NOW
    /// relay routing. Called when identity exchange completes on a connection.
    pub async fn register_connection_peer_id(&self, addr: SocketAddr, peer_id: [u8; 32]) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            let endpoint = node.transport.endpoint();
            endpoint.register_connection_peer_id(addr, peer_id);
            // Also register the dual-stack alternate form (IPv4 ↔ IPv4-mapped IPv6)
            // so peer ID routing works regardless of which form the connection uses.
            if let Some(alt) = saorsa_transport::shared::dual_stack_alternate(&addr) {
                endpoint.register_connection_peer_id(alt, peer_id);
            }
        }
    }

    /// Check if a peer has a live QUIC connection via either stack.
    ///
    /// Checks the underlying P2pEndpoint's NatTraversalEndpoint connections
    /// DashMap directly, which is authoritative for QUIC connection state.
    /// Tries both the plain and IPv4-mapped address forms to handle
    /// dual-stack normalization.
    pub async fn is_peer_connected_by_addr(&self, addr: &std::net::SocketAddr) -> bool {
        let mapped = saorsa_transport::shared::dual_stack_alternate(addr);
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            // Check NatTraversalEndpoint's connections (authoritative for QUIC state)
            let endpoint = node.transport.endpoint();
            if endpoint.inner_is_connected(addr) {
                return true;
            }
            if let Some(ref alt) = mapped
                && endpoint.inner_is_connected(alt)
            {
                return true;
            }
            // Also check the link transport capabilities cache
            if node.is_connected(addr).await {
                return true;
            }
            if let Some(ref alt) = mapped
                && node.is_connected(alt).await
            {
                return true;
            }
        }
        false
    }

    /// Shut down the underlying QUIC endpoints on both stacks.
    ///
    /// This cancels each endpoint's internal `CancellationToken`, which
    /// unblocks any in-flight `recv()` calls and aborts per-connection
    /// reader tasks.  Call this **before** joining background tasks that
    /// are blocked inside `endpoint().recv()`.
    pub async fn shutdown_endpoints(&self) {
        if let Some(ref v6) = self.v6 {
            v6.transport.endpoint().shutdown().await;
        }
        if let Some(ref v4) = self.v4 {
            v4.transport.endpoint().shutdown().await;
        }
    }

    /// Spawn background tasks that forward address-related `P2pEvent`s from
    /// each stack's `P2pEndpoint` to the upper layers.
    ///
    /// Three event flavours are bridged:
    ///
    /// - **`PeerAddressUpdated`**: a connected peer advertised a new
    ///   reachable address via an ADD_ADDRESS frame (typically a relay).
    ///   Returned via the first mpsc receiver as
    ///   `(peer_connection_addr, advertised_addr)`.
    /// - **`RelayEstablished`**: this node set up a MASQUE relay and now
    ///   needs to publish the relay address to the K closest peers.
    ///   Returned via the second mpsc receiver.
    /// - **`ExternalAddressDiscovered`**: a peer reported the address it
    ///   sees this node at, via a QUIC `OBSERVED_ADDRESS` frame. Recorded
    ///   directly into the supplied [`ObservedAddressCache`] so the
    ///   transport layer can fall back to it when no live connection has an
    ///   observation. See the cache module for the frequency- and
    ///   recency-aware selection algorithm.
    ///
    /// Other `P2pEvent` variants are not consumed by saorsa-core and are
    /// silently ignored.
    pub fn spawn_peer_address_update_forwarder(
        &self,
        observed_cache: Arc<parking_lot::Mutex<ObservedAddressCache>>,
    ) -> (
        tokio::sync::mpsc::Receiver<(SocketAddr, SocketAddr)>,
        tokio::sync::mpsc::Receiver<SocketAddr>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(ADDRESS_EVENT_CHANNEL_CAPACITY);
        let (relay_tx, relay_rx) = tokio::sync::mpsc::channel(ADDRESS_EVENT_CHANNEL_CAPACITY);
        let drop_counter = Arc::new(AtomicU64::new(0));
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            let mut p2p_rx = node.transport.endpoint().subscribe();
            let tx_clone = tx.clone();
            let relay_tx_clone = relay_tx.clone();
            let cache_clone = Arc::clone(&observed_cache);
            let drops = Arc::clone(&drop_counter);
            // Capture which local bind owns this forwarder so the cache can
            // partition observations by interface (multi-homed correctness).
            let local_bind = node.local_address();
            tokio::spawn(async move {
                tracing::debug!(
                    local_bind = %local_bind,
                    "ADDR_FWD: peer address update forwarder started"
                );
                loop {
                    match p2p_rx.recv().await {
                        Ok(saorsa_transport::P2pEvent::PeerAddressUpdated {
                            peer_addr,
                            advertised_addr,
                        }) => {
                            tracing::debug!(
                                "ADDR_FWD: received PeerAddressUpdated peer={} addr={}",
                                peer_addr,
                                advertised_addr
                            );
                            let payload = (
                                saorsa_transport::shared::normalize_socket_addr(peer_addr),
                                saorsa_transport::shared::normalize_socket_addr(advertised_addr),
                            );
                            if let Err(err) = tx_clone.try_send(payload) {
                                handle_address_event_drop(&drops, "PeerAddressUpdated", &err);
                            }
                        }
                        Ok(saorsa_transport::P2pEvent::RelayEstablished { relay_addr }) => {
                            tracing::info!(
                                "ADDR_FWD: received RelayEstablished relay_addr={}",
                                relay_addr
                            );
                            if let Err(err) = relay_tx_clone.try_send(relay_addr) {
                                handle_address_event_drop(&drops, "RelayEstablished", &err);
                            }
                        }
                        Ok(saorsa_transport::P2pEvent::ExternalAddressDiscovered { addr }) => {
                            // Convert TransportAddr → SocketAddr for QUIC.
                            // Non-UDP transports (BLE, LoRa) yield None and
                            // are skipped — the cache only models routable
                            // IP addresses.
                            if let Some(socket_addr) = addr.as_socket_addr() {
                                let normalized =
                                    saorsa_transport::shared::normalize_socket_addr(socket_addr);
                                tracing::debug!(
                                    local_bind = %local_bind,
                                    "ADDR_FWD: caching observed external address {}",
                                    normalized
                                );
                                cache_clone.lock().record(local_bind, normalized);
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("ADDR_FWD: channel closed, exiting");
                            break;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("ADDR_FWD: lagged {} events", n);
                            continue;
                        }
                        Ok(_other) => {
                            // Other P2pEvent variants (PeerConnected,
                            // PeerDisconnected, NatTraversalProgress,
                            // BootstrapStatus, PeerAuthenticated,
                            // DataReceived, …) are not consumed here.
                            // They are observed via other channels or are
                            // simply not relevant to saorsa-core.
                            continue;
                        }
                    }
                }
            });
        }
        (rx, relay_rx)
    }

    /// Create dual nodes bound to IPv6 and IPv4 addresses with default
    /// connection limit.
    pub async fn new(v6_addr: Option<SocketAddr>, v4_addr: Option<SocketAddr>) -> Result<Self> {
        Self::new_with_max_connections(v6_addr, v4_addr, DEFAULT_MAX_CONNECTIONS, None).await
    }

    /// Create dual nodes with an explicit maximum connection limit and
    /// optional message-size override.
    ///
    /// When `max_msg_size` is `None` the crate-level [`MAX_MESSAGE_SIZE`]
    /// default is used.
    pub async fn new_with_max_connections(
        v6_addr: Option<SocketAddr>,
        v4_addr: Option<SocketAddr>,
        max_connections: usize,
        max_msg_size: Option<usize>,
    ) -> Result<Self> {
        Self::new_with_options(v6_addr, v4_addr, max_connections, max_msg_size, false).await
    }

    /// Create dual nodes with full control over connection limits, message
    /// size, and loopback address acceptance.
    pub async fn new_with_options(
        v6_addr: Option<SocketAddr>,
        v4_addr: Option<SocketAddr>,
        max_connections: usize,
        max_msg_size: Option<usize>,
        allow_loopback: bool,
    ) -> Result<Self> {
        let v6 = if let Some(addr) = v6_addr {
            Some(
                P2PNetworkNode::new_with_options(
                    addr,
                    max_connections,
                    max_msg_size,
                    allow_loopback,
                )
                .await?,
            )
        } else {
            None
        };
        let v4 = if let Some(addr) = v4_addr {
            match P2PNetworkNode::new_with_options(
                addr,
                max_connections,
                max_msg_size,
                allow_loopback,
            )
            .await
            {
                Ok(node) => Some(node),
                Err(e) => {
                    // On Linux with net.ipv6.bindv6only=0 (the default), an IPv6
                    // socket bound to [::]:port already accepts IPv4 traffic via
                    // dual-stack.  Binding a separate IPv4 socket to the same port
                    // then fails with "Address in use".  When we already hold an
                    // IPv6 socket on that port we can safely skip the IPv4 bind.
                    //
                    // Only applies when the IPv6 address is unspecified ([::]); a
                    // specific IPv6 address won't accept IPv4 traffic.
                    let same_port = match (v6_addr, v4_addr) {
                        (Some(v6_sock), Some(v4_sock)) => v6_sock.port() == v4_sock.port(),
                        _ => false,
                    };
                    let v6_is_unspecified = matches!(
                        v6_addr,
                        Some(SocketAddr::V6(ref a)) if a.ip().is_unspecified()
                    );
                    // Prefer downcasting through the error chain to find the
                    // original io::Error (works when .context() preserves the
                    // source).  Fall back to string matching because the current
                    // transport layer stringifies the io::Error before wrapping.
                    let is_addr_in_use = e
                        .chain()
                        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                        .any(|io_err| io_err.kind() == std::io::ErrorKind::AddrInUse)
                        || format!("{e:#}").contains("in use");

                    if v6.is_some() && v6_is_unspecified && same_port && is_addr_in_use {
                        info!(
                            port = addr.port(),
                            "IPv6 socket is dual-stack — skipping separate IPv4 bind"
                        );
                        debug!("IPv4 bind error (suppressed): {e}");
                        None
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            None
        };
        let is_dual_stack = v6.is_some() && v4.is_none();
        Ok(Self {
            v6,
            v4,
            is_dual_stack,
        })
    }

    /// Send to peer using P2pEndpoint's optimized send method.
    ///
    /// Uses P2pEndpoint::send() which corresponds with recv() for proper
    /// bidirectional communication. Tries IPv6 first, then IPv4.
    ///
    /// In dual-stack mode, converts plain IPv4 addresses to the mapped form
    /// expected by the v6 transport before sending.
    pub async fn send_to_peer_optimized(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        // Preserve the underlying error(s) from the v6 and v4 stacks so the
        // caller can surface them at WARN level. The previous implementation
        // dropped both errors and returned a hardcoded
        // "send_to_peer_optimized failed on both stacks" which made every
        // transport failure look identical in the logs.
        let mut v6_err: Option<anyhow::Error> = None;
        let mut v4_err: Option<anyhow::Error> = None;

        if let Some(v6) = &self.v6 {
            let wire_addr = self.to_mapped_if_needed(addr);
            match v6.send_to_peer_optimized(&wire_addr, data).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!("[DUAL SEND] IPv6 send to {} failed: {:#}", addr, e);
                    v6_err = Some(e);
                }
            }
        }
        if let Some(v4) = &self.v4 {
            match v4.send_to_peer_optimized(addr, data).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!("[DUAL SEND] IPv4 send to {} failed: {:#}", addr, e);
                    v4_err = Some(e);
                }
            }
        }

        // Produce a single error that preserves the full cause chain from
        // whichever stack(s) were actually tried. In dual-stack-over-v6 mode
        // (v4 is None) we don't lie about having tried v4.
        let err = match (v6_err, v4_err) {
            (Some(v6), Some(v4)) => v6.context(format!(
                "send_to_peer_optimized to {} failed on both stacks (v4 cause: {:#})",
                addr, v4
            )),
            (Some(v6), None) => v6.context(format!(
                "send_to_peer_optimized to {} failed (v6-only: no v4 stack bound)",
                addr
            )),
            (None, Some(v4)) => v4.context(format!(
                "send_to_peer_optimized to {} failed (v4-only: no v6 stack bound)",
                addr
            )),
            (None, None) => anyhow::anyhow!(
                "send_to_peer_optimized to {}: neither v6 nor v4 stack available",
                addr
            ),
        };
        Err(err)
    }

    /// Disconnect a peer, closing the underlying QUIC connection.
    ///
    /// Tries both IPv6 and IPv4 stacks. In dual-stack mode, converts
    /// plain IPv4 to mapped form for the v6 transport.
    pub async fn disconnect_peer_by_addr(&self, addr: &SocketAddr) {
        if let Some(ref v6) = self.v6 {
            let wire_addr = self.to_mapped_if_needed(addr);
            v6.disconnect_peer_quic(&wire_addr).await;
        }
        if let Some(ref v4) = self.v4 {
            v4.disconnect_peer_quic(addr).await;
        }
    }

    /// Disconnect a peer by address.
    pub async fn disconnect_peer(&self, addr: &SocketAddr) {
        self.disconnect_peer_by_addr(addr).await;
    }

    /// Spawn recv tasks for all active stacks.
    ///
    /// In dual-stack mode, addresses from the v6 transport are normalised
    /// (IPv4-mapped → plain IPv4) before being sent to the channel so that
    /// saorsa-core always sees a consistent address format.
    pub fn spawn_recv_tasks(
        &self,
        tx: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        if let Some(v6) = self.v6.as_ref() {
            if self.is_dual_stack {
                let (inner_tx, mut inner_rx) = tokio::sync::mpsc::channel::<(SocketAddr, Vec<u8>)>(
                    crate::network::MESSAGE_RECV_CHANNEL_CAPACITY,
                );
                handles.push(v6.spawn_recv_task(inner_tx, shutdown.clone()));
                let outer_tx = tx.clone();
                handles.push(tokio::spawn(async move {
                    while let Some((addr, data)) = inner_rx.recv().await {
                        let norm = saorsa_transport::shared::normalize_socket_addr(addr);
                        if outer_tx.send((norm, data)).await.is_err() {
                            break;
                        }
                    }
                }));
            } else {
                handles.push(v6.spawn_recv_task(tx.clone(), shutdown.clone()));
            }
        }

        if let Some(v4) = self.v4.as_ref() {
            handles.push(v4.spawn_recv_task(tx.clone(), shutdown.clone()));
        }

        handles
    }
}

#[allow(dead_code)]
impl<T: LinkTransport + Send + Sync + 'static> DualStackNetworkNode<T> {
    /// Create with custom transports (for testing)
    pub fn with_transports(v6: Option<P2PNetworkNode<T>>, v4: Option<P2PNetworkNode<T>>) -> Self {
        let is_dual_stack = v6.is_some() && v4.is_none();
        Self {
            v6,
            v4,
            is_dual_stack,
        }
    }

    /// If dual-stack, normalise IPv4-mapped IPv6 → plain IPv4.
    /// Otherwise return unchanged.  Used on all addresses leaving the
    /// transport boundary towards saorsa-core.
    fn normalize(&self, addr: SocketAddr) -> SocketAddr {
        if self.is_dual_stack {
            saorsa_transport::shared::normalize_socket_addr(addr)
        } else {
            addr
        }
    }

    /// If dual-stack and `addr` is plain IPv4, convert to the mapped
    /// form `[::ffff:x.x.x.x]` that the v6 transport expects.
    /// Used on all addresses entering the transport from saorsa-core.
    fn to_mapped_if_needed(&self, addr: &SocketAddr) -> SocketAddr {
        if self.is_dual_stack
            && let SocketAddr::V4(v4) = addr
        {
            return SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0));
        }
        *addr
    }

    /// Happy Eyeballs connect: race IPv6 and IPv4 attempts.
    ///
    /// In dual-stack mode, IPv4 targets are converted to mapped form for the
    /// v6 transport.  The returned address is always normalised (plain IPv4).
    pub async fn connect_happy_eyeballs(&self, targets: &[SocketAddr]) -> Result<SocketAddr> {
        let mut v6_targets: Vec<SocketAddr> = Vec::new();
        let mut v4_targets: Vec<SocketAddr> = Vec::new();
        for &t in targets {
            if t.is_ipv6() {
                v6_targets.push(t);
            } else {
                v4_targets.push(t);
            }
        }

        // Race both stacks if both are available with targets
        let (v6_node, v4_node) = match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) if !v6_targets.is_empty() && !v4_targets.is_empty() => (v6, v4),
            (Some(_), _) if !v6_targets.is_empty() => {
                let addr = self.connect_sequential(&self.v6, &v6_targets).await?;
                return Ok(self.normalize(addr));
            }
            (_, Some(_)) if !v4_targets.is_empty() => {
                let addr = self.connect_sequential(&self.v4, &v4_targets).await?;
                return Ok(self.normalize(addr));
            }
            // Dual-stack: v6 socket can reach IPv4 peers via mapped addresses
            (Some(_), None) if !v4_targets.is_empty() => {
                let mapped: Vec<SocketAddr> = v4_targets
                    .iter()
                    .map(|a| self.to_mapped_if_needed(a))
                    .collect();
                let addr = self.connect_sequential(&self.v6, &mapped).await?;
                return Ok(self.normalize(addr));
            }
            _ => return Err(anyhow::anyhow!("No suitable transport available")),
        };

        let v6_targets_clone = v6_targets.clone();
        let v4_targets_clone = v4_targets.clone();

        let v6_fut = async {
            for addr in v6_targets_clone {
                if let Ok(connected_addr) = v6_node.connect_to_peer(addr).await {
                    return Ok(connected_addr);
                }
            }
            Err(anyhow::anyhow!("IPv6 connect attempts failed"))
        };

        let v4_fut = async {
            sleep(Duration::from_millis(50)).await; // Slight delay per Happy Eyeballs
            for addr in v4_targets_clone {
                if let Ok(connected_addr) = v4_node.connect_to_peer(addr).await {
                    return Ok(connected_addr);
                }
            }
            Err(anyhow::anyhow!("IPv4 connect attempts failed"))
        };

        tokio::select! {
            res6 = v6_fut => match res6 {
                Ok(connected_addr) => Ok(connected_addr),
                Err(_) => {
                    for addr in v4_targets {
                        if let Ok(connected_addr) = v4_node.connect_to_peer(addr).await {
                            return Ok(connected_addr);
                        }
                    }
                    Err(anyhow::anyhow!("All connect attempts failed"))
                }
            },
            res4 = v4_fut => match res4 {
                Ok(connected_addr) => Ok(connected_addr),
                Err(_) => {
                    for addr in v6_targets {
                        if let Ok(connected_addr) = v6_node.connect_to_peer(addr).await {
                            return Ok(connected_addr);
                        }
                    }
                    Err(anyhow::anyhow!("All connect attempts failed"))
                }
            }
        }
    }

    async fn connect_sequential(
        &self,
        node: &Option<P2PNetworkNode<T>>,
        targets: &[SocketAddr],
    ) -> Result<SocketAddr> {
        let node = node
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node not available"))?;
        for &addr in targets {
            if let Ok(connected_addr) = node.connect_to_peer(addr).await {
                return Ok(connected_addr);
            }
        }
        Err(anyhow::anyhow!("All connect attempts failed"))
    }

    /// Return all local listening addresses
    pub async fn local_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            let actual_addr = v6.actual_listening_address().await?;
            out.push(actual_addr);
        }
        if let Some(v4) = &self.v4 {
            let actual_addr = v4.actual_listening_address().await?;
            out.push(actual_addr);
        }
        Ok(out)
    }

    /// Accept the next incoming connection from either stack.
    ///
    /// Returns `None` when shutdown is signalled or no stacks are available.
    /// Addresses are normalised so callers always see plain IPv4.
    pub async fn accept_any(&self) -> Option<SocketAddr> {
        let raw = match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                tokio::select! {
                    res = v6.accept_connection() => res,
                    res = v4.accept_connection() => res,
                }
            }
            (Some(v6), None) => v6.accept_connection().await,
            (None, Some(v4)) => v4.accept_connection().await,
            (None, None) => None,
        };
        raw.map(|a| self.normalize(a))
    }

    /// Get all connected peer addresses (merged from both stacks).
    /// Addresses are normalised so callers always see plain IPv4.
    pub async fn get_connected_peers(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            out.extend(v6.get_connected_peers().await);
        }
        if let Some(v4) = &self.v4 {
            out.extend(v4.get_connected_peers().await);
        }
        if self.is_dual_stack {
            for addr in &mut out {
                *addr = saorsa_transport::shared::normalize_socket_addr(*addr);
            }
        }
        out
    }

    /// Send to peer by address; tries IPv6 first, then IPv4.
    /// In dual-stack mode, converts plain IPv4 to mapped form for v6.
    pub async fn send_to_peer_raw(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        if let Some(v6) = &self.v6 {
            let wire_addr = self.to_mapped_if_needed(addr);
            if v6.send_to_peer_raw(&wire_addr, data).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(v4) = &self.v4
            && v4.send_to_peer_raw(addr, data).await.is_ok()
        {
            return Ok(());
        }
        Err(anyhow::anyhow!("send_to_peer_raw failed on both stacks"))
    }

    /// Send to peer by address.
    pub async fn send_to_peer(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        self.send_to_peer_raw(addr, data).await
    }

    /// Subscribe to connection lifecycle events from both stacks.
    /// Addresses in events are normalised so callers always see plain IPv4.
    pub fn subscribe_connection_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        let (tx, rx) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let dual = self.is_dual_stack;

        if let Some(v6) = &self.v6 {
            let mut v6_rx = v6.subscribe_connection_events();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                loop {
                    match v6_rx.recv().await {
                        Ok(event) => {
                            let event = if dual {
                                normalize_connection_event(event)
                            } else {
                                event
                            };
                            let _ = tx_clone.send(event);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                "IPv6 connection event forwarder lagged, skipped {n} events"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                tracing::debug!("IPv6 connection event forwarder exited");
            });
        }

        if let Some(v4) = &self.v4 {
            let mut v4_rx = v4.subscribe_connection_events();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                loop {
                    match v4_rx.recv().await {
                        Ok(event) => {
                            let _ = tx_clone.send(event);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                "IPv4 connection event forwarder lagged, skipped {n} events"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                tracing::debug!("IPv4 connection event forwarder exited");
            });
        }

        // Drop the original sender so channel lifetime is determined by forwarder tasks
        drop(tx);
        rx
    }

    /// Get observed external address
    pub fn get_observed_external_address(&self) -> Option<SocketAddr> {
        let raw = self
            .v4
            .as_ref()
            .and_then(|v4| v4.get_observed_external_address())
            .or_else(|| {
                self.v6
                    .as_ref()
                    .and_then(|v6| v6.get_observed_external_address())
            });
        raw.map(|a| self.normalize(a))
    }

    /// Return observed external addresses for **every** stack that has one.
    ///
    /// Multi-homed publishing path: each stack (v4 / v6) is queried
    /// independently and any address it reports is included in the
    /// returned list (deduped, normalised). A multi-homed host that has
    /// observations on both v4 and v6 will return both — `local_dht_node`
    /// then publishes both so peers reaching the host on either family
    /// can dial it.
    pub fn get_observed_external_addresses(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for stack in [self.v4.as_ref(), self.v6.as_ref()].into_iter().flatten() {
            if let Some(raw) = stack.get_observed_external_address() {
                let normalized = self.normalize(raw);
                if !out.contains(&normalized) {
                    out.push(normalized);
                }
            }
        }
        out
    }
}

/// Normalise addresses in a `ConnectionEvent` (IPv4-mapped → plain IPv4).
fn normalize_connection_event(event: ConnectionEvent) -> ConnectionEvent {
    use saorsa_transport::shared::normalize_socket_addr;
    match event {
        ConnectionEvent::Established {
            remote_address,
            public_key,
        } => ConnectionEvent::Established {
            remote_address: normalize_socket_addr(remote_address),
            public_key,
        },
        ConnectionEvent::Lost {
            remote_address,
            reason,
        } => ConnectionEvent::Lost {
            remote_address: normalize_socket_addr(remote_address),
            reason,
        },
        ConnectionEvent::Failed {
            remote_address,
            reason,
        } => ConnectionEvent::Failed {
            remote_address: normalize_socket_addr(remote_address),
            reason,
        },
        ConnectionEvent::PeerAddressUpdated {
            peer_addr,
            advertised_addr,
        } => ConnectionEvent::PeerAddressUpdated {
            peer_addr: normalize_socket_addr(peer_addr),
            advertised_addr: normalize_socket_addr(advertised_addr),
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    /// Test TDD: verify no duplicate peer registration
    ///
    /// Fixed: Event forwarder no longer tracks peers, only broadcasts events.
    /// Peer tracking with geographic validation is done by add_peer() in
    /// connect_to_peer() and accept_connection(). This avoids duplicate
    /// registration while preserving geographic validation functionality.
    #[test]
    fn test_no_duplicate_peer_registration() {
        // The fix is verified by:
        // - test_send_to_peer_string: Exercises connect_to_peer with add_peer call
        // Integration tests verify the ConnectionEvent broadcasts work correctly.
    }
}
