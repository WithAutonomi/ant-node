//! Local devnet infrastructure for spawning and managing multiple nodes.
//!
//! This module provides a local, in-process devnet suitable for running
//! multi-node networks on a single machine.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{default_root_dir, NODES_SUBDIR, NODE_IDENTITY_FILENAME};
use crate::logging::{debug, info, warn};
use crate::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, QuoteGenerator,
    QuotingMetricsTracker,
};
use crate::replication::config::ReplicationConfig;
use crate::storage::{AntProtocol, ChunkRequestContext, ChunkStore, ChunkStoreConfig};
use evmlib::Network as EvmNetwork;
use evmlib::RewardsAddress;
#[cfg(feature = "webrtc-direct")]
use rand::Rng;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{
    IPDiversityConfig, MultiAddr, NodeConfig as CoreNodeConfig, P2PEvent, P2PNode, PeerId,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::node::NativeSwarmRouter;
#[cfg(feature = "webrtc-direct")]
use crate::swarm::SwarmService;

#[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
use crate::ant_protocol::{ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse};
#[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
use crate::browser::BrowserPublicFile;
#[cfg(feature = "webrtc-direct")]
use crate::browser::{browser_payment_network, BrowserBootstrapNode, BrowserPaymentNetwork};
#[cfg(feature = "webrtc-direct")]
use crate::config::WebRtcDirectConfig;
#[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
use bytes::Bytes;
#[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
use std::collections::HashMap;

mod run_dir;

use run_dir::RunDir;
pub use run_dir::{LOCK_FILE, MARKER_FILE};

// =============================================================================
// Devnet Constants
// =============================================================================

/// Minimum port for random devnet allocation.
pub const DEVNET_PORT_RANGE_MIN: u16 = 20_000;

/// Maximum port for random devnet allocation.
pub const DEVNET_PORT_RANGE_MAX: u16 = 60_000;

// =============================================================================
// Default Timing Constants
// =============================================================================

/// Directory under the ant data root that devnet runs create their own data
/// directories in by default (see [`DevnetConfig::data_dir`]).
pub const DEVNETS_SUBDIR: &str = "devnets";

/// Default delay between spawning nodes (milliseconds).
const DEFAULT_SPAWN_DELAY_MS: u64 = 200;

/// Default timeout for network stabilization (seconds).
const DEFAULT_STABILIZATION_TIMEOUT_SECS: u64 = 120;

/// Default timeout for single node startup (seconds).
const DEFAULT_NODE_STARTUP_TIMEOUT_SECS: u64 = 30;

/// Stabilization timeout for minimal network (seconds).
const MINIMAL_STABILIZATION_TIMEOUT_SECS: u64 = 30;

/// Stabilization timeout for small network (seconds).
const SMALL_STABILIZATION_TIMEOUT_SECS: u64 = 60;

/// Polling interval when waiting for individual nodes to become ready (milliseconds).
const NODE_READY_POLL_INTERVAL_MS: u64 = 100;

/// Polling interval when waiting for network stabilization (seconds).
const STABILIZATION_POLL_INTERVAL_SECS: u64 = 1;

/// Maximum minimum connections required per node during stabilization.
const STABILIZATION_MIN_CONNECTIONS_CAP: usize = 3;

/// Health monitor check interval (seconds).
const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// How long shutdown gives a node's request handlers, and then the storage
/// writes they started, to finish (seconds), as a node does. A node still
/// writing after that keeps the run directory.
const DRAIN_GRACE_SECS: u64 = 5;

// =============================================================================
// AntProtocol Devnet Configuration
// =============================================================================

/// Payment cache capacity for devnet nodes.
const DEVNET_PAYMENT_CACHE_CAPACITY: usize = 1000;

/// Devnet rewards address (20 bytes, all 0x01).
const DEVNET_REWARDS_ADDRESS: [u8; 20] = [0x01; 20];

/// Initial records for quoting metrics (devnet value).
const DEVNET_INITIAL_RECORDS: usize = 1000;

async fn handle_chunk_message(
    protocol: Arc<AntProtocol>,
    p2p: Arc<P2PNode>,
    source: PeerId,
    data: Vec<u8>,
    node_index: usize,
    received_at: Instant,
) {
    let handled = protocol
        .try_handle_request_with_context(
            &data,
            Some(
                ChunkRequestContext::new(source.to_string(), received_at.into(), Duration::ZERO)
                    .with_requester(source),
            ),
        )
        .await;
    let telemetry = handled.get_telemetry;
    match handled.response {
        Ok(Some(response)) => {
            let send_started = Instant::now();
            let send_result = p2p
                .send_message(&source, CHUNK_PROTOCOL_ID, response.to_vec(), &[])
                .await;
            if let Some(telemetry) = telemetry {
                telemetry.finish_send(send_started.elapsed(), send_result.is_ok());
            }
            if let Err(e) = send_result {
                warn!("Node {node_index} failed to send response to {source}: {e}");
            }
        }
        Ok(None) => {
            if let Some(telemetry) = telemetry {
                telemetry.finish_without_send("no_response");
            }
        }
        Err(e) => {
            if let Some(telemetry) = telemetry {
                telemetry.finish_without_send("encode_error");
            }
            warn!("Node {node_index} protocol handler error: {e}");
        }
    }
}

// =============================================================================
// Default Node Counts
// =============================================================================

/// Default number of nodes in a full devnet.
pub const DEFAULT_NODE_COUNT: usize = 25;

/// Default number of bootstrap nodes.
pub const DEFAULT_BOOTSTRAP_COUNT: usize = 3;

/// Number of nodes in a minimal devnet.
pub const MINIMAL_NODE_COUNT: usize = 5;

/// Number of bootstrap nodes in a minimal network.
pub const MINIMAL_BOOTSTRAP_COUNT: usize = 2;

/// Number of nodes in a small devnet.
pub const SMALL_NODE_COUNT: usize = 10;

/// Error type for devnet operations.
#[derive(Debug, thiserror::Error)]
pub enum DevnetError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Node startup error
    #[error("Node startup error: {0}")]
    Startup(String),

    /// Network stabilization error
    #[error("Network stabilization error: {0}")]
    Stabilization(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Core error
    #[error("Core error: {0}")]
    Core(String),
}

/// Result type for devnet operations.
pub type Result<T> = std::result::Result<T, DevnetError>;

/// Configuration for the devnet.
///
/// Each configuration is automatically isolated with its own data directory,
/// and by default its nodes bind ports the OS assigns, to prevent collisions
/// when running multiple devnets.
#[derive(Debug, Clone)]
pub struct DevnetConfig {
    /// Number of nodes to spawn (default: 25).
    pub node_count: usize,

    /// Base port for node allocation. 0 (the default) means OS-assigned: each
    /// node binds port 0, and [`Devnet::bootstrap_addrs`] reports the port it
    /// was given. Otherwise node `i` binds `base_port + i`, up to
    /// `DEVNET_PORT_RANGE_MAX`. When the WebRTC Direct listeners' ports are
    /// fixed ([`Self::webrtc_direct_base_port`], or a LAN devnet), 0 picks a
    /// fixed range disjoint from theirs instead, because a node on port 0 could
    /// be given a port a later listener needs.
    ///
    /// Fixed ports used to be the only mode, with 0 meaning a random range.
    /// That range overlaps the OS ephemeral range, so a node could fail with
    /// "Failed to create transport" on a port another socket had just been
    /// given, such as an earlier node's `UPnP` gateway search, or on a port a
    /// Windows runner had reserved (V2-1896). The OS never assigns either.
    pub base_port: u16,

    /// Number of bootstrap nodes (first N nodes, default: 3).
    pub bootstrap_count: usize,

    /// Directory each run creates its own data directory in (default:
    /// `{ant data root}/devnets`).
    ///
    /// [`Devnet::new`] creates a fresh `{pid}-{random}` directory inside it,
    /// and from then on [`Devnet::config`]'s `data_dir` is that run
    /// directory. A devnet deletes only a directory it created and marked as
    /// its own ([`MARKER_FILE`]), never this one or anything else in it: the
    /// ant data root also holds real nodes' data and the client's payment
    /// caches and upload history (ant-node#261). Run directories that earlier
    /// runs left here, killed before they could remove them, are removed when
    /// the next run starts, unless they were kept.
    ///
    /// On Unix it must be a directory only the user and root can change, as
    /// must every directory above it, or [`Devnet::new`] fails: another user
    /// who could would be able to redirect what the nodes write.
    pub data_dir: PathBuf,

    /// Delay between node spawns (default: 200ms).
    pub spawn_delay: Duration,

    /// Timeout for network stabilization (default: 120s).
    pub stabilization_timeout: Duration,

    /// Timeout for single node startup (default: 30s).
    pub node_startup_timeout: Duration,

    /// Enable verbose logging for devnet nodes.
    pub enable_node_logging: bool,

    /// Whether to remove the run's data directory on shutdown. When `false`,
    /// its marker also tells later runs to leave it alone.
    pub cleanup_data_dir: bool,

    /// Optional EVM network for payment verification.
    /// When `Some`, nodes will use this network (e.g. Anvil testnet) for
    /// on-chain verification. Defaults to Arbitrum One when `None`.
    pub evm_network: Option<EvmNetwork>,

    /// Optional IPv4 to advertise to peers/clients (LAN devnet). When `Some`,
    /// nodes bind 0.0.0.0 and advertise this IP instead of 127.0.0.1.
    pub advertise_ip: Option<Ipv4Addr>,

    /// Run one direct-browser WebRTC Direct listener per devnet node.
    pub webrtc_direct: bool,

    /// First UDP port in the WebRTC Direct node range. 0 (the default) means
    /// OS-assigned on a loopback devnet whose nodes use OS-assigned ports too;
    /// the listeners then advertise the address they bound. Otherwise 0 picks a
    /// fixed range disjoint from the nodes': a LAN devnet
    /// ([`Self::advertise_ip`]) must advertise its ports up front (V2-1897),
    /// and a listener on port 0 could be given a port a later node needs.
    pub webrtc_direct_base_port: u16,
}

impl Default for DevnetConfig {
    fn default() -> Self {
        Self {
            node_count: DEFAULT_NODE_COUNT,
            base_port: 0,
            bootstrap_count: DEFAULT_BOOTSTRAP_COUNT,
            data_dir: default_root_dir().join(DEVNETS_SUBDIR),
            spawn_delay: Duration::from_millis(DEFAULT_SPAWN_DELAY_MS),
            stabilization_timeout: Duration::from_secs(DEFAULT_STABILIZATION_TIMEOUT_SECS),
            node_startup_timeout: Duration::from_secs(DEFAULT_NODE_STARTUP_TIMEOUT_SECS),
            enable_node_logging: false,
            cleanup_data_dir: true,
            evm_network: None,
            advertise_ip: None,
            webrtc_direct: false,
            webrtc_direct_base_port: 0,
        }
    }
}

impl DevnetConfig {
    /// Minimal devnet preset (5 nodes).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            node_count: MINIMAL_NODE_COUNT,
            bootstrap_count: MINIMAL_BOOTSTRAP_COUNT,
            stabilization_timeout: Duration::from_secs(MINIMAL_STABILIZATION_TIMEOUT_SECS),
            ..Self::default()
        }
    }

    /// Small devnet preset (10 nodes).
    #[must_use]
    pub fn small() -> Self {
        Self {
            node_count: SMALL_NODE_COUNT,
            bootstrap_count: MINIMAL_BOOTSTRAP_COUNT,
            stabilization_timeout: Duration::from_secs(SMALL_STABILIZATION_TIMEOUT_SECS),
            ..Self::default()
        }
    }
}

// The manifest types are shared with ant-client (CLI reads them, devnet
// writes them), so they live in ant-protocol. Re-exported here for
// backwards compatibility.
pub use ant_protocol::devnet_manifest::{DevnetEvmInfo, DevnetManifest};

/// Network state for devnet startup lifecycle.
#[derive(Debug, Clone)]
pub enum NetworkState {
    /// Not started.
    Uninitialized,
    /// Bootstrapping nodes are starting.
    BootstrappingPhase,
    /// Regular nodes are starting.
    NodeSpawningPhase,
    /// Waiting for stabilization.
    Stabilizing,
    /// Network is ready.
    Ready,
    /// Shutting down.
    ShuttingDown,
    /// Stopped.
    Stopped,
}

/// Node state for devnet nodes.
#[derive(Debug, Clone)]
pub enum NodeState {
    /// Not started yet.
    Pending,
    /// Starting up.
    Starting,
    /// Running.
    Running,
    /// Connected to peers.
    Connected,
    /// Stopped.
    Stopped,
    /// Failed to start.
    Failed(String),
}

/// A single devnet node instance.
#[allow(dead_code)]
pub struct DevnetNode {
    index: usize,
    label: String,
    peer_id: PeerId,
    port: u16,
    data_dir: PathBuf,
    p2p_node: Option<Arc<P2PNode>>,
    ant_protocol: Option<Arc<AntProtocol>>,
    is_bootstrap: bool,
    state: Arc<RwLock<NodeState>>,
    bootstrap_addrs: Vec<MultiAddr>,
    protocol_task: Option<JoinHandle<()>>,
    /// The request handlers `protocol_task` has started, which shutdown
    /// waits for.
    handlers: TaskTracker,
    #[cfg(feature = "webrtc-direct")]
    webrtc_direct_task: Option<JoinHandle<()>>,
    #[cfg(feature = "webrtc-direct")]
    webrtc_diagnostics: Option<crate::web_rtc::WebRtcServerDiagnostics>,
    #[cfg(feature = "webrtc-direct")]
    browser_endpoint: Option<crate::browser::BrowserEndpoint>,
}

impl DevnetNode {
    /// Get the node's peer count.
    pub async fn peer_count(&self) -> usize {
        if let Some(ref node) = self.p2p_node {
            node.peer_count().await
        } else {
            0
        }
    }
}

/// A local devnet composed of multiple nodes.
///
/// Call [`shutdown`](Self::shutdown) before dropping it. Dropped without one,
/// the nodes it started are not stopped, and its run directory is left,
/// locked until the process exits so that no other run deletes it while they
/// may still be writing there.
pub struct Devnet {
    config: DevnetConfig,
    nodes: Vec<DevnetNode>,
    shutdown: CancellationToken,
    state: Arc<RwLock<NetworkState>>,
    health_monitor: Option<JoinHandle<()>>,
    /// This run's data directory, until [`shutdown`](Self::shutdown) removes
    /// or releases it. Dropped without a shutdown, the devnet keeps it locked
    /// until the process exits.
    run_dir: Option<RunDir>,
    /// [`DRAIN_GRACE_SECS`], shorter in tests.
    drain_grace: Duration,
    #[cfg(feature = "webrtc-direct")]
    browser_endpoint_catalog: Arc<crate::web_rtc::BrowserEndpointCatalog>,
}

/// A fixed port range for `count` nodes or browser listeners, in the local
/// test range and disjoint from `other` when given: next to it if there is
/// room, otherwise anywhere that doesn't overlap it.
#[cfg(feature = "webrtc-direct")]
fn allocate_disjoint_range(other: Option<(u16, u16)>, count: u16) -> Result<u16> {
    let max_base = DEVNET_PORT_RANGE_MAX.saturating_sub(count);
    if max_base <= DEVNET_PORT_RANGE_MIN {
        return Err(DevnetError::Config(format!(
            "{count} nodes need more ports than the devnet port range              {DEVNET_PORT_RANGE_MIN}..{DEVNET_PORT_RANGE_MAX} has"
        )));
    }
    let mut rng = rand::thread_rng();
    let Some((start, end)) = other else {
        return Ok(rng.gen_range(DEVNET_PORT_RANGE_MIN..max_base));
    };
    if end >= DEVNET_PORT_RANGE_MIN
        && end
            .checked_add(count)
            .is_some_and(|after| after <= DEVNET_PORT_RANGE_MAX)
    {
        return Ok(end);
    }
    if let Some(before) = start
        .checked_sub(count)
        .filter(|before| *before >= DEVNET_PORT_RANGE_MIN)
    {
        return Ok(before);
    }
    (0..128)
        .map(|_| rng.gen_range(DEVNET_PORT_RANGE_MIN..max_base))
        .find(|candidate| candidate.saturating_add(count) <= start || *candidate >= end)
        .ok_or_else(|| {
            DevnetError::Config(
                "Could not allocate disjoint native and WebRtcDirect port ranges".to_string(),
            )
        })
}

impl Devnet {
    /// Create a new devnet with the given configuration.
    ///
    /// Creates this run's own data directory inside `config.data_dir`, after
    /// removing any that earlier runs left there and that are over and not
    /// kept (see [`DevnetConfig::data_dir`]).
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Config` if the configuration is invalid (e.g. bootstrap
    /// count exceeds node count or port range overflow).
    /// Returns `DevnetError::Io` if the data directory cannot be created.
    #[allow(clippy::too_many_lines)]
    pub async fn new(mut config: DevnetConfig) -> Result<Self> {
        if config.bootstrap_count >= config.node_count {
            return Err(DevnetError::Config(
                "Bootstrap count must be less than node count".to_string(),
            ));
        }

        if config.bootstrap_count == 0 {
            return Err(DevnetError::Config(
                "At least one bootstrap node is required".to_string(),
            ));
        }

        let node_count = config.node_count;
        let node_count_u16 = u16::try_from(node_count).map_err(|_| {
            DevnetError::Config(format!("Node count {node_count} exceeds u16::MAX"))
        })?;

        // Ports are either all OS-assigned or all fixed, in disjoint ranges: a
        // node or browser listener on port 0 could be given a port that a later
        // fixed one still needs. Only a loopback devnet's browser listeners can
        // bind port 0 (a LAN listener advertises its port up front, V2-1897),
        // so any fixed port, native or browser, fixes them all.
        #[cfg(feature = "webrtc-direct")]
        if config.webrtc_direct
            && (config.base_port != 0
                || config.webrtc_direct_base_port != 0
                || config.advertise_ip.is_some())
        {
            if config.base_port == 0 {
                let browser = (config.webrtc_direct_base_port != 0).then(|| {
                    let base = config.webrtc_direct_base_port;
                    (base, base.saturating_add(node_count_u16))
                });
                config.base_port = allocate_disjoint_range(browser, node_count_u16)?;
            }
            if config.webrtc_direct_base_port == 0 {
                let native = (
                    config.base_port,
                    config.base_port.saturating_add(node_count_u16),
                );
                config.webrtc_direct_base_port =
                    allocate_disjoint_range(Some(native), node_count_u16)?;
            }
        }

        // The native range, when the ports are fixed. With `base_port == 0`
        // the OS assigns each node's port, and there is nothing to check.
        let native_range = if config.base_port == 0 {
            None
        } else {
            let base_port = config.base_port;
            let max_port = base_port.checked_add(node_count_u16).ok_or_else(|| {
                DevnetError::Config(format!(
                    "Port range overflow: base_port {base_port} + node_count {node_count} exceeds u16::MAX"
                ))
            })?;
            if max_port > DEVNET_PORT_RANGE_MAX {
                return Err(DevnetError::Config(format!(
                    "Port range overflow: max port {max_port} exceeds DEVNET_PORT_RANGE_MAX {DEVNET_PORT_RANGE_MAX}"
                )));
            }
            Some((base_port, max_port))
        };

        #[cfg(not(feature = "webrtc-direct"))]
        if config.webrtc_direct {
            return Err(DevnetError::Config(
                "WebRtcDirect devnet support requires the 'webrtc-direct' feature".to_string(),
            ));
        }
        // Only the WebRtcDirect range checks below read it.
        #[cfg(not(feature = "webrtc-direct"))]
        let _ = native_range;

        #[cfg(feature = "webrtc-direct")]
        if config.webrtc_direct && config.webrtc_direct_base_port != 0 {
            let webrtc_direct_end = config
                .webrtc_direct_base_port
                .checked_add(node_count_u16)
                .ok_or_else(|| {
                    DevnetError::Config("WebRtcDirect port range overflow".to_string())
                })?;
            if config.webrtc_direct_base_port < DEVNET_PORT_RANGE_MIN
                || webrtc_direct_end > DEVNET_PORT_RANGE_MAX
            {
                return Err(DevnetError::Config(format!(
                    "WebRtcDirect ports must remain in the local test range {DEVNET_PORT_RANGE_MIN}..{DEVNET_PORT_RANGE_MAX}"
                )));
            }
            if let Some((base_port, max_port)) = native_range {
                if base_port < webrtc_direct_end && config.webrtc_direct_base_port < max_port {
                    return Err(DevnetError::Config(
                        "Native and WebRtcDirect devnet port ranges overlap".to_string(),
                    ));
                }
            }
        }

        let parent = config.data_dir.clone();
        let keep = !config.cleanup_data_dir;
        let run_dir = tokio::task::spawn_blocking(move || RunDir::create(&parent, keep))
            .await
            .map_err(std::io::Error::other)??;
        config.data_dir = run_dir.path().to_path_buf();
        info!("Devnet data directory: {}", config.data_dir.display());

        Ok(Self {
            config,
            nodes: Vec::new(),
            shutdown: CancellationToken::new(),
            state: Arc::new(RwLock::new(NetworkState::Uninitialized)),
            health_monitor: None,
            run_dir: Some(run_dir),
            drain_grace: Duration::from_secs(DRAIN_GRACE_SECS),
            #[cfg(feature = "webrtc-direct")]
            browser_endpoint_catalog: Arc::new(crate::web_rtc::BrowserEndpointCatalog::default()),
        })
    }

    /// Start the devnet.
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Startup` if any node fails to start, or
    /// `DevnetError::Stabilization` if the network does not stabilize within the timeout.
    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting devnet with {} nodes ({} bootstrap)",
            self.config.node_count, self.config.bootstrap_count
        );

        *self.state.write().await = NetworkState::BootstrappingPhase;
        self.start_bootstrap_nodes().await?;

        *self.state.write().await = NetworkState::NodeSpawningPhase;
        self.start_regular_nodes().await?;

        *self.state.write().await = NetworkState::Stabilizing;
        self.wait_for_stabilization().await?;

        self.start_health_monitor();

        *self.state.write().await = NetworkState::Ready;
        info!("Devnet is ready");
        Ok(())
    }

    /// Shutdown the devnet.
    ///
    /// Stops every node, then removes the run's data directory, but only if
    /// they have all stopped writing to it. A node that has not, because a
    /// request is still being handled after a few seconds or its P2P node
    /// failed to shut down, leaves the directory, locked until the process
    /// exits; the next run removes it then.
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Io` if the data directory cleanup fails.
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down devnet");
        *self.state.write().await = NetworkState::ShuttingDown;

        self.shutdown.cancel();

        if let Some(handle) = self.health_monitor.take() {
            handle.abort();
        }

        let grace = self.drain_grace;
        let mut stops = Vec::with_capacity(self.nodes.len());
        for node in self.nodes.iter_mut().rev() {
            debug!("Stopping node {}", node.index);
            let node_index = node.index;
            let node_state = Arc::clone(&node.state);
            let protocol_task = node.protocol_task.take();
            #[cfg(feature = "webrtc-direct")]
            let webrtc_direct_task = node.webrtc_direct_task.take();
            let handlers = node.handlers.clone();
            let storage = node
                .ant_protocol
                .as_ref()
                .map(|protocol| protocol.storage());
            let p2p_node = node.p2p_node.take();

            stops.push(async move {
                let mut stopped = true;
                // The token cancelled above closes the browser listener,
                // which drains its own requests before it returns.
                #[cfg(feature = "webrtc-direct")]
                if let Some(handle) = webrtc_direct_task {
                    if let Err(error) = handle.await {
                        warn!("Error stopping node {node_index} WebRtcDirect listener: {error}");
                        stopped = false;
                    }
                }
                // As a node does: the routing loop first, aborted and awaited
                // so that it starts no more handlers, then the handlers it
                // started, given a moment to finish.
                if let Some(handle) = protocol_task {
                    handle.abort();
                    let _ = handle.await;
                }
                handlers.close();
                if tokio::time::timeout(grace, handlers.wait()).await.is_err() {
                    warn!(
                        "Node {node_index}: {} request handler(s) still running after {grace:?}",
                        handlers.len()
                    );
                    stopped = false;
                }
                // A storage write outlives the future that started it.
                if let Some(storage) = storage {
                    if tokio::time::timeout(grace, storage.wait_idle())
                        .await
                        .is_err()
                    {
                        warn!("Node {node_index}: storage writes still running after {grace:?}");
                        stopped = false;
                    }
                }
                if let Some(p2p) = p2p_node {
                    if let Err(e) = p2p.shutdown().await {
                        warn!("Error shutting down node {node_index}: {e}");
                        stopped = false;
                    }
                }
                *node_state.write().await = NodeState::Stopped;
                stopped
            });
        }
        let all_stopped = futures::future::join_all(stops)
            .await
            .into_iter()
            .all(|stopped| stopped);

        match self.run_dir.take() {
            Some(run_dir) if !all_stopped => {
                warn!(
                    "Leaving devnet data directory {}: not every node has stopped writing to it. \
                     It stays locked until this process exits, and the next run removes it.",
                    self.config.data_dir.display()
                );
                run_dir.keep_locked_until_exit();
            }
            Some(run_dir) if self.config.cleanup_data_dir => {
                match tokio::task::spawn_blocking(move || run_dir.remove()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!(
                        "Failed to remove devnet data directory {}: {e}",
                        self.config.data_dir.display()
                    ),
                    Err(e) => warn!("Failed to remove devnet data directory: {e}"),
                }
            }
            // Without cleanup, dropping the run directory releases its lock
            // and leaves it, marked to be kept.
            Some(_) | None => {}
        }

        *self.state.write().await = NetworkState::Stopped;
        info!("Devnet shutdown complete");
        Ok(())
    }

    /// A token that stops this devnet's [`start`](Self::start) when cancelled.
    ///
    /// A start in progress returns an error at its next safe point: between
    /// node spawns, or while it waits for nodes to come up or the network to
    /// stabilize. Every node it started is registered by then, so a following
    /// [`shutdown`](Self::shutdown) stops them all before it removes the data
    /// directory. Dropping a `start` future part-way instead can leave a node
    /// running unregistered, still writing into that directory. It is the same
    /// token `shutdown` cancels.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Wait `delay`, or fail at once if the devnet has been cancelled.
    async fn pause(&self, delay: Duration) -> Result<()> {
        tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Err(start_cancelled()),
            () = tokio::time::sleep(delay) => Ok(()),
        }
    }

    /// Get devnet configuration.
    #[must_use]
    pub fn config(&self) -> &DevnetConfig {
        &self.config
    }

    /// Get bootstrap addresses.
    #[must_use]
    pub fn bootstrap_addrs(&self) -> Vec<MultiAddr> {
        self.nodes
            .iter()
            .take(self.config.bootstrap_count)
            .map(|n| {
                MultiAddr::quic(SocketAddr::from((
                    self.config.advertise_ip.unwrap_or(Ipv4Addr::LOCALHOST),
                    n.port,
                )))
            })
            .collect()
    }

    /// Snapshot every browser listener, including counters retained after shutdown.
    #[cfg(feature = "webrtc-direct")]
    #[must_use]
    pub fn browser_listener_diagnostics(&self) -> Vec<crate::web_rtc::WebRtcServerSnapshot> {
        self.nodes
            .iter()
            .filter_map(|node| {
                node.webrtc_diagnostics
                    .as_ref()
                    .map(crate::web_rtc::WebRtcServerDiagnostics::snapshot)
            })
            .collect()
    }

    /// Test-only handles for exercising browser admission during stalled storage.
    #[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
    #[must_use]
    pub fn test_browser_node(
        &self,
        index: usize,
    ) -> Option<(Arc<AntProtocol>, crate::web_rtc::WebRtcServerDiagnostics)> {
        let node = self.nodes.get(index)?;
        Some((
            Arc::clone(node.ant_protocol.as_ref()?),
            node.webrtc_diagnostics.clone()?,
        ))
    }

    /// Get every direct browser endpoint in this devnet.
    #[cfg(feature = "webrtc-direct")]
    #[must_use]
    pub fn browser_endpoints(&self) -> Vec<BrowserBootstrapNode> {
        self.nodes
            .iter()
            .filter_map(|node| {
                node.browser_endpoint
                    .clone()
                    .map(|endpoint| BrowserBootstrapNode { endpoint })
            })
            .collect()
    }

    /// Publish a complete self-encrypted file to the browser-enabled devnet.
    ///
    /// The file is split using the same `self_encryption` crate as `ant-client`.
    /// Every encrypted data chunk and the public `MessagePack` `DataMap` are then
    /// submitted through each node's ordinary chunk PUT handler. Address
    /// verification, DHT responsibility, payment-cache admission, and chunk
    /// integrity checks therefore remain active.
    ///
    /// # Errors
    ///
    /// Returns an error when WebRTC Direct is disabled, self-encryption fails,
    /// a generated chunk is too large, no node admits a required record, or
    /// protocol serialization fails.
    #[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
    pub async fn publish_public_file(
        &self,
        name: String,
        content_type: String,
        content: &[u8],
    ) -> Result<BrowserPublicFile> {
        if !self.config.webrtc_direct {
            return Err(DevnetError::Config(
                "Cannot publish a browser file when WebRtcDirect is disabled".to_string(),
            ));
        }
        if content.len() < self_encryption::MIN_ENCRYPTABLE_BYTES {
            return Err(DevnetError::Config(format!(
                "Public file is {} bytes; self-encryption requires at least {} bytes",
                content.len(),
                self_encryption::MIN_ENCRYPTABLE_BYTES
            )));
        }

        let (published_data_map, encrypted_chunks) =
            self_encryption::encrypt(Bytes::copy_from_slice(content)).map_err(|error| {
                DevnetError::Core(format!("Failed to self-encrypt browser file: {error}"))
            })?;
        let mut records = HashMap::<[u8; 32], Bytes>::new();
        for chunk in encrypted_chunks {
            if chunk.content.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
                return Err(DevnetError::Core(format!(
                    "Self-encryption produced a {}-byte chunk; node maximum is {}",
                    chunk.content.len(),
                    crate::ant_protocol::MAX_CHUNK_SIZE
                )));
            }
            let address = crate::client::compute_address(&chunk.content);
            records.entry(address).or_insert(chunk.content);
        }

        let mut get_local_chunk = |address: self_encryption::XorName| {
            records.get(&address.0).cloned().ok_or_else(|| {
                self_encryption::Error::Generic(format!(
                    "Self-encryption output omitted chunk {}",
                    hex::encode(address.0)
                ))
            })
        };
        let root_data_map =
            self_encryption::get_root_data_map(published_data_map.clone(), &mut get_local_chunk)
                .map_err(|error| {
                    DevnetError::Core(format!("Failed to resolve browser file DataMap: {error}"))
                })?;
        let serialized_data_map = rmp_serde::to_vec(&published_data_map).map_err(|error| {
            DevnetError::Core(format!("Failed to serialize browser file DataMap: {error}"))
        })?;
        let data_map_size = serialized_data_map.len();
        let data_map_address = crate::client::compute_address(&serialized_data_map);
        records.insert(data_map_address, Bytes::from(serialized_data_map));

        let record_count = records.len();
        let mut replicas = usize::MAX;
        for (address, bytes) in &records {
            replicas = replicas.min(self.publish_browser_record(*address, bytes).await?);
        }

        let chunks = root_data_map
            .infos()
            .iter()
            .map(|info| crate::browser::BrowserChunkInfo {
                index: info.index,
                dst_hash: hex::encode(info.dst_hash.0),
                src_hash: hex::encode(info.src_hash.0),
                src_size: info.src_size,
            })
            .collect();
        let published = BrowserPublicFile {
            name,
            address: hex::encode(data_map_address),
            size: content.len(),
            content_type,
            blake3: hex::encode(crate::client::compute_address(content)),
            data_map_size,
            chunks,
            replicas,
        };
        info!(
            "Published browser devnet file '{}' at {} as {record_count} record(s), each on at least {} node(s)",
            published.name, published.address, published.replicas
        );
        Ok(published)
    }

    /// Public EVM chain and contracts advertised to direct browser clients.
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Config` if a custom RPC cannot report its chain ID.
    #[cfg(feature = "webrtc-direct")]
    pub async fn browser_payment_network(&self) -> Result<BrowserPaymentNetwork> {
        let network = self
            .config
            .evm_network
            .as_ref()
            .unwrap_or(&EvmNetwork::ArbitrumOne);
        browser_payment_network(network)
            .await
            .map_err(|error| DevnetError::Config(error.to_string()))
    }

    #[cfg(all(feature = "webrtc-direct", feature = "test-utils"))]
    async fn publish_browser_record(&self, address: [u8; 32], content: &Bytes) -> Result<usize> {
        let mut replicas = 0usize;
        let mut failures = Vec::new();

        for node in &self.nodes {
            let Some(protocol) = node.ant_protocol.as_ref() else {
                failures.push(format!("node {} has no protocol handler", node.index));
                continue;
            };
            protocol
                .payment_verifier_arc()
                .cache_insert_browser_devnet_seed(address);

            let request = ChunkMessage {
                request_id: u64::try_from(node.index).unwrap_or(u64::MAX),
                body: ChunkMessageBody::PutRequest(ChunkPutRequest::new(address, content.clone())),
            };
            let request_bytes = request.encode().map_err(|error| {
                DevnetError::Core(format!("Failed to encode public-file PUT: {error}"))
            })?;
            let response_bytes = protocol
                .try_handle_request(&request_bytes)
                .await
                .map_err(|error| {
                    DevnetError::Core(format!(
                        "Node {} public-file PUT failed: {error}",
                        node.index
                    ))
                })?
                .ok_or_else(|| {
                    DevnetError::Core(format!(
                        "Node {} returned no public-file PUT response",
                        node.index
                    ))
                })?;
            let response = ChunkMessage::decode(&response_bytes).map_err(|error| {
                DevnetError::Core(format!(
                    "Failed to decode node {} public-file response: {error}",
                    node.index
                ))
            })?;
            match response.body {
                ChunkMessageBody::PutResponse(
                    ChunkPutResponse::Success { .. } | ChunkPutResponse::AlreadyExists { .. },
                ) => {
                    replicas += 1;
                }
                ChunkMessageBody::PutResponse(other) => {
                    failures.push(format!("node {}: {other:?}", node.index));
                }
                other => failures.push(format!(
                    "node {} returned unexpected response {other:?}",
                    node.index
                )),
            }
        }

        if replicas == 0 {
            return Err(DevnetError::Startup(format!(
                "No devnet node admitted browser record {}: {}",
                hex::encode(address),
                failures.join("; ")
            )));
        }
        if !failures.is_empty() {
            debug!(
                "Browser record was admitted by {replicas} nodes; {} non-responsible/failed nodes: {}",
                failures.len(),
                failures.join("; ")
            );
        }
        Ok(replicas)
    }

    async fn start_bootstrap_nodes(&mut self) -> Result<()> {
        info!("Starting {} bootstrap nodes", self.config.bootstrap_count);

        for i in 0..self.config.bootstrap_count {
            let node = self.create_node(i, true, vec![]).await?;
            self.start_node(node).await?;
            self.pause(self.config.spawn_delay).await?;
        }

        self.wait_for_nodes_ready(0..self.config.bootstrap_count)
            .await?;

        info!("All bootstrap nodes are ready");
        Ok(())
    }

    async fn start_regular_nodes(&mut self) -> Result<()> {
        let regular_count = self.config.node_count - self.config.bootstrap_count;
        info!("Starting {} regular nodes", regular_count);

        let bootstrap_addrs: Vec<MultiAddr> = self
            .nodes
            .get(0..self.config.bootstrap_count)
            .ok_or_else(|| {
                DevnetError::Config(format!(
                    "Bootstrap count {} exceeds nodes length {}",
                    self.config.bootstrap_count,
                    self.nodes.len()
                ))
            })?
            .iter()
            .map(|n| {
                MultiAddr::quic(SocketAddr::from((
                    self.config.advertise_ip.unwrap_or(Ipv4Addr::LOCALHOST),
                    n.port,
                )))
            })
            .collect();

        for i in self.config.bootstrap_count..self.config.node_count {
            let node = self.create_node(i, false, bootstrap_addrs.clone()).await?;
            self.start_node(node).await?;
            self.pause(self.config.spawn_delay).await?;
        }

        info!("All regular nodes started");
        Ok(())
    }

    async fn create_node(
        &self,
        index: usize,
        is_bootstrap: bool,
        bootstrap_addrs: Vec<MultiAddr>,
    ) -> Result<DevnetNode> {
        let index_u16 = u16::try_from(index)
            .map_err(|_| DevnetError::Config(format!("Node index {index} exceeds u16::MAX")))?;
        // 0 until the node starts, when `start_node` records the port the OS
        // assigned.
        let port = if self.config.base_port == 0 {
            0
        } else {
            self.config.base_port + index_u16
        };

        // Generate identity first so we can use peer_id as the directory name
        let identity = NodeIdentity::generate()
            .map_err(|e| DevnetError::Core(format!("Failed to generate node identity: {e}")))?;
        let peer_id = *identity.peer_id();
        let label = format!("devnet_node_{index}");
        let data_dir = self
            .config
            .data_dir
            .join(NODES_SUBDIR)
            .join(peer_id.to_hex());

        tokio::fs::create_dir_all(&data_dir).await?;

        identity
            .save_to_file(&data_dir.join(NODE_IDENTITY_FILENAME))
            .await
            .map_err(|e| DevnetError::Core(format!("Failed to save node identity: {e}")))?;

        let ant_protocol = Self::create_ant_protocol(&data_dir, &identity, &self.config).await?;

        Ok(DevnetNode {
            index,
            label,
            peer_id,
            port,
            data_dir,
            p2p_node: None,
            ant_protocol: Some(Arc::new(ant_protocol)),
            is_bootstrap,
            state: Arc::new(RwLock::new(NodeState::Pending)),
            bootstrap_addrs,
            protocol_task: None,
            handlers: TaskTracker::new(),
            #[cfg(feature = "webrtc-direct")]
            webrtc_direct_task: None,
            #[cfg(feature = "webrtc-direct")]
            webrtc_diagnostics: None,
            #[cfg(feature = "webrtc-direct")]
            browser_endpoint: None,
        })
    }

    async fn create_ant_protocol(
        data_dir: &std::path::Path,
        identity: &NodeIdentity,
        config: &DevnetConfig,
    ) -> Result<AntProtocol> {
        let storage_config = ChunkStoreConfig {
            root_dir: data_dir.to_path_buf(),
            verify_on_read: true,
            ..ChunkStoreConfig::default()
        };
        let storage = ChunkStore::new(storage_config)
            .await
            .map_err(|e| DevnetError::Core(format!("Failed to create the chunk store: {e}")))?;

        let evm_config = EvmVerifierConfig {
            network: config
                .evm_network
                .clone()
                .unwrap_or(EvmNetwork::ArbitrumOne),
        };

        let rewards_address = RewardsAddress::new(DEVNET_REWARDS_ADDRESS);
        let replication_config = ReplicationConfig::default();
        let payment_config = PaymentVerifierConfig {
            evm: evm_config,
            cache_capacity: DEVNET_PAYMENT_CACHE_CAPACITY,
            close_group_size: replication_config.close_group_size,
            local_rewards_address: rewards_address,
            price_floor: PriceFloorConfig::default(),
        };
        let payment_verifier = PaymentVerifier::new(payment_config);
        let metrics_tracker = QuotingMetricsTracker::new(DEVNET_INITIAL_RECORDS);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing from the devnet node's identity
        crate::payment::wire_ml_dsa_signer(&mut quote_generator, identity)
            .map_err(|e| DevnetError::Startup(format!("Failed to wire ML-DSA-65 signer: {e}")))?;

        let storage = Arc::new(storage);
        let payment_verifier = Arc::new(payment_verifier);

        // Same pointer wiring as a production node, so a devnet exercises the
        // real path rather than a node that silently refuses every pointer.
        let pointer_store = crate::pointer::PointerStore::new(storage.root_dir())
            .await
            .map_err(|e| DevnetError::Startup(format!("Failed to open pointer store: {e}")))?;
        let pointers = crate::pointer::PointerService::new(pointer_store)
            .with_chunk_store(Arc::clone(&storage))
            .with_payments(Arc::clone(&payment_verifier));

        Ok(
            AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator))
                .with_pointer_service(pointers),
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn start_node(&mut self, mut node: DevnetNode) -> Result<()> {
        debug!("Starting node {}", node.index);
        *node.state.write().await = NodeState::Starting;

        let mut core_config = CoreNodeConfig::builder()
            .port(node.port)
            .local(self.config.advertise_ip.is_none())
            .max_message_size(crate::ant_protocol::MAX_WIRE_MESSAGE_SIZE)
            .build()
            .map_err(|e| DevnetError::Core(format!("Failed to create core config: {e}")))?;

        // Load the node identity for app-level message signing.
        let identity = NodeIdentity::load_from_file(
            &node.data_dir.join(crate::config::NODE_IDENTITY_FILENAME),
        )
        .await
        .map_err(|e| DevnetError::Core(format!("Failed to load node identity: {e}")))?;

        core_config.node_identity = Some(Arc::new(identity));
        core_config
            .bootstrap_peers
            .clone_from(&node.bootstrap_addrs);
        core_config.diversity_config = Some(IPDiversityConfig::permissive());
        // Devnet nodes serve chunks, so they announce get-or-closer
        // (ADR-0020) as a production node does.
        core_config.custom_user_agent = Some(crate::node::user_agent(true));

        let index = node.index;
        let p2p_node = P2PNode::new(core_config)
            .await
            .map_err(|e| DevnetError::Startup(format!("Failed to create node {index}: {e}")))?;

        p2p_node
            .start()
            .await
            .map_err(|e| DevnetError::Startup(format!("Failed to start node {index}: {e}")))?;

        node.p2p_node = Some(Arc::new(p2p_node));
        *node.state.write().await = NodeState::Running;
        // Registered as soon as it runs, so that should the rest of its
        // startup fail, shutdown still stops it before removing its data.
        self.nodes.push(node);
        let node = self
            .nodes
            .last_mut()
            .ok_or_else(|| DevnetError::Startup(format!("Node {index} was not registered")))?;
        // Bootstrap addresses are IPv4 (`bootstrap_addrs`). A dual-stack node
        // on port 0 gets a different port for each stack, so record the IPv4 one.
        if node.port == 0 {
            let p2p = node
                .p2p_node
                .clone()
                .ok_or_else(|| DevnetError::Startup(format!("Node {index} lost its P2P handle")))?;
            node.port = p2p
                .listen_addrs()
                .await
                .iter()
                .filter_map(MultiAddr::socket_addr)
                .find(SocketAddr::is_ipv4)
                .map(|addr| addr.port())
                .ok_or_else(|| {
                    DevnetError::Startup(format!("Node {index} has no IPv4 listen address"))
                })?;
        }
        debug!("Node {index} listening on port {}", node.port);

        #[cfg(feature = "webrtc-direct")]
        if self.config.webrtc_direct {
            let index_u16 = u16::try_from(node.index).map_err(|_| {
                DevnetError::Config(format!("Node index {} exceeds u16::MAX", node.index))
            })?;
            // 0: the OS assigns the port. `Devnet::new` fixes the browser ports
            // whenever any port is fixed, so this only happens on a loopback
            // devnet whose nodes use OS-assigned ports too.
            let port = if self.config.webrtc_direct_base_port == 0 {
                0
            } else {
                self.config
                    .webrtc_direct_base_port
                    .checked_add(index_u16)
                    .ok_or_else(|| {
                        DevnetError::Config(format!(
                            "WebRtcDirect port overflow for node {}",
                            node.index
                        ))
                    })?
            };
            let advertised_ip = self.config.advertise_ip.unwrap_or(Ipv4Addr::LOCALHOST);
            let bind_ip = self
                .config
                .advertise_ip
                .map_or(Ipv4Addr::LOCALHOST, |_| Ipv4Addr::UNSPECIFIED);
            let webrtc_direct_config = WebRtcDirectConfig {
                enabled: true,
                bind: SocketAddr::from((bind_ip, port)),
                // A loopback listener on port 0 advertises the address it bound.
                advertised_addr: (port != 0).then(|| SocketAddr::from((advertised_ip, port))),
                ..WebRtcDirectConfig::default()
            };

            let p2p = node.p2p_node.clone().ok_or_else(|| {
                DevnetError::Startup(format!(
                    "Node {} lost its P2P handle before WebRtcDirect startup",
                    node.index
                ))
            })?;
            let swarm = node
                .ant_protocol
                .as_ref()
                .map_or_else(SwarmService::new, |protocol| Arc::clone(protocol.swarm()));
            swarm.set_node_id(*p2p.peer_id().to_bytes());
            let server = crate::web_rtc::spawn(
                &webrtc_direct_config,
                &node.data_dir,
                p2p,
                node.ant_protocol.clone(),
                swarm,
                self.config
                    .evm_network
                    .as_ref()
                    .unwrap_or(&EvmNetwork::ArbitrumOne),
                self.shutdown.clone(),
                Some(Arc::clone(&self.browser_endpoint_catalog)),
            )
            .await
            .map_err(|error| {
                DevnetError::Startup(format!(
                    "Failed to start node {} WebRtcDirect listener: {error}",
                    node.index
                ))
            })?;
            node.browser_endpoint = server.endpoint;
            node.webrtc_diagnostics = Some(server.diagnostics);
            node.webrtc_direct_task = Some(server.task);
        }

        if let (Some(ref p2p), Some(ref protocol)) = (&node.p2p_node, &node.ant_protocol) {
            // Wire P2P into AntProtocol for payment-proof closeness checks.
            protocol.attach_p2p_node(Arc::clone(p2p));

            let mut events = p2p.subscribe_events();
            let p2p_clone = Arc::clone(p2p);
            let protocol_clone = Arc::clone(protocol);
            let handlers = node.handlers.clone();
            let node_index = node.index;
            // Native clients' swarm requests, as a node routes them.
            let swarm = NativeSwarmRouter::start(
                Arc::clone(protocol.swarm()),
                Arc::clone(p2p),
                TaskTracker::new(),
                self.shutdown.clone(),
            );
            node.protocol_task = Some(tokio::spawn(async move {
                while let Ok(event) = events.recv().await {
                    if swarm.route(&event) {
                        continue;
                    }
                    if let P2PEvent::Message {
                        topic,
                        source: Some(source),
                        data,
                        ..
                    } = event
                    {
                        if topic == CHUNK_PROTOCOL_ID {
                            debug!(
                                "Node {node_index} received chunk protocol message from {source}"
                            );
                            let protocol = Arc::clone(&protocol_clone);
                            let p2p = Arc::clone(&p2p_clone);
                            let received_at = Instant::now();
                            handlers.spawn(handle_chunk_message(
                                protocol,
                                p2p,
                                source,
                                data,
                                node_index,
                                received_at,
                            ));
                        }
                    }
                }
            }));
        }

        debug!("Node {} started successfully", node.index);
        Ok(())
    }

    async fn wait_for_nodes_ready(&self, range: std::ops::Range<usize>) -> Result<()> {
        let deadline = Instant::now() + self.config.node_startup_timeout;

        for i in range {
            while Instant::now() < deadline {
                let node = self.nodes.get(i).ok_or_else(|| {
                    DevnetError::Config(format!(
                        "Node index {i} out of bounds (len: {})",
                        self.nodes.len()
                    ))
                })?;
                let state = node.state.read().await.clone();
                match state {
                    NodeState::Running | NodeState::Connected => break,
                    NodeState::Failed(ref e) => {
                        return Err(DevnetError::Startup(format!("Node {i} failed: {e}")));
                    }
                    _ => {
                        self.pause(Duration::from_millis(NODE_READY_POLL_INTERVAL_MS))
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn wait_for_stabilization(&self) -> Result<()> {
        let deadline = Instant::now() + self.config.stabilization_timeout;
        let min_connections = self
            .config
            .bootstrap_count
            .min(STABILIZATION_MIN_CONNECTIONS_CAP);

        info!(
            "Waiting for devnet stabilization (min {} connections per node)",
            min_connections
        );

        while Instant::now() < deadline {
            let mut all_connected = true;
            let mut total_connections = 0;

            for node in &self.nodes {
                let peer_count = node.peer_count().await;
                total_connections += peer_count;

                if peer_count < min_connections {
                    all_connected = false;
                }
            }

            if all_connected {
                info!("Devnet stabilized: {} total connections", total_connections);
                return Ok(());
            }

            debug!(
                "Waiting for stabilization: {} total connections",
                total_connections
            );
            self.pause(Duration::from_secs(STABILIZATION_POLL_INTERVAL_SECS))
                .await?;
        }

        Err(DevnetError::Stabilization(
            "Devnet failed to stabilize within timeout".to_string(),
        ))
    }

    fn start_health_monitor(&mut self) {
        let nodes: Vec<Arc<P2PNode>> = self
            .nodes
            .iter()
            .filter_map(|n| n.p2p_node.clone())
            .collect();
        let shutdown = self.shutdown.clone();

        self.health_monitor = Some(tokio::spawn(async move {
            let check_interval = Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS);

            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(check_interval) => {
                        for (i, node) in nodes.iter().enumerate() {
                            if !node.is_running() {
                                warn!("Node {} appears unhealthy", i);
                            }
                        }
                    }
                }
            }
        }));
    }
}

/// The error a cancelled [`Devnet::start`] returns.
fn start_cancelled() -> DevnetError {
    DevnetError::Startup("devnet start cancelled".to_string())
}

impl Drop for Devnet {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.health_monitor.take() {
            handle.abort();
        }
        // Not shut down, so nodes it started may still be running: their
        // tasks hold them, and outlive this. Keep the run directory locked
        // until the process exits, so that no sweep deletes it under them. A
        // later run removes it then, as it would after a SIGKILL.
        if let Some(run_dir) = self.run_dir.take() {
            run_dir.keep_locked_until_exit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backward-compatibility contract: a default config advertises no LAN IP,
    /// so nodes bind loopback (`.local(advertise_ip.is_none())` → `.local(true)`)
    /// and stamp `127.0.0.1` into the manifest bootstrap addresses — exactly as
    /// before the `--host` flag existed.
    #[test]
    fn default_config_has_no_advertise_ip() {
        assert!(DevnetConfig::default().advertise_ip.is_none());
    }

    #[test]
    fn runs_go_in_the_devnets_dir_of_the_data_root_by_default() {
        let devnets = default_root_dir().join(DEVNETS_SUBDIR);
        for config in [
            DevnetConfig::default(),
            DevnetConfig::minimal(),
            DevnetConfig::small(),
        ] {
            assert_eq!(config.data_dir, devnets);
            assert!(config.cleanup_data_dir);
        }
    }

    #[tokio::test]
    async fn each_devnet_gets_and_removes_only_its_own_run_dir(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("devnets");
        let mut config = DevnetConfig::minimal();
        config.data_dir.clone_from(&parent);
        let mut first = Devnet::new(config.clone()).await?;
        let mut second = Devnet::new(config).await?;
        let first_dir = first.config().data_dir.clone();
        let second_dir = second.config().data_dir.clone();

        assert_ne!(first_dir, second_dir);
        for dir in [&first_dir, &second_dir] {
            assert_eq!(
                dir.parent().map(std::fs::canonicalize).transpose()?,
                Some(std::fs::canonicalize(&parent)?),
                "{}",
                dir.display()
            );
            assert!(dir.join(MARKER_FILE).is_file(), "{}", dir.display());
        }

        first.shutdown().await?;
        assert!(!first_dir.exists());
        assert!(second_dir.join(MARKER_FILE).is_file());
        second.shutdown().await?;
        assert!(!second_dir.exists());
        assert!(parent.is_dir(), "the parent is not the devnet's to delete");
        Ok(())
    }

    #[tokio::test]
    async fn without_cleanup_the_run_dir_is_kept(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = DevnetConfig::minimal();
        config.data_dir = temp.path().to_path_buf();
        config.cleanup_data_dir = false;
        let mut devnet = Devnet::new(config.clone()).await?;
        let kept = devnet.config().data_dir.clone();
        devnet.shutdown().await?;
        drop(devnet);

        // A later run's sweep leaves it too.
        config.cleanup_data_dir = true;
        let mut later = Devnet::new(config).await?;
        assert!(kept.join(MARKER_FILE).is_file());
        later.shutdown().await?;
        assert!(kept.join(MARKER_FILE).is_file());
        Ok(())
    }

    /// A default devnet's nodes bind ports the OS assigns, and the bootstrap
    /// addresses carry the ports they were given (V2-1896).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_default_devnet_binds_os_assigned_ports(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config = two_nodes(temp.path());
        assert_eq!(config.base_port, 0);
        let mut devnet = Devnet::new(config).await?;
        assert_eq!(
            devnet.config().base_port,
            0,
            "0 is no longer resolved to a range"
        );
        devnet.start().await?;

        let ports: Vec<u16> = devnet.nodes.iter().map(|node| node.port).collect();
        assert!(ports.iter().all(|port| *port != 0), "{ports:?}");
        assert_ne!(ports[0], ports[1], "{ports:?}");
        let bootstrap: Vec<u16> = devnet
            .bootstrap_addrs()
            .iter()
            .filter_map(MultiAddr::socket_addr)
            .map(|addr| addr.port())
            .collect();
        assert_eq!(bootstrap, ports[..1], "the bootstrap node's bound port");

        devnet.shutdown().await?;
        Ok(())
    }

    /// The native and browser base ports `Devnet::new` settles on for a
    /// two-node devnet with WebRTC Direct.
    #[cfg(feature = "webrtc-direct")]
    async fn resolved_ports(
        parent: &std::path::Path,
        base_port: u16,
        webrtc_direct_base_port: u16,
        advertise_ip: Option<Ipv4Addr>,
    ) -> Result<(u16, u16)> {
        let mut config = two_nodes(parent);
        config.webrtc_direct = true;
        config.base_port = base_port;
        config.webrtc_direct_base_port = webrtc_direct_base_port;
        config.advertise_ip = advertise_ip;
        let devnet = Devnet::new(config).await?;
        Ok((
            devnet.config().base_port,
            devnet.config().webrtc_direct_base_port,
        ))
    }

    /// Ports are all OS-assigned or all fixed in disjoint ranges. A node or
    /// browser listener on port 0 could otherwise be given a port a later fixed
    /// one still needs (Hermes on #282).
    #[cfg(feature = "webrtc-direct")]
    #[tokio::test]
    async fn devnet_ports_are_all_os_assigned_or_all_fixed_and_disjoint(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let parent = temp.path();
        let disjoint = |a: u16, b: u16| a + 2 <= b || b + 2 <= a;
        let lan = Some(Ipv4Addr::new(192, 168, 1, 10));

        // A loopback devnet with nothing fixed: all OS-assigned.
        assert_eq!(resolved_ports(parent, 0, 0, None).await?, (0, 0));

        // Fixed nodes: the listeners get a fixed range clear of theirs.
        let (native, browser) = resolved_ports(parent, 30_000, 0, None).await?;
        assert_eq!(native, 30_000);
        assert!(
            browser != 0 && disjoint(native, browser),
            "{native} {browser}"
        );

        // Fixed listeners: the nodes get a fixed range clear of theirs.
        let (native, browser) = resolved_ports(parent, 0, 40_000, None).await?;
        assert_eq!(browser, 40_000);
        assert!(
            native != 0 && disjoint(native, browser),
            "{native} {browser}"
        );

        // A LAN devnet: listeners advertise their ports up front, so all fixed.
        let (native, browser) = resolved_ports(parent, 0, 0, lan).await?;
        assert!(native != 0 && browser != 0, "{native} {browser}");
        assert!(disjoint(native, browser), "{native} {browser}");
        Ok(())
    }

    /// A devnet whose fixed ranges can't fit in the local test range is a
    /// configuration error, not a panic on an empty random range (Hermes on
    /// #282).
    #[cfg(feature = "webrtc-direct")]
    #[tokio::test]
    async fn a_devnet_too_large_for_the_port_range_is_rejected(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = two_nodes(temp.path());
        config.webrtc_direct = true;
        config.advertise_ip = Some(Ipv4Addr::new(192, 168, 1, 10));
        config.node_count = 40_000;
        match Devnet::new(config).await {
            Err(DevnetError::Config(_)) => Ok(()),
            Err(other) => Err(format!("expected a config error, got {other}").into()),
            Ok(_) => Err("a devnet too large for the port range was accepted".into()),
        }
    }

    /// A devnet of two nodes, quick to start, running in `parent`.
    fn two_nodes(parent: &std::path::Path) -> DevnetConfig {
        let mut config = DevnetConfig::minimal();
        config.node_count = 2;
        config.bootstrap_count = 1;
        config.base_port = 0;
        config.spawn_delay = Duration::from_millis(20);
        config.data_dir = parent.join("devnets");
        config
    }

    /// Hermes round 3 on #263: a started devnet dropped without a shutdown
    /// leaves nodes running, still writing into its run directory, so the
    /// next devnet's sweep must leave it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_started_devnet_dropped_without_shutdown_is_not_swept(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config = two_nodes(temp.path());
        let mut dropped = Devnet::new(config.clone()).await?;
        dropped.start().await?;
        let dropped_dir = dropped.config().data_dir.clone();
        drop(dropped);

        let mut next = Devnet::new(config).await?;

        assert!(
            dropped_dir.join(MARKER_FILE).is_file(),
            "the next devnet swept {}",
            dropped_dir.display()
        );
        next.shutdown().await?;
        Ok(())
    }

    /// Hermes round 4 on #263: a PUT still being written when the devnet
    /// shuts down keeps the run directory, locked, rather than having it
    /// removed under the write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::await_holding_lock)]
    async fn a_put_still_being_written_at_shutdown_keeps_the_run_dir(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::ant_protocol::{ChunkMessage, ChunkMessageBody, ChunkPutRequest};

        let temp = tempfile::tempdir()?;
        let mut devnet = Devnet::new(two_nodes(temp.path())).await?;
        devnet.start().await?;
        devnet.drain_grace = Duration::from_millis(500);
        let run_dir = devnet.config().data_dir.clone();
        let sender = devnet
            .nodes
            .first()
            .and_then(|node| node.p2p_node.clone())
            .ok_or("no sender")?;
        let receiver = devnet.nodes.get(1).ok_or("no receiver")?;
        let peer = receiver.peer_id;
        let protocol = receiver.ant_protocol.clone().ok_or("no protocol")?;
        let storage = protocol.storage();
        let content = b"a chunk still being written at shutdown";
        let address = ChunkStore::compute_address(content);
        protocol.payment_verifier().cache_insert(address);
        let request = ChunkMessage {
            request_id: 1,
            body: ChunkMessageBody::PutRequest(ChunkPutRequest::new(
                address,
                bytes::Bytes::from_static(content),
            )),
        }
        .encode()?;

        // Held, the write waits on its way into the store.
        let gate = storage.test_put_gate();
        let held = gate.write();
        sender
            .send_message(&peer, CHUNK_PROTOCOL_ID, request, &[])
            .await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while storage.tasks_in_flight() == 0 {
            assert!(Instant::now() < deadline, "the PUT never reached the store");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        devnet.shutdown().await?;

        assert!(
            run_dir.join(MARKER_FILE).is_file(),
            "{} was removed under a write",
            run_dir.display()
        );
        drop(held);
        storage.wait_idle().await;
        assert!(run_dir.join(MARKER_FILE).is_file());
        // Kept locked, so the next run leaves it too.
        let mut next = Devnet::new(two_nodes(temp.path())).await?;
        assert!(run_dir.join(MARKER_FILE).is_file());
        next.shutdown().await?;
        Ok(())
    }

    /// Hermes round 4 on #263: a node whose startup fails once its P2P node
    /// is running, here because its WebRTC Direct port is taken, is
    /// registered all the same, so shutdown stops it.
    #[cfg(feature = "webrtc-direct")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_node_whose_startup_fails_part_way_is_stopped_by_shutdown(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = two_nodes(temp.path());
        config.webrtc_direct = true;
        // Hold a port in the devnet range and make it node 0's browser port,
        // so node 0's native transport starts and its listener then fails.
        let taken = (0..64)
            .find_map(|_| {
                let port =
                    rand::thread_rng().gen_range(DEVNET_PORT_RANGE_MIN..DEVNET_PORT_RANGE_MAX - 2);
                std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).ok()
            })
            .ok_or("no free port in the devnet range")?;
        config.webrtc_direct_base_port = taken.local_addr()?.port();
        let mut devnet = Devnet::new(config).await?;

        let started = devnet.start().await;

        assert!(
            matches!(started, Err(DevnetError::Startup(_))),
            "{started:?}"
        );
        let p2p = devnet
            .nodes
            .first()
            .and_then(|node| node.p2p_node.clone())
            .ok_or("the node that failed part-way was not registered")?;
        assert!(p2p.is_running());
        devnet.shutdown().await?;
        assert!(!p2p.is_running(), "shutdown left the node running");
        assert!(!devnet.config().data_dir.exists());
        drop(taken);
        Ok(())
    }

    #[tokio::test]
    async fn a_cancelled_devnet_stops_pausing_at_once(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = DevnetConfig::minimal();
        config.data_dir = temp.path().join("devnet");
        config.cleanup_data_dir = false;
        let devnet = Devnet::new(config).await?;

        assert!(devnet.pause(Duration::ZERO).await.is_ok());
        devnet.cancellation_token().cancel();
        let started = Instant::now();
        let paused = devnet.pause(Duration::from_mins(1)).await;
        assert!(matches!(paused, Err(DevnetError::Startup(_))), "{paused:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }
}
