//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{
    default_root_dir, EvmNetworkConfig, IpVersion, NetworkMode, NodeConfig, NODE_IDENTITY_FILENAME,
};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::wallet::parse_rewards_address;
use crate::payment::{PaymentVerifier, PaymentVerifierConfig, QuoteGenerator};
use crate::storage::{AntProtocol, LmdbStorage, LmdbStorageConfig};
use crate::upgrade::{AutoApplyUpgrader, UpgradeMonitor, UpgradeResult};
use ant_evm::RewardsAddress;
use evmlib::Network as EvmNetwork;
use saorsa_core::identity::{NodeId, NodeIdentity};
use saorsa_core::{
    BootstrapConfig as CoreBootstrapConfig, BootstrapManager,
    IPDiversityConfig as CoreDiversityConfig, NodeConfig as CoreNodeConfig, P2PEvent, P2PNode,
    ProductionConfig as CoreProductionConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Maximum number of records for quoting metrics.
const DEFAULT_MAX_QUOTING_RECORDS: usize = 100_000;

/// Default rewards address when none is configured (20-byte zero address).
const DEFAULT_REWARDS_ADDRESS: [u8; 20] = [0u8; 20];

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

/// Builder for constructing a saorsa node.
pub struct NodeBuilder {
    config: NodeConfig,
}

impl NodeBuilder {
    /// Create a new node builder with the given configuration.
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    /// Build and start the node.
    ///
    /// # Errors
    ///
    /// Returns an error if the node fails to start.
    pub async fn build(mut self) -> Result<RunningNode> {
        info!("Building saorsa-node with config: {:?}", self.config);

        // Resolve identity and root_dir (may update self.config.root_dir)
        let identity = Self::resolve_identity(&mut self.config).await?;
        let peer_id = node_id_to_peer_id(identity.node_id());

        info!(peer_id = %peer_id, root_dir = %self.config.root_dir.display(), "Node identity resolved");

        // Ensure root directory exists
        std::fs::create_dir_all(&self.config.root_dir)?;

        // Create shutdown token
        let shutdown = CancellationToken::new();

        // Create event channel
        let (events_tx, events_rx) = create_event_channel();

        // Convert our config to saorsa-core's config, injecting our stable peer_id
        let mut core_config = Self::build_core_config(&self.config)?;
        core_config.peer_id = Some(peer_id);
        debug!("Core config: {:?}", core_config);

        // Initialize saorsa-core's P2PNode
        let p2p_node = P2PNode::new(core_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create P2P node: {e}")))?;

        // Create upgrade monitor if enabled
        let upgrade_monitor = if self.config.upgrade.enabled {
            let node_id_seed = p2p_node.peer_id().as_bytes();
            Some(Self::build_upgrade_monitor(&self.config, node_id_seed))
        } else {
            None
        };

        // Initialize bootstrap cache manager if enabled
        let bootstrap_manager = if self.config.bootstrap_cache.enabled {
            Self::build_bootstrap_manager(&self.config).await
        } else {
            info!("Bootstrap cache disabled");
            None
        };

        // Initialize ANT protocol handler for chunk storage
        let ant_protocol = if self.config.storage.enabled {
            Some(Arc::new(Self::build_ant_protocol(&self.config).await?))
        } else {
            info!("Chunk storage disabled");
            None
        };

        let node = RunningNode {
            config: self.config,
            p2p_node: Arc::new(p2p_node),
            shutdown,
            events_tx,
            events_rx: Some(events_rx),
            upgrade_monitor,
            bootstrap_manager,
            ant_protocol,
            protocol_task: None,
        };

        Ok(node)
    }

    /// Build the saorsa-core `NodeConfig` from our config.
    fn build_core_config(config: &NodeConfig) -> Result<CoreNodeConfig> {
        // Determine listen address based on port and IP version
        let listen_addr: SocketAddr = match config.ip_version {
            IpVersion::Ipv4 | IpVersion::Dual => format!("0.0.0.0:{}", config.port)
                .parse()
                .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?,
            IpVersion::Ipv6 => format!("[::]:{}", config.port)
                .parse()
                .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?,
        };

        let mut core_config = CoreNodeConfig::new()
            .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;

        // Set listen address
        core_config.listen_addr = listen_addr;
        core_config.listen_addrs = vec![listen_addr];

        // Enable IPv6 if configured
        core_config.enable_ipv6 = matches!(config.ip_version, IpVersion::Ipv6 | IpVersion::Dual);

        // Add bootstrap peers
        core_config.bootstrap_peers.clone_from(&config.bootstrap);

        // Propagate network-mode tuning into saorsa-core where supported.
        match config.network_mode {
            NetworkMode::Production => {
                core_config.production_config = Some(CoreProductionConfig::default());
                core_config.diversity_config = Some(CoreDiversityConfig::default());
            }
            NetworkMode::Testnet => {
                core_config.production_config = Some(CoreProductionConfig::default());
                let mut diversity = CoreDiversityConfig::testnet();
                diversity.max_nodes_per_asn = config.testnet.max_nodes_per_asn;
                diversity.max_nodes_per_64 = config.testnet.max_nodes_per_64;
                diversity.enable_geolocation_check = config.testnet.enable_geo_checks;
                diversity.min_geographic_diversity = if config.testnet.enable_geo_checks {
                    3
                } else {
                    1
                };
                core_config.diversity_config = Some(diversity);

                if config.testnet.enforce_age_requirements {
                    warn!(
                        "testnet.enforce_age_requirements is set but saorsa-core does not yet \
                         expose a knob; age checks may remain relaxed"
                    );
                }
            }
            NetworkMode::Development => {
                core_config.production_config = None;
                core_config.diversity_config = Some(CoreDiversityConfig::permissive());
            }
        }

        Ok(core_config)
    }

    /// Resolve the node identity from disk or generate a new one.
    ///
    /// **When `root_dir` is explicit** (set via `--root-dir` or differs from the
    /// platform default, e.g. loaded from `config.toml`):
    ///   - If `{root_dir}/node_identity.key` exists, load it.
    ///   - Otherwise, generate a new identity and save it there.
    ///
    /// **When `root_dir` is the platform default** (first run, no config file):
    ///   1. Compute `base_dir` = platform data dir for "saorsa".
    ///   2. Scan `base_dir` for subdirectories containing `node_identity.key`.
    ///   3. **None found** — first run: generate identity, derive `{base_dir}/{hex_prefix}/`,
    ///      save identity there, and update `config.root_dir`.
    ///   4. **Exactly one found** — load it and update `config.root_dir`.
    ///   5. **Multiple found** — return an error asking the user to specify `--root-dir`.
    async fn resolve_identity(config: &mut NodeConfig) -> Result<NodeIdentity> {
        // Treat root_dir as explicit if it was set via --root-dir OR differs from
        // the platform default (e.g. loaded from config.toml). This prevents
        // silently ignoring a custom root_dir from config files.
        let base_dir = default_root_dir();
        if config.root_dir_explicit || config.root_dir != base_dir {
            return Self::load_or_generate_identity(&config.root_dir).await;
        }

        Self::resolve_identity_in_base_dir(config, &base_dir).await
    }

    /// Scan `base_dir` for identity subdirectories and load/generate accordingly.
    ///
    /// - **None found** — generate a new identity in `{base_dir}/{hex_prefix}/`.
    /// - **Exactly one** — load it.
    /// - **Multiple** — error asking the user to specify `--root-dir`.
    async fn resolve_identity_in_base_dir(
        config: &mut NodeConfig,
        base_dir: &std::path::Path,
    ) -> Result<NodeIdentity> {
        let identity_dirs = Self::scan_identity_dirs(base_dir)?;

        match identity_dirs.len() {
            0 => {
                // First run: generate new identity and create a peer-id-scoped subdirectory
                let identity = NodeIdentity::generate().map_err(|e| {
                    Error::Startup(format!("Failed to generate node identity: {e}"))
                })?;
                let prefix = node_id_hex_prefix(identity.node_id());
                let node_dir = base_dir.join(&prefix);
                std::fs::create_dir_all(&node_dir)?;
                identity
                    .save_to_file(&node_dir.join(NODE_IDENTITY_FILENAME))
                    .await
                    .map_err(|e| Error::Startup(format!("Failed to save node identity: {e}")))?;
                config.root_dir = node_dir;
                Ok(identity)
            }
            1 => {
                let dir = &identity_dirs[0];
                let identity = NodeIdentity::load_from_file(&dir.join(NODE_IDENTITY_FILENAME))
                    .await
                    .map_err(|e| Error::Startup(format!("Failed to load node identity: {e}")))?;
                config.root_dir.clone_from(dir);
                Ok(identity)
            }
            _ => {
                let dirs: Vec<String> = identity_dirs
                    .iter()
                    .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .collect();
                Err(Error::Config(format!(
                    "Multiple node identities found at {}: [{}]. Specify --root-dir to select one.",
                    base_dir.display(),
                    dirs.join(", ")
                )))
            }
        }
    }

    /// Load an existing identity from `dir/node_identity.key`, or generate and save a new one.
    async fn load_or_generate_identity(dir: &std::path::Path) -> Result<NodeIdentity> {
        let key_path = dir.join(NODE_IDENTITY_FILENAME);
        if key_path.exists() {
            NodeIdentity::load_from_file(&key_path)
                .await
                .map_err(|e| Error::Startup(format!("Failed to load node identity: {e}")))
        } else {
            let identity = NodeIdentity::generate()
                .map_err(|e| Error::Startup(format!("Failed to generate node identity: {e}")))?;
            std::fs::create_dir_all(dir)?;
            identity
                .save_to_file(&key_path)
                .await
                .map_err(|e| Error::Startup(format!("Failed to save node identity: {e}")))?;
            Ok(identity)
        }
    }

    /// Scan `base_dir` for immediate subdirectories that contain `node_identity.key`.
    fn scan_identity_dirs(base_dir: &std::path::Path) -> Result<Vec<PathBuf>> {
        let mut dirs = Vec::new();
        let read_dir = match std::fs::read_dir(base_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(dirs),
            Err(e) => return Err(e.into()),
        };
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join(NODE_IDENTITY_FILENAME).exists() {
                dirs.push(path);
            }
        }
        Ok(dirs)
    }

    fn build_upgrade_monitor(config: &NodeConfig, node_id_seed: &[u8]) -> Arc<UpgradeMonitor> {
        let monitor = UpgradeMonitor::new(
            config.upgrade.github_repo.clone(),
            config.upgrade.channel,
            config.upgrade.check_interval_hours,
        );

        if config.upgrade.staged_rollout_hours > 0 {
            Arc::new(monitor.with_staged_rollout(node_id_seed, config.upgrade.staged_rollout_hours))
        } else {
            Arc::new(monitor)
        }
    }

    /// Build the ANT protocol handler from config.
    ///
    /// Initializes LMDB storage, payment verifier, and quote generator.
    async fn build_ant_protocol(config: &NodeConfig) -> Result<AntProtocol> {
        // Create LMDB storage
        let storage_config = LmdbStorageConfig {
            root_dir: config.root_dir.clone(),
            verify_on_read: config.storage.verify_on_read,
            max_chunks: config.storage.max_chunks,
        };
        let storage = LmdbStorage::new(storage_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create LMDB storage: {e}")))?;

        // Create payment verifier
        let evm_network = match config.payment.evm_network {
            EvmNetworkConfig::ArbitrumOne => EvmNetwork::ArbitrumOne,
            EvmNetworkConfig::ArbitrumSepolia => EvmNetwork::ArbitrumSepoliaTest,
        };
        let payment_config = PaymentVerifierConfig {
            evm: crate::payment::EvmVerifierConfig {
                enabled: config.payment.enabled,
                network: evm_network,
            },
            cache_capacity: config.payment.cache_capacity,
        };
        let payment_verifier = PaymentVerifier::new(payment_config);

        // Create quote generator
        let rewards_address = match config.payment.rewards_address {
            Some(ref addr) => parse_rewards_address(addr)?,
            None => RewardsAddress::new(DEFAULT_REWARDS_ADDRESS),
        };
        let metrics_tracker = QuotingMetricsTracker::new(DEFAULT_MAX_QUOTING_RECORDS, 0);
        let quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        info!(
            "ANT protocol handler initialized (protocol={})",
            CHUNK_PROTOCOL_ID
        );

        Ok(AntProtocol::new(
            Arc::new(storage),
            Arc::new(payment_verifier),
            Arc::new(quote_generator),
        ))
    }

    /// Build the bootstrap cache manager from config.
    async fn build_bootstrap_manager(config: &NodeConfig) -> Option<BootstrapManager> {
        let cache_dir = config
            .bootstrap_cache
            .cache_dir
            .clone()
            .unwrap_or_else(|| config.root_dir.join("bootstrap_cache"));

        // Create cache directory
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!("Failed to create bootstrap cache directory: {}", e);
            return None;
        }

        let bootstrap_config = CoreBootstrapConfig {
            cache_dir,
            max_peers: config.bootstrap_cache.max_contacts,
            ..CoreBootstrapConfig::default()
        };

        match BootstrapManager::with_config(bootstrap_config).await {
            Ok(manager) => {
                info!(
                    "Bootstrap cache initialized with {} max contacts",
                    config.bootstrap_cache.max_contacts
                );
                Some(manager)
            }
            Err(e) => {
                warn!("Failed to initialize bootstrap cache: {}", e);
                None
            }
        }
    }
}

/// Number of leading bytes from a `NodeId` used to form the directory-name hex prefix.
/// 8 bytes → 16 hex characters, giving ~18 quintillion unique prefixes.
const NODE_ID_PREFIX_BYTES: usize = 8;

/// Convert a `NodeId` to a hex-encoded `PeerId` string (full 64 hex chars).
fn node_id_to_peer_id(node_id: &NodeId) -> String {
    hex::encode(node_id.0)
}

/// Derive a short hex prefix from a `NodeId` for use as a directory name.
fn node_id_hex_prefix(node_id: &NodeId) -> String {
    hex::encode(&node_id.0[..NODE_ID_PREFIX_BYTES])
}

/// A running saorsa node.
pub struct RunningNode {
    config: NodeConfig,
    p2p_node: Arc<P2PNode>,
    shutdown: CancellationToken,
    events_tx: NodeEventsSender,
    events_rx: Option<NodeEventsChannel>,
    upgrade_monitor: Option<Arc<UpgradeMonitor>>,
    /// Bootstrap cache manager for persistent peer storage.
    bootstrap_manager: Option<BootstrapManager>,
    /// ANT protocol handler for chunk storage.
    ant_protocol: Option<Arc<AntProtocol>>,
    /// Protocol message routing background task.
    protocol_task: Option<JoinHandle<()>>,
}

impl RunningNode {
    /// Get the node's root directory.
    #[must_use]
    pub fn root_dir(&self) -> &PathBuf {
        &self.config.root_dir
    }

    /// Get a receiver for node events.
    ///
    /// Note: Can only be called once. Subsequent calls return None.
    pub fn events(&mut self) -> Option<NodeEventsChannel> {
        self.events_rx.take()
    }

    /// Subscribe to node events.
    #[must_use]
    pub fn subscribe_events(&self) -> NodeEventsChannel {
        self.events_tx.subscribe()
    }

    /// Run the node until shutdown is requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the node encounters a fatal error.
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting saorsa-node");

        // Start the P2P node
        self.p2p_node
            .start()
            .await
            .map_err(|e| Error::Startup(format!("Failed to start P2P node: {e}")))?;

        info!(
            "P2P node started, listening on {:?}",
            self.p2p_node.listen_addrs().await
        );

        // Emit started event
        if let Err(e) = self.events_tx.send(NodeEvent::Started) {
            warn!("Failed to send Started event: {e}");
        }

        // Start protocol message routing (P2P → AntProtocol → P2P response)
        self.start_protocol_routing();

        // Start upgrade monitor if enabled
        if let Some(ref monitor) = self.upgrade_monitor {
            let monitor = Arc::clone(monitor);
            let events_tx = self.events_tx.clone();
            let shutdown = self.shutdown.clone();

            tokio::spawn(async move {
                let upgrader = AutoApplyUpgrader::new();

                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => {
                            break;
                        }
                        result = monitor.check_for_updates() => {
                            if let Ok(Some(upgrade_info)) = result {
                                info!(
                                    "Upgrade available: {} -> {}",
                                    upgrader.current_version(),
                                    upgrade_info.version
                                );

                                // Send notification event
                                if let Err(e) = events_tx.send(NodeEvent::UpgradeAvailable {
                                    version: upgrade_info.version.to_string(),
                                }) {
                                    warn!("Failed to send UpgradeAvailable event: {e}");
                                }

                                // Auto-apply the upgrade
                                info!("Starting auto-apply upgrade...");
                                match upgrader.apply_upgrade(&upgrade_info).await {
                                    Ok(UpgradeResult::Success { version }) => {
                                        info!("Upgrade to {} successful! Process will restart.", version);
                                        // If we reach here, exec() failed or not supported
                                    }
                                    Ok(UpgradeResult::RolledBack { reason }) => {
                                        warn!("Upgrade rolled back: {}", reason);
                                    }
                                    Ok(UpgradeResult::NoUpgrade) => {
                                        debug!("No upgrade needed");
                                    }
                                    Err(e) => {
                                        error!("Critical upgrade error: {}", e);
                                    }
                                }
                            }
                            // Wait for next check interval
                            tokio::time::sleep(monitor.check_interval()).await;
                        }
                    }
                }
            });
        }

        info!("Node running, waiting for shutdown signal");

        // Run the main event loop with signal handling
        self.run_event_loop().await?;

        // Log bootstrap cache stats before shutdown
        if let Some(ref manager) = self.bootstrap_manager {
            match manager.get_stats().await {
                Ok(stats) => {
                    info!(
                        "Bootstrap cache shutdown: {} contacts, avg quality {:.2}",
                        stats.total_contacts, stats.average_quality_score
                    );
                }
                Err(e) => {
                    debug!("Failed to get bootstrap cache stats: {}", e);
                }
            }
        }

        // Stop protocol routing task
        if let Some(handle) = self.protocol_task.take() {
            handle.abort();
        }

        // Shutdown P2P node
        info!("Shutting down P2P node...");
        if let Err(e) = self.p2p_node.shutdown().await {
            warn!("Error during P2P node shutdown: {e}");
        }

        if let Err(e) = self.events_tx.send(NodeEvent::ShuttingDown) {
            warn!("Failed to send ShuttingDown event: {e}");
        }
        info!("Node shutdown complete");
        Ok(())
    }

    /// Run the main event loop, handling shutdown and signals.
    #[cfg(unix)]
    async fn run_event_loop(&self) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT (Ctrl-C), initiating shutdown");
                    self.shutdown();
                    break;
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating shutdown");
                    self.shutdown();
                    break;
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP, could reload config here");
                    // TODO: Implement config reload on SIGHUP
                }
            }
        }
        Ok(())
    }

    /// Run the main event loop, handling shutdown signals (non-Unix version).
    #[cfg(not(unix))]
    async fn run_event_loop(&self) -> Result<()> {
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl-C, initiating shutdown");
                    self.shutdown();
                    break;
                }
            }
        }
        Ok(())
    }

    /// Start the protocol message routing background task.
    ///
    /// Subscribes to P2P events and routes incoming chunk protocol messages
    /// to the `AntProtocol` handler, sending responses back to the sender.
    fn start_protocol_routing(&mut self) {
        let protocol = match self.ant_protocol {
            Some(ref p) => Arc::clone(p),
            None => return,
        };

        let mut events = self.p2p_node.subscribe_events();
        let p2p = Arc::clone(&self.p2p_node);

        self.protocol_task = Some(tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if let P2PEvent::Message {
                    topic,
                    source,
                    data,
                } = event
                {
                    if topic == CHUNK_PROTOCOL_ID {
                        debug!("Received chunk protocol message from {}", source);
                        let protocol = Arc::clone(&protocol);
                        let p2p = Arc::clone(&p2p);
                        tokio::spawn(async move {
                            match protocol.handle_message(&data).await {
                                Ok(response) => {
                                    if let Err(e) = p2p
                                        .send_message(&source, CHUNK_PROTOCOL_ID, response.to_vec())
                                        .await
                                    {
                                        warn!(
                                            "Failed to send protocol response to {}: {}",
                                            source, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!("Protocol handler error: {}", e);
                                }
                            }
                        });
                    }
                }
            }
        }));
        info!("Protocol message routing started");
    }

    /// Request the node to shut down.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_build_upgrade_monitor_staged_rollout_enabled() {
        let config = NodeConfig {
            upgrade: crate::config::UpgradeConfig {
                enabled: true,
                staged_rollout_hours: 24,
                ..Default::default()
            },
            ..Default::default()
        };
        let seed = b"node-seed";

        let monitor = NodeBuilder::build_upgrade_monitor(&config, seed);
        assert!(monitor.has_staged_rollout());
    }

    #[test]
    fn test_build_upgrade_monitor_staged_rollout_disabled() {
        let config = NodeConfig {
            upgrade: crate::config::UpgradeConfig {
                enabled: true,
                staged_rollout_hours: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let seed = b"node-seed";

        let monitor = NodeBuilder::build_upgrade_monitor(&config, seed);
        assert!(!monitor.has_staged_rollout());
    }

    #[test]
    fn test_build_core_config_sets_production_mode() {
        let config = NodeConfig {
            network_mode: NetworkMode::Production,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(core.production_config.is_some());
        assert!(core.diversity_config.is_some());
    }

    #[test]
    fn test_build_core_config_sets_development_mode_relaxed() {
        let config = NodeConfig {
            network_mode: NetworkMode::Development,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(core.production_config.is_none());
        let diversity = core.diversity_config.expect("diversity");
        assert!(diversity.is_relaxed());
    }

    #[test]
    fn test_scan_identity_dirs_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_scan_identity_dirs_nonexistent_dir() {
        let path = PathBuf::from("/tmp/saorsa_nonexistent_test_dir_12345");
        let dirs = NodeBuilder::scan_identity_dirs(&path).unwrap();
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_scan_identity_dirs_finds_one() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("abc123");
        std::fs::create_dir_all(&node_dir).unwrap();
        std::fs::write(node_dir.join(NODE_IDENTITY_FILENAME), "{}").unwrap();

        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], node_dir);
    }

    #[test]
    fn test_scan_identity_dirs_finds_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        for name in &["node_a", "node_b"] {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(NODE_IDENTITY_FILENAME), "{}").unwrap();
        }
        // A directory without a key file should be ignored
        std::fs::create_dir_all(tmp.path().join("no_key")).unwrap();

        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert_eq!(dirs.len(), 2);
    }

    #[tokio::test]
    async fn test_resolve_identity_first_run_creates_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            root_dir_explicit: true,
            ..Default::default()
        };

        let identity = NodeBuilder::resolve_identity(&mut config).await.unwrap();
        // Key file should exist
        assert!(tmp.path().join(NODE_IDENTITY_FILENAME).exists());
        // peer_id should be derivable from the identity
        let peer_id = node_id_to_peer_id(identity.node_id());
        assert_eq!(peer_id.len(), 64); // 32 bytes hex-encoded
    }

    #[tokio::test]
    async fn test_resolve_identity_loads_existing() {
        let tmp = tempfile::tempdir().unwrap();

        // Generate and save an identity
        let original = NodeIdentity::generate().unwrap();
        original
            .save_to_file(&tmp.path().join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();

        let mut config = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            root_dir_explicit: true,
            ..Default::default()
        };

        let loaded = NodeBuilder::resolve_identity(&mut config).await.unwrap();
        assert_eq!(loaded.node_id(), original.node_id());
    }

    #[test]
    fn test_node_id_hex_prefix_length() {
        let id = NodeId::from_bytes([0xab; 32]);
        let prefix = node_id_hex_prefix(&id);
        assert_eq!(prefix.len(), 16); // 8 bytes = 16 hex chars
        assert_eq!(prefix, "abababababababab");
    }

    #[test]
    fn test_node_id_to_peer_id_length() {
        let id = NodeId::from_bytes([0x42; 32]);
        let peer_id = node_id_to_peer_id(&id);
        assert_eq!(peer_id.len(), 64); // 32 bytes = 64 hex chars
    }

    /// Simulates a node restart: first run creates identity in a scoped subdir,
    /// second run discovers and reloads it — `peer_id` must be identical.
    #[tokio::test]
    async fn test_identity_persisted_across_restarts() {
        let base_dir = tempfile::tempdir().unwrap();

        // First "boot": empty base_dir → generates new identity
        let mut config1 = NodeConfig::default();
        let identity1 = NodeBuilder::resolve_identity_in_base_dir(&mut config1, base_dir.path())
            .await
            .unwrap();
        let peer_id1 = node_id_to_peer_id(identity1.node_id());
        let root_dir1 = config1.root_dir.clone();

        // Verify the key file was written inside a scoped subdir
        assert!(root_dir1.starts_with(base_dir.path()));
        assert!(root_dir1.join(NODE_IDENTITY_FILENAME).exists());

        // Second "boot": same base_dir → should find and reload the same identity
        let mut config2 = NodeConfig::default();
        let identity2 = NodeBuilder::resolve_identity_in_base_dir(&mut config2, base_dir.path())
            .await
            .unwrap();
        let peer_id2 = node_id_to_peer_id(identity2.node_id());

        assert_eq!(peer_id1, peer_id2, "peer_id must survive restart");
        assert_eq!(
            config2.root_dir, root_dir1,
            "root_dir must be the same directory"
        );
    }

    /// When two identity subdirs exist, the scan path must return an error
    /// instructing the user to pick one via --root-dir.
    #[tokio::test]
    async fn test_multiple_identities_errors() {
        let base_dir = tempfile::tempdir().unwrap();

        // Create two identity subdirectories manually
        for name in &["aaaa", "bbbb"] {
            let dir = base_dir.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let identity = NodeIdentity::generate().unwrap();
            identity
                .save_to_file(&dir.join(NODE_IDENTITY_FILENAME))
                .await
                .unwrap();
        }

        let mut config = NodeConfig::default();
        let result = NodeBuilder::resolve_identity_in_base_dir(&mut config, base_dir.path()).await;

        let Err(err) = result else {
            panic!("Expected error for multiple identities, got Ok")
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("Multiple node identities"),
            "Expected multiple-identity error, got: {err_msg}"
        );
    }

    /// With --root-dir (explicit), the identity is created on first run and
    /// reloaded on subsequent runs from the same directory.
    #[tokio::test]
    async fn test_explicit_root_dir_persists_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();

        // First boot
        let mut config1 = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            root_dir_explicit: true,
            ..Default::default()
        };
        let identity1 = NodeBuilder::resolve_identity(&mut config1).await.unwrap();

        // Second boot — same dir
        let mut config2 = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            root_dir_explicit: true,
            ..Default::default()
        };
        let identity2 = NodeBuilder::resolve_identity(&mut config2).await.unwrap();

        assert_eq!(
            identity1.node_id(),
            identity2.node_id(),
            "explicit --root-dir must yield stable identity"
        );
    }
}
