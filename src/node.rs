//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::client::{peer_id_to_xor_name, XorName};
use crate::config::{EvmNetworkConfig, IpVersion, NetworkMode, NodeConfig};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::wallet::parse_rewards_address;
use crate::payment::{PaymentVerifier, PaymentVerifierConfig, QuoteGenerator};
use crate::replication::fresh;
use crate::replication::paid_list::PaidForList;
use crate::replication::protocol::{ReplicationBody, ReplicationMessage, REPLICATION_PROTOCOL_ID};
use crate::storage::{AntProtocol, DiskStorage, DiskStorageConfig, NewChunkStored};
use crate::upgrade::{AutoApplyUpgrader, UpgradeMonitor, UpgradeResult};
use ant_evm::RewardsAddress;
use evmlib::Network as EvmNetwork;
use parking_lot::RwLock;
use saorsa_core::{
    BootstrapConfig as CoreBootstrapConfig, BootstrapManager,
    IPDiversityConfig as CoreDiversityConfig, NodeConfig as CoreNodeConfig, P2PEvent, P2PNode,
    ProductionConfig as CoreProductionConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
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
    pub async fn build(self) -> Result<RunningNode> {
        info!("Building saorsa-node with config: {:?}", self.config);

        // Ensure root directory exists
        std::fs::create_dir_all(&self.config.root_dir)?;

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Create event channel
        let (events_tx, events_rx) = create_event_channel();

        // Convert our config to saorsa-core's config
        let core_config = Self::build_core_config(&self.config)?;
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

        // Create new-chunk notification channel for replication
        let (new_chunk_tx, new_chunk_rx) = mpsc::unbounded_channel();

        // Initialize ANT protocol handler for chunk storage
        let ant_protocol = if self.config.storage.enabled {
            let protocol = Self::build_ant_protocol(&self.config)
                .await?
                .with_new_chunk_notifier(new_chunk_tx);
            Some(Arc::new(protocol))
        } else {
            info!("Chunk storage disabled");
            None
        };

        // Initialize PaidForList for replication
        let paid_list = match PaidForList::load(&self.config.root_dir) {
            Ok(list) => {
                info!("PaidForList loaded ({} keys)", list.len());
                Some(Arc::new(RwLock::new(list)))
            }
            Err(e) => {
                warn!("Failed to load PaidForList, replication degraded: {e}");
                None
            }
        };

        let node = RunningNode {
            config: self.config,
            p2p_node: Arc::new(p2p_node),
            shutdown_tx,
            shutdown_rx,
            events_tx,
            events_rx: Some(events_rx),
            upgrade_monitor,
            bootstrap_manager,
            ant_protocol,
            protocol_task: None,
            replication_task: None,
            fresh_replication_task: None,
            paid_list,
            routing_view: Arc::new(RwLock::new(Vec::new())),
            new_chunk_rx: Some(new_chunk_rx),
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
    /// Initializes disk storage, payment verifier, and quote generator.
    async fn build_ant_protocol(config: &NodeConfig) -> Result<AntProtocol> {
        // Create disk storage
        let storage_config = DiskStorageConfig {
            root_dir: config.root_dir.clone(),
            verify_on_read: config.storage.verify_on_read,
            max_chunks: config.storage.max_chunks,
        };
        let storage = DiskStorage::new(storage_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create disk storage: {e}")))?;

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

/// A running saorsa node.
pub struct RunningNode {
    config: NodeConfig,
    p2p_node: Arc<P2PNode>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    events_tx: NodeEventsSender,
    events_rx: Option<NodeEventsChannel>,
    upgrade_monitor: Option<Arc<UpgradeMonitor>>,
    /// Bootstrap cache manager for persistent peer storage.
    bootstrap_manager: Option<BootstrapManager>,
    /// ANT protocol handler for chunk storage.
    ant_protocol: Option<Arc<AntProtocol>>,
    /// Protocol message routing background task.
    protocol_task: Option<JoinHandle<()>>,
    /// Replication protocol routing background task.
    replication_task: Option<JoinHandle<()>>,
    /// Fresh replication trigger background task.
    fresh_replication_task: Option<JoinHandle<()>>,
    /// Shared `PaidForList` for replication (Section 5.15).
    paid_list: Option<Arc<RwLock<PaidForList>>>,
    /// Live routing view: connected peers and their XOR names.
    routing_view: Arc<RwLock<Vec<(String, XorName)>>>,
    /// Receiver for new-chunk notifications from the storage handler.
    new_chunk_rx: Option<mpsc::UnboundedReceiver<NewChunkStored>>,
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

        // Start protocol and replication message routing
        self.start_protocol_routing();
        self.start_replication_routing();
        self.start_fresh_replication_trigger();

        self.start_upgrade_monitor();

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

        // Stop replication tasks and flush PaidForList
        for handle in [
            self.replication_task.take(),
            self.fresh_replication_task.take(),
        ]
        .into_iter()
        .flatten()
        {
            handle.abort();
        }
        if let Some(ref paid_list) = self.paid_list {
            let flush_result = paid_list.write().flush();
            if let Err(e) = flush_result {
                warn!("Failed to flush PaidForList on shutdown: {e}");
            }
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
    async fn run_event_loop(&mut self) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Shutdown signal received");
                        break;
                    }
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
    async fn run_event_loop(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Shutdown signal received");
                        break;
                    }
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

    /// Start the upgrade monitor background task if enabled.
    fn start_upgrade_monitor(&self) {
        let Some(ref monitor) = self.upgrade_monitor else {
            return;
        };
        let monitor = Arc::clone(monitor);
        let events_tx = self.events_tx.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let upgrader = AutoApplyUpgrader::new();

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    result = monitor.check_for_updates() => {
                        if let Ok(Some(upgrade_info)) = result {
                            info!(
                                "Upgrade available: {} -> {}",
                                upgrader.current_version(),
                                upgrade_info.version
                            );

                            if let Err(e) = events_tx.send(NodeEvent::UpgradeAvailable {
                                version: upgrade_info.version.to_string(),
                            }) {
                                warn!("Failed to send UpgradeAvailable event: {e}");
                            }

                            info!("Starting auto-apply upgrade...");
                            match upgrader.apply_upgrade(&upgrade_info).await {
                                Ok(UpgradeResult::Success { version }) => {
                                    info!("Upgrade to {} successful! Process will restart.", version);
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
                        tokio::time::sleep(monitor.check_interval()).await;
                    }
                }
            }
        });
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

    /// Start the replication protocol routing background task.
    ///
    /// Subscribes to P2P events and routes incoming replication messages
    /// to the fresh replication handlers (Section 6.1).
    fn start_replication_routing(&mut self) {
        let storage = match self.ant_protocol {
            Some(ref p) => Arc::clone(p.storage()),
            None => return,
        };
        let paid_list = match self.paid_list {
            Some(ref p) => Arc::clone(p),
            None => return,
        };

        let self_id = self.p2p_node.peer_id().clone();
        let Some(self_xor) = peer_id_to_xor_name(&self_id) else {
            warn!("Cannot derive XOR name from peer ID, replication disabled");
            return;
        };

        let routing_view = Arc::clone(&self.routing_view);
        let mut events = self.p2p_node.subscribe_events();
        let p2p = Arc::clone(&self.p2p_node);

        self.replication_task = Some(tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                let P2PEvent::Message {
                    topic,
                    source,
                    data,
                } = event
                else {
                    continue;
                };
                if topic != REPLICATION_PROTOCOL_ID {
                    continue;
                }
                let msg = match ReplicationMessage::decode(&data) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Failed to decode replication message from {source}: {e}");
                        continue;
                    }
                };
                dispatch_replication_msg(
                    msg,
                    &source,
                    &self_id,
                    &self_xor,
                    &storage,
                    &paid_list,
                    &routing_view,
                    &p2p,
                );
            }
        }));
        info!("Replication protocol routing started");
    }

    /// Start the fresh replication trigger background task.
    ///
    /// Receives [`NewChunkStored`] notifications from the storage handler
    /// and sends `FreshOffer`/`PaidNotify` to the appropriate peers.
    fn start_fresh_replication_trigger(&mut self) {
        let Some(mut new_chunk_rx) = self.new_chunk_rx.take() else {
            return;
        };

        let self_id = self.p2p_node.peer_id().clone();
        let Some(self_xor) = peer_id_to_xor_name(&self_id) else {
            return;
        };

        let routing_view = Arc::clone(&self.routing_view);
        let p2p = Arc::clone(&self.p2p_node);

        self.fresh_replication_task = Some(tokio::spawn(async move {
            while let Some(notification) = new_chunk_rx.recv().await {
                let rt_snapshot = routing_view.read().clone();
                let plan = fresh::plan_fresh_replication(
                    &self_id,
                    &self_xor,
                    &notification.key,
                    &rt_snapshot,
                );

                let key_hex = hex::encode(notification.key);
                let offer_count = plan.offer_targets.len();
                let notify_count = plan.notify_only_targets.len();

                if offer_count == 0 && notify_count == 0 {
                    debug!("No replication targets for chunk {key_hex} (empty routing view)");
                    continue;
                }

                debug!(
                    "Fresh replication for {key_hex}: {} offers, {} notifies",
                    offer_count, notify_count
                );

                // Send FreshOffer to close group peers
                for target in &plan.offer_targets {
                    let offer = ReplicationMessage {
                        request_id: 0, // fire-and-forget, no correlation needed
                        body: ReplicationBody::FreshOffer(
                            crate::replication::protocol::FreshOfferRequest {
                                key: notification.key,
                                content: notification.content.clone(),
                                proof_of_payment: notification.payment_proof.clone(),
                            },
                        ),
                    };
                    if let Ok(bytes) = offer.encode() {
                        let p2p = Arc::clone(&p2p);
                        let target = target.clone();
                        tokio::spawn(async move {
                            if let Err(e) = p2p
                                .send_message(&target, REPLICATION_PROTOCOL_ID, bytes)
                                .await
                            {
                                warn!("Failed to send FreshOffer to {target}: {e}");
                            }
                        });
                    }
                }

                // Send PaidNotify to wider paid-close-group peers
                for target in &plan.notify_only_targets {
                    let notify = ReplicationMessage {
                        request_id: 0,
                        body: ReplicationBody::PaidNotify(
                            crate::replication::protocol::PaidNotifyRequest {
                                key: notification.key,
                                proof_of_payment: notification.payment_proof.clone(),
                            },
                        ),
                    };
                    if let Ok(bytes) = notify.encode() {
                        let p2p = Arc::clone(&p2p);
                        let target = target.clone();
                        tokio::spawn(async move {
                            if let Err(e) = p2p
                                .send_message(&target, REPLICATION_PROTOCOL_ID, bytes)
                                .await
                            {
                                warn!("Failed to send PaidNotify to {target}: {e}");
                            }
                        });
                    }
                }
            }
        }));
        info!("Fresh replication trigger started");
    }

    /// Request the node to shut down.
    pub fn shutdown(&self) {
        if let Err(e) = self.shutdown_tx.send(true) {
            warn!("Failed to send shutdown signal: {e}");
        }
    }
}

/// Dispatch a decoded replication message to the appropriate handler.
///
/// Extracted from `start_replication_routing` to keep that method within
/// the clippy line-count limit.
#[allow(clippy::too_many_arguments)]
fn dispatch_replication_msg(
    msg: ReplicationMessage,
    source: &str,
    self_id: &str,
    self_xor: &XorName,
    storage: &Arc<DiskStorage>,
    paid_list: &Arc<RwLock<PaidForList>>,
    routing_view: &Arc<RwLock<Vec<(String, XorName)>>>,
    p2p: &Arc<P2PNode>,
) {
    let request_id = msg.request_id;
    match msg.body {
        ReplicationBody::FreshOffer(request) => {
            let storage = Arc::clone(storage);
            let paid_list = Arc::clone(paid_list);
            let routing_view = Arc::clone(routing_view);
            let p2p = Arc::clone(p2p);
            let self_id = self_id.to_owned();
            let self_xor = *self_xor;
            let source = source.to_owned();

            tokio::spawn(async move {
                let rt_snapshot = routing_view.read().clone();
                let response = fresh::handle_fresh_offer(
                    &self_id,
                    &self_xor,
                    &request,
                    &rt_snapshot,
                    &storage,
                )
                .await;

                if matches!(
                    response,
                    crate::replication::protocol::FreshOfferResponse::Accepted { .. }
                ) {
                    paid_list.write().add(request.key);
                }

                let reply = ReplicationMessage {
                    request_id,
                    body: ReplicationBody::FreshOfferResponse(response),
                };
                if let Ok(bytes) = reply.encode() {
                    if let Err(e) = p2p
                        .send_message(&source, REPLICATION_PROTOCOL_ID, bytes)
                        .await
                    {
                        warn!("Failed to send FreshOffer response to {source}: {e}");
                    }
                }
            });
        }
        ReplicationBody::PaidNotify(request) => {
            let rt_snapshot = routing_view.read().clone();
            let response = {
                let mut pl = paid_list.write();
                fresh::handle_paid_notify(self_id, self_xor, &request, &rt_snapshot, &mut pl)
            };

            let reply = ReplicationMessage {
                request_id,
                body: ReplicationBody::PaidNotifyResponse(response),
            };
            if let Ok(bytes) = reply.encode() {
                let p2p = Arc::clone(p2p);
                let source = source.to_owned();
                tokio::spawn(async move {
                    if let Err(e) = p2p
                        .send_message(&source, REPLICATION_PROTOCOL_ID, bytes)
                        .await
                    {
                        warn!("Failed to send PaidNotify response to {source}: {e}");
                    }
                });
            }
        }
        _ => {
            debug!("Ignoring unhandled replication message variant from {source}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
}
