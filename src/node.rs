//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{
    default_nodes_dir, default_root_dir, NetworkMode, NodeConfig, NODE_IDENTITY_FILENAME,
};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::logging::{debug, error, info, warn};
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::wallet::parse_rewards_address;
use crate::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, QuoteGenerator,
};
use crate::replication::config::ReplicationConfig;
use crate::replication::ReplicationEngine;
use crate::storage::MIB;
use crate::storage::{AntProtocol, ChunkRequestContext, ChunkStore, ChunkStoreConfig};
use crate::upgrade::{
    upgrade_cache_dir, AutoApplyUpgrader, BinaryCache, ReleaseCache, UpgradeMonitor, UpgradeResult,
};
use rand::Rng;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{
    IPDiversityConfig as CoreDiversityConfig, MultiAddr, NodeConfig as CoreNodeConfig, P2PEvent,
    P2PNode,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

/// Builder for constructing an Ant node.
pub struct NodeBuilder {
    config: NodeConfig,
}

impl NodeBuilder {
    /// Create a new node builder with the given configuration.
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    /// Reject startup in production mode without a usable rewards address.
    ///
    /// A node that cannot receive payment must not silently run on the
    /// production network. The placeholder address shipped in the example
    /// config and an empty string both count as "unconfigured".
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `network_mode` is `Production` and
    /// `payment.rewards_address` is unset, empty, or the example placeholder.
    fn validate_production_rewards_address(config: &NodeConfig) -> Result<()> {
        if config.network_mode != NetworkMode::Production {
            return Ok(());
        }
        let configured = config
            .payment
            .rewards_address
            .as_deref()
            .is_some_and(|addr| !addr.is_empty() && addr != "0xYOUR_ARBITRUM_ADDRESS_HERE");
        if configured {
            Ok(())
        } else {
            Err(Error::Config(
                "CRITICAL: Rewards address is not configured. \
                 Set payment.rewards_address in config to your Arbitrum wallet address."
                    .to_string(),
            ))
        }
    }

    /// Build and start the node.
    ///
    /// # Errors
    ///
    /// Returns an error if the node fails to start.
    pub async fn build(mut self) -> Result<RunningNode> {
        info!("Building ant-node with config: {:?}", self.config);

        Self::validate_production_rewards_address(&self.config)?;

        // Resolve identity and root_dir (may update self.config.root_dir)
        let identity = Arc::new(Self::resolve_identity(&mut self.config).await?);
        let peer_id = identity.peer_id().to_hex();

        info!(peer_id = %peer_id, root_dir = %self.config.root_dir.display(), "Node identity resolved");

        // Ensure root directory exists
        std::fs::create_dir_all(&self.config.root_dir)?;

        // One release-level decision, applied before anything can audit: while the fleet
        // moves off the legacy chunk store, a peer is not penalised for failing to hold a
        // chunk it was supposed to be holding. It is still penalised for failing a
        // commitment-bound audit. Audits of both kinds run and record throughout.
        crate::replication::config::apply_close_group_storage_penalty_policy();

        // Create shutdown token
        let shutdown = CancellationToken::new();

        // Create event channel
        let (events_tx, events_rx) = create_event_channel();

        // Convert our config to saorsa-core's config
        let mut core_config = Self::build_core_config(&self.config)?;
        // Inject the ML-DSA identity so the P2PNode's transport peer ID
        // matches the pub_key embedded in payment quotes.
        core_config.node_identity = Some(Arc::clone(&identity));
        debug!("Core config: {:?}", core_config);

        // Initialize saorsa-core's P2PNode
        let p2p_node = P2PNode::new(core_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create P2P node: {e}")))?;

        // Create upgrade monitor
        let upgrade_monitor = {
            let node_id_seed = p2p_node.peer_id().as_bytes();
            Some(Self::build_upgrade_monitor(&self.config, node_id_seed))
        };

        let repl_config = ReplicationConfig::default();

        // Initialize ANT protocol handler for chunk storage and
        // wire the fresh-write channel so PUTs trigger replication.
        let (ant_protocol, fresh_write_rx) = if self.config.storage.enabled {
            let (fresh_write_tx, fresh_write_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut protocol =
                Self::build_ant_protocol(&self.config, &identity, repl_config.close_group_size)
                    .await?;
            protocol.set_fresh_write_sender(fresh_write_tx);
            (Some(Arc::new(protocol)), Some(fresh_write_rx))
        } else {
            info!("Chunk storage disabled");
            (None, None)
        };

        let p2p_arc = Arc::new(p2p_node);

        // Wire the P2PNode handle into AntProtocol so payment proofs can query
        // live-DHT closeness.
        if let Some(ref protocol) = ant_protocol {
            protocol.attach_p2p_node(Arc::clone(&p2p_arc));
        }

        // Set inside the engine branch below, once the migration's dependencies exist.
        let mut migration_task: Option<JoinHandle<()>> = None;
        // Initialize replication engine (if storage is enabled)
        let replication_engine = if let (Some(ref protocol), Some(fresh_rx)) =
            (&ant_protocol, fresh_write_rx)
        {
            let storage_arc = protocol.storage();
            let payment_verifier_arc = protocol.payment_verifier_arc();
            match ReplicationEngine::new(
                repl_config,
                Arc::clone(&p2p_arc),
                storage_arc,
                payment_verifier_arc,
                Arc::clone(&identity),
                &self.config.root_dir,
                fresh_rx,
                shutdown.clone(),
            )
            .await
            {
                Ok(engine) => {
                    // ADR-0004: wire the engine's commitment state as the
                    // quote generator's commitment source so quotes force
                    // their price from the live storage commitment. Done
                    // here because the engine owns the commitment state and
                    // is built after the protocol.
                    if let Some(ref protocol) = ant_protocol {
                        let concrete = Arc::clone(engine.commitment_state());
                        let source: Arc<dyn crate::payment::quote::CommitmentSource> = concrete;
                        protocol.attach_commitment_source(source);
                        // ADR-0004: share the engine's gossip commitment
                        // cache with the verifier so the cross-check can
                        // resolve quote pins against neighbours' commitments.
                        protocol
                            .payment_verifier_arc()
                            .attach_commitment_cache(Arc::clone(engine.last_commitment_by_peer()));
                        // ADR-0004: give the verifier the monetized-pin sender so
                        // commitments that back a payment get a deterministic
                        // first audit from the engine's drainer.
                        protocol
                            .payment_verifier_arc()
                            .attach_monetized_pin_sender(engine.monetized_pin_sender());

                        migration_task = Self::spawn_storage_migration(
                            protocol.storage(),
                            &p2p_arc,
                            &engine,
                            shutdown.clone(),
                        );
                    }
                    Some(engine)
                }
                Err(e) => {
                    warn!("Failed to initialize replication engine: {e}");
                    None
                }
            }
        } else {
            None
        };

        let node = RunningNode {
            config: self.config,
            p2p_node: p2p_arc,
            shutdown,
            events_tx,
            events_rx: Some(events_rx),
            upgrade_monitor,
            ant_protocol,
            replication_engine,
            protocol_task: None,
            migration_task,
            upgrade_exit_code: Arc::new(AtomicI32::new(-1)),
        };

        Ok(node)
    }

    /// Build the saorsa-core `NodeConfig` from our config.
    fn build_core_config(config: &NodeConfig) -> Result<CoreNodeConfig> {
        let local = matches!(config.network_mode, NetworkMode::Development);

        let mut core_config = CoreNodeConfig::builder()
            .port(config.port)
            .ipv6(!config.ipv4_only)
            .local(local)
            .max_message_size(config.max_message_size)
            .build()
            .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;

        // Add bootstrap peers.
        core_config.bootstrap_peers = config
            .bootstrap
            .iter()
            .map(|addr| MultiAddr::quic(*addr))
            .collect();

        // Propagate network-mode tuning into saorsa-core where supported.
        match config.network_mode {
            NetworkMode::Production => {
                core_config.diversity_config = Some(CoreDiversityConfig::default());
            }
            NetworkMode::Testnet => {
                // Testnet allows loopback so nodes can be co-located on one machine.
                core_config.allow_loopback = true;
                core_config.diversity_config = Some(CoreDiversityConfig {
                    max_per_ip: config.testnet.max_per_ip,
                    max_per_subnet: config.testnet.max_per_subnet,
                });
            }
            NetworkMode::Development => {
                core_config.diversity_config = Some(CoreDiversityConfig::permissive());
            }
        }

        // Persist close group peers + trust scores across restarts.
        // Default to root_dir (alongside node_identity.key) when not explicitly set.
        core_config.close_group_cache_dir = Some(
            config
                .close_group_cache_dir
                .clone()
                .unwrap_or_else(|| config.root_dir.clone()),
        );

        Ok(core_config)
    }

    /// Resolve the node identity from disk or generate a new one.
    ///
    /// **When `root_dir` differs from the platform default** (set via `--root-dir`
    /// or loaded from `config.toml`):
    ///   - Use `root_dir` directly: load existing identity or generate a new one.
    ///
    /// **When `root_dir` is the platform default** (first run, no config file):
    ///   1. Scan `{default_root_dir}/nodes/` for subdirectories containing
    ///      `node_identity.key`.
    ///   2. **None found** — first run: generate identity, create
    ///      `nodes/{full_peer_id}/`, save identity there, update `config.root_dir`.
    ///   3. **Exactly one found** — load it and update `config.root_dir`.
    ///   4. **Multiple found** — return an error asking for `--root-dir`.
    async fn resolve_identity(config: &mut NodeConfig) -> Result<NodeIdentity> {
        if config.root_dir != default_root_dir() {
            return Self::load_or_generate_identity(&config.root_dir).await;
        }

        let nodes_dir = default_nodes_dir();
        let identity_dirs = Self::scan_identity_dirs(&nodes_dir)?;

        match identity_dirs.len() {
            0 => {
                // First run: generate new identity and create a peer-id-scoped subdirectory
                let identity = NodeIdentity::generate().map_err(|e| {
                    Error::Startup(format!("Failed to generate node identity: {e}"))
                })?;
                let peer_id = identity.peer_id().to_hex();
                let peer_dir = nodes_dir.join(&peer_id);
                std::fs::create_dir_all(&peer_dir)?;
                identity
                    .save_to_file(&peer_dir.join(NODE_IDENTITY_FILENAME))
                    .await
                    .map_err(|e| Error::Startup(format!("Failed to save node identity: {e}")))?;
                config.root_dir = peer_dir;
                Ok(identity)
            }
            1 => {
                let dir = identity_dirs
                    .first()
                    .ok_or_else(|| Error::Config("No identity dirs found".to_string()))?;
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
                    nodes_dir.display(),
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

    fn build_upgrade_monitor(config: &NodeConfig, node_id_seed: &[u8]) -> UpgradeMonitor {
        let mut monitor = UpgradeMonitor::new(
            config.upgrade.github_repo.clone(),
            config.upgrade.channel,
            config.upgrade.check_interval_hours,
        );

        if let Ok(cache_dir) = upgrade_cache_dir() {
            monitor = monitor.with_release_cache(ReleaseCache::new(
                cache_dir,
                std::time::Duration::from_secs(3600),
            ));
        }

        if config.upgrade.staged_rollout_hours > 0 {
            monitor =
                monitor.with_staged_rollout(node_id_seed, config.upgrade.staged_rollout_hours);
        }

        monitor
    }

    /// Start moving this node off the legacy LMDB chunk store, if it still has one.
    ///
    /// Started after the replication engine rather than with the store, because the
    /// copier needs two things only the engine has: the commitment state, which owns the
    /// retention veto on deleting the old store, and live routing, which is how the node
    /// knows which chunks it is among the closest to and therefore must never give up.
    fn spawn_storage_migration(
        store: Arc<ChunkStore>,
        p2p: &Arc<P2PNode>,
        engine: &ReplicationEngine,
        shutdown: CancellationToken,
    ) -> Option<JoinHandle<()>> {
        if !crate::storage::migration::should_migrate(&store) {
            return None;
        }
        let context = crate::storage::migration::MigrationContext {
            p2p: Some(Arc::clone(p2p)),
            self_id: Some(*p2p.peer_id()),
            self_xor: crate::client::peer_id_to_xor_name(&p2p.peer_id().to_string()),
            commitment: Some(Arc::clone(engine.commitment_state())),
            replication: Some(Arc::clone(engine.config())),
            sync_state: Some(Arc::clone(engine.sync_state())),
            audit_challenge_coordinator: Some(Arc::clone(engine.audit_challenge_coordinator())),
            peer_commitments: Some(Arc::clone(engine.last_commitment_by_peer())),
            close_group_size: engine.config().close_group_size,
        };
        Some(tokio::spawn(async move {
            crate::storage::migration::run(store, context, shutdown).await;
        }))
    }

    /// Build the ANT protocol handler from config.
    ///
    /// Initializes LMDB storage, payment verifier, and quote generator.
    /// Wires ML-DSA-65 signing from the node's identity into the quote generator.
    async fn build_ant_protocol(
        config: &NodeConfig,
        identity: &NodeIdentity,
        close_group_size: usize,
    ) -> Result<AntProtocol> {
        // Create LMDB storage
        let storage_config = ChunkStoreConfig {
            root_dir: config.root_dir.clone(),
            verify_on_read: config.storage.verify_on_read,
            max_map_size: config.storage.db_size_gb.saturating_mul(1024 * 1024 * 1024),
            disk_reserve: config.storage.disk_reserve_mb.saturating_mul(MIB),
            migration: config.storage.migration.clone(),
        };
        let storage = ChunkStore::new(storage_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create LMDB storage: {e}")))?;

        // Parse rewards address (required — node must know where to receive payments)
        let rewards_address = match config.payment.rewards_address {
            Some(ref addr) => parse_rewards_address(addr)?,
            None => {
                return Err(Error::Startup(
                    "No rewards address configured. Set --rewards-address or payment.rewards_address in config.".to_string(),
                ));
            }
        };

        // Create payment verifier
        let evm_network = config.payment.evm_network.clone().into_evm_network();
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                network: evm_network,
            },
            cache_capacity: config.payment.cache_capacity,
            close_group_size,
            local_rewards_address: rewards_address,
            // Shadow mode by default; enforcement is a per-node canary opt-in
            // via ANT_PRICE_FLOOR_ENFORCE (see PriceFloorConfig).
            price_floor: PriceFloorConfig::from_env(),
        };
        if payment_config.price_floor.enforce {
            info!(
                "Price floor ENFORCEMENT enabled (tolerance {}%)",
                payment_config.price_floor.tolerance_percent
            );
        }
        let payment_verifier = PaymentVerifier::new(payment_config);
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing from node identity.
        // This same signer is used for both regular quotes and merkle candidate quotes.
        crate::payment::wire_ml_dsa_signer(&mut quote_generator, identity)?;

        let storage = Arc::new(storage);
        let payment_verifier = Arc::new(payment_verifier);

        let protocol = AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator));

        info!(
            "ANT protocol handler initialized with ML-DSA-65 signing (protocol={CHUNK_PROTOCOL_ID})"
        );

        Ok(protocol)
    }
}

/// A running Ant node.
pub struct RunningNode {
    config: NodeConfig,
    p2p_node: Arc<P2PNode>,
    shutdown: CancellationToken,
    events_tx: NodeEventsSender,
    events_rx: Option<NodeEventsChannel>,
    upgrade_monitor: Option<UpgradeMonitor>,
    /// ANT protocol handler for chunk storage.
    ant_protocol: Option<Arc<AntProtocol>>,
    /// Replication engine (manages neighbor sync, verification, audits).
    replication_engine: Option<ReplicationEngine>,
    /// Protocol message routing background task.
    protocol_task: Option<JoinHandle<()>>,
    /// The task moving this node off the legacy chunk store, if it has one.
    ///
    /// Awaited before the replication engine and the P2P layer are torn down, because it
    /// holds handles to both and is in the middle of reading and writing the chunk store.
    migration_task: Option<JoinHandle<()>>,
    /// Exit code requested by a successful upgrade (-1 = no upgrade exit pending).
    upgrade_exit_code: Arc<AtomicI32>,
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
    #[allow(clippy::too_many_lines)]
    pub async fn run(&mut self) -> Result<()> {
        info!("Node runtime loop starting");

        // Subscribe to DHT events BEFORE starting the P2P node so the
        // bootstrap-sync task does not miss the BootstrapComplete event
        // emitted during P2PNode::start().
        let dht_events_for_bootstrap = self
            .replication_engine
            .as_ref()
            .map(|_| self.p2p_node.dht_manager().subscribe_events());

        // Start the P2P node
        self.p2p_node
            .start()
            .await
            .map_err(|e| Error::Startup(format!("Failed to start P2P node: {e}")))?;

        let listen_addrs = self.p2p_node.listen_addrs().await;
        info!(listen_addrs = ?listen_addrs, "P2P node started");

        // Extract the actual bound port (config port may be 0 = auto-select)
        let actual_port = listen_addrs
            .first()
            .and_then(MultiAddr::port)
            .unwrap_or(self.config.port);
        info!(
            port = actual_port,
            "Node is running on port: {}", actual_port
        );

        // Emit started event
        if let Err(e) = self.events_tx.send(NodeEvent::Started) {
            warn!("Failed to send Started event: {e}");
        }

        // Start protocol message routing (P2P → AntProtocol → P2P response)
        self.start_protocol_routing();

        // Start replication engine background tasks
        if let Some(ref mut engine) = self.replication_engine {
            // Safety: dht_events_for_bootstrap is Some when replication_engine
            // is Some (both arms use the same condition).
            if let Some(dht_events) = dht_events_for_bootstrap {
                engine.start(dht_events);
            }
            info!("Replication engine started");
        }

        // Start upgrade monitor if enabled
        if let Some(monitor) = self.upgrade_monitor.take() {
            let events_tx = self.events_tx.clone();
            let shutdown = self.shutdown.clone();
            let stop_on_upgrade = self.config.upgrade.stop_on_upgrade;
            let upgrade_exit_code = Arc::clone(&self.upgrade_exit_code);

            tokio::spawn(async move {
                let mut monitor = monitor;
                let mut upgrader = AutoApplyUpgrader::new().with_stop_on_upgrade(stop_on_upgrade);
                if let Ok(cache_dir) = upgrade_cache_dir() {
                    upgrader = upgrader.with_binary_cache(BinaryCache::new(cache_dir));
                }

                // Add randomized jitter before the first upgrade check to prevent all nodes
                // from hitting the GitHub API simultaneously when started together.
                {
                    let jitter_duration = jittered_interval(monitor.check_interval());
                    let first_check_time = chrono::Utc::now()
                        + chrono::Duration::from_std(jitter_duration).unwrap_or_else(|e| {
                            warn!("chrono::Duration::from_std failed for jitter ({e}), defaulting to 1 minute");
                            chrono::Duration::minutes(1)
                        });
                    info!(
                        "First upgrade check scheduled for {} (jitter: {}s)",
                        first_check_time.to_rfc3339(),
                        jitter_duration.as_secs()
                    );
                    tokio::time::sleep(jitter_duration).await;
                }

                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => {
                            break;
                        }
                        result = monitor.check_for_ready_upgrade() => {
                            match result {
                                Ok(Some(upgrade_info)) => {
                                    info!(
                                        current_version = %upgrader.current_version(),
                                        new_version = %upgrade_info.version,
                                        "Upgrade available"
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
                                        Ok(UpgradeResult::Success { version, exit_code }) => {
                                            info!("Upgrade to {} successful, initiating graceful shutdown", version);
                                            upgrade_exit_code.store(exit_code, Ordering::SeqCst);
                                            shutdown.cancel();
                                            break;
                                        }
                                        Ok(UpgradeResult::RolledBack { reason }) => {
                                            warn!("Error during upgrade process: {}", reason);
                                        }
                                        Ok(UpgradeResult::NoUpgrade) => {
                                            info!("Already running latest version");
                                        }
                                        Err(e) => {
                                            error!("Error during upgrade process: {}", e);
                                        }
                                    }
                                }
                                Ok(None) => {
                                    if let Some(remaining) = monitor.time_until_upgrade() {
                                        info!(
                                            "Upgrade pending, rollout delay remaining: {}m {}s",
                                            remaining.as_secs() / 60,
                                            remaining.as_secs() % 60
                                        );
                                    } else {
                                        info!("No upgrade available");
                                    }
                                }
                                Err(e) => {
                                    warn!("Error during upgrade process: {}", e);
                                }
                            }
                            // If an upgrade is pending, sleep for exactly the remaining
                            // rollout delay so the node restarts at its scheduled time
                            // rather than waiting for the next check interval tick.
                            let sleep_duration = monitor.time_until_upgrade().map_or_else(
                                || {
                                    // No pending upgrade - schedule next check with jitter
                                    let jittered_duration =
                                        jittered_interval(monitor.check_interval());
                                    let next_check = chrono::Utc::now()
                                        + chrono::Duration::from_std(jittered_duration).unwrap_or_else(|e| {
                                            warn!("chrono::Duration::from_std failed for interval ({e}), defaulting to 1 hour");
                                            chrono::Duration::hours(1)
                                        });
                                    info!("Next upgrade check scheduled for {}", next_check.to_rfc3339());
                                    jittered_duration
                                },
                                |remaining| {
                                    // If the rollout delay has fully elapsed but the upgrade was
                                    // not successfully applied, avoid a tight loop by backing off
                                    // at least one check interval before retrying.
                                    if remaining.is_zero() {
                                        let backoff = jittered_interval(monitor.check_interval());
                                        let next_check = chrono::Utc::now()
                                            + chrono::Duration::from_std(backoff).unwrap_or_else(|e| {
                                                warn!("chrono::Duration::from_std failed for backoff ({e}), defaulting to 1 hour");
                                                chrono::Duration::hours(1)
                                            });
                                        info!(
                                            "Upgrade rollout delay elapsed but previous apply did not succeed; \
                                             backing off, next check scheduled for {}",
                                            next_check.to_rfc3339()
                                        );
                                        backoff
                                    } else {
                                        let wake_time = chrono::Utc::now()
                                            + chrono::Duration::from_std(remaining).unwrap_or_else(|e| {
                                                warn!("chrono::Duration::from_std failed for rollout delay ({e}), defaulting to 1 minute");
                                                chrono::Duration::minutes(1)
                                            });
                                        info!("Will apply upgrade at {}", wake_time.to_rfc3339());
                                        remaining
                                    }
                                },
                            );
                            // Use select! so shutdown can interrupt long sleeps
                            // (e.g. during a full rollout window delay).
                            tokio::select! {
                                () = shutdown.cancelled() => {
                                    break;
                                }
                                () = tokio::time::sleep(sleep_duration) => {}
                            }
                        }
                    }
                }
            });
        }

        // A node that still has a legacy chunk store and no task moving it off one is the
        // failure this cannot be allowed to have silently: the store opens, serves the
        // union of both, and never frees a byte. It happened once, during a rebase that
        // dropped the spawn, and nothing noticed because a node without a legacy store
        // starts no migration and every test built the store directly. Say so loudly.
        if let Some(ref protocol) = self.ant_protocol {
            if protocol.storage().has_legacy() && self.migration_task.is_none() {
                error!(
                    migration_event = "not_started",
                    "This node still has a legacy chunk store but nothing is migrating it. \
                     Its disk will never be reclaimed. This is a wiring fault, not a \
                     configuration one: report it rather than working around it."
                );
            }
        }

        info!("Node running, waiting for shutdown signal");

        // Run the main event loop with signal handling
        self.run_event_loop().await?;

        // The migration first, and awaited rather than aborted: it is mid-way through
        // reading and writing the chunk store, and it holds the commitment state and the
        // routing handle that the two shutdowns below are about to invalidate. It watches
        // the same cancellation token, so this returns as soon as its current step does.
        if let Some(handle) = self.migration_task.take() {
            if let Err(e) = handle.await {
                warn!("Storage migration task did not stop cleanly: {e}");
            }
        }

        // Shutdown replication engine before P2P so background tasks don't
        // use a dead P2P layer, and Arc<ChunkStore> references are released.
        if let Some(ref mut engine) = self.replication_engine {
            engine.shutdown().await;
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

        // If an upgrade triggered the shutdown, exit with the requested code.
        // This happens *after* all cleanup (P2P shutdown, log flush, etc.) so
        // that destructors and async resources are properly torn down.
        let exit_code = self.upgrade_exit_code.load(Ordering::SeqCst);
        if exit_code >= 0 {
            info!("Exiting with code {} for upgrade restart", exit_code);
            std::process::exit(exit_code);
        }

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
                    info!("Received SIGHUP (config reload not yet supported)");
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
        let semaphore = Arc::new(Semaphore::new(64));

        self.protocol_task = Some(tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if let P2PEvent::Message {
                    topic,
                    source: Some(source),
                    data,
                    ..
                } = event
                {
                    let handler_info: Option<(&str, &str)> = if topic == CHUNK_PROTOCOL_ID {
                        Some(("chunk", CHUNK_PROTOCOL_ID))
                    } else {
                        None
                    };

                    if let Some((data_type, response_topic)) = handler_info {
                        debug!("Received {data_type} protocol message from {source}");
                        let received_at = Instant::now();
                        let protocol = Arc::clone(&protocol);
                        let p2p = Arc::clone(&p2p);
                        let sem = semaphore.clone();
                        tokio::spawn(async move {
                            let Ok(_permit) = sem.acquire().await else {
                                return;
                            };
                            let queue_wait = received_at.elapsed();
                            let handled = match data_type {
                                "chunk" => {
                                    protocol
                                        .try_handle_request_with_context(
                                            &data,
                                            Some(ChunkRequestContext::new(
                                                source.to_string(),
                                                received_at,
                                                queue_wait,
                                            )),
                                        )
                                        .await
                                }
                                _ => return,
                            };
                            let telemetry = handled.get_telemetry;
                            match handled.response {
                                Ok(Some(response)) => {
                                    let send_started = Instant::now();
                                    let send_result = p2p
                                        .send_message(
                                            &source,
                                            response_topic,
                                            response.to_vec(),
                                            &[],
                                        )
                                        .await;
                                    if let Some(telemetry) = telemetry {
                                        telemetry.finish_send(
                                            send_started.elapsed(),
                                            send_result.is_ok(),
                                        );
                                    }
                                    if let Err(e) = send_result {
                                        warn!("Failed to send {data_type} protocol response to {source}: {e}");
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
                                    warn!("{data_type} protocol handler error: {e}");
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

/// Apply ±5% jitter to a base interval to prevent thundering-herd behaviour
/// when multiple nodes check for upgrades on the same schedule.
fn jittered_interval(base: std::time::Duration) -> std::time::Duration {
    let secs = base.as_secs();
    let variance = secs / 20; // 5%
    if variance == 0 {
        return base;
    }
    let jitter = rand::thread_rng().gen_range(0..=variance * 2);
    std::time::Duration::from_secs(secs.saturating_sub(variance) + jitter)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use tempfile::TempDir;

    /// A node with a legacy chunk store must get a migration task; one without must not.
    ///
    /// The spawn helper is tested directly because its *absence* is the failure mode that
    /// already happened here: a rebase dropped the call, the store still opened and still
    /// served, and no test could tell the difference.
    #[tokio::test]
    async fn a_legacy_store_gets_a_migration_task_and_a_fresh_node_does_not() {
        let dir = TempDir::new().expect("temp dir");
        let root = dir.path().join("node");
        std::fs::create_dir_all(&root).expect("mkdir");

        // Fresh node: nothing to migrate, so no task.
        let fresh = Arc::new(
            crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
                root_dir: root.clone(),
                ..crate::storage::ChunkStoreConfig::test_default()
            })
            .await
            .expect("open fresh"),
        );
        assert!(!fresh.has_legacy());
        assert!(
            !crate::storage::migration::should_migrate(&fresh),
            "a node with no legacy store has nothing to migrate"
        );
        drop(fresh);

        // Seed a legacy store, then reopen: now there is something to migrate.
        {
            let lmdb = crate::storage::LmdbStorage::new(crate::storage::LmdbStorageConfig {
                root_dir: root.clone(),
                verify_on_read: true,
                max_map_size: 0,
                disk_reserve: 0,
            })
            .await
            .expect("open legacy");
            let content = b"a chunk from before the migration";
            let addr = crate::client::compute_address(content);
            lmdb.put(&addr, content).await.expect("put");
            lmdb.wait_idle().await;
        }
        let upgrading = Arc::new(
            crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
                root_dir: root.clone(),
                ..crate::storage::ChunkStoreConfig::test_default()
            })
            .await
            .expect("open upgrading"),
        );
        assert!(upgrading.has_legacy());
        assert!(
            crate::storage::migration::should_migrate(&upgrading),
            "a node with a legacy store must be migrated, or its disk is never reclaimed"
        );
    }
    use super::*;
    use crate::config::NODES_SUBDIR;

    #[test]
    fn test_build_upgrade_monitor_staged_rollout_enabled() {
        let config = NodeConfig {
            upgrade: crate::config::UpgradeConfig {
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
        assert!(core.diversity_config.is_some());
    }

    #[test]
    fn test_build_core_config_ipv4_only() {
        let config = NodeConfig {
            ipv4_only: true,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(!core.ipv6, "ipv4_only should disable IPv6");
    }

    #[test]
    fn test_build_core_config_dual_stack_by_default() {
        let config = NodeConfig::default();
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(core.ipv6, "dual-stack should be the default");
    }

    #[test]
    fn test_build_core_config_sets_development_mode_permissive() {
        let config = NodeConfig {
            network_mode: NetworkMode::Development,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        let diversity = core.diversity_config.expect("diversity");
        assert_eq!(diversity.max_per_ip, Some(usize::MAX));
        assert_eq!(diversity.max_per_subnet, Some(usize::MAX));
    }

    #[test]
    fn test_scan_identity_dirs_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_scan_identity_dirs_nonexistent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent_identity_dir");
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
            ..Default::default()
        };

        let identity = NodeBuilder::resolve_identity(&mut config).await.unwrap();
        // Key file should exist
        assert!(tmp.path().join(NODE_IDENTITY_FILENAME).exists());
        // peer_id should be derivable from the identity
        let peer_id = identity.peer_id().to_hex();
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
            ..Default::default()
        };

        let loaded = NodeBuilder::resolve_identity(&mut config).await.unwrap();
        assert_eq!(loaded.peer_id(), original.peer_id());
    }

    #[test]
    fn test_peer_id_hex_length() {
        let id = saorsa_core::identity::PeerId::from_bytes([0x42; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    /// Simulates a node restart: first run creates identity in a scoped subdir
    /// under `nodes/`, second run discovers and reloads it — `peer_id` must be
    /// identical and the directory name is the full 64-char hex peer ID.
    #[tokio::test]
    async fn test_identity_persisted_across_restarts() {
        let base_dir = tempfile::tempdir().unwrap();
        let nodes_dir = base_dir.path().join(NODES_SUBDIR);

        // First "boot": generate identity, save it in nodes/{peer_id}/
        let identity1 = NodeIdentity::generate().unwrap();
        let peer_id1 = identity1.peer_id().to_hex();
        let peer_dir = nodes_dir.join(&peer_id1);
        std::fs::create_dir_all(&peer_dir).unwrap();
        identity1
            .save_to_file(&peer_dir.join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();

        // Verify directory name is the full 64-char hex peer ID
        assert_eq!(peer_id1.len(), 64);
        assert_eq!(peer_dir.file_name().unwrap().to_string_lossy(), peer_id1);

        // Second "boot": scan should find and reload the same identity
        let identity_dirs = NodeBuilder::scan_identity_dirs(&nodes_dir).unwrap();
        assert_eq!(identity_dirs.len(), 1);
        let loaded = NodeIdentity::load_from_file(&identity_dirs[0].join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();
        let peer_id2 = loaded.peer_id().to_hex();

        assert_eq!(peer_id1, peer_id2, "peer_id must survive restart");
        assert_eq!(
            identity_dirs[0], peer_dir,
            "root_dir must be the same directory"
        );
    }

    /// When two identity subdirs exist under `nodes/`, the scan finds multiple
    /// and the resolve path would error asking for `--root-dir`.
    #[tokio::test]
    async fn test_multiple_identities_errors() {
        let base_dir = tempfile::tempdir().unwrap();
        let nodes_dir = base_dir.path().join(NODES_SUBDIR);

        // Create two identity subdirectories under nodes/
        for name in &["aaaa", "bbbb"] {
            let dir = nodes_dir.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let identity = NodeIdentity::generate().unwrap();
            identity
                .save_to_file(&dir.join(NODE_IDENTITY_FILENAME))
                .await
                .unwrap();
        }

        let identity_dirs = NodeBuilder::scan_identity_dirs(&nodes_dir).unwrap();
        assert_eq!(identity_dirs.len(), 2, "should find both identity dirs");
    }

    /// With a non-default `root_dir` (explicit path), the identity is created on
    /// first run and reloaded on subsequent runs from the same directory.
    #[tokio::test]
    async fn test_explicit_root_dir_persists_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();

        // First boot — non-default root_dir triggers explicit path
        let mut config1 = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let identity1 = NodeBuilder::resolve_identity(&mut config1).await.unwrap();

        // Second boot — same dir
        let mut config2 = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let identity2 = NodeBuilder::resolve_identity(&mut config2).await.unwrap();

        assert_eq!(
            identity1.peer_id(),
            identity2.peer_id(),
            "explicit --root-dir must yield stable identity"
        );
    }
}
