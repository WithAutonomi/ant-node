//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{
    default_nodes_dir, default_root_dir, NetworkMode, NodeConfig, DAEMON_IDENTITY_FILENAME,
    NODE_IDENTITY_FILENAME,
};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::logging::{debug, error, info, warn};
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::wallet::parse_rewards_address;
use crate::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, QuoteGenerator,
    SharedPaymentCache,
};
use crate::replication::config::ReplicationConfig;
use crate::replication::paid_list::PaidListCatalog;
use crate::replication::{admission, config::storage_admission_width};
use crate::replication::{DaemonReplicationCoordinator, ReplicationEngine};
use crate::storage::lmdb::MIB;
use crate::storage::{
    AntProtocol, ChunkRequestContext, ChunkStore, LmdbStorage, LmdbStorageConfig,
    SharedChunkStoreBase, SharedChunkStoreConfig,
};
use crate::upgrade::{
    upgrade_cache_dir, AutoApplyUpgrader, BinaryCache, ReleaseCache, UpgradeMonitor, UpgradeResult,
};
use rand::Rng;
use saorsa_core::identity::{NodeIdentity, PeerId};
use saorsa_core::{
    IPDiversityConfig as CoreDiversityConfig, MultiAddr, NodeConfig as CoreNodeConfig, P2PEvent,
    P2PNode, SharedTransport,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
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

        // Resolve identity and root_dir (may update self.config.root_dir)
        let identity = Arc::new(Self::resolve_identity(&mut self.config).await?);
        self.build_resolved(identity, None, true).await
    }

    #[allow(clippy::too_many_lines)]
    async fn build_resolved(
        self,
        identity: Arc<NodeIdentity>,
        daemon_services: Option<&DaemonSharedServices>,
        enable_upgrade_monitor: bool,
    ) -> Result<RunningNode> {
        let exit_process_on_upgrade = daemon_services.is_none();
        let handle_os_signals = daemon_services.is_none();
        Self::validate_production_rewards_address(&self.config)?;
        let peer_id = identity.peer_id().to_hex();

        info!(peer_id = %peer_id, root_dir = %self.config.root_dir.display(), "Node identity resolved");

        // Ensure root directory exists
        std::fs::create_dir_all(&self.config.root_dir)?;

        // Create shutdown token
        let shutdown = daemon_services.map_or_else(CancellationToken::new, |services| {
            services.shutdown.child_token()
        });

        // Create event channel
        let (events_tx, events_rx) = create_event_channel();

        // Convert our config to saorsa-core's config
        let mut core_config = Self::build_core_config(&self.config)?;
        // Inject the ML-DSA identity so the P2PNode's transport peer ID
        // matches the pub_key embedded in payment quotes.
        core_config.node_identity = Some(Arc::clone(&identity));
        debug!("Core config: {:?}", core_config);

        // Initialize saorsa-core's P2PNode
        let p2p_node = match daemon_services {
            Some(services) => {
                P2PNode::new_with_shared_transport(core_config, services.transport.as_ref()).await
            }
            None => P2PNode::new(core_config).await,
        }
        .map_err(|e| Error::Startup(format!("Failed to create P2P node: {e}")))?;

        // Create upgrade monitor
        let upgrade_monitor = enable_upgrade_monitor.then(|| {
            let node_id_seed = p2p_node.peer_id().as_bytes();
            Self::build_upgrade_monitor(&self.config, node_id_seed)
        });

        let repl_config = ReplicationConfig::default();

        // Initialize ANT protocol handler for chunk storage and
        // wire the fresh-write channel so PUTs trigger replication.
        let (ant_protocol, fresh_write_rx) = if self.config.storage.enabled {
            let (fresh_write_tx, fresh_write_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut protocol = Self::build_ant_protocol(
                &self.config,
                &identity,
                repl_config.close_group_size,
                daemon_services.map(|services| services.payment_cache.clone()),
                daemon_services.map(|services| {
                    let view = services
                        .chunk_store
                        .view(*identity.peer_id(), self.config.root_dir.clone());
                    let store: Arc<dyn ChunkStore> = view;
                    store
                }),
            )
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

        // Initialize replication engine (if storage is enabled)
        let replication_engine = if let (Some(ref protocol), Some(fresh_rx)) =
            (&ant_protocol, fresh_write_rx)
        {
            let storage_arc = protocol.storage();
            let payment_verifier_arc = protocol.payment_verifier_arc();
            let engine_result = match daemon_services {
                Some(services) => {
                    let paid_list =
                        Arc::new(services.paid_catalog.view(*identity.peer_id().as_bytes()));
                    ReplicationEngine::new_with_paid_list(
                        repl_config,
                        Arc::clone(&p2p_arc),
                        storage_arc,
                        paid_list,
                        Some(Arc::clone(&services.replication_coordinator)),
                        payment_verifier_arc,
                        Arc::clone(&identity),
                        fresh_rx,
                        shutdown.clone(),
                    )
                    .await
                }
                None => {
                    ReplicationEngine::new(
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
                }
            };
            match engine_result {
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
            upgrade_exit_code: Arc::new(AtomicI32::new(-1)),
            exit_process_on_upgrade,
            handle_os_signals,
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

    /// Build the ANT protocol handler from config.
    ///
    /// Initializes LMDB storage, payment verifier, and quote generator.
    /// Wires ML-DSA-65 signing from the node's identity into the quote generator.
    async fn build_ant_protocol(
        config: &NodeConfig,
        identity: &NodeIdentity,
        close_group_size: usize,
        shared_payment_cache: Option<SharedPaymentCache>,
        shared_storage: Option<Arc<dyn ChunkStore>>,
    ) -> Result<AntProtocol> {
        let storage: Arc<dyn ChunkStore> = if let Some(storage) = shared_storage {
            storage
        } else {
            let storage_config = LmdbStorageConfig {
                root_dir: config.root_dir.clone(),
                verify_on_read: config.storage.verify_on_read,
                max_map_size: config.storage.db_size_gb.saturating_mul(1024 * 1024 * 1024),
                disk_reserve: config.storage.disk_reserve_mb.saturating_mul(MIB),
            };
            let storage = LmdbStorage::new(storage_config)
                .await
                .map_err(|e| Error::Startup(format!("Failed to create LMDB storage: {e}")))?;
            Arc::new(storage)
        };

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
        let payment_verifier = match shared_payment_cache {
            Some(cache) => PaymentVerifier::new_with_shared_cache(payment_config, cache),
            None => PaymentVerifier::new(payment_config),
        };
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing from node identity.
        // This same signer is used for both regular quotes and merkle candidate quotes.
        crate::payment::wire_ml_dsa_signer(&mut quote_generator, identity)?;

        let payment_verifier = Arc::new(payment_verifier);

        let protocol = AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator));

        info!(
            "ANT protocol handler initialized with ML-DSA-65 signing (protocol={CHUNK_PROTOCOL_ID})"
        );

        Ok(protocol)
    }
}

/// Machine-wide services owned by the full node daemon.
///
/// Stage one contains the shared physical transport, process lifecycle and
/// identity-independent payment-chain cache. Later ADR stages add routing
/// observations, storage/catalogue and replication planning behind this same
/// ownership boundary.
struct DaemonSharedServices {
    transport: Arc<SharedTransport>,
    payment_cache: SharedPaymentCache,
    chunk_store: Arc<SharedChunkStoreBase>,
    paid_catalog: Arc<PaidListCatalog>,
    replication_coordinator: Arc<DaemonReplicationCoordinator>,
    shutdown: CancellationToken,
}

const DAEMON_ROSTER_FILENAME: &str = "identity-roster.json";
const GIB_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonRosterEntry {
    peer_id: String,
    root: PathBuf,
    active: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DaemonRosterManifest {
    version: u8,
    identities: Vec<DaemonRosterEntry>,
}

/// Builder for the stage-one fixed-roster, shared-network node daemon.
pub struct NodeDaemonBuilder {
    config: NodeConfig,
}

impl NodeDaemonBuilder {
    /// Create a daemon builder from a configuration with at least one
    /// `daemon.identity_roots` entry.
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    /// Load the fixed identity roster and build all logical nodes on one
    /// physical transport endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty roster, duplicate directories or peer
    /// IDs, missing identity keys, or failure to construct any logical node.
    #[allow(clippy::too_many_lines)]
    pub async fn build(mut self) -> Result<RunningNodeDaemon> {
        if !self.config.daemon.is_enabled() {
            return Err(Error::Config(
                "daemon mode requires at least one daemon.identity_roots entry".to_string(),
            ));
        }

        self.prepare_auto_scaled_roster().await?;

        let mut seen_roots = HashSet::new();
        let mut seen_peer_ids = HashSet::new();
        let mut roster = Vec::with_capacity(self.config.daemon.identity_roots.len());
        for configured_root in &self.config.daemon.identity_roots {
            let root = std::fs::canonicalize(configured_root).map_err(|error| {
                Error::Config(format!(
                    "identity root {} cannot be resolved: {error}",
                    configured_root.display()
                ))
            })?;
            if !seen_roots.insert(root.clone()) {
                return Err(Error::Config(format!(
                    "identity root {} appears more than once in the daemon roster",
                    root.display()
                )));
            }

            let key_path = root.join(NODE_IDENTITY_FILENAME);
            if !key_path.is_file() {
                return Err(Error::Config(format!(
                    "identity root {} does not contain {}",
                    root.display(),
                    NODE_IDENTITY_FILENAME
                )));
            }
            let identity = Arc::new(NodeIdentity::load_from_file(&key_path).await.map_err(
                |error| {
                    Error::Startup(format!(
                        "Failed to load node identity from {}: {error}",
                        key_path.display()
                    ))
                },
            )?);
            if !seen_peer_ids.insert(*identity.peer_id()) {
                return Err(Error::Config(format!(
                    "peer ID {} appears more than once in the daemon roster",
                    identity.peer_id()
                )));
            }
            roster.push((root, identity));
        }

        std::fs::create_dir_all(&self.config.root_dir)?;
        let daemon_state_root = self.config.root_dir.join("daemon-state");
        std::fs::create_dir_all(&daemon_state_root)?;
        Self::persist_loaded_roster(&daemon_state_root, &roster)?;
        let daemon_identity =
            Arc::new(Self::load_or_generate_daemon_identity(&self.config.root_dir).await?);

        let first_root = roster
            .first()
            .map(|(root, _)| root)
            .ok_or_else(|| Error::Config("daemon identity roster is empty".to_string()))?;
        let mut physical_node_config = self.config.clone();
        physical_node_config.root_dir = first_root.clone();
        physical_node_config.close_group_cache_dir = Some(first_root.clone());
        let physical_core_config = NodeBuilder::build_core_config(&physical_node_config)?;
        let shared_transport = Arc::new(
            SharedTransport::new(&physical_core_config, daemon_identity)
                .await
                .map_err(|error| {
                    Error::Startup(format!("Failed to create shared daemon transport: {error}"))
                })?,
        );
        let volume_roots = if self.config.daemon.storage_roots.is_empty() {
            vec![daemon_state_root.join("chunk-volumes").join("volume-0")]
        } else {
            self.config.daemon.storage_roots.clone()
        };
        let chunk_store = SharedChunkStoreBase::new(SharedChunkStoreConfig {
            daemon_root: daemon_state_root.clone(),
            volume_roots,
            verify_on_read: self.config.storage.verify_on_read,
            max_map_size: self
                .config
                .storage
                .db_size_gb
                .saturating_mul(1024 * 1024 * 1024),
            disk_reserve: self.config.storage.disk_reserve_mb.saturating_mul(MIB),
        })
        .await
        .map_err(|error| Error::Startup(format!("Failed to open shared chunk store: {error}")))?;
        let paid_catalog = PaidListCatalog::new(&daemon_state_root)
            .await
            .map_err(|error| {
                Error::Startup(format!("Failed to open shared paid catalogue: {error}"))
            })?;
        let services = Arc::new(DaemonSharedServices {
            transport: shared_transport,
            payment_cache: SharedPaymentCache::new(),
            chunk_store,
            paid_catalog,
            replication_coordinator: Arc::new(DaemonReplicationCoordinator::new()),
            shutdown: CancellationToken::new(),
        });

        let mut nodes = Vec::with_capacity(roster.len());
        for (index, (root, identity)) in roster.into_iter().enumerate() {
            Self::import_legacy_identity_state(
                services.as_ref(),
                &self.config,
                &root,
                identity.as_ref(),
            )
            .await?;
            let mut identity_config = self.config.clone();
            identity_config.root_dir = root;
            identity_config.close_group_cache_dir = Some(identity_config.root_dir.clone());
            identity_config.daemon.identity_roots.clear();
            match NodeBuilder::new(identity_config)
                .build_resolved(identity, Some(services.as_ref()), index == 0)
                .await
            {
                Ok(node) => nodes.push(node),
                Err(error) => {
                    services.shutdown.cancel();
                    if let Err(shutdown_error) = services.transport.shutdown().await {
                        warn!(
                            "Failed to stop shared transport after build error: {shutdown_error}"
                        );
                    }
                    return Err(error);
                }
            }
        }

        info!(
            daemon_peer_id = %services.transport.daemon_peer_id(),
            logical_identities = nodes.len(),
            "Built full node daemon with shared network, storage and paid state"
        );
        Ok(RunningNodeDaemon {
            nodes,
            services,
            config: self.config,
        })
    }

    fn persist_loaded_roster(
        daemon_state_root: &Path,
        roster: &[(PathBuf, Arc<NodeIdentity>)],
    ) -> Result<()> {
        let path = daemon_state_root.join(DAEMON_ROSTER_FILENAME);
        let mut identities = if path.is_file() {
            serde_json::from_slice::<DaemonRosterManifest>(&std::fs::read(&path)?)
                .map_err(|error| Error::Config(format!("Failed to parse daemon roster: {error}")))?
                .identities
                .into_iter()
                .filter(|entry| !entry.active)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        identities.extend(roster.iter().map(|(root, identity)| DaemonRosterEntry {
            peer_id: identity.peer_id().to_hex(),
            root: root.clone(),
            active: true,
        }));
        let manifest = DaemonRosterManifest {
            version: 1,
            identities,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| Error::Config(format!("Failed to encode daemon roster: {error}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    async fn prepare_auto_scaled_roster(&mut self) -> Result<()> {
        if !self.config.daemon.auto_scale_identities {
            return Ok(());
        }
        let daemon = &self.config.daemon;
        if daemon.min_identities == 0 {
            return Err(Error::Config(
                "daemon.min_identities must be at least one".to_string(),
            ));
        }
        if daemon.gib_per_identity == 0 {
            return Err(Error::Config(
                "daemon.gib_per_identity must be greater than zero".to_string(),
            ));
        }
        if daemon.max_identities != 0 && daemon.max_identities < daemon.min_identities {
            return Err(Error::Config(
                "daemon.max_identities must be zero or at least daemon.min_identities".to_string(),
            ));
        }

        let state_root = self.config.root_dir.join("daemon-state");
        std::fs::create_dir_all(&state_root)?;
        let manifest_path = state_root.join(DAEMON_ROSTER_FILENAME);
        let existing_manifest = if manifest_path.is_file() {
            let bytes = std::fs::read(&manifest_path)?;
            serde_json::from_slice::<DaemonRosterManifest>(&bytes).map_err(|error| {
                Error::Config(format!(
                    "Failed to parse daemon roster {}: {error}",
                    manifest_path.display()
                ))
            })?
        } else {
            DaemonRosterManifest::default()
        };

        let mut roots = self.config.daemon.identity_roots.clone();
        for entry in existing_manifest
            .identities
            .iter()
            .filter(|entry| entry.active)
        {
            if !roots.contains(&entry.root) {
                roots.push(entry.root.clone());
            }
        }
        if existing_manifest.identities.is_empty() {
            for root in NodeBuilder::scan_identity_dirs(&self.config.root_dir.join("nodes"))? {
                if !roots.contains(&root) {
                    roots.push(root);
                }
            }
        }

        let desired = Self::desired_identity_count(&self.config)?;
        let target = desired.max(roots.len());
        let nodes_root = self.config.root_dir.join("nodes");
        std::fs::create_dir_all(&nodes_root)?;
        while roots.len() < target {
            let identity = NodeIdentity::generate().map_err(|error| {
                Error::Startup(format!("Failed to generate daemon node identity: {error}"))
            })?;
            let root = nodes_root.join(identity.peer_id().to_hex());
            std::fs::create_dir_all(&root)?;
            identity
                .save_to_file(&root.join(NODE_IDENTITY_FILENAME))
                .await
                .map_err(|error| {
                    Error::Startup(format!(
                        "Failed to persist generated identity {}: {error}",
                        identity.peer_id()
                    ))
                })?;
            info!(peer_id = %identity.peer_id(), root = %root.display(), "Generated capacity-backed daemon identity");
            roots.push(root);
        }
        self.config.daemon.identity_roots = roots;
        Self::persist_roster_manifest(&self.config, &manifest_path)?;
        Ok(())
    }

    fn desired_identity_count(config: &NodeConfig) -> Result<usize> {
        let daemon = &config.daemon;
        let roots = if daemon.storage_roots.is_empty() {
            vec![config
                .root_dir
                .join("daemon-state")
                .join("chunk-volumes")
                .join("volume-0")]
        } else {
            daemon.storage_roots.clone()
        };
        let reserve = daemon.capacity_reserve_gib.saturating_mul(GIB_BYTES);
        let mut usable = 0_u64;
        let mut filesystems = HashSet::new();
        for root in roots {
            std::fs::create_dir_all(&root)?;
            let filesystem = Self::filesystem_capacity_key(&root)?;
            if !filesystems.insert(filesystem) {
                continue;
            }
            let available = fs2::available_space(&root).map_err(|error| {
                Error::Config(format!(
                    "Failed to inspect daemon storage volume {}: {error}",
                    root.display()
                ))
            })?;
            usable = usable.saturating_add(available.saturating_sub(reserve));
        }
        let bytes_per_identity = daemon.gib_per_identity.saturating_mul(GIB_BYTES).max(1);
        #[allow(clippy::cast_possible_truncation)]
        let capacity_count = (usable / bytes_per_identity) as usize;
        let mut desired = capacity_count.max(daemon.min_identities);
        if daemon.max_identities > 0 {
            desired = desired.min(daemon.max_identities);
        }
        Ok(desired)
    }

    #[cfg(unix)]
    fn filesystem_capacity_key(path: &Path) -> Result<String> {
        use std::os::unix::fs::MetadataExt;
        Ok(format!("dev:{}", std::fs::metadata(path)?.dev()))
    }

    #[cfg(not(unix))]
    fn filesystem_capacity_key(path: &Path) -> Result<String> {
        // Canonical roots at least prevent exact aliases on platforms where
        // the standard library does not expose a stable volume identifier.
        Ok(std::fs::canonicalize(path)?.to_string_lossy().into_owned())
    }

    fn persist_roster_manifest(config: &NodeConfig, path: &Path) -> Result<()> {
        let mut identities = if path.is_file() {
            let bytes = std::fs::read(path)?;
            serde_json::from_slice::<DaemonRosterManifest>(&bytes)
                .map_err(|error| Error::Config(format!("Failed to parse daemon roster: {error}")))?
                .identities
                .into_iter()
                .filter(|entry| !entry.active)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for root in &config.daemon.identity_roots {
            let key_path = root.join(NODE_IDENTITY_FILENAME);
            let peer_id = if key_path.is_file() {
                // The peer ID is also the canonical generated directory name.
                root.file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
            } else {
                String::new()
            };
            identities.push(DaemonRosterEntry {
                peer_id,
                root: root.clone(),
                active: true,
            });
        }
        let manifest = DaemonRosterManifest {
            version: 1,
            identities,
        };
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| Error::Config(format!("Failed to encode daemon roster: {error}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    async fn import_legacy_identity_state(
        services: &DaemonSharedServices,
        config: &NodeConfig,
        root: &Path,
        identity: &NodeIdentity,
    ) -> Result<()> {
        let migration_dir = config.root_dir.join("daemon-state").join("migrations");
        std::fs::create_dir_all(&migration_dir)?;
        let marker = migration_dir.join(format!("{}.v1", identity.peer_id().to_hex()));
        if marker.is_file() {
            return Ok(());
        }
        if root.join("chunks.mdb").is_dir() {
            let legacy = LmdbStorage::new(LmdbStorageConfig {
                root_dir: root.to_path_buf(),
                verify_on_read: config.storage.verify_on_read,
                max_map_size: config.storage.db_size_gb.saturating_mul(1024 * 1024 * 1024),
                disk_reserve: config.storage.disk_reserve_mb.saturating_mul(MIB),
            })
            .await
            .map_err(|error| {
                Error::Startup(format!(
                    "Failed to open legacy chunk store at {}: {error}",
                    root.display()
                ))
            })?;
            let imported = services
                .chunk_store
                .import_identity(*identity.peer_id(), root.to_path_buf(), &legacy)
                .await?;
            legacy.wait_idle().await;
            if imported > 0 {
                info!(peer_id = %identity.peer_id(), imported, "Imported legacy chunks into daemon store; source retained");
            }
        }
        let imported_paid = services
            .paid_catalog
            .import_legacy(*identity.peer_id().as_bytes(), root)
            .await?;
        if imported_paid > 0 {
            info!(peer_id = %identity.peer_id(), imported_paid, "Imported legacy paid entries into daemon catalogue; source retained");
        }
        let tmp = marker.with_extension("v1.tmp");
        std::fs::write(
            &tmp,
            b"shared chunk and paid state imported; legacy source retained\n",
        )?;
        std::fs::rename(tmp, marker)?;
        Ok(())
    }

    async fn load_or_generate_daemon_identity(root: &Path) -> Result<NodeIdentity> {
        let key_path = root.join(DAEMON_IDENTITY_FILENAME);
        if key_path.exists() {
            return NodeIdentity::load_from_file(&key_path)
                .await
                .map_err(|error| {
                    Error::Startup(format!(
                        "Failed to load daemon transport identity from {}: {error}",
                        key_path.display()
                    ))
                });
        }

        let identity = NodeIdentity::generate().map_err(|error| {
            Error::Startup(format!(
                "Failed to generate daemon transport identity: {error}"
            ))
        })?;
        identity.save_to_file(&key_path).await.map_err(|error| {
            Error::Startup(format!(
                "Failed to save daemon transport identity to {}: {error}",
                key_path.display()
            ))
        })?;
        Ok(identity)
    }
}

/// A machine daemon hosting a fixed set of logical node identities.
pub struct RunningNodeDaemon {
    nodes: Vec<RunningNode>,
    services: Arc<DaemonSharedServices>,
    config: NodeConfig,
}

struct ActiveDaemonIdentity {
    root: PathBuf,
    shutdown: CancellationToken,
    p2p_node: Arc<P2PNode>,
    upgrade_exit_code: Arc<AtomicI32>,
}

#[cfg(unix)]
async fn wait_for_daemon_shutdown_signal() -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("Received SIGINT (Ctrl-C), shutting down node daemon");
                return Ok(());
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down node daemon");
                return Ok(());
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP (daemon config reload not yet supported)");
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_daemon_shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    info!("Received Ctrl-C, shutting down node daemon");
    Ok(())
}

impl RunningNodeDaemon {
    /// Number of logical node identities hosted by this daemon.
    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.nodes.len()
    }

    /// Logical peer IDs in fixed-roster order.
    #[must_use]
    pub fn peer_ids(&self) -> Vec<String> {
        self.nodes
            .iter()
            .map(|node| node.p2p_node.peer_id().to_hex())
            .collect()
    }

    /// Stop the shared physical transport without running the daemon.
    ///
    /// # Errors
    ///
    /// Returns an error if the physical transport cannot shut down cleanly.
    pub async fn shutdown(&self) -> Result<()> {
        self.services.shutdown.cancel();
        self.services
            .transport
            .shutdown()
            .await
            .map_err(|error| Error::Startup(format!("Shared transport shutdown failed: {error}")))
    }

    /// Run every logical node and stop the physical transport after all
    /// identity services have drained.
    ///
    /// # Errors
    ///
    /// Returns the first logical node or task failure.
    pub async fn run(&mut self) -> Result<()> {
        let mut join_set = tokio::task::JoinSet::new();
        let nodes = std::mem::take(&mut self.nodes);
        let mut active = HashMap::new();
        for node in nodes {
            Self::spawn_identity(&mut join_set, &mut active, node);
        }

        let daemon_shutdown = self.services.shutdown.clone();
        let signal_task = tokio::spawn(async move {
            if let Err(error) = wait_for_daemon_shutdown_signal().await {
                error!("Daemon signal monitor failed: {error}");
            }
            daemon_shutdown.cancel();
        });

        let mut first_error = None;
        let mut requested_upgrade_exit = None;
        let mut retiring = HashSet::new();
        let mut lower_capacity_since: Option<(usize, Instant)> = None;
        let scale_period =
            std::time::Duration::from_secs(self.config.daemon.scale_interval_secs.max(1));
        let mut scale_tick = tokio::time::interval(scale_period);
        scale_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut shutting_down = false;

        while !active.is_empty() {
            tokio::select! {
                () = self.services.shutdown.cancelled(), if !shutting_down => {
                    shutting_down = true;
                    for identity in active.values() {
                        identity.shutdown.cancel();
                    }
                }
                _ = scale_tick.tick(), if !shutting_down => {
                    let maintenance = self.run_daemon_maintenance(&active).await;
                    let scaling = if self.config.daemon.auto_scale_identities {
                        self.reconcile_identity_capacity(
                            &mut join_set,
                            &mut active,
                            &mut retiring,
                            &mut lower_capacity_since,
                        ).await
                    } else {
                        Ok(())
                    };
                    if let Err(error) = maintenance.and(scaling) {
                        first_error.get_or_insert(error);
                        self.services.shutdown.cancel();
                    }
                }
                result = join_set.join_next() => {
                    let Some(result) = result else { break };
                    match result {
                        Ok((peer_id, result)) => {
                            let intentional = retiring.remove(&peer_id) || shutting_down;
                            if let Some(identity) = active.get(&peer_id) {
                                let exit_code = identity.upgrade_exit_code.load(Ordering::SeqCst);
                                if exit_code >= 0 {
                                    requested_upgrade_exit = Some(exit_code);
                                }
                            }
                            active.remove(&peer_id);
                            match result {
                                Ok(()) if intentional => {}
                                Ok(()) => {
                                    first_error.get_or_insert_with(|| Error::Startup(format!(
                                        "logical node {peer_id} stopped unexpectedly"
                                    )));
                                    self.services.shutdown.cancel();
                                }
                                Err(error) => {
                                    first_error.get_or_insert(error);
                                    self.services.shutdown.cancel();
                                }
                            }
                        }
                        Err(error) => {
                            first_error.get_or_insert_with(|| Error::Startup(format!(
                                "logical node task failed: {error}"
                            )));
                            self.services.shutdown.cancel();
                        }
                    }
                }
            }
        }

        signal_task.abort();
        let _ = signal_task.await;
        self.shutdown().await?;
        if let Some(exit_code) = requested_upgrade_exit {
            info!("Exiting shared daemon with code {exit_code} for upgrade restart");
            std::process::exit(exit_code);
        }
        first_error.map_or(Ok(()), Err)
    }

    fn spawn_identity(
        join_set: &mut tokio::task::JoinSet<(String, Result<()>)>,
        active: &mut HashMap<String, ActiveDaemonIdentity>,
        mut node: RunningNode,
    ) {
        let peer_id = node.p2p_node.peer_id().to_hex();
        active.insert(
            peer_id.clone(),
            ActiveDaemonIdentity {
                root: node.config.root_dir.clone(),
                shutdown: node.shutdown.clone(),
                p2p_node: Arc::clone(&node.p2p_node),
                upgrade_exit_code: Arc::clone(&node.upgrade_exit_code),
            },
        );
        join_set.spawn(async move {
            let result = node.run().await;
            (peer_id, result)
        });
    }

    async fn reconcile_identity_capacity(
        &self,
        join_set: &mut tokio::task::JoinSet<(String, Result<()>)>,
        active: &mut HashMap<String, ActiveDaemonIdentity>,
        retiring: &mut HashSet<String>,
        lower_capacity_since: &mut Option<(usize, Instant)>,
    ) -> Result<()> {
        let desired = NodeDaemonBuilder::desired_identity_count(&self.config)?;
        if desired > active.len() {
            *lower_capacity_since = None;
            while active.len() < desired {
                let node = self.build_dynamic_identity().await?;
                Self::spawn_identity(join_set, active, node);
            }
            self.persist_active_roster(active, retiring)?;
            return Ok(());
        }

        if desired >= active.len() || active.len() <= self.config.daemon.min_identities {
            *lower_capacity_since = None;
            return Ok(());
        }

        let now = Instant::now();
        let since = match lower_capacity_since {
            Some((previous_desired, since)) if *previous_desired == desired => *since,
            _ => {
                *lower_capacity_since = Some((desired, now));
                return Ok(());
            }
        };
        if now.duration_since(since).as_secs() < self.config.daemon.scale_down_grace_secs {
            return Ok(());
        }

        // Retire one identity per interval. Preserve the oldest roster entry as
        // an anchor because the shared transport publisher is established by
        // the first identity during startup.
        let anchor = self
            .config
            .daemon
            .identity_roots
            .first()
            .and_then(|root| active.iter().find(|(_, state)| &state.root == root))
            .map(|(peer, _)| peer.clone());
        let candidate = active
            .iter()
            .filter(|(peer, _)| Some(peer.as_str()) != anchor.as_deref())
            .filter(|(peer, _)| !retiring.contains(*peer))
            .max_by_key(|(_, state)| &state.root)
            .map(|(peer, _)| peer.clone());
        let Some(peer_id) = candidate else {
            return Ok(());
        };
        let target = active
            .keys()
            .find(|peer| **peer != peer_id && !retiring.contains(*peer))
            .cloned()
            .ok_or_else(|| {
                Error::Startup("no identity available to receive drained leases".to_string())
            })?;
        let from = PeerId::from_bytes(
            hex::decode(&peer_id)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| Error::Startup(format!("invalid active peer ID {peer_id}")))?,
        );
        let to = PeerId::from_bytes(
            hex::decode(&target)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| Error::Startup(format!("invalid target peer ID {target}")))?,
        );
        self.services.chunk_store.begin_identity_drain(from);
        let transferred = self
            .services
            .chunk_store
            .transfer_identity_leases(from, to)
            .await?;
        info!(
            peer_id,
            target, transferred, "Drained retiring identity leases to a live local identity"
        );
        retiring.insert(peer_id.clone());
        if let Some(identity) = active.get(&peer_id) {
            identity.shutdown.cancel();
        }
        *lower_capacity_since = Some((desired, now));
        self.persist_active_roster(active, retiring)?;
        Ok(())
    }

    async fn run_daemon_maintenance(
        &self,
        active: &HashMap<String, ActiveDaemonIdentity>,
    ) -> Result<()> {
        self.plan_shared_replication(active).await?;
        let moved = self.services.chunk_store.rebalance_once(128).await?;
        if moved > 0 {
            info!(
                moved,
                "Rebalanced shared chunks across daemon storage volumes"
            );
        }
        Ok(())
    }

    async fn plan_shared_replication(
        &self,
        active: &HashMap<String, ActiveDaemonIdentity>,
    ) -> Result<()> {
        let ready = active
            .values()
            .filter(|state| state.p2p_node.is_bootstrapped())
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Ok(());
        }
        let physical_keys = self.services.chunk_store.all_physical_keys().await?;
        let width = storage_admission_width(ReplicationConfig::default().close_group_size);
        let mut local_handoffs = 0_u64;
        for (index, key) in physical_keys.iter().enumerate() {
            if self.services.shutdown.is_cancelled() {
                return Ok(());
            }
            if index % 256 == 0 {
                tokio::task::yield_now().await;
            }
            for state in &ready {
                let peer_id = state.p2p_node.peer_id();
                if admission::is_responsible(peer_id, key, &state.p2p_node, width).await {
                    let view = self.services.chunk_store.view(*peer_id, state.root.clone());
                    if view.acquire_local(key).await? {
                        local_handoffs += 1;
                    }
                }
            }
        }
        if !physical_keys.is_empty() {
            debug!(
                physical_chunks = physical_keys.len(),
                logical_identities = ready.len(),
                local_handoffs,
                "Completed one-pass daemon replication responsibility plan"
            );
        }
        Ok(())
    }

    async fn build_dynamic_identity(&self) -> Result<RunningNode> {
        let identity = Arc::new(NodeIdentity::generate().map_err(|error| {
            Error::Startup(format!("Failed to generate dynamic identity: {error}"))
        })?);
        let root = self
            .config
            .root_dir
            .join("nodes")
            .join(identity.peer_id().to_hex());
        std::fs::create_dir_all(&root)?;
        identity
            .save_to_file(&root.join(NODE_IDENTITY_FILENAME))
            .await
            .map_err(|error| {
                Error::Startup(format!("Failed to persist dynamic identity: {error}"))
            })?;
        self.persist_roster_entry(DaemonRosterEntry {
            peer_id: identity.peer_id().to_hex(),
            root: root.clone(),
            active: true,
        })?;
        let mut config = self.config.clone();
        config.root_dir = root;
        config.close_group_cache_dir = Some(config.root_dir.clone());
        config.daemon.identity_roots.clear();
        let node = NodeBuilder::new(config)
            .build_resolved(identity, Some(self.services.as_ref()), false)
            .await?;
        info!(peer_id = %node.p2p_node.peer_id(), "Added dynamic logical identity to running daemon");
        Ok(node)
    }

    fn persist_roster_entry(&self, entry: DaemonRosterEntry) -> Result<()> {
        let path = self
            .config
            .root_dir
            .join("daemon-state")
            .join(DAEMON_ROSTER_FILENAME);
        let mut manifest = if path.is_file() {
            serde_json::from_slice::<DaemonRosterManifest>(&std::fs::read(&path)?)
                .map_err(|error| Error::Config(format!("Failed to parse daemon roster: {error}")))?
        } else {
            DaemonRosterManifest {
                version: 1,
                identities: Vec::new(),
            }
        };
        manifest
            .identities
            .retain(|known| known.peer_id != entry.peer_id);
        manifest.identities.push(entry);
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| Error::Config(format!("Failed to encode daemon roster: {error}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    fn persist_active_roster(
        &self,
        active: &HashMap<String, ActiveDaemonIdentity>,
        retiring: &HashSet<String>,
    ) -> Result<()> {
        let path = self
            .config
            .root_dir
            .join("daemon-state")
            .join(DAEMON_ROSTER_FILENAME);
        let mut by_peer = if path.is_file() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice::<DaemonRosterManifest>(&bytes)
                .map_err(|error| Error::Config(format!("Failed to parse daemon roster: {error}")))?
                .identities
                .into_iter()
                .map(|entry| (entry.peer_id.clone(), entry))
                .collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };
        for (peer_id, state) in active {
            by_peer.insert(
                peer_id.clone(),
                DaemonRosterEntry {
                    peer_id: peer_id.clone(),
                    root: state.root.clone(),
                    active: !retiring.contains(peer_id),
                },
            );
        }
        let manifest = DaemonRosterManifest {
            version: 1,
            identities: by_peer.into_values().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| Error::Config(format!("Failed to encode daemon roster: {error}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)?;
        Ok(())
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
    /// Exit code requested by a successful upgrade (-1 = no upgrade exit pending).
    upgrade_exit_code: Arc<AtomicI32>,
    /// Legacy nodes may exit after their own cleanup; shared-daemon nodes
    /// defer process exit until every identity and the physical transport
    /// have drained.
    exit_process_on_upgrade: bool,
    /// Standalone nodes own OS signal handling. Daemon identity contexts wait
    /// only on the daemon lifecycle token so one process has one supervisor.
    handle_os_signals: bool,
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

        info!("Node running, waiting for shutdown signal");

        // Run the main event loop with signal handling
        self.run_event_loop().await?;

        // Shutdown replication engine before P2P so background tasks don't
        // use a dead P2P layer, and Arc<LmdbStorage> references are released.
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
        if exit_code >= 0 && self.exit_process_on_upgrade {
            info!("Exiting with code {} for upgrade restart", exit_code);
            std::process::exit(exit_code);
        }

        Ok(())
    }

    /// Run the main event loop, handling shutdown and signals.
    #[cfg(unix)]
    async fn run_event_loop(&self) -> Result<()> {
        if !self.handle_os_signals {
            self.shutdown.cancelled().await;
            return Ok(());
        }

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
        if !self.handle_os_signals {
            self.shutdown.cancelled().await;
            return Ok(());
        }

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

    async fn create_identity_root(parent: &Path, name: &str) -> (PathBuf, String) {
        let root = parent.join(name);
        std::fs::create_dir_all(&root).unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let peer_id = identity.peer_id().to_hex();
        identity
            .save_to_file(&root.join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();
        (root, peer_id)
    }

    #[tokio::test]
    async fn daemon_roster_rejects_duplicate_identity_roots() {
        let temp = tempfile::tempdir().unwrap();
        let (identity_root, _) = create_identity_root(temp.path(), "identity-a").await;
        let config = NodeConfig {
            root_dir: temp.path().join("daemon"),
            daemon: crate::config::DaemonConfig {
                identity_roots: vec![identity_root.clone(), identity_root],
                ..Default::default()
            },
            network_mode: NetworkMode::Development,
            storage: crate::config::StorageConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let Err(error) = NodeDaemonBuilder::new(config).build().await else {
            panic!("duplicate roster should fail");
        };
        assert!(error.to_string().contains("appears more than once"));
    }

    #[tokio::test]
    async fn daemon_build_preserves_fixed_roster_peer_ids() {
        let temp = tempfile::tempdir().unwrap();
        let (identity_a, peer_a) = create_identity_root(temp.path(), "identity-a").await;
        let (identity_b, peer_b) = create_identity_root(temp.path(), "identity-b").await;
        let daemon_root = temp.path().join("daemon");
        let config = NodeConfig {
            root_dir: daemon_root.clone(),
            daemon: crate::config::DaemonConfig {
                identity_roots: vec![identity_a, identity_b],
                ..Default::default()
            },
            network_mode: NetworkMode::Development,
            storage: crate::config::StorageConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let daemon = NodeDaemonBuilder::new(config).build().await.unwrap();
        assert_eq!(daemon.identity_count(), 2);
        assert_eq!(daemon.peer_ids(), vec![peer_a, peer_b]);
        assert!(daemon_root.join(DAEMON_IDENTITY_FILENAME).is_file());
        daemon.shutdown().await.unwrap();
        assert!(daemon.services.shutdown.is_cancelled());
        assert!(
            daemon.nodes.iter().all(|node| node.shutdown.is_cancelled()),
            "daemon shutdown must cancel every logical identity context"
        );
    }

    #[tokio::test]
    async fn daemon_auto_scale_persists_capacity_backed_startup_roster() {
        let temp = tempfile::tempdir().unwrap();
        let daemon_root = temp.path().join("daemon");
        let config = NodeConfig {
            root_dir: daemon_root.clone(),
            daemon: crate::config::DaemonConfig {
                auto_scale_identities: true,
                min_identities: 2,
                max_identities: 2,
                storage_roots: vec![temp.path().join("volume")],
                ..Default::default()
            },
            network_mode: NetworkMode::Development,
            storage: crate::config::StorageConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let daemon = NodeDaemonBuilder::new(config).build().await.unwrap();
        assert_eq!(daemon.identity_count(), 2);
        let bytes = std::fs::read(
            daemon_root
                .join("daemon-state")
                .join(DAEMON_ROSTER_FILENAME),
        )
        .unwrap();
        let manifest: DaemonRosterManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            manifest
                .identities
                .iter()
                .filter(|entry| entry.active)
                .count(),
            2
        );
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn running_daemon_adds_identity_when_capacity_target_increases() {
        let temp = tempfile::tempdir().unwrap();
        let daemon_root = temp.path().join("daemon");
        let config = NodeConfig {
            root_dir: daemon_root.clone(),
            daemon: crate::config::DaemonConfig {
                auto_scale_identities: true,
                min_identities: 1,
                max_identities: 1,
                storage_roots: vec![temp.path().join("volume")],
                scale_interval_secs: 1,
                ..Default::default()
            },
            network_mode: NetworkMode::Development,
            storage: crate::config::StorageConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut daemon = NodeDaemonBuilder::new(config).build().await.unwrap();
        daemon.config.daemon.min_identities = 2;
        daemon.config.daemon.max_identities = 2;
        let shutdown = daemon.services.shutdown.clone();
        let task = tokio::spawn(async move { daemon.run().await });

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let bytes = std::fs::read(
                    daemon_root
                        .join("daemon-state")
                        .join(DAEMON_ROSTER_FILENAME),
                )
                .unwrap();
                let manifest: DaemonRosterManifest = serde_json::from_slice(&bytes).unwrap();
                if manifest
                    .identities
                    .iter()
                    .filter(|entry| entry.active)
                    .count()
                    == 2
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("runtime scale-up should persist a second active identity");

        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("daemon should stop")
            .expect("daemon task should join")
            .expect("daemon run should succeed");
    }

    #[tokio::test]
    async fn running_daemon_marks_drained_identity_retired_without_deleting_key() {
        let temp = tempfile::tempdir().unwrap();
        let daemon_root = temp.path().join("daemon");
        let config = NodeConfig {
            root_dir: daemon_root.clone(),
            daemon: crate::config::DaemonConfig {
                auto_scale_identities: true,
                min_identities: 2,
                max_identities: 2,
                storage_roots: vec![temp.path().join("volume")],
                scale_interval_secs: 1,
                scale_down_grace_secs: 0,
                ..Default::default()
            },
            network_mode: NetworkMode::Development,
            storage: crate::config::StorageConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut daemon = NodeDaemonBuilder::new(config).build().await.unwrap();
        daemon.config.daemon.min_identities = 1;
        daemon.config.daemon.max_identities = 1;
        let shutdown = daemon.services.shutdown.clone();
        let task = tokio::spawn(async move { daemon.run().await });

        let retired_root = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let bytes = std::fs::read(
                    daemon_root
                        .join("daemon-state")
                        .join(DAEMON_ROSTER_FILENAME),
                )
                .unwrap();
                let manifest: DaemonRosterManifest = serde_json::from_slice(&bytes).unwrap();
                if let Some(entry) = manifest.identities.iter().find(|entry| !entry.active) {
                    break entry.root.clone();
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("runtime scale-down should persist a retired identity");
        assert!(retired_root.join(NODE_IDENTITY_FILENAME).is_file());

        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("daemon should stop")
            .expect("daemon task should join")
            .expect("daemon run should succeed");
    }
}
