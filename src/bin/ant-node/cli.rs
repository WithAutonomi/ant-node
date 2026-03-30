//! Command-line interface definition.

use ant_node::config::{
    BootstrapCacheConfig, BootstrapPeersConfig, BootstrapSource, EvmNetworkConfig, IpVersion,
    NetworkMode, NodeConfig, PaymentConfig, UpgradeChannel,
};
use clap::{Parser, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Pure quantum-proof network node for the Autonomi decentralized network.
#[derive(Parser, Debug)]
#[command(name = "ant-node")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Root directory for node data.
    #[arg(long, env = "ANT_ROOT_DIR")]
    pub root_dir: Option<PathBuf>,

    /// Listening port (0 for auto-select).
    #[arg(long, short, default_value = "0", env = "ANT_PORT")]
    pub port: u16,

    /// IP version to use.
    #[arg(long, value_enum, default_value = "dual", env = "ANT_IP_VERSION")]
    pub ip_version: CliIpVersion,

    /// Bootstrap peer addresses.
    #[arg(long, short, env = "ANT_BOOTSTRAP")]
    pub bootstrap: Vec<SocketAddr>,

    /// Release channel for upgrades.
    #[arg(
        long,
        value_enum,
        default_value = "stable",
        env = "ANT_UPGRADE_CHANNEL"
    )]
    pub upgrade_channel: CliUpgradeChannel,

    /// Cache capacity for verified `XorName` values.
    #[arg(long, default_value = "100000", env = "ANT_CACHE_CAPACITY")]
    pub cache_capacity: usize,

    /// EVM wallet address for receiving payments (e.g., "0x...").
    #[arg(long, env = "ANT_REWARDS_ADDRESS")]
    pub rewards_address: Option<String>,

    /// EVM network for payment processing.
    #[arg(
        long,
        value_enum,
        default_value = "arbitrum-one",
        env = "ANT_EVM_NETWORK"
    )]
    pub evm_network: CliEvmNetwork,

    /// Metrics port for Prometheus scraping (0 to disable).
    #[arg(long, default_value = "9100", env = "ANT_METRICS_PORT")]
    pub metrics_port: u16,

    /// Log level.
    #[arg(long, value_enum, default_value = "info", env = "RUST_LOG")]
    pub log_level: CliLogLevel,

    /// Log output format.
    #[arg(long, value_enum, default_value = "text", env = "ANT_LOG_FORMAT")]
    pub log_format: CliLogFormat,

    /// Directory for log file output.
    /// When set, logs are written to files in this directory instead of stdout.
    /// Files rotate daily and are named ant-node.YYYY-MM-DD.log.
    #[arg(long, env = "ANT_LOG_DIR")]
    pub log_dir: Option<PathBuf>,

    /// Maximum number of rotated log files to retain (only used with --log-dir).
    /// Oldest files are deleted when this limit is reached. Rotation is daily.
    #[arg(long, default_value = "7", env = "ANT_LOG_MAX_FILES")]
    pub log_max_files: usize,

    /// Network mode (production, testnet, or development).
    /// Testnet mode uses relaxed IP diversity limits suitable for
    /// single-provider deployments with many nodes per IP.
    #[arg(
        long,
        value_enum,
        default_value = "production",
        env = "ANT_NETWORK_MODE"
    )]
    pub network_mode: CliNetworkMode,

    /// Path to configuration file.
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// Exit cleanly on upgrade instead of spawning a new process.
    /// Use when running under a service manager (systemd, launchd, Windows Service)
    /// that will restart the process automatically.
    #[arg(long)]
    pub stop_on_upgrade: bool,

    /// Disable persistent bootstrap cache.
    #[arg(long)]
    pub disable_bootstrap_cache: bool,

    /// Directory for bootstrap cache files.
    #[arg(long, env = "ANT_BOOTSTRAP_CACHE_DIR")]
    pub bootstrap_cache_dir: Option<PathBuf>,

    /// Maximum peers to cache in the bootstrap cache.
    #[arg(long, default_value = "10000", env = "ANT_BOOTSTRAP_CACHE_CAPACITY")]
    pub bootstrap_cache_capacity: usize,
}

/// IP version CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliIpVersion {
    /// IPv4 only.
    Ipv4,
    /// IPv6 only.
    Ipv6,
    /// Dual-stack (both IPv4 and IPv6).
    Dual,
}

/// Upgrade channel CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUpgradeChannel {
    /// Stable releases only.
    Stable,
    /// Beta releases.
    Beta,
}

/// EVM network CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliEvmNetwork {
    /// Arbitrum One mainnet.
    #[default]
    #[value(name = "arbitrum-one")]
    ArbitrumOne,
    /// Arbitrum Sepolia testnet.
    #[value(name = "arbitrum-sepolia")]
    ArbitrumSepolia,
}

/// Log level CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliLogLevel {
    /// Error messages only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Informational messages (default).
    #[default]
    Info,
    /// Debug messages.
    Debug,
    /// Trace messages (verbose).
    Trace,
}

/// Log format CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliLogFormat {
    /// Plain text output (default).
    #[default]
    Text,
    /// Structured JSON output.
    Json,
}

/// Network mode CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliNetworkMode {
    /// Production mode with full anti-Sybil protection.
    #[default]
    Production,
    /// Testnet mode with relaxed diversity requirements.
    /// Allows many nodes per IP/ASN for single-provider deployments.
    Testnet,
    /// Development mode with minimal restrictions.
    /// Only use for local testing.
    Development,
}

impl Cli {
    /// Convert CLI arguments into a `NodeConfig` and the source of bootstrap peers.
    ///
    /// # Bootstrap peer precedence (highest to lowest)
    ///
    /// 1. `--bootstrap` CLI argument (or `ANT_BOOTSTRAP` env var)
    /// 2. `bootstrap` field in a `--config` file
    /// 3. Auto-discovered `bootstrap_peers.toml` from well-known paths
    /// 4. Empty list
    ///
    /// # Errors
    ///
    /// Returns an error if a config file is specified but cannot be loaded.
    pub fn into_config(self) -> color_eyre::Result<(NodeConfig, BootstrapSource)> {
        // Start with default config or load from file
        let has_config_file = self.config.is_some();
        let mut config = if let Some(ref path) = self.config {
            NodeConfig::from_file(path)?
        } else {
            NodeConfig::default()
        };

        // Track whether CLI provided bootstrap peers.
        let cli_bootstrap_provided = !self.bootstrap.is_empty();

        // Override with CLI arguments
        if let Some(root_dir) = self.root_dir {
            config.root_dir = root_dir;
        }

        config.port = self.port;
        config.ip_version = self.ip_version.into();
        config.log_level = self.log_level.into();
        config.network_mode = self.network_mode.into();

        // Apply CLI bootstrap peers if provided; otherwise keep config file value.
        if cli_bootstrap_provided {
            config.bootstrap = self.bootstrap;
        }

        // Upgrade config
        config.upgrade.channel = self.upgrade_channel.into();
        config.upgrade.stop_on_upgrade = self.stop_on_upgrade;

        // Payment config (payment verification is always on)
        config.payment = PaymentConfig {
            cache_capacity: self.cache_capacity,
            rewards_address: self.rewards_address,
            evm_network: self.evm_network.into(),
            metrics_port: self.metrics_port,
        };

        // Bootstrap cache config
        config.bootstrap_cache = BootstrapCacheConfig {
            enabled: !self.disable_bootstrap_cache,
            cache_dir: self.bootstrap_cache_dir,
            max_contacts: self.bootstrap_cache_capacity,
            ..config.bootstrap_cache
        };

        // Determine bootstrap source and apply auto-discovery if needed.
        let bootstrap_source = if cli_bootstrap_provided {
            BootstrapSource::Cli
        } else if !config.bootstrap.is_empty() && has_config_file {
            BootstrapSource::ConfigFile
        } else if config.bootstrap.is_empty() {
            // No peers from CLI or config file — try auto-discovery.
            if let Some((peers_config, path)) = BootstrapPeersConfig::discover() {
                config.bootstrap = peers_config.peers;
                BootstrapSource::AutoDiscovered(path)
            } else {
                BootstrapSource::None
            }
        } else {
            // Config had peers from default (e.g., testnet preset) but no --config file.
            BootstrapSource::None
        };

        Ok((config, bootstrap_source))
    }
}

impl From<CliIpVersion> for IpVersion {
    fn from(v: CliIpVersion) -> Self {
        match v {
            CliIpVersion::Ipv4 => Self::Ipv4,
            CliIpVersion::Ipv6 => Self::Ipv6,
            CliIpVersion::Dual => Self::Dual,
        }
    }
}

impl From<CliUpgradeChannel> for UpgradeChannel {
    fn from(c: CliUpgradeChannel) -> Self {
        match c {
            CliUpgradeChannel::Stable => Self::Stable,
            CliUpgradeChannel::Beta => Self::Beta,
        }
    }
}

impl From<CliEvmNetwork> for EvmNetworkConfig {
    fn from(n: CliEvmNetwork) -> Self {
        match n {
            CliEvmNetwork::ArbitrumOne => Self::ArbitrumOne,
            CliEvmNetwork::ArbitrumSepolia => Self::ArbitrumSepolia,
        }
    }
}

impl From<CliLogLevel> for String {
    fn from(level: CliLogLevel) -> Self {
        match level {
            CliLogLevel::Error => "error".to_string(),
            CliLogLevel::Warn => "warn".to_string(),
            CliLogLevel::Info => "info".to_string(),
            CliLogLevel::Debug => "debug".to_string(),
            CliLogLevel::Trace => "trace".to_string(),
        }
    }
}

impl From<CliNetworkMode> for NetworkMode {
    fn from(mode: CliNetworkMode) -> Self {
        match mode {
            CliNetworkMode::Production => Self::Production,
            CliNetworkMode::Testnet => Self::Testnet,
            CliNetworkMode::Development => Self::Development,
        }
    }
}
