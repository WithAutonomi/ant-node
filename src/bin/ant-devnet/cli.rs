//! CLI definition for ant-devnet.

use clap::Parser;
use std::path::PathBuf;

/// Local devnet runner for ant-node.
#[derive(Parser, Debug)]
#[command(name = "ant-devnet")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Node count to spawn.
    #[arg(long)]
    pub nodes: Option<usize>,

    /// Bootstrap node count (first N nodes).
    #[arg(long)]
    pub bootstrap_count: Option<usize>,

    /// Base port for node allocation (0 for auto).
    #[arg(long)]
    pub base_port: Option<u16>,

    /// Data directory for node state.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Keep node data directories on shutdown instead of removing them.
    #[arg(long)]
    pub no_cleanup: bool,

    /// Spawn delay in milliseconds.
    #[arg(long)]
    pub spawn_delay_ms: Option<u64>,

    /// Stabilization timeout in seconds.
    #[arg(long)]
    pub stabilization_timeout_secs: Option<u64>,

    /// Preset: minimal, small, default.
    #[arg(long)]
    pub preset: Option<String>,

    /// Path to write a devnet manifest JSON.
    #[arg(long)]
    pub manifest: Option<PathBuf>,

    /// Enable logging output.
    /// When omitted, the tracing subscriber is not installed and no log
    /// records are emitted, even if the binary was built with the
    /// `logging` feature. `--log-level` is ignored unless this flag is set.
    #[cfg(feature = "logging")]
    #[arg(long, env = "ANT_ENABLE_LOGGING")]
    pub enable_logging: bool,

    /// Log level for devnet process.
    #[cfg(feature = "logging")]
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Start a local Anvil blockchain for EVM payment verification.
    /// Starts Anvil, deploys contracts, and configures all nodes to verify
    /// payments against the local chain.
    #[arg(long)]
    pub enable_evm: bool,
}
