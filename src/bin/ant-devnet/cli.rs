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
    /// payments against the local chain. With `--host`, Anvil binds the same
    /// LAN IP (unless `ANVIL_IP_ADDR` overrides it) so the manifest's
    /// `rpc_url` is reachable from other devices — external signers on the
    /// LAN can pay, not just download.
    #[arg(long)]
    pub enable_evm: bool,

    /// Advertise this IPv4 to peers/clients and bind 0.0.0.0, so the devnet is
    /// reachable from other devices on the LAN. When omitted, nodes bind
    /// loopback (127.0.0.1) as before (single-machine only). Also becomes
    /// Anvil's bind/publish address under `--enable-evm` (see there).
    #[arg(long)]
    pub host: Option<std::net::Ipv4Addr>,

    /// EVM network for node payment verification. `arbitrum-sepolia` makes
    /// nodes verify against the real deployed Arbitrum Sepolia contracts —
    /// no local Anvil and no embedded wallet key (bring your own funded
    /// wallet via an external signer). Omit for the local-Anvil devnet
    /// (`--enable-evm`). Mutually exclusive with `--enable-evm`.
    #[arg(long, conflicts_with = "enable_evm")]
    pub evm_network: Option<String>,

    /// Serve the manifest over a read-only HTTP API on this port (binds
    /// 0.0.0.0). Any LAN device can then GET
    /// `http://<host>:<port>/api/devnet-manifest.json` (and `/api/info`) —
    /// no file copying. Open CORS. Suggested: 8088. Requires `--host` (the API
    /// advertises a LAN URL, so a loopback-only devnet would be misleading).
    #[arg(long, requires = "host", value_parser = clap::value_parser!(u16).range(1..))]
    pub serve_port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Backward-compatibility contract: with none of the LAN flags, the new
    /// options parse to `None`, so behavior is identical to before.
    #[test]
    fn lan_flags_default_off() {
        let cli = Cli::parse_from(["ant-devnet", "--preset", "small"]);
        assert!(cli.host.is_none());
        assert!(cli.evm_network.is_none());
        assert!(cli.serve_port.is_none());
    }

    /// The LAN flags parse into the expected typed values.
    #[test]
    fn lan_flags_parse() {
        let cli = Cli::parse_from([
            "ant-devnet",
            "--host",
            "192.168.1.100",
            "--evm-network",
            "arbitrum-sepolia",
            "--serve-port",
            "8088",
        ]);
        assert_eq!(cli.host, Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(cli.evm_network.as_deref(), Some("arbitrum-sepolia"));
        assert_eq!(cli.serve_port, Some(8088));
    }

    /// A non-IPv4 `--host` is rejected by clap's value parser.
    #[test]
    fn host_rejects_non_ipv4() {
        assert!(Cli::try_parse_from(["ant-devnet", "--host", "not-an-ip"]).is_err());
    }

    /// `--serve-port` requires `--host` (it advertises a LAN URL).
    #[test]
    fn serve_port_requires_host() {
        assert!(Cli::try_parse_from(["ant-devnet", "--serve-port", "8088"]).is_err());
    }

    /// `--serve-port 0` is rejected (an ephemeral port would be advertised as `:0`).
    #[test]
    fn serve_port_rejects_zero() {
        assert!(
            Cli::try_parse_from(["ant-devnet", "--host", "192.168.1.5", "--serve-port", "0"])
                .is_err()
        );
    }
}
