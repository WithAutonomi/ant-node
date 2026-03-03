//! CLI definition for saorsa-client.

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Client CLI for chunk operations.
#[derive(Parser, Debug)]
#[command(name = "saorsa-client")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Bootstrap peer addresses.
    #[arg(long, short)]
    pub bootstrap: Vec<SocketAddr>,

    /// Path to devnet manifest JSON (output of saorsa-devnet).
    #[arg(long)]
    pub devnet_manifest: Option<PathBuf>,

    /// Timeout for network operations (seconds).
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,

    /// Log level for client process.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// EVM wallet private key (hex-encoded) for paid chunk storage.
    #[arg(long)]
    pub private_key: Option<String>,

    /// EVM network for payment processing.
    #[arg(long, default_value = "arbitrum-one")]
    pub evm_network: String,

    /// Command to run.
    #[command(subcommand)]
    pub command: ClientCommand,
}

/// Client commands.
#[derive(Subcommand, Debug)]
pub enum ClientCommand {
    /// Put a chunk. Reads from --file or stdin.
    Put {
        /// Input file (defaults to stdin if omitted).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Get a chunk. Writes to --out or stdout.
    Get {
        /// Hex-encoded chunk address (64 hex chars).
        address: String,
        /// Output file (defaults to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_private_key_and_evm_network() {
        let cli = Cli::try_parse_from([
            "saorsa-client",
            "--bootstrap",
            "127.0.0.1:10000",
            "--private-key",
            "0xdeadbeef",
            "--evm-network",
            "arbitrum-sepolia",
            "put",
        ])
        .unwrap();

        assert_eq!(cli.private_key.as_deref(), Some("0xdeadbeef"));
        assert_eq!(cli.evm_network, "arbitrum-sepolia");
    }

    #[test]
    fn test_default_evm_network_is_arbitrum_one() {
        let cli = Cli::try_parse_from(["saorsa-client", "--bootstrap", "127.0.0.1:10000", "put"])
            .unwrap();

        assert!(cli.private_key.is_none());
        assert_eq!(cli.evm_network, "arbitrum-one");
    }

    #[test]
    fn test_backward_compat_without_wallet_flags() {
        let cli = Cli::try_parse_from([
            "saorsa-client",
            "--bootstrap",
            "127.0.0.1:10000",
            "--timeout-secs",
            "60",
            "get",
            "abcd1234",
            "--out",
            "/tmp/output.bin",
        ])
        .unwrap();

        assert!(cli.private_key.is_none());
        assert_eq!(cli.evm_network, "arbitrum-one");
        assert_eq!(cli.timeout_secs, 60);
    }
}
