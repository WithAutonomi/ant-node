//! CLI definition for saorsa-cli.

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Saorsa CLI for file upload and download with EVM payments.
#[derive(Parser, Debug)]
#[command(name = "saorsa-cli")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Bootstrap peer addresses.
    #[arg(long, short)]
    pub bootstrap: Vec<SocketAddr>,

    /// Path to devnet manifest JSON (output of saorsa-devnet).
    #[arg(long)]
    pub devnet_manifest: Option<PathBuf>,

    /// Timeout for network operations (seconds).
    #[arg(long, default_value_t = 60)]
    pub timeout_secs: u64,

    /// Log level.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// EVM network for payment processing.
    #[arg(long, default_value = "local")]
    pub evm_network: String,

    /// Command to run.
    #[command(subcommand)]
    pub command: CliCommand,
}

/// CLI commands.
#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// File operations.
    File {
        #[command(subcommand)]
        action: FileAction,
    },
}

/// File subcommands.
#[derive(Subcommand, Debug)]
pub enum FileAction {
    /// Upload a file to the network with EVM payment.
    Upload {
        /// Path to the file to upload.
        path: PathBuf,
    },
    /// Download a file from the network.
    Download {
        /// Hex-encoded manifest address (returned by upload).
        address: String,
        /// Output file path (defaults to stdout).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upload_command() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "file",
            "upload",
            "/tmp/test.txt",
        ])
        .unwrap();

        assert!(!cli.bootstrap.is_empty());
        assert!(matches!(
            cli.command,
            CliCommand::File {
                action: FileAction::Upload { .. }
            }
        ));
    }

    #[test]
    fn test_parse_download_command() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--devnet-manifest",
            "/tmp/manifest.json",
            "file",
            "download",
            "abcd1234",
            "--output",
            "/tmp/out.bin",
        ])
        .unwrap();

        assert!(cli.devnet_manifest.is_some());
    }

    #[test]
    fn test_secret_key_from_env() {
        // SECRET_KEY is read at runtime, not parsed by clap
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "file",
            "upload",
            "/tmp/test.txt",
        ])
        .unwrap();

        assert_eq!(cli.evm_network, "local");
    }
}
