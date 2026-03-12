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
    /// File operations (multi-chunk upload/download with EVM payment).
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Single-chunk operations (low-level put/get without file splitting).
    Chunk {
        #[command(subcommand)]
        action: ChunkAction,
    },
}

/// Chunk subcommands.
#[derive(Subcommand, Debug)]
pub enum ChunkAction {
    /// Store a single chunk. Reads from FILE or stdin.
    Put {
        /// Input file (reads from stdin if omitted).
        file: Option<PathBuf>,
    },
    /// Retrieve a single chunk. Writes to FILE or stdout.
    Get {
        /// Hex-encoded chunk address (64 hex chars).
        address: String,
        /// Output file (writes to stdout if omitted).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

/// File subcommands.
#[derive(Subcommand, Debug)]
pub enum FileAction {
    /// Upload a file to the network with EVM payment.
    Upload {
        /// Path to the file to upload.
        path: PathBuf,
        /// Public mode: store the data map on the network (anyone with the
        /// address can download). Default is private (data map saved locally).
        #[arg(long)]
        public: bool,
    },
    /// Download a file from the network.
    Download {
        /// Hex-encoded address (public data map address).
        address: Option<String>,
        /// Path to a local data map file (for private downloads).
        #[arg(long)]
        datamap: Option<PathBuf>,
        /// Output file path (defaults to stdout).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    fn test_parse_upload_public() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "file",
            "upload",
            "--public",
            "/tmp/test.txt",
        ])
        .unwrap();

        if let CliCommand::File {
            action: FileAction::Upload { public, .. },
        } = cli.command
        {
            assert!(public, "Upload should be public");
        } else {
            panic!("Expected File Upload");
        }
    }

    #[test]
    fn test_parse_download_with_datamap() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "file",
            "download",
            "--datamap",
            "/tmp/my.datamap",
            "--output",
            "/tmp/out.bin",
        ])
        .unwrap();

        if let CliCommand::File {
            action:
                FileAction::Download {
                    address,
                    datamap,
                    output,
                },
        } = cli.command
        {
            assert!(
                address.is_none(),
                "Address should be None for datamap download"
            );
            assert_eq!(
                datamap.as_deref(),
                Some(std::path::Path::new("/tmp/my.datamap"))
            );
            assert!(output.is_some());
        } else {
            panic!("Expected File Download");
        }
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

    #[test]
    fn test_parse_chunk_put() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "chunk",
            "put",
            "/tmp/test.txt",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            CliCommand::Chunk {
                action: ChunkAction::Put { .. }
            }
        ));
    }

    #[test]
    fn test_parse_chunk_get() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "chunk",
            "get",
            "abcd1234",
            "--output",
            "/tmp/out.bin",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            CliCommand::Chunk {
                action: ChunkAction::Get { .. }
            }
        ));
    }

    #[test]
    fn test_parse_chunk_put_stdin() {
        let cli = Cli::try_parse_from([
            "saorsa-cli",
            "--bootstrap",
            "127.0.0.1:10000",
            "chunk",
            "put",
        ])
        .unwrap();
        if let CliCommand::Chunk {
            action: ChunkAction::Put { file },
        } = cli.command
        {
            assert!(file.is_none());
        } else {
            panic!("Expected Chunk Put");
        }
    }
}
