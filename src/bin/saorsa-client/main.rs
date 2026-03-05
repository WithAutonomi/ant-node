//! saorsa-client CLI entry point.

mod cli;

use bytes::Bytes;
use clap::Parser;
use cli::{Cli, ClientCommand};
use evmlib::wallet::Wallet;
use evmlib::Network as EvmNetwork;
use saorsa_core::P2PNode;
use saorsa_node::ant_protocol::MAX_WIRE_MESSAGE_SIZE;
use saorsa_node::client::{QuantumClient, QuantumConfig, XorName};
use saorsa_node::devnet::DevnetManifest;
use saorsa_node::error::Error;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Length of an `XorName` address in bytes.
const XORNAME_BYTE_LEN: usize = 32;

/// Default replica count for client chunk operations.
const DEFAULT_CLIENT_REPLICA_COUNT: u8 = 1;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();

    info!("saorsa-client v{}", env!("CARGO_PKG_VERSION"));

    let (bootstrap, manifest) = resolve_bootstrap(&cli)?;
    let node = create_client_node(bootstrap).await?;
    let mut client = QuantumClient::new(QuantumConfig {
        timeout_secs: cli.timeout_secs,
        replica_count: DEFAULT_CLIENT_REPLICA_COUNT,
        encrypt_data: false,
    })
    .with_node(node);

    // Resolve private key: CLI flag > SECRET_KEY env var
    let private_key = cli
        .private_key
        .clone()
        .or_else(|| std::env::var("SECRET_KEY").ok());

    if let Some(ref key) = private_key {
        let network = resolve_evm_network(&cli.evm_network, manifest.as_ref())?;
        let wallet = Wallet::new_from_private_key(network, key)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create wallet: {e}"))?;
        info!("Wallet configured for payments on {}", cli.evm_network);
        client = client.with_wallet(wallet);
    }

    match cli.command {
        ClientCommand::Put { file } => {
            let content = read_input(file)?;
            let address = client.put_chunk(Bytes::from(content)).await?;
            println!("{}", hex::encode(address));
        }
        ClientCommand::Get { address, out } => {
            let addr = parse_address(&address)?;
            let result = client.get_chunk(&addr).await?;
            match result {
                Some(chunk) => write_output(&chunk.content, out)?,
                None => {
                    return Err(color_eyre::eyre::eyre!(
                        "Chunk not found for address {address}"
                    ));
                }
            }
        }
    }

    Ok(())
}

fn resolve_evm_network(
    evm_network: &str,
    manifest: Option<&DevnetManifest>,
) -> color_eyre::Result<EvmNetwork> {
    match evm_network {
        "arbitrum-one" => Ok(EvmNetwork::ArbitrumOne),
        "arbitrum-sepolia" => Ok(EvmNetwork::ArbitrumSepoliaTest),
        "local" => {
            // Build Custom network from manifest EVM info
            if let Some(m) = manifest {
                if let Some(ref evm) = m.evm {
                    let rpc_url: reqwest::Url = evm
                        .rpc_url
                        .parse()
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid RPC URL: {e}"))?;
                    let token_addr: evmlib::common::Address = evm
                        .payment_token_address
                        .parse()
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid token address: {e}"))?;
                    let payments_addr: evmlib::common::Address = evm
                        .data_payments_address
                        .parse()
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid payments address: {e}"))?;
                    return Ok(EvmNetwork::Custom(evmlib::CustomNetwork {
                        rpc_url_http: rpc_url,
                        payment_token_address: token_addr,
                        data_payments_address: payments_addr,
                        merkle_payments_address: None,
                    }));
                }
            }
            Err(color_eyre::eyre::eyre!(
                "EVM network 'local' requires --devnet-manifest with EVM info"
            ))
        }
        other => Err(color_eyre::eyre::eyre!(
            "Unsupported EVM network: {other}. Use 'arbitrum-one', 'arbitrum-sepolia', or 'local'."
        )),
    }
}

fn resolve_bootstrap(
    cli: &Cli,
) -> color_eyre::Result<(Vec<std::net::SocketAddr>, Option<DevnetManifest>)> {
    if !cli.bootstrap.is_empty() {
        return Ok((cli.bootstrap.clone(), None));
    }

    if let Some(ref manifest_path) = cli.devnet_manifest {
        let data = std::fs::read_to_string(manifest_path)?;
        let manifest: DevnetManifest = serde_json::from_str(&data)?;
        let bootstrap = manifest.bootstrap.clone();
        return Ok((bootstrap, Some(manifest)));
    }

    Err(color_eyre::eyre::eyre!(
        "No bootstrap peers provided. Use --bootstrap or --devnet-manifest."
    ))
}

async fn create_client_node(bootstrap: Vec<std::net::SocketAddr>) -> Result<Arc<P2PNode>, Error> {
    let mut core_config = saorsa_core::NodeConfig::new()
        .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;
    core_config.listen_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e| Error::Config(format!("Invalid listen addr: {e}")))?;
    core_config.listen_addrs = vec![core_config.listen_addr];
    core_config.enable_ipv6 = false;
    core_config.bootstrap_peers = bootstrap;
    core_config.max_message_size = Some(MAX_WIRE_MESSAGE_SIZE);

    let node = P2PNode::new(core_config)
        .await
        .map_err(|e| Error::Network(format!("Failed to create P2P node: {e}")))?;
    node.start()
        .await
        .map_err(|e| Error::Network(format!("Failed to start P2P node: {e}")))?;

    Ok(Arc::new(node))
}

fn parse_address(address: &str) -> color_eyre::Result<XorName> {
    let bytes = hex::decode(address)?;
    if bytes.len() != XORNAME_BYTE_LEN {
        return Err(color_eyre::eyre::eyre!(
            "Invalid address length: expected {XORNAME_BYTE_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; XORNAME_BYTE_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_input(file: Option<PathBuf>) -> color_eyre::Result<Vec<u8>> {
    if let Some(path) = file {
        return Ok(std::fs::read(path)?);
    }

    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_output(content: &Bytes, out: Option<PathBuf>) -> color_eyre::Result<()> {
    if let Some(path) = out {
        std::fs::write(path, content)?;
        return Ok(());
    }

    let mut stdout = std::io::stdout();
    stdout.write_all(content)?;
    Ok(())
}
