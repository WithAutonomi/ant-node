//! saorsa-cli entry point — file upload/download with EVM payments.

mod cli;

use bytes::Bytes;
use clap::Parser;
use cli::{ChunkAction, Cli, CliCommand, FileAction};
use evmlib::wallet::Wallet;
use evmlib::Network as EvmNetwork;
use saorsa_core::P2PNode;
use saorsa_node::ant_protocol::{MAX_CHUNK_SIZE, MAX_WIRE_MESSAGE_SIZE};
use saorsa_node::client::self_encrypt::{
    deserialize_data_map, download_and_decrypt_file, encrypt_and_upload_file,
    fetch_data_map_public, serialize_data_map, store_data_map_public,
};
use saorsa_node::client::{QuantumClient, QuantumConfig, XorName};
use saorsa_node::devnet::DevnetManifest;
use saorsa_node::error::Error;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Length of an `XorName` address in bytes.
const XORNAME_BYTE_LEN: usize = 32;

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

    info!("saorsa-cli v{}", env!("CARGO_PKG_VERSION"));

    // Resolve private key from SECRET_KEY env var (check early, before network bootstrap)
    let private_key = std::env::var("SECRET_KEY").ok();

    // Fail fast if storage operations require SECRET_KEY but it's not set
    let needs_wallet = matches!(
        cli.command,
        CliCommand::File {
            action: FileAction::Upload { .. }
        } | CliCommand::Chunk {
            action: ChunkAction::Put { .. }
        }
    );
    if needs_wallet && private_key.is_none() {
        return Err(color_eyre::eyre::eyre!(
            "SECRET_KEY environment variable required for storage operations (payment)"
        ));
    }

    let (bootstrap, manifest) = resolve_bootstrap(&cli)?;
    let node = create_client_node(bootstrap, cli.allow_loopback).await?;

    // Build client with timeout
    let mut client = QuantumClient::new(QuantumConfig {
        timeout_secs: cli.timeout_secs,
        replica_count: 1,
        encrypt_data: false,
    })
    .with_node(node);

    if needs_wallet {
        if let Some(ref key) = private_key {
            let network = resolve_evm_network(&cli.evm_network, manifest.as_ref())?;
            let wallet = Wallet::new_from_private_key(network, key)
                .map_err(|e| color_eyre::eyre::eyre!("Failed to create wallet: {e}"))?;
            info!("Wallet configured for EVM payments");
            client = client.with_wallet(wallet);
        }
    }

    match cli.command {
        CliCommand::File { action } => match action {
            FileAction::Upload { path, public } => {
                handle_upload(&client, &path, public).await?;
            }
            FileAction::Download {
                address,
                datamap,
                output,
            } => {
                handle_download(
                    &client,
                    address.as_deref(),
                    datamap.as_deref(),
                    output.as_deref(),
                )
                .await?;
            }
        },
        CliCommand::Chunk { action } => match action {
            ChunkAction::Put { file } => {
                handle_chunk_put(&client, file).await?;
            }
            ChunkAction::Get { address, output } => {
                handle_chunk_get(&client, &address, output).await?;
            }
        },
    }

    Ok(())
}

async fn handle_upload(
    client: &QuantumClient,
    path: &Path,
    public: bool,
) -> color_eyre::Result<()> {
    let file_size = std::fs::metadata(path)?.len();
    info!("Uploading file: {} ({file_size} bytes)", path.display());

    // Encrypt and upload all chunks using streaming self-encryption
    let (data_map, all_tx_hashes) = encrypt_and_upload_file(path, client).await?;
    let chunk_count = data_map.chunk_identifiers.len();
    let total_tx_count = all_tx_hashes.len();

    if public {
        // Public mode: store the DataMap on the network too
        let (dm_address, dm_tx_hashes) = store_data_map_public(&data_map, client).await?;
        let address_hex = hex::encode(dm_address);
        let combined_tx = total_tx_count + dm_tx_hashes.len();

        println!("FILE_ADDRESS={address_hex}");
        println!("MODE=public");
        println!("CHUNKS={chunk_count}");
        println!("TOTAL_SIZE={file_size}");
        println!("PAYMENTS={combined_tx}");

        let mut all = all_tx_hashes;
        all.extend(dm_tx_hashes);
        println!("TX_HASHES={}", all.join(","));

        info!("Upload complete (public): address={address_hex}, chunks={chunk_count}");
    } else {
        // Private mode: save DataMap locally, never upload it
        let data_map_bytes = serialize_data_map(&data_map)?;
        let datamap_path = path.with_extension("datamap");
        std::fs::write(&datamap_path, &data_map_bytes)?;

        println!("DATAMAP_FILE={}", datamap_path.display());
        println!("MODE=private");
        println!("CHUNKS={chunk_count}");
        println!("TOTAL_SIZE={file_size}");
        println!("PAYMENTS={total_tx_count}");
        println!("TX_HASHES={}", all_tx_hashes.join(","));

        info!(
            "Upload complete (private): datamap saved to {}, chunks={chunk_count}",
            datamap_path.display()
        );
    }

    Ok(())
}

async fn handle_download(
    client: &QuantumClient,
    address: Option<&str>,
    datamap_path: Option<&Path>,
    output: Option<&Path>,
) -> color_eyre::Result<()> {
    // Resolve the DataMap: either from network (public) or local file (private)
    let data_map = if let Some(dm_path) = datamap_path {
        info!("Loading DataMap from local file: {}", dm_path.display());
        let dm_bytes = std::fs::read(dm_path)?;
        deserialize_data_map(&dm_bytes)?
    } else if let Some(addr_str) = address {
        let addr = parse_address(addr_str)?;
        info!("Fetching DataMap from network: {addr_str}");
        fetch_data_map_public(&addr, client).await?
    } else {
        return Err(color_eyre::eyre::eyre!(
            "Either an address or --datamap must be provided for download"
        ));
    };

    let chunk_count = data_map.chunk_identifiers.len();
    info!("DataMap loaded: {chunk_count} chunk(s)");

    // Determine output path
    let output_path = output.map_or_else(
        || PathBuf::from("downloaded_file"),
        std::borrow::ToOwned::to_owned,
    );

    download_and_decrypt_file(&data_map, &output_path, client).await?;

    let file_size = std::fs::metadata(&output_path)?.len();
    println!("Downloaded {file_size} bytes to {}", output_path.display());

    Ok(())
}

async fn handle_chunk_put(client: &QuantumClient, file: Option<PathBuf>) -> color_eyre::Result<()> {
    let content = read_input(file.as_deref())?;
    info!("Storing single chunk ({} bytes)", content.len());

    let (address, tx_hashes) = client.put_chunk_with_payment(Bytes::from(content)).await?;
    let hex_addr = hex::encode(address);
    info!("Chunk stored at {hex_addr}");

    println!("{hex_addr}");
    let tx_strs: Vec<String> = tx_hashes.iter().map(|tx| format!("{tx:?}")).collect();
    println!("TX_HASHES={}", tx_strs.join(","));

    Ok(())
}

async fn handle_chunk_get(
    client: &QuantumClient,
    address: &str,
    output: Option<PathBuf>,
) -> color_eyre::Result<()> {
    let addr = parse_address(address)?;
    info!("Retrieving chunk {address}");

    let result = client.get_chunk(&addr).await?;
    match result {
        Some(chunk) => {
            if let Some(path) = output {
                std::fs::write(&path, &chunk.content)?;
                info!("Chunk saved to {}", path.display());
            } else {
                std::io::stdout().write_all(&chunk.content)?;
            }
        }
        None => {
            return Err(color_eyre::eyre::eyre!(
                "Chunk not found for address {address}"
            ));
        }
    }

    Ok(())
}

fn read_input(file: Option<&Path>) -> color_eyre::Result<Vec<u8>> {
    if let Some(path) = file {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_CHUNK_SIZE as u64 {
            return Err(color_eyre::eyre::eyre!(
                "Input file exceeds MAX_CHUNK_SIZE ({MAX_CHUNK_SIZE} bytes): {} bytes",
                meta.len()
            ));
        }
        return Ok(std::fs::read(path)?);
    }
    let limit = (MAX_CHUNK_SIZE + 1) as u64;
    let mut buf = Vec::new();
    std::io::stdin().take(limit).read_to_end(&mut buf)?;
    if buf.len() > MAX_CHUNK_SIZE {
        return Err(color_eyre::eyre::eyre!(
            "Stdin input exceeds MAX_CHUNK_SIZE ({MAX_CHUNK_SIZE} bytes)"
        ));
    }
    Ok(buf)
}

fn resolve_evm_network(
    evm_network: &str,
    manifest: Option<&DevnetManifest>,
) -> color_eyre::Result<EvmNetwork> {
    match evm_network {
        "arbitrum-one" => Ok(EvmNetwork::ArbitrumOne),
        "arbitrum-sepolia" => Ok(EvmNetwork::ArbitrumSepoliaTest),
        "local" => {
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
) -> color_eyre::Result<(Vec<saorsa_core::MultiAddr>, Option<DevnetManifest>)> {
    if !cli.bootstrap.is_empty() {
        let addrs = cli
            .bootstrap
            .iter()
            .map(|addr| saorsa_core::MultiAddr::quic(*addr))
            .collect();
        return Ok((addrs, None));
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

async fn create_client_node(
    bootstrap: Vec<saorsa_core::MultiAddr>,
    allow_loopback: bool,
) -> Result<Arc<P2PNode>, Error> {
    let mut core_config = saorsa_core::NodeConfig::builder()
        .local(allow_loopback)
        .max_message_size(MAX_WIRE_MESSAGE_SIZE)
        .mode(saorsa_core::NodeMode::Client)
        .build()
        .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;
    core_config.bootstrap_peers = bootstrap;

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
