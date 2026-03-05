//! saorsa-cli entry point — file upload/download with EVM payments.

mod cli;

use bytes::Bytes;
use clap::Parser;
use cli::{ChunkAction, Cli, CliCommand, FileAction};
use evmlib::wallet::Wallet;
use evmlib::Network as EvmNetwork;
use saorsa_core::P2PNode;
use saorsa_node::ant_protocol::MAX_WIRE_MESSAGE_SIZE;
use saorsa_node::client::{
    create_manifest, deserialize_manifest, reassemble_file, serialize_manifest, split_file,
    QuantumClient, QuantumConfig, XorName,
};
use saorsa_node::devnet::DevnetManifest;
use saorsa_node::error::Error;
use std::io::Read as _;
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
    let node = create_client_node(bootstrap).await?;

    // Build client with timeout
    let mut client = QuantumClient::new(QuantumConfig {
        timeout_secs: cli.timeout_secs,
        replica_count: 1,
        encrypt_data: false,
    })
    .with_node(node);

    if let Some(ref key) = private_key {
        let network = resolve_evm_network(&cli.evm_network, manifest.as_ref())?;
        let wallet = Wallet::new_from_private_key(network, key)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create wallet: {e}"))?;
        info!("Wallet configured for EVM payments");
        client = client.with_wallet(wallet);
    }

    match cli.command {
        CliCommand::File { action } => match action {
            FileAction::Upload { path } => {
                handle_upload(&client, &path).await?;
            }
            FileAction::Download { address, output } => {
                handle_download(&client, &address, output.as_deref()).await?;
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

async fn handle_upload(client: &QuantumClient, path: &Path) -> color_eyre::Result<()> {
    let filename = path.file_name().and_then(|n| n.to_str()).map(String::from);
    let file_content = std::fs::read(path)?;
    let file_size = file_content.len();

    info!("Uploading file: {} ({file_size} bytes)", path.display());

    // Split file into chunks
    let chunks = split_file(&file_content);
    let chunk_count = chunks.len();
    info!("File split into {chunk_count} chunk(s)");

    // Upload each chunk with payment, collecting tx hashes
    let mut chunk_addresses: Vec<[u8; 32]> = Vec::with_capacity(chunk_count);
    let mut all_tx_hashes: Vec<String> = Vec::new();

    for (i, chunk) in chunks.into_iter().enumerate() {
        let chunk_num = i + 1;
        info!(
            "Uploading chunk {chunk_num}/{chunk_count} ({} bytes)",
            chunk.len()
        );
        let (address, tx_hashes) = client.put_chunk_with_payment(chunk).await?;
        info!(
            "Chunk {chunk_num}/{chunk_count} stored at {}",
            hex::encode(address)
        );
        chunk_addresses.push(address);
        for tx in &tx_hashes {
            all_tx_hashes.push(format!("{tx:?}"));
        }
    }

    // Create and upload manifest (also paid)
    let total_size =
        u64::try_from(file_size).map_err(|e| color_eyre::eyre::eyre!("File too large: {e}"))?;
    let manifest = create_manifest(filename, total_size, chunk_addresses);
    let manifest_bytes = serialize_manifest(&manifest)?;
    let (manifest_address, manifest_tx_hashes) =
        client.put_chunk_with_payment(manifest_bytes).await?;
    for tx in &manifest_tx_hashes {
        all_tx_hashes.push(format!("{tx:?}"));
    }

    let manifest_hex = hex::encode(manifest_address);
    let total_tx_count = all_tx_hashes.len();
    let tx_hashes_str = all_tx_hashes.join(",");

    // Print results to stdout
    println!("FILE_ADDRESS={manifest_hex}");
    println!("CHUNKS={chunk_count}");
    println!("TOTAL_SIZE={file_size}");
    println!("PAYMENTS={total_tx_count}");
    println!("TX_HASHES={tx_hashes_str}");

    info!(
        "Upload complete: address={manifest_hex}, chunks={chunk_count}, payments={total_tx_count}"
    );

    Ok(())
}

async fn handle_download(
    client: &QuantumClient,
    address: &str,
    output: Option<&Path>,
) -> color_eyre::Result<()> {
    let manifest_address = parse_address(address)?;
    info!("Downloading file from manifest {address}");

    // Fetch manifest chunk
    let manifest_chunk = client
        .get_chunk(&manifest_address)
        .await?
        .ok_or_else(|| color_eyre::eyre::eyre!("Manifest chunk not found at {address}"))?;

    let manifest = deserialize_manifest(&manifest_chunk.content)?;
    let chunk_count = manifest.chunk_addresses.len();
    info!(
        "Manifest loaded: {} chunk(s), {} bytes total",
        chunk_count, manifest.total_size
    );

    // Fetch all data chunks in order
    let mut chunks = Vec::with_capacity(chunk_count);
    for (i, chunk_addr) in manifest.chunk_addresses.iter().enumerate() {
        let chunk_num = i + 1;
        info!(
            "Downloading chunk {chunk_num}/{chunk_count} ({})",
            hex::encode(chunk_addr)
        );
        let chunk = client.get_chunk(chunk_addr).await?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Data chunk not found: {}", hex::encode(chunk_addr))
        })?;
        chunks.push(chunk.content);
    }

    // Reassemble file
    let file_content = reassemble_file(&manifest, &chunks)?;
    info!("File reassembled: {} bytes", file_content.len());

    // Write output
    if let Some(path) = output {
        std::fs::write(path, &file_content)?;
        info!("File saved to {}", path.display());
        println!(
            "Downloaded {} bytes to {}",
            file_content.len(),
            path.display()
        );
    } else {
        use std::io::Write;
        std::io::stdout().write_all(&file_content)?;
    }

    Ok(())
}

async fn handle_chunk_put(client: &QuantumClient, file: Option<PathBuf>) -> color_eyre::Result<()> {
    let content = read_input(file)?;
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
                use std::io::Write;
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

fn read_input(file: Option<PathBuf>) -> color_eyre::Result<Vec<u8>> {
    if let Some(path) = file {
        return Ok(std::fs::read(path)?);
    }
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
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
