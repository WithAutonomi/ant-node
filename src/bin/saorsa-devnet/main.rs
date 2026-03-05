//! saorsa-devnet CLI entry point.

mod cli;

use clap::Parser;
use cli::Cli;
use saorsa_node::devnet::{Devnet, DevnetConfig, DevnetEvmInfo, DevnetManifest};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    info!("saorsa-devnet v{}", env!("CARGO_PKG_VERSION"));

    let mut config =
        cli.preset
            .as_deref()
            .map_or_else(DevnetConfig::default, |preset| match preset {
                "minimal" => DevnetConfig::minimal(),
                "small" => DevnetConfig::small(),
                _ => DevnetConfig::default(),
            });

    if let Some(count) = cli.nodes {
        config.node_count = count;
    }
    if let Some(bootstrap) = cli.bootstrap_count {
        config.bootstrap_count = bootstrap;
    }
    if let Some(base_port) = cli.base_port {
        config.base_port = base_port;
    }
    if let Some(dir) = cli.data_dir {
        config.data_dir = dir;
    }
    config.cleanup_data_dir = !cli.no_cleanup;
    if let Some(delay_ms) = cli.spawn_delay_ms {
        config.spawn_delay = std::time::Duration::from_millis(delay_ms);
    }
    if let Some(timeout_secs) = cli.stabilization_timeout_secs {
        config.stabilization_timeout = std::time::Duration::from_secs(timeout_secs);
    }

    // Start Anvil and deploy contracts if EVM is enabled
    let evm_info = if cli.enable_evm {
        info!("Starting local Anvil blockchain for EVM payment enforcement...");
        let testnet = evmlib::testnet::Testnet::new().await;
        let network = testnet.to_network();
        let wallet_key = testnet.default_wallet_private_key();

        let (rpc_url, token_addr, payments_addr) = match &network {
            evmlib::Network::Custom(custom) => (
                custom.rpc_url_http.to_string(),
                format!("{:?}", custom.payment_token_address),
                format!("{:?}", custom.data_payments_address),
            ),
            _ => {
                return Err(color_eyre::eyre::eyre!(
                    "Anvil testnet returned non-Custom network"
                ))
            }
        };

        config.enable_evm = true;
        config.evm_network = Some(network);

        info!("Anvil blockchain running at {rpc_url}");
        info!("Funded wallet private key: {wallet_key}");

        // Keep testnet alive by leaking it (it will be cleaned up on process exit)
        // This is necessary because AnvilInstance stops Anvil when dropped
        std::mem::forget(testnet);

        Some(DevnetEvmInfo {
            rpc_url,
            wallet_private_key: wallet_key,
            payment_token_address: token_addr,
            data_payments_address: payments_addr,
        })
    } else {
        None
    };

    let mut devnet = Devnet::new(config).await?;
    devnet.start().await?;

    let manifest = DevnetManifest {
        base_port: devnet.config().base_port,
        node_count: devnet.config().node_count,
        bootstrap: devnet.bootstrap_addrs(),
        data_dir: devnet.config().data_dir.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        evm: evm_info,
    };

    let json = serde_json::to_string_pretty(&manifest)?;
    if let Some(path) = cli.manifest {
        tokio::fs::write(&path, &json).await?;
        info!("Wrote manifest to {}", path.display());
    } else {
        println!("{json}");
    }

    info!("Devnet running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    devnet.shutdown().await?;
    Ok(())
}
