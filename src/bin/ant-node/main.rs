//! ant-node CLI entry point.

mod cli;
mod platform;

use ant_node::config::BootstrapSource;
use ant_node::NodeBuilder;
use clap::Parser;
use cli::{Cli, CliLogFormat};
use tracing::{info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter, Layer};

/// Force at least 4 worker threads regardless of CPU count.
///
/// On small VMs (1-2 vCPU), the default `num_cpus` gives only 1-2 worker
/// threads.  The NAT traversal `poll()` function does synchronous work
/// (`parking_lot` locks, `DashMap` iteration) that blocks its worker thread.
/// With only 1 worker, this freezes the entire runtime — timers stop,
/// keepalives can't fire, and connections die silently.
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> color_eyre::Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Parse CLI arguments
    let cli = Cli::parse();

    // Extract logging options before consuming the CLI struct
    let log_format = cli.log_format;
    let log_dir = cli.log_dir.clone();
    let log_max_files = cli.log_max_files;

    // Initialize tracing
    let log_level: String = cli.log_level.into();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));

    // _guard must live for the duration of main() to ensure log flushing.
    // The guard's Drop impl flushes buffered logs — it is intentionally held, not read.
    #[allow(clippy::collection_is_never_read)]
    let _guard: Option<tracing_appender::non_blocking::WorkerGuard>;

    let layer: Box<dyn Layer<_> + Send + Sync> = match (log_format, log_dir) {
        (CliLogFormat::Text, None) => {
            _guard = None;
            Box::new(fmt::layer())
        }
        (CliLogFormat::Json, None) => {
            _guard = None;
            Box::new(fmt::layer().json().flatten_event(true))
        }
        (CliLogFormat::Text, Some(dir)) => {
            let file_appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .max_log_files(log_max_files)
                .filename_prefix("ant-node")
                .filename_suffix("log")
                .build(dir)?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            _guard = Some(guard);
            Box::new(fmt::layer().with_writer(non_blocking).with_ansi(false))
        }
        (CliLogFormat::Json, Some(dir)) => {
            let file_appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .max_log_files(log_max_files)
                .filename_prefix("ant-node")
                .filename_suffix("log")
                .build(dir)?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            _guard = Some(guard);
            Box::new(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_writer(non_blocking)
                    .with_ansi(false),
            )
        }
    };

    tracing_subscriber::registry()
        .with(layer)
        .with(filter)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("ANT_GIT_COMMIT"),
        "ant-node starting"
    );

    // Prevent macOS App Nap from throttling background timer operations.
    // _activity must live for the duration of main() — dropping it re-enables App Nap.
    #[allow(clippy::collection_is_never_read)]
    let _activity = match platform::disable_app_nap() {
        Ok(activity) => {
            info!("App Nap prevention enabled");
            Some(activity)
        }
        Err(e) => {
            warn!("Failed to disable App Nap: {e}");
            None
        }
    };

    // Build configuration
    let (config, bootstrap_source) = cli.into_config()?;

    match &bootstrap_source {
        BootstrapSource::Cli => {
            info!(
                count = config.bootstrap.len(),
                "Bootstrap peers provided via CLI"
            );
        }
        BootstrapSource::ConfigFile => {
            info!(
                count = config.bootstrap.len(),
                "Bootstrap peers loaded from config file"
            );
        }
        BootstrapSource::AutoDiscovered(path) => {
            info!(
                count = config.bootstrap.len(),
                path = %path.display(),
                "Bootstrap peers loaded from discovered config"
            );
        }
        BootstrapSource::None => {
            warn!(
                "No bootstrap peers configured — node will not be able to join an existing network"
            );
        }
    }

    // Build and run the node
    let mut node = NodeBuilder::new(config).build().await?;

    // Run until shutdown
    node.run().await?;

    info!("Goodbye!");
    Ok(())
}
