//! saorsa-node CLI entry point.

mod cli;

use clap::Parser;
use cli::Cli;
#[cfg(debug_assertions)]
use cli::CliLogFormat;
use saorsa_node::info;
use saorsa_node::NodeBuilder;
#[cfg(debug_assertions)]
use tracing_subscriber::prelude::*;
#[cfg(debug_assertions)]
use tracing_subscriber::{fmt, EnvFilter, Layer};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Parse CLI arguments
    let cli = Cli::parse();

    #[cfg(debug_assertions)]
    {
        // Extract logging options before consuming the CLI struct
        let log_format = cli.log_format;
        let log_dir = cli.log_dir.clone();
        let log_max_files = cli.log_max_files;

        // Initialize tracing
        let log_level: String = cli.log_level.into();
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));

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
                    .filename_prefix("saorsa-node")
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
                    .filename_prefix("saorsa-node")
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
    }

    info!(
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("SAORSA_GIT_COMMIT"),
        "saorsa-node starting"
    );

    // Build configuration
    let config = cli.into_config()?;

    // Build and run the node
    let mut node = NodeBuilder::new(config).build().await?;

    // Run until shutdown
    node.run().await?;

    info!("Goodbye!");
    Ok(())
}
