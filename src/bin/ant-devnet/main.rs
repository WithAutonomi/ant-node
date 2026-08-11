//! ant-devnet CLI entry point.
//!
//! Runs a local devnet for testing. By default all nodes bind loopback
//! (`127.0.0.1`), so only the host machine can reach them.
//!
//! Three opt-in flags extend this to a **LAN / external-devnet** scenario for
//! testing from another device (a phone, a simulator, a second machine). All
//! default off — omitting them reproduces the original loopback behavior:
//!
//! - `--host <ipv4>`: bind `0.0.0.0` and advertise this LAN IP in the manifest's
//!   bootstrap addresses, so other devices on the LAN can connect.
//! - `--evm-network arbitrum-sepolia`: verify payments against the real deployed
//!   Arbitrum Sepolia contracts (no local Anvil, empty wallet key) — exercises
//!   the external-signer payment flow.
//! - `--serve-port <port>`: expose the manifest over a small read-only HTTP API
//!   (`GET /api/devnet-manifest.json` + `/api/info`) so devices fetch it instead
//!   of copying files.
//!
//! ```text
//! # single-machine, local Anvil (unchanged default behavior)
//! ant-devnet --preset small --enable-evm
//!
//! # LAN devnet backed by Arbitrum Sepolia, manifest served over HTTP
//! ant-devnet --preset small --host 192.168.1.100 \
//!     --evm-network arbitrum-sepolia --serve-port 8088
//! ```

#![cfg_attr(not(feature = "logging"), allow(unused_variables))]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod cli;

use ant_node::devnet::{Devnet, DevnetConfig, DevnetEvmInfo, DevnetManifest};
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    #[cfg(feature = "logging")]
    if cli.enable_logging {
        use tracing_subscriber::{fmt, prelude::*, EnvFilter};

        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(filter)
            .init();
    }

    ant_node::logging::info!("ant-devnet v{}", env!("CARGO_PKG_VERSION"));

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

    // A non-unicast --host would stamp unreachable bootstrap addresses into the
    // manifest (LAN mode would fail non-obviously), so reject it early.
    if let Some(host) = cli
        .host
        .filter(|h| h.is_loopback() || h.is_unspecified() || h.is_multicast() || h.is_broadcast())
    {
        return Err(color_eyre::eyre::eyre!(
            "--host must be a routable unicast LAN IPv4 (got {host}); \
             loopback/unspecified/multicast/broadcast are not reachable bootstrap addresses"
        ));
    }
    config.advertise_ip = cli.host;
    let evm_info = resolve_evm_info(
        cli.evm_network.as_deref(),
        cli.enable_evm,
        cli.host,
        &mut config,
    )
    .await?;

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
        ant_node::logging::info!("Wrote manifest to {}", path.display());
    } else {
        println!("{json}");
    }

    // Optional read-only HTTP API so LAN devices fetch the manifest instead of
    // copying files (GET /api/devnet-manifest.json + /api/info).
    if let Some(port) = cli.serve_port {
        serve_manifest_api(port, cli.host, &manifest, json.clone())?;
    }

    ant_node::logging::info!("Devnet running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    devnet.shutdown().await?;
    Ok(())
}

/// Resolve which EVM backing the devnet uses, updating `config` accordingly:
/// an **external** network (`--evm-network`, e.g. Arbitrum Sepolia verified
/// against the real deployed contracts, no embedded wallet key); a **local
/// Anvil** chain (`--enable-evm`); or **none**. External takes precedence.
async fn resolve_evm_info(
    evm_network: Option<&str>,
    enable_evm: bool,
    host: Option<std::net::Ipv4Addr>,
    config: &mut DevnetConfig,
) -> color_eyre::Result<Option<DevnetEvmInfo>> {
    if let Some(net_name) = evm_network {
        let network = match net_name {
            "arbitrum-sepolia" => evmlib::Network::ArbitrumSepoliaTest,
            other => {
                return Err(color_eyre::eyre::eyre!(
                    "Unsupported --evm-network {other} (supported: arbitrum-sepolia)"
                ))
            }
        };
        let rpc_url = network.rpc_url().to_string();
        let token_addr = format!("{:?}", network.payment_token_address());
        let vault_addr = format!("{:?}", network.payment_vault_address());
        ant_node::logging::info!(
            "Using external EVM network {net_name}: rpc={rpc_url} token={token_addr} vault={vault_addr}"
        );
        config.evm_network = Some(network);
        Ok(Some(DevnetEvmInfo {
            rpc_url,
            wallet_private_key: String::new(),
            payment_token_address: token_addr,
            payment_vault_address: vault_addr,
        }))
    } else if enable_evm {
        // Anvil binds — and evmlib publishes in the manifest's `rpc_url` —
        // the address in `ANVIL_IP_ADDR`, defaulting to localhost. A LAN
        // devnet must expose the chain the way it exposes the nodes, or the
        // published `rpc_url` is unreachable from every other device —
        // exactly the audience `--host` serves (external signers can join
        // and download, but not pay). An explicit `ANVIL_IP_ADDR` wins.
        if let Some(anvil_ip) = anvil_ip_for_lan(host, std::env::var_os("ANVIL_IP_ADDR")) {
            ant_node::logging::info!(
                "Binding Anvil to {anvil_ip} (via ANVIL_IP_ADDR) so LAN clients \
                 can reach the manifest's rpc_url"
            );
            std::env::set_var("ANVIL_IP_ADDR", anvil_ip);
        }
        ant_node::logging::info!("Starting local Anvil blockchain for EVM payment enforcement...");
        let testnet = evmlib::testnet::Testnet::new()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("Failed to start Anvil testnet: {e}"))?;
        let network = testnet.to_network();
        let wallet_key = testnet
            .default_wallet_private_key()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to get wallet key: {e}"))?;

        let (rpc_url, token_addr, vault_addr) = match &network {
            evmlib::Network::Custom(custom) => (
                custom.rpc_url_http.to_string(),
                format!("{:?}", custom.payment_token_address),
                format!("{:?}", custom.payment_vault_address),
            ),
            _ => {
                return Err(color_eyre::eyre::eyre!(
                    "Anvil testnet returned non-Custom network"
                ))
            }
        };

        config.evm_network = Some(network);

        ant_node::logging::info!("Anvil blockchain running at {rpc_url}");
        ant_node::logging::info!("Funded wallet private key: {wallet_key}");

        // Keep testnet alive by leaking it (it will be cleaned up on process exit)
        // This is necessary because AnvilInstance stops Anvil when dropped
        std::mem::forget(testnet);

        Ok(Some(DevnetEvmInfo {
            rpc_url,
            wallet_private_key: wallet_key,
            payment_token_address: token_addr,
            payment_vault_address: vault_addr,
        }))
    } else {
        Ok(None)
    }
}

/// Build the `/api/info` payload for `manifest` and start the read-only HTTP
/// server on `port`. `host` is the advertised LAN IP when set, otherwise a
/// best-effort local-IP guess is used for the URLs it reports.
fn serve_manifest_api(
    port: u16,
    host: Option<std::net::Ipv4Addr>,
    manifest: &DevnetManifest,
    manifest_json: String,
) -> color_eyre::Result<()> {
    let host_ip = host.map_or_else(local_ip_guess, |i| i.to_string());
    let evm_block = manifest.evm.as_ref().map_or(serde_json::Value::Null, |e| {
        let loopback = e.rpc_url.contains("127.0.0.1") || e.rpc_url.contains("localhost");
        serde_json::json!({
            "rpc_url": e.rpc_url,
            "network": if loopback { "local-anvil" } else { "external" },
            "reachable_from_lan": !loopback,
            "note": if loopback {
                format!(
                    "Anvil binds loopback on the host — bridge it (socat \
                     TCP-LISTEN:8545,fork,bind=0.0.0.0 TCP:127.0.0.1:<anvil-port>) \
                     and use http://{host_ip}:8545/."
                )
            } else {
                "Public RPC — reachable directly from any device.".to_string()
            },
        })
    });
    let bootstrap = serde_json::to_value(&manifest.bootstrap)?;
    let info = serde_json::json!({
        "host_ip": host_ip,
        "manifest_url": format!("http://{host_ip}:{port}/api/devnet-manifest.json"),
        "node_count": manifest.node_count as u64,
        "bootstrap": bootstrap,
        "evm": evm_block,
    });
    let info_json = serde_json::to_string_pretty(&info)?;
    // Bind synchronously so a failure (e.g. the port is already in use)
    // propagates to the caller instead of the devnet silently coming up
    // without its manifest API.
    let listener = std::net::TcpListener::bind(("0.0.0.0", port)).map_err(|e| {
        color_eyre::eyre::eyre!("failed to bind manifest API on 0.0.0.0:{port}: {e}")
    })?;
    ant_node::logging::info!(
        "manifest API on http://0.0.0.0:{port}/api/devnet-manifest.json (+ /api/info)"
    );
    spawn_manifest_server(listener, manifest_json, info_json);
    Ok(())
}

/// Best-effort primary LAN IP (src of the default route) for the info endpoint.
fn local_ip_guess() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Run a tiny read-only HTTP server on `listener` (its own thread) exposing the
/// manifest over the LAN. GET-only, open CORS; hand-rolled HTTP/1.1 so there's
/// no new dependency. Connections are handled **inline, one at a time** — the
/// payloads are tiny and a devnet serves a handful of LAN devices, so a single
/// thread bounds resource use (no per-connection thread to exhaust). Each
/// connection gets a read timeout so a slow/idle client can't stall the loop.
/// The thread is detached and dies when the process exits on Ctrl+C.
fn spawn_manifest_server(
    listener: std::net::TcpListener,
    manifest_json: String,
    info_json: String,
) {
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let mut tokens = req.split_whitespace();
            let method = tokens.next().unwrap_or("");
            let raw = tokens.next().unwrap_or("/");
            let path = raw.split('?').next().unwrap_or("/").trim_end_matches('/');
            // Read-only API — only GET is allowed; anything else is 405.
            let (status, body) = if method == "GET" {
                match path {
                    "/api/devnet-manifest.json" => ("200 OK", manifest_json.as_str()),
                    "/api/info" => ("200 OK", info_json.as_str()),
                    "" | "/api" => (
                        "200 OK",
                        "{\"service\":\"ant-devnet manifest API\",\
                         \"endpoints\":[\"/api/devnet-manifest.json\",\"/api/info\"]}",
                    ),
                    _ => ("404 Not Found", "{\"error\":\"not found\"}"),
                }
            } else {
                (
                    "405 Method Not Allowed",
                    "{\"error\":\"method not allowed\"}",
                )
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
}

/// The Anvil bind/publish address a LAN devnet should use: the `--host` IP,
/// unless the operator set `ANVIL_IP_ADDR` explicitly (their override wins),
/// or there is no `--host` (loopback devnet — keep Anvil's localhost
/// default). Returns the value to write into `ANVIL_IP_ADDR`, or `None` to
/// leave the environment untouched.
fn anvil_ip_for_lan(
    host: Option<std::net::Ipv4Addr>,
    existing_override: Option<std::ffi::OsString>,
) -> Option<String> {
    match (host, existing_override) {
        (Some(host), None) => Some(host.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::anvil_ip_for_lan;
    use std::net::Ipv4Addr;

    #[test]
    fn lan_host_becomes_anvil_ip() {
        assert_eq!(
            anvil_ip_for_lan(Some(Ipv4Addr::new(192, 168, 0, 61)), None),
            Some("192.168.0.61".to_string())
        );
    }

    #[test]
    fn explicit_override_wins() {
        assert_eq!(
            anvil_ip_for_lan(
                Some(Ipv4Addr::new(192, 168, 0, 61)),
                Some("10.0.0.9".into())
            ),
            None
        );
    }

    #[test]
    fn loopback_devnet_keeps_anvil_default() {
        assert_eq!(anvil_ip_for_lan(None, None), None);
        assert_eq!(anvil_ip_for_lan(None, Some("10.0.0.9".into())), None);
    }
}
