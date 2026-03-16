//! Live testnet tests for load testing and data verification.
//!
//! These tests connect to the live saorsa testnet for comprehensive testing.
//! They are designed to be run via shell scripts that set environment variables.
//! When environment variables are not set, the tests skip gracefully.
//!
//! TODO: Rewrite to use `QuantumClient` — `dht_put`/`dht_get` were removed
//! from `saorsa-core` v0.16 (`P2PNode` no longer exposes raw DHT operations).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use saorsa_core::{MultiAddr, NodeConfig as CoreNodeConfig, P2PNode};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

/// Get bootstrap addresses from environment or use defaults.
fn get_bootstrap_addrs() -> Vec<SocketAddr> {
    let bootstrap_str = env::var("SAORSA_TEST_BOOTSTRAP")
        .unwrap_or_else(|_| "142.93.52.129:12000,24.199.82.114:12000".to_string());

    bootstrap_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Create a P2P node connected to the live testnet.
async fn create_testnet_client() -> P2PNode {
    let bootstrap_addrs = get_bootstrap_addrs();
    println!("Connecting to testnet via: {bootstrap_addrs:?}");

    let mut config = CoreNodeConfig::builder()
        .local(true)
        .build()
        .expect("Failed to create config");
    config.bootstrap_peers = bootstrap_addrs
        .iter()
        .map(|addr| MultiAddr::quic(*addr))
        .collect();

    let node = P2PNode::new(config)
        .await
        .expect("Failed to create P2P node");

    node.start().await.expect("Failed to start P2P node");

    // Wait for connection
    tokio::time::sleep(Duration::from_secs(5)).await;

    println!(
        "Connected to testnet with {} peers",
        node.peer_count().await
    );

    node
}

/// Load test: store thousands of chunks on the testnet.
///
/// Disabled until rewritten for `QuantumClient` (saorsa-core 0.16 removed `dht_put`/`dht_get`).
#[tokio::test]
#[ignore = "needs rewrite: dht_put/dht_get removed in saorsa-core 0.16"]
async fn run_load_test() {
    let _node = create_testnet_client().await;
    unimplemented!("rewrite with QuantumClient");
}

/// Verify chunks: check that all stored chunks are retrievable.
///
/// Disabled until rewritten for `QuantumClient` (saorsa-core 0.16 removed `dht_put`/`dht_get`).
#[tokio::test]
#[ignore = "needs rewrite: dht_put/dht_get removed in saorsa-core 0.16"]
async fn run_verify_chunks() {
    let _node = create_testnet_client().await;
    unimplemented!("rewrite with QuantumClient");
}

/// Comprehensive data test: store, retrieve, and verify.
///
/// Disabled until rewritten for `QuantumClient` (saorsa-core 0.16 removed `dht_put`/`dht_get`).
#[tokio::test]
#[ignore = "needs rewrite: dht_put/dht_get removed in saorsa-core 0.16"]
async fn run_comprehensive_data_tests() {
    let _node = create_testnet_client().await;
    unimplemented!("rewrite with QuantumClient");
}
