// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Integration tests for the P2PNode lifecycle: create → start → stop → shutdown.
//!
//! Verifies that the node correctly transitions between states and that
//! transport, DHT, and trust systems initialise and tear down properly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{AdaptiveDhtConfig, NodeConfig, NodeMode, P2PNode};
use std::time::Duration;

/// Helper: local loopback, ephemeral port, IPv4 only.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

/// A freshly-created node is not running and not bootstrapped.
#[tokio::test]
async fn new_node_is_not_running() {
    let node = P2PNode::new(test_config()).await.unwrap();

    assert!(!node.is_running(), "New node should not be running");
    assert!(
        !node.is_bootstrapped(),
        "New node should not be bootstrapped"
    );
}

/// Each node gets a unique peer ID (derived from a fresh keypair).
#[tokio::test]
async fn each_node_gets_unique_peer_id() {
    let node_a = P2PNode::new(test_config()).await.unwrap();
    let node_b = P2PNode::new(test_config()).await.unwrap();

    assert_ne!(
        node_a.peer_id(),
        node_b.peer_id(),
        "Two nodes should have different peer IDs"
    );
}

/// The config round-trips through the node.
#[tokio::test]
async fn config_accessible_after_creation() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .max_connections(42)
        .connection_timeout(Duration::from_secs(7))
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();

    assert_eq!(node.config().max_connections, 42);
    assert_eq!(node.config().connection_timeout, Duration::from_secs(7));
}

// ---------------------------------------------------------------------------
// Start / stop
// ---------------------------------------------------------------------------

/// Starting a node transitions it to running and binds at least one address.
#[tokio::test]
async fn start_makes_node_running() {
    let node = P2PNode::new(test_config()).await.unwrap();

    node.start().await.unwrap();
    assert!(node.is_running(), "Node should be running after start()");

    let addrs = node.listen_addrs().await;
    assert!(
        !addrs.is_empty(),
        "Started node should have at least one listen address"
    );

    node.stop().await.unwrap();
}

/// Stopping a running node transitions it to not-running.
#[tokio::test]
async fn stop_makes_node_not_running() {
    let node = P2PNode::new(test_config()).await.unwrap();

    node.start().await.unwrap();
    assert!(node.is_running());

    node.stop().await.unwrap();
    assert!(
        !node.is_running(),
        "Node should not be running after stop()"
    );
}

/// `shutdown()` is an alias for `stop()` and also transitions to not-running.
#[tokio::test]
async fn shutdown_alias_works() {
    let node = P2PNode::new(test_config()).await.unwrap();

    node.start().await.unwrap();
    node.shutdown().await.unwrap();

    assert!(
        !node.is_running(),
        "Node should not be running after shutdown()"
    );
}

// ---------------------------------------------------------------------------
// Health and uptime
// ---------------------------------------------------------------------------

/// Health check passes on a freshly-created node (no connections needed).
#[tokio::test]
async fn health_check_passes_with_no_peers() {
    let node = P2PNode::new(test_config()).await.unwrap();
    assert!(node.health_check().await.is_ok());
}

/// Uptime increases after creation.
#[tokio::test]
async fn uptime_increases() {
    let node = P2PNode::new(test_config()).await.unwrap();

    let t1 = node.uptime();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let t2 = node.uptime();

    assert!(t2 > t1, "Uptime should increase over time");
}

/// A started node reports zero peers when isolated.
#[tokio::test]
async fn started_node_has_zero_peers_when_isolated() {
    let node = P2PNode::new(test_config()).await.unwrap();

    node.start().await.unwrap();

    let peers = node.connected_peers().await;
    assert!(peers.is_empty(), "Isolated node should have no peers");
    assert_eq!(node.peer_count().await, 0);

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Builder pattern
// ---------------------------------------------------------------------------

/// The builder produces a working config with defaults.
#[tokio::test]
async fn builder_defaults_produce_valid_node() {
    let config = NodeConfig::builder().local(true).port(0).build().unwrap();
    let node = P2PNode::new(config).await.unwrap();
    assert!(!node.is_running());
}

/// Builder `.mode(Client)` sets the correct mode.
#[tokio::test]
async fn builder_client_mode() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .mode(NodeMode::Client)
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();
    assert_eq!(node.config().mode, NodeMode::Client);
}

/// Builder `.trust_enforcement(false)` sets swap threshold to 0.0.
#[tokio::test]
async fn builder_trust_enforcement_toggle() {
    let config_off = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .trust_enforcement(false)
        .build()
        .unwrap();

    let node_off = P2PNode::new(config_off).await.unwrap();
    assert!(
        (node_off.adaptive_dht().config().swap_threshold - 0.0).abs() < f64::EPSILON,
        "trust_enforcement(false) should set threshold to 0.0"
    );

    let config_on = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .trust_enforcement(true)
        .build()
        .unwrap();

    let node_on = P2PNode::new(config_on).await.unwrap();
    assert!(
        (node_on.adaptive_dht().config().swap_threshold
            - AdaptiveDhtConfig::default().swap_threshold)
            .abs()
            < f64::EPSILON,
        "trust_enforcement(true) should use default threshold"
    );
}

/// Builder `.allow_loopback` is auto-set when `.local(true)`.
#[tokio::test]
async fn local_mode_auto_enables_loopback() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .unwrap();

    assert!(
        config.allow_loopback,
        "local(true) should auto-enable allow_loopback"
    );
}

// ---------------------------------------------------------------------------
// Trust system initialised at creation
// ---------------------------------------------------------------------------

/// The AdaptiveDHT and TrustEngine are accessible immediately after creation
/// (before start).
#[tokio::test]
async fn trust_system_available_before_start() {
    let node = P2PNode::new(test_config()).await.unwrap();

    // TrustEngine should be queryable
    let _engine = node.trust_engine();
    let _dht = node.adaptive_dht();

    // Score queries should work
    let score = node.peer_trust(&saorsa_core::PeerId::random());
    assert!((score - 0.5).abs() < f64::EPSILON);
}

/// Events can be reported before the node is started (scores still track).
#[tokio::test]
async fn trust_events_work_before_start() {
    let node = P2PNode::new(test_config()).await.unwrap();
    let peer = saorsa_core::PeerId::random();

    node.report_trust_event(&peer, saorsa_core::TrustEvent::ApplicationSuccess(1.0))
        .await;

    assert!(
        node.peer_trust(&peer) > 0.5,
        "Trust event should take effect before start()"
    );
}

// ---------------------------------------------------------------------------
// Event subscription
// ---------------------------------------------------------------------------

/// Subscribing to events returns a receiver without errors.
#[tokio::test]
async fn event_subscription_works() {
    let node = P2PNode::new(test_config()).await.unwrap();
    let _rx = node.subscribe_events();
}

// ---------------------------------------------------------------------------
// Concurrent node creation
// ---------------------------------------------------------------------------

/// Multiple nodes can be created and started concurrently on different ports.
#[tokio::test]
async fn multiple_nodes_coexist() {
    let mut nodes = Vec::new();

    for _ in 0..3 {
        let node = P2PNode::new(test_config()).await.unwrap();
        node.start().await.unwrap();
        nodes.push(node);
    }

    // All should be running on distinct addresses
    let mut all_addrs: Vec<String> = Vec::new();
    for node in &nodes {
        let addrs = node.listen_addrs().await;
        assert!(!addrs.is_empty());
        for addr in &addrs {
            let addr_str = addr.to_string();
            assert!(
                !all_addrs.contains(&addr_str),
                "Duplicate address found: {addr_str}"
            );
            all_addrs.push(addr_str);
        }
    }

    // Cleanup
    for node in &nodes {
        node.stop().await.unwrap();
    }
}
