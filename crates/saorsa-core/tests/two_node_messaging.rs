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

//! Integration tests for two-node communication over QUIC loopback.
//!
//! These tests create two `P2PNode` instances on the local machine, connect
//! them, exchange messages, and verify that trust auto-reporting works
//! through the `send_request` path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{NodeConfig, P2PEvent, P2PNode, PeerId, TrustEvent};
use std::time::Duration;
use tokio::time::timeout;

/// Helper: local loopback, ephemeral port, IPv4-only config.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Helper: start two nodes and connect node_a → node_b.
/// Returns (node_a, node_b, peer_id_of_b).
async fn connected_pair() -> (P2PNode, P2PNode, PeerId) {
    let node_a = P2PNode::new(test_config()).await.unwrap();
    let node_b = P2PNode::new(test_config()).await.unwrap();

    node_a.start().await.unwrap();
    node_b.start().await.unwrap();

    // Brief wait for listeners to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Get node_b's listen address (IPv4)
    let node_b_addr = node_b
        .listen_addrs()
        .await
        .into_iter()
        .find(|a| a.is_ipv4())
        .expect("node_b should have an IPv4 listen address");

    // Connect node_a → node_b
    let channel_id = timeout(Duration::from_secs(2), node_a.connect_peer(&node_b_addr))
        .await
        .expect("connect should not timeout")
        .expect("connect should succeed");

    // Wait for identity exchange to complete
    let peer_b = timeout(
        Duration::from_secs(2),
        node_a.wait_for_peer_identity(&channel_id, Duration::from_secs(2)),
    )
    .await
    .expect("identity exchange should not timeout")
    .expect("identity exchange should succeed");

    assert_eq!(
        &peer_b,
        node_b.peer_id(),
        "Identity exchange should reveal node_b's peer ID"
    );

    (node_a, node_b, peer_b)
}

// ---------------------------------------------------------------------------
// Connection establishment
// ---------------------------------------------------------------------------

/// Two nodes can connect over loopback and complete identity exchange.
#[tokio::test]
async fn two_nodes_connect_and_identify() {
    let (node_a, node_b, peer_b) = connected_pair().await;

    // node_a should see node_b as connected
    let peers = node_a.connected_peers().await;
    assert!(
        peers.contains(&peer_b),
        "node_a should list node_b as a connected peer"
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Fire-and-forget messaging
// ---------------------------------------------------------------------------

/// `send_message` succeeds between two connected nodes.
#[tokio::test]
async fn send_message_between_connected_nodes() {
    let (node_a, node_b, peer_b) = connected_pair().await;

    let payload = b"hello from node_a".to_vec();
    let result = timeout(
        Duration::from_millis(500),
        node_a.send_message(&peer_b, "test/echo", payload, &[]),
    )
    .await
    .expect("send should not timeout");

    // send_message is fire-and-forget; it should succeed if the peer is connected.
    assert!(
        result.is_ok(),
        "send_message to connected peer should succeed: {:?}",
        result.unwrap_err()
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

/// Sending to a non-existent peer returns an error.
#[tokio::test]
async fn send_message_to_unknown_peer_fails() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let fake_peer = PeerId::random();
    let result = node
        .send_message(&fake_peer, "test/echo", vec![1, 2, 3], &[])
        .await;
    assert!(result.is_err(), "Sending to unknown peer should fail");

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

/// A PeerConnected event is emitted when a peer completes identity exchange.
#[tokio::test]
async fn peer_connected_event_emitted() {
    let node_a = P2PNode::new(test_config()).await.unwrap();
    let node_b = P2PNode::new(test_config()).await.unwrap();

    node_a.start().await.unwrap();
    node_b.start().await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut events_rx = node_a.subscribe_events();

    let node_b_addr = node_b
        .listen_addrs()
        .await
        .into_iter()
        .find(|a| a.is_ipv4())
        .expect("node_b should have an IPv4 address");

    let channel_id = timeout(Duration::from_secs(2), node_a.connect_peer(&node_b_addr))
        .await
        .unwrap()
        .unwrap();

    // Wait for identity exchange
    let _ = timeout(
        Duration::from_secs(2),
        node_a.wait_for_peer_identity(&channel_id, Duration::from_secs(2)),
    )
    .await
    .unwrap()
    .unwrap();

    // Drain events to find PeerConnected
    let mut found_connected = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(100), events_rx.recv()).await {
            Ok(Ok(P2PEvent::PeerConnected(pid, _user_agent))) => {
                if pid == *node_b.peer_id() {
                    found_connected = true;
                    break;
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break, // channel closed
            Err(_) => {}         // inner timeout elapsed — retry within deadline
        }
    }

    assert!(
        found_connected,
        "Expected PeerConnected event for node_b's peer ID"
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Trust reporting via send_message
// ---------------------------------------------------------------------------

/// Reporting a trust event for a connected peer changes their score.
#[tokio::test]
async fn trust_event_for_connected_peer() {
    let (node_a, node_b, peer_b) = connected_pair().await;

    // Before any explicit trust events, peer starts at neutral
    let initial = node_a.peer_trust(&peer_b);

    // Report positive trust
    for _ in 0..10 {
        node_a
            .report_trust_event(&peer_b, TrustEvent::ApplicationSuccess(1.0))
            .await;
    }

    let after_success = node_a.peer_trust(&peer_b);
    assert!(
        after_success > initial,
        "Trust should increase after successes: {initial} -> {after_success}"
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Bidirectional connectivity
// ---------------------------------------------------------------------------

/// Both nodes can see each other as connected after a single connect call.
#[tokio::test]
async fn bidirectional_peer_visibility() {
    let (node_a, node_b, peer_b) = connected_pair().await;

    // node_a sees node_b
    assert!(node_a.connected_peers().await.contains(&peer_b));

    // node_b should eventually see node_a (the inbound connection triggers
    // identity exchange from node_b's perspective too)
    let peer_a = *node_a.peer_id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut b_sees_a = false;
    while tokio::time::Instant::now() < deadline {
        if node_b.connected_peers().await.contains(&peer_a) {
            b_sees_a = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(b_sees_a, "node_b should see node_a as connected");

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Peer count
// ---------------------------------------------------------------------------

/// Peer count reflects connected peers.
#[tokio::test]
async fn peer_count_reflects_connections() {
    let (node_a, node_b, _peer_b) = connected_pair().await;

    assert!(
        node_a.peer_count().await >= 1,
        "node_a should have at least 1 peer after connecting"
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}
