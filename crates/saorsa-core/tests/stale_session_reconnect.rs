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

//! Integration test: stale QUIC session recovery.
//!
//! Verifies that `send_message` transparently reconnects when the underlying
//! QUIC connection is dead but the channel bookkeeping still considers it
//! alive.  This exercises the reconnect-and-retry path in
//! `P2PNode::send_message`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{NodeConfig, P2PNode, PeerId};
use std::time::Duration;
use tokio::time::timeout;

/// Maximum time to wait for node_b to recognise node_a after initial dial.
const BILATERAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default QUIC idle timeout configured in saorsa-transport (RFC 9308 § 3.2).
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling interval when waiting for bilateral connection.
const CONNECT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Helper: local loopback, ephemeral port, IPv4-only config.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Helper: start two nodes with a bilateral connection.
///
/// Connects node_a → node_b, waits for identity exchange on both sides,
/// and returns (node_a, peer_a, node_b, peer_b).
async fn connected_pair() -> (P2PNode, PeerId, P2PNode, PeerId) {
    let node_a = P2PNode::new(test_config()).await.unwrap();
    let node_b = P2PNode::new(test_config()).await.unwrap();

    let peer_a = *node_a.peer_id();
    let peer_b_expected = *node_b.peer_id();

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

    // Wait for identity exchange on node_a's side
    let peer_b = timeout(
        Duration::from_secs(2),
        node_a.wait_for_peer_identity(&channel_id, Duration::from_secs(2)),
    )
    .await
    .expect("identity exchange should not timeout")
    .expect("identity exchange should succeed");

    assert_eq!(
        peer_b, peer_b_expected,
        "Identity exchange should reveal node_b's peer ID"
    );

    // Wait for node_b to also recognise node_a (bilateral connection).
    // The incoming identity exchange on node_b is async, so poll until ready.
    let bilateral = timeout(BILATERAL_CONNECT_TIMEOUT, async {
        loop {
            if node_b.is_peer_connected(&peer_a).await {
                break;
            }
            tokio::time::sleep(CONNECT_POLL_INTERVAL).await;
        }
    })
    .await;
    assert!(
        bilateral.is_ok(),
        "node_b should recognise node_a within {:?}",
        BILATERAL_CONNECT_TIMEOUT,
    );

    (node_a, peer_a, node_b, peer_b)
}

// ---------------------------------------------------------------------------
// Target-side disconnect (the common real-world scenario)
// ---------------------------------------------------------------------------

/// The target peer drops the connection (e.g. idle timeout), while the sender
/// still believes it is connected.  `send_message` should detect the dead
/// connection, reconnect transparently, and deliver the message.
#[tokio::test]
async fn send_recovers_when_target_drops_connection() {
    let (node_a, peer_a, node_b, peer_b) = connected_pair().await;

    // Sanity: a normal send works before the disconnect.
    let pre_result = timeout(
        Duration::from_millis(500),
        node_a.send_message(&peer_b, "test/echo", b"before disconnect".to_vec(), &[]),
    )
    .await
    .expect("pre-disconnect send should not timeout");
    assert!(
        pre_result.is_ok(),
        "pre-disconnect send should succeed: {:?}",
        pre_result.unwrap_err()
    );

    // Target peer drops the connection — simulates an idle timeout where the
    // remote side cleans up first.  node_a's bookkeeping is untouched, but
    // the underlying QUIC session is dead from node_b's side.
    node_b.disconnect_peer(&peer_a).await.unwrap();

    // Brief pause so the QUIC close propagates at the transport level.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // node_a still thinks it's connected, but the next send should fail on
    // the dead QUIC session, trigger reconnect, and succeed on a fresh
    // connection.
    let post_result = timeout(
        Duration::from_secs(10),
        node_a.send_message(&peer_b, "test/echo", b"after disconnect".to_vec(), &[]),
    )
    .await
    .expect("post-disconnect send should not timeout");
    assert!(
        post_result.is_ok(),
        "send_message should recover after target drops connection: {:?}",
        post_result.unwrap_err()
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Natural idle timeout expiry
// ---------------------------------------------------------------------------

/// Both peers sit idle past the QUIC idle timeout.  The connection dies
/// naturally on both sides.  The next `send_message` should reconnect
/// transparently.
#[tokio::test]
async fn send_recovers_after_idle_timeout_expiry() {
    let (node_a, _peer_a, node_b, peer_b) = connected_pair().await;

    // Sanity: a normal send works before going idle.
    let pre_result = timeout(
        Duration::from_millis(500),
        node_a.send_message(&peer_b, "test/echo", b"before idle".to_vec(), &[]),
    )
    .await
    .expect("pre-idle send should not timeout");
    assert!(
        pre_result.is_ok(),
        "pre-idle send should succeed: {:?}",
        pre_result.unwrap_err()
    );

    // Wait for the QUIC idle timeout to expire on both sides.
    tokio::time::sleep(QUIC_IDLE_TIMEOUT + Duration::from_secs(1)).await;

    // Both peers should have independently detected the idle timeout and
    // cleaned up.  The next send should trigger a reconnect.
    let post_result = timeout(
        Duration::from_secs(10),
        node_a.send_message(&peer_b, "test/echo", b"after idle".to_vec(), &[]),
    )
    .await
    .expect("post-idle send should not timeout");
    assert!(
        post_result.is_ok(),
        "send_message should recover after idle timeout: {:?}",
        post_result.unwrap_err()
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}
