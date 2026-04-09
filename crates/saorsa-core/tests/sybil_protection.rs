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

//! Integration tests for trust-based peer management (sybil protection).
//!
//! These tests verify that low-trust peers are NOT blocked from `send_request`
//! (the lazy swap-out model only replaces them during routing table admission).
//! Trust scores are still tracked and affect routing table swap-out decisions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{AdaptiveDhtConfig, NodeConfig, P2PNode, PeerId, TrustEvent};
use std::time::Duration;

/// Default swap threshold.
const SWAP_THRESHOLD: f64 = 0.35;

/// Helper: local test config.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

// ---------------------------------------------------------------------------
// send_request never blocks based on trust
// ---------------------------------------------------------------------------

/// `send_request` to a low-trust peer does NOT return a blocking error.
/// It will fail for other reasons (not connected) but trust alone does not
/// prevent communication.
#[tokio::test]
async fn send_request_not_blocked_for_low_trust_peer() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let bad_peer = PeerId::random();

    // Tank the peer's trust below swap threshold
    for _ in 0..100 {
        node.report_trust_event(&bad_peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&bad_peer);
    assert!(
        score < SWAP_THRESHOLD,
        "Peer score {score} should be below threshold {SWAP_THRESHOLD}"
    );

    // send_request should NOT fail with a blocking error
    let result = node
        .send_request(
            &bad_peer,
            "test/echo",
            vec![1, 2, 3],
            Duration::from_secs(1),
        )
        .await;

    assert!(result.is_err(), "send_request to unknown peer should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("blocked") && !err_msg.contains("Blocked"),
        "Low-trust peer should not be blocked, got: {err_msg}"
    );

    node.stop().await.unwrap();
}

/// `send_request` to a neutral-trust peer behaves normally.
#[tokio::test]
async fn send_request_not_blocked_for_neutral_peer() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let unknown_peer = PeerId::random();

    let result = node
        .send_request(
            &unknown_peer,
            "test/echo",
            vec![1, 2, 3],
            Duration::from_secs(1),
        )
        .await;

    // It will fail (peer not connected) but NOT because of blocking
    assert!(result.is_err(), "Request to unknown peer should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("blocked") && !err_msg.contains("Blocked"),
        "Unknown peer should not be blocked, got: {err_msg}"
    );

    node.stop().await.unwrap();
}

/// A peer with score above the threshold is not affected.
#[tokio::test]
async fn peer_above_threshold_not_affected() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let peer = PeerId::random();

    // Push score down partway but not below threshold
    for _ in 0..2 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(
        score >= SWAP_THRESHOLD,
        "Score {score} should still be above threshold {SWAP_THRESHOLD}"
    );

    let result = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;

    if let Err(e) = &result {
        let msg = e.to_string();
        assert!(
            !msg.contains("blocked") && !msg.contains("Blocked"),
            "Peer above threshold should not be blocked, got: {msg}"
        );
    }

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Custom threshold configuration
// ---------------------------------------------------------------------------

/// Custom swap threshold is stored and accessible.
#[tokio::test]
async fn custom_swap_threshold_accepted() {
    let custom_threshold = 0.4;
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .adaptive_dht_config(AdaptiveDhtConfig {
            swap_threshold: custom_threshold,
        })
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();

    let threshold = node.adaptive_dht().config().swap_threshold;
    assert!(
        (threshold - custom_threshold).abs() < f64::EPSILON,
        "Stored threshold {threshold} should match configured {custom_threshold}"
    );

    // Even with a custom threshold, send_request does not block
    let peer = PeerId::random();
    for _ in 0..10 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }
    let score = node.peer_trust(&peer);
    assert!(
        score < custom_threshold,
        "Score {score} should be below custom threshold {custom_threshold}"
    );

    node.start().await.unwrap();
    let result = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("blocked") && !err_msg.contains("Blocked"),
        "send_request should never mention blocking, got: {err_msg}"
    );

    node.stop().await.unwrap();
}

/// With trust enforcement disabled (threshold 0.0), peers are never
/// swap-eligible and never blocked.
#[tokio::test]
async fn enforcement_disabled_never_blocks() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .trust_enforcement(false)
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();
    node.start().await.unwrap();

    let peer = PeerId::random();

    // Tank trust completely
    for _ in 0..100 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(score < 0.01, "Score should be near zero: {score}");

    let result = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;

    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("blocked") && !err_msg.contains("Blocked"),
        "With enforcement disabled, should not block: {err_msg}"
    );

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Trust is per-peer
// ---------------------------------------------------------------------------

/// Low trust for one peer does not affect requests to other peers.
#[tokio::test]
async fn low_trust_does_not_affect_other_peers() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let bad_peer = PeerId::random();
    let clean_peer = PeerId::random();

    // Tank one peer's trust
    for _ in 0..100 {
        node.report_trust_event(&bad_peer, TrustEvent::ConnectionFailed)
            .await;
    }

    assert!(node.peer_trust(&bad_peer) < SWAP_THRESHOLD);
    assert!((node.peer_trust(&clean_peer) - 0.5).abs() < f64::EPSILON);

    // Neither peer should get a blocking error
    for peer in [&bad_peer, &clean_peer] {
        let result = node
            .send_request(peer, "test/echo", vec![], Duration::from_secs(1))
            .await;
        if let Err(e) = &result {
            let msg = e.to_string();
            assert!(
                !msg.contains("blocked") && !msg.contains("Blocked"),
                "No peer should ever be blocked, got: {msg}"
            );
        }
    }

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Trust removal resets score
// ---------------------------------------------------------------------------

/// Removing a peer from the trust engine resets their score to neutral.
#[tokio::test]
async fn trust_removal_resets_peer_score() {
    let node = P2PNode::new(test_config()).await.unwrap();

    let peer = PeerId::random();

    // Tank trust
    for _ in 0..100 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }
    assert!(node.peer_trust(&peer) < SWAP_THRESHOLD);

    // Remove from trust engine -> reset to neutral
    node.trust_engine().remove_node(&peer);
    assert!(
        (node.peer_trust(&peer) - 0.5).abs() < f64::EPSILON,
        "After removal, peer should return to neutral trust"
    );
}
