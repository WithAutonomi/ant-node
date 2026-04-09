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

//! Integration tests for the trust event flow through P2PNode → AdaptiveDHT → TrustEngine.
//!
//! These tests verify that trust signals reported via the public `P2PNode` API
//! flow through the full component stack and produce the expected score changes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{AdaptiveDhtConfig, NodeConfig, P2PNode, PeerId, TrustEvent};

/// Default neutral trust score for unknown peers.
const NEUTRAL_TRUST: f64 = 0.5;

/// Default trust threshold below which peers become eligible for swap-out.
const SWAP_THRESHOLD: f64 = 0.35;

/// Helper: create a local-only test node config (loopback, ephemeral port, IPv4 only).
fn test_node_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

// ---------------------------------------------------------------------------
// Basic trust scoring via P2PNode
// ---------------------------------------------------------------------------

/// Unknown peers start at neutral trust (0.5).
#[tokio::test]
async fn unknown_peer_starts_at_neutral() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    let score = node.peer_trust(&peer);
    assert!(
        (score - NEUTRAL_TRUST).abs() < f64::EPSILON,
        "Expected neutral trust {NEUTRAL_TRUST}, got {score}"
    );
}

/// Reporting successful events raises a peer's trust above neutral.
#[tokio::test]
async fn successes_raise_trust_above_neutral() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    for _ in 0..20 {
        node.report_trust_event(&peer, TrustEvent::ApplicationSuccess(1.0))
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(
        score > NEUTRAL_TRUST,
        "After 20 successes, trust {score} should exceed neutral {NEUTRAL_TRUST}"
    );
}

/// Reporting failure events lowers a peer's trust below neutral.
#[tokio::test]
async fn failures_lower_trust_below_neutral() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    for _ in 0..20 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(
        score < NEUTRAL_TRUST,
        "After 20 failures, trust {score} should be below neutral {NEUTRAL_TRUST}"
    );
}

// ---------------------------------------------------------------------------
// Trust event variants
// ---------------------------------------------------------------------------

/// All TrustEvent variants with valid weights affect the score (no panics, no no-ops for valid inputs).
#[tokio::test]
async fn all_trust_event_variants_affect_score() {
    let node = P2PNode::new(test_node_config()).await.unwrap();

    let positive_events = [TrustEvent::ApplicationSuccess(1.0)];
    let negative_events = [TrustEvent::ConnectionFailed, TrustEvent::ConnectionTimeout];

    for event in positive_events {
        let peer = PeerId::random();
        node.report_trust_event(&peer, event).await;
        let score = node.peer_trust(&peer);
        assert!(
            score > NEUTRAL_TRUST,
            "Positive event {event:?} should raise score above neutral, got {score}"
        );
    }

    for event in negative_events {
        let peer = PeerId::random();
        node.report_trust_event(&peer, event).await;
        let score = node.peer_trust(&peer);
        assert!(
            score < NEUTRAL_TRUST,
            "Negative event {event:?} should lower score below neutral, got {score}"
        );
    }
}

// ---------------------------------------------------------------------------
// Trust scoring and swap threshold
// ---------------------------------------------------------------------------

/// Sustained failures push a peer below the swap threshold.
#[tokio::test]
async fn sustained_failures_drop_below_swap_threshold() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let bad_peer = PeerId::random();

    for _ in 0..50 {
        node.report_trust_event(&bad_peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&bad_peer);
    assert!(
        score < SWAP_THRESHOLD,
        "After 50 failures, trust {score} should be below swap threshold {SWAP_THRESHOLD}"
    );
}

/// A single failure from neutral does NOT cross the swap threshold.
#[tokio::test]
async fn single_failure_does_not_cross_swap_threshold() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
        .await;

    let score = node.peer_trust(&peer);
    assert!(
        score >= SWAP_THRESHOLD,
        "One failure from neutral should not cross threshold; score={score}, threshold={SWAP_THRESHOLD}"
    );
}

/// A well-trusted peer is resilient to a few failures.
#[tokio::test]
async fn trusted_peer_resilient_to_occasional_failures() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    // Build up trust
    for _ in 0..50 {
        node.report_trust_event(&peer, TrustEvent::ApplicationSuccess(1.0))
            .await;
    }
    let high_score = node.peer_trust(&peer);

    // A few failures
    for _ in 0..3 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score_after = node.peer_trust(&peer);
    assert!(
        score_after >= SWAP_THRESHOLD,
        "3 failures after 50 successes should not block; score={score_after}"
    );
    assert!(
        score_after < high_score,
        "Score should have decreased from {high_score} to {score_after}"
    );
}

// ---------------------------------------------------------------------------
// Trust engine access & peer removal
// ---------------------------------------------------------------------------

/// The trust engine Arc is shared: scores reported via P2PNode are visible
/// through the engine reference.
#[tokio::test]
async fn trust_engine_arc_shares_state_with_node() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    // Report via P2PNode
    node.report_trust_event(&peer, TrustEvent::ApplicationSuccess(1.0))
        .await;

    // Read via TrustEngine Arc
    let engine = node.trust_engine();
    let score = engine.score(&peer);
    assert!(
        score > NEUTRAL_TRUST,
        "Engine should reflect the event reported through P2PNode; got {score}"
    );
}

/// Removing a peer via the trust engine resets their score to neutral.
#[tokio::test]
async fn removing_peer_resets_to_neutral() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    // Tank the score
    for _ in 0..30 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }
    assert!(node.peer_trust(&peer) < NEUTRAL_TRUST);

    // Remove via engine
    node.trust_engine().remove_node(&peer);

    let score = node.peer_trust(&peer);
    assert!(
        (score - NEUTRAL_TRUST).abs() < f64::EPSILON,
        "Removed peer should return to neutral; got {score}"
    );
}

// ---------------------------------------------------------------------------
// Multiple peers tracked independently
// ---------------------------------------------------------------------------

/// Trust for different peers is tracked independently.
#[tokio::test]
async fn peers_tracked_independently() {
    let node = P2PNode::new(test_node_config()).await.unwrap();

    let good_peer = PeerId::random();
    let bad_peer = PeerId::random();
    let neutral_peer = PeerId::random();

    for _ in 0..20 {
        node.report_trust_event(&good_peer, TrustEvent::ApplicationSuccess(1.0))
            .await;
        node.report_trust_event(&bad_peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let good_score = node.peer_trust(&good_peer);
    let bad_score = node.peer_trust(&bad_peer);
    let neutral_score = node.peer_trust(&neutral_peer);

    assert!(good_score > NEUTRAL_TRUST, "Good peer score: {good_score}");
    assert!(bad_score < NEUTRAL_TRUST, "Bad peer score: {bad_score}");
    assert!(
        (neutral_score - NEUTRAL_TRUST).abs() < f64::EPSILON,
        "Untouched peer should be neutral: {neutral_score}"
    );
}

// ---------------------------------------------------------------------------
// Trust scores bounded
// ---------------------------------------------------------------------------

/// Trust scores remain within [0.0, 1.0] regardless of extreme inputs.
#[tokio::test]
async fn trust_scores_bounded() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    // Extreme successes
    for _ in 0..500 {
        node.report_trust_event(&peer, TrustEvent::ApplicationSuccess(1.0))
            .await;
    }
    let high = node.peer_trust(&peer);
    assert!((0.0..=1.0).contains(&high), "Score out of bounds: {high}");

    // Extreme failures
    for _ in 0..1000 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }
    let low = node.peer_trust(&peer);
    assert!((0.0..=1.0).contains(&low), "Score out of bounds: {low}");
}

// ---------------------------------------------------------------------------
// AdaptiveDHT config validation flows through P2PNode
// ---------------------------------------------------------------------------

/// Custom swap threshold in AdaptiveDhtConfig is respected by the node.
#[tokio::test]
async fn custom_swap_threshold_respected() {
    let custom_threshold = 0.3;
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
        "Expected threshold {custom_threshold}, got {threshold}"
    );
}

/// Trust enforcement disabled (threshold 0.0) means no peers are ever swap-eligible.
#[tokio::test]
async fn trust_enforcement_disabled_no_swap_eligibility() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .trust_enforcement(false)
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();
    let peer = PeerId::random();

    // Max failures
    for _ in 0..100 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    let threshold = node.adaptive_dht().config().swap_threshold;

    // threshold is 0.0, so score (which is ≥0.0) is always >= threshold
    assert!(
        score >= threshold,
        "With enforcement disabled (threshold={threshold}), score {score} should be >= threshold"
    );
}

// ---------------------------------------------------------------------------
// EMA blending behavior
// ---------------------------------------------------------------------------

/// A success after a failure blends the score upward (EMA behavior).
#[tokio::test]
async fn ema_blends_observations() {
    let node = P2PNode::new(test_node_config()).await.unwrap();
    let peer = PeerId::random();

    // One failure
    node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
        .await;
    let after_fail = node.peer_trust(&peer);

    // One success
    node.report_trust_event(&peer, TrustEvent::ApplicationSuccess(1.0))
        .await;
    let after_recovery = node.peer_trust(&peer);

    assert!(
        after_recovery > after_fail,
        "Success after failure should raise score: {after_fail} -> {after_recovery}"
    );
}

/// The swap threshold from AdaptiveDhtConfig matches the default constant.
#[tokio::test]
async fn default_config_matches_expected_threshold() {
    let config = AdaptiveDhtConfig::default();
    assert!(
        (config.swap_threshold - SWAP_THRESHOLD).abs() < f64::EPSILON,
        "Default threshold {} != expected {}",
        config.swap_threshold,
        SWAP_THRESHOLD
    );
}

/// Invalid swap threshold values are rejected during node creation.
#[tokio::test]
async fn invalid_swap_threshold_rejected() {
    for bad_threshold in [f64::NAN, f64::NEG_INFINITY, -0.1, 1.1, f64::INFINITY] {
        let config = NodeConfig::builder()
            .local(true)
            .port(0)
            .ipv6(false)
            .adaptive_dht_config(AdaptiveDhtConfig {
                swap_threshold: bad_threshold,
            })
            .build();

        // Validation may happen at build() or at P2PNode::new() — either is acceptable
        match config {
            Err(_) => {}
            Ok(config) => {
                let result = P2PNode::new(config).await;
                assert!(
                    result.is_err(),
                    "Swap threshold {bad_threshold} should be rejected"
                );
            }
        }
    }
}
