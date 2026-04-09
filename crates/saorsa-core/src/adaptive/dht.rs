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

//! AdaptiveDHT — the trust boundary for all DHT operations.
//!
//! `AdaptiveDHT` is the **sole component** that creates and owns the [`TrustEngine`].
//! All DHT operations flow through it, and all trust signals originate from it.
//!
//! Internal DHT operations (iterative lookups) record trust via the `TrustEngine`
//! reference passed to `DhtNetworkManager`. External callers report additional
//! trust signals through [`AdaptiveDHT::report_trust_event`].

use crate::adaptive::trust::{NodeStatisticsUpdate, TrustEngine};
use crate::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use crate::{MultiAddr, PeerId};

use crate::error::P2pResult as Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Default trust score threshold below which a peer is eligible for swap-out
const DEFAULT_SWAP_THRESHOLD: f64 = 0.35;

/// Maximum weight multiplier per single consumer-reported event.
/// Caps the influence of any single consumer event on the EMA.
const MAX_CONSUMER_WEIGHT: f64 = 5.0;

/// Configuration for the AdaptiveDHT layer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptiveDhtConfig {
    /// Trust score below which a peer becomes eligible for swap-out from
    /// the routing table when a better candidate is available.
    /// Peers are NOT immediately evicted.
    /// Default: 0.35
    pub swap_threshold: f64,
}

impl Default for AdaptiveDhtConfig {
    fn default() -> Self {
        Self {
            swap_threshold: DEFAULT_SWAP_THRESHOLD,
        }
    }
}

impl AdaptiveDhtConfig {
    /// Validate that all config values are within acceptable ranges.
    ///
    /// Returns `Err` if `swap_threshold` is outside `[0.0, 0.5)` or is NaN.
    /// Values >= 0.5 (neutral trust) would make all unknown peers immediately
    /// swap-eligible since they start at neutral (0.5).
    pub fn validate(&self) -> crate::error::P2pResult<()> {
        if !(0.0..0.5).contains(&self.swap_threshold) || self.swap_threshold.is_nan() {
            return Err(crate::error::P2PError::Validation(
                format!(
                    "swap_threshold must be in [0.0, 0.5), got {}",
                    self.swap_threshold
                )
                .into(),
            ));
        }
        Ok(())
    }
}

/// Trust-relevant events for peer scoring.
///
/// Core only records **penalties** — successful responses are the expected
/// baseline and do not warrant a reward.  Positive trust signals are the
/// consumer's responsibility via [`ApplicationSuccess`](Self::ApplicationSuccess).
///
/// Consumer-reported events carry a weight multiplier that controls the
/// severity of the update (clamped to `MAX_CONSUMER_WEIGHT`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrustEvent {
    // === Negative signals (core) ===
    /// Could not establish a connection to the peer
    ConnectionFailed,
    /// Connection attempt timed out
    ConnectionTimeout,

    // === Consumer-reported signals ===
    /// Consumer-reported: peer completed an application-level task successfully.
    /// Weight controls severity (clamped to MAX_CONSUMER_WEIGHT).
    ApplicationSuccess(f64),
    /// Consumer-reported: peer failed an application-level task.
    /// Weight controls severity (clamped to MAX_CONSUMER_WEIGHT).
    ApplicationFailure(f64),
}

impl TrustEvent {
    /// Convert a TrustEvent to the internal NodeStatisticsUpdate
    fn to_stats_update(self) -> NodeStatisticsUpdate {
        match self {
            TrustEvent::ApplicationSuccess(_) => NodeStatisticsUpdate::CorrectResponse,
            TrustEvent::ConnectionFailed
            | TrustEvent::ConnectionTimeout
            | TrustEvent::ApplicationFailure(_) => NodeStatisticsUpdate::FailedResponse,
        }
    }
}

/// AdaptiveDHT — the trust boundary for all DHT operations.
///
/// Owns the `TrustEngine` and `DhtNetworkManager`. All DHT operations
/// should go through this component. Application-level trust signals
/// are reported via [`report_trust_event`](Self::report_trust_event).
pub struct AdaptiveDHT {
    /// The underlying DHT network manager (handles raw DHT operations)
    dht_manager: Arc<DhtNetworkManager>,

    /// The trust engine — sole authority on peer trust scores
    trust_engine: Arc<TrustEngine>,

    /// Configuration for trust-weighted behavior
    config: AdaptiveDhtConfig,
}

impl AdaptiveDHT {
    /// Create a new AdaptiveDHT instance.
    ///
    /// This creates the `TrustEngine` and the `DhtNetworkManager` with the
    /// trust engine injected. Call [`start`](Self::start) to begin DHT
    /// operations. Trust scores are computed live — low-trust peers are
    /// swapped out when better candidates arrive.
    ///
    /// # Errors
    ///
    /// Returns an error if `swap_threshold` is not in `[0.0, 0.5)` or if
    /// the underlying `DhtNetworkManager` fails to initialise.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        mut dht_config: DhtNetworkConfig,
        adaptive_config: AdaptiveDhtConfig,
    ) -> Result<Self> {
        adaptive_config.validate()?;

        dht_config.swap_threshold = adaptive_config.swap_threshold;

        let trust_engine = Arc::new(TrustEngine::new());

        let dht_manager = Arc::new(
            DhtNetworkManager::new(transport, Some(trust_engine.clone()), dht_config).await?,
        );

        Ok(Self {
            dht_manager,
            trust_engine,
            config: adaptive_config,
        })
    }

    // =========================================================================
    // Trust API — the only place where external callers record trust events
    // =========================================================================

    /// Report a trust event for a peer.
    ///
    /// For core penalty events (connection failure/timeout), applies unit weight.
    /// For consumer-reported events ([`TrustEvent::ApplicationSuccess`] /
    /// [`TrustEvent::ApplicationFailure`]), validates and clamps the weight
    /// to [`MAX_CONSUMER_WEIGHT`]. Zero or negative weights are silently
    /// ignored (no-op).
    ///
    /// Trust scores are updated immediately but low-trust peers are not
    /// evicted — they remain in the routing table until a better candidate
    /// arrives and triggers a swap-out.
    pub async fn report_trust_event(&self, peer_id: &PeerId, event: TrustEvent) {
        match event {
            TrustEvent::ApplicationSuccess(weight) | TrustEvent::ApplicationFailure(weight) => {
                if weight > 0.0 {
                    let clamped_weight = weight.min(MAX_CONSUMER_WEIGHT);
                    self.trust_engine.update_node_stats_weighted(
                        peer_id,
                        event.to_stats_update(),
                        clamped_weight,
                    );
                }
            }
            _ => {
                // Internal events: unit weight
                self.trust_engine
                    .update_node_stats(peer_id, event.to_stats_update());
            }
        }
    }

    /// Get the current trust score for a peer (synchronous).
    ///
    /// Returns `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers.
    pub fn peer_trust(&self, peer_id: &PeerId) -> f64 {
        self.trust_engine.score(peer_id)
    }

    /// Get a reference to the underlying trust engine for advanced use cases.
    pub fn trust_engine(&self) -> &Arc<TrustEngine> {
        &self.trust_engine
    }

    /// Get the adaptive DHT configuration.
    pub fn config(&self) -> &AdaptiveDhtConfig {
        &self.config
    }

    // =========================================================================
    // DHT operations — delegates to DhtNetworkManager
    // =========================================================================

    /// Get the underlying DHT network manager.
    ///
    /// All DHT operations are accessible through this reference.
    /// The DHT manager records trust internally for per-peer outcomes
    /// during iterative lookups.
    pub fn dht_manager(&self) -> &Arc<DhtNetworkManager> {
        &self.dht_manager
    }

    /// Start the DHT manager.
    ///
    /// Trust scores are computed live — no background tasks needed.
    /// Low-trust peers are swapped out when better candidates arrive.
    pub async fn start(&self) -> Result<()> {
        Arc::clone(&self.dht_manager).start().await
    }

    /// Stop the DHT manager gracefully.
    pub async fn stop(&self) -> Result<()> {
        self.dht_manager.stop().await
    }

    /// Trigger an immediate self-lookup to refresh the close neighborhood.
    ///
    /// Delegates to [`DhtNetworkManager::trigger_self_lookup`] which performs
    /// an iterative FIND_NODE for this node's own key.
    pub async fn trigger_self_lookup(&self) -> Result<()> {
        self.dht_manager.trigger_self_lookup().await
    }

    /// Look up connectable addresses for a peer.
    ///
    /// Checks the DHT routing table first, then falls back to the transport
    /// layer. Returns an empty vec when the peer is unknown or has no dialable
    /// addresses.
    pub(crate) async fn peer_addresses_for_dial(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        self.dht_manager.peer_addresses_for_dial(peer_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::trust::DEFAULT_NEUTRAL_TRUST;

    #[test]
    fn test_trust_event_mapping() {
        // Consumer success maps to CorrectResponse
        assert!(matches!(
            TrustEvent::ApplicationSuccess(1.0).to_stats_update(),
            NodeStatisticsUpdate::CorrectResponse
        ));

        // Penalty events map to FailedResponse
        assert!(matches!(
            TrustEvent::ConnectionFailed.to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
        assert!(matches!(
            TrustEvent::ConnectionTimeout.to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
        assert!(matches!(
            TrustEvent::ApplicationFailure(1.0).to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
    }

    #[test]
    fn test_adaptive_dht_config_defaults() {
        let config = AdaptiveDhtConfig::default();
        assert!((config.swap_threshold - DEFAULT_SWAP_THRESHOLD).abs() < f64::EPSILON);
    }

    #[test]
    fn test_swap_threshold_validation_rejects_invalid() {
        // Values outside [0.0, 0.5) or non-finite should be rejected.
        // 0.5 would block all unknown peers (they start at neutral 0.5).
        for &bad in &[
            -0.1,
            0.5,
            1.0,
            1.1,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let config = AdaptiveDhtConfig {
                swap_threshold: bad,
            };
            assert!(
                config.validate().is_err(),
                "swap_threshold {bad} should fail validation"
            );
        }
    }

    #[test]
    fn test_swap_threshold_validation_accepts_valid() {
        for &good in &[0.0, 0.15, 0.49] {
            let config = AdaptiveDhtConfig {
                swap_threshold: good,
            };
            assert!(
                config.validate().is_ok(),
                "swap_threshold {good} should pass validation"
            );
        }
    }

    // =========================================================================
    // Integration tests: full trust signal flow
    // =========================================================================

    /// Test: trust events flow through to TrustEngine and change scores immediately
    #[tokio::test]
    async fn test_trust_events_affect_scores() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        // Unknown peer starts at neutral trust
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);

        // Record consumer successes — score should rise above neutral
        for _ in 0..10 {
            engine.update_node_stats(&peer, TrustEvent::ApplicationSuccess(1.0).to_stats_update());
        }

        assert!(engine.score(&peer) > DEFAULT_NEUTRAL_TRUST);
    }

    /// Test: failures reduce trust below swap threshold
    #[tokio::test]
    async fn test_failures_reduce_trust_below_swap_threshold() {
        let engine = Arc::new(TrustEngine::new());
        let bad_peer = PeerId::random();

        // Record only failures — score should drop toward zero
        for _ in 0..20 {
            engine.update_node_stats(&bad_peer, TrustEvent::ConnectionFailed.to_stats_update());
        }

        let trust = engine.score(&bad_peer);
        assert!(
            trust < DEFAULT_SWAP_THRESHOLD,
            "Bad peer trust {trust} should be below swap threshold {DEFAULT_SWAP_THRESHOLD}"
        );
    }

    /// Test: TrustEngine scores are bounded 0.0-1.0
    #[tokio::test]
    async fn test_trust_scores_bounded() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        for _ in 0..100 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse);
        }

        let score = engine.score(&peer);
        assert!(score >= 0.0, "Score must be >= 0.0, got {score}");
        assert!(score <= 1.0, "Score must be <= 1.0, got {score}");
    }

    /// Test: all TrustEvent variants produce valid stats updates
    #[test]
    fn test_all_trust_events_produce_valid_updates() {
        let events = [
            TrustEvent::ConnectionFailed,
            TrustEvent::ConnectionTimeout,
            TrustEvent::ApplicationSuccess(1.0),
            TrustEvent::ApplicationFailure(3.0),
        ];

        for event in events {
            // Should not panic
            let _update = event.to_stats_update();
        }
    }

    // =========================================================================
    // End-to-end: peer lifecycle from trusted to swap-eligible to recovered
    // =========================================================================

    /// Full lifecycle: good peer -> fails -> swap-eligible -> time passes -> recovered
    #[tokio::test]
    async fn test_peer_lifecycle_trust_and_recovery() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Phase 1: Peer starts at neutral
        assert!(
            engine.score(&peer) >= DEFAULT_SWAP_THRESHOLD,
            "New peer should not be swap-eligible"
        );

        // Phase 2: Some successes — peer is trusted
        for _ in 0..20 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse);
        }
        let good_score = engine.score(&peer);
        assert!(
            good_score > DEFAULT_NEUTRAL_TRUST,
            "Trusted peer: {good_score}"
        );

        // Phase 3: Peer starts failing — score drops below swap threshold
        for _ in 0..200 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse);
        }
        let bad_score = engine.score(&peer);
        assert!(
            bad_score < DEFAULT_SWAP_THRESHOLD,
            "After many failures, peer should be swap-eligible: {bad_score}"
        );

        // Phase 4: Time passes (1+ day) — score decays back toward neutral
        let one_day = std::time::Duration::from_secs(24 * 3600);
        engine.simulate_elapsed(&peer, one_day).await;
        let recovered_score = engine.score(&peer);
        assert!(
            recovered_score >= DEFAULT_SWAP_THRESHOLD,
            "After 1 day idle, peer should have recovered: {recovered_score}"
        );
    }

    /// Verify the swap threshold separates eligible from ineligible peers
    #[tokio::test]
    async fn test_swap_threshold_is_binary() {
        let engine = TrustEngine::new();
        let threshold = DEFAULT_SWAP_THRESHOLD;

        let peer_above = PeerId::random();
        let peer_below = PeerId::random();

        // Peer with some successes — above threshold
        for _ in 0..5 {
            engine.update_node_stats(&peer_above, NodeStatisticsUpdate::CorrectResponse);
        }
        assert!(
            engine.score(&peer_above) >= threshold,
            "Peer with successes should be above threshold"
        );

        // Peer with only failures — below threshold
        for _ in 0..50 {
            engine.update_node_stats(&peer_below, NodeStatisticsUpdate::FailedResponse);
        }
        assert!(
            engine.score(&peer_below) < threshold,
            "Peer with only failures should be below threshold"
        );

        // Unknown peer — at neutral, which is above threshold
        let unknown = PeerId::random();
        assert!(
            engine.score(&unknown) >= threshold,
            "Unknown peer at neutral should not be swap-eligible"
        );
    }

    /// Verify that a single failure doesn't make a peer swap-eligible
    #[tokio::test]
    async fn test_single_failure_does_not_cross_swap_threshold() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        engine.update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse);

        // A single failure from neutral (0.5) should give ~0.44, still above 0.35
        assert!(
            engine.score(&peer) >= DEFAULT_SWAP_THRESHOLD,
            "One failure from neutral should not cross swap threshold: {}",
            engine.score(&peer)
        );
    }

    /// Verify that a previously-trusted peer needs many failures to become swap-eligible
    #[tokio::test]
    async fn test_trusted_peer_resilient_to_occasional_failures() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Build up trust
        for _ in 0..50 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse);
        }
        let trusted_score = engine.score(&peer);

        // A few failures shouldn't cross the swap threshold
        for _ in 0..3 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse);
        }

        assert!(
            engine.score(&peer) >= DEFAULT_SWAP_THRESHOLD,
            "3 failures after 50 successes should not cross swap threshold: {}",
            engine.score(&peer)
        );
        assert!(
            engine.score(&peer) < trusted_score,
            "Score should have decreased"
        );
    }

    /// Verify removing a peer resets their state completely
    #[tokio::test]
    async fn test_removed_peer_starts_fresh() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Block the peer
        for _ in 0..100 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse);
        }
        assert!(engine.score(&peer) < DEFAULT_SWAP_THRESHOLD);

        // Remove and check — should be back to neutral
        engine.remove_node(&peer);
        assert!(
            (engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON,
            "Removed peer should return to neutral"
        );
    }

    // =========================================================================
    // Consumer trust event tests (Design Matrix 53, 60, 61, 62)
    // =========================================================================

    /// Test 53: consumer reward improves trust
    #[tokio::test]
    async fn test_consumer_reward_improves_trust() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        let before = engine.score(&peer);
        engine.update_node_stats(&peer, TrustEvent::ApplicationSuccess(1.0).to_stats_update());
        let after = engine.score(&peer);

        assert!(
            after > before,
            "consumer reward should improve trust: {before} -> {after}"
        );
    }

    /// Test 60: higher weight produces larger score impact
    #[tokio::test]
    async fn test_higher_weight_larger_impact() {
        let engine = Arc::new(TrustEngine::new());
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        engine.update_node_stats_weighted(&peer_a, NodeStatisticsUpdate::FailedResponse, 1.0);
        engine.update_node_stats_weighted(&peer_b, NodeStatisticsUpdate::FailedResponse, 5.0);

        assert!(
            engine.score(&peer_b) < engine.score(&peer_a),
            "weight-5 failure should have larger impact than weight-1"
        );
    }

    /// Test 62: zero and negative weights rejected
    #[tokio::test]
    async fn test_zero_negative_weights_noop() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        let neutral = engine.score(&peer);

        // Zero weight should be a no-op (but this is validated in AdaptiveDHT,
        // not TrustEngine directly). If called on TrustEngine with weight 0,
        // the EMA formula with weight=0 produces alpha_w=0, so score stays unchanged.
        engine.update_node_stats_weighted(&peer, NodeStatisticsUpdate::FailedResponse, 0.0);
        let after_zero = engine.score(&peer);

        // With weight 0: alpha_w = 1 - (1-0.1)^0 = 1 - 1 = 0, so no change
        assert!(
            (after_zero - neutral).abs() < 1e-10,
            "zero-weight should not change score: {neutral} -> {after_zero}"
        );
    }

    // =======================================================================
    // Phase 8: Integration test matrix — missing coverage
    // =======================================================================

    // -----------------------------------------------------------------------
    // Test 61: Weight clamping at MAX_CONSUMER_WEIGHT
    // -----------------------------------------------------------------------
    // Full clamping happens in AdaptiveDHT::report_trust_event (which requires
    // a transport setup we can't construct in a unit test). Instead we verify
    // that TrustEngine does NOT clamp — proving that the caller is responsible
    // for clamping. This validates the design's layering.

    /// At the TrustEngine level, weight 100 must have MORE impact than weight 5,
    /// confirming that TrustEngine does not clamp. The clamping contract
    /// belongs to AdaptiveDHT::report_trust_event.
    #[tokio::test]
    async fn test_trust_engine_does_not_clamp_weights() {
        let engine = Arc::new(TrustEngine::new());
        let peer_clamped = PeerId::random();
        let peer_unclamped = PeerId::random();

        // Weight 5 (MAX_CONSUMER_WEIGHT) for peer_clamped
        engine.update_node_stats_weighted(
            &peer_clamped,
            NodeStatisticsUpdate::FailedResponse,
            MAX_CONSUMER_WEIGHT,
        );
        let score_at_max = engine.score(&peer_clamped);

        // Weight 100 (should NOT be clamped at TrustEngine level) for peer_unclamped
        engine.update_node_stats_weighted(
            &peer_unclamped,
            NodeStatisticsUpdate::FailedResponse,
            100.0,
        );
        let score_at_100 = engine.score(&peer_unclamped);

        assert!(
            score_at_100 < score_at_max,
            "TrustEngine should not clamp: weight-100 ({score_at_100}) should have more impact than weight-{MAX_CONSUMER_WEIGHT} ({score_at_max})"
        );
    }

    // -----------------------------------------------------------------------
    // Test 55: Consumer penalty pushes trust below swap threshold
    // -----------------------------------------------------------------------
    // At this layer we verify that enough failures push trust below the swap
    // threshold. Actual swap-out from the routing table happens during
    // admission (covered by trust swap-out tests in core_engine).

    /// A peer slightly above the swap threshold can be pushed below it by
    /// consumer-reported failures of sufficient weight.
    #[tokio::test]
    async fn test_consumer_penalty_crosses_swap_threshold() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        // First, bring the peer down to just above the swap threshold.
        // From neutral (0.5), 2 failures bring it to ~0.384 (still above 0.35).
        for _ in 0..2 {
            engine.update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse);
        }
        let score_before = engine.score(&peer);
        assert!(
            score_before > DEFAULT_SWAP_THRESHOLD,
            "should be above swap threshold: {score_before}"
        );

        // Heavy consumer failures should push it below the swap threshold.
        for _ in 0..10 {
            engine.update_node_stats_weighted(
                &peer,
                NodeStatisticsUpdate::FailedResponse,
                MAX_CONSUMER_WEIGHT,
            );
        }
        let score_after = engine.score(&peer);
        assert!(
            score_after < DEFAULT_SWAP_THRESHOLD,
            "after heavy consumer failures, score {score_after} should be below swap threshold {DEFAULT_SWAP_THRESHOLD}"
        );
    }

    // -----------------------------------------------------------------------
    // TrustEvent to_stats_update is exhaustive
    // -----------------------------------------------------------------------

    /// Verify that all consumer-reported event variants correctly map to the
    /// expected NodeStatisticsUpdate direction (success -> CorrectResponse,
    /// failure -> FailedResponse).
    #[test]
    fn test_consumer_event_direction_mapping() {
        // Success variants all map to CorrectResponse
        let success_events = [
            TrustEvent::ApplicationSuccess(0.5),
            TrustEvent::ApplicationSuccess(1.0),
            TrustEvent::ApplicationSuccess(5.0),
        ];
        for event in success_events {
            assert!(
                matches!(
                    event.to_stats_update(),
                    NodeStatisticsUpdate::CorrectResponse
                ),
                "{event:?} should map to CorrectResponse"
            );
        }

        // Failure variants all map to FailedResponse
        let failure_events = [
            TrustEvent::ApplicationFailure(0.5),
            TrustEvent::ApplicationFailure(1.0),
            TrustEvent::ApplicationFailure(5.0),
        ];
        for event in failure_events {
            assert!(
                matches!(
                    event.to_stats_update(),
                    NodeStatisticsUpdate::FailedResponse
                ),
                "{event:?} should map to FailedResponse"
            );
        }
    }
}
