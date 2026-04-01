//! Tunable parameters for the replication subsystem.
//!
//! All values below are a reference profile used for logic validation.
//! Parameter safety constraints (Section 4):
//! 1. `1 <= QUORUM_THRESHOLD <= CLOSE_GROUP_SIZE`
//! 2. Effective paid-list threshold is per-key dynamic:
//!    `ConfirmNeeded(K) = floor(PaidGroupSize(K)/2)+1`
//! 3. If constraints are violated at runtime reconfiguration, node MUST reject
//!    the config.

#![allow(clippy::module_name_repetitions)]

use std::time::Duration;

use rand::Rng;

// ---------------------------------------------------------------------------
// Static constants (compile-time reference profile)
// ---------------------------------------------------------------------------

/// Maximum number of peers per k-bucket in the Kademlia routing table.
pub const K_BUCKET_SIZE: usize = 20;

/// Close-group width and target holder count per key.
pub const CLOSE_GROUP_SIZE: usize = 7;

/// Full-network target for required positive presence votes.
///
/// Effective per-key threshold is
/// `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
pub const QUORUM_THRESHOLD: usize = 4; // floor(CLOSE_GROUP_SIZE / 2) + 1

/// Maximum number of closest nodes tracking paid status for a key.
pub const PAID_LIST_CLOSE_GROUP_SIZE: usize = 20;

/// Number of closest peers to self eligible for neighbor sync.
pub const NEIGHBOR_SYNC_SCOPE: usize = 20;

/// Number of close-neighbor peers synced concurrently per round-robin repair
/// round.
pub const NEIGHBOR_SYNC_PEER_COUNT: usize = 4;

/// Minimum neighbor-sync cadence. Actual interval is randomized within
/// `[min, max]`.
const NEIGHBOR_SYNC_INTERVAL_MIN_SECS: u64 = 10 * 60;
/// Maximum neighbor-sync cadence.
const NEIGHBOR_SYNC_INTERVAL_MAX_SECS: u64 = 20 * 60;

/// Neighbor sync cadence range (min).
pub const NEIGHBOR_SYNC_INTERVAL_MIN: Duration =
    Duration::from_secs(NEIGHBOR_SYNC_INTERVAL_MIN_SECS);

/// Neighbor sync cadence range (max).
pub const NEIGHBOR_SYNC_INTERVAL_MAX: Duration =
    Duration::from_secs(NEIGHBOR_SYNC_INTERVAL_MAX_SECS);

/// Per-peer minimum spacing between successive syncs with the same peer.
const NEIGHBOR_SYNC_COOLDOWN_SECS: u64 = 60 * 60; // 1 hour
/// Per-peer minimum spacing between successive syncs with the same peer.
pub const NEIGHBOR_SYNC_COOLDOWN: Duration = Duration::from_secs(NEIGHBOR_SYNC_COOLDOWN_SECS);

/// Minimum self-lookup cadence.
const SELF_LOOKUP_INTERVAL_MIN_SECS: u64 = 5 * 60;
/// Maximum self-lookup cadence.
const SELF_LOOKUP_INTERVAL_MAX_SECS: u64 = 10 * 60;

/// Periodic self-lookup cadence range (min) to keep close neighborhood
/// current.
pub const SELF_LOOKUP_INTERVAL_MIN: Duration = Duration::from_secs(SELF_LOOKUP_INTERVAL_MIN_SECS);

/// Periodic self-lookup cadence range (max).
pub const SELF_LOOKUP_INTERVAL_MAX: Duration = Duration::from_secs(SELF_LOOKUP_INTERVAL_MAX_SECS);

/// Bootstrap concurrent fetches cap.
pub const MAX_PARALLEL_FETCH_BOOTSTRAP: usize = 20;

/// Normal-operation concurrent fetches cap (post-bootstrap).
pub const MAX_PARALLEL_FETCH_NORMAL: usize = 50;

/// Minimum audit-scheduler cadence.
const AUDIT_TICK_INTERVAL_MIN_SECS: u64 = 30 * 60;
/// Maximum audit-scheduler cadence.
const AUDIT_TICK_INTERVAL_MAX_SECS: u64 = 60 * 60;

/// Audit scheduler cadence range (min).
pub const AUDIT_TICK_INTERVAL_MIN: Duration = Duration::from_secs(AUDIT_TICK_INTERVAL_MIN_SECS);

/// Audit scheduler cadence range (max).
pub const AUDIT_TICK_INTERVAL_MAX: Duration = Duration::from_secs(AUDIT_TICK_INTERVAL_MAX_SECS);

/// Maximum local keys sampled per audit round (also max challenge items).
pub const AUDIT_BATCH_SIZE: usize = 8;

/// Audit response deadline.
const AUDIT_RESPONSE_TIMEOUT_SECS: u64 = 12;
/// Audit response deadline.
pub const AUDIT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(AUDIT_RESPONSE_TIMEOUT_SECS);

/// Maximum duration a peer may claim bootstrap status before penalties apply.
const BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS: u64 = 24 * 60 * 60; // 24 h
/// Maximum duration a peer may claim bootstrap status before penalties apply.
pub const BOOTSTRAP_CLAIM_GRACE_PERIOD: Duration =
    Duration::from_secs(BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS);

/// Minimum continuous out-of-range duration before pruning a key.
const PRUNE_HYSTERESIS_DURATION_SECS: u64 = 6 * 60 * 60; // 6 h
/// Minimum continuous out-of-range duration before pruning a key.
pub const PRUNE_HYSTERESIS_DURATION: Duration = Duration::from_secs(PRUNE_HYSTERESIS_DURATION_SECS);

/// Protocol identifier for replication operations.
pub const REPLICATION_PROTOCOL_ID: &str = "autonomi/ant/replication/v1";

/// 10 MiB — maximum replication wire message size (accommodates hint batches).
const REPLICATION_MESSAGE_SIZE_MIB: usize = 10;
/// Maximum replication wire message size.
pub const MAX_REPLICATION_MESSAGE_SIZE: usize = REPLICATION_MESSAGE_SIZE_MIB * 1024 * 1024;

/// Verification request timeout (per-batch).
const VERIFICATION_REQUEST_TIMEOUT_SECS: u64 = 15;
/// Verification request timeout (per-batch).
pub const VERIFICATION_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(VERIFICATION_REQUEST_TIMEOUT_SECS);

/// Fetch request timeout.
const FETCH_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Fetch request timeout.
pub const FETCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(FETCH_REQUEST_TIMEOUT_SECS);

/// Maximum consumer trust event weight (clamped by `TrustEngine`).
pub const MAX_CONSUMER_TRUST_WEIGHT: f64 = 5.0;

// ---------------------------------------------------------------------------
// Runtime-configurable wrapper
// ---------------------------------------------------------------------------

/// Runtime-configurable replication parameters.
///
/// Validated on construction — node rejects invalid configs.
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Close-group width and target holder count per key.
    pub close_group_size: usize,
    /// Required positive presence votes for quorum.
    pub quorum_threshold: usize,
    /// Maximum closest nodes tracking paid status for a key.
    pub paid_list_close_group_size: usize,
    /// Number of closest peers to self eligible for neighbor sync.
    pub neighbor_sync_scope: usize,
    /// Peers synced concurrently per round-robin repair round.
    pub neighbor_sync_peer_count: usize,
    /// Neighbor sync cadence range (min).
    pub neighbor_sync_interval_min: Duration,
    /// Neighbor sync cadence range (max).
    pub neighbor_sync_interval_max: Duration,
    /// Minimum spacing between successive syncs with the same peer.
    pub neighbor_sync_cooldown: Duration,
    /// Self-lookup cadence range (min).
    pub self_lookup_interval_min: Duration,
    /// Self-lookup cadence range (max).
    pub self_lookup_interval_max: Duration,
    /// Bootstrap concurrent fetches cap.
    pub max_parallel_fetch_bootstrap: usize,
    /// Audit scheduler cadence range (min).
    pub audit_tick_interval_min: Duration,
    /// Audit scheduler cadence range (max).
    pub audit_tick_interval_max: Duration,
    /// Maximum local keys sampled per audit round.
    pub audit_batch_size: usize,
    /// Audit response deadline.
    pub audit_response_timeout: Duration,
    /// Maximum duration a peer may claim bootstrap status.
    pub bootstrap_claim_grace_period: Duration,
    /// Minimum continuous out-of-range duration before pruning a key.
    pub prune_hysteresis_duration: Duration,
    /// Verification request timeout (per-batch).
    pub verification_request_timeout: Duration,
    /// Fetch request timeout.
    pub fetch_request_timeout: Duration,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            close_group_size: CLOSE_GROUP_SIZE,
            quorum_threshold: QUORUM_THRESHOLD,
            paid_list_close_group_size: PAID_LIST_CLOSE_GROUP_SIZE,
            neighbor_sync_scope: NEIGHBOR_SYNC_SCOPE,
            neighbor_sync_peer_count: NEIGHBOR_SYNC_PEER_COUNT,
            neighbor_sync_interval_min: NEIGHBOR_SYNC_INTERVAL_MIN,
            neighbor_sync_interval_max: NEIGHBOR_SYNC_INTERVAL_MAX,
            neighbor_sync_cooldown: NEIGHBOR_SYNC_COOLDOWN,
            self_lookup_interval_min: SELF_LOOKUP_INTERVAL_MIN,
            self_lookup_interval_max: SELF_LOOKUP_INTERVAL_MAX,
            max_parallel_fetch_bootstrap: MAX_PARALLEL_FETCH_BOOTSTRAP,
            audit_tick_interval_min: AUDIT_TICK_INTERVAL_MIN,
            audit_tick_interval_max: AUDIT_TICK_INTERVAL_MAX,
            audit_batch_size: AUDIT_BATCH_SIZE,
            audit_response_timeout: AUDIT_RESPONSE_TIMEOUT,
            bootstrap_claim_grace_period: BOOTSTRAP_CLAIM_GRACE_PERIOD,
            prune_hysteresis_duration: PRUNE_HYSTERESIS_DURATION,
            verification_request_timeout: VERIFICATION_REQUEST_TIMEOUT,
            fetch_request_timeout: FETCH_REQUEST_TIMEOUT,
        }
    }
}

impl ReplicationConfig {
    /// Validate safety constraints. Returns `Err` with a description if any
    /// constraint is violated.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message describing the first violated
    /// constraint.
    pub fn validate(&self) -> Result<(), String> {
        if self.close_group_size == 0 {
            return Err("close_group_size must be >= 1".to_string());
        }
        if self.quorum_threshold == 0 || self.quorum_threshold > self.close_group_size {
            return Err(format!(
                "quorum_threshold ({}) must satisfy 1 <= quorum_threshold <= close_group_size ({})",
                self.quorum_threshold, self.close_group_size,
            ));
        }
        if self.paid_list_close_group_size == 0 {
            return Err("paid_list_close_group_size must be >= 1".to_string());
        }
        if self.neighbor_sync_interval_min > self.neighbor_sync_interval_max {
            return Err(format!(
                "neighbor_sync_interval_min ({:?}) must be <= neighbor_sync_interval_max ({:?})",
                self.neighbor_sync_interval_min, self.neighbor_sync_interval_max,
            ));
        }
        if self.audit_tick_interval_min > self.audit_tick_interval_max {
            return Err(format!(
                "audit_tick_interval_min ({:?}) must be <= audit_tick_interval_max ({:?})",
                self.audit_tick_interval_min, self.audit_tick_interval_max,
            ));
        }
        if self.self_lookup_interval_min > self.self_lookup_interval_max {
            return Err(format!(
                "self_lookup_interval_min ({:?}) must be <= self_lookup_interval_max ({:?})",
                self.self_lookup_interval_min, self.self_lookup_interval_max,
            ));
        }
        if self.neighbor_sync_peer_count == 0 {
            return Err("neighbor_sync_peer_count must be >= 1".to_string());
        }
        if self.audit_batch_size == 0 {
            return Err("audit_batch_size must be >= 1".to_string());
        }
        Ok(())
    }

    /// Effective quorum votes required for a key given the number of
    /// reachable quorum targets.
    ///
    /// `min(self.quorum_threshold, floor(quorum_targets_count / 2) + 1)`
    #[must_use]
    pub fn quorum_needed(&self, quorum_targets_count: usize) -> usize {
        let majority = quorum_targets_count / 2 + 1;
        self.quorum_threshold.min(majority)
    }

    /// Confirmations required for paid-list consensus given the number of
    /// peers in the paid-list close group for a key.
    ///
    /// `floor(paid_group_size / 2) + 1`
    #[must_use]
    pub fn confirm_needed(paid_group_size: usize) -> usize {
        paid_group_size / 2 + 1
    }

    /// Returns a random duration in `[neighbor_sync_interval_min,
    /// neighbor_sync_interval_max]`.
    #[must_use]
    pub fn random_neighbor_sync_interval(&self) -> Duration {
        random_duration_in_range(
            self.neighbor_sync_interval_min,
            self.neighbor_sync_interval_max,
        )
    }

    /// Returns a random duration in `[audit_tick_interval_min,
    /// audit_tick_interval_max]`.
    #[must_use]
    pub fn random_audit_tick_interval(&self) -> Duration {
        random_duration_in_range(self.audit_tick_interval_min, self.audit_tick_interval_max)
    }

    /// Returns a random duration in `[self_lookup_interval_min,
    /// self_lookup_interval_max]`.
    #[must_use]
    pub fn random_self_lookup_interval(&self) -> Duration {
        random_duration_in_range(self.self_lookup_interval_min, self.self_lookup_interval_max)
    }
}

/// Pick a random `Duration` uniformly in `[min, max]` at millisecond
/// granularity.
///
/// When `min == max` the result is deterministic.
fn random_duration_in_range(min: Duration, max: Duration) -> Duration {
    if min == max {
        return min;
    }
    // Our intervals are minutes/hours, well within u64 range. Saturate to
    // u64::MAX on the impossible overflow path to avoid a lossy cast.
    let to_u64_millis = |d: Duration| -> u64 { u64::try_from(d.as_millis()).unwrap_or(u64::MAX) };
    let chosen = rand::thread_rng().gen_range(to_u64_millis(min)..=to_u64_millis(max));
    Duration::from_millis(chosen)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_pass_validation() {
        let config = ReplicationConfig::default();
        assert!(config.validate().is_ok(), "default config must be valid");
    }

    #[test]
    fn quorum_threshold_zero_rejected() {
        let config = ReplicationConfig {
            quorum_threshold: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn quorum_threshold_exceeds_close_group_rejected() {
        let defaults = ReplicationConfig::default();
        let config = ReplicationConfig {
            quorum_threshold: defaults.close_group_size + 1,
            ..defaults
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn close_group_size_zero_rejected() {
        let config = ReplicationConfig {
            close_group_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn paid_list_close_group_size_zero_rejected() {
        let config = ReplicationConfig {
            paid_list_close_group_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_interval_inverted_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_interval_min: Duration::from_secs(100),
            neighbor_sync_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_tick_interval_inverted_rejected() {
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(100),
            audit_tick_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn self_lookup_interval_inverted_rejected() {
        let config = ReplicationConfig {
            self_lookup_interval_min: Duration::from_secs(100),
            self_lookup_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_peer_count_zero_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_peer_count: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_batch_size_zero_rejected() {
        let config = ReplicationConfig {
            audit_batch_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn quorum_needed_uses_smaller_of_threshold_and_majority() {
        let config = ReplicationConfig::default();

        // With 7 targets: majority = 7/2+1 = 4, threshold = 4 → min = 4
        assert_eq!(config.quorum_needed(7), 4);

        // With 3 targets: majority = 3/2+1 = 2, threshold = 4 → min = 2
        assert_eq!(config.quorum_needed(3), 2);

        // With 0 targets: majority = 0/2+1 = 1, threshold = 4 → min = 1
        assert_eq!(config.quorum_needed(0), 1);

        // With 100 targets: majority = 51, threshold = 4 → min = 4
        assert_eq!(config.quorum_needed(100), 4);
    }

    #[test]
    fn confirm_needed_is_strict_majority() {
        assert_eq!(ReplicationConfig::confirm_needed(1), 1);
        assert_eq!(ReplicationConfig::confirm_needed(2), 2);
        assert_eq!(ReplicationConfig::confirm_needed(3), 2);
        assert_eq!(ReplicationConfig::confirm_needed(4), 3);
        assert_eq!(ReplicationConfig::confirm_needed(20), 11);
    }

    #[test]
    fn random_intervals_within_bounds() {
        let config = ReplicationConfig::default();

        // Run several iterations to exercise randomness.
        let iterations = 50;
        for _ in 0..iterations {
            let ns = config.random_neighbor_sync_interval();
            assert!(ns >= config.neighbor_sync_interval_min);
            assert!(ns <= config.neighbor_sync_interval_max);

            let at = config.random_audit_tick_interval();
            assert!(at >= config.audit_tick_interval_min);
            assert!(at <= config.audit_tick_interval_max);

            let sl = config.random_self_lookup_interval();
            assert!(sl >= config.self_lookup_interval_min);
            assert!(sl <= config.self_lookup_interval_max);
        }
    }

    #[test]
    fn random_interval_equal_bounds_is_deterministic() {
        let fixed = Duration::from_secs(42);
        let config = ReplicationConfig {
            neighbor_sync_interval_min: fixed,
            neighbor_sync_interval_max: fixed,
            ..ReplicationConfig::default()
        };
        assert_eq!(config.random_neighbor_sync_interval(), fixed);
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 18: Invalid runtime config is rejected by `validate()`.
    #[test]
    fn scenario_18_invalid_config_rejected() {
        // quorum_threshold > close_group_size -> validation fails.
        let config = ReplicationConfig {
            quorum_threshold: 10,
            close_group_size: 7,
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("quorum_threshold"),
            "error should mention quorum_threshold: {err}"
        );

        // close_group_size = 0 -> validation fails.
        let config = ReplicationConfig {
            close_group_size: 0,
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("close_group_size"),
            "error should mention close_group_size: {err}"
        );

        // neighbor_sync interval min > max -> validation fails.
        let config = ReplicationConfig {
            neighbor_sync_interval_min: Duration::from_secs(200),
            neighbor_sync_interval_max: Duration::from_secs(100),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("neighbor_sync_interval"),
            "error should mention neighbor_sync_interval: {err}"
        );

        // self_lookup interval min > max -> validation fails.
        let config = ReplicationConfig {
            self_lookup_interval_min: Duration::from_secs(999),
            self_lookup_interval_max: Duration::from_secs(1),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("self_lookup_interval"),
            "error should mention self_lookup_interval: {err}"
        );

        // audit_tick interval min > max -> validation fails.
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(500),
            audit_tick_interval_max: Duration::from_secs(10),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("audit_tick_interval"),
            "error should mention audit_tick_interval: {err}"
        );
    }

    /// Scenario 26: Dynamic paid-list threshold for undersized set.
    /// With PaidGroupSize=8, `ConfirmNeeded` = floor(8/2)+1 = 5.
    #[test]
    fn scenario_26_dynamic_paid_threshold_undersized() {
        assert_eq!(ReplicationConfig::confirm_needed(8), 5, "floor(8/2)+1 = 5");

        // Additional boundary checks for small paid groups.
        assert_eq!(
            ReplicationConfig::confirm_needed(1),
            1,
            "single peer requires 1 confirmation"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(2),
            2,
            "2 peers require 2 confirmations"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(3),
            2,
            "3 peers require 2 confirmations"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(0),
            1,
            "0 peers yields floor(0/2)+1 = 1 (degenerate case)"
        );
    }
}
